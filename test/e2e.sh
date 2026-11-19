#!/bin/sh
# e2e test runner — boots the image ./build.sh produces and exercises the SMTP
# route, the sendmail handler, the metrics endpoint, and startup validation.
#
#   sh test/e2e.sh
#
# E2E_IMAGE overrides the image (default: the NOTICE slug with a :test tag).
# CADDY_EMAIL_STUB_IMAGE overrides the stub image built by ./build.sh.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

TMP=$(mktemp -d /tmp/caddy-email-e2e-XXXXXX)
PORT=9099
SMTP_PORT=9098
PERIP_PORT=9097
RATE_PORT=9096
SLUG=$(sed -n '1s/^[^:]*: //p' ./NOTICE)
IMAGE="${E2E_IMAGE:-${SLUG}:test}"
CONTAINER_NAME="caddyemail-e2e-runner"
PASS=0
FAIL=0

cleanup() {
	docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
	rm -rf "$TMP"
}
trap cleanup EXIT

docker image inspect "$IMAGE" >/dev/null 2>&1 || {
	echo "test/e2e.sh: image $IMAGE not found; build it with ./build.sh" >&2
	exit 1
}

# ── Create test Caddyfile ──────────────────────────────
cat >"$TMP/Caddyfile" <<'CADDY'
{
	admin off
	log {
		level ERROR
	}
	mta {
		spool_dir /var/lib/caddy/spool
		settle_delay 1h
	}
	smtp :2525 {
		hostname mail.test
		tls off
		route {
			reverse_proxy 127.0.0.1:8080
		}
	}
	# One slot per peer, so a second concurrent connection from the same
	# address is refused instead of being accepted. Test 9 holds the slot with
	# a slow upload and probes it from the host over a published port.
	smtp :2526 {
		hostname mail.test
		tls off
		max_ip_clients 1
	}
	# One new connection per second per peer, so a reconnect burst is refused
	# rather than accepted. Test 10 opens two connections back to back.
	smtp :2527 {
		hostname mail.test
		tls off
		max_ip_rate 1
	}
}

# The backend answers 250 only when the SMTP route dropped every hostile
# HTTP-level header and forwarded the allowlisted ones.
:8080 {
	@leak expression {http.request.header.Authorization} != "" || {http.request.header.Cookie} != ""
	respond @leak "sender set an HTTP-level header" 550
	@noreceived expression {http.request.header.Received} == ""
	respond @noreceived "missing Received trace header" 550
	@envfrom expression {http.request.header.X-Envelope-From} != "a@b"
	respond @envfrom "envelope sender missing" 550
	@nosubject expression {http.request.header.Subject} != "header test"
	respond @nosubject "allowlisted header did not arrive" 550
	@nospam expression {http.request.header.X-Spam-Status} != "No"
	respond @nospam "prefixed allowlisted header did not arrive" 550
	respond "ok" 200
}

:8081 {
	route {
		@sendmail path /sendmail/*
		handle @sendmail {
			sendmail {
				from no-reply@example.com
			}
		}
		@metrics path /metrics
		handle @metrics {
			metrics
		}
		respond "not found" 404
	}
}
CADDY

# ── Test 0: the image runs the versions go.mod pins ────
# The container and `go test` must resolve the same dependencies. A stale image
# hides behavior changes behind a green suite.
echo ""
echo "=== Test 0: dependency versions ==="
for mod in "github.com/caddyserver/caddy/v2" "github.com/prometheus/client_golang"; do
	want=$(awk -v m="$mod" '$1 == m && $2 ~ /^v/ {print $2}' go.mod)
	got=$(timeout 30s docker run --rm --entrypoint /bin/cat "$IMAGE" /usr/share/licenses/versions.txt 2>/dev/null \
		| awk -v m="$mod" '$1 == "dep" && $2 == m {print $3}')
	if [ -n "$want" ] && [ "$want" = "$got" ]; then
		echo "  PASS: $mod $got matches go.mod"
		PASS=$((PASS + 1))
	else
		echo "  FAIL: $mod: go.mod pins ${want:-nothing}, image has ${got:-nothing}"
		FAIL=$((FAIL + 1))
	fi
done

# ── Start Caddy ────────────────────────────────────────
echo "=== Starting Caddy container ==="
docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
timeout 60s docker run -d \
	--name "$CONTAINER_NAME" \
	-v "$TMP/Caddyfile:/etc/caddy/Caddyfile:ro" \
	-p "127.0.0.1:$PORT:8081" \
	-p "127.0.0.1:$SMTP_PORT:2525" \
	-p "127.0.0.1:$PERIP_PORT:2526" \
	-p "127.0.0.1:$RATE_PORT:2527" \
	"$IMAGE" run --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null

echo "=== Waiting for Caddy ==="
i=0
while [ "$i" -lt 30 ]; do
	if curl -sf --max-time 2 "http://127.0.0.1:$PORT/metrics" >/dev/null 2>&1; then
		echo "Caddy ready after ${i}s"
		break
	fi
	sleep 1
	i=$((i + 1))
done

ok() {
	echo "  PASS: $1"
	PASS=$((PASS + 1))
}

bad() {
	echo "  FAIL: $1"
	shift
	for line in "$@"; do
		echo "    $line"
	done
	FAIL=$((FAIL + 1))
}

check() {
	desc=$1 expected=$2 actual=$3
	if printf '%s\n' "$actual" | grep -q "$expected"; then
		ok "$desc"
	else
		bad "$desc" "expected to contain: $expected" "got: $actual"
	fi
}

check_eq() {
	desc=$1 expected=$2 actual=$3
	if [ "$actual" = "$expected" ]; then
		ok "$desc"
	else
		bad "$desc" "expected: $expected" "got: $actual"
	fi
}

# smtp_send leaves the full conversation in SMTP_OUT and curl's exit status in
# SMTP_STATUS, so a caller can assert both an accept and a reject.
smtp_send() {
	set +e
	SMTP_OUT=$(curl -sS -v --max-time 15 --url "smtp://127.0.0.1:$SMTP_PORT" \
		--mail-from "$1" --mail-rcpt "$2" --upload-file "$3" 2>&1)
	SMTP_STATUS=$?
	set -e
}

spooled() {
	timeout 30s docker exec "$CONTAINER_NAME" \
		sh -c 'cat /var/lib/caddy/spool/incoming/df*' 2>/dev/null | tr -d '\r' || true
}

metric_value() {
	printf '%s\n' "$METRICS" | awk -v key="$1" '$1 == key {print $2; exit}'
}

# ── Test 1: SMTP route header allowlist ────────────────
echo ""
echo "=== Test 1: SMTP route header allowlist ==="
{
	printf 'From: sender@example.com\r\n'
	printf 'Subject: header test\r\n'
	printf 'Message-ID: <abc@example.com>\r\n'
	printf 'X-Spam-Status: No\r\n'
	printf 'Authorization: Bearer evil\r\n'
	printf 'Cookie: session=evil\r\n'
	printf 'X-Forwarded-For: 10.0.0.1\r\n'
	printf 'Content-Length: 999999\r\n'
	printf 'X-Envelope-From: attacker@evil.example\r\n'
	printf '\r\n'
	printf 'hello from the wire\r\n'
} >"$TMP/injected.eml"

smtp_send a@b c@d "$TMP/injected.eml"
check_eq "allowlisted message accepted" 0 "$SMTP_STATUS"
check "SMTP replied 250 2.0.0 OK" '250 2.0.0 OK' "$SMTP_OUT"

# ── Test 2: control message is rejected ────────────────
echo ""
echo "=== Test 2: control message ==="
printf 'From: sender@example.com\r\n\r\n' >"$TMP/control.eml"
smtp_send a@b c@d "$TMP/control.eml"
check "control message rejected with 550" '550' "$SMTP_OUT"
if printf '%s\n' "$SMTP_OUT" | grep -q '250 2.0.0 OK'; then
	bad "control message was accepted"
else
	ok "control message was not accepted"
fi

# ── Test 3: sendmail handler enqueues ──────────────────
echo ""
echo "=== Test 3: sendmail handler ==="
CODE=$(curl -sS --max-time 10 -o "$TMP/send1.json" -w '%{http_code}' -X POST \
	-H 'Content-Type: text/plain' \
	-H 'From: sender@example.com' -H 'To: rcpt@example.com' \
	--data-binary 'hello world' "http://127.0.0.1:$PORT/sendmail/")
check_eq "POST /sendmail/ returns 202" 202 "$CODE"
check "response carries a queue id" 'queue_id' "$(cat "$TMP/send1.json")"

CODE=$(curl -sS --max-time 10 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/sendmail/")
check_eq "GET /sendmail/ returns 405" 405 "$CODE"

# ── Test 4: generated Message-ID ───────────────────────
echo ""
echo "=== Test 4: generated Message-ID ==="
SPOOL=$(spooled)
COUNT=$(printf '%s\n' "$SPOOL" | grep -c '^Message-ID:' || true)
check_eq "spooled message has exactly one Message-ID" 1 "$COUNT"
check "Message-ID uses the envelope sender domain" '^Message-ID: <[^>]*@example.com>$' "$SPOOL"

# ── Test 5: caller-supplied Message-ID is preserved ────
echo ""
echo "=== Test 5: supplied Message-ID ==="
CODE=$(curl -sS --max-time 10 -o "$TMP/send2.json" -w '%{http_code}' -X POST \
	-H 'Content-Type: text/plain' \
	-H 'From: sender@example.com' -H 'To: rcpt@example.com' \
	-H 'Message-ID: <keep@example.com>' \
	--data-binary 'keep my id' "http://127.0.0.1:$PORT/sendmail/")
check_eq "POST with Message-ID returns 202" 202 "$CODE"
SPOOL=$(spooled)
check "caller-supplied Message-ID survives" '<keep@example.com>' "$SPOOL"
COUNT=$(printf '%s\n' "$SPOOL" | grep -c '^Message-ID:' || true)
check_eq "one Message-ID per message" 2 "$COUNT"

# ── Test 6: metrics endpoint ───────────────────────────
echo ""
echo "=== Test 6: metrics ==="
set +e
METRICS=$(curl -sf --max-time 10 "http://127.0.0.1:$PORT/metrics")
METRICS_STATUS=$?
set -e
check_eq "GET /metrics succeeds" 0 "$METRICS_STATUS"

for name in \
	caddy_email_sendmail_enqueued_total \
	caddy_email_mta_enqueued_total \
	caddy_email_mta_notify_dropped_total \
	caddy_email_mta_spool_bytes \
	caddy_email_mta_spool_jobs \
	caddy_email_smtp_connections_total \
	caddy_email_smtp_messages_total
do
	check "metric $name is exported" "^$name" "$METRICS"
done

check_eq "two sendmail enqueues counted" 2 "$(metric_value caddy_email_sendmail_enqueued_total)"
check_eq "two MTA enqueues counted" 2 "$(metric_value caddy_email_mta_enqueued_total)"
check_eq "two SMTP connections counted" 2 "$(metric_value caddy_email_smtp_connections_total)"
check_eq "one accepted SMTP message counted" 1 "$(metric_value caddy_email_smtp_messages_total)"

# The spool gauges are computed at scrape time: settle_delay keeps both jobs in
# incoming/. A hold state used to be exported without anything ever writing to
# it, so it must stay gone.
check_eq "two jobs sit in incoming" 2 "$(metric_value 'caddy_email_mta_spool_jobs{state="incoming"}')"
if [ "$(metric_value caddy_email_mta_spool_bytes)" -gt 0 ] 2>/dev/null; then
	ok "spool bytes are positive"
else
	bad "spool bytes are positive" "got: $(metric_value caddy_email_mta_spool_bytes)"
fi
if printf '%s\n' "$METRICS" | grep -q 'caddy_email_mta_spool_jobs{state="hold"}'; then
	bad "no dead hold state is exported"
else
	ok "no dead hold state is exported"
fi

# ── Test 7: startup validation ─────────────────────────
echo ""
echo "=== Test 7: startup validation ==="
neg() {
	desc=$1 file=$2 expect=$3 adapter=${4:-caddyfile}
	set +e
	if [ "$adapter" = json ]; then
		out=$(timeout 30s docker run --rm \
			-v "$file:/etc/caddy/config.json:ro" \
			"$IMAGE" run --config /etc/caddy/config.json 2>&1)
	else
		out=$(timeout 30s docker run --rm \
			-v "$file:/etc/caddy/Caddyfile:ro" \
			"$IMAGE" run --config /etc/caddy/Caddyfile --adapter caddyfile 2>&1)
	fi
	status=$?
	set -e
	if [ "$status" -ne 0 ] && printf '%s\n' "$out" | grep -q "$expect"; then
		ok "$desc"
	else
		bad "$desc" "expected non-zero exit containing: $expect" "got exit=$status: $out"
	fi
}

cat >"$TMP/neg-unknown-option.Caddyfile" <<'CADDY'
{
	admin off
	mta
}
:8080 {
	route /sendmail/* {
		sendmail {
			bootstrap_servers 127.0.0.1:25
		}
	}
}
CADDY

cat >"$TMP/neg-bad-body-size.Caddyfile" <<'CADDY'
{
	admin off
	mta
}
:8080 {
	route /sendmail/* {
		sendmail {
			max_body_size huge
		}
	}
}
CADDY

cat >"$TMP/neg-zero-concurrency.Caddyfile" <<'CADDY'
{
	admin off
	mta {
		concurrency -1
	}
}
:8080 {
	respond "ok"
}
CADDY

cat >"$TMP/neg-negative-settle.Caddyfile" <<'CADDY'
{
	admin off
	mta {
		settle_delay -1s
	}
}
:8080 {
	respond "ok"
}
CADDY

neg "unknown sendmail option fails" "$TMP/neg-unknown-option.Caddyfile" 'unknown sendmail option'
neg "non-numeric max_body_size fails" "$TMP/neg-bad-body-size.Caddyfile" 'invalid syntax'
neg "negative mta concurrency fails" "$TMP/neg-zero-concurrency.Caddyfile" 'concurrency must be > 0'
neg "negative settle_delay fails" "$TMP/neg-negative-settle.Caddyfile" 'settle_delay must be >= 0'

# ── Test 8: wrong mta app aborts cleanly ───────────────
echo ""
echo "=== Test 8: wrong mta app ==="
STUB_IMAGE=${CADDY_EMAIL_STUB_IMAGE:-${IMAGE}-stub}
docker image inspect "$STUB_IMAGE" >/dev/null 2>&1 || {
	echo "test/e2e.sh: stub image $STUB_IMAGE not found; build it with ./build.sh" >&2
	exit 1
}

cat >"$TMP/stub.json" <<'JSON'
{
	"admin": {"disabled": true},
	"apps": {
		"mta": {},
		"http": {
			"servers": {
				"stub": {
					"listen": ["127.0.0.1:18081"],
					"routes": [
						{"handle": [{"handler": "stubtrigger", "ext": {"sendmail": {}}}]}
					]
				}
			}
		}
	}
}
JSON

set +e
STUB_OUT=$(timeout 60s docker run --rm \
	-v "$TMP/stub.json:/etc/caddy/stub.json:ro" \
	"$STUB_IMAGE" run --config /etc/caddy/stub.json 2>&1)
STUB_STATUS=$?
set -e

if [ "$STUB_STATUS" -eq 0 ]; then
	bad "startup fails when mta is not an enqueuer" "caddy started"
elif printf '%s\n' "$STUB_OUT" | grep -q 'panic'; then
	bad "startup fails without a panic" "startup panicked: $STUB_OUT"
elif printf '%s\n' "$STUB_OUT" | grep -q 'does not implement shared.Enqueuer'; then
	ok "startup fails with the enqueuer error"
else
	bad "startup fails with the enqueuer error" "got exit=$STUB_STATUS: $STUB_OUT"
fi

# ── Test 9: per-IP connection cap ──────────────────────
echo ""
echo "=== Test 9: per-IP connection cap ==="
# The :2526 listener allows one connection per peer. Published-port traffic
# from the host all arrives from the same peer address, so a slow upload holds
# the only slot while a second connection must be refused with a retryable
# 421. Closing the first connection must hand the slot back.
dd if=/dev/zero of="$TMP/hold.eml" bs=1024 count=1024 2>/dev/null
set +e
curl -sS -v --max-time 18 --limit-rate 1k --url "smtp://127.0.0.1:$PERIP_PORT" \
	--mail-from a@b --mail-rcpt c@d --upload-file "$TMP/hold.eml" >/dev/null 2>&1 &
HOLD_PID=$!
sleep 2
PERIP_OUT=$(curl -sS -v --max-time 10 --url "smtp://127.0.0.1:$PERIP_PORT" \
	--mail-from a@b --mail-rcpt c@d --upload-file "$TMP/control.eml" 2>&1)
kill "$HOLD_PID" 2>/dev/null
wait "$HOLD_PID" 2>/dev/null
set -e
check "second concurrent connection from one IP is refused" '^< 421 4\.7\.0' "$PERIP_OUT"
if printf '%s\n' "$PERIP_OUT" | grep -q '^< 220 '; then
	bad "refused connection never got a greeting"
else
	ok "refused connection never got a greeting"
fi

i=0
PERIP_AFTER=
while [ "$i" -lt 10 ]; do
	PERIP_AFTER=$(curl -sS -v --max-time 5 --url "smtp://127.0.0.1:$PERIP_PORT" \
		--mail-from a@b --mail-rcpt c@d --upload-file "$TMP/control.eml" 2>&1 || true)
	printf '%s\n' "$PERIP_AFTER" | grep -q '^< 220 ' && break
	sleep 1
	i=$((i + 1))
done
check "slot is released once the held connection closes" '^< 220 ' "$PERIP_AFTER"

set +e
METRICS=$(curl -sf --max-time 10 "http://127.0.0.1:$PORT/metrics")
METRICS_STATUS=$?
set -e
check_eq "GET /metrics succeeds after the per-IP probe" 0 "$METRICS_STATUS"
check_eq "one per-IP rejection counted" 1 "$(metric_value caddy_email_smtp_ip_rejections_total)"

# ── Test 10: per-IP connection rate cap ────────────────
echo ""
echo "=== Test 10: per-IP connection rate cap ==="
# The :2527 listener allows one new connection per second per peer. Two
# connections opened back to back must let the first through and refuse the
# second with a retryable 421; once the bucket refills the peer may connect
# again. A concurrency cap would let the second one through, so this fails
# without rate limiting.
set +e
RATE_FIRST=$(curl -sS -v --max-time 10 --url "smtp://127.0.0.1:$RATE_PORT" \
	--mail-from a@b --mail-rcpt c@d --upload-file "$TMP/control.eml" 2>&1)
RATE_SECOND=$(curl -sS -v --max-time 10 --url "smtp://127.0.0.1:$RATE_PORT" \
	--mail-from a@b --mail-rcpt c@d --upload-file "$TMP/control.eml" 2>&1)
set -e
check "first connection under the rate cap is greeted" '^< 220 ' "$RATE_FIRST"
check "back-to-back connection is refused by the rate cap" '^< 421 4\.7\.1' "$RATE_SECOND"

sleep 2
set +e
RATE_AFTER=$(curl -sS -v --max-time 10 --url "smtp://127.0.0.1:$RATE_PORT" \
	--mail-from a@b --mail-rcpt c@d --upload-file "$TMP/control.eml" 2>&1)
set -e
check "peer is greeted again once the bucket refills" '^< 220 ' "$RATE_AFTER"

set +e
METRICS=$(curl -sf --max-time 10 "http://127.0.0.1:$PORT/metrics")
METRICS_STATUS=$?
set -e
check_eq "GET /metrics succeeds after the rate probe" 0 "$METRICS_STATUS"
check_eq "one per-IP rate rejection counted" 1 "$(metric_value caddy_email_smtp_ip_rate_rejections_total)"

# ── Summary ────────────────────────────────────────────
echo ""
echo "=========================================="
echo "  PASS: $PASS   FAIL: $FAIL"
echo "=========================================="
[ "$FAIL" -eq 0 ] && echo "ALL TESTS PASSED" || echo "SOME TESTS FAILED"
exit "$FAIL"
