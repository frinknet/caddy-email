#!/usr/bin/env bash
# End-to-end check against the container image ./build.sh produces (default
# caddy-email:test). The image runs a Caddyfile with an SMTP route, the
# sendmail handler and the metrics handler; the script drives that container
# over published ports and asserts what it sees.
#
# All orchestration lives here, in bash. The Go test in this directory only
# calls this script; run it directly with:
#
#   tests/e2e/container.sh [image]
set -euo pipefail

IMG=${1:-${CADDY_EMAIL_TEST_IMAGE:-caddy-email:test}}
NAME="caddy-email-e2e-$$"
WORK=$(mktemp -d)

cleanup() {
	docker rm -f "$NAME" >/dev/null 2>&1 || true
	rm -rf "$WORK"
}
trap cleanup EXIT

command -v docker >/dev/null 2>&1 || {
	echo "container.sh: docker is not installed" >&2
	exit 1
}
docker image inspect "$IMG" >/dev/null 2>&1 || {
	echo "container.sh: image $IMG not found; build it with ./build.sh" >&2
	exit 1
}

cat >"$WORK/Caddyfile" <<'CADDY'
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
}

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

docker run -d --name "$NAME" \
	-p 127.0.0.1::2525 \
	-p 127.0.0.1::8081 \
	-v "$WORK/Caddyfile:/srv/www/Caddyfile:ro" "$IMG" >/dev/null

host_port() {
	docker port "$NAME" "$1/tcp" | awk -F: 'NR == 1 {print $NF}'
}

ROUTE_PORT=$(host_port 2525)
HTTP_PORT=$(host_port 8081)
export ROUTE_PORT HTTP_PORT NAME

python3 - <<'PY'
import http.client
import os
import socket
import subprocess
import sys
import time

route_port = int(os.environ["ROUTE_PORT"])
http_port = int(os.environ["HTTP_PORT"])
container = os.environ["NAME"]


def wait_for_banner(port):
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2) as conn:
                conn.settimeout(2)
                # Docker's port proxy accepts connections before the listener
                # is up, so wait for the SMTP banner instead of a bare connect.
                if conn.recv(256).startswith(b"220"):
                    return
        except OSError:
            pass
        time.sleep(0.2)
    sys.exit("SMTP listener on port %d never sent a banner" % port)


def smtp(port, headers, payload="hello from the wire"):
    script = (
        "EHLO test\r\n"
        "MAIL FROM:<a@b>\r\n"
        "RCPT TO:<c@d>\r\n"
        "DATA\r\n" + headers + "\r\n"
        + payload + "\r\n"
        ".\r\n"
        "QUIT\r\n"
    )
    with socket.create_connection(("127.0.0.1", port), timeout=10) as conn:
        conn.sendall(script.encode())
        out = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            out += chunk
    return out.decode(errors="replace")


def request(method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", http_port, timeout=10)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        return resp.status, resp.read().decode(errors="replace")
    finally:
        conn.close()


def spooled():
    """Return the raw text of every queued message body."""
    out = subprocess.run(
        ["docker", "exec", container, "sh", "-c", "cat /var/lib/caddy/spool/incoming/df*"],
        capture_output=True,
        text=True,
    )
    if out.returncode != 0:
        sys.exit("could not read the spool: " + out.stderr)
    return out.stdout


def message_id_lines(raw):
    ids = []
    for line in raw.splitlines():
        if line.lower().startswith("message-id:"):
            ids.append(line)
        elif line == "":
            break
    return ids


wait_for_banner(route_port)

clean = (
    "From: sender@example.com\r\n"
    "Subject: header test\r\n"
    "Message-ID: <abc@example.com>\r\n"
    "X-Spam-Status: No\r\n"
)
injected = (
    clean
    + "Authorization: Bearer evil\r\n"
    + "Cookie: session=evil\r\n"
    + "X-Forwarded-For: 10.0.0.1\r\n"
    + "Content-Length: 999999\r\n"
    + "X-Envelope-From: attacker@evil.example\r\n"
)

# Leg 1: SMTP route through reverse_proxy, with hostile headers injected.
out = smtp(route_port, injected)
if "250 2.0.0 OK" not in out:
    sys.exit("allowlisted message was not accepted, server said:\n" + out)

# Control: the backend rejects when an allowlisted header is missing, proving
# the route really ran and the check above is meaningful.
out = smtp(route_port, "From: sender@example.com\r\n")
if "550" not in out or "250 2.0.0 OK" in out:
    sys.exit("control message should have been rejected, server said:\n" + out)

# Leg 2: HTTP sendmail handler enqueues into the MTA spool.
status, body = request(
    "POST",
    "/sendmail/",
    body="hello world",
    headers={"From": "sender@example.com", "To": "rcpt@example.com"},
)
if status != 202:
    sys.exit("POST /sendmail/ returned %d, want 202: %s" % (status, body))

# The message crossed the spool without a Message-ID, so one must be generated
# from the envelope sender's domain.
ids = message_id_lines(spooled())
if len(ids) != 1:
    sys.exit("spooled message has %d Message-ID headers, want 1: %r" % (len(ids), ids))
if not ids[0].startswith("Message-ID: <") or "@example.com>" not in ids[0]:
    sys.exit("generated Message-ID has the wrong shape: %r" % ids[0])

# A caller-supplied Message-ID must be preserved, not replaced or duplicated.
status, body = request(
    "POST",
    "/sendmail/",
    body="keep my id",
    headers={
        "From": "sender@example.com",
        "To": "rcpt@example.com",
        "Message-ID": "<keep@example.com>",
    },
)
if status != 202:
    sys.exit("POST /sendmail/ with Message-ID returned %d, want 202: %s" % (status, body))
raw = spooled()
if "<keep@example.com>" not in raw:
    sys.exit("caller-supplied Message-ID was replaced: %r" % raw)
if raw.lower().count("message-id:") != 2:
    sys.exit("want exactly one Message-ID per message, spool holds: %r" % raw)

# Leg 3: scrape Caddy's metrics handler.
status, metrics = request("GET", "/metrics")
if status != 200:
    sys.exit("GET /metrics returned %d, want 200" % status)

for name in (
    "caddy_email_sendmail_enqueued_total",
    "caddy_email_mta_enqueued_total",
    "caddy_email_mta_notify_dropped_total",
    "caddy_email_mta_spool_bytes",
    "caddy_email_mta_spool_jobs",
    "caddy_email_smtp_connections_total",
    "caddy_email_smtp_messages_total",
):
    if name not in metrics:
        sys.exit("metric %s missing from /metrics output" % name)


def metric_value(text, name):
    for line in text.splitlines():
        prefix = name + " "
        if line.startswith(prefix):
            return float(line[len(prefix):])
    return -1.0


exact = {
    "caddy_email_sendmail_enqueued_total": 2.0,
    "caddy_email_mta_enqueued_total": 2.0,
}
for name, want in exact.items():
    got = metric_value(metrics, name)
    if got != want:
        sys.exit("%s = %v, want %v" % (name, got, want))

# The readiness probe and the rejected control message are connections too,
# so only the direction is meaningful; messages counts accepted transactions.
for name, want in {
    "caddy_email_smtp_connections_total": 3.0,
    "caddy_email_smtp_messages_total": 1.0,
}.items():
    got = metric_value(metrics, name)
    if got < want:
        sys.exit("%s = %v, want at least %v" % (name, got, want))

# The spool gauges are computed at scrape time: the two enqueued jobs sit in
# incoming/ (settle_delay keeps the tick from claiming them).
incoming = metric_value(metrics, 'caddy_email_mta_spool_jobs{state="incoming"}')
if incoming != 2.0:
    sys.exit('caddy_email_mta_spool_jobs{state="incoming"} = %v, want 2' % incoming)
if metric_value(metrics, "caddy_email_mta_spool_bytes") <= 0:
    sys.exit("caddy_email_mta_spool_bytes = 0, want > 0")
# Every exported state is a state something can write to. hold/ used to be
# created and reported but never written, so it must not be exported.
if 'caddy_email_mta_spool_jobs{state="hold"}' in metrics:
    sys.exit("caddy_email_mta_spool_jobs exports a dead hold state")

print("container e2e ok")
PY
