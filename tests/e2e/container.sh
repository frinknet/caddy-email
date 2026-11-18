#!/bin/sh
# End-to-end check against the container image ./build.sh produces (default
# caddy-email:test). It mounts a config, delivers a message over SMTP with
# headers a sender must not be able to set, and reads the SMTP reply back.
#
# Usage: tests/e2e/container.sh [image]
set -eu

IMG=${1:-caddy-email:test}
PORT=${SMTP_PORT:-2525}
NAME=caddy-email-e2e-$$
WORK=$(mktemp -d)
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT

cat >"$WORK/Caddyfile" <<'CADDY'
{
	admin off
	log {
		level ERROR
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
	@nosubject expression {http.request.header.Subject} != "header test"
	respond @nosubject "allowlisted header did not arrive" 550
	respond "ok" 200
}
CADDY

docker run -d --name "$NAME" -p "127.0.0.1:$PORT:2525" \
	-v "$WORK/Caddyfile:/srv/www/Caddyfile:ro" "$IMG" >/dev/null

python3 - "$PORT" <<'PY'
import socket, sys, time

port = int(sys.argv[1])
deadline = time.time() + 20
ready = False
while time.time() < deadline:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2) as conn:
            conn.settimeout(2)
            # Docker's port proxy accepts connections before the listener is
            # up, so wait for the SMTP banner instead of a bare connect.
            if conn.recv(256).startswith(b"220"):
                ready = True
                break
    except OSError:
        pass
    time.sleep(0.2)
if not ready:
    sys.exit("SMTP listener never sent a banner")


def deliver(headers):
    script = (
        "EHLO test\r\n"
        "MAIL FROM:<a@b>\r\n"
        "RCPT TO:<c@d>\r\n"
        "DATA\r\n" + headers + "\r\n"
        "hello from the wire\r\n"
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


clean = (
    "From: sender@example.com\r\n"
    "Subject: header test\r\n"
    "Message-ID: <abc@example.com>\r\n"
)
injected = (
    clean
    + "Authorization: Bearer evil\r\n"
    + "Cookie: session=evil\r\n"
    + "X-Forwarded-For: 10.0.0.1\r\n"
    + "Content-Length: 999999\r\n"
    + "X-Envelope-From: attacker@evil.example\r\n"
)

out = deliver(injected)
if "250 2.0.0 OK" not in out:
    sys.exit("allowlisted message was not accepted, server said:\n" + out)

# Control: the backend rejects when an allowlisted header is missing, proving
# the route really ran and the checks above are meaningful.
out = deliver("From: sender@example.com\r\n")
if "550" not in out or "250 2.0.0 OK" in out:
    sys.exit("control message should have been rejected, server said:\n" + out)

print("container e2e ok")
PY
