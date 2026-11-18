package smtp

import (
	"net/http"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// TestSessionNullSender checks that the null reverse-path (RFC 5321 section
// 4.5.5) is accepted and delivered, with an empty envelope sender, rather than
// being treated as "no MAIL yet".
func TestSessionNullSender(t *testing.T) {
	t.Parallel()
	conn := newFakeConn()
	conn.Buffer.WriteString(
		"EHLO test\r\n" +
			"MAIL FROM:<>\r\n" +
			"RCPT TO:<c@d>\r\n" +
			"DATA\r\n" +
			"From: \r\n" +
			"To: c@d\r\n" +
			"\r\n" +
			"bounce body\r\n" +
			".\r\n" +
			"QUIT\r\n",
	)
	lc := &ListenerConfig{
		Port:           25,
		Hostname:       "mail.test",
		MaxMessageSize: 25 << 20,
		MaxRecipients:  50,
		TLS:            "off",
		Route: &caddyhttp.Subroute{
			Routes: caddyhttp.RouteList{
				{Handlers: []caddyhttp.MiddlewareHandler{
					testHandler{fn: func(w http.ResponseWriter, r *http.Request) error {
						if got := r.Header.Get("X-Envelope-From"); got != "" {
							t.Errorf("X-Envelope-From = %q, want empty", got)
						}
						if got := r.Header.Get("X-Envelope-To"); got != "c@d" {
							t.Errorf("X-Envelope-To = %q, want c@d", got)
						}
						w.WriteHeader(http.StatusOK)
						return nil
					}},
				}},
			},
		},
	}
	if err := lc.Route.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision route: %v", err)
	}
	s := newSession(lc, conn)
	s.run()
	out := conn.Buffer.String()
	if strings.Contains(out, "503") {
		t.Errorf("null sender was rejected with 503: %s", out)
	}
	if !strings.Contains(out, "250 2.0.0 OK") {
		t.Errorf("null sender message was not accepted: %s", out)
	}
}

// TestSessionDataBeforeMail still requires a MAIL command; only a null sender
// is allowed, not a missing sender.
func TestSessionDataBeforeMail(t *testing.T) {
	t.Parallel()
	conn := newFakeConn()
	conn.Buffer.WriteString("EHLO test\r\nDATA\r\nQUIT\r\n")
	lc := &ListenerConfig{
		Port:           25,
		Hostname:       "mail.test",
		MaxMessageSize: 25 << 20,
		MaxRecipients:  50,
		TLS:            "off",
	}
	s := newSession(lc, conn)
	s.run()
	if out := conn.Buffer.String(); !strings.Contains(out, "503") {
		t.Errorf("DATA without MAIL should be 503, got: %s", out)
	}
}

// TestSessionResetClearsPlaceholders checks that clearing the transaction also
// clears the replacer, so a later route cannot observe a previous envelope.
func TestSessionResetClearsPlaceholders(t *testing.T) {
	t.Parallel()
	conn := newFakeConn()
	lc := &ListenerConfig{Port: 25, Hostname: "mail.test", TLS: "off"}
	s := newSession(lc, conn)
	s.handleMail("FROM:<a@b>")
	s.handleRcpt("TO:<c@d>")
	s.resetTransaction()

	if s.mailSeen || s.from != "" || len(s.rcpts) != 0 {
		t.Fatalf("session state not cleared: mailSeen=%v from=%q rcpts=%v", s.mailSeen, s.from, s.rcpts)
	}
	stale := map[string]string{"{smtp.from}": "a@b", "{smtp.rcpt}": "c@d", "{smtp.rcpts}": "c@d"}
	for ph, old := range stale {
		if got := s.repl.ReplaceAll(ph, ""); strings.Contains(got, old) {
			t.Errorf("placeholder %s still exposes %q after reset", ph, old)
		}
	}
}

// TestSessionCommandLineTooLong checks that an over-long command line is
// rejected and the session resynchronizes rather than buffering it whole.
func TestSessionCommandLineTooLong(t *testing.T) {
	t.Parallel()
	conn := newFakeConn()
	conn.Buffer.WriteString(strings.Repeat("A", maxCommandLine+100) + "\r\nNOOP\r\nQUIT\r\n")
	lc := &ListenerConfig{
		Port:           25,
		Hostname:       "mail.test",
		MaxMessageSize: 25 << 20,
		MaxRecipients:  50,
		TLS:            "off",
	}
	s := newSession(lc, conn)
	s.run()
	out := conn.Buffer.String()
	if !strings.Contains(out, "500") {
		t.Errorf("expected 500 for over-long command line, got: %s", out)
	}
	if !strings.Contains(out, "250 OK") {
		t.Errorf("session did not resynchronize after an over-long command line: %s", out)
	}
}

// TestSessionDataLineTooLong checks that a single body line past the cap is
// rejected with 552 instead of being buffered without bound.
func TestSessionDataLineTooLong(t *testing.T) {
	t.Parallel()
	conn := newFakeConn()
	conn.Buffer.WriteString(
		"EHLO test\r\n" +
			"MAIL FROM:<a@b>\r\n" +
			"RCPT TO:<c@d>\r\n" +
			"DATA\r\n" +
			strings.Repeat("A", maxDataLine+100) + "\r\n" +
			".\r\n" +
			"QUIT\r\n",
	)
	lc := &ListenerConfig{
		Port:           25,
		Hostname:       "mail.test",
		MaxMessageSize: 25 << 20,
		MaxRecipients:  50,
		TLS:            "off",
	}
	s := newSession(lc, conn)
	s.run()
	if out := conn.Buffer.String(); !strings.Contains(out, "552") {
		t.Errorf("expected 552 for over-long data line, got: %s", out)
	}
}
