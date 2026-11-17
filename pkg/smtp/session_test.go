package smtp

import (
	"bytes"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

type testHandler struct {
	fn func(w http.ResponseWriter, r *http.Request) error
}

func (h testHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	return h.fn(w, r)
}

type fakeConn struct {
	*bytes.Buffer
	remoteAddr net.Addr
	localAddr  net.Addr
}

func newFakeConn() *fakeConn {
	return &fakeConn{
		Buffer:     &bytes.Buffer{},
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
		localAddr:  &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 25},
	}
}

func (c *fakeConn) Close() error                       { return nil }
func (c *fakeConn) RemoteAddr() net.Addr               { return c.remoteAddr }
func (c *fakeConn) LocalAddr() net.Addr                { return c.localAddr }
func (c *fakeConn) SetDeadline(t time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(t time.Time) error { return nil }

func TestSplitCmd(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input    string
		wantCmd  string
		wantArgs string
	}{
		{"EHLO client.example.com", "EHLO", "client.example.com"},
		{"HELO", "HELO", ""},
		{"MAIL FROM:<alice@test>", "MAIL", "FROM:<alice@test>"},
		{"RCPT TO:<bob@test>", "RCPT", "TO:<bob@test>"},
		{"DATA", "DATA", ""},
		{"QUIT", "QUIT", ""},
		{"  NOOP  ", "NOOP", ""},
	}
	for _, tc := range tests {
		cmd, args := splitCmd(tc.input)
		if cmd != tc.wantCmd || args != tc.wantArgs {
			t.Errorf("splitCmd(%q) = (%q, %q), want (%q, %q)", tc.input, cmd, args, tc.wantCmd, tc.wantArgs)
		}
	}
}

func TestExtractAngle(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  string
	}{
		{"FROM:<alice@test>", "alice@test"},
		{"FROM:<>", ""},
		{"no angle", ""},
		{"<only-open", ""},
		{"only-close>", ""},
	}
	for _, tc := range tests {
		got := extractAngle(tc.input)
		if got != tc.want {
			t.Errorf("extractAngle(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// TestSessionEHLO verifies the advertised capability set for a receive-only
// listener. No AUTH, no relay gating, STARTTLS only when configured.
func TestSessionEHLO(t *testing.T) {
	t.Parallel()
	conn := newFakeConn()
	conn.Buffer.WriteString("EHLO client.test\r\nQUIT\r\n")
	lc := &ListenerConfig{
		Port:           25,
		Hostname:       "mail.test",
		MaxMessageSize: 10 << 20,
		MaxRecipients:  50,
		// TLS omitted → defaults to "off" in Provision, but we bypass
		// Provision here so set it explicitly to keep the test honest.
		TLS: "off",
	}
	s := newSession(lc, conn)
	s.run()
	out := conn.Buffer.String()
	if !strings.Contains(out, "250-mail.test") {
		t.Error("expected EHLO multi-line, got:", out)
	}
	if !strings.Contains(out, "SIZE") {
		t.Error("expected SIZE capability")
	}
	if !strings.Contains(out, "PIPELINING") {
		t.Error("expected PIPELINING capability")
	}
	if !strings.Contains(out, "ENHANCEDSTATUSCODES") {
		t.Error("expected ENHANCEDSTATUSCODES capability")
	}
	if strings.Contains(out, "STARTTLS") {
		t.Error("should not advertise STARTTLS when off")
	}
	if strings.Contains(out, "AUTH") {
		t.Error("should never advertise AUTH — receive-only listener")
	}
}

// TestSessionNoAuthNoTLS is the positive receive-only contract: an
// anonymous client that speaks plaintext SMTP is not gated at MAIL/RCPT.
// The route is the only policy surface.
func TestSessionNoAuthNoTLS(t *testing.T) {
	t.Parallel()
	conn := newFakeConn()
	conn.Buffer.WriteString(
		"EHLO stranger.test\r\n" +
			"MAIL FROM:<anyone@anywhere>\r\n" +
			"RCPT TO:<whoever@mail.test>\r\n" +
			"DATA\r\n" +
			"From: anyone@anywhere\r\n" +
			"To: whoever@mail.test\r\n" +
			"\r\n" +
			"hello\r\n" +
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
	if strings.Contains(out, "530") {
		t.Errorf("receive-only listener must not gate MAIL with 530: %s", out)
	}
	if strings.Contains(out, "550 Relay") {
		t.Errorf("receive-only listener must not gate MAIL with 550 Relay: %s", out)
	}
	if !strings.Contains(out, "250 2.0.0 OK") {
		t.Errorf("expected delivery accepted, got: %s", out)
	}
}

func TestSessionDataTooLarge(t *testing.T) {
	t.Parallel()
	conn := newFakeConn()
	body := strings.Repeat("x", 100)
	conn.Buffer.WriteString(
		"EHLO test\r\n" +
			"MAIL FROM:<a@b>\r\n" +
			"RCPT TO:<c@d>\r\n" +
			"DATA\r\n" +
			body + "\r\n" +
			".\r\n" +
			"QUIT\r\n",
	)
	lc := &ListenerConfig{
		Port:           25,
		Hostname:       "mail.test",
		MaxMessageSize: 50,
		MaxRecipients:  50,
		TLS:            "off",
	}
	s := newSession(lc, conn)
	s.run()
	out := conn.Buffer.String()
	if !strings.Contains(out, "552") {
		t.Error("expected 552 message too large, got:", out)
	}
}

func TestSessionFullFlow(t *testing.T) {
	t.Parallel()
	conn := newFakeConn()
	conn.Buffer.WriteString(
		"EHLO test\r\n" +
			"MAIL FROM:<a@b>\r\n" +
			"RCPT TO:<c@d>\r\n" +
			"DATA\r\n" +
			"From: a\r\n" +
			"To: c\r\n" +
			"Subject: test\r\n" +
			"\r\n" +
			"hello world\r\n" +
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
						if got := r.Header.Get("X-Envelope-From"); got != "a@b" {
							t.Errorf("X-Envelope-From = %q, want %q", got, "a@b")
						}
						if got := r.Header.Get("X-Envelope-To"); got != "c@d" {
							t.Errorf("X-Envelope-To = %q, want %q", got, "c@d")
						}
						if got := r.Header.Get("X-Client-Helo"); got != "test" {
							t.Errorf("X-Client-Helo = %q, want %q", got, "test")
						}
						if got := r.Header.Get("X-Client-IP"); got != "127.0.0.1:12345" {
							t.Errorf("X-Client-IP = %q", got)
						}
						if got := r.Header.Get("X-Smtp-TLS"); got != "" {
							t.Errorf("X-Smtp-TLS should be absent on plaintext, got %q", got)
						}
						body := make([]byte, r.ContentLength)
						if _, err := r.Body.Read(body); err != nil && err.Error() != "EOF" {
							t.Errorf("read body: %v", err)
						}
						if !strings.Contains(string(body), "hello world") {
							t.Errorf("body missing payload: %q", body)
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
	if !strings.Contains(out, "250 2.0.0 OK") {
		t.Errorf("expected delivery accepted, got: %s", out)
	}
}
