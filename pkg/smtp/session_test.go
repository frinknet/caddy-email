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

func (c *fakeConn) Close() error                      { return nil }
func (c *fakeConn) RemoteAddr() net.Addr               { return c.remoteAddr }
func (c *fakeConn) LocalAddr() net.Addr                { return c.localAddr }
func (c *fakeConn) SetDeadline(t time.Time) error       { return nil }
func (c *fakeConn) SetReadDeadline(t time.Time) error   { return nil }
func (c *fakeConn) SetWriteDeadline(t time.Time) error  { return nil }

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

func TestSessionEHLO(t *testing.T) {
	t.Parallel()
	conn := newFakeConn()
	conn.Buffer.WriteString("EHLO client.test\r\nQUIT\r\n")
	lc := &ListenerConfig{
		Port:           25,
		Hostname:       "mail.test",
		MaxMessageSize: 10 << 20,
		MaxRecipients:  50,
		Auth:           "off",
		TLS:            "off",
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
	if strings.Contains(out, "STARTTLS") {
		t.Error("should not advertise STARTTLS when off")
	}
	if strings.Contains(out, "AUTH") {
		t.Error("should not advertise AUTH when off")
	}
}

func TestSessionEHLOWithAuth(t *testing.T) {
	t.Parallel()
	conn := newFakeConn()
	conn.Buffer.WriteString("EHLO client.test\r\nQUIT\r\n")
	lc := &ListenerConfig{
		Port:          587,
		Hostname:      "mail.test",
		MaxRecipients: 50,
		Auth:          "required",
		TLS:           "starttls",
	}
	s := newSession(lc, conn)
	s.run()
	out := conn.Buffer.String()
	if !strings.Contains(out, "AUTH PLAIN") {
		t.Error("expected AUTH PLAIN capability, got:", out)
	}
	if !strings.Contains(out, "STARTTLS") {
		t.Error("expected STARTTLS capability")
	}
}

func TestSessionMailRequiresAuth(t *testing.T) {
	t.Parallel()
	conn := newFakeConn()
	conn.Buffer.WriteString("EHLO client.test\r\nMAIL FROM:<alice@test>\r\nQUIT\r\n")
	lc := &ListenerConfig{
		Port:          587,
		Hostname:      "mail.test",
		MaxRecipients: 50,
		Auth:          "required",
		TLS:           "off",
	}
	s := newSession(lc, conn)
	s.run()
	out := conn.Buffer.String()
	if !strings.Contains(out, "530 Authentication required") {
		t.Error("expected auth required, got:", out)
	}
}

func TestSessionMailRequiresTLS(t *testing.T) {
	t.Parallel()
	conn := newFakeConn()
	conn.Buffer.WriteString("EHLO client.test\r\nMAIL FROM:<alice@test>\r\nQUIT\r\n")
	lc := &ListenerConfig{
		Port:          587,
		Hostname:      "mail.test",
		MaxRecipients: 50,
		Auth:          "off",
		TLS:           "starttls",
	}
	s := newSession(lc, conn)
	s.run()
	out := conn.Buffer.String()
	if !strings.Contains(out, "530 STARTTLS required") {
		t.Error("expected STARTTLS required, got:", out)
	}
}

func TestSessionRelayNotPermitted(t *testing.T) {
	t.Parallel()
	conn := newFakeConn()
	conn.Buffer.WriteString("EHLO external.test\r\nMAIL FROM:<alice@other.com>\r\nQUIT\r\n")
	lc := &ListenerConfig{
		Port:          25,
		Hostname:      "mail.test",
		MaxRecipients: 50,
		Auth:          "off",
		TLS:           "off",
	}
	s := newSession(lc, conn)
	s.run()
	out := conn.Buffer.String()
	if !strings.Contains(out, "550 Relay not permitted") {
		t.Error("expected relay not permitted, got:", out)
	}
}

func TestSessionTrustedIPBypassesRelayCheck(t *testing.T) {
	t.Parallel()
	conn := newFakeConn()
	conn.Buffer.WriteString("EHLO trusted.test\r\nMAIL FROM:<alice@test>\r\nRCPT TO:<bob@test>\r\nDATA\r\nFrom: alice\r\nTo: bob\r\n\r\nhello\r\n.\r\nQUIT\r\n")
	lc := &ListenerConfig{
		Port:              25,
		Hostname:          "mail.test",
		PermitMyNetworks:  []string{"127.0.0.0/8"},
		MaxMessageSize:    25 << 20,
		MaxRecipients:     50,
		Auth:              "off",
		TLS:               "off",
		Route: &caddyhttp.Subroute{
			Routes: caddyhttp.RouteList{
				{Handlers: []caddyhttp.MiddlewareHandler{
					testHandler{fn: func(w http.ResponseWriter, r *http.Request) error {
						w.WriteHeader(200)
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
		t.Error("expected delivery accepted, got:", out)
	}
}

func TestSessionDataTooLarge(t *testing.T) {
	t.Parallel()
	conn := newFakeConn()
	body := strings.Repeat("x", 100)
	conn.Buffer.WriteString("EHLO test\r\nMAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\nDATA\r\n" + body + "\r\n.\r\nQUIT\r\n")
	lc := &ListenerConfig{
		Port:              25,
		Hostname:          "mail.test",
		PermitMyNetworks:  []string{"127.0.0.0/8"},
		MaxMessageSize:    50,
		MaxRecipients:     50,
		Auth:              "off",
		TLS:               "off",
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
	conn.Buffer.WriteString("EHLO test\r\nMAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\nDATA\r\nFrom: a\r\nTo: c\r\nSubject: test\r\n\r\nhello world\r\n.\r\nQUIT\r\n")
	lc := &ListenerConfig{
		Port:              25,
		Hostname:          "mail.test",
		PermitMyNetworks:  []string{"127.0.0.0/8"},
		MaxMessageSize:    25 << 20,
		MaxRecipients:     50,
		Auth:              "off",
		TLS:               "off",
		Route: &caddyhttp.Subroute{
			Routes: caddyhttp.RouteList{
				{Handlers: []caddyhttp.MiddlewareHandler{
					testHandler{fn: func(w http.ResponseWriter, r *http.Request) error {
						if r.Header.Get("X-Envelope-From") != "a@b" {
							t.Error("missing envelope from")
						}
						if r.Header.Get("X-Envelope-To") != "c@d" {
							t.Error("missing envelope to")
						}
						w.WriteHeader(200)
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
		t.Error("expected success, got:", out)
	}
}

func TestSessionRouteReturnsError(t *testing.T) {
	t.Parallel()
	conn := newFakeConn()
	conn.Buffer.WriteString("EHLO test\r\nMAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\nDATA\r\nFrom: a\r\nTo: c\r\n\r\nhello\r\n.\r\nQUIT\r\n")
	lc := &ListenerConfig{
		Port:              25,
		Hostname:          "mail.test",
		PermitMyNetworks:  []string{"127.0.0.0/8"},
		MaxMessageSize:    25 << 20,
		MaxRecipients:     50,
		Auth:              "off",
		TLS:               "off",
		Route: &caddyhttp.Subroute{
			Routes: caddyhttp.RouteList{
				{Handlers: []caddyhttp.MiddlewareHandler{
					testHandler{fn: func(w http.ResponseWriter, r *http.Request) error {
						return caddyhttp.Error(500, nil)
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
	if !strings.Contains(out, "451") {
		t.Error("expected 451 temporary failure, got:", out)
	}
}

func TestMapStatus(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input    int
		wantCode int
	}{
		{0, 250}, {200, 250}, {302, 250},
		{400, 451}, {403, 451},
		{502, 451}, {503, 451}, {504, 451},
		{500, 550}, {550, 550},
	}
	for _, tc := range tests {
		code, _ := mapStatus(tc.input)
		if code != tc.wantCode {
			t.Errorf("mapStatus(%d) = %d, want %d", tc.input, code, tc.wantCode)
		}
	}
}

func TestParseHeaderLines(t *testing.T) {
	t.Parallel()
	raw := []byte("From: alice\r\nTo: bob\r\nSubject: test\r\n\r\nbody")
	headers := parseHeaderLines(raw)
	if len(headers) != 3 {
		t.Fatalf("expected 3 headers, got %d", len(headers))
	}
	if headers[0][0] != "From" || headers[0][1] != "alice" {
		t.Errorf("header 0 = %v", headers[0])
	}
	if headers[2][0] != "Subject" || headers[2][1] != "test" {
		t.Errorf("header 2 = %v", headers[2])
	}
}

func TestSplitBody(t *testing.T) {
	t.Parallel()
	body := splitBody([]byte("header: val\r\n\r\nthis is the body"))
	if string(body) != "this is the body" {
		t.Errorf("got %q", body)
	}
	body = splitBody([]byte("just body"))
	if string(body) != "just body" {
		t.Errorf("got %q", body)
	}
}

func TestIsTrustedIP(t *testing.T) {
	t.Parallel()
	lc := &ListenerConfig{
		PermitMyNetworks: []string{"10.0.0.0/8", "192.168.0.0/16"},
		MaxRecipients:    50,
	}
	trusted := []string{"10.1.2.3:45678", "192.168.1.1:25"}
	untrusted := []string{"8.8.8.8:1234", "1.2.3.4:5678"}

	for _, addr := range trusted {
		host, _, _ := net.SplitHostPort(addr)
		conn := &fakeConn{
			Buffer:     &bytes.Buffer{},
			remoteAddr: &net.TCPAddr{IP: net.ParseIP(host), Port: 45678},
			localAddr:  &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 25},
		}
		s := newSession(lc, conn)
		if !s.isTrustedIP() {
			t.Errorf("expected %s to be trusted", addr)
		}
	}
	for _, addr := range untrusted {
		host, _, _ := net.SplitHostPort(addr)
		conn := &fakeConn{
			Buffer:     &bytes.Buffer{},
			remoteAddr: &net.TCPAddr{IP: net.ParseIP(host), Port: 45678},
			localAddr:  &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 25},
		}
		s := newSession(lc, conn)
		if s.isTrustedIP() {
			t.Errorf("expected %s to be untrusted", addr)
		}
	}
}
