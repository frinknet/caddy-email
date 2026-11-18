// End-to-end check of the SMTP route: a real Caddy instance receives a message
// over SMTP, dispatches it through reverse_proxy, and the backend sees only the
// allowlisted message headers.
package e2e

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"

	_ "github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
)

type deliveredRequest struct {
	header http.Header
	body   string
}

func TestSMTPRouteHeaderAllowlist(t *testing.T) {
	delivered := make(chan deliveredRequest, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		delivered <- deliveredRequest{header: r.Header.Clone(), body: string(body)}
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	smtpPort := freePort(t, ":0")
	upstream := strings.TrimPrefix(backend.URL, "http://")

	caddyfile := fmt.Sprintf(`{
    admin off
    log {
        level ERROR
    }
    smtp :%d {
        hostname mail.test
        tls off
        route {
            reverse_proxy %s
        }
    }
}
`, smtpPort, upstream)

	adapter := caddyconfig.GetAdapter("caddyfile")
	if adapter == nil {
		t.Fatal("caddyfile adapter not registered")
	}
	adapted, warnings, err := adapter.Adapt([]byte(caddyfile), nil)
	if err != nil {
		t.Fatalf("adapt Caddyfile: %v", err)
	}
	for _, w := range warnings {
		t.Logf("adapt warning: %s", w)
	}

	if err := caddy.Load(adapted, true); err != nil {
		t.Fatalf("load config: %v", err)
	}
	t.Cleanup(func() { caddy.Stop() })

	addr := fmt.Sprintf("127.0.0.1:%d", smtpPort)
	var conn net.Conn
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err = net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("SMTP listener never became ready: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	script := "EHLO test\r\n" +
		"MAIL FROM:<a@b>\r\n" +
		"RCPT TO:<c@d>\r\n" +
		"DATA\r\n" +
		"From: sender@example.com\r\n" +
		"Subject: header test\r\n" +
		"Message-ID: <abc@example.com>\r\n" +
		"X-Spam-Status: No\r\n" +
		"Authorization: Bearer evil\r\n" +
		"Cookie: session=evil\r\n" +
		"X-Forwarded-For: 10.0.0.1\r\n" +
		"Content-Length: 999999\r\n" +
		"X-Envelope-From: attacker@evil.example\r\n" +
		"\r\n" +
		"hello from the wire\r\n" +
		".\r\n" +
		"QUIT\r\n"
	if _, err := conn.Write([]byte(script)); err != nil {
		t.Fatalf("write SMTP script: %v", err)
	}
	out, _ := io.ReadAll(conn)
	if !strings.Contains(string(out), "250 2.0.0 OK") {
		t.Fatalf("SMTP exchange did not accept the message; server said:\n%s", out)
	}

	var got deliveredRequest
	select {
	case got = <-delivered:
	case <-time.After(5 * time.Second):
		t.Fatal("route did not reach the backend within 5s")
	}

	for name, want := range map[string]string{
		"From":          "sender@example.com",
		"Subject":       "header test",
		"Message-ID":    "<abc@example.com>",
		"X-Spam-Status": "No",
	} {
		if v := got.header.Get(name); v != want {
			t.Errorf("backend %s = %q, want %q", name, v, want)
		}
	}

	if v := got.header.Get("X-Envelope-From"); v != "a@b" {
		t.Errorf("backend X-Envelope-From = %q, want envelope sender a@b", v)
	}
	for _, name := range []string{"Authorization", "Cookie"} {
		if v := got.header.Get(name); v != "" {
			t.Errorf("sender-controlled %s reached the backend: %q", name, v)
		}
	}
	// reverse_proxy writes its own X-Forwarded-For; the injected value must not
	// survive into it.
	if v := got.header.Get("X-Forwarded-For"); strings.Contains(v, "10.0.0.1") {
		t.Errorf("injected X-Forwarded-For reached the backend: %q", v)
	}
	if v := got.header.Get("Content-Length"); v == "999999" {
		t.Errorf("injected Content-Length reached the backend")
	}
	if !strings.Contains(got.body, "hello from the wire") {
		t.Errorf("backend body = %q, want message payload", got.body)
	}
}
