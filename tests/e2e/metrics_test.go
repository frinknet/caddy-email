// Package e2e boots a real Caddy instance with the email modules loaded and
// exercises the full paths: an HTTP request into the sendmail handler, an SMTP
// session into the smtp app, enqueue via the MTA app, then a scrape of Caddy's
// own metrics handler.
package e2e

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"

	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp"
	_ "github.com/caddyserver/caddy/v2/modules/metrics"

	_ "github.com/frinknet/caddy-email/pkg/mta"
	_ "github.com/frinknet/caddy-email/pkg/sendmail"
	_ "github.com/frinknet/caddy-email/pkg/smtp"
)

// freePort asks the kernel for an unused port on the same address the server
// will bind, so the probe cannot disagree with the real bind.
func freePort(t *testing.T, addr string) int {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("find free port on %s: %v", addr, err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		return 0, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// metricValue returns the value of an unlabeled metric line, or -1 if absent.
func metricValue(body, name string) float64 {
	for _, line := range strings.Split(body, "\n") {
		if rest, ok := strings.CutPrefix(line, name+" "); ok {
			f, err := strconv.ParseFloat(strings.TrimSpace(rest), 64)
			if err == nil {
				return f
			}
		}
	}
	return -1
}

// smtpDeliver runs one full SMTP transaction against addr and fails unless the
// message is accepted.
func smtpDeliver(t *testing.T, addr string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial SMTP %s: %v", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	script := "EHLO test\r\n" +
		"MAIL FROM:<a@b>\r\n" +
		"RCPT TO:<c@d>\r\n" +
		"DATA\r\n" +
		"Subject: x\r\n" +
		"\r\n" +
		"hi\r\n" +
		".\r\n" +
		"QUIT\r\n"
	if _, err := conn.Write([]byte(script)); err != nil {
		t.Fatalf("write SMTP script: %v", err)
	}
	out, _ := io.ReadAll(conn)
	if !strings.Contains(string(out), "250 2.0.0 OK") {
		t.Fatalf("SMTP exchange did not accept the message; server said:\n%s", out)
	}
}

func TestMetricsEndToEnd(t *testing.T) {
	// The HTTP server binds loopback explicitly; the SMTP listener binds all
	// interfaces (":port"). Probe the same address each will use.
	httpPort := freePort(t, "127.0.0.1:0")
	smtpPort := freePort(t, ":0")
	spool := t.TempDir()

	cfg := fmt.Sprintf(`{
  "admin": {"disabled": true},
  "logging": {"logs": {"default": {"level": "ERROR"}}},
  "apps": {
    "mta": {"spool_dir": %q, "settle_delay": "1h"},
    "smtp": {"listeners": [{"port": %d, "hostname": "mail.test", "tls": "off", "max_connections": 10}]},
    "http": {
      "servers": {
        "srv0": {
          "listen": ["127.0.0.1:%d"],
          "routes": [
            {"match": [{"path": ["/sendmail/*"]}], "handle": [{"handler": "sendmail", "from": "no-reply@example.com"}]},
            {"match": [{"path": ["/metrics"]}], "handle": [{"handler": "metrics"}]}
          ]
        }
      }
    }
  }
}`, spool, smtpPort, httpPort)

	if err := caddy.Load([]byte(cfg), true); err != nil {
		t.Fatalf("load config: %v", err)
	}
	t.Cleanup(func() { caddy.Stop() })

	base := fmt.Sprintf("http://127.0.0.1:%d", httpPort)
	ready := false
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if code, _ := get(t, base+"/metrics"); code == http.StatusOK {
			ready = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatal("Caddy server did not become ready within 10s")
	}

	// Leg 1: HTTP sendmail handler -> MTA enqueue.
	req, err := http.NewRequest(http.MethodPost, base+"/sendmail/", bytes.NewReader([]byte("hello world")))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("From", "sender@example.com")
	req.Header.Set("To", "rcpt@example.com")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /sendmail/: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /sendmail/ status = %d, want %d", resp.StatusCode, http.StatusAccepted)
	}

	// Leg 2: inbound SMTP session.
	smtpDeliver(t, fmt.Sprintf("127.0.0.1:%d", smtpPort))

	code, body := get(t, base+"/metrics")
	if code != http.StatusOK {
		t.Fatalf("GET /metrics status = %d, want 200", code)
	}

	for _, name := range []string{
		"caddy_email_sendmail_enqueued_total",
		"caddy_email_mta_enqueued_total",
		"caddy_email_mta_notify_dropped_total",
		"caddy_email_mta_spool_bytes",
		"caddy_email_mta_spool_jobs",
		"caddy_email_smtp_connections_total",
		"caddy_email_smtp_messages_total",
	} {
		if !strings.Contains(body, name) {
			t.Errorf("metric %s missing from /metrics output", name)
		}
	}

	for name, want := range map[string]float64{
		"caddy_email_sendmail_enqueued_total": 1,
		"caddy_email_mta_enqueued_total":      1,
		"caddy_email_smtp_connections_total":  1,
		"caddy_email_smtp_messages_total":     1,
	} {
		if got := metricValue(body, name); got != want {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
	// The spool gauges are computed at scrape time, so they are exact: the one
	// enqueued job sits in incoming/ (settle_delay keeps the tick from
	// claiming it).
	if got := metricValue(body, `caddy_email_mta_spool_jobs{state="incoming"}`); got != 1 {
		t.Errorf(`caddy_email_mta_spool_jobs{state="incoming"} = %v, want 1`, got)
	}
}
