package smtp

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func testServerCert(t *testing.T) *tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mail.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"mail.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// readSMTPReply reads one (possibly multi-line) SMTP reply and returns its
// final status code and the full text.
func readSMTPReply(t *testing.T, br *bufio.Reader) (int, string) {
	t.Helper()
	var full strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read reply: %v (so far %q)", err, full.String())
		}
		line = strings.TrimRight(line, "\r\n")
		full.WriteString(line)
		full.WriteString("\n")
		if len(line) < 4 || line[3] == '-' {
			continue
		}
		var code int
		if _, err := fmt.Sscanf(line[:3], "%d", &code); err != nil {
			t.Fatalf("malformed reply %q", line)
		}
		return code, full.String()
	}
}

// TestSessionSTARTTLSResetsState drives a real TLS handshake and asserts that
// pre-TLS session state is discarded (RFC 3207 section 4.2) and that STARTTLS
// cannot be negotiated a second time.
func TestSessionSTARTTLSResetsState(t *testing.T) {
	cert := testServerCert(t)
	c1, c2 := net.Pipe()
	t.Cleanup(func() { c1.Close(); c2.Close() })
	if err := c2.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	heloSeen := make(chan string, 1)
	route := &caddyhttp.Subroute{
		Routes: caddyhttp.RouteList{
			{Handlers: []caddyhttp.MiddlewareHandler{
				testHandler{fn: func(w http.ResponseWriter, r *http.Request) error {
					helo := ""
					if repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer); ok {
						helo = repl.ReplaceAll("{smtp.helo}", "")
					}
					select {
					case heloSeen <- helo:
					default:
					}
					w.WriteHeader(http.StatusOK)
					return nil
				}},
			}},
		},
	}
	if err := route.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision route: %v", err)
	}

	lc := &ListenerConfig{
		Port:           587,
		Hostname:       "mail.test",
		TLS:            "starttls",
		tlsCert:        cert,
		MaxMessageSize: 1 << 20,
		MaxRecipients:  5,
		DeliverTimeout: caddy.Duration(5 * time.Second),
		Route:          route,
	}
	s := newSession(lc, c1)
	go s.run()

	br := bufio.NewReader(c2)
	if code, txt := readSMTPReply(t, br); code != 220 {
		t.Fatalf("greeting = %d (%s), want 220", code, txt)
	}
	if _, err := fmt.Fprint(c2, "EHLO client.test\r\n"); err != nil {
		t.Fatalf("write EHLO: %v", err)
	}
	if code, txt := readSMTPReply(t, br); code != 250 {
		t.Fatalf("EHLO = %d (%s), want 250", code, txt)
	}
	if _, err := fmt.Fprint(c2, "STARTTLS\r\n"); err != nil {
		t.Fatalf("write STARTTLS: %v", err)
	}
	if code, txt := readSMTPReply(t, br); code != 220 {
		t.Fatalf("STARTTLS = %d (%s), want 220", code, txt)
	}

	tlsConn := tls.Client(c2, &tls.Config{InsecureSkipVerify: true, ServerName: "mail.test"})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("tls handshake: %v", err)
	}
	tbr := bufio.NewReader(tlsConn)

	// STARTTLS must not be accepted a second time.
	if _, err := fmt.Fprint(tlsConn, "STARTTLS\r\n"); err != nil {
		t.Fatalf("write second STARTTLS: %v", err)
	}
	if code, txt := readSMTPReply(t, tbr); code != 503 {
		t.Errorf("second STARTTLS = %d (%s), want 503", code, txt)
	}

	// No EHLO after the handshake, so the client name from before it must be
	// gone. The route observes that as an empty {smtp.helo}.
	for _, cmd := range []string{"MAIL FROM:<a@b>\r\n", "RCPT TO:<c@d>\r\n"} {
		if _, err := fmt.Fprint(tlsConn, cmd); err != nil {
			t.Fatalf("write %q: %v", cmd, err)
		}
		if code, txt := readSMTPReply(t, tbr); code != 250 {
			t.Fatalf("%q = %d (%s), want 250", cmd, code, txt)
		}
	}
	if _, err := fmt.Fprint(tlsConn, "DATA\r\n"); err != nil {
		t.Fatalf("write DATA: %v", err)
	}
	if code, txt := readSMTPReply(t, tbr); code != 354 {
		t.Fatalf("DATA = %d (%s), want 354", code, txt)
	}
	if _, err := fmt.Fprint(tlsConn, "Subject: hi\r\n\r\nbody\r\n.\r\n"); err != nil {
		t.Fatalf("write body: %v", err)
	}
	if code, txt := readSMTPReply(t, tbr); code != 250 {
		t.Fatalf("end of DATA = %d (%s), want 250", code, txt)
	}

	select {
	case helo := <-heloSeen:
		if helo != "" {
			t.Errorf("pre-TLS EHLO leaked across STARTTLS: {smtp.helo} = %q, want empty", helo)
		}
	default:
		t.Fatal("route did not run")
	}
}

// TestSessionSTARTTLSRefusedDuringTransaction checks the state guard that runs
// before any TLS bytes are exchanged.
func TestSessionSTARTTLSRefusedDuringTransaction(t *testing.T) {
	t.Parallel()
	conn := newFakeConn()
	conn.Buffer.WriteString("EHLO test\r\nMAIL FROM:<a@b>\r\nSTARTTLS\r\nQUIT\r\n")
	lc := &ListenerConfig{
		Port:     587,
		Hostname: "mail.test",
		TLS:      "starttls",
		tlsCert:  &tls.Certificate{},
	}
	s := newSession(lc, conn)
	s.run()
	if out := conn.Buffer.String(); !strings.Contains(out, "503") {
		t.Errorf("STARTTLS during a transaction should be 503, got: %s", out)
	}
}
