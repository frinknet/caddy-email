package smtp

import (
	"net"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestMetricsRegistered guards the integration contract: registerMetrics adds
// the SMTP collectors to the registry Caddy serves from its /metrics endpoint,
// and registering twice (multiple listeners or a reload) is not an error.
func TestMetricsRegistered(t *testing.T) {
	reg := prometheus.NewRegistry()
	if err := registerMetrics(reg); err != nil {
		t.Fatalf("registerMetrics: %v", err)
	}
	if err := registerMetrics(reg); err != nil {
		t.Fatalf("second registerMetrics: %v", err)
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	present := make(map[string]bool, len(families))
	for _, f := range families {
		present[f.GetName()] = true
	}
	for _, name := range []string{
		"caddy_email_smtp_connections_total",
		"caddy_email_smtp_messages_total",
	} {
		if !present[name] {
			t.Errorf("%s not registered in the metrics registry", name)
		}
	}
}

// oneShotListener yields a single connection then fails, so a listener loop
// can be driven for exactly one accept.
type oneShotListener struct {
	conn net.Conn
	done bool
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	if !l.done {
		l.done = true
		return l.conn, nil
	}
	return nil, &net.OpError{Op: "accept", Err: net.ErrClosed}
}
func (l *oneShotListener) Close() error   { return nil }
func (l *oneShotListener) Addr() net.Addr { return &net.TCPAddr{} }

func TestMetricsMessages(t *testing.T) {
	conn := newFakeConn()
	conn.Buffer.WriteString(
		"EHLO test\r\n" +
			"MAIL FROM:<a@b>\r\n" +
			"RCPT TO:<c@d>\r\n" +
			"DATA\r\n" +
			"From: a\r\nTo: c\r\nSubject: test\r\n\r\nhi\r\n.\r\n" +
			"QUIT\r\n",
	)
	lc := &ListenerConfig{
		Port:           25,
		Hostname:       "mail.test",
		MaxMessageSize: 25 << 20,
		MaxRecipients:  50,
		TLS:            "off",
	}

	before := testutil.ToFloat64(metricMessages)
	newSession(lc, conn).run()
	if got := testutil.ToFloat64(metricMessages); got != before+1 {
		t.Errorf("messages_total = %v, want %v", got, before+1)
	}
}

func TestMetricsConnections(t *testing.T) {
	lc := &ListenerConfig{
		Port:           25,
		Hostname:       "mail.test",
		MaxMessageSize: 25 << 20,
		MaxRecipients:  50,
		MaxConnections: 10,
		TLS:            "off",
	}
	s := &SMTP{Listeners: []*ListenerConfig{lc}, stopCh: make(chan struct{})}
	close(s.stopCh)

	before := testutil.ToFloat64(metricConnections)
	s.wg.Add(1)
	s.serve(lc, &oneShotListener{conn: newFakeConn()})
	if got := testutil.ToFloat64(metricConnections); got != before+1 {
		t.Errorf("connections_total = %v, want %v", got, before+1)
	}
}
