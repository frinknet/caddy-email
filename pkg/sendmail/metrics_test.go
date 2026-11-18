package sendmail

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/frinknet/caddy-email/pkg/shared"
)

// TestMetricsRegistered guards the integration contract: registerMetrics adds
// the sendmail collector to the registry Caddy serves from its /metrics
// endpoint, and registering twice (several handlers or a reload) is not an
// error.
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
	if !present["caddy_email_sendmail_enqueued_total"] {
		t.Error("caddy_email_sendmail_enqueued_total not registered in the metrics registry")
	}
}

type fakeEnqueuer struct {
	id  string
	err error
}

func (f fakeEnqueuer) Enqueue(context.Context, *shared.Envelope, []byte) (string, error) {
	return f.id, f.err
}

func TestMetricsEnqueued(t *testing.T) {
	s := &Sendmail{MaxBodySize: 30 << 20, enq: fakeEnqueuer{id: "q1"}}
	r := &http.Request{
		Method: http.MethodPost,
		Header: http.Header{
			"Content-Type": {"text/plain"},
			"From":         {"sender@test.com"},
			"To":           {"rcpt@test.com"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte("Hello World"))),
	}
	w := httptest.NewRecorder()

	before := testutil.ToFloat64(metricEnqueued)
	if err := s.ServeHTTP(w, r, nil); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if got := testutil.ToFloat64(metricEnqueued); got != before+1 {
		t.Errorf("enqueued_total = %v, want %v", got, before+1)
	}
}
