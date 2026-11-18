package mta

import (
	"context"
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"

	"github.com/frinknet/caddy-email/pkg/shared"
)

// TestMetricsRegistered guards the integration contract: registerMetrics adds
// the MTA collectors to the registry Caddy serves from its /metrics endpoint,
// and doing it twice (a reload) is not an error.
func TestMetricsRegistered(t *testing.T) {
	reg := prometheus.NewRegistry()
	if err := registerMetrics(reg, newSpool(t)); err != nil {
		t.Fatalf("registerMetrics: %v", err)
	}
	if err := registerMetrics(reg, newSpool(t)); err != nil {
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
		"caddy_email_mta_events_total",
		"caddy_email_mta_enqueued_total",
		"caddy_email_mta_notify_dropped_total",
		"caddy_email_mta_spool_bytes",
		"caddy_email_mta_spool_jobs",
	} {
		if !present[name] {
			t.Errorf("%s not registered in the metrics registry", name)
		}
	}
}

func TestMetricsEnqueuedAndEvents(t *testing.T) {
	dir := newSpool(t)
	m := &MTA{SpoolDir: dir}

	before := testutil.ToFloat64(metricEnqueued)
	if _, err := m.Enqueue(context.Background(), &shared.Envelope{From: "a@b", To: []string{"c@d"}}, []byte("body")); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if got := testutil.ToFloat64(metricEnqueued); got != before+1 {
		t.Errorf("enqueued_total = %v, want %v", got, before+1)
	}

	for _, ev := range []string{"delivered", "deferred", "bounced"} {
		beforeEv := testutil.ToFloat64(metricEvents.WithLabelValues(ev))
		m.notify(shared.DeliveryEvent{Event: ev})
		if got := testutil.ToFloat64(metricEvents.WithLabelValues(ev)); got != beforeEv+1 {
			t.Errorf("events_total{%s} = %v, want %v", ev, got, beforeEv+1)
		}
	}
}

// TestMetricsSpoolCollector checks the scrape-time collector reports exact
// per-state job counts and total spool bytes, with no timer in between.
func TestMetricsSpoolCollector(t *testing.T) {
	dir := newSpool(t)
	env := &shared.Envelope{From: "a@b", To: []string{"c@d"}}
	for i := 0; i < 3; i++ {
		if _, err := shared.Enqueue(dir, env, []byte("body")); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
	}

	var wantBytes float64
	if err := filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, ierr := d.Info(); ierr == nil {
			wantBytes += float64(info.Size())
		}
		return nil
	}); err != nil {
		t.Fatalf("walk: %v", err)
	}

	reg := prometheus.NewRegistry()
	if err := reg.Register(newSpoolCollector(dir)); err != nil {
		t.Fatalf("register collector: %v", err)
	}

	if got := labeledGauge(t, reg, "caddy_email_mta_spool_jobs", "state", shared.StateIncoming); got != 3 {
		t.Errorf("spool_jobs{incoming} = %v, want 3", got)
	}
	if got := labeledGauge(t, reg, "caddy_email_mta_spool_jobs", "state", shared.StateActive); got != 0 {
		t.Errorf("spool_jobs{active} = %v, want 0", got)
	}
	if got := gaugeValue(t, reg, "caddy_email_mta_spool_bytes"); got != wantBytes {
		t.Errorf("spool_bytes = %v, want %v", got, wantBytes)
	}
}

func TestMetricsNotifyDropped(t *testing.T) {
	m := &MTA{NotifyURL: "https://example.com/hook"}
	// A zero-value notifyCh cannot accept the send, so the event is dropped.
	before := testutil.ToFloat64(metricNotifyDropped)
	m.notify(shared.DeliveryEvent{Event: "delivered"})
	if got := testutil.ToFloat64(metricNotifyDropped); got != before+1 {
		t.Errorf("notify_dropped_total = %v, want %v", got, before+1)
	}
}

// gaugeValue returns the value of the single series of a named gauge.
func gaugeValue(t *testing.T, reg *prometheus.Registry, name string) float64 {
	t.Helper()
	for _, f := range gather(t, reg) {
		if f.GetName() != name {
			continue
		}
		ms := f.GetMetric()
		if len(ms) != 1 {
			t.Fatalf("%s has %d series, want 1", name, len(ms))
		}
		return ms[0].GetGauge().GetValue()
	}
	t.Fatalf("metric %s not found", name)
	return 0
}

// labeledGauge returns the gauge value for a specific label pair.
func labeledGauge(t *testing.T, reg *prometheus.Registry, name, label, want string) float64 {
	t.Helper()
	for _, f := range gather(t, reg) {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == label && l.GetValue() == want {
					return m.GetGauge().GetValue()
				}
			}
		}
	}
	t.Fatalf("%s{%s=%q} not found", name, label, want)
	return 0
}

func gather(t *testing.T, reg *prometheus.Registry) []*dto.MetricFamily {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	return families
}
