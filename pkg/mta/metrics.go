package mta

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/frinknet/caddy-email/pkg/shared"
)

// metricsNamespace is deliberately not "caddy": these are this module's
// metrics, not Caddy core's, and sharing the "caddy" namespace invites a
// future name collision with upstream.
const metricsNamespace = "caddy_email"

// These collectors are registered into Caddy's per-context metrics registry
// (see registerMetrics), which is the registry Caddy serves from its /metrics
// endpoint. Registration happens in Provision, not at init, because the
// registry is created per config load.
var (
	metricEvents = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: "mta",
		Name:      "events_total",
		Help:      "Delivery events emitted by the outbound queue, by outcome.",
	}, []string{"event"})

	metricEnqueued = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: "mta",
		Name:      "enqueued_total",
		Help:      "Messages accepted into the outbound spool.",
	})

	metricNotifyDropped = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: "mta",
		Name:      "notify_dropped_total",
		Help:      "Delivery events dropped because the webhook buffer was full.",
	})
)

var spoolStates = []string{
	shared.StateIncoming, shared.StateActive, shared.StateDeferred,
	shared.StateBounce, shared.StateCorrupt,
}

// spoolCollector reports queue depth and disk usage for one spool directory.
//
// Both are computed at scrape time from a single walk, which is the correct
// pattern for state-of-the-world metrics: a timer-refreshed gauge is stale
// between ticks, and incremental bookkeeping across enqueue/claim/defer/
// bounce/unlink/sweep/recover drifts. A scrape is infrequent, so paying for
// one walk then is cheaper than maintaining the numbers continuously.
type spoolCollector struct {
	spoolDir string
	jobs     *prometheus.Desc
	bytes    *prometheus.Desc
}

func newSpoolCollector(spoolDir string) *spoolCollector {
	return &spoolCollector{
		spoolDir: spoolDir,
		jobs: prometheus.NewDesc(
			prometheus.BuildFQName(metricsNamespace, "mta", "spool_jobs"),
			"Queued jobs by spool state.",
			[]string{"state"}, nil,
		),
		bytes: prometheus.NewDesc(
			prometheus.BuildFQName(metricsNamespace, "mta", "spool_bytes"),
			"Total bytes held by the spool directory.",
			nil, nil,
		),
	}
}

func (c *spoolCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.jobs
	ch <- c.bytes
}

func (c *spoolCollector) Collect(ch chan<- prometheus.Metric) {
	counts := make(map[string]float64, len(spoolStates))
	for _, s := range spoolStates {
		counts[s] = 0
	}
	var total float64

	// Best effort: an unreadable entry is skipped rather than failing the
	// whole scrape.
	_ = filepath.WalkDir(c.spoolDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, ierr := d.Info(); ierr == nil {
			total += float64(info.Size())
		}
		name := d.Name()
		if strings.HasSuffix(name, ".tmp") || !strings.HasPrefix(name, "qf") {
			return nil
		}
		rel, rerr := filepath.Rel(c.spoolDir, path)
		if rerr != nil {
			return nil
		}
		state, _, _ := strings.Cut(rel, string(filepath.Separator))
		if _, ok := counts[state]; ok {
			counts[state]++
		}
		return nil
	})

	for _, s := range spoolStates {
		ch <- prometheus.MustNewConstMetric(c.jobs, prometheus.GaugeValue, counts[s], s)
	}
	ch <- prometheus.MustNewConstMetric(c.bytes, prometheus.GaugeValue, total)
}

// registerMetrics registers the MTA collectors with the given registry.
// AlreadyRegistered is ignored so a reload does not fail; the counters are
// shared, so the first registration wins.
func registerMetrics(reg *prometheus.Registry, spoolDir string) error {
	if reg == nil {
		return nil
	}
	// Materialize the labeled children so the families are discoverable before
	// the first event fires.
	for _, ev := range []string{"delivered", "deferred", "bounced"} {
		metricEvents.WithLabelValues(ev)
	}
	collectors := []prometheus.Collector{
		metricEvents, metricEnqueued, metricNotifyDropped, newSpoolCollector(spoolDir),
	}
	for _, c := range collectors {
		if err := reg.Register(c); err != nil {
			var already prometheus.AlreadyRegisteredError
			if !errors.As(err, &already) {
				return err
			}
		}
	}
	return nil
}
