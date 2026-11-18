package sendmail

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
)

// metricsNamespace is deliberately not "caddy": these are this module's
// metrics, not Caddy core's.
const metricsNamespace = "caddy_email"

// Registered into Caddy's per-context metrics registry (see registerMetrics),
// which is what Caddy serves from its /metrics endpoint.
var metricEnqueued = prometheus.NewCounter(prometheus.CounterOpts{
	Namespace: metricsNamespace,
	Subsystem: "sendmail",
	Name:      "enqueued_total",
	Help:      "Messages accepted by the sendmail HTTP API and queued for delivery.",
})

// registerMetrics registers the sendmail collector with the given registry,
// ignoring AlreadyRegistered so several sendmail handlers (or a reload) do not
// fail.
func registerMetrics(reg *prometheus.Registry) error {
	if reg == nil {
		return nil
	}
	if err := reg.Register(metricEnqueued); err != nil {
		var already prometheus.AlreadyRegisteredError
		if !errors.As(err, &already) {
			return err
		}
	}
	return nil
}
