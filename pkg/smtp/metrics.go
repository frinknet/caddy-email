package smtp

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
)

// metricsNamespace is deliberately not "caddy": these are this module's
// metrics, not Caddy core's.
const metricsNamespace = "caddy_email"

// Registered into Caddy's per-context metrics registry (see registerMetrics),
// which is what Caddy serves from its /metrics endpoint.
var (
	metricConnections = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: "smtp",
		Name:      "connections_total",
		Help:      "Inbound SMTP connections accepted.",
	})

	metricMessages = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: "smtp",
		Name:      "messages_total",
		Help:      "Inbound messages accepted by the route.",
	})
)

// registerMetrics registers the SMTP collectors with the given registry,
// ignoring AlreadyRegistered so multiple listeners or a reload do not fail.
func registerMetrics(reg *prometheus.Registry) error {
	if reg == nil {
		return nil
	}
	for _, c := range []prometheus.Collector{metricConnections, metricMessages} {
		if err := reg.Register(c); err != nil {
			var already prometheus.AlreadyRegisteredError
			if !errors.As(err, &already) {
				return err
			}
		}
	}
	return nil
}
