package mta

import "net"

// relayKey is the single MX-group key used when a relay is configured, so that
// per-MX concurrency applies to the smarthost as a whole rather than per
// recipient domain.
const relayKey = "relay"

// relaySpec reports the smarthost that every message is forwarded to, when one
// is configured. This is what lets the MTA hand all outbound mail to a
// downstream MTA (for example KumoMTA) instead of resolving MX and delivering
// directly.
//
// The port defaults to smtpPort (25). ok is false when no relay is set.
func (m *MTA) relaySpec() (host, port string, ok bool) {
	if m.Relay == "" {
		return "", "", false
	}
	h, p, err := net.SplitHostPort(m.Relay)
	if err != nil {
		// No port given: the whole spec is the host.
		h = m.Relay
	}
	if p == "" {
		p = m.smtpPort
	}
	if p == "" {
		p = "25"
	}
	return h, p, true
}

// dialPort is the port used to reach a delivery host: the relay port when
// relaying, otherwise the MX port (25 by default).
func (m *MTA) dialPort() string {
	if _, port, ok := m.relaySpec(); ok {
		return port
	}
	if m.smtpPort != "" {
		return m.smtpPort
	}
	return "25"
}
