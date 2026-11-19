// Package stubmta registers an app with the ID "mta" that deliberately does
// not implement shared.Enqueuer. It exists only for the end-to-end test that
// proves sendmail's Provision returns a startup error, rather than panicking
// on an unchecked type assertion, when the app behind "mta" is the wrong type.
//
// It must never be linked into the shipped binary, which imports pkg/mta
// instead; two registrations of the same module ID panic at init.
package stubmta

import "github.com/caddyserver/caddy/v2"

func init() {
	caddy.RegisterModule(MTA{})
}

// MTA is an app module named "mta" with no Enqueue method.
type MTA struct{}

// CaddyModule returns the Caddy module information.
func (MTA) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "mta",
		New: func() caddy.Module { return new(MTA) },
	}
}

// Provision is a no-op so the app loads.
func (*MTA) Provision(caddy.Context) error { return nil }
