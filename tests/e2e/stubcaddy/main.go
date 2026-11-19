// Command stubcaddy builds a Caddy binary that links the sendmail modules with
// a stand-in "mta" app that is not a shared.Enqueuer. The container e2e uses it
// to prove the sendmail template functions fail startup cleanly instead of
// panicking. The shipped image is built from the repository root instead.
package main

import (
	"net/http"

	"github.com/caddyserver/caddy/v2"
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	_ "github.com/frinknet/caddy-email/pkg/sendmail"
	_ "github.com/frinknet/caddy-email/tests/e2e/stubmta"
)

func main() {
	caddycmd.Main()
}

func init() {
	caddy.RegisterModule(trigger{})
}

// trigger provisions the sendmail template functions and nothing else, so the
// e2e reaches their Provision without pulling in Caddy's templates module.
type trigger struct {
	Ext caddy.ModuleMap `json:"ext,omitempty" caddy:"namespace=http.handlers.templates.functions"`
}

// CaddyModule returns the Caddy module information.
func (trigger) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.stubtrigger",
		New: func() caddy.Module { return new(trigger) },
	}
}

// Provision loads the configured template function modules.
func (t *trigger) Provision(ctx caddy.Context) error {
	_, err := ctx.LoadModule(t, "Ext")
	return err
}

// ServeHTTP passes the request through untouched.
func (t *trigger) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	return next.ServeHTTP(w, r)
}

var _ caddyhttp.MiddlewareHandler = (*trigger)(nil)
