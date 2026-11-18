package smtp

import (
	"encoding/json"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	_ "github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
)

// TestCaddyfileRouteParsed guards the documented `route { ... }` syntax: the
// block must survive adaptation into the app's JSON config, otherwise the
// listener would silently accept every message without dispatching.
func TestCaddyfileRouteParsed(t *testing.T) {
	t.Parallel()
	src := []byte(`{
    smtp :2525 {
        hostname mail.test
        route {
            @internal remote_ip 10.0.0.0/8
            reverse_proxy @internal 127.0.0.1:9999
            respond "Relay not permitted" 550
        }
    }
}
`)
	adapter := caddyconfig.GetAdapter("caddyfile")
	if adapter == nil {
		t.Fatal("caddyfile adapter not registered")
	}
	adapted, warnings, err := adapter.Adapt(caddyfile.Format(src), nil)
	if err != nil {
		t.Fatalf("adapt: %v", err)
	}
	if len(warnings) > 0 {
		t.Errorf("unexpected adapt warnings: %v", warnings)
	}

	var cfg struct {
		Apps struct {
			SMTP struct {
				Listeners []struct {
					Route *struct {
						Routes []struct {
							Handle []map[string]any `json:"handle"`
						} `json:"routes"`
					} `json:"route"`
				} `json:"listeners"`
			} `json:"smtp"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(adapted, &cfg); err != nil {
		t.Fatalf("decode adapted config: %v", err)
	}
	if n := len(cfg.Apps.SMTP.Listeners); n != 1 {
		t.Fatalf("listeners = %d, want 1", n)
	}
	route := cfg.Apps.SMTP.Listeners[0].Route
	if route == nil {
		t.Fatal("route block was dropped from the adapted config")
	}
	if len(route.Routes) != 2 {
		t.Fatalf("route routes = %d, want 2", len(route.Routes))
	}
	if n := len(route.Routes[0].Handle); n == 0 {
		t.Error("first route has no handlers")
	}
}
