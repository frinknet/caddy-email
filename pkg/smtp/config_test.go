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

// TestCaddyfileMaxIPClientsParsed guards the documented `max_ip_clients`
// option: dropping it in the adapter would silently fall back to the default
// cap and let one peer take every listener slot.
func TestCaddyfileMaxIPClientsParsed(t *testing.T) {
	t.Parallel()
	src := []byte(`{
    smtp :2525 {
        max_ip_clients 7
    }
}
`)
	adapter := caddyconfig.GetAdapter("caddyfile")
	if adapter == nil {
		t.Fatal("caddyfile adapter not registered")
	}
	adapted, _, err := adapter.Adapt(caddyfile.Format(src), nil)
	if err != nil {
		t.Fatalf("adapt: %v", err)
	}

	var cfg struct {
		Apps struct {
			SMTP struct {
				Listeners []struct {
					MaxIPClients int `json:"max_ip_clients"`
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
	if got := cfg.Apps.SMTP.Listeners[0].MaxIPClients; got != 7 {
		t.Fatalf("max_ip_clients = %d, want 7", got)
	}
}

// TestCaddyfileMaxIPRateParsed guards the documented `max_ip_rate` option:
// dropping it in the adapter would leave the listener without a connection
// rate cap while the operator believes one is configured.
func TestCaddyfileMaxIPRateParsed(t *testing.T) {
	t.Parallel()
	src := []byte(`{
    smtp :2525 {
        max_ip_rate 3
    }
}
`)
	adapter := caddyconfig.GetAdapter("caddyfile")
	if adapter == nil {
		t.Fatal("caddyfile adapter not registered")
	}
	adapted, _, err := adapter.Adapt(caddyfile.Format(src), nil)
	if err != nil {
		t.Fatalf("adapt: %v", err)
	}

	var cfg struct {
		Apps struct {
			SMTP struct {
				Listeners []struct {
					MaxIPRate int `json:"max_ip_rate"`
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
	if got := cfg.Apps.SMTP.Listeners[0].MaxIPRate; got != 3 {
		t.Fatalf("max_ip_rate = %d, want 3", got)
	}
}

// TestCaddyfileRepeatedSMTPBlocksKeepBothListeners guards the README promise
// that the block is repeatable: Caddy stores one value per global option, so
// the adapter must merge listeners across occurrences instead of letting the
// last block replace the first.
func TestCaddyfileRepeatedSMTPBlocksKeepBothListeners(t *testing.T) {
	t.Parallel()
	src := []byte(`{
    smtp :2525 {
        hostname mail.test
    }
    smtp :2526 {
        max_ip_clients 7
    }
}
`)
	adapter := caddyconfig.GetAdapter("caddyfile")
	if adapter == nil {
		t.Fatal("caddyfile adapter not registered")
	}
	adapted, _, err := adapter.Adapt(caddyfile.Format(src), nil)
	if err != nil {
		t.Fatalf("adapt: %v", err)
	}

	var cfg struct {
		Apps struct {
			SMTP struct {
				Listeners []struct {
					Port         int `json:"port"`
					MaxIPClients int `json:"max_ip_clients"`
				} `json:"listeners"`
			} `json:"smtp"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(adapted, &cfg); err != nil {
		t.Fatalf("decode adapted config: %v", err)
	}
	if n := len(cfg.Apps.SMTP.Listeners); n != 2 {
		t.Fatalf("listeners = %d, want 2", n)
	}
	if got := cfg.Apps.SMTP.Listeners[0].Port; got != 2525 {
		t.Fatalf("first listener port = %d, want 2525", got)
	}
	if got := cfg.Apps.SMTP.Listeners[1].Port; got != 2526 {
		t.Fatalf("second listener port = %d, want 2526", got)
	}
	if got := cfg.Apps.SMTP.Listeners[1].MaxIPClients; got != 7 {
		t.Fatalf("second listener max_ip_clients = %d, want 7", got)
	}
}
