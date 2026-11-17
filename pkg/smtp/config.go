package smtp

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterGlobalOption("smtp", parseSMTPOption)
}

func parseSMTPOption(d *caddyfile.Dispenser, _ any) (any, error) {
	app := new(SMTP)
	for d.Next() {
		lc := &ListenerConfig{Port: 25}
		if d.NextArg() {
			arg := d.Val()
			if strings.HasPrefix(arg, ":") {
				if p, err := strconv.Atoi(arg[1:]); err == nil {
					lc.Port = p
				}
			}
		}
		for d.NextBlock(0) {
			switch d.Val() {
			case "hostname":
				if !d.AllArgs(&lc.Hostname) {
					return nil, d.ArgErr()
				}
			case "max_message_size":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				sz, err := strconv.ParseInt(d.Val(), 10, 64)
				if err != nil {
					return nil, err
				}
				lc.MaxMessageSize = sz
			case "max_recipients":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				n, err := strconv.Atoi(d.Val())
				if err != nil {
					return nil, err
				}
				lc.MaxRecipients = n
			case "max_connections":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				n, err := strconv.Atoi(d.Val())
				if err != nil {
					return nil, err
				}
				lc.MaxConnections = n
			case "deliver_timeout":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return nil, err
				}
				lc.DeliverTimeout = caddy.Duration(dur)
			case "tls":
				if !d.AllArgs(&lc.TLS) {
					return nil, d.ArgErr()
				}
			case "tls_cert_file":
				if !d.AllArgs(&lc.TLSCertFile) {
					return nil, d.ArgErr()
				}
			case "tls_key_file":
				if !d.AllArgs(&lc.TLSKeyFile) {
					return nil, d.ArgErr()
				}
			case "route":
				sr, err := httpcaddyfile.ParseSegmentAsSubroute(httpcaddyfile.Helper{
					Dispenser: d,
					State:     make(map[string]any),
				})
				if err != nil {
					return nil, err
				}
				lc.Route = sr.(*caddyhttp.Subroute)
			default:
				return nil, d.Errf("unknown smtp option: %s", d.Val())
			}
		}
		app.Listeners = append(app.Listeners, lc)
	}
	value, err := json.Marshal(app)
	if err != nil {
		return nil, err
	}
	return httpcaddyfile.App{Name: "smtp", Value: value}, nil
}
