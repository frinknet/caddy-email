package smtp

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
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
				sr, err := parseRouteBlock(d)
				if err != nil {
					return nil, err
				}
				lc.Route = sr
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

// parseRouteBlock parses the smtp `route` block into a Subroute. The block
// holds ordinary HTTP directive syntax, so it is re-rendered as a throwaway
// Caddyfile and adapted: httpcaddyfile.ParseSegmentAsSubroute requires a
// Helper the adapter builds itself, and a global option cannot supply one.
func parseRouteBlock(d *caddyfile.Dispenser) (*caddyhttp.Subroute, error) {
	adapter := caddyconfig.GetAdapter("caddyfile")
	if adapter == nil {
		return nil, d.Errf("smtp route: caddyfile adapter is not registered")
	}
	src := caddyfile.Format([]byte(":80 {\n" + renderSegment(d.NewFromNextSegment()) + "\n}\n"))
	adapted, _, err := adapter.Adapt(src, nil)
	if err != nil {
		return nil, d.WrapErr(err)
	}

	var parsed struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Routes []struct {
						Handle []json.RawMessage `json:"handle"`
					} `json:"routes"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(adapted, &parsed); err != nil {
		return nil, d.WrapErr(err)
	}
	for _, srv := range parsed.Apps.HTTP.Servers {
		for _, route := range srv.Routes {
			if len(route.Handle) == 0 {
				continue
			}
			var sr caddyhttp.Subroute
			if err := json.Unmarshal(route.Handle[0], &sr); err != nil {
				return nil, d.WrapErr(err)
			}
			return &sr, nil
		}
	}
	return nil, d.Errf("smtp route: block produced no HTTP handlers")
}

// renderSegment writes a Caddyfile segment back out as text, keeping tokens
// that shared a source line on one line. Tokens are quoted when they contain
// whitespace or a comment character so the lexer reads them back unchanged.
func renderSegment(seg *caddyfile.Dispenser) string {
	var b strings.Builder
	line := -1
	for seg.Next() {
		tok := seg.Token()
		switch tok.Text {
		case "{":
			b.WriteString(" {\n")
			continue
		case "}":
			b.WriteString("\n}\n")
			continue
		}
		if line >= 0 && tok.Line != line {
			b.WriteByte('\n')
		} else if b.Len() > 0 && !strings.HasSuffix(b.String(), "\n") {
			b.WriteByte(' ')
		}
		line = tok.Line
		b.WriteString(quoteToken(tok.Text))
	}
	return b.String()
}

func quoteToken(s string) string {
	if s == "" || strings.ContainsAny(s, " \t\r\n#\"'`") {
		return strconv.Quote(s)
	}
	return s
}
