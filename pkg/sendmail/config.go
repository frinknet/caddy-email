package sendmail

import (
	"strconv"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func parseSendmail(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	s := new(Sendmail)
	if err := s.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Sendmail) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "from":
				if !d.AllArgs(&s.DefaultFrom) {
					return d.ArgErr()
				}
			case "max_body_size":
				if !d.NextArg() {
					return d.ArgErr()
				}
				sz, err := strconv.ParseInt(d.Val(), 10, 64)
				if err != nil {
					return err
				}
				s.MaxBodySize = sz
			case "allowed_from":
				s.AllowedFrom = append(s.AllowedFrom, d.RemainingArgs()...)
			case "require_auth":
				s.RequireAuth = true
			default:
				return d.Errf("unknown sendmail option: %s", d.Val())
			}
		}
	}
	return nil
}
