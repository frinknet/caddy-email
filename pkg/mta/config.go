package mta

import (
	"encoding/json"
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

func init() {
	httpcaddyfile.RegisterGlobalOption("mta", parseMTAOption)
}

func parseMTAOption(d *caddyfile.Dispenser, _ any) (any, error) {
	m := new(MTA)
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "hostname":
				if !d.AllArgs(&m.Hostname) {
					return nil, d.ArgErr()
				}
			case "spool_dir":
				if !d.AllArgs(&m.SpoolDir) {
					return nil, d.ArgErr()
				}
			case "settle_delay":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return nil, err
				}
				m.SettleDelay = caddy.Duration(dur)
			case "tick_interval":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return nil, err
				}
				m.TickInterval = caddy.Duration(dur)
			case "max_batch":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				n, err := strconv.Atoi(d.Val())
				if err != nil {
					return nil, err
				}
				m.MaxBatch = n
			case "concurrency":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				n, err := strconv.Atoi(d.Val())
				if err != nil {
					return nil, err
				}
				m.Concurrency = n
			case "per_mx_concurrency":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				n, err := strconv.Atoi(d.Val())
				if err != nil {
					return nil, err
				}
				m.PerMXConcurrency = n
			case "max_retries":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				n, err := strconv.Atoi(d.Val())
				if err != nil {
					return nil, err
				}
				m.MaxRetries = n
			case "initial_backoff":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return nil, err
				}
				m.InitialBackoff = caddy.Duration(dur)
			case "max_backoff":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return nil, err
				}
				m.MaxBackoff = caddy.Duration(dur)
			case "connect_timeout":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return nil, err
				}
				m.ConnectTimeout = caddy.Duration(dur)
			case "data_timeout":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return nil, err
				}
				m.DataTimeout = caddy.Duration(dur)
			case "command_timeout":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return nil, err
				}
				m.CommandTimeout = caddy.Duration(dur)
			case "notify_url":
				if !d.AllArgs(&m.NotifyURL) {
					return nil, d.ArgErr()
				}
			case "notify_secret":
				if !d.AllArgs(&m.NotifySecret) {
					return nil, d.ArgErr()
				}
			case "mx_cache_ttl":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return nil, err
				}
				m.MxCacheTTL = caddy.Duration(dur)
			case "dkim":
				cfg := &DKIMConfig{}
				for nesting := d.Nesting(); d.NextBlock(nesting); {
					switch d.Val() {
					case "selector":
						if !d.AllArgs(&cfg.Selector) {
							return nil, d.ArgErr()
						}
					case "domain":
						if !d.AllArgs(&cfg.Domain) {
							return nil, d.ArgErr()
						}
					case "private_key":
						if !d.NextArg() {
							return nil, d.ArgErr()
						}
						cfg.PrivateKey = d.Val()
					default:
						return nil, d.Errf("unknown dkim option: %s", d.Val())
					}
				}
				if cfg.Selector == "" || cfg.PrivateKey == "" {
					return nil, d.Errf("dkim: selector and private_key required")
				}
				m.DKIM = cfg
			default:
				return nil, d.Errf("unknown mta option: %s", d.Val())
			}
		}
	}
	value, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return httpcaddyfile.App{Name: "mta", Value: value}, nil
}
