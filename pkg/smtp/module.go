package smtp

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(new(SMTP))
}

type SMTP struct {
	Listeners []*ListenerConfig `json:"listeners,omitempty"`

	log    *zap.Logger
	lns    []net.Listener
	stopCh chan struct{}
	wg     sync.WaitGroup
}

type ListenerConfig struct {
	Port             int                `json:"port,omitempty"`
	Hostname         string             `json:"hostname,omitempty"`
	MaxMessageSize   int64              `json:"max_message_size,omitempty"`
	MaxRecipients    int                `json:"max_recipients,omitempty"`
	MaxConnections   int                `json:"max_connections,omitempty"`
	PermitMyNetworks []string           `json:"permit_mynetworks,omitempty"`
	DeliverTimeout   caddy.Duration     `json:"deliver_timeout,omitempty"`
	DeliverSecret    string             `json:"deliver_secret,omitempty"`
	TLS              string             `json:"tls,omitempty"`  // "starttls" | "off"
	Auth             string             `json:"auth,omitempty"` // "required" | "optional" | "off"
	Route            *caddyhttp.Subroute `json:"-"`
}

func (*SMTP) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "smtp",
		New: func() caddy.Module { return new(SMTP) },
	}
}

func (s *SMTP) Provision(ctx caddy.Context) error {
	s.log = ctx.Logger()
	for _, lc := range s.Listeners {
		if lc.Hostname == "" {
			h, _ := os.Hostname()
			if h == "" {
				h = "localhost.localdomain"
			}
			lc.Hostname = h
		}
		if lc.MaxMessageSize == 0 {
			lc.MaxMessageSize = 25 << 20
		}
		if lc.MaxRecipients == 0 {
			lc.MaxRecipients = 50
		}
		if lc.MaxConnections == 0 {
			lc.MaxConnections = 200
		}
		if lc.DeliverTimeout == 0 {
			lc.DeliverTimeout = caddy.Duration(30 * time.Second)
		}
		if lc.TLS == "" {
			if lc.Port == 587 {
				lc.TLS = "starttls"
			} else {
				lc.TLS = "off"
			}
		}
		if lc.Auth == "" {
			if lc.Port == 587 {
				lc.Auth = "required"
			} else {
				lc.Auth = "off"
			}
		}
		if lc.Port == 25 && len(lc.PermitMyNetworks) == 0 {
			lc.PermitMyNetworks = []string{"127.0.0.0/8", "::1/128"}
		}
		if lc.Route != nil {
			if err := lc.Route.Provision(ctx); err != nil {
				return fmt.Errorf("smtp :%d route: %w", lc.Port, err)
			}
		}
	}
	return nil
}

func (s *SMTP) Validate() error {
	for _, lc := range s.Listeners {
		if lc.Port == 0 {
			return fmt.Errorf("smtp: listener port required")
		}
		if lc.Port == 25 && len(lc.PermitMyNetworks) == 0 {
			return fmt.Errorf("smtp :25 requires explicit permit_mynetworks (open relay)")
		}
	}
	return nil
}

func (s *SMTP) Start() error {
	s.stopCh = make(chan struct{})
	for _, lc := range s.Listeners {
		addr := fmt.Sprintf(":%d", lc.Port)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("smtp: listen %s: %w", addr, err)
		}
		s.lns = append(s.lns, ln)
		s.wg.Add(1)
		go s.serve(lc, ln)
		s.log.Info("smtp listening", zap.Int("port", lc.Port))
	}
	return nil
}

func (s *SMTP) Stop() error {
	close(s.stopCh)
	for _, ln := range s.lns {
		ln.Close()
	}
	s.wg.Wait()
	return nil
}

func (s *SMTP) serve(lc *ListenerConfig, ln net.Listener) {
	defer s.wg.Done()
	sem := make(chan struct{}, lc.MaxConnections)
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.stopCh:
				return
			default:
				continue
			}
		}
		sem <- struct{}{}
		go func(c net.Conn) {
			defer func() { <-sem }()
			defer c.Close()
			// Enforce idle timeout
			timeout := time.Duration(lc.DeliverTimeout)
			if timeout > 0 {
				c.SetDeadline(time.Now().Add(timeout))
			}
			newSession(lc, c).run()
		}(conn)
	}
}

var _ = context.Background
