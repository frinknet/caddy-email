package smtp

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/frinknet/caddy-email/pkg/shared"
)

// dispatch synthesizes an *http.Request for the message, runs it through
// the compiled listener route, and translates the response status into
// an SMTP reply code.
func (s *session) dispatch(raw []byte) {
	if s.lc.Route == nil {
		metricMessages.Inc()
		s.reply(250, "2.0.0 OK")
		return
	}

	rrw := newSmtpResponseWriter()
	req := s.buildRequest(s.withReceived(raw))

	// Handlers expect the context Caddy normally attaches to a request:
	// replacer, vars (client IP, trusted proxy), and a server. Without these
	// reverse_proxy panics on the missing variables.
	req = caddyhttp.PrepareRequest(req, s.repl, rrw, nil)
	ctx := context.WithValue(req.Context(), caddyhttp.ServerCtxKey, new(caddyhttp.Server))
	req = req.WithContext(ctx)
	caddyhttp.SetVar(ctx, caddyhttp.ClientIPVarKey, s.conn.RemoteAddr().String())

	// Apply deliver timeout
	timeout := time.Duration(s.lc.DeliverTimeout)
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
		req = req.WithContext(ctx)
	}

	terminal := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	})
	if err := s.lc.Route.ServeHTTP(rrw, req, terminal); err != nil {
		s.reply(451, "4.4.1 Internal error")
		return
	}
	code, msg := mapStatus(rrw.status)
	if code == 250 {
		metricMessages.Inc()
	}
	s.reply(code, msg)
}

// withReceived prepends this server's RFC 5321 trace header to the message so
// the route, and anything downstream, can see the SMTP hop it arrived on.
func (s *session) withReceived(raw []byte) []byte {
	remote := s.conn.RemoteAddr().String()
	if host, _, err := net.SplitHostPort(remote); err == nil {
		remote = host
	}
	proto := "ESMTP"
	if s.tlsOn {
		proto = "ESMTPS"
	}
	forAddr := ""
	if len(s.rcpts) == 1 {
		forAddr = s.rcpts[0]
	}
	return shared.PrependHeader(raw,
		shared.ReceivedHeader(s.helo, remote, s.lc.Hostname, proto, "", forAddr, time.Now()))
}

// forwardedHeaders is the allowlist of message header names copied into the
// synthesized request. Anything not listed here is dropped, so a remote sender
// cannot smuggle HTTP-level headers (Authorization, Cookie, Content-Length,
// X-Forwarded-For, ...) into a reverse_proxy route. Envelope metadata is set
// separately and always overrides a message header of the same name.
var forwardedHeaders = map[string]struct{}{
	"auto-submitted":              {},
	"cc":                          {},
	"comments":                    {},
	"content-description":         {},
	"content-disposition":         {},
	"content-id":                  {},
	"content-language":            {},
	"content-transfer-encoding":   {},
	"content-type":                {},
	"date":                        {},
	"delivered-to":                {},
	"disposition-notification-to": {},
	"errors-to":                   {},
	"from":                        {},
	"importance":                  {},
	"in-reply-to":                 {},
	"keywords":                    {},
	"mail-followup-to":            {},
	"mail-reply-to":               {},
	"message-id":                  {},
	"mime-version":                {},
	"organization":                {},
	"precedence":                  {},
	"priority":                    {},
	"received":                    {},
	"references":                  {},
	"reply-to":                    {},
	"resent-from":                 {},
	"resent-to":                   {},
	"return-path":                 {},
	"sender":                      {},
	"subject":                     {},
	"thread-index":                {},
	"thread-topic":                {},
	"to":                          {},
	"user-agent":                  {},
	"x-mailer":                    {},
}

// forwardedHeaderPrefixes covers list-management and filtering headers that
// are legitimately numerous: List-Id, List-Unsubscribe, X-Spam-Status, ARC-*.
var forwardedHeaderPrefixes = []string{"list-", "x-spam-", "x-virus-", "arc-"}

// forwardHeader reports whether a message header may be copied to the request.
func forwardHeader(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if _, ok := forwardedHeaders[n]; ok {
		return true
	}
	for _, p := range forwardedHeaderPrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

func (s *session) buildRequest(raw []byte) *http.Request {
	hdr := http.Header{}
	for _, h := range parseHeaderLines(raw) {
		if forwardHeader(h[0]) {
			hdr.Add(h[0], h[1])
		}
	}
	hdr.Set("X-Envelope-From", s.from)
	hdr.Set("X-Envelope-To", strings.Join(s.rcpts, ","))
	hdr.Set("X-Client-Helo", s.helo)
	hdr.Set("X-Client-IP", s.conn.RemoteAddr().String())
	if s.tlsOn {
		hdr.Set("X-Smtp-TLS", "true")
	}
	body := splitBody(raw)
	req := &http.Request{
		Method:     http.MethodPost,
		URL:        &url.URL{Path: "/", Scheme: "http"},
		Host:       s.lc.Hostname,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     hdr,
		Body:       http.NoBody,
	}
	if body != nil {
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
	}
	req.RemoteAddr = s.conn.RemoteAddr().String()
	return req
}

func parseHeaderLines(raw []byte) [][2]string {
	out := [][2]string{}
	i := 0
	for i < len(raw) {
		j := i
		for j < len(raw) && raw[j] != '\n' {
			j++
		}
		line := string(raw[i:j])
		if line == "" || line == "\r" {
			break
		}
		line = strings.TrimRight(line, "\r")
		if k := strings.Index(line, ":"); k > 0 {
			out = append(out, [2]string{line[:k], strings.TrimSpace(line[k+1:])})
		}
		i = j + 1
	}
	return out
}

func splitBody(raw []byte) []byte {
	if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
		return raw[i+4:]
	}
	if i := bytes.Index(raw, []byte("\n\n")); i >= 0 {
		return raw[i+2:]
	}
	return raw
}

type smtpResponseWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func newSmtpResponseWriter() *smtpResponseWriter {
	return &smtpResponseWriter{header: http.Header{}}
}

func (w *smtpResponseWriter) Header() http.Header { return w.header }
func (w *smtpResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(p)
}
func (w *smtpResponseWriter) WriteHeader(code int) { w.status = code }

func mapStatus(code int) (int, string) {
	if code == 0 || (code >= 200 && code < 400) {
		return 250, "2.0.0 OK"
	}
	// reverse_proxy transport errors → temporary so retry happens
	if code == 502 || code == 503 || code == 504 {
		return 451, "4.4.1 Backend unavailable"
	}
	if code >= 400 && code < 500 {
		return 451, "4.4.1 Temporary failure"
	}
	return 550, "5.0.0 Rejected"
}
