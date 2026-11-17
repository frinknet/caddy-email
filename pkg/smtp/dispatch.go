package smtp

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// dispatch synthesizes an *http.Request for the message, runs it through
// the compiled listener route, and translates the response status into
// an SMTP reply code.
func (s *session) dispatch(raw []byte) {
	if s.lc.Route == nil {
		s.reply(250, "2.0.0 OK")
		return
	}

	req := s.buildRequest(raw)
	rrw := newSmtpResponseWriter()

	ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, s.repl)
	req = req.WithContext(ctx)

	// Apply deliver timeout
	timeout := time.Duration(s.lc.DeliverTimeout)
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(req.Context(), timeout)
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
	s.reply(code, msg)
}

func (s *session) buildRequest(raw []byte) *http.Request {
	hdr := http.Header{}
	for _, h := range parseHeaderLines(raw) {
		hdr.Add(h[0], h[1])
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
		Host:       s.helo,
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
