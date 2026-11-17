package smtp

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"strings"

	"github.com/caddyserver/caddy/v2"
)

type session struct {
	lc     *ListenerConfig
	conn   net.Conn
	reader *bufio.Reader
	writer *bufio.Writer
	repl   *caddy.Replacer

	helo  string
	from  string
	rcpts []string
	tlsOn bool
}

func newSession(lc *ListenerConfig, conn net.Conn) *session {
	s := &session{
		lc:     lc,
		conn:   conn,
		reader: bufio.NewReader(conn),
		writer: bufio.NewWriter(conn),
		repl:   caddy.NewReplacer(),
	}
	s.repl.Set("smtp.remote_ip", conn.RemoteAddr().String())
	s.repl.Set("smtp.local_ip", conn.LocalAddr().String())
	s.repl.Set("smtp.hostname", lc.Hostname)
	return s
}

func (s *session) replyf(format string, args ...any) {
	fmt.Fprintf(s.writer, format+"\r\n", args...)
	s.writer.Flush()
}

func (s *session) reply(code int, msg string) {
	s.replyf("%d %s", code, msg)
}

func (s *session) run() {
	s.replyf("220 %s ESMTP ready", s.lc.Hostname)
	for {
		line, err := s.reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		cmd, args := splitCmd(line)
		switch cmd {
		case "EHLO":
			s.handleEHLO(args)
		case "HELO":
			s.handleHELO(args)
		case "MAIL":
			s.handleMail(args)
		case "RCPT":
			s.handleRcpt(args)
		case "DATA":
			s.handleData()
		case "RSET":
			s.from = ""
			s.rcpts = nil
			s.reply(250, "OK")
		case "NOOP":
			s.reply(250, "OK")
		case "QUIT":
			s.reply(221, "Bye")
			return
		case "STARTTLS":
			s.handleSTARTTLS()
		default:
			s.reply(500, "Unknown command")
		}
	}
}

func (s *session) handleEHLO(args string) {
	s.helo = args
	s.repl.Set("smtp.helo", args)

	var caps []string
	caps = append(caps, s.lc.Hostname)
	if s.lc.MaxMessageSize > 0 {
		caps = append(caps, fmt.Sprintf("SIZE %d", s.lc.MaxMessageSize))
	}
	caps = append(caps, "PIPELINING")
	caps = append(caps, "ENHANCEDSTATUSCODES")
	if s.lc.TLS == "starttls" && !s.tlsOn {
		caps = append(caps, "STARTTLS")
	}

	for i, cap := range caps {
		if i == len(caps)-1 {
			s.replyf("250 %s", cap)
		} else {
			s.replyf("250-%s", cap)
		}
	}
}

func (s *session) handleHELO(args string) {
	s.helo = args
	s.repl.Set("smtp.helo", args)
	s.reply(250, s.lc.Hostname)
}

func (s *session) handleMail(args string) {
	from := extractAngle(args)
	if from == "" && !strings.Contains(strings.ToUpper(args), "FROM:<>") {
		s.reply(501, "Syntax: MAIL FROM:<addr>")
		return
	}
	s.from = from
	s.repl.Set("smtp.from", from)
	s.reply(250, "OK")
}

func (s *session) handleRcpt(args string) {
	rcpt := extractAngle(args)
	if rcpt == "" {
		s.reply(501, "Syntax: RCPT TO:<addr>")
		return
	}
	if len(s.rcpts) >= s.lc.MaxRecipients {
		s.reply(452, "Too many recipients")
		return
	}
	s.rcpts = append(s.rcpts, rcpt)
	s.repl.Set("smtp.rcpt", rcpt)
	s.repl.Set("smtp.rcpts", s.rcpts)
	s.reply(250, "OK")
}

func (s *session) handleData() {
	if s.from == "" {
		s.reply(503, "MAIL FROM first")
		return
	}
	if len(s.rcpts) == 0 {
		s.reply(503, "RCPT TO first")
		return
	}
	s.reply(354, "End with <CRLF>.<CRLF>")
	var body bytes.Buffer
	for {
		line, err := s.reader.ReadString('\n')
		if err != nil {
			return
		}
		if line == ".\r\n" || line == ".\n" {
			break
		}
		if strings.HasPrefix(line, "..") {
			line = line[1:]
		}
		if int64(body.Len())+int64(len(line)) > s.lc.MaxMessageSize {
			s.reply(552, "Message too large")
			return
		}
		body.WriteString(line)
	}
	s.dispatch(body.Bytes())
	s.from = ""
	s.rcpts = nil
}

func (s *session) handleSTARTTLS() {
	if s.lc.TLS != "starttls" {
		s.reply(502, "STARTTLS not available")
		return
	}
	if s.lc.tlsCert == nil {
		s.reply(502, "STARTTLS not configured")
		return
	}
	s.reply(220, "Ready to start TLS")
	tlsConn := tls.Server(s.conn, &tls.Config{
		Certificates: []tls.Certificate{*s.lc.tlsCert},
	})
	if err := tlsConn.Handshake(); err != nil {
		s.reply(550, "TLS handshake failed")
		return
	}
	s.conn = tlsConn
	s.reader = bufio.NewReader(tlsConn)
	s.writer = bufio.NewWriter(tlsConn)
	s.tlsOn = true
	s.repl.Set("smtp.tls", "true")
}

func splitCmd(line string) (string, string) {
	line = strings.TrimSpace(line)
	sp := strings.IndexAny(line, " \t")
	if sp < 0 {
		return strings.ToUpper(line), ""
	}
	return strings.ToUpper(line[:sp]), strings.TrimSpace(line[sp+1:])
}

func extractAngle(s string) string {
	i := strings.Index(s, "<")
	j := strings.Index(s, ">")
	if i < 0 || j < 0 || j <= i {
		return ""
	}
	return s[i+1 : j]
}
