package smtp

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
)

type session struct {
	lc     *ListenerConfig
	conn   net.Conn
	reader *bufio.Reader
	writer *bufio.Writer
	repl   *caddy.Replacer

	helo     string
	from     string
	rcpts    []string
	mailSeen bool
	tlsOn    bool

	// closing is set when the peer must be disconnected after the current
	// command (for example after it keeps streaming an oversized body).
	closing bool
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
	if d := time.Duration(s.lc.DeliverTimeout); d > 0 {
		s.conn.SetWriteDeadline(time.Now().Add(d))
	}
	s.writer.Flush()
}

func (s *session) reply(code int, msg string) {
	s.replyf("%d %s", code, msg)
}

// refreshDeadline rearms the read deadline before every blocking read. This
// bounds an idle client without killing a slow-but-active transfer: session
// length is unlimited as long as data keeps arriving within DeliverTimeout.
func (s *session) refreshDeadline() {
	if d := time.Duration(s.lc.DeliverTimeout); d > 0 {
		s.conn.SetReadDeadline(time.Now().Add(d))
	}
}

// Line length caps. No real client sends a command anywhere near
// maxCommandLine, and capping the body line bounds the memory a single
// unterminated line can consume before max_message_size is enforced.
const (
	maxCommandLine = 8 << 10
	maxDataLine    = 1 << 20
)

var errLineTooLong = errors.New("smtp: line too long")

// readLine reads one '\n'-terminated line, bounded by limit bytes. When the
// line exceeds the limit it consumes and discards the remainder of that line
// and returns errLineTooLong, letting the caller reply and resynchronize
// instead of buffering an unbounded line.
func (s *session) readLine(limit int) (string, error) {
	var buf []byte
	for {
		chunk, err := s.reader.ReadSlice('\n')
		buf = append(buf, chunk...)
		if len(buf) > limit {
			for err == bufio.ErrBufferFull {
				_, err = s.reader.ReadSlice('\n')
			}
			if err != nil {
				return "", err
			}
			return "", errLineTooLong
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			return "", err
		}
		return string(buf), nil
	}
}

func (s *session) run() {
	s.refreshDeadline()
	s.replyf("220 %s ESMTP ready", s.lc.Hostname)
	for {
		s.refreshDeadline()
		line, err := s.readLine(maxCommandLine)
		if err != nil {
			if errors.Is(err, errLineTooLong) {
				s.reply(500, "5.5.2 Line too long")
				continue
			}
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
			s.resetTransaction()
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
		if s.closing {
			return
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
	caps = append(caps, "8BITMIME")
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
	s.mailSeen = true
	s.from = from
	s.repl.Set("smtp.from", from)
	s.reply(250, "OK")
}

// resetTransaction clears the envelope and the placeholders that expose it, so
// a later transaction (or a post-STARTTLS route) cannot observe a stale
// MAIL/RCPT from an earlier one. A null sender stays distinguishable from "no
// MAIL yet" because mailSeen is tracked separately from the sender value.
func (s *session) resetTransaction() {
	s.mailSeen = false
	s.from = ""
	s.rcpts = nil
	s.repl.Set("smtp.from", "")
	s.repl.Set("smtp.rcpt", "")
	s.repl.Set("smtp.rcpts", "")
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
	if !s.mailSeen {
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
		s.refreshDeadline()
		line, err := s.readLine(maxDataLine)
		if err != nil {
			if errors.Is(err, errLineTooLong) {
				s.reply(552, "5.3.4 Line too long")
				s.drainData()
				s.resetTransaction()
			}
			return
		}
		if line == ".\r\n" || line == ".\n" {
			break
		}
		if strings.HasPrefix(line, "..") {
			line = line[1:]
		}
		if s.lc.MaxMessageSize > 0 && int64(body.Len())+int64(len(line)) > s.lc.MaxMessageSize {
			s.reply(552, "5.3.4 Message too large")
			// Drain the rest of DATA so the remaining body lines are not
			// parsed as SMTP commands, then abort the transaction.
			s.drainData()
			s.resetTransaction()
			return
		}
		body.WriteString(line)
	}
	s.dispatch(body.Bytes())
	s.resetTransaction()
}

// drainData consumes lines until the end-of-data terminator, so that after an
// early 552 the leftover body is not misinterpreted as commands. If the peer
// keeps streaming past the message limit, the session is marked for closing
// instead of reading an unbounded body.
func (s *session) drainData() {
	var drained int64
	limit := s.lc.MaxMessageSize
	for {
		s.refreshDeadline()
		line, err := s.readLine(maxDataLine)
		if err != nil {
			if errors.Is(err, errLineTooLong) {
				continue
			}
			return
		}
		if line == ".\r\n" || line == ".\n" {
			return
		}
		if limit > 0 {
			drained += int64(len(line))
			if drained > limit {
				s.closing = true
				return
			}
		}
	}
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
	if s.tlsOn {
		s.reply(503, "TLS already active")
		return
	}
	if s.mailSeen || len(s.rcpts) > 0 {
		s.reply(503, "STARTTLS not allowed during a transaction")
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
	// RFC 3207 section 4.2: discard any state obtained before the handshake
	// that was not itself obtained over TLS.
	s.resetTransaction()
	s.helo = ""
	s.repl.Set("smtp.helo", "")
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
