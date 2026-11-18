package smtp

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// benchConn serves a fixed command script on Read and discards writes, so a
// session can be driven end-to-end without a real socket.
type benchConn struct {
	r     *bytes.Reader
	wrote int
}

func (c *benchConn) Read(p []byte) (int, error) { return c.r.Read(p) }
func (c *benchConn) Write(p []byte) (int, error) {
	c.wrote += len(p)
	return len(p), nil
}
func (c *benchConn) Close() error        { return nil }
func (c *benchConn) LocalAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4zero, Port: 25} }
func (c *benchConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 54321}
}
func (c *benchConn) SetDeadline(time.Time) error      { return nil }
func (c *benchConn) SetReadDeadline(time.Time) error  { return nil }
func (c *benchConn) SetWriteDeadline(time.Time) error { return nil }

const benchScript = "EHLO client.example.com\r\n" +
	"MAIL FROM:<alice@example.com>\r\n" +
	"RCPT TO:<bob@example.com>\r\n" +
	"DATA\r\n" +
	"From: alice@example.com\r\n" +
	"To: bob@example.com\r\n" +
	"Subject: hello\r\n" +
	"\r\n" +
	"The quick brown fox jumps over the lazy dog.\r\n" +
	".\r\n" +
	"QUIT\r\n"

// BenchmarkSessionTransaction drives one complete EHLO/MAIL/RCPT/DATA/QUIT
// exchange through the command parser. It isolates per-session CPU cost from
// network and disk, since dispatch short-circuits when no route is configured.
func BenchmarkSessionTransaction(b *testing.B) {
	lc := &ListenerConfig{
		Port:           25,
		Hostname:       "mail.test",
		MaxMessageSize: 10 << 20,
		MaxRecipients:  100,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn := &benchConn{r: bytes.NewReader([]byte(benchScript))}
		s := newSession(lc, conn)
		s.run()
	}
}
