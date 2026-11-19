package smtp

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// ipLimiter caps how many connections one remote IP may hold open at once.
// Without it a single peer can take every slot in the listener-wide
// semaphore and starve legitimate senders.
type ipLimiter struct {
	limit int
	mu    sync.Mutex
	conns map[string]int
}

// newIPLimiter returns a limiter, or nil when no per-IP cap is configured.
func newIPLimiter(limit int) *ipLimiter {
	if limit <= 0 {
		return nil
	}
	return &ipLimiter{limit: limit, conns: make(map[string]int)}
}

// acquire counts one connection for ip and reports false when that IP is
// already at its limit.
func (l *ipLimiter) acquire(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conns[ip] >= l.limit {
		return false
	}
	l.conns[ip]++
	return true
}

// release drops one connection for ip and forgets the IP once it holds none,
// so the map cannot grow with every peer ever seen.
func (l *ipLimiter) release(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n := l.conns[ip] - 1; n > 0 {
		l.conns[ip] = n
	} else {
		delete(l.conns, ip)
	}
}

// remoteIP reduces a peer address to its host part so an IPv6 peer's port
// cannot split it into a new accounting bucket.
func remoteIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// rejectTooManyConnections answers the peer with a retryable 421 and closes,
// so it backs off instead of timing out against a stalled accept loop.
func rejectTooManyConnections(lc *ListenerConfig, conn net.Conn) {
	rejectWith(lc, conn, "421 4.7.0 Too many connections from your IP, try again later\r\n")
}

// rejectWith writes one reply under the listener's write deadline and closes
// the connection, so a peer that stops reading cannot pin the goroutine.
func rejectWith(lc *ListenerConfig, conn net.Conn, reply string) {
	defer conn.Close()
	if d := time.Duration(lc.DeliverTimeout); d > 0 {
		conn.SetWriteDeadline(time.Now().Add(d))
	}
	fmt.Fprint(conn, reply)
}
