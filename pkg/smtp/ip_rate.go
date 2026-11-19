package smtp

import (
	"math"
	"net"
	"sync"
	"time"
)

// ipRateLimiter caps how fast one remote IP may open new connections.
// The concurrent cap alone still lets a peer connect, hang up, and reconnect
// in a loop, which burns accept and session work forever. A token bucket
// tolerates a short burst and then refills at a fixed rate, so a real client
// that reconnects a few times is unaffected while a loop is turned away.
type ipRateLimiter struct {
	rate    float64 // tokens added per second
	burst   float64 // bucket capacity, also the largest allowed burst
	idle    time.Duration
	mu      sync.Mutex
	buckets map[string]*ipBucket
	lastGC  time.Time
	now     func() time.Time
}

// ipBucket is one peer's token bucket. seen doubles as the idle marker so a
// peer that keeps connecting is never swept.
type ipBucket struct {
	tokens float64
	seen   time.Time
}

// newIPRateLimiter returns a limiter that allows perSecond new connections per
// IP with an equal burst, or nil when the rate is disabled.
func newIPRateLimiter(perSecond int) *ipRateLimiter {
	if perSecond <= 0 {
		return nil
	}
	rate := float64(perSecond)
	return &ipRateLimiter{
		rate:  rate,
		burst: rate,
		// A bucket refills from empty in burst/rate = 1s, so dropping a peer
		// that has been idle that long loses nothing it would not recover.
		idle:    time.Second,
		buckets: make(map[string]*ipBucket),
		now:     time.Now,
	}
}

// allow spends one token for ip and reports false when the bucket is empty.
func (l *ipRateLimiter) allow(ip string) bool {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(now)
	b := l.buckets[ip]
	if b == nil {
		b = &ipBucket{tokens: l.burst, seen: now}
		l.buckets[ip] = b
	}
	if elapsed := now.Sub(b.seen).Seconds(); elapsed > 0 {
		b.tokens = math.Min(l.burst, b.tokens+elapsed*l.rate)
	}
	b.seen = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweepLocked forgets peers that have been quiet long enough for their bucket
// to be full again, so the map cannot grow with every host ever seen.
func (l *ipRateLimiter) sweepLocked(now time.Time) {
	if now.Sub(l.lastGC) < l.idle {
		return
	}
	l.lastGC = now
	for ip, b := range l.buckets {
		if now.Sub(b.seen) >= l.idle {
			delete(l.buckets, ip)
		}
	}
}

// rejectTooFast answers a rate-limited peer with a retryable 421 and closes,
// so it backs off instead of reconnecting as fast as it can.
func rejectTooFast(lc *ListenerConfig, conn net.Conn) {
	rejectWith(lc, conn, "421 4.7.1 Too many connections from your IP, slow down\r\n")
}
