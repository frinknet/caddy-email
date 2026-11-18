package mta

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/frinknet/caddy-email/pkg/shared"
)

// lookupMX resolves MX records for a domain. It is a variable so tests can
// stub DNS without touching the network.
var lookupMX = net.LookupMX

type mxCacheEntry struct {
	hosts  []string
	null   bool
	expiry time.Time
}

// mxTarget is the ordered set of hosts to try for a domain. When null is true
// the domain publishes a "null MX" (RFC 7505) and accepts no mail at all.
type mxTarget struct {
	hosts []string
	null  bool
}

// key identifies the target for grouping and per-host concurrency limiting.
func (t mxTarget) key(domain string) string {
	if t.null {
		return "null:" + domain
	}
	if len(t.hosts) == 0 {
		return "empty:" + domain
	}
	return t.hosts[0]
}

// classifyMX turns raw MX records into an ordered host list. A single root
// record (".") with preference 0 is the RFC 7505 null MX: the domain accepts no
// mail, so hosts is empty and null is true. Root records mixed into a normal
// MX set are skipped.
func classifyMX(mxs []*net.MX) (hosts []string, null bool) {
	sorted := make([]*net.MX, len(mxs))
	copy(sorted, mxs)
	sort.Slice(sorted, func(i, k int) bool { return sorted[i].Pref < sorted[k].Pref })

	if len(sorted) == 1 && sorted[0].Pref == 0 && isRootMX(sorted[0].Host) {
		return nil, true
	}
	for _, mx := range sorted {
		h := strings.TrimSuffix(mx.Host, ".")
		if h == "" {
			continue
		}
		hosts = append(hosts, h)
	}
	return hosts, false
}

func isRootMX(host string) bool {
	h := strings.TrimSuffix(host, ".")
	return h == "" || h == "."
}

// resolveTarget returns the delivery target for a domain, consulting the cache
// first. A nil error with null == true means the domain rejects all mail.
// A non-nil error is a temporary DNS failure and the caller should defer.
func (m *MTA) resolveTarget(domain string) (mxTarget, error) {
	m.mxCacheMu.RLock()
	entry, ok := m.mxCache[domain]
	m.mxCacheMu.RUnlock()
	if ok && time.Now().Before(entry.expiry) {
		return mxTarget{hosts: entry.hosts, null: entry.null}, nil
	}

	mxs, err := lookupMX(domain)
	var target mxTarget
	switch {
	case err == nil && len(mxs) > 0:
		hosts, null := classifyMX(mxs)
		target = mxTarget{hosts: hosts, null: null}
	case err == nil:
		// No MX records: fall back to the domain's A/AAAA record (implicit MX).
		target = mxTarget{hosts: []string{domain}}
	default:
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			// NXDOMAIN for MX is not fatal: the domain may still have an
			// address record, so treat it as an implicit MX.
			target = mxTarget{hosts: []string{domain}}
			break
		}
		return mxTarget{}, fmt.Errorf("lookup mx %s: %w", domain, err)
	}

	m.mxCacheMu.Lock()
	if m.mxCache == nil {
		m.mxCache = make(map[string]mxCacheEntry)
	}
	m.mxCache[domain] = mxCacheEntry{
		hosts:  target.hosts,
		null:   target.null,
		expiry: time.Now().Add(time.Duration(m.MxCacheTTL)),
	}
	m.mxCacheMu.Unlock()
	return target, nil
}

// recipientDomain returns the lower-cased domain of an address, or "" when
// the address has no domain part.
func recipientDomain(rcpt string) string {
	at := strings.LastIndex(rcpt, "@")
	if at < 0 {
		return ""
	}
	return strings.ToLower(rcpt[at+1:])
}

// mxGroup is a set of jobs sharing one delivery target.
type mxGroup struct {
	hosts []string
	key   string
	jobs  []*shared.Job
}

// groupByMX resolves each job's recipient domain and groups jobs by delivery
// target. Callers split multi-domain jobs first (see splitMultiDomain), so a
// job normally targets exactly one domain. Jobs that can never be delivered --
// an empty recipient set, an unqualified recipient, or a null-MX domain -- are
// failed here; jobs whose MX lookup fails temporarily are deferred.
//
// When a relay is configured no MX lookup happens: every job is grouped under
// the smarthost so it is forwarded rather than delivered directly.
func (m *MTA) groupByMX(jobs []*shared.Job) map[string]*mxGroup {
	result := map[string]*mxGroup{}
	relayHost, _, relaying := m.relaySpec()
	for _, j := range jobs {
		if len(j.To) == 0 {
			m.failPermanent(j, "no recipients")
			continue
		}
		if relaying {
			g := result[relayKey]
			if g == nil {
				g = &mxGroup{hosts: []string{relayHost}, key: relayKey}
				result[relayKey] = g
			}
			g.jobs = append(g.jobs, j)
			continue
		}
		dom := recipientDomain(j.To[0])
		if dom == "" {
			m.failPermanent(j, "recipient has no domain: "+j.To[0])
			continue
		}
		target, err := m.resolveTarget(dom)
		if err != nil {
			m.failTemporary(j, "mx lookup: "+err.Error())
			continue
		}
		if target.null {
			m.failPermanent(j, dom+" does not accept mail (null MX)")
			continue
		}
		key := target.key(dom)
		g := result[key]
		if g == nil {
			g = &mxGroup{hosts: target.hosts, key: key}
			result[key] = g
		}
		g.jobs = append(g.jobs, j)
	}
	return result
}
