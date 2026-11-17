package mta

import (
	"net"
	"sort"
	"strings"
	"time"

	"github.com/frinknet/caddy-email/pkg/shared"
	"go.uber.org/zap"
)

type mxCacheEntry struct {
	host   string
	expiry time.Time
}

// resolveMX returns the MX host for a domain, consulting the cache first.
func (m *MTA) resolveMX(domain string) string {
	m.mxCacheMu.RLock()
	entry, ok := m.mxCache[domain]
	m.mxCacheMu.RUnlock()
	if ok && time.Now().Before(entry.expiry) {
		return entry.host
	}

	mxs, err := net.LookupMX(domain)
	host := domain // implicit MX: A-record fallback
	if err == nil && len(mxs) > 0 {
		sort.Slice(mxs, func(i, k int) bool { return mxs[i].Pref < mxs[k].Pref })
		host = strings.TrimSuffix(mxs[0].Host, ".")
	}

	m.mxCacheMu.Lock()
	m.mxCache[domain] = mxCacheEntry{
		host:   host,
		expiry: time.Now().Add(time.Duration(m.MxCacheTTL)),
	}
	m.mxCacheMu.Unlock()
	return host
}

// groupByMX resolves each recipient domain to an MX host and groups
// jobs by MX. A single job may appear under multiple MXes if its
// recipients span domains served by different hosts.
func (m *MTA) groupByMX(jobs []*shared.Job, log *zap.Logger) map[string][]*shared.Job {
	domainJobs := map[string][]*shared.Job{}
	for _, j := range jobs {
		for _, rcpt := range j.To {
			at := strings.LastIndex(rcpt, "@")
			if at < 0 {
				continue
			}
			dom := strings.ToLower(rcpt[at+1:])
			domainJobs[dom] = append(domainJobs[dom], j)
		}
	}

	domainMX := map[string]string{}
	for dom := range domainJobs {
		domainMX[dom] = m.resolveMX(dom)
	}

	seen := map[string]map[string]bool{}
	result := map[string][]*shared.Job{}
	for dom, dj := range domainJobs {
		mx := domainMX[dom]
		if seen[mx] == nil {
			seen[mx] = map[string]bool{}
		}
		for _, j := range dj {
			if seen[mx][j.ID] {
				continue
			}
			seen[mx][j.ID] = true
			result[mx] = append(result[mx], j)
		}
	}
	return result
}
