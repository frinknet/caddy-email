package mta

import (
	"net"
	"sort"
	"strings"

	"github.com/example/caddy-email/pkg/shared"
	"go.uber.org/zap"
)

// groupByMX resolves each recipient domain to an MX host and groups
// jobs by MX. A single job may appear under multiple MXes if its
// recipients span domains served by different hosts.
func groupByMX(jobs []*shared.Job, log *zap.Logger) map[string][]*shared.Job {
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
		mxs, err := net.LookupMX(dom)
		if err != nil || len(mxs) == 0 {
			domainMX[dom] = dom // implicit MX: A-record fallback
			continue
		}
		sort.Slice(mxs, func(i, k int) bool { return mxs[i].Pref < mxs[k].Pref })
		domainMX[dom] = strings.TrimSuffix(mxs[0].Host, ".")
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
