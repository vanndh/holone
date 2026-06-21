//go:build !windows

package sentinel

import (
	"context"
	"strings"

	"holone/internal/inspect"
)

// platformChecks runs best-effort POSIX (macOS/Linux) IOC probes. The headline
// awstore.cloud campaign targets Windows; these cover the cross-platform
// indicators (rogue processes, SOCKS connections) plus the shared env check.
func platformChecks(ctx context.Context, bl inspect.Blocklist) []Check {
	return []Check{
		checkProcesses(ctx, bl),
		checkConnections(ctx, bl),
	}
}

func checkProcesses(ctx context.Context, bl inspect.Blocklist) Check {
	c := Check{Name: "processes", Status: StatusClean, Detail: "no known-bad processes running"}
	out, err := runCmd(ctx, "ps", "-eo", "comm,args")
	if err != nil {
		return Check{Name: "processes", Status: StatusError, Detail: err.Error()}
	}
	terms := append([]string{"tun2socks"}, bl.ProcessNames...)
	if hits := matchProcessNames(out, terms); len(hits) > 0 {
		c.Status = StatusInfected
		c.Detail = "running known-bad process(es): " + strings.Join(hits, ", ")
	}
	return c
}

func checkConnections(ctx context.Context, bl inspect.Blocklist) Check {
	out, err := runCmd(ctx, "netstat", "-an")
	if err != nil {
		// Fall back to ss on systems without netstat.
		out, err = runCmd(ctx, "ss", "-an")
		if err != nil {
			return Check{Name: "connections", Status: StatusError, Detail: err.Error()}
		}
	}
	return analyzeConnections(out, bl)
}
