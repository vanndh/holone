//go:build windows

package sentinel

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vanndh/holone/internal/inspect"
)

// platformChecks runs the Windows-specific IOC probes from the awstore.cloud
// campaign and similar provider-payload malware.
func platformChecks(ctx context.Context, bl inspect.Blocklist) []Check {
	return []Check{
		checkProcesses(ctx, bl),
		checkScheduledTasks(ctx, bl),
		checkDroppedFiles(bl),
		checkConnections(ctx, bl),
		checkRoutes(ctx, bl),
	}
}

func checkProcesses(ctx context.Context, bl inspect.Blocklist) Check {
	c := Check{Name: "processes", Status: StatusClean, Detail: "no known-bad processes running"}
	out, err := runCmd(ctx, "tasklist", "/fo", "csv", "/nh")
	if err != nil {
		return Check{Name: "processes", Status: StatusError, Detail: err.Error()}
	}
	if hits := matchProcessNames(out, append([]string{"tun2socks"}, bl.ProcessNames...)); len(hits) > 0 {
		c.Status = StatusInfected
		c.Detail = "running known-bad process(es): " + strings.Join(hits, ", ")
	}
	return c
}

func checkScheduledTasks(ctx context.Context, bl inspect.Blocklist) Check {
	c := Check{Name: "scheduled-tasks", Status: StatusClean, Detail: "no known-bad scheduled tasks"}
	out, err := runCmd(ctx, "schtasks", "/query", "/fo", "csv", "/nh")
	if err != nil {
		return Check{Name: "scheduled-tasks", Status: StatusError, Detail: err.Error()}
	}
	if hits := scanFor(out, bl.TaskNames); len(hits) > 0 {
		c.Status = StatusInfected
		c.Detail = "persistence task(s) present: " + strings.Join(hits, ", ")
	}
	return c
}

func checkDroppedFiles(bl inspect.Blocklist) Check {
	c := Check{Name: "dropped-files", Status: StatusClean, Detail: "no known dropper paths present"}
	var hits []string
	localApp := os.Getenv("LOCALAPPDATA")
	candidates := []string{}
	if localApp != "" {
		candidates = append(candidates,
			filepath.Join(localApp, "Microsoft", "SngCache"))
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			hits = append(hits, p)
		}
	}
	if len(hits) > 0 {
		c.Status = StatusInfected
		c.Detail = "dropper path(s) exist: " + strings.Join(hits, ", ")
	}
	return c
}

func checkConnections(ctx context.Context, bl inspect.Blocklist) Check {
	out, err := runCmd(ctx, "netstat", "-ano")
	if err != nil {
		return Check{Name: "connections", Status: StatusError, Detail: err.Error()}
	}
	return analyzeConnections(out, bl)
}

func checkRoutes(ctx context.Context, bl inspect.Blocklist) Check {
	c := Check{Name: "routes", Status: StatusClean, Detail: "no known-bad routes"}
	out, err := runCmd(ctx, "route", "print")
	if err != nil {
		return Check{Name: "routes", Status: StatusError, Detail: err.Error()}
	}
	if hits := scanFor(out, bl.IPs); len(hits) > 0 {
		c.Status = StatusWarn
		c.Detail = fmt.Sprintf("route table references known-bad IP(s): %s", strings.Join(hits, ", "))
	}
	return c
}
