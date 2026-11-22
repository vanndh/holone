//go:build !windows

package sentinel

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/vanndh/holone/internal/inspect"
)

// platformChecks runs best-effort POSIX (macOS/Linux) IOC probes covering
// rogue processes, SOCKS connections, and user persistence mechanisms.
func platformChecks(ctx context.Context, homeDir string, bl inspect.Blocklist, eng *inspect.Engine) []Check {
	return []Check{
		checkProcesses(ctx, bl),
		checkConnections(ctx, bl),
		checkPersistence(ctx, homeDir, bl, eng),
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

func checkPersistence(ctx context.Context, homeDir string, bl inspect.Blocklist, eng *inspect.Engine) Check {
	c := Check{Name: "user-persistence", Status: StatusClean, Detail: "no suspicious launchd, systemd user units, or crontab entries"}
	var hits []string
	infected := false

	scanContent := func(label, body string) {
		if strings.TrimSpace(body) == "" {
			return
		}
		if bad := scanFor(body, append(append([]string{}, bl.Domains...), bl.IPs...)); len(bad) > 0 {
			infected = true
			hits = append(hits, label+" (IOC: "+strings.Join(bad, ", ")+")")
		}
		if eng != nil {
			for _, f := range eng.Inspect(body, "persistence:"+label) {
				if f.Severity == inspect.SevHigh.String() {
					infected = true
				}
				hits = append(hits, label+" ("+f.RuleID+")")
			}
		}
	}

	if homeDir != "" {
		patterns := []string{
			filepath.Join(homeDir, "Library", "LaunchAgents", "*.plist"),
			filepath.Join(homeDir, ".config", "systemd", "user", "*.service"),
		}
		for _, pat := range patterns {
			matches, _ := filepath.Glob(pat)
			for _, p := range matches {
				if b, ok := readBoundedFile(p, maxConfigInspectBytes); ok {
					scanContent(p, b)
				}
			}
		}
	}

	if out, err := runCmd(ctx, "crontab", "-l"); err == nil && out != "" {
		scanContent("crontab", out)
	}

	if len(hits) > 0 {
		if infected {
			c.Status = StatusInfected
		} else {
			c.Status = StatusWarn
		}
		c.Detail = strings.Join(hits, "; ")
	}
	return c
}
