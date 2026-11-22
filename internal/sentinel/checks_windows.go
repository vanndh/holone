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
func platformChecks(ctx context.Context, homeDir string, bl inspect.Blocklist, eng *inspect.Engine) []Check {
	return []Check{
		checkProcesses(ctx, bl),
		checkScheduledTasks(ctx, bl),
		checkDroppedFiles(homeDir, bl),
		checkRegistryRun(ctx, bl, eng),
		checkDefenderExclusions(ctx, bl),
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

func checkDroppedFiles(homeDir string, bl inspect.Blocklist) Check {
	c := Check{Name: "dropped-files", Status: StatusClean, Detail: "no known dropper paths present"}
	localApp := os.Getenv("LOCALAPPDATA")
	appData := os.Getenv("APPDATA")

	seen := map[string]bool{}
	var candidates []string
	addCand := func(p string) {
		p = filepath.Clean(strings.TrimSpace(p))
		if p == "" || p == "." {
			return
		}
		k := strings.ToLower(p)
		if !seen[k] {
			seen[k] = true
			candidates = append(candidates, p)
		}
	}

	if localApp != "" {
		addCand(filepath.Join(localApp, "Microsoft", "SngCache"))
	}
	for _, bp := range bl.Paths {
		bp = strings.TrimSpace(bp)
		if bp == "" {
			continue
		}
		norm := filepath.FromSlash(bp)
		if filepath.IsAbs(norm) {
			addCand(norm)
			continue
		}
		if localApp != "" {
			addCand(filepath.Join(localApp, norm))
			addCand(filepath.Join(localApp, "Microsoft", norm))
		}
		if appData != "" {
			addCand(filepath.Join(appData, norm))
		}
		if homeDir != "" {
			addCand(filepath.Join(homeDir, norm))
		}
	}

	var hits []string
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

func checkRegistryRun(ctx context.Context, bl inspect.Blocklist, eng *inspect.Engine) Check {
	c := Check{Name: "registry-run", Status: StatusClean, Detail: "no suspicious HKCU Run/RunOnce entries"}
	keys := []string{
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		`HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`,
	}
	var hits []string
	infected := false

	for _, key := range keys {
		out, err := runCmd(ctx, "reg", "query", key)
		if err != nil {
			lowOut := strings.ToLower(out)
			if strings.Contains(lowOut, "unable to find") || strings.Contains(lowOut, "cannot find") {
				continue
			}
			continue
		}
		if bad := scanFor(out, append(append([]string{}, bl.Domains...), bl.IPs...)); len(bad) > 0 {
			infected = true
			hits = append(hits, key+": "+strings.Join(bad, ", "))
		}
		if badProc := scanFor(out, bl.ProcessNames); len(badProc) > 0 {
			infected = true
			hits = append(hits, key+": "+strings.Join(badProc, ", "))
		}
		if eng != nil {
			for _, f := range eng.Inspect(out, "registry:"+key) {
				if f.Severity == inspect.SevHigh.String() {
					infected = true
				}
				hits = append(hits, key+": "+f.RuleID)
			}
		}
	}
	if len(hits) > 0 {
		if infected {
			c.Status = StatusInfected
		} else {
			c.Status = StatusWarn
		}
		c.Detail = "suspicious autostart entry: " + strings.Join(hits, "; ")
	}
	return c
}

func checkDefenderExclusions(ctx context.Context, bl inspect.Blocklist) Check {
	c := Check{Name: "defender-exclusions", Status: StatusClean, Detail: "no known-bad Defender exclusions"}
	out, err := runCmd(ctx, "reg", "query", `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths`)
	if err != nil {
		// Reading Defender exclusions frequently requires elevation or the key is
		// absent when no exclusions are configured; treat unreadable as clean.
		c.Detail = "no readable Defender path exclusions"
		return c
	}
	if bad := scanFor(out, bl.Paths); len(bad) > 0 {
		c.Status = StatusInfected
		c.Detail = "Defender excludes known-bad path(s): " + strings.Join(bad, ", ")
		return c
	}
	low := strings.ToLower(out)
	for _, susp := range []string{`sngcache`, `\temp\`, `\appdata\local\temp`} {
		if strings.Contains(low, susp) {
			c.Status = StatusWarn
			c.Detail = "Defender excludes suspicious temporary/cache path (" + susp + ")"
			return c
		}
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
