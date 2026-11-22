package sentinel

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/vanndh/holone/internal/inspect"
)

const maxConfigInspectBytes = 512 << 10

var gitHooksPathRe = regexp.MustCompile(`(?im)^\s*hooksPath\s*=`)

type configCandidate struct {
	absPath      string
	label        string
	isGitConfig  bool
	isClientJSON bool
}

// checkAIConfigs scans AI-client configuration, MCP manifests, instruction
// files, git hooks, package-manager configs, and shell startup scripts for
// injected payloads or poisoned persistence hooks.
func checkAIConfigs(homeDir, workDir string, eng *inspect.Engine) Check {
	c := Check{
		Name:   "ai-client-configs",
		Status: StatusClean,
		Detail: "no poisoned AI-client configs, git hooks, or shell profiles found",
	}
	if eng == nil {
		var err error
		eng, err = inspect.Default()
		if err != nil {
			return Check{Name: "ai-client-configs", Status: StatusError, Detail: err.Error()}
		}
	}

	candidates := collectConfigCandidates(homeDir, workDir)
	var findingsDesc []string
	maxSev := inspect.SevLow
	hasFinding := false

	for _, cand := range candidates {
		content, ok := readBoundedFile(cand.absPath, maxConfigInspectBytes)
		if !ok || strings.TrimSpace(content) == "" {
			continue
		}

		fs := eng.Inspect(content, "audit:"+cand.label)
		var ruleIDs []string
		seenRule := map[string]bool{}
		addRule := func(id string, sev inspect.Severity) {
			hasFinding = true
			if sev > maxSev {
				maxSev = sev
			}
			if !seenRule[id] {
				seenRule[id] = true
				ruleIDs = append(ruleIDs, id)
			}
		}

		for _, f := range fs {
			addRule(f.RuleID, inspect.ParseSeverity(f.Severity))
		}
		if cand.isGitConfig && gitHooksPathRe.MatchString(content) {
			addRule("git-hookspath", inspect.SevHigh)
		}
		if cand.isClientJSON && len(fs) == 0 && hasClientLifecycleHooks(content) {
			addRule("client-lifecycle-hooks", inspect.SevMedium)
		}

		if len(ruleIDs) > 0 {
			sort.Strings(ruleIDs)
			findingsDesc = append(findingsDesc, fmt.Sprintf("%s (%s)", cand.label, strings.Join(ruleIDs, ", ")))
		}
	}

	if hasFinding {
		if maxSev == inspect.SevHigh {
			c.Status = StatusInfected
		} else {
			c.Status = StatusWarn
		}
		c.Detail = "suspicious config(s): " + strings.Join(findingsDesc, "; ")
	}
	return c
}

func collectConfigCandidates(homeDir, workDir string) []configCandidate {
	var out []configCandidate
	seen := map[string]bool{}
	add := func(abs, label string, isGitCfg, isClientJSON bool) {
		if abs == "" {
			return
		}
		cleaned := filepath.Clean(abs)
		key := strings.ToLower(cleaned)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, configCandidate{
			absPath:      cleaned,
			label:        label,
			isGitConfig:  isGitCfg,
			isClientJSON: isClientJSON,
		})
	}

	if homeDir != "" {
		homeFiles := []struct {
			rel        string
			clientJSON bool
		}{
			{".claude/settings.json", true},
			{".claude/settings.local.json", true},
			{".claude.json", true},
			{".claude/mcp.json", true},
			{".claude/CLAUDE.md", false},
			{".cursor/mcp.json", true},
			{".npmrc", false},
			{".pip/pip.conf", false},
			{".bashrc", false},
			{".zshrc", false},
			{".profile", false},
			{".bash_profile", false},
			{".zprofile", false},
		}
		for _, hf := range homeFiles {
			add(filepath.Join(homeDir, filepath.FromSlash(hf.rel)), "~/"+hf.rel, false, hf.clientJSON)
		}
	}

	if workDir != "" {
		workFiles := []struct {
			rel        string
			gitCfg     bool
			clientJSON bool
		}{
			{".claude/settings.json", false, true},
			{".claude/settings.local.json", false, true},
			{".mcp.json", false, true},
			{".cursor/mcp.json", false, true},
			{"CLAUDE.md", false, false},
			{"AGENTS.md", false, false},
			{".cursorrules", false, false},
			{".git/config", true, false},
		}
		for _, wf := range workFiles {
			add(filepath.Join(workDir, filepath.FromSlash(wf.rel)), wf.rel, wf.gitCfg, wf.clientJSON)
		}

		hooksDir := filepath.Join(workDir, ".git", "hooks")
		if entries, err := os.ReadDir(hooksDir); err == nil {
			for _, ent := range entries {
				if ent.IsDir() || strings.HasSuffix(ent.Name(), ".sample") {
					continue
				}
				add(filepath.Join(hooksDir, ent.Name()), ".git/hooks/"+ent.Name(), false, false)
			}
		}
	}
	return out
}

func readBoundedFile(path string, maxBytes int64) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return "", false
	}
	b, err := io.ReadAll(io.LimitReader(f, maxBytes))
	if err != nil {
		return "", false
	}
	return string(b), true
}

func hasClientLifecycleHooks(content string) bool {
	low := strings.ToLower(content)
	return strings.Contains(low, `"pretooluse"`) ||
		strings.Contains(low, `"posttooluse"`) ||
		strings.Contains(low, `"userpromptsubmit"`)
}
