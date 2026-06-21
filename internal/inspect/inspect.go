// Package inspect implements the client-independent detection engine: it scans
// assistant text and tool-call payloads (extracted from a provider's streamed
// response) against behavioral regex rules and a literal IOC blocklist, and
// reports findings. It is deliberately stateless and fast so it can run inline
// on a streaming hot path without adding meaningful latency.
package inspect

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/vanndh/holone/rules"
)

// Severity ranks how dangerous a finding is.
type Severity int

const (
	SevLow Severity = iota
	SevMedium
	SevHigh
)

func (s Severity) String() string {
	switch s {
	case SevHigh:
		return "high"
	case SevMedium:
		return "medium"
	default:
		return "low"
	}
}

// ParseSeverity maps a rule's textual severity to the Severity enum.
func ParseSeverity(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high":
		return SevHigh
	case "medium":
		return SevMedium
	default:
		return SevLow
	}
}

// RuleAnomalyUnsolicitedTool is the synthetic rule id used by the proxy when a
// response contains a tool call although the client never advertised any tools
// — a strong signal of provider-side injection.
const RuleAnomalyUnsolicitedTool = "proto-tooluse-unsolicited"

type ruleSpec struct {
	ID          string `json:"id"`
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Pattern     string `json:"pattern"`
	Description string `json:"description"`
}

type rulesFile struct {
	Version int        `json:"version"`
	Rules   []ruleSpec `json:"rules"`
}

type compiledRule struct {
	spec ruleSpec
	sev  Severity
	re   *regexp.Regexp
}

// Blocklist holds literal indicators of compromise.
type Blocklist struct {
	Domains      []string `json:"domains"`
	IPs          []string `json:"ips"`
	Paths        []string `json:"paths"`
	TaskNames    []string `json:"task_names"`
	ProcessNames []string `json:"process_names"`
	Hashes       []string `json:"hashes"`
}

type blockTerm struct {
	term  string
	lower string
	kind  string
}

// Finding describes a single detection hit.
type Finding struct {
	RuleID      string `json:"rule_id"`
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Match       string `json:"match"`
	Excerpt     string `json:"excerpt"`
	Source      string `json:"source"`
	Description string `json:"description,omitempty"`
}

// Engine is a compiled, immutable, concurrency-safe detector.
type Engine struct {
	rules    []compiledRule
	terms    []blockTerm
	descByID map[string]string
}

// New compiles an engine from raw rules.json and blocklist.json bytes.
func New(rulesJSON, blocklistJSON []byte) (*Engine, error) {
	var rf rulesFile
	if err := json.Unmarshal(rulesJSON, &rf); err != nil {
		return nil, fmt.Errorf("parse rules: %w", err)
	}
	e := &Engine{descByID: map[string]string{}}
	for _, rs := range rf.Rules {
		if rs.ID == "" || rs.Pattern == "" {
			return nil, fmt.Errorf("rule with empty id or pattern: %+v", rs)
		}
		re, err := regexp.Compile(rs.Pattern)
		if err != nil {
			return nil, fmt.Errorf("rule %q: bad pattern: %w", rs.ID, err)
		}
		e.rules = append(e.rules, compiledRule{spec: rs, sev: ParseSeverity(rs.Severity), re: re})
		e.descByID[rs.ID] = rs.Description
	}

	if len(blocklistJSON) > 0 {
		var bl Blocklist
		if err := json.Unmarshal(blocklistJSON, &bl); err != nil {
			return nil, fmt.Errorf("parse blocklist: %w", err)
		}
		addTerms := func(kind string, vals []string) {
			for _, v := range vals {
				v = strings.TrimSpace(v)
				if v == "" {
					continue
				}
				e.terms = append(e.terms, blockTerm{term: v, lower: strings.ToLower(v), kind: kind})
			}
		}
		addTerms("domain", bl.Domains)
		addTerms("ip", bl.IPs)
		addTerms("path", bl.Paths)
		addTerms("task", bl.TaskNames)
		addTerms("process", bl.ProcessNames)
		addTerms("hash", bl.Hashes)
	}
	return e, nil
}

// Default builds an engine from the embedded default rule set.
func Default() (*Engine, error) {
	return New(rules.RulesJSON, rules.BlocklistJSON)
}

// EmbeddedSources returns the raw bytes of the built-in rules and blocklist,
// so callers can mix custom overrides with embedded defaults.
func EmbeddedSources() (rulesJSON, blocklistJSON []byte) {
	return rules.RulesJSON, rules.BlocklistJSON
}

// DefaultBlocklist returns the embedded IOC blocklist (used by the sentinel and
// scanner to match against system state and resolved endpoints).
func DefaultBlocklist() (Blocklist, error) {
	var bl Blocklist
	if err := json.Unmarshal(rules.BlocklistJSON, &bl); err != nil {
		return bl, fmt.Errorf("parse blocklist: %w", err)
	}
	return bl, nil
}

// Description returns the human-readable description for a rule id (best effort).
func (e *Engine) Description(ruleID string) string {
	if d, ok := e.descByID[ruleID]; ok {
		return d
	}
	return ""
}

// RuleCount reports how many behavioral rules are loaded (for diagnostics).
func (e *Engine) RuleCount() int { return len(e.rules) }

// Inspect scans a single piece of text and returns all findings. source is a
// short label describing where the text came from (e.g. "tool_use:Bash").
func (e *Engine) Inspect(text, source string) []Finding {
	if text == "" {
		return nil
	}
	var out []Finding
	seen := make(map[string]struct{})
	add := func(f Finding) {
		key := f.RuleID + "\x00" + f.Match
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, f)
	}

	for _, r := range e.rules {
		loc := r.re.FindStringIndex(text)
		if loc == nil {
			continue
		}
		add(Finding{
			RuleID:      r.spec.ID,
			Category:    r.spec.Category,
			Severity:    r.sev.String(),
			Match:       truncate(text[loc[0]:loc[1]], 160),
			Excerpt:     excerpt(text, loc[0], loc[1]),
			Source:      source,
			Description: r.spec.Description,
		})
	}

	if len(e.terms) > 0 {
		low := strings.ToLower(text)
		for _, bt := range e.terms {
			idx := strings.Index(low, bt.lower)
			if idx < 0 {
				continue
			}
			add(Finding{
				RuleID:      "ioc-" + bt.kind,
				Category:    "ioc",
				Severity:    SevHigh.String(),
				Match:       bt.term,
				Excerpt:     excerpt(text, idx, idx+len(bt.lower)),
				Source:      source,
				Description: "Known indicator of compromise (" + bt.kind + ")",
			})
		}
	}
	return out
}

// MaxSeverity returns the highest severity among findings.
func MaxSeverity(fs []Finding) Severity {
	m := SevLow
	for _, f := range fs {
		if s := ParseSeverity(f.Severity); s > m {
			m = s
		}
	}
	return m
}

// SortFindings orders findings by descending severity then rule id (stable,
// deterministic output for logs and tests).
func SortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		si, sj := ParseSeverity(fs[i].Severity), ParseSeverity(fs[j].Severity)
		if si != sj {
			return si > sj
		}
		return fs[i].RuleID < fs[j].RuleID
	})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// excerpt returns a whitespace-collapsed, length-bounded window of context
// around [start,end) so logs are readable and don't leak huge blobs.
func excerpt(text string, start, end int) string {
	const pad = 48
	lo := start - pad
	if lo < 0 {
		lo = 0
	}
	hi := end + pad
	if hi > len(text) {
		hi = len(text)
	}
	window := text[lo:hi]
	window = strings.Join(strings.Fields(window), " ")
	return truncate(window, 200)
}
