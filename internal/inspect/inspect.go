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
	"runtime"
	"sort"
	"strings"
	"sync"

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

// RuleAnomalyToolNameNotDeclared is the synthetic rule id used when the client
// did declare tools, but the provider returned one of a different name.
const RuleAnomalyToolNameNotDeclared = "proto-tool-name-not-declared"

// RuleAnomalyOversizedToolCall is the synthetic rule id used when a buffered
// tool call exceeds the hard size cap and cannot be inspected end-to-end; the
// call is never forwarded.
const RuleAnomalyOversizedToolCall = "proto-toolcall-oversized"

// RuleAnomalyOversizedSSELine is the synthetic rule id used when a single SSE
// line exceeds the parser's hard limit and cannot be inspected safely.
const RuleAnomalyOversizedSSELine = "proto-sse-line-oversized"

// RuleAnomalyOversizedSSEFrame is the synthetic rule id used when an SSE frame
// (many lines without a blank-line separator) exceeds the frame cap.
const RuleAnomalyOversizedSSEFrame = "proto-sse-frame-oversized"

// RuleAnomalyEncodingUninspected is the synthetic rule id used when the
// upstream used a Content-Encoding holone cannot decode: in monitor mode the
// bytes are forwarded untouched, so the gap is surfaced as a finding.
const RuleAnomalyEncodingUninspected = "proto-encoding-uninspected"

type ruleSpec struct {
	ID            string `json:"id"`
	Category      string `json:"category"`
	Severity      string `json:"severity"`
	Pattern       string `json:"pattern"`
	Description   string `json:"description"`
	DescriptionRU string `json:"description_ru,omitempty"`

	// Keywords, when present, are literals of which at least one MUST occur in
	// any match of Pattern (case-insensitive). They are only a prefilter: a rule
	// without them is always evaluated.
	Keywords []string `json:"keywords,omitempty"`
}

type rulesFile struct {
	Version int        `json:"version"`
	Rules   []ruleSpec `json:"rules"`
}

type compiledRule struct {
	spec     ruleSpec
	sev      Severity
	re       *regexp.Regexp
	keywords []string // lowercased; empty = always run the regex
}

// RuleInfo is a safe, UI-facing description of a detection rule.
type RuleInfo struct {
	ID            string `json:"id"`
	Category      string `json:"category"`
	Severity      string `json:"severity"`
	Pattern       string `json:"pattern"`
	DescriptionEN string `json:"description_en"`
	DescriptionRU string `json:"description_ru"`
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
	rules       []compiledRule
	terms       []blockTerm
	descByID    map[string]string
	hasKeywords bool // at least one rule has a keyword prefilter
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
		kw := normalizeKeywords(rs.Keywords)
		if len(kw) > 0 {
			e.hasKeywords = true
		}
		e.rules = append(e.rules, compiledRule{spec: rs, sev: ParseSeverity(rs.Severity), re: re, keywords: kw})
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

// Rules returns a stable, UI-facing rule catalog.
func (e *Engine) Rules() []RuleInfo {
	out := make([]RuleInfo, 0, len(e.rules))
	for _, r := range e.rules {
		ru := strings.TrimSpace(r.spec.DescriptionRU)
		if ru == "" {
			ru = russianRuleDescription(r.spec)
		}
		out = append(out, RuleInfo{
			ID:            r.spec.ID,
			Category:      r.spec.Category,
			Severity:      r.sev.String(),
			Pattern:       r.spec.Pattern,
			DescriptionEN: r.spec.Description,
			DescriptionRU: ru,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return ParseSeverity(out[i].Severity) > ParseSeverity(out[j].Severity)
		}
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Inputs at least this large are worth evaluating in parallel: the regexes are
// expensive enough per byte to amortise the goroutine setup.
const parallelInspectMin = 32 << 10

// minRulesPerGroup keeps each parallel group large enough to be useful.
const minRulesPerGroup = 8

// Inspect scans a single piece of text and returns all findings. source is a
// short label describing where the text came from (e.g. "tool_use:Bash").
//
// Rules that declare required keywords are skipped when none of those literals
// occurs in the text, which avoids most regex work on benign prose. The result
// is identical to evaluating every regex: keywords are only provable literals.
func (e *Engine) Inspect(text, source string) []Finding {
	if text == "" {
		return nil
	}
	// One lowercase copy serves both the keyword prefilter and the IOC scan.
	var low string
	if e.hasKeywords {
		low = strings.ToLower(text)
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

	if len(text) >= parallelInspectMin {
		for _, f := range e.inspectRulesParallel(text, low, source) {
			add(f)
		}
	} else {
		for i := range e.rules {
			if f, ok := e.matchRule(i, text, low, source); ok {
				add(f)
			}
		}
	}

	if len(e.terms) > 0 {
		if low == "" {
			low = strings.ToLower(text)
		}
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
				Excerpt:     redact(excerpt(text, idx, idx+len(bt.lower))),
				Source:      source,
				Description: "Known indicator of compromise (" + bt.kind + ")",
			})
		}
	}
	return out
}

// matchRule applies the keyword prefilter, then evaluates the rule's regex.
func (e *Engine) matchRule(i int, text, low, source string) (Finding, bool) {
	r := &e.rules[i]
	if len(r.keywords) > 0 && !containsAny(low, r.keywords) {
		return Finding{}, false
	}
	loc := r.re.FindStringIndex(text)
	if loc == nil {
		return Finding{}, false
	}
	return Finding{
		RuleID:      r.spec.ID,
		Category:    r.spec.Category,
		Severity:    r.sev.String(),
		Match:       redact(truncate(text[loc[0]:loc[1]], 160)),
		Excerpt:     redact(excerpt(text, loc[0], loc[1])),
		Source:      source,
		Description: r.spec.Description,
	}, true
}

// containsAny reports whether s contains at least one lowercased keyword.
func containsAny(s string, keywords []string) bool {
	for _, k := range keywords {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

// inspectRulesParallel evaluates contiguous rule groups concurrently and merges
// their findings in rule order, so the output is identical to the serial path.
// It shares no mutable state between groups: every result slice is owned by one
// goroutine, and the engine itself is immutable.
func (e *Engine) inspectRulesParallel(text, low, source string) []Finding {
	groups := runtime.GOMAXPROCS(0)
	if maxGroups := len(e.rules) / minRulesPerGroup; groups > maxGroups {
		groups = maxGroups
	}
	if groups < 1 {
		groups = 1
	}

	if groups == 1 {
		out := make([]Finding, 0, len(e.rules))
		for i := range e.rules {
			if f, ok := e.matchRule(i, text, low, source); ok {
				out = append(out, f)
			}
		}
		return out
	}

	results := make([][]Finding, groups)
	var wg sync.WaitGroup
	for g := range groups {
		start := g * len(e.rules) / groups
		end := (g + 1) * len(e.rules) / groups
		wg.Add(1)
		go func(g, start, end int) {
			defer wg.Done()
			var fs []Finding
			for i := start; i < end; i++ {
				if f, ok := e.matchRule(i, text, low, source); ok {
					fs = append(fs, f)
				}
			}
			results[g] = fs
		}(g, start, end)
	}
	wg.Wait()

	out := make([]Finding, 0, len(e.rules))
	for _, fs := range results {
		out = append(out, fs...)
	}
	return out
}

// normalizeKeywords lowercases, trims and deduplicates keyword literals.
func normalizeKeywords(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, k := range in {
		k = strings.ToLower(strings.TrimSpace(k))
		if k == "" {
			continue
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
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

func russianRuleDescription(r ruleSpec) string {
	category := map[string]string{
		"download-exec":      "загрузка и выполнение кода",
		"obfuscation":        "обфускация или скрытое выполнение",
		"persistence":        "закрепление в системе",
		"network":            "изменение сети или прокси",
		"anti-forensics":     "анти-форензика",
		"locale":             "изменение локали",
		"client-config":      "отравление конфигурации AI-клиента",
		"credential-theft":   "кража учётных данных",
		"exfil":              "эксфильтрация данных",
		"git-attack":         "атака на git или CI",
		"supply-chain":       "атака на цепочку поставки",
		"process-injection":  "инъекция в процесс",
		"uac-bypass":         "обход UAC",
		"defense-evasion":    "отключение или обход защиты",
		"container-escape":   "выход из контейнера",
		"thinking-injection": "скрытая инъекция через thinking-блоки",
	}
	severity := map[string]string{
		"high":   "высокий риск: блокировать в block-режиме",
		"medium": "средний риск: показать оператору и проверить контекст",
		"low":    "низкий риск: слабый сигнал для корреляции",
	}
	cat := category[r.Category]
	if cat == "" {
		cat = r.Category
	}
	sev := severity[ParseSeverity(r.Severity).String()]
	return fmt.Sprintf("%s; %s. Срабатывает на технику: %s", cat, sev, r.Description)
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
