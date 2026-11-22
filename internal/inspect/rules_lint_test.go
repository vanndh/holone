package inspect

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestRulesJSONLint(t *testing.T) {
	rawRules, _ := EmbeddedSources()
	var rf rulesFile
	if err := json.Unmarshal(rawRules, &rf); err != nil {
		t.Fatalf("unmarshal rules.json: %v", err)
	}
	if len(rf.Rules) == 0 {
		t.Fatal("rules.json has zero rules")
	}

	seenIDs := make(map[string]bool, len(rf.Rules))
	for _, r := range rf.Rules {
		if r.ID == "" {
			t.Errorf("rule has empty id: %+v", r)
			continue
		}
		if seenIDs[r.ID] {
			t.Errorf("duplicate rule id %q", r.ID)
		}
		seenIDs[r.ID] = true

		switch r.Severity {
		case "low", "medium", "high":
		default:
			t.Errorf("rule %q has invalid severity %q", r.ID, r.Severity)
		}
		if strings.TrimSpace(r.Category) == "" {
			t.Errorf("rule %q has empty category", r.ID)
		}
		if strings.TrimSpace(r.Description) == "" {
			t.Errorf("rule %q has empty description", r.ID)
		}
		if strings.TrimSpace(r.DescriptionRU) == "" {
			t.Errorf("rule %q has empty description_ru", r.ID)
		}
	}

	eng := mustEngine(t)
	for _, ri := range eng.Rules() {
		if strings.Contains(ri.DescriptionRU, "Срабатывает на технику:") {
			t.Errorf("rule %q fell back to generic description_ru instead of explicit translation", ri.ID)
		}
	}
}

func TestUTF8CaseFoldAndTruncateNoPanic(t *testing.T) {
	eng := mustEngine(t)
	// Turkish capital I with dot above ('İ', 2 bytes -> "i\u0307", 3 bytes)
	// expands strings.ToLower length beyond len(text) before the IOC match.
	text := strings.Repeat("İ", 120) + " https://awstore.cloud/payload"
	fs := eng.Inspect(text, "test")
	if !hasRule(fs, "ioc-domain") {
		t.Fatalf("expected ioc-domain finding, got %+v", fs)
	}
	for _, f := range fs {
		if !utf8.ValidString(f.Match) {
			t.Errorf("finding %s Match is invalid UTF-8: %q", f.RuleID, f.Match)
		}
		if !utf8.ValidString(f.Excerpt) {
			t.Errorf("finding %s Excerpt is invalid UTF-8: %q", f.RuleID, f.Excerpt)
		}
	}

	cyrillic := strings.Repeat("ПриветМир", 30)
	tr := truncate(cyrillic, 19)
	if !utf8.ValidString(tr) {
		t.Fatalf("truncate split UTF-8 rune: %q", tr)
	}
}
