package inspect

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// findingKeys renders a finding set as sorted (rule id, match) pairs.
func findingKeys(fs []Finding) []string {
	keys := make([]string, 0, len(fs))
	for _, f := range fs {
		keys = append(keys, f.RuleID+"\x00"+f.Match)
	}
	sort.Strings(keys)
	return keys
}

func hasRule(fs []Finding, id string) bool {
	for _, f := range fs {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

// stripKeywordsBytes rebuilds rules.json without the optional keywords field,
// so the same rule set can be evaluated by the unfiltered engine.
func stripKeywordsBytes(raw []byte) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse rules: %w", err)
	}
	rules, _ := doc["rules"].([]any)
	for _, r := range rules {
		if m, ok := r.(map[string]any); ok {
			delete(m, "keywords")
		}
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("marshal rules: %w", err)
	}
	return out, nil
}

// stripKeywords is the testing.TB-flavoured wrapper around stripKeywordsBytes.
func stripKeywords(t testing.TB, raw []byte) []byte {
	t.Helper()
	out, err := stripKeywordsBytes(raw)
	if err != nil {
		t.Fatalf("strip keywords: %v", err)
	}
	return out
}

// TestKeywordPrefilterSoundness is the safety net for the prefilter: the engine
// with keywords MUST produce exactly the same findings as the engine without
// them, for every sample in the corpus and in the detection tests.
func TestKeywordPrefilterSoundness(t *testing.T) {
	rulesJSON, blocklistJSON := EmbeddedSources()
	filtered, err := New(rulesJSON, blocklistJSON)
	if err != nil {
		t.Fatalf("New(rules): %v", err)
	}
	unfiltered, err := New(stripKeywords(t, rulesJSON), blocklistJSON)
	if err != nil {
		t.Fatalf("New(rules without keywords): %v", err)
	}

	var texts []string
	for _, pattern := range []string{"testdata/corpus/malicious/*.txt", "testdata/corpus/clean/*.txt"} {
		paths, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range paths {
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			texts = append(texts, string(b))
		}
	}
	for _, c := range highSeveritySamples {
		texts = append(texts, c.text)
	}
	for _, c := range mediumSeveritySamples {
		texts = append(texts, c.text)
	}
	texts = append(texts, cleanSamples...)

	exercised := map[string]bool{}
	for i, text := range texts {
		want := findingKeys(unfiltered.Inspect(text, "soundness"))
		got := findingKeys(filtered.Inspect(text, "soundness"))
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("sample %d: keyword prefilter changed the findings for %q\n want: %v\n  got: %v",
				i, text, want, got)
		}
		for _, k := range want {
			exercised[strings.SplitN(k, "\x00", 2)[0]] = true
		}
	}

	// Guard against a vacuous test: most keyword-bearing rules must actually be
	// exercised by the samples above.
	var keywordRules int
	var covered int
	for _, r := range filtered.rules {
		if len(r.keywords) == 0 {
			continue
		}
		keywordRules++
		if exercised[r.spec.ID] {
			covered++
		}
	}
	if keywordRules == 0 {
		t.Fatal("no rules declare keywords")
	}
	if covered < keywordRules*3/4 {
		t.Fatalf("soundness samples only exercise %d/%d keyword rules; add samples", covered, keywordRules)
	}
	t.Logf("soundness: %d samples, %d/%d keyword rules exercised (%d rules total)",
		len(texts), covered, keywordRules, filtered.RuleCount())
}

// Every keyword is a case-insensitive literal that must be present for its rule
// to match: verify the compiled form is normalized and that a rule with a
// keyword is skipped when the literal is absent.
func TestKeywordPrefilterMechanics(t *testing.T) {
	rulesJSON := []byte(`{"version":1,"rules":[
		{"id":"kw-rule","category":"test","severity":"high","pattern":"(?i)MAGICWORD\\s*=\\s*1",
		 "keywords":["magicword"],"description":"keyword-gated rule"},
		{"id":"always","category":"test","severity":"low","pattern":"(?i)always",
		 "description":"unfiltered rule"}]}`)
	e, err := New(rulesJSON, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if fs := e.Inspect("nothing suspicious here", "test"); len(fs) != 0 {
		t.Fatalf("expected no findings, got %+v", fs)
	}
	// Keyword absent -> regex skipped; the unfiltered rule still runs.
	fs := e.Inspect("ALWAYS running", "test")
	if !hasRule(fs, "always") || hasRule(fs, "kw-rule") {
		t.Fatalf("keyword-less rule must still run, gated rule must be skipped: %+v", fs)
	}
	// Keyword present (different case) -> rule evaluates and matches.
	fs = e.Inspect("MAGICWORD = 1", "test")
	if !hasRule(fs, "kw-rule") {
		t.Fatalf("gated rule did not fire with its keyword present: %+v", fs)
	}
}

// Parallel rule evaluation must return exactly what the serial loop returns,
// including order, so findings stay deterministic.
func TestParallelRuleEvaluationMatchesSerial(t *testing.T) {
	e := mustEngine(t)
	text := strings.Repeat(adversarialText(), 32) // well above parallelInspectMin
	if len(text) < parallelInspectMin {
		t.Fatalf("test input too small: %d", len(text))
	}
	low := strings.ToLower(text)

	var serial []Finding
	for i := range e.rules {
		if f, ok := e.matchRule(i, text, low, "test"); ok {
			serial = append(serial, f)
		}
	}
	parallel := e.inspectRulesParallel(text, low, "test")
	if !reflect.DeepEqual(serial, parallel) {
		t.Fatalf("parallel findings differ from serial\n serial: %v\nparallel: %v", findingKeys(serial), findingKeys(parallel))
	}
}
