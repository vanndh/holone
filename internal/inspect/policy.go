package inspect

import "strings"

// Policy customizes which rules are active and overrides severities (for
// example, downgrading a noisy rule to medium when working on security code).
type Policy struct {
	DisabledRules     []string          `json:"disabled_rules,omitempty"`
	SeverityOverrides map[string]string `json:"severity_overrides,omitempty"`
}

// WithPolicy returns an immutable copy of e with the given policy applied.
func (e *Engine) WithPolicy(p Policy) *Engine {
	if e == nil {
		return nil
	}
	if len(p.DisabledRules) == 0 && len(p.SeverityOverrides) == 0 {
		return e
	}
	disabled := make(map[string]bool, len(p.DisabledRules))
	for _, id := range p.DisabledRules {
		id = strings.TrimSpace(id)
		if id != "" {
			disabled[id] = true
		}
	}
	overrides := make(map[string]Severity, len(p.SeverityOverrides))
	for id, sev := range p.SeverityOverrides {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		overrides[id] = ParseSeverity(sev)
	}

	out := &Engine{
		rules:         make([]compiledRule, 0, len(e.rules)),
		terms:         append([]blockTerm(nil), e.terms...),
		blocklist:     e.Blocklist(),
		descByID:      make(map[string]string, len(e.descByID)),
		disabledRules: disabled,
		sevOverrides:  overrides,
	}
	for k, v := range e.descByID {
		out.descByID[k] = v
	}
	for _, r := range e.rules {
		if disabled[r.spec.ID] {
			continue
		}
		rc := r
		if sev, ok := overrides[rc.spec.ID]; ok {
			rc.sev = sev
			rc.spec.Severity = sev.String()
		}
		if len(rc.keywords) > 0 {
			out.hasKeywords = true
		}
		out.rules = append(out.rules, rc)
	}
	return out
}

// ApplyPolicy applies rule disabling and severity overrides to synthetic or
// tool-aware findings that are not compiled from rules.json regexes.
func (e *Engine) ApplyPolicy(f Finding) (Finding, bool) {
	if e == nil {
		return f, true
	}
	if e.disabledRules[f.RuleID] {
		return Finding{}, false
	}
	if sev, ok := e.sevOverrides[f.RuleID]; ok {
		f.Severity = sev.String()
	}
	return f, true
}
