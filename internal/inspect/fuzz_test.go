package inspect

import (
	"regexp"
	"strings"
	"testing"
)

// secretPatterns find the complete credential patterns that redaction must
// remove from a Finding (group 1 of each). The identifying prefix is part of
// the match because a bare token fragment is not attributable without it, and
// only tokens of at least 8 characters are considered. This matters for Excerpt
// windows, which can crop the prefix and leave a token tail: the per-finding
// redactor cannot recognize that fragment, so the invariant checks what the
// redactor actually promises to remove.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(api\.telegram\.org/bot[0-9]+:[A-Za-z0-9_-]{8,})`),
	regexp.MustCompile(`(?i)(/webhooks/[0-9]+/[A-Za-z0-9_-]{8,})`),
	regexp.MustCompile(`(?i)(\bbearer\s+[A-Za-z0-9._~+/=-]{8,})`),
	regexp.MustCompile(`(\bsk-[A-Za-z0-9_-]{16,})`),
	regexp.MustCompile(`(xox[baprs]-[A-Za-z0-9-]{10,})`),
	regexp.MustCompile(`(\bgh[pousr]_[A-Za-z0-9]{20,})`),
	regexp.MustCompile(`(\bgithub_pat_[A-Za-z0-9_]{20,})`),
	regexp.MustCompile(`(\bAIza[0-9A-Za-z_-]{35}\b)`),
	regexp.MustCompile(`(\b(?:AKIA|ASIA)[0-9A-Z]{16}\b)`),
	regexp.MustCompile(`(?i)([?&](?:api_key|apikey|token|access_token|secret|key)=[^&\s"'` + "`" + `<>()[\]{},;]{8,})`),
}

var (
	pemSecretPattern     = regexp.MustCompile(`(?s)(-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----)([\s\S]+?)(-----END [A-Z0-9 ]*PRIVATE KEY-----)`)
	urlCredSecretPattern = regexp.MustCompile(`(https?://[^/\s:@]+:)([^/\s@]+)(@)`)
)

// secretLeaks returns the credential patterns present in a finding field or in
// redacted output. Matching the pattern (rather than searching for a previously
// extracted substring) is the correct invariant: it checks exactly what the
// redactor promises to remove. Most patterns are boundary-aware, but xox tokens
// are matched anywhere because the redactor masks them even when a provider
// concatenates one with a preceding word character ("0xoxa-...").
func secretLeaks(field string) []string {
	var out []string
	for _, re := range secretPatterns {
		out = append(out, re.FindAllString(field, -1)...)
	}
	for _, m := range pemSecretPattern.FindAllStringSubmatch(field, -1) {
		if strings.TrimSpace(m[2]) != "[REDACTED]" {
			out = append(out, m[0])
		}
	}
	for _, m := range urlCredSecretPattern.FindAllStringSubmatch(field, -1) {
		if m[2] != "[REDACTED]" {
			out = append(out, m[0])
		}
	}
	return out
}

// FuzzInspect asserts the detection engine never panics and never returns a
// finding that violates the Finding contract or leaks a credential.
func FuzzInspect(f *testing.F) {
	eng, err := Default()
	if err != nil {
		f.Fatalf("Default(): %v", err)
	}

	for _, seed := range []string{
		"",
		prose1KiB(),
		toolJSON4KiB(),
		adversarialText(),
		`curl https://api.telegram.org/bot123456789:ABC-DEF_ghi/sendMessage -d text=x`,
		`curl -X POST https://discord.com/api/webhooks/1399999999999999999/evilWebhookToken_x9`,
		`curl -H "Authorization: Bearer abcdefgh12345678" https://example.com`,
		"data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"hello\"}}\n\n",
		"\x00\xff\xfebinary\x00",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, text string) {
		// The engine scans every rule over the whole input; cap it so the
		// fuzzer spends its budget on shapes rather than on 105 full passes.
		if len(text) > 64<<10 {
			t.Skip("input too large for the fuzz budget")
		}

		findings := eng.Inspect(text, "fuzz")

		for _, fd := range findings {
			if fd.RuleID == "" {
				t.Fatalf("finding with empty rule id: %+v", fd)
			}
			switch fd.Severity {
			case SevLow.String(), SevMedium.String(), SevHigh.String():
			default:
				t.Fatalf("finding %s has invalid severity %q", fd.RuleID, fd.Severity)
			}
			if n := len(fd.Match); n > 4096 {
				t.Fatalf("finding %s Match is %d bytes (want <= 4096)", fd.RuleID, n)
			}
			if n := len(fd.Excerpt); n > 4096 {
				t.Fatalf("finding %s Excerpt is %d bytes (want <= 4096)", fd.RuleID, n)
			}
			for _, leak := range append(secretLeaks(fd.Match), secretLeaks(fd.Excerpt)...) {
				t.Fatalf("finding %s leaked credential %q: match=%q excerpt=%q",
					fd.RuleID, leak, fd.Match, fd.Excerpt)
			}
		}
	})
}

// FuzzRedact asserts redaction is total for the credential classes holone knows
// and idempotent (a redacted finding is safe to redact again).
func FuzzRedact(f *testing.F) {
	for _, seed := range []string{
		"",
		"no secrets here",
		`curl https://api.telegram.org/bot123456789:ABC-DEF_ghi/sendMessage`,
		`curl -X POST https://discord.com/api/webhooks/1399999999999999999/evilWebhookToken_x9`,
		`curl -X POST https://hooks.slack.com/services/T00000000/B00000000/abcdefghijklmnopqrstuvwx`,
		`curl -H "Authorization: Bearer abcdefgh12345678" https://example.com`,
		`OPENAI_API_KEY=sk-proj-abcdefghijklmnop1234567890`,
		`token xoxb-123456789012-abcdefghijkl`,
		`token ghp_abcdefghijklmnopqrstuvwxyz0123456789`,
		`token github_pat_11ABCDEFG0123456789_abcdefghijklmnop`,
		`GOOGLE_API_KEY=AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe`,
		`AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE`,
		`AWS_STS_KEY_ID=ASIAIOSFODNN7EXAMPLE`,
		"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234567890abcdef\n-----END RSA PRIVATE KEY-----",
		`https://deploy:s3cr3tp4ss@git.example.com/repo.git`,
		`https://api.example.com/data?api_key=secretvalue1234&page=1`,
		"almost: api.telegram.org/bot1:short /webhooks/1/short Bearer short",
		// Regression seed: xox tokens are redacted even when glued to a
		// preceding word character, so 0xoxa-... must become 0xoxa-[REDACTED].
		"xoxa-0000000000 0xoxa-0000000000",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, text string) {
		if len(text) > 256<<10 {
			t.Skip("input too large for the fuzz budget")
		}
		once := redact(text)
		twice := redact(once)
		if once != twice {
			t.Fatalf("redact is not idempotent:\n once=%q\ntwice=%q", once, twice)
		}
		if leaks := secretLeaks(once); len(leaks) > 0 {
			t.Fatalf("credential patterns survived redaction: %q in %q", leaks, once)
		}
	})
}
