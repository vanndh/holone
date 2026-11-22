package inspect

import "regexp"

// holone persists findings to its own audit log and to the dashboard. A
// finding quotes a slice of the provider's payload, so without redaction the
// proxy would write credential material it was supposed to catch (bot tokens,
// webhook URLs, API keys) into ~/.holone/holone.log. Detection always runs on
// the raw text; only the copy stored in a Finding is redacted.
var redactions = []struct {
	re   *regexp.Regexp
	repl string
}{
	// PEM private key blocks (must run early so inner substrings cannot confuse
	// structure, though the whole block body becomes [REDACTED]).
	{regexp.MustCompile(`(?s)(-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----)[\s\S]+?(-----END [A-Z0-9 ]*PRIVATE KEY-----)`), "${1}\n[REDACTED]\n${2}"},
	// Telegram bot token: api.telegram.org/bot<id>:<token>
	{regexp.MustCompile(`(?i)(api\.telegram\.org/bot)[0-9]+:[A-Za-z0-9_-]+`), "${1}[REDACTED]"},
	// Discord webhook: /webhooks/<id>/<token>
	{regexp.MustCompile(`(?i)(/webhooks/)[0-9]+/[A-Za-z0-9_-]+`), "${1}[REDACTED]"},
	// Slack incoming webhook: /services/T.../B.../<token>
	{regexp.MustCompile(`(?i)(/services/)[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+`), "${1}[REDACTED]"},
	// URL Basic Auth credentials: https://user:pass@host
	{regexp.MustCompile(`(https?://[^/\s:@]+:)[^/\s@]+(@)`), "${1}[REDACTED]${2}"},
	// Query-string secret parameters (?api_key=..., &token=..., etc.)
	{regexp.MustCompile(`(?i)([?&](?:api_key|apikey|token|access_token|secret|key)=)([^&\s"'` + "`" + `<>()[\]{},;]{8,})`), "${1}[REDACTED]"},
	// Authorization: Bearer <token> / bearer <token>
	{regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}`), "Bearer [REDACTED]"},
	// OpenAI-style secret keys.
	{regexp.MustCompile(`\b(sk-)[A-Za-z0-9_-]{16,}`), "${1}[REDACTED]"},
	// Slack bot/user tokens. No \b here on purpose: a token glued to other
	// text (e.g. "0xoxa-...") is still a credential, and redaction must not
	// depend on how the provider happened to concatenate it. The xox[baprs]-
	// prefix is distinctive enough that word-internal matching is safe.
	{regexp.MustCompile(`(xox[baprs]-)[A-Za-z0-9-]{10,}`), "${1}[REDACTED]"},
	// GitHub classic and fine-grained tokens.
	{regexp.MustCompile(`\b(gh[pousr]_)[A-Za-z0-9]{20,}`), "${1}[REDACTED]"},
	{regexp.MustCompile(`\b(github_pat_)[A-Za-z0-9_]{20,}`), "${1}[REDACTED]"},
	// Google / Gemini API keys.
	{regexp.MustCompile(`\b(AIza)[0-9A-Za-z_-]{35}\b`), "${1}[REDACTED]"},
	// AWS access key ids (IAM AKIA and STS ASIA).
	{regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`), "${1}[REDACTED]"},
}

// Redact replaces credential-shaped substrings in text while keeping
// surrounding context readable. It is safe and idempotent.
func Redact(text string) string {
	return redact(text)
}

// redact replaces credential-shaped substrings in text destined for holone's
// own log/dashboard while keeping the surrounding context readable.
func redact(text string) string {
	for _, r := range redactions {
		text = r.re.ReplaceAllString(text, r.repl)
	}
	return text
}
