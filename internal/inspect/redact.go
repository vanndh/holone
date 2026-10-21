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
	// Telegram bot token: api.telegram.org/bot<id>:<token>
	{regexp.MustCompile(`(?i)(api\.telegram\.org/bot)[0-9]+:[A-Za-z0-9_-]+`), "${1}[REDACTED]"},
	// Discord webhook: /webhooks/<id>/<token>
	{regexp.MustCompile(`(?i)(/webhooks/)[0-9]+/[A-Za-z0-9_-]+`), "${1}[REDACTED]"},
	// Slack incoming webhook: /services/T.../B.../<token>
	{regexp.MustCompile(`(?i)(/services/)[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+`), "${1}[REDACTED]"},
	// Authorization: Bearer <token> / bearer <token>
	{regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}`), "Bearer [REDACTED]"},
	// OpenAI-style secret keys.
	{regexp.MustCompile(`\b(sk-)[A-Za-z0-9_-]{16,}`), "${1}[REDACTED]"},
	// Slack bot/user tokens.
	{regexp.MustCompile(`\b(xox[baprs]-)[A-Za-z0-9-]{10,}`), "${1}[REDACTED]"},
	// GitHub tokens.
	{regexp.MustCompile(`\b(gh[pousr]_)[A-Za-z0-9]{20,}`), "${1}[REDACTED]"},
	// AWS access key ids.
	{regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), "AKIA[REDACTED]"},
}

// redact replaces credential-shaped substrings in text destined for holone's
// own log/dashboard while keeping the surrounding context readable.
func redact(text string) string {
	for _, r := range redactions {
		text = r.re.ReplaceAllString(text, r.repl)
	}
	return text
}
