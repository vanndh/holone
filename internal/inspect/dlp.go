package inspect

import (
	"regexp"
	"strings"
)

type secretDetector struct {
	ruleID      string
	re          *regexp.Regexp
	description string
	// skipMatch optionally filters out already-redacted placeholders.
	skipMatch func(m string) bool
}

var secretDetectors = []secretDetector{
	{
		ruleID:      "dlp-openai-key",
		re:          regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{16,}`),
		description: "Outbound text contains an OpenAI/Anthropic-style secret API key (sk-...)",
	},
	{
		ruleID:      "dlp-github-token",
		re:          regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})`),
		description: "Outbound text contains a GitHub personal access token",
	},
	{
		ruleID:      "dlp-aws-key",
		re:          regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`),
		description: "Outbound text contains an AWS access key ID (AKIA/ASIA)",
	},
	{
		ruleID:      "dlp-google-key",
		re:          regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`),
		description: "Outbound text contains a Google / Gemini API key (AIza...)",
	},
	{
		ruleID:      "dlp-slack-token",
		re:          regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`),
		description: "Outbound text contains a Slack API token (xox...)",
	},
	{
		ruleID:      "dlp-telegram-bot",
		re:          regexp.MustCompile(`(?i)api\.telegram\.org/bot[0-9]+:[A-Za-z0-9_-]+`),
		description: "Outbound text contains a Telegram bot token",
	},
	{
		ruleID:      "dlp-discord-webhook",
		re:          regexp.MustCompile(`(?i)/webhooks/[0-9]+/[A-Za-z0-9_-]+`),
		description: "Outbound text contains a Discord webhook token URL",
	},
	{
		ruleID:      "dlp-slack-webhook",
		re:          regexp.MustCompile(`(?i)/services/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+`),
		description: "Outbound text contains a Slack webhook URL",
	},
	{
		ruleID:      "dlp-bearer-token",
		re:          regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}`),
		description: "Outbound text contains a Bearer authorization token",
	},
	{
		ruleID:      "dlp-pem-private-key",
		re:          regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z0-9 ]*PRIVATE KEY-----`),
		description: "Outbound text contains a PEM private key block",
		skipMatch: func(m string) bool {
			return strings.Contains(m, "\n[REDACTED]\n")
		},
	},
	{
		ruleID:      "dlp-url-credentials",
		re:          regexp.MustCompile(`https?://[^/\s:@]+:[^/\s@]+@`),
		description: "Outbound text contains HTTP(S) URL Basic Auth credentials",
		skipMatch: func(m string) bool {
			return strings.Contains(m, ":[REDACTED]@")
		},
	},
	{
		ruleID:      "dlp-query-secret",
		re:          regexp.MustCompile(`(?i)[?&](?:api_key|apikey|token|access_token|secret|key)=[^&\s"'` + "`" + `<>()[\]{},;]{8,}`),
		description: "Outbound text contains a secret token in a URL query parameter",
	},
}

// InspectSecrets scans outbound request text for credential material (DLP).
// Matches and excerpts are redacted so logs and UI never echo the raw secret.
func InspectSecrets(text, source string) []Finding {
	if text == "" {
		return nil
	}
	var out []Finding
	seen := make(map[string]struct{})
	for _, det := range secretDetectors {
		locs := det.re.FindAllStringIndex(text, -1)
		for _, loc := range locs {
			rawMatch := text[loc[0]:loc[1]]
			if det.skipMatch != nil && det.skipMatch(rawMatch) {
				continue
			}
			redactedMatch := redact(truncate(rawMatch, 160))
			key := det.ruleID + "\x00" + redactedMatch
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, Finding{
				RuleID:      det.ruleID,
				Category:    "egress-dlp",
				Severity:    SevHigh.String(),
				Match:       redactedMatch,
				Excerpt:     redact(excerpt(text, loc[0], loc[1])),
				Source:      source,
				Description: det.description,
			})
		}
	}
	return out
}

// RedactSecrets masks credential material in text and reports all DLP findings.
func RedactSecrets(text, source string) (string, []Finding) {
	findings := InspectSecrets(text, source)
	if len(findings) == 0 {
		return text, nil
	}
	return redact(text), findings
}
