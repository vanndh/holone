package inspect

import (
	"strings"
	"testing"
)

func TestInspectSecretsAndRedactSecrets(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		ruleID string
		secret string
	}{
		{
			name:   "openai key",
			input:  `{"messages":[{"role":"user","content":"my key is sk-proj-abcdefghijklmnop1234567890"}]}`,
			ruleID: "dlp-openai-key",
			secret: "abcdefghijklmnop1234567890",
		},
		{
			name:   "github token",
			input:  `GITHUB_TOKEN=github_pat_11ABCDEFG0123456789_abcdefghijklmnop`,
			ruleID: "dlp-github-token",
			secret: "11ABCDEFG0123456789_abcdefghijklmnop",
		},
		{
			name:   "aws key",
			input:  `aws_access_key_id = AKIAIOSFODNN7EXAMPLE`,
			ruleID: "dlp-aws-key",
			secret: "IOSFODNN7EXAMPLE",
		},
		{
			name:   "google api key",
			input:  `GEMINI_API_KEY=AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe`,
			ruleID: "dlp-google-key",
			secret: "SyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe",
		},
		{
			name:   "pem private key",
			input:  "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSj\n-----END PRIVATE KEY-----",
			ruleID: "dlp-pem-private-key",
			secret: "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSj",
		},
		{
			name:   "url basic auth",
			input:  `connect to https://admin:SuperSecretPass99@db.example.com/api`,
			ruleID: "dlp-url-credentials",
			secret: "SuperSecretPass99",
		},
		{
			name:   "query secret",
			input:  `fetch("https://api.example.com/v1/items?access_token=topsecret_token_98765")`,
			ruleID: "dlp-query-secret",
			secret: "topsecret_token_98765",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := InspectSecrets(tc.input, "egress")
			if !hasRule(fs, tc.ruleID) {
				t.Fatalf("expected %s, got %+v", tc.ruleID, fs)
			}
			for _, f := range fs {
				if f.Category != "egress-dlp" || f.Severity != "high" {
					t.Errorf("unexpected DLP finding metadata: %+v", f)
				}
				if strings.Contains(f.Match, tc.secret) || strings.Contains(f.Excerpt, tc.secret) {
					t.Errorf("DLP finding leaked raw secret %q: %+v", tc.secret, f)
				}
			}

			redacted, rfs := RedactSecrets(tc.input, "egress")
			if len(rfs) != len(fs) {
				t.Fatalf("RedactSecrets findings count = %d, want %d", len(rfs), len(fs))
			}
			if strings.Contains(redacted, tc.secret) {
				t.Fatalf("RedactSecrets left secret %q in output: %q", tc.secret, redacted)
			}
		})
	}

	if fs := InspectSecrets(`{"messages":[{"role":"user","content":"write a fibonacci function in Go"}]}`, "egress"); len(fs) != 0 {
		t.Fatalf("expected no DLP findings on clean prompt, got %+v", fs)
	}
}
