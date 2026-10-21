package scanner

import (
	"strings"
	"testing"
)

// FuzzEndpointURL asserts base-URL normalization and endpoint construction never
// panic, and that the automatic "/v1" join never duplicates the segment when no
// explicit path override is given.
func FuzzEndpointURL(f *testing.F) {
	f.Add("https://api.example.com", "", ProtocolChatCompletions)
	f.Add("api.example.com", "", ProtocolResponses)
	f.Add("https://api.example.com/v1", "", ProtocolAnthropic)
	f.Add("https://api.example.com/v1/", "", ProtocolChatCompletions)
	f.Add("http://localhost:8080/proxy", "", ProtocolChatCompletions)
	f.Add("https://user:pass@[::1]:8443/v1", "", ProtocolResponses)
	f.Add("https://api.example.com", "/v1/messages", ProtocolAnthropic)
	f.Add("https://api.example.com/base", "/custom", ProtocolChatCompletions)
	f.Add("", "", ProtocolAuto)
	f.Add("ftp://api.example.com", "", ProtocolChatCompletions)

	f.Fuzz(func(t *testing.T, raw, pathOverride, protocol string) {
		if len(raw) > 4096 || len(pathOverride) > 4096 || len(protocol) > 64 {
			t.Skip("input exceeds the fuzz budget")
		}

		base, err := normalizeBaseURL(raw)
		if err != nil {
			return
		}
		got, err := endpointURL(base, protocol, pathOverride)
		if err != nil {
			return
		}

		if pathOverride != "" {
			// An explicit --path is used as given; duplication there is the
			// caller's input, not a join bug.
			return
		}
		lower := strings.ToLower(got)
		if strings.Contains(lower, "/v1/v1") && !strings.Contains(strings.ToLower(base.Path), "/v1/v1") {
			t.Fatalf("endpointURL(%q, %q) duplicated /v1: %q", raw, protocol, got)
		}
	})
}
