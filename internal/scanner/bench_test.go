package scanner

import "testing"

// BenchmarkNormalizeBaseURL measures validation/defaulting of a user-supplied
// base URL (scheme injection, trailing-slash trim, query/fragment drop).
func BenchmarkNormalizeBaseURL(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if _, err := normalizeBaseURL("api.example.com/v1/?token=x#frag"); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEndpointURL measures endpoint construction from an already parsed
// base; it must not append a second /v1 when the base already carries one.
func BenchmarkEndpointURL(b *testing.B) {
	base, err := normalizeBaseURL("https://api.example.com/v1/")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := endpointURL(base, ProtocolChatCompletions, ""); err != nil {
			b.Fatal(err)
		}
	}
}
