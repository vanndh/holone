package main

import "testing"

func TestNormalizeScanArgsAllowsFlagsAfterURL(t *testing.T) {
	got := normalizeScanArgs([]string{"https://example.com", "--json", "--model", "gpt-4o", "--key", "sk-test"})
	want := []string{"--json", "--model", "gpt-4o", "--key", "sk-test", "https://example.com"}
	if len(got) != len(want) {
		t.Fatalf("len mismatch: got %+v want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("arg %d mismatch: got %+v want %+v", i, got, want)
		}
	}
}
