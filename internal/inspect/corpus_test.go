package inspect

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCorpus runs the engine over a directory-based corpus so contributors can
// add a new attack sample (or a benign counter-example) just by dropping a file:
//
//	testdata/corpus/malicious/*.txt  -> must produce at least one finding
//	testdata/corpus/clean/*.txt      -> must produce zero findings
//
// Each .txt file holds one raw payload (a tool input / command / response text).
func TestCorpus(t *testing.T) {
	e := mustEngine(t)

	t.Run("malicious", func(t *testing.T) {
		for _, path := range glob(t, "testdata/corpus/malicious/*.txt") {
			path := path
			t.Run(filepath.Base(path), func(t *testing.T) {
				fs := e.Inspect(readFile(t, path), "corpus")
				if len(fs) == 0 {
					t.Errorf("malicious sample produced NO findings (evasion): %s", filepath.Base(path))
				}
			})
		}
	})

	t.Run("clean", func(t *testing.T) {
		for _, path := range glob(t, "testdata/corpus/clean/*.txt") {
			path := path
			t.Run(filepath.Base(path), func(t *testing.T) {
				if fs := e.Inspect(readFile(t, path), "corpus"); len(fs) != 0 {
					t.Errorf("clean sample produced findings (false positive) in %s:\n  %+v", filepath.Base(path), fs)
				}
			})
		}
	})
}

func glob(t *testing.T, pattern string) []string {
	t.Helper()
	m, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
