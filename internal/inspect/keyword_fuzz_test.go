package inspect

import (
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
)

// The equivalence fuzz target needs both engines once per test process: the
// production rule set (with keywords) and the same rules with the optional
// keywords field stripped.
var (
	kwEnginesOnce sync.Once
	kwFiltered    *Engine
	kwUnfiltered  *Engine
	kwEnginesErr  error
)

func keywordEngines() (*Engine, *Engine, error) {
	kwEnginesOnce.Do(func() {
		rulesJSON, blocklistJSON := EmbeddedSources()
		kwFiltered, kwEnginesErr = New(rulesJSON, blocklistJSON)
		if kwEnginesErr != nil {
			return
		}
		stripped, err := stripKeywordsBytes(rulesJSON)
		if err != nil {
			kwEnginesErr = err
			return
		}
		kwUnfiltered, kwEnginesErr = New(stripped, blocklistJSON)
	})
	return kwFiltered, kwUnfiltered, kwEnginesErr
}

// FuzzKeywordPrefilterEquivalence is the differential check behind the keyword
// prefilter: for any input, the engine that uses keywords MUST return the same
// findings (rule id + match) as the engine that evaluates every regex. A
// divergence means a keyword is not actually implied by its pattern.
func FuzzKeywordPrefilterEquivalence(f *testing.F) {
	filtered, unfiltered, err := keywordEngines()
	if err != nil {
		f.Fatalf("build engines: %v", err)
	}

	// Seeds: the whole corpus plus every payload from the detection tests, so
	// the mutator starts from inputs that exercise real rules.
	for _, pattern := range []string{
		"testdata/corpus/malicious/*.txt",
		"testdata/corpus/clean/*.txt",
	} {
		paths, err := filepath.Glob(pattern)
		if err != nil {
			f.Fatal(err)
		}
		for _, path := range paths {
			b, err := os.ReadFile(path)
			if err != nil {
				f.Fatal(err)
			}
			f.Add(b)
		}
	}
	for _, c := range highSeveritySamples {
		f.Add([]byte(c.text))
	}
	for _, c := range mediumSeveritySamples {
		f.Add([]byte(c.text))
	}

	// Keep a single fuzz execution bounded: both engines scan the whole input.
	const maxFuzzInput = 64 << 10

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxFuzzInput {
			data = data[:maxFuzzInput]
		}
		text := string(data)
		got := findingKeys(filtered.Inspect(text, "fuzz"))
		want := findingKeys(unfiltered.Inspect(text, "fuzz"))
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("keyword prefilter changed the findings for this input; "+
				"a rule keyword is not guaranteed by its pattern\n"+
				"input (%d bytes): %q\nwith keywords:    %v\nwithout keywords: %v",
				len(text), text, got, want)
		}
	})
}
