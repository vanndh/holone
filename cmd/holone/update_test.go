package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		name    string
		latest  string
		current string
		newer   bool
	}{
		{name: "minor newer", latest: "v0.4.0", current: "0.3.0", newer: true},
		{name: "patch newer", latest: "0.3.1", current: "v0.3.0", newer: true},
		{name: "same", latest: "v0.3.0", current: "0.3.0", newer: false},
		{name: "older", latest: "v0.2.9", current: "0.3.0", newer: false},
		{name: "double digit", latest: "v0.10.0", current: "0.9.9", newer: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNewerVersion(tt.latest, tt.current); got != tt.newer {
				t.Fatalf("isNewerVersion(%q, %q) = %v, want %v", tt.latest, tt.current, got, tt.newer)
			}
		})
	}
}

func TestFetchLatestGitHubRelease(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/releases/latest" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"tag_name":"v0.4.0","html_url":"https://github.com/vanndh/holone/releases/tag/v0.4.0"}`))
	}))
	defer ts.Close()

	latest, err := fetchLatestGitHubRelease(context.Background(), ts.Client(), ts.URL+"/releases/latest")
	if err != nil {
		t.Fatal(err)
	}
	if latest.TagName != "v0.4.0" || latest.HTMLURL == "" {
		t.Fatalf("unexpected release: %+v", latest)
	}
}

func TestUpdateNotice(t *testing.T) {
	release := githubRelease{TagName: "v0.4.0", HTMLURL: "https://github.com/vanndh/holone/releases/tag/v0.4.0"}
	got := updateNotice(release, "0.3.0")
	want := "Update available / Доступно обновление: holone v0.4.0 (current/текущая 0.3.0)\nhttps://github.com/vanndh/holone/releases/tag/v0.4.0\n"
	if got != want {
		t.Fatalf("notice mismatch\ngot:  %q\nwant: %q", got, want)
	}

	if got := updateNotice(release, "0.4.0"); got != "" {
		t.Fatalf("expected no notice for current release, got %q", got)
	}
}

func TestUpdateCheckCanBeDisabled(t *testing.T) {
	t.Setenv("HOLONE_NO_UPDATE_CHECK", "1")
	if !updateCheckDisabled([]string{"holone", "scan", "https://example.com"}) {
		t.Fatal("env should disable update checks")
	}

	t.Setenv("HOLONE_NO_UPDATE_CHECK", "")
	if !updateCheckDisabled([]string{"holone", "--no-update-check", "version"}) {
		t.Fatal("global flag should disable update checks")
	}
	if !updateCheckDisabled([]string{"holone", "scan", "--no-update-check", "https://example.com"}) {
		t.Fatal("command flag should disable update checks")
	}
}

func TestArgsWithoutUpdateFlag(t *testing.T) {
	got := argsWithoutUpdateFlag([]string{"holone", "scan", "--no-update-check", "https://example.com"})
	want := []string{"holone", "scan", "https://example.com"}
	if len(got) != len(want) {
		t.Fatalf("len mismatch: got %+v want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("arg %d mismatch: got %+v want %+v", i, got, want)
		}
	}
}

func TestUpdateCacheFreshness(t *testing.T) {
	path := filepath.Join(t.TempDir(), "update-check.json")
	release := githubRelease{TagName: "v0.4.0", HTMLURL: "https://github.com/vanndh/holone/releases/tag/v0.4.0"}
	if err := writeUpdateCache(path, release, time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	cached, ok := readFreshUpdateCache(path, 12*time.Hour)
	if !ok {
		t.Fatal("expected fresh cache")
	}
	if cached.TagName != release.TagName || cached.HTMLURL != release.HTMLURL {
		t.Fatalf("unexpected cached release: %+v", cached)
	}

	if err := writeUpdateCache(path, release, time.Now().Add(-24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, ok := readFreshUpdateCache(path, 12*time.Hour); ok {
		t.Fatal("expected stale cache")
	}
}
