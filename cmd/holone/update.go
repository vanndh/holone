package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	latestReleaseURL = "https://api.github.com/repos/vanndh/holone/releases/latest"
	updateCacheTTL   = 12 * time.Hour
)

type githubRelease struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
}

type updateCache struct {
	CheckedAt time.Time     `json:"checked_at"`
	Release   githubRelease `json:"release"`
}

func checkForUpdate(args []string) {
	if updateCheckDisabled(args) {
		return
	}
	cachePath := defaultUpdateCachePath()
	if release, ok := readFreshUpdateCache(cachePath, updateCacheTTL); ok {
		if notice := updateNotice(release, version); notice != "" {
			fmt.Fprint(os.Stderr, notice)
		}
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	release, err := fetchLatestGitHubRelease(ctx, http.DefaultClient, latestReleaseURL)
	if err != nil {
		return
	}
	_ = writeUpdateCache(cachePath, release, time.Now())
	if notice := updateNotice(release, version); notice != "" {
		fmt.Fprint(os.Stderr, notice)
	}
}

func updateCheckDisabled(args []string) bool {
	if truthy(os.Getenv("HOLONE_NO_UPDATE_CHECK")) {
		return true
	}
	for _, arg := range args[1:] {
		if arg == "--no-update-check" {
			return true
		}
	}
	return false
}

func argsWithoutUpdateFlag(args []string) []string {
	out := args[:0]
	for _, arg := range args {
		if arg != "--no-update-check" {
			out = append(out, arg)
		}
	}
	return out
}

func truthy(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "1" || s == "true" || s == "yes" || s == "on"
}

func defaultUpdateCachePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "holone-update-check.json"
	}
	return filepath.Join(home, ".holone", "update-check.json")
}

func readFreshUpdateCache(path string, ttl time.Duration) (githubRelease, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return githubRelease{}, false
	}
	var cache updateCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return githubRelease{}, false
	}
	if strings.TrimSpace(cache.Release.TagName) == "" || time.Since(cache.CheckedAt) > ttl {
		return githubRelease{}, false
	}
	return cache.Release, true
}

func writeUpdateCache(path string, release githubRelease, checkedAt time.Time) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(updateCache{CheckedAt: checkedAt.UTC(), Release: release}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func fetchLatestGitHubRelease(ctx context.Context, client *http.Client, endpoint string) (githubRelease, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return githubRelease{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "holone/"+version)

	resp, err := client.Do(req)
	if err != nil {
		return githubRelease{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return githubRelease{}, fmt.Errorf("github releases: HTTP %d", resp.StatusCode)
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return githubRelease{}, err
	}
	if strings.TrimSpace(release.TagName) == "" {
		return githubRelease{}, fmt.Errorf("github releases: empty tag_name")
	}
	return release, nil
}

func updateNotice(release githubRelease, current string) string {
	if !isNewerVersion(release.TagName, current) {
		return ""
	}
	url := strings.TrimSpace(release.HTMLURL)
	if url == "" {
		url = "https://github.com/vanndh/holone/releases/tag/" + release.TagName
	}
	return fmt.Sprintf("Update available / Доступно обновление: holone %s (current/текущая %s)\n%s\n", release.TagName, current, url)
}

func isNewerVersion(latest, current string) bool {
	lv := parseVersion(latest)
	cv := parseVersion(current)
	for i := 0; i < len(lv) || i < len(cv); i++ {
		var l, c int
		if i < len(lv) {
			l = lv[i]
		}
		if i < len(cv) {
			c = cv[i]
		}
		if l != c {
			return l > c
		}
	}
	return false
}

func parseVersion(v string) []int {
	v = strings.TrimSpace(strings.TrimPrefix(v, "v"))
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			out = append(out, 0)
			continue
		}
		for i, r := range p {
			if r < '0' || r > '9' {
				p = p[:i]
				break
			}
		}
		n, _ := strconv.Atoi(p)
		out = append(out, n)
	}
	return out
}
