package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type fileConfig struct {
	Mode              string            `json:"mode,omitempty"`
	Protocol          string            `json:"protocol,omitempty"`
	EgressDLP         string            `json:"egress_dlp,omitempty"`
	DisableRules      []string          `json:"disable_rules,omitempty"`
	SeverityOverrides map[string]string `json:"severity_overrides,omitempty"`
	LogAlertsOnly     bool              `json:"log_alerts_only,omitempty"`
	MaxRequestSize    string            `json:"max_request_size,omitempty"`
	MaxResponseSize   string            `json:"max_response_size,omitempty"`
	Rules             string            `json:"rules,omitempty"`
	Blocklist         string            `json:"blocklist,omitempty"`
}

func defaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".holone", "config.json")
}

func loadConfigFile(path string, explicit bool) (fileConfig, error) {
	if path == "" {
		path = defaultConfigPath()
		if path == "" {
			return fileConfig{}, nil
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) && !explicit {
			return fileConfig{}, nil
		}
		return fileConfig{}, fmt.Errorf("read config %q: %w", path, err)
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return fileConfig{}, nil
	}
	var cfg fileConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return fileConfig{}, fmt.Errorf("parse config %q: %w", path, err)
	}
	return cfg, nil
}

func parseRuleIDList(csv string) []string {
	if strings.TrimSpace(csv) == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(csv, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
