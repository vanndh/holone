package proxy

import (
	"fmt"
	"strings"
)

// DLPMode controls how the proxy treats secrets detected in outbound requests
// before they are sent to an upstream LLM provider.
type DLPMode int

const (
	DLPModeOff DLPMode = iota
	DLPModeWarn
	DLPModeBlock
	DLPModeRedact
)

func (m DLPMode) String() string {
	switch m {
	case DLPModeWarn:
		return "warn"
	case DLPModeBlock:
		return "block"
	case DLPModeRedact:
		return "redact"
	default:
		return "off"
	}
}

// ParseDLPMode maps a CLI/config string to a DLPMode.
func ParseDLPMode(s string) (DLPMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "off", "none", "disabled":
		return DLPModeOff, nil
	case "warn", "monitor":
		return DLPModeWarn, nil
	case "block":
		return DLPModeBlock, nil
	case "redact", "mask":
		return DLPModeRedact, nil
	default:
		return DLPModeOff, fmt.Errorf("unknown egress-dlp mode %q (want off|warn|block|redact)", s)
	}
}
