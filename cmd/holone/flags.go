package main

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

func normalizeScanArgs(args []string) []string {
	if len(args) == 0 || len(args[0]) == 0 || args[0][0] == '-' {
		return args
	}
	out := append([]string{}, args[1:]...)
	out = append(out, args[0])
	return out
}

// parseByteSize parses a byte count for the proxy body-size flags. It accepts a
// plain integer number of bytes ("1048576") or an integer with a binary size
// suffix ("512KiB", "32MiB", "1GiB"). KB/MB/GB are accepted as the same
// 1024-based units, and the suffix is case-insensitive. An empty string means
// "not set" and returns 0, leaving the proxy's built-in default in place.
func parseByteSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}

	// Split the numeric prefix from the unit suffix; a sign, a decimal point or
	// any other leading character is rejected rather than silently guessed at.
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, fmt.Errorf("invalid size %q: want bytes or <n>KiB/MiB/GiB", s)
	}
	num, err := strconv.ParseInt(s[:i], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q: %v", s, err)
	}

	unit := strings.ToLower(strings.TrimSpace(s[i:]))
	var mult int64
	switch unit {
	case "", "b":
		mult = 1
	case "k", "kb", "kib":
		mult = 1 << 10
	case "m", "mb", "mib":
		mult = 1 << 20
	case "g", "gb", "gib":
		mult = 1 << 30
	default:
		return 0, fmt.Errorf("invalid size %q: unknown unit %q (want B/KiB/MiB/GiB)", s, s[i:])
	}

	if num > math.MaxInt64/mult {
		return 0, fmt.Errorf("invalid size %q: too large", s)
	}
	return num * mult, nil
}
