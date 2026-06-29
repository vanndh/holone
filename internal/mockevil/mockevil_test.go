package mockevil

import (
	"strings"
	"testing"

	"github.com/vanndh/holone/internal/inspect"
)

// TestEvilCommandsAreDetected runs every mock payload through the real inspect
// engine and asserts each one is caught. This ties the mock provider's injected
// payloads to the detection rules end-to-end (no network): a new profile that
// evades detection fails here before it can reach the proxy integration tests.
func TestEvilCommandsAreDetected(t *testing.T) {
	eng, err := inspect.Default()
	if err != nil {
		t.Fatalf("inspect.Default: %v", err)
	}
	if eng.RuleCount() == 0 {
		t.Fatal("no rules loaded")
	}

	for prof, byProto := range EvilCommands {
		if !IsEvilProfile(prof) {
			t.Errorf("EvilCommands key %q is not treated as an evil profile by IsEvilProfile", prof)
			continue
		}
		for proto, cmd := range byProto {
			cmd, proto := cmd, proto
			t.Run(prof+"/"+proto, func(t *testing.T) {
				fs := eng.Inspect(cmd, "mockevil:"+prof)
				if len(fs) == 0 {
					t.Fatalf("evil payload UNDETECTED (evasion):\n  profile=%s proto=%s\n  payload=%q", prof, proto, cmd)
				}
				// Every evil profile payload must surface at least one
				// high-severity finding — these are active injection payloads,
				// not weak signals.
				if inspect.MaxSeverity(fs) != inspect.SevHigh {
					t.Fatalf("expected a HIGH finding for %s/%s, got max=%s\n  payload=%q\n  findings=%+v",
						prof, proto, inspect.MaxSeverity(fs), cmd, fs)
				}
				t.Logf("%s/%s: %d findings, max=%s — %s", prof, proto, len(fs),
					inspect.MaxSeverity(fs), ruleIDs(fs))
			})
		}
	}
}

// TestCleanProfileIsNotEvil guards the profile gate so an accidental "clean*"
// name can never be treated as an injection profile.
func TestCleanProfileIsNotEvil(t *testing.T) {
	for _, p := range []string{"clean", "", "default", "claude"} {
		if IsEvilProfile(p) {
			t.Errorf("IsEvilProfile(%q) = true, want false", p)
		}
	}
}

// TestEvilProfilePrefixAccepted confirms any "evil*" profile name is recognized
// (so the new evil-cfg / evil-cred / evil-exfil profiles route through the
// injection branch of the streamers).
func TestEvilProfilePrefixAccepted(t *testing.T) {
	for _, p := range []string{"evil", "Evil", "EVIL-CFG", "evil-cred", "evil-exfil"} {
		if !IsEvilProfile(p) {
			t.Errorf("IsEvilProfile(%q) = false, want true", p)
		}
	}
}

func ruleIDs(fs []inspect.Finding) string {
	var ids []string
	for _, f := range fs {
		ids = append(ids, f.RuleID)
	}
	return strings.Join(ids, ", ")
}
