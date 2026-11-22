package inspect

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	// RuleToolSensitiveFile is emitted when a file-access tool targets a
	// sensitive credential store directly (e.g. ~/.ssh/id_rsa) without shell.
	RuleToolSensitiveFile = "cred-tool-sensitive-file"
	// RuleToolSensitiveWrite is emitted when a file-write tool modifies an AI
	// client config, git hook, CI workflow, or shell RC file.
	RuleToolSensitiveWrite = "cfg-tool-sensitive-write"
)

// UnescapeJSONEscapes decodes JSON escape sequences (\uXXXX including UTF-16
// surrogate pairs, \", \/, \\, \n, \r, \t, \b, \f) in s without requiring s to
// be a complete JSON document. Unknown escapes (like Windows \U or \.) are kept
// verbatim so raw paths are never corrupted.
func UnescapeJSONEscapes(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] != '\\' || i+1 >= len(s) {
			sb.WriteByte(s[i])
			i++
			continue
		}
		switch s[i+1] {
		case '"', '/', '\\':
			sb.WriteByte(s[i+1])
			i += 2
		case 'b':
			sb.WriteByte('\b')
			i += 2
		case 'f':
			sb.WriteByte('\f')
			i += 2
		case 'n':
			sb.WriteByte('\n')
			i += 2
		case 'r':
			sb.WriteByte('\r')
			i += 2
		case 't':
			sb.WriteByte('\t')
			i += 2
		case 'u':
			if i+6 <= len(s) {
				if r1, ok := parseHex4(s[i+2 : i+6]); ok {
					if utf16.IsSurrogate(r1) && i+12 <= len(s) && s[i+6] == '\\' && s[i+7] == 'u' {
						if r2, ok2 := parseHex4(s[i+8 : i+12]); ok2 {
							combined := utf16.DecodeRune(r1, r2)
							if combined != utf8.RuneError {
								sb.WriteRune(combined)
								i += 12
								continue
							}
						}
					}
					sb.WriteRune(r1)
					i += 6
					continue
				}
			}
			sb.WriteByte(s[i])
			i++
		default:
			sb.WriteByte(s[i])
			i++
		}
	}
	return sb.String()
}

func parseHex4(hex string) (rune, bool) {
	if len(hex) != 4 {
		return 0, false
	}
	v, err := strconv.ParseUint(hex, 16, 16)
	if err != nil {
		return 0, false
	}
	return rune(v), true
}

const (
	maxExtractedStrings = 2048
	maxExtractedBytes   = 2 << 20
)

// ExtractJSONStrings parses raw as JSON and collects all string leaf values in
// deterministic key order. Returns nil if raw is not valid JSON.
func ExtractJSONStrings(raw string) []string {
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return nil
	}
	var out []string
	var totalBytes int
	var walk func(any)
	walk = func(node any) {
		if len(out) >= maxExtractedStrings || totalBytes >= maxExtractedBytes {
			return
		}
		switch x := node.(type) {
		case string:
			if x != "" {
				out = append(out, x)
				totalBytes += len(x)
			}
		case []any:
			for _, elem := range x {
				walk(elem)
				if len(out) >= maxExtractedStrings || totalBytes >= maxExtractedBytes {
					return
				}
			}
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(x[k])
				if len(out) >= maxExtractedStrings || totalBytes >= maxExtractedBytes {
					return
				}
			}
		}
	}
	walk(v)
	return out
}

// InspectToolArgs inspects tool-call arguments in three complementary views:
// raw text, JSON-unescaped text (catching \uXXXX evasion even in fragments),
// decoded JSON string leaves, and tool-aware file path/content inspection.
func (e *Engine) InspectToolArgs(toolName, rawArgs, source string) []Finding {
	if e == nil || rawArgs == "" {
		return nil
	}
	var out []Finding
	seen := make(map[string]struct{})
	add := func(fs ...Finding) {
		for _, f := range fs {
			key := f.RuleID + "\x00" + f.Match
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, f)
		}
	}

	add(e.Inspect(rawArgs, source)...)
	if strings.ContainsRune(rawArgs, '\\') {
		unescaped := UnescapeJSONEscapes(rawArgs)
		if unescaped != rawArgs {
			add(e.Inspect(unescaped, source)...)
		}
	}
	if strs := ExtractJSONStrings(rawArgs); len(strs) > 0 {
		joined := strings.Join(strs, "\n")
		if joined != rawArgs {
			add(e.Inspect(joined, source)...)
		}
	}
	if toolName != "" {
		add(e.inspectFileTool(toolName, rawArgs, source)...)
	}
	return out
}

var (
	readToolNames = map[string]bool{
		"read": true, "read_file": true, "view_file": true, "cat": true,
		"open_file": true, "get_file": true, "readfile": true, "view": true,
	}
	writeToolNames = map[string]bool{
		"write": true, "write_file": true, "write_to_file": true,
		"edit": true, "edit_file": true, "multiedit": true, "multi_edit": true,
		"replace_file_content": true, "multi_replace_file_content": true,
		"notebookedit": true, "create_file": true, "str_replace_editor": true,
		"apply_patch": true, "save_file": true, "patch": true,
	}
)

var sensitiveCredFileSubstrs = []string{
	"/.ssh/id_rsa",
	"/.ssh/id_ed25519",
	"/.ssh/id_ecdsa",
	"/.ssh/id_dsa",
	"/.aws/credentials",
	"/.kube/config",
	"/.docker/config.json",
	"/.netrc",
	"/.azure/accesstokens",
	"/.azure/msal_token_cache",
	"/.config/gcloud/credentials",
	"google/chrome/default/login data",
	"google/chrome/default/cookies",
	"google/chrome/local state",
}

type sensitiveWriteTarget struct {
	substr     string
	alwaysHigh bool
}

var sensitiveConfigWriteTargets = []sensitiveWriteTarget{
	{".claude/settings.json", false},
	{".claude/settings.local.json", false},
	{".claude.json", false},
	{".claude/hooks/", true},
	{".mcp.json", true},
	{".cursor/mcp.json", true},
	{".git/hooks/", true},
	{".github/workflows/", true},
	{"/.bashrc", true},
	{"/.zshrc", true},
	{"/.profile", true},
	{"/.bash_profile", true},
	{"/.zprofile", true},
	{"/.npmrc", true},
	{"/.pip/pip.conf", true},
	{"/pip.ini", true},
	{"/launchagents/", true},
	{"/launchdaemons/", true},
	{"/etc/systemd/system/", true},
	{"/etc/cron.", true},
}

func (e *Engine) inspectFileTool(toolName, rawArgs, source string) []Finding {
	normTool := strings.ToLower(strings.TrimSpace(toolName))
	isRead := readToolNames[normTool]
	isWrite := writeToolNames[normTool]
	if !isRead && !isWrite {
		return nil
	}

	var obj map[string]any
	if err := json.Unmarshal([]byte(rawArgs), &obj); err != nil {
		return nil
	}
	paths, content := extractToolPathsAndContent(obj)
	if len(paths) == 0 {
		return nil
	}

	var out []Finding
	for _, rawPath := range paths {
		norm := normalizeToolPath(rawPath)
		if isSensitiveCredPath(norm) {
			f := Finding{
				RuleID:      RuleToolSensitiveFile,
				Category:    "credential-theft",
				Severity:    SevHigh.String(),
				Match:       redact(truncate(rawPath, 160)),
				Excerpt:     redact(truncate(toolName+" path="+rawPath, 200)),
				Source:      source,
				Description: "File tool targets a sensitive credential store (" + truncate(rawPath, 80) + ")",
			}
			if pf, ok := e.ApplyPolicy(f); ok {
				out = append(out, pf)
			}
		}
		if isWrite {
			if matched, alwaysHigh := matchSensitiveWriteTarget(norm); matched {
				sev := SevMedium
				if alwaysHigh || writePayloadHasHookOrExec(content) {
					sev = SevHigh
				}
				f := Finding{
					RuleID:      RuleToolSensitiveWrite,
					Category:    "client-config",
					Severity:    sev.String(),
					Match:       redact(truncate(rawPath, 160)),
					Excerpt:     redact(truncate(toolName+" write path="+rawPath, 200)),
					Source:      source,
					Description: "File write tool targets sensitive client config or persistence file (" + truncate(rawPath, 80) + ")",
				}
				if pf, ok := e.ApplyPolicy(f); ok {
					out = append(out, pf)
				}
			}
		}
	}
	return out
}

func extractToolPathsAndContent(obj map[string]any) ([]string, string) {
	var paths []string
	var content strings.Builder
	seenPath := make(map[string]bool)
	addPath := func(s string) {
		s = strings.TrimSpace(s)
		if s != "" && !seenPath[s] {
			seenPath[s] = true
			paths = append(paths, s)
		}
	}

	var walk func(node any, depth int)
	walk = func(node any, depth int) {
		if depth > 4 {
			return
		}
		switch x := node.(type) {
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				v := x[k]
				lk := strings.ToLower(strings.ReplaceAll(k, "_", ""))
				if sv, ok := v.(string); ok {
					switch lk {
					case "filepath", "path", "targetfile", "filename", "file", "absolutepath":
						addPath(sv)
					case "content", "newstring", "newstr", "oldstring", "patch", "code", "replacement", "replacementcontent", "text":
						if content.Len() < 64<<10 {
							content.WriteString(sv)
							content.WriteByte('\n')
						}
					}
				} else {
					walk(v, depth+1)
				}
			}
		case []any:
			for _, el := range x {
				walk(el, depth+1)
			}
		}
	}
	walk(obj, 0)
	return paths, content.String()
}

func normalizeToolPath(p string) string {
	norm := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(p, "\\", "/")))
	if strings.HasPrefix(norm, "~/") {
		norm = norm[1:] // "/..."
	} else if !strings.HasPrefix(norm, "/") {
		norm = "/" + norm
	}
	return norm
}

func isSensitiveCredPath(norm string) bool {
	if strings.HasSuffix(norm, ".pub") {
		return false
	}
	for _, sub := range sensitiveCredFileSubstrs {
		if strings.Contains(norm, sub) {
			// Avoid matching "~/.ssh/id_rsa_backup_note.md" unless exact or dir-matched?
			// Allow exact suffix or common variants like id_rsa / id_rsa.pem, but skip .pub above.
			return true
		}
	}
	return false
}

func matchSensitiveWriteTarget(norm string) (matched bool, alwaysHigh bool) {
	for _, tgt := range sensitiveConfigWriteTargets {
		needle := tgt.substr
		if !strings.HasPrefix(needle, "/") {
			needle = "/" + needle
		}
		if strings.Contains(norm, needle) {
			if tgt.alwaysHigh {
				return true, true
			}
			matched = true
		}
	}
	return matched, false
}

func writePayloadHasHookOrExec(content string) bool {
	low := strings.ToLower(content)
	for _, marker := range []string{
		"pretooluse", "posttooluse", "userpromptsubmit", "\"hooks\"", "mcpservers", "mcp_servers",
		"curl ", "wget ", "powershell", "invoke-expression", "/bin/sh", "/bin/bash", "npx ", "uvx ",
	} {
		if strings.Contains(low, marker) {
			return true
		}
	}
	return false
}
