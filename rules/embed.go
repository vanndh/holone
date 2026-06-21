// Package rules embeds the default behavioral detection rules and IOC blocklist
// so the compiled binary is fully self-contained (no external data files needed).
package rules

import _ "embed"

//go:embed rules.json
var RulesJSON []byte

//go:embed blocklist.json
var BlocklistJSON []byte
