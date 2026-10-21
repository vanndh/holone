#!/bin/sh
# Thin wrapper: print the toolchain, then run every benchmark once.
set -eu
cd "$(dirname "$0")/.."

echo "go version: $(go version)"
go env GOOS GOARCH
echo

exec go test -run '^$' -bench . -benchmem ./internal/...
