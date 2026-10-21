# Thin wrapper: print the toolchain, then run every benchmark once.
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

Write-Output "go version: $(go version)"
go env GOOS GOARCH
Write-Output ""

go test -run '^$' -bench . -benchmem ./internal/...
