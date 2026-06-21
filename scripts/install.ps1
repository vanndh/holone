# holone installer for windows (powershell)
#
#   irm https://raw.githubusercontent.com/vanndh/holone/main/scripts/install.ps1 | iex
#
# downloads the latest release binary for your cpu, drops it in
# %LOCALAPPDATA%\holone and adds that folder to your user PATH.

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$repo = 'vanndh/holone'
$arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
$asset = "holone-windows-$arch.exe"
$version = if ($env:HOLONE_VERSION) { $env:HOLONE_VERSION } else { 'latest' }
$url = if ($version -eq 'latest') {
    "https://github.com/$repo/releases/latest/download/$asset"
} else {
    "https://github.com/$repo/releases/download/$version/$asset"
}

$dir = Join-Path $env:LOCALAPPDATA 'holone'
$dest = Join-Path $dir 'holone.exe'

Write-Host ""
Write-Host "  holone installer" -ForegroundColor Cyan
Write-Host "  arch:    windows/$arch"
Write-Host "  source:  $url"
Write-Host "  target:  $dest"
Write-Host ""

New-Item -ItemType Directory -Force -Path $dir | Out-Null
Write-Host "  downloading..." -NoNewline
Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing
Write-Host " done" -ForegroundColor Green

# add to user PATH if missing
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($userPath -notlike "*$dir*") {
    [Environment]::SetEnvironmentVariable('Path', "$userPath;$dir", 'User')
    Write-Host "  added $dir to your user PATH (restart the terminal to pick it up)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "  installed:" -ForegroundColor Green
& $dest version
Write-Host ""
Write-Host "  next:" -ForegroundColor Cyan
Write-Host "    holone proxy --upstream https://your-provider"
Write-Host "    then point your client's base URL at http://127.0.0.1:8787"
Write-Host ""
