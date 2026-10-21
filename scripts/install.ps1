# holone installer for windows (powershell)
#
#   irm https://raw.githubusercontent.com/vanndh/holone/main/scripts/install.ps1 | iex
#
# downloads the latest release binary for your cpu, verifies its sha-256
# against the release's SHA256SUMS.txt, drops it in %LOCALAPPDATA%\holone and
# adds that folder to your user PATH.

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$repo = 'vanndh/holone'
$arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
$asset = "holone-windows-$arch.exe"
$version = if ($env:HOLONE_VERSION) { $env:HOLONE_VERSION } else { 'latest' }
$base = if ($version -eq 'latest') {
    "https://github.com/$repo/releases/latest/download"
} else {
    "https://github.com/$repo/releases/download/$version"
}
$url = "$base/$asset"
$sumsUrl = "$base/SHA256SUMS.txt"

$dir = Join-Path $env:LOCALAPPDATA 'holone'
$dest = Join-Path $dir 'holone.exe'

Write-Host ""
Write-Host "  holone installer" -ForegroundColor Cyan
Write-Host "  arch:    windows/$arch"
Write-Host "  source:  $url"
Write-Host "  target:  $dest"
Write-Host ""

New-Item -ItemType Directory -Force -Path $dir | Out-Null

$tmp = Join-Path $env:TEMP ("holone-download-" + [guid]::NewGuid().ToString('N') + '.exe')
$sumsTmp = Join-Path $env:TEMP ("holone-sha256sums-" + [guid]::NewGuid().ToString('N') + '.txt')

try {
    Write-Host "  downloading..." -NoNewline
    Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing
    Write-Host " binary" -NoNewline
    Invoke-WebRequest -Uri $sumsUrl -OutFile $sumsTmp -UseBasicParsing
    Write-Host " + checksums" -ForegroundColor Green

    $expected = $null
    foreach ($line in Get-Content -Path $sumsTmp) {
        $parts = $line.Trim() -split '\s+'
        if ($parts.Count -ge 2) {
            $name = $parts[1].TrimStart('*')
            if ($name -eq $asset) {
                $expected = $parts[0].ToLowerInvariant()
                break
            }
        }
    }
    if (-not $expected) {
        throw "ERROR: downloaded holone binary failed integrity verification (no SHA-256 entry for $asset in SHA256SUMS.txt)"
    }

    $actual = (Get-FileHash -Algorithm SHA256 -Path $tmp).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        throw "ERROR: downloaded holone binary failed integrity verification (expected $expected, got $actual)"
    }
    Write-Host "  verified sha256: $actual" -ForegroundColor Green

    Move-Item -Force -Path $tmp -Destination $dest
} catch {
    if (Test-Path $tmp) { Remove-Item -Force $tmp -ErrorAction SilentlyContinue }
    throw
} finally {
    if (Test-Path $sumsTmp) { Remove-Item -Force $sumsTmp -ErrorAction SilentlyContinue }
}

# add to user PATH if missing
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($userPath -notlike "*$dir*") {
    [Environment]::SetEnvironmentVariable('Path', "$userPath;$dir", 'User')
    Write-Host "  added $dir to your user PATH (restart the terminal to pick it up)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "  installed:" -ForegroundColor Green
& $dest version --no-update-check
Write-Host ""
Write-Host "  next:" -ForegroundColor Cyan
Write-Host "    holone proxy --upstream https://your-provider"
Write-Host "    then point your client's base URL at http://127.0.0.1:8787"
Write-Host ""
