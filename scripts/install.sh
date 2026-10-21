#!/bin/sh
# holone installer for linux / macos
#
#   curl -fsSL https://raw.githubusercontent.com/vanndh/holone/main/scripts/install.sh | sh
#
# downloads the latest release binary for your os/cpu, verifies its sha-256
# against the release's SHA256SUMS.txt, and installs it to /usr/local/bin (or
# ~/.local/bin if that is not writable).

set -eu

repo="vanndh/holone"
version="${HOLONE_VERSION:-latest}"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$os" in
    linux)  os="linux" ;;
    darwin) os="darwin" ;;
    *) echo "unsupported os: $os (use the windows installer or download manually)"; exit 1 ;;
esac

arch="$(uname -m)"
case "$arch" in
    x86_64|amd64) arch="amd64" ;;
    arm64|aarch64) arch="arm64" ;;
    *) echo "unsupported arch: $arch"; exit 1 ;;
esac

asset="holone-${os}-${arch}"
if [ "$version" = "latest" ]; then
    base="https://github.com/${repo}/releases/latest/download"
else
    base="https://github.com/${repo}/releases/download/${version}"
fi
url="${base}/${asset}"
sums_url="${base}/SHA256SUMS.txt"

# pick an install dir we can actually write to
if [ -w /usr/local/bin ] 2>/dev/null; then
    bindir="/usr/local/bin"; sudo=""
elif command -v sudo >/dev/null 2>&1; then
    bindir="/usr/local/bin"; sudo="sudo"
else
    bindir="$HOME/.local/bin"; sudo=""
fi
mkdir -p "$bindir" 2>/dev/null || true

echo ""
echo "  holone installer"
echo "  target: ${os}/${arch}"
echo "  source: ${url}"
echo "  into:   ${bindir}/holone"
echo ""

tmp="$(mktemp)"
sums="$(mktemp)"
cleanup() {
    rm -f "$tmp" "$sums"
}
trap cleanup EXIT
trap 'cleanup; exit 1' HUP INT TERM

fetch() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$1" -o "$2"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$2" "$1"
    else
        echo "ERROR: need curl or wget to download ${1}" >&2
        exit 1
    fi
}

echo "  downloading..."
if ! fetch "$url" "$tmp"; then
    echo "ERROR: failed to download ${url}" >&2
    exit 1
fi
echo "  downloading checksums..."
if ! fetch "$sums_url" "$sums"; then
    echo "ERROR: failed to download ${sums_url}" >&2
    exit 1
fi

# exact-asset lookup in "<hex>  <asset-name>" lines; tolerate a "*" binary marker.
expected="$(
    awk -v name="$asset" '
        {
            f = $2
            sub(/^\*/, "", f)
            if (f == name) { print $1; exit }
        }
    ' "$sums"
)"
if [ -z "$expected" ]; then
    echo "ERROR: downloaded holone binary failed integrity verification" >&2
    echo "       no SHA-256 entry for ${asset} in SHA256SUMS.txt" >&2
    exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$tmp" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "$tmp" | awk '{print $1}')"
elif command -v openssl >/dev/null 2>&1; then
    actual="$(openssl dgst -sha256 "$tmp" | awk '{print $NF}')"
else
    echo "ERROR: downloaded holone binary failed integrity verification" >&2
    echo "       no SHA-256 tool found (need sha256sum, shasum, or openssl)" >&2
    exit 1
fi

actual="$(printf '%s' "$actual" | tr 'A-F' 'a-f')"
expected="$(printf '%s' "$expected" | tr 'A-F' 'a-f')"
if [ "$actual" != "$expected" ]; then
    echo "ERROR: downloaded holone binary failed integrity verification" >&2
    echo "       expected ${expected}" >&2
    echo "       got      ${actual}" >&2
    exit 1
fi

echo "  verified sha256: ${actual}"
chmod +x "$tmp"
$sudo mv "$tmp" "${bindir}/holone"

echo "  installed:"
"${bindir}/holone" version --no-update-check || true
echo ""
case ":$PATH:" in
    *":$bindir:"*) ;;
    *) echo "  note: add $bindir to your PATH:"; echo "    export PATH=\"$bindir:\$PATH\"" ;;
esac
echo ""
echo "  next: holone proxy --upstream https://your-provider"
echo ""
