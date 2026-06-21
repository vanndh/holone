#!/bin/sh
# holone installer for linux / macos
#
#   curl -fsSL https://raw.githubusercontent.com/vanndh/holone/main/scripts/install.sh | sh
#
# downloads the latest release binary for your os/cpu and installs it to
# /usr/local/bin (or ~/.local/bin if that is not writable).

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
    url="https://github.com/${repo}/releases/latest/download/${asset}"
else
    url="https://github.com/${repo}/releases/download/${version}/${asset}"
fi

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
echo "  downloading..."
if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$tmp"
else
    wget -qO "$tmp" "$url"
fi
chmod +x "$tmp"
$sudo mv "$tmp" "${bindir}/holone"

echo "  installed:"
"${bindir}/holone" version || true
echo ""
case ":$PATH:" in
    *":$bindir:"*) ;;
    *) echo "  note: add $bindir to your PATH:"; echo "    export PATH=\"$bindir:\$PATH\"" ;;
esac
echo ""
echo "  next: holone proxy --upstream https://your-provider"
echo ""
