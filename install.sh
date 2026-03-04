#!/usr/bin/env bash
# Install mcplint — static security analyzer for MCP configurations
# Usage: curl -fsSL https://raw.githubusercontent.com/mcplint/mcplint/main/install.sh | bash
set -euo pipefail

VERSION="${MCPLINT_VERSION:-latest}"
INSTALL_DIR="${MCPLINT_INSTALL_DIR:-$HOME/.local/bin}"

# Detect platform
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
  x86_64)        ARCH="x86_64" ;;
  aarch64|arm64) ARCH="aarch64" ;;
  *) echo "Error: unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

case "$OS" in
  linux)  TARGET="${ARCH}-unknown-linux-gnu" ;;
  darwin) TARGET="${ARCH}-apple-darwin" ;;
  *) echo "Error: unsupported OS: $OS" >&2; exit 1 ;;
esac

if [ "$VERSION" = "latest" ]; then
  URL="https://github.com/mcplint/mcplint/releases/latest/download/mcplint-${TARGET}.tar.gz"
else
  URL="https://github.com/mcplint/mcplint/releases/download/${VERSION}/mcplint-${TARGET}.tar.gz"
fi

echo "Installing mcplint ${VERSION} for ${TARGET}..."
mkdir -p "$INSTALL_DIR"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

curl -fsSL "$URL" -o "$TMPDIR/mcplint.tar.gz"
tar xzf "$TMPDIR/mcplint.tar.gz" -C "$TMPDIR"
install -m 755 "$TMPDIR/mcplint" "$INSTALL_DIR/mcplint"

echo "Installed mcplint to ${INSTALL_DIR}/mcplint"

# Check if INSTALL_DIR is in PATH
case ":$PATH:" in
  *":${INSTALL_DIR}:"*) ;;
  *)
    echo ""
    echo "Add to your PATH:"
    echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
    ;;
esac

echo ""
"${INSTALL_DIR}/mcplint" --version
