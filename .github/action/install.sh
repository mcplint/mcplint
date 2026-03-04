#!/usr/bin/env bash
set -euo pipefail

VERSION="${MCPLINT_VERSION:-latest}"

# Detect platform
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
  x86_64)  ARCH="x86_64" ;;
  aarch64|arm64) ARCH="aarch64" ;;
  *) echo "::error::Unsupported architecture: $ARCH"; exit 1 ;;
esac

case "$OS" in
  linux)  TARGET="${ARCH}-unknown-linux-gnu" ;;
  darwin) TARGET="${ARCH}-apple-darwin" ;;
  *) echo "::error::Unsupported OS: $OS"; exit 1 ;;
esac

if [ "$VERSION" = "latest" ]; then
  DOWNLOAD_URL="https://github.com/mcplint/mcplint/releases/latest/download/mcplint-${TARGET}.tar.gz"
else
  DOWNLOAD_URL="https://github.com/mcplint/mcplint/releases/download/v${VERSION}/mcplint-${TARGET}.tar.gz"
fi

echo "::group::Installing mcplint ${VERSION} for ${TARGET}"
INSTALL_DIR="${HOME}/.mcplint/bin"
mkdir -p "$INSTALL_DIR"

# Try unversioned URL first, fall back to versioned for older releases
if ! curl -fsSL "$DOWNLOAD_URL" | tar -xz -C "$INSTALL_DIR" 2>/dev/null; then
  echo "::warning::Unversioned archive not found, trying versioned..."
  VERSIONED_URL="https://github.com/mcplint/mcplint/releases/download/v${VERSION}/mcplint-v${VERSION}-${TARGET}.tar.gz"
  curl -fsSL "$VERSIONED_URL" | tar -xz -C "$INSTALL_DIR"
fi

chmod +x "$INSTALL_DIR/mcplint"
echo "$INSTALL_DIR" >> "$GITHUB_PATH"
echo "::endgroup::"

echo "Installed mcplint $("${INSTALL_DIR}"/mcplint --version 2>/dev/null || echo "${VERSION}")"
