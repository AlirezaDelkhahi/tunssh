#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <amd64|arm64> <dest_dir>" >&2
  exit 1
fi

ARCH="$1"
DEST_DIR="$2"

case "$ARCH" in
  amd64) SHA_CONST="WintunSHA256AMD64" ;;
  arm64) SHA_CONST="WintunSHA256ARM64" ;;
  *)
    echo "Unsupported Wintun architecture: $ARCH (expected amd64 or arm64)" >&2
    exit 1
    ;;
esac

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENGINE_GO="$REPO_ROOT/internal/tun/engine.go"
if [[ ! -f "$ENGINE_GO" ]]; then
  echo "Cannot locate $ENGINE_GO to read $SHA_CONST" >&2
  exit 1
fi

EXPECTED_DLL_SHA="$(sed -n "s/^[[:space:]]*${SHA_CONST}[[:space:]]*=[[:space:]]*\"\([0-9a-fA-F]\{64\}\)\".*/\1/p" "$ENGINE_GO" | tr '[:upper:]' '[:lower:]' | head -n 1)"
if [[ ! "$EXPECTED_DLL_SHA" =~ ^[0-9a-f]{64}$ ]]; then
  echo "Failed to extract valid 64-hex digest for $SHA_CONST from $ENGINE_GO" >&2
  exit 1
fi

WINTUN_URL="https://www.wintun.net/builds/wintun-0.14.1.zip"
EXPECTED_ZIP_SHA="07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"

mkdir -p "$DEST_DIR"
DEST_DLL="$DEST_DIR/wintun.dll"

verify_sha256() {
  local file="$1"
  local expected="$2"
  local actual
  actual="$(sha256sum "$file" | awk '{print tolower($1)}')"
  if [[ "$actual" != "$expected" ]]; then
    echo "SHA-256 mismatch for $file: got $actual, want $expected" >&2
    return 1
  fi
}

if [[ -f "$DEST_DLL" ]] && verify_sha256 "$DEST_DLL" "$EXPECTED_DLL_SHA" >/dev/null 2>&1; then
  echo "Verified existing $DEST_DLL ($ARCH: $EXPECTED_DLL_SHA)"
  exit 0
fi

for cmd in curl unzip sha256sum; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Required tool '$cmd' not found in PATH" >&2
    exit 1
  fi
done

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

ZIP_PATH="$TMP_DIR/wintun-0.14.1.zip"
echo "Downloading Wintun 0.14.1 for $ARCH..."
curl -fsSL --retry 3 --retry-delay 2 -o "$ZIP_PATH" "$WINTUN_URL"
verify_sha256 "$ZIP_PATH" "$EXPECTED_ZIP_SHA"

unzip -q -j "$ZIP_PATH" "wintun/bin/${ARCH}/wintun.dll" -d "$TMP_DIR"
verify_sha256 "$TMP_DIR/wintun.dll" "$EXPECTED_DLL_SHA"

TMP_OUT="$(mktemp "$DEST_DIR/.wintun.dll.XXXXXX")"
cp "$TMP_DIR/wintun.dll" "$TMP_OUT"
chmod 0755 "$TMP_OUT"
mv -f "$TMP_OUT" "$DEST_DLL"
echo "Installed verified $DEST_DLL ($ARCH: $EXPECTED_DLL_SHA)"
