#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<EOF
Usage: $0 <aar|debug|release>

Subcommands:
  aar      Build android/app/libs/tunssh.aar via gomobile bind
  debug    Build AAR (unless SKIP_AAR=1 and AAR exists) and assembleDebug APK
  release  Build AAR (unless SKIP_AAR=1 and AAR exists) and assembleRelease APKs
EOF
}

if [[ $# -ne 1 ]]; then
  usage
  exit 1
fi

SUBCOMMAND="$1"
case "$SUBCOMMAND" in
  aar|debug|release) ;;
  -h|--help)
    usage
    exit 0
    ;;
  *)
    echo "Error: Unknown subcommand '$SUBCOMMAND'" >&2
    usage
    exit 1
    ;;
esac

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${VERSION:-$(git -C "$REPO_ROOT" describe --tags --always --dirty 2>/dev/null || echo 0.2.0)}"
CLEAN_VERSION="${VERSION#v}"

if [[ -z "${ANDROID_VERSION_CODE:-}" ]]; then
  commit_count="$(git -C "$REPO_ROOT" rev-list --count HEAD 2>/dev/null || echo 1)"
  if [[ "$commit_count" =~ ^[0-9]+$ ]] && [[ "$commit_count" -ge 1 ]]; then
    ANDROID_VERSION_CODE="$commit_count"
  else
    ANDROID_VERSION_CODE=1
  fi
fi

if [[ ! "$ANDROID_VERSION_CODE" =~ ^[0-9]+$ ]] || [[ "$ANDROID_VERSION_CODE" -lt 1 ]]; then
  echo "Error: ANDROID_VERSION_CODE must be an integer >= 1 (got: '$ANDROID_VERSION_CODE')" >&2
  exit 1
fi

DIST_DIR="${DIST_DIR:-$REPO_ROOT/dist}"
AAR_OUT="$REPO_ROOT/android/app/libs/tunssh.aar"
ANDROID_GO_TARGETS="${ANDROID_GO_TARGETS:-android/arm64,android/amd64}"

CLEANUP_DIRS=()
cleanup() {
  local d
  if [[ ${#CLEANUP_DIRS[@]} -gt 0 ]]; then
    for d in "${CLEANUP_DIRS[@]}"; do
      if [[ -n "$d" && -d "$d" ]]; then
        rm -rf "$d"
      fi
    done
  fi
}
trap cleanup EXIT

if ! command -v go >/dev/null 2>&1; then
  echo "Error: 'go' is not installed or not in PATH." >&2
  exit 1
fi

GOPATH_BIN="$(go env GOPATH)/bin"
if [[ -d "$GOPATH_BIN" ]]; then
  export PATH="$GOPATH_BIN:$PATH"
fi

ensure_gomobile_and_sdk() {
  local cmd
  for cmd in gomobile gobind; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo "Error: '$cmd' not found in PATH (checked '$GOPATH_BIN')." >&2
      echo "Install with:" >&2
      echo "  go install golang.org/x/mobile/cmd/gomobile@latest" >&2
      echo "  go install golang.org/x/mobile/cmd/gobind@latest" >&2
      echo "  gomobile init" >&2
      exit 1
    fi
  done

  local sdk_dir="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
  if [[ -z "$sdk_dir" ]]; then
    local candidate
    for candidate in "$HOME/Android/Sdk" "/usr/local/lib/android/sdk" "/opt/android-sdk"; do
      if [[ -d "$candidate" ]]; then
        sdk_dir="$candidate"
        break
      fi
    done
  fi
  if [[ -z "$sdk_dir" || ! -d "$sdk_dir" ]]; then
    echo "Error: Android SDK not found. Set ANDROID_HOME or ANDROID_SDK_ROOT to an Android SDK directory (API 35 + NDK)." >&2
    exit 1
  fi
  export ANDROID_HOME="$sdk_dir"
  export ANDROID_SDK_ROOT="$sdk_dir"

  local ndk_dir="${ANDROID_NDK_HOME:-}"
  if [[ -z "$ndk_dir" || ! -d "$ndk_dir" ]]; then
    if [[ -d "$sdk_dir/ndk" ]]; then
      ndk_dir="$(find "$sdk_dir/ndk" -mindepth 1 -maxdepth 1 -type d | sort -V | tail -n 1 || true)"
    fi
  fi
  if [[ -z "$ndk_dir" || ! -d "$ndk_dir" ]]; then
    if [[ -d "$sdk_dir/ndk-bundle" ]]; then
      ndk_dir="$sdk_dir/ndk-bundle"
    fi
  fi
  if [[ -z "$ndk_dir" || ! -d "$ndk_dir" ]]; then
    echo "Error: Android NDK not found under '$sdk_dir/ndk' or ANDROID_NDK_HOME." >&2
    echo "Install via sdkmanager, e.g.: sdkmanager \"ndk;27.2.12479018\"" >&2
    exit 1
  fi
  export ANDROID_NDK_HOME="$ndk_dir"
}

build_aar() {
  ensure_gomobile_and_sdk

  local go_ver
  go_ver="$(sed -n 's/^go[[:space:]]\+\([0-9][^[:space:]]*\).*/\1/p' "$REPO_ROOT/go.mod" | head -n 1)"
  go_ver="${go_ver:-1.26.3}"

  local stage_dir
  stage_dir="$(mktemp -d)"
  CLEANUP_DIRS+=("$stage_dir")

  mkdir -p "$(dirname "$AAR_OUT")"

  cat > "$stage_dir/go.mod" <<EOF
module gobridge

go ${go_ver}

require github.com/AlirezaDelkhahi/tunssh v0.0.0

replace github.com/AlirezaDelkhahi/tunssh => ${REPO_ROOT}
EOF
  cp "$REPO_ROOT/go.sum" "$stage_dir/go.sum"

  cat > "$stage_dir/bridge.go" <<'EOF'
package gobridge

import (
	_ "github.com/AlirezaDelkhahi/tunssh/mobile"
	_ "golang.org/x/mobile/bind"
	_ "golang.org/x/mobile/bind/java"
	_ "golang.org/x/mobile/bind/seq"
)
EOF

  echo "Building Android AAR ($ANDROID_GO_TARGETS) -> $AAR_OUT"
  (
    cd "$stage_dir"
    export GOWORK=off
    go get golang.org/x/mobile/bind@latest
    go mod tidy
    gomobile bind \
      -target="$ANDROID_GO_TARGETS" \
      -androidapi 26 \
      -ldflags="-s -w" \
      -javapkg dev.tunssh \
      -o "$AAR_OUT" \
      github.com/AlirezaDelkhahi/tunssh/mobile
  )
}

run_gradle() {
  local gradle_cmd
  if [[ -x "$REPO_ROOT/android/gradlew" ]]; then
    gradle_cmd="$REPO_ROOT/android/gradlew"
  elif command -v gradle >/dev/null 2>&1; then
    gradle_cmd="gradle"
  else
    echo "Error: Neither '$REPO_ROOT/android/gradlew' nor 'gradle' in PATH was found." >&2
    exit 1
  fi

  "$gradle_cmd" \
    -p "$REPO_ROOT/android" \
    "-PtunsshVersionName=$CLEAN_VERSION" \
    "-PtunsshVersionCode=$ANDROID_VERSION_CODE" \
    "$@"
}

maybe_build_aar() {
  if [[ "${SKIP_AAR:-0}" == "1" && -f "$AAR_OUT" ]]; then
    echo "Skipping AAR build (SKIP_AAR=1 and $AAR_OUT exists)"
  else
    build_aar
  fi
}

build_debug() {
  maybe_build_aar
  run_gradle assembleDebug

  mkdir -p "$DIST_DIR"
  local apk_dir="$REPO_ROOT/android/app/build/outputs/apk/debug"
  local found=0
  while IFS= read -r -d '' apk; do
    cp -f "$apk" "$DIST_DIR/"
    echo "Packaged debug APK: $DIST_DIR/$(basename "$apk")"
    found=1
  done < <(find "$apk_dir" -type f -name '*.apk' -print0 2>/dev/null || true)

  if [[ "$found" -eq 0 ]]; then
    echo "Error: No debug APKs found under '$apk_dir'." >&2
    exit 1
  fi
}

build_release() {
  maybe_build_aar

  local sign_dir
  sign_dir="$(mktemp -d)"
  CLEANUP_DIRS+=("$sign_dir")

  local stripped_b64
  stripped_b64="$(printf '%s' "${ANDROID_KEYSTORE_BASE64:-}" | tr -d ' \t\r\n')"

  if [[ -n "$stripped_b64" ]]; then
    if [[ -z "${ANDROID_KEYSTORE_PASSWORD:-}" ]]; then
      echo "Error: ANDROID_KEYSTORE_BASE64 is configured, but ANDROID_KEYSTORE_PASSWORD is empty." >&2
      exit 1
    fi
    printf '%s' "$stripped_b64" | base64 -d > "$sign_dir/release.keystore"
    export ANDROID_KEYSTORE_PATH="$sign_dir/release.keystore"
    export ANDROID_KEYSTORE_PASSWORD
    export ANDROID_KEY_ALIAS="${ANDROID_KEY_ALIAS:-tunssh}"
    export ANDROID_KEY_PASSWORD="${ANDROID_KEY_PASSWORD:-$ANDROID_KEYSTORE_PASSWORD}"
  elif [[ -n "${ANDROID_KEYSTORE_PATH:-}" ]]; then
    if [[ ! -r "$ANDROID_KEYSTORE_PATH" ]]; then
      echo "Error: ANDROID_KEYSTORE_PATH ('$ANDROID_KEYSTORE_PATH') does not exist or is not readable." >&2
      exit 1
    fi
    if [[ -z "${ANDROID_KEYSTORE_PASSWORD:-}" ]]; then
      echo "Error: ANDROID_KEYSTORE_PATH is configured, but ANDROID_KEYSTORE_PASSWORD is empty." >&2
      exit 1
    fi
    export ANDROID_KEYSTORE_PATH
    export ANDROID_KEYSTORE_PASSWORD
    export ANDROID_KEY_ALIAS="${ANDROID_KEY_ALIAS:-tunssh}"
    export ANDROID_KEY_PASSWORD="${ANDROID_KEY_PASSWORD:-$ANDROID_KEYSTORE_PASSWORD}"
  else
    if ! command -v keytool >/dev/null 2>&1; then
      echo "Error: 'keytool' not found in PATH to generate an ephemeral release keystore." >&2
      exit 1
    fi
    echo "WARNING: ANDROID_KEYSTORE_BASE64 / ANDROID_KEYSTORE_PATH not configured; generating an ephemeral ad-hoc PKCS#12 release signing key for this build." >&2
    local eph_pass
    eph_pass="$(od -An -tx1 -N 16 /dev/urandom | tr -d ' \n')"
    export ANDROID_KEYSTORE_PATH="$sign_dir/ephemeral-release.p12"
    export ANDROID_KEYSTORE_PASSWORD="$eph_pass"
    export ANDROID_KEY_ALIAS="tunssh"
    export ANDROID_KEY_PASSWORD="$eph_pass"
    keytool -genkeypair -noprompt \
      -keystore "$ANDROID_KEYSTORE_PATH" \
      -storetype PKCS12 \
      -alias "$ANDROID_KEY_ALIAS" \
      -keyalg RSA \
      -keysize 2048 \
      -validity 365 \
      -storepass:env ANDROID_KEYSTORE_PASSWORD \
      -keypass:env ANDROID_KEY_PASSWORD \
      -dname "CN=tunssh, OU=Release, O=tunssh, L=Unknown, ST=Unknown, C=US" >/dev/null
  fi

  run_gradle assembleRelease

  mkdir -p "$DIST_DIR"
  local release_dir="$REPO_ROOT/android/app/build/outputs/apk/release"
  local arm64_src universal_src
  arm64_src="$(find "$release_dir" -type f -name 'app-arm64-v8a-release.apk' 2>/dev/null | head -n 1 || true)"
  universal_src="$(find "$release_dir" -type f -name 'app-universal-release.apk' 2>/dev/null | head -n 1 || true)"

  if [[ -z "$arm64_src" || ! -f "$arm64_src" ]]; then
    echo "Error: Expected arm64 release APK (app-arm64-v8a-release.apk) was not produced under '$release_dir'." >&2
    exit 1
  fi
  if [[ -z "$universal_src" || ! -f "$universal_src" ]]; then
    echo "Error: Expected universal release APK (app-universal-release.apk) was not produced under '$release_dir'." >&2
    exit 1
  fi

  local arm64_dest="$DIST_DIR/tunssh-${CLEAN_VERSION}-android-arm64.apk"
  local universal_dest="$DIST_DIR/tunssh-${CLEAN_VERSION}-android-universal.apk"
  cp -f "$arm64_src" "$arm64_dest"
  cp -f "$universal_src" "$universal_dest"
  echo "Packaged release APK: $arm64_dest"
  echo "Packaged release APK: $universal_dest"
}

case "$SUBCOMMAND" in
  aar)
    build_aar
    ;;
  debug)
    build_debug
    ;;
  release)
    build_release
    ;;
esac
