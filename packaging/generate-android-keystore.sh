#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<EOF
Usage: $0 [output_p12_path]

Generates a PKCS#12 Android release signing keystore (.p12) and a matching
single-line Base64 file (.p12.b64) with strict 0600 permissions for GitHub Actions.

Environment variables:
  ANDROID_KEY_ALIAS  Key alias inside the keystore (default: tunssh)
EOF
}

if [[ $# -gt 1 ]]; then
  usage
  exit 1
fi

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

KEYSTORE_PATH="${1:-$HOME/tunssh-android-release.p12}"
B64_PATH="${KEYSTORE_PATH}.b64"
ALIAS="${ANDROID_KEY_ALIAS:-tunssh}"

for cmd in keytool base64; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Error: '$cmd' is not installed or not in PATH." >&2
    exit 1
  fi
done

if [[ -e "$KEYSTORE_PATH" ]]; then
  echo "Error: Keystore already exists at '$KEYSTORE_PATH'." >&2
  echo "Remove it first or pass a different output path: $0 /path/to/new-release.p12" >&2
  exit 1
fi

if [[ -e "$B64_PATH" ]]; then
  echo "Error: Base64 output file already exists at '$B64_PATH'." >&2
  echo "Remove it first or pass a different output path: $0 /path/to/new-release.p12" >&2
  exit 1
fi

umask 077
mkdir -p "$(dirname "$KEYSTORE_PATH")"

cleanup_secrets() {
  unset STORE_PASS CONFIRM_PASS KEYTOOL_STOREPASS 2>/dev/null || true
}
trap cleanup_secrets EXIT

while true; do
  read -r -s -p "Enter keystore & key passphrase (min 6 characters): " STORE_PASS
  printf '\n' >&2
  if [[ ${#STORE_PASS} -lt 6 ]]; then
    echo "Error: Passphrase must be at least 6 characters (Java keytool requirement)." >&2
    continue
  fi

  read -r -s -p "Confirm passphrase: " CONFIRM_PASS
  printf '\n' >&2
  if [[ "$STORE_PASS" != "$CONFIRM_PASS" ]]; then
    echo "Error: Passphrases do not match. Please try again." >&2
    continue
  fi
  break
done

DEFAULT_DNAME="CN=tunssh, OU=Mobile, O=tunssh, L=Unknown, ST=Unknown, C=US"
read -r -p "Distinguished Name [${DEFAULT_DNAME}]: " DNAME
DNAME="${DNAME:-$DEFAULT_DNAME}"

export KEYTOOL_STOREPASS="$STORE_PASS"
keytool -genkeypair -noprompt \
  -keystore "$KEYSTORE_PATH" \
  -storetype PKCS12 \
  -alias "$ALIAS" \
  -keyalg RSA \
  -keysize 2048 \
  -validity 10000 \
  -storepass:env KEYTOOL_STOREPASS \
  -keypass:env KEYTOOL_STOREPASS \
  -dname "$DNAME"

unset STORE_PASS CONFIRM_PASS KEYTOOL_STOREPASS

if ! base64 -w0 "$KEYSTORE_PATH" > "$B64_PATH" 2>/dev/null; then
  base64 < "$KEYSTORE_PATH" | tr -d '\n' > "$B64_PATH"
fi

cat <<EOF

Generated Android release keystore (mode 0600):
  Keystore (.p12): $KEYSTORE_PATH
  Base64   (.b64): $B64_PATH
  Key alias      : $ALIAS

Configure these 4 GitHub Actions repository secrets (Settings -> Secrets and variables -> Actions):
  ANDROID_KEYSTORE_BASE64    Contents of $B64_PATH
  ANDROID_KEYSTORE_PASSWORD  The passphrase you entered
  ANDROID_KEY_ALIAS          $ALIAS
  ANDROID_KEY_PASSWORD       The passphrase you entered

Keep $KEYSTORE_PATH backed up securely and never commit .p12 or .b64 files to git.
EOF
