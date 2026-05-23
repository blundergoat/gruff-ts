#!/usr/bin/env bash
# npm-publish.sh
#
# Purpose:
#   Release gruff-ts to npm with local preflight checks and human confirmation.
#
# Usage:
#   bash scripts/npm-publish.sh
#
# Behavior:
#   1) reads package.json name/version
#   2) verifies npm authentication
#   3) checks version lockstep and runs the release preflight gate
#   4) prints a dry-run publish summary
#   5) asks for manual confirmation before `npm publish`
#
# Exit:
#   0 if published or explicitly aborted, non-zero on failed auth/preflight/publish.
#
# Requirements:
#   - node, npm
#   - npm publish authentication:
#       npm package publishing requires either account 2FA for the publish
#       prompt or a granular access token with Bypass 2FA enabled.
#
#     Preferred token setup for this script:
#       1. In npmjs.com, open Account -> Access Tokens.
#       2. Generate a Granular Access Token.
#       3. Grant read/write access to gruff-ts, or to all packages for the
#          publishing account.
#       4. Enable Bypass 2FA for write actions.
#       5. Either store it in your npm user config:
#            npm config set //registry.npmjs.org/:_authToken=npm_...
#            bash scripts/npm-publish.sh
#
#          Or keep it out of ~/.npmrc and pass it for this shell only:
#            export NPM_TOKEN="npm_..."
#            bash scripts/npm-publish.sh
#
#     NODE_AUTH_TOKEN is also accepted for the temporary-token path. The
#     script writes env tokens to a temporary npm config file and removes it
#     on exit. Do not commit an .npmrc containing a real token.
set -euo pipefail

REGISTRY_URL="https://registry.npmjs.org/"
AUTH_SOURCE=""
TEMP_NPMRC=""
PACKAGE_NAME=""

usage() {
  cat <<'USAGE'
Usage:
  bash scripts/npm-publish.sh
  bash scripts/npm-publish.sh --help

Publishes the current package version to npm after:
  - npm auth/token validation
  - scripts/bump-version.sh --check
  - scripts/preflight-checks.sh
  - npm publish --dry-run

The final publish still requires an interactive y/N confirmation.
USAGE
}

die() {
  printf 'npm-publish: %s\n' "$*" >&2
  exit 1
}

repo_root() {
  local script_dir
  script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
  CDPATH='' cd -- "$script_dir/.." && pwd
}

read_package_name() {
  node -p "require('./package.json').name"
}

read_package_version() {
  node -p "require('./package.json').version"
}

cleanup() {
  if [[ -n "$TEMP_NPMRC" && -f "$TEMP_NPMRC" ]]; then
    rm -f -- "$TEMP_NPMRC"
  fi
}
trap cleanup EXIT

print_token_instructions() {
  local reason="$1"

  printf 'Error: %s\n' "$reason" >&2
  cat >&2 <<EOF

Publish token setup:
  1. Go to npmjs.com -> Account -> Access Tokens.
  2. Generate a Granular Access Token.
  3. Grant read/write access to ${PACKAGE_NAME}, or to all packages for the
     publishing account.
  4. Enable Bypass 2FA for write actions.
  5. Store the token in your npm user config:

       npm config set //registry.npmjs.org/:_authToken=npm_...
       bash scripts/npm-publish.sh

     This is simple, but it persists the token in ~/.npmrc.

     To avoid storing the token, pass it for this shell only:

       export NPM_TOKEN="npm_..."
       bash scripts/npm-publish.sh

     NODE_AUTH_TOKEN works too:

       export NODE_AUTH_TOKEN="npm_..."
       bash scripts/npm-publish.sh

Do not commit an .npmrc containing a real token.
EOF
}

configure_token_from_env() {
  local token_source=""
  local token_value=""

  if [[ -n "${NPM_TOKEN:-}" ]]; then
    token_source="NPM_TOKEN"
    token_value="$NPM_TOKEN"
  elif [[ -n "${NODE_AUTH_TOKEN:-}" ]]; then
    token_source="NODE_AUTH_TOKEN"
    token_value="$NODE_AUTH_TOKEN"
  else
    return 1
  fi

  TEMP_NPMRC=$(mktemp)
  chmod 0600 "$TEMP_NPMRC"
  {
    printf 'registry=%s\n' "$REGISTRY_URL"
    printf '//registry.npmjs.org/:_authToken=%s\n' "$token_value"
  } >"$TEMP_NPMRC"

  export NPM_CONFIG_USERCONFIG="$TEMP_NPMRC"
  AUTH_SOURCE="$token_source"
}

has_configured_registry_token() {
  npm config list 2>/dev/null | grep -Eq '^//registry\.npmjs\.org/:_authToken = \(protected\)$'
}

trim_output() {
  tr -d '\r' | awk '{$1=$1; print}'
}

verify_publish_auth() {
  local npm_user
  local tfa_mode

  echo "--- Auth check ---"
  if configure_token_from_env; then
    echo "Using ${AUTH_SOURCE} via temporary npm config."
  fi

  if ! npm_user=$(npm whoami --registry="$REGISTRY_URL" 2>/dev/null); then
    print_token_instructions "npm is not authenticated for ${REGISTRY_URL}."
    exit 1
  fi

  echo "Logged in as: ${npm_user}"

  if [[ -n "$AUTH_SOURCE" ]]; then
    echo "Publish token source: ${AUTH_SOURCE}"
    echo "Token must be granular, read/write for ${PACKAGE_NAME}, and Bypass 2FA enabled."
    echo ""
    return 0
  fi

  if has_configured_registry_token; then
    AUTH_SOURCE="npm user config"
    echo "Publish token source: ${AUTH_SOURCE}"
    echo "Token must be granular, read/write for ${PACKAGE_NAME}, and Bypass 2FA enabled."
    echo ""
    return 0
  fi

  if ! tfa_mode=$(npm profile get "two-factor auth" --registry="$REGISTRY_URL" 2>/dev/null | trim_output); then
    print_token_instructions "unable to verify npm 2FA state and no publish token was supplied."
    exit 1
  fi

  if [[ -z "$tfa_mode" ]]; then
    print_token_instructions "npm did not report an account 2FA mode and no publish token was supplied."
    exit 1
  fi

  echo "Account 2FA mode: ${tfa_mode}"
  if [[ "$tfa_mode" == "disabled" ]]; then
    print_token_instructions "npm account 2FA is disabled and no publish token was supplied."
    exit 1
  fi

  echo "No explicit publish token supplied; npm must complete the publish with an interactive OTP."
  echo ""
}

main() {
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi

  if [[ "$#" -ne 0 ]]; then
    usage >&2
    die "unknown argument: $1"
  fi

  cd "$(repo_root)"
  [[ -f package.json ]] || die "package.json not found"

  PACKAGE_NAME="$(read_package_name)" || die "failed to read package.json name"
  local version
  version="$(read_package_version)" || die "failed to read package.json version"
  [[ -n "$PACKAGE_NAME" ]] || die "package.json has no name field"
  [[ -n "$version" ]] || die "package.json has no version field"

  local publish_args=("--registry=$REGISTRY_URL")
  if [[ "$PACKAGE_NAME" == @*/* ]]; then
    publish_args+=(--access public)
  fi

  echo "Publishing ${PACKAGE_NAME}@${version}"
  verify_publish_auth

  echo "--- Preflight ---"
  bash scripts/bump-version.sh --check
  bash scripts/preflight-checks.sh
  echo ""

  echo "--- Dry run ---"
  npm publish --dry-run "${publish_args[@]}"
  echo ""

  local confirm
  read -rp "Publish ${PACKAGE_NAME}@${version} to npm? (y/N) " confirm
  if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo "Aborted."
    exit 0
  fi

  npm publish "${publish_args[@]}"
  echo ""
  echo "Published: https://www.npmjs.com/package/${PACKAGE_NAME}/v/${version}"
}

main "$@"
