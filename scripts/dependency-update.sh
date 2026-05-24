#!/usr/bin/env bash
set -euo pipefail

NPM_AUDIT_LEVEL="${NPM_AUDIT_LEVEL:-moderate}"
DRY_RUN=0
LATEST=0
RUN_AUDIT=1
RUN_CHECK=1

usage() {
  cat <<'USAGE'
Usage:
  scripts/dependency-update.sh [options]

Updates npm dependencies, then verifies the result.

Default behavior:
  - npm update
  - npm audit --audit-level=moderate
  - npm run check

Options:
  --dry-run            Show npm outdated output without changing files
  --latest            Update direct dependencies/devDependencies to @latest
  --audit-level LEVEL  npm audit threshold (default: moderate)
  --no-audit           Skip npm audit after update
  --no-check           Skip npm run check after update
  --help, -h           Show this help

Environment:
  NPM_AUDIT_LEVEL      Default audit threshold when --audit-level is omitted
USAGE
}

die() {
  printf 'dependency-update: %s\n' "$*" >&2
  exit 1
}

repo_root() {
  local script_dir
  script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
  CDPATH='' cd -- "$script_dir/.." && pwd
}

parse_args() {
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --dry-run)
        DRY_RUN=1
        ;;
      --latest)
        LATEST=1
        ;;
      --audit-level)
        [[ "$#" -ge 2 ]] || die "--audit-level requires a value"
        NPM_AUDIT_LEVEL="$2"
        shift
        ;;
      --audit-level=*)
        NPM_AUDIT_LEVEL="${1#*=}"
        ;;
      --no-audit)
        RUN_AUDIT=0
        ;;
      --no-check)
        RUN_CHECK=0
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      *)
        usage >&2
        die "unknown option: $1"
        ;;
    esac
    shift
  done
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required"
}

print_outdated() {
  local output
  local status

  if output=$(npm outdated --long 2>&1); then
    printf '%s\n' "$output"
    echo "All dependencies are current within the configured ranges."
    return 0
  else
    status=$?
  fi

  # npm outdated exits non-zero when it finds outdated dependencies.
  if [[ -n "$output" ]]; then
    printf '%s\n' "$output"
  fi
  if ((status == 1)); then
    return 0
  fi

  return "$status"
}

read_direct_dependencies() {
  local field="$1"
  node -e "const pkg = require('./package.json'); console.log(Object.keys(pkg['$field'] || {}).join('\n'));"
}

install_latest_dependencies() {
  local -a dependencies=()
  local -a dev_dependencies=()
  local dependency

  mapfile -t dependencies < <(read_direct_dependencies dependencies)
  mapfile -t dev_dependencies < <(read_direct_dependencies devDependencies)

  if [[ "${#dependencies[@]}" -gt 0 ]]; then
    for dependency in "${dependencies[@]}"; do
      dependency="${dependency}@latest"
      echo "Updating production dependency: $dependency"
      npm install --save-prod "$dependency"
    done
  fi

  if [[ "${#dev_dependencies[@]}" -gt 0 ]]; then
    for dependency in "${dev_dependencies[@]}"; do
      dependency="${dependency}@latest"
      echo "Updating development dependency: $dependency"
      npm install --save-dev "$dependency"
    done
  fi
}

main() {
  parse_args "$@"
  cd "$(repo_root)"

  require_tool node
  require_tool npm
  [[ -f package.json ]] || die "package.json not found"
  [[ -f package-lock.json ]] || die "package-lock.json not found"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "--- Outdated dependencies ---"
    print_outdated
    exit 0
  fi

  echo "--- Update dependencies ---"
  if [[ "$LATEST" -eq 1 ]]; then
    install_latest_dependencies
  else
    npm update
  fi

  if [[ "$RUN_AUDIT" -eq 1 ]]; then
    echo ""
    echo "--- Dependency audit ---"
    npm audit --audit-level="$NPM_AUDIT_LEVEL"
  fi

  if [[ "$RUN_CHECK" -eq 1 ]]; then
    echo ""
    echo "--- TypeScript + tests ---"
    npm run check
  fi
}

main "$@"
