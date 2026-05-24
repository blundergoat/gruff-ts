#!/usr/bin/env bash
set -euo pipefail

NPM_AUDIT_LEVEL="${NPM_AUDIT_LEVEL:-moderate}"
RUN_AUDIT=1
RUN_CHECK=0

usage() {
  cat <<'USAGE'
Usage:
  scripts/dependency-install.sh [options]

Installs dependencies from package-lock.json using npm ci.

Options:
  --audit-level LEVEL  npm audit threshold (default: moderate)
  --no-audit           Skip npm audit after install
  --check              Run npm run check after install and audit
  --help, -h           Show this help

Environment:
  NPM_AUDIT_LEVEL      Default audit threshold when --audit-level is omitted
USAGE
}

die() {
  printf 'dependency-install: %s\n' "$*" >&2
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
      --check)
        RUN_CHECK=1
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

main() {
  parse_args "$@"
  cd "$(repo_root)"

  require_tool node
  require_tool npm
  [[ -f package.json ]] || die "package.json not found"
  [[ -f package-lock.json ]] || die "package-lock.json not found"

  echo "--- Install dependencies ---"
  npm ci

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
