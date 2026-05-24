#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  BOLD=$'\033[1m'
  DIM=$'\033[2m'
  GREEN=$'\033[32m'
  RED=$'\033[31m'
  YELLOW=$'\033[33m'
  BLUE=$'\033[34m'
  RESET=$'\033[0m'
else
  BOLD=''
  DIM=''
  GREEN=''
  RED=''
  YELLOW=''
  BLUE=''
  RESET=''
fi

PASS="${GREEN}OK${RESET}"
FAIL="${RED}FAIL${RESET}"
SKIP="${YELLOW}SKIP${RESET}"
ARROW="${BLUE}->${RESET}"

TOTAL=0
PASSED=0
FAILED=0
FAILURES=()
TMP_FILES=()
START_TIME=$(date +%s%N)
NPM_REGISTRY_URL="${NPM_REGISTRY_URL:-https://registry.npmjs.org/}"
NPM_AUDIT_LEVEL="${NPM_AUDIT_LEVEL:-moderate}"

usage() {
  cat <<'USAGE'
Usage:
  scripts/preflight-checks.sh

Runs the local preflight gate:
  - release version is internally consistent and not already published to npm
  - npm dependency audit
  - npm run check (TypeScript compile plus unit tests)
  - gruff-ts full-project scan
  - shellcheck for scripts/*.sh when shellcheck is installed

Environment:
  GRUFF_TS_FAIL_ON   gruff-ts severity that fails static analysis (default: advisory)
  NPM_REGISTRY_URL   npm registry used for the published-version check
  NPM_AUDIT_LEVEL    npm audit threshold (default: moderate)
USAGE
}

cleanup() {
  local temp_file

  for temp_file in "${TMP_FILES[@]}"; do
    [[ -f "$temp_file" ]] && rm -f -- "$temp_file"
  done
}

trap cleanup EXIT

rule() {
  printf '  %s\n' "${DIM}--------------------------------------------${RESET}"
}

elapsed_since() {
  local started_at="$1"
  local finished_at
  local elapsed_ms
  local seconds
  local minutes
  local remainder
  local frac

  finished_at=$(date +%s%N)
  elapsed_ms=$(((finished_at - started_at) / 1000000))

  if ((elapsed_ms < 1000)); then
    printf '%dms' "$elapsed_ms"
    return
  fi

  seconds=$((elapsed_ms / 1000))
  frac=$(((elapsed_ms % 1000) / 100))

  if ((seconds < 60)); then
    printf '%d.%ds' "$seconds" "$frac"
    return
  fi

  minutes=$((seconds / 60))
  remainder=$((seconds % 60))
  printf '%dm %02d.%ds' "$minutes" "$remainder" "$frac"
}

header() {
  printf '\n'
  printf '  %sPreflight Check%s\n' "$BOLD" "$RESET"
  printf '  %s%s%s\n' "$DIM" "$(date '+%Y-%m-%d %H:%M:%S')" "$RESET"
  rule
  printf '\n'
}

step() {
  local label="$1"

  TOTAL=$((TOTAL + 1))
  printf '  %s %-36s' "$ARROW" "$label"
}

pass() {
  local detail="${1:-}"

  PASSED=$((PASSED + 1))
  if [[ -n "$detail" ]]; then
    printf '%s  %s%s%s\n' "$PASS" "$DIM" "$detail" "$RESET"
  else
    printf '%s\n' "$PASS"
  fi
}

fail() {
  local label="$1"

  FAILED=$((FAILED + 1))
  FAILURES+=("$label")
  printf '%s\n' "$FAIL"
}

skip() {
  local reason="${1:-skipped}"

  printf '%s  %s%s%s\n' "$SKIP" "$DIM" "$reason" "$RESET"
}

indent_output() {
  while IFS= read -r line; do
    printf '    %s%s%s\n' "$DIM" "$line" "$RESET"
  done
}

run_step() {
  local label="$1"
  shift

  local started_at
  local output
  local status
  local elapsed

  step "$label"
  started_at=$(date +%s%N)
  output=$("$@" 2>&1)
  status=$?
  elapsed=$(elapsed_since "$started_at")

  if ((status == 0)); then
    pass "${output:+$output }$elapsed"
  else
    fail "$label"
    if [[ -n "$output" ]]; then
      printf '%s\n' "$output" | tail -20 | indent_output
    fi
    printf '    %sexit %d after %s%s\n' "$DIM" "$status" "$elapsed" "$RESET"
  fi

  return "$status"
}

make_temp_file() {
  local suffix="$1"
  local temp_file

  temp_file=$(mktemp "${TMPDIR:-/tmp}/gruff-ts-preflight.XXXXXX.$suffix") || return 1
  TMP_FILES+=("$temp_file")
  printf '%s\n' "$temp_file"
}

read_package_name() {
  node -p "require('./package.json').name"
}

read_package_version() {
  node -p "require('./package.json').version"
}

npm_version_check() {
  local package_name
  local version
  local output
  local status

  package_name="$(read_package_name)" || return 1
  version="$(read_package_version)" || return 1
  [[ -n "$package_name" ]] || {
    printf 'package.json has no name field\n'
    return 1
  }
  [[ -n "$version" ]] || {
    printf 'package.json has no version field\n'
    return 1
  }

  output=$(bash scripts/bump-version.sh --check 2>&1)
  status=$?
  if ((status != 0)); then
    printf '%s\n' "$output"
    return "$status"
  fi

  output=$(npm view "${package_name}@${version}" version --registry="$NPM_REGISTRY_URL" 2>&1)
  status=$?
  if ((status == 0)); then
    printf '%s@%s is already published on %s; run scripts/bump-version.sh <next-version>\n' "$package_name" "$version" "$NPM_REGISTRY_URL"
    return 1
  fi

  if printf '%s\n' "$output" | grep -Eq '(^|[[:space:]])(E404|404)([[:space:]]|$)'; then
    printf 'lockstep ok; %s@%s is not published on %s' "$package_name" "$version" "$NPM_REGISTRY_URL"
    return 0
  fi

  printf '%s\n' "$output"
  return "$status"
}

npm_audit_check() {
  local output
  local status
  local summary

  output=$(npm audit --audit-level="$NPM_AUDIT_LEVEL" 2>&1)
  status=$?
  if ((status != 0)); then
    printf '%s\n' "$output"
    return "$status"
  fi

  summary=$(printf '%s\n' "$output" | awk '/found .* vulnerabilities|audited .* packages/ { line = $0 } END { print line }')
  printf '%s' "${summary:-completed}"
  return 0
}

npm_check() {
  local output
  local status
  local tests
  local passed
  local failed

  output=$(npm run check 2>&1)
  status=$?

  if ((status != 0)); then
    printf '%s\n' "$output"
    return "$status"
  fi

  tests=$(printf '%s\n' "$output" | awk '/^# tests / { print $3; exit }')
  passed=$(printf '%s\n' "$output" | awk '/^# pass / { print $3; exit }')
  failed=$(printf '%s\n' "$output" | awk '/^# fail / { print $3; exit }')

  if [[ -n "$tests" && -n "$passed" ]]; then
    printf '%s/%s tests passed' "$passed" "$tests"
    if [[ -n "$failed" && "$failed" != "0" ]]; then
      printf ', %s failed' "$failed"
    fi
  else
    printf 'completed'
  fi

  return 0
}

gruff_report_summary() {
  local report_path="$1"

  # shellcheck disable=SC2016
  node --input-type=module -e '
import { readFileSync } from "node:fs";

const report = JSON.parse(readFileSync(process.argv[1], "utf8"));
const summary = report.summary ?? {};
const score = report.score ?? {};
const paths = report.paths ?? {};
const total = Number(summary.total ?? 0);
const advisory = Number(summary.advisory ?? 0);
const warning = Number(summary.warning ?? 0);
const error = Number(summary.error ?? 0);
const grade = String(score.grade ?? "n/a");
const composite = Number(score.composite ?? 0).toFixed(1);
const analysedFiles = Number(paths.analysedFiles ?? 0);

console.log(`${total} findings (advisory=${advisory}, warning=${warning}, error=${error}), ${grade} ${composite}/100, ${analysedFiles} files`);
' "$report_path"
}

gruff_ts_check() {
  local gruff_fail_on="${GRUFF_TS_FAIL_ON:-advisory}"
  local report_path
  local error_path
  local status
  local summary_status=0
  local printed=0

  report_path=$(make_temp_file json) || return 1
  error_path=$(make_temp_file err) || return 1

  ./bin/gruff-ts analyse . --format=json --fail-on="$gruff_fail_on" --no-baseline >"$report_path" 2>"$error_path"
  status=$?

  if [[ -s "$report_path" ]]; then
    gruff_report_summary "$report_path"
    summary_status=$?
    printed=1
  fi

  if [[ -s "$error_path" ]]; then
    if ((printed)); then
      printf '\n'
    fi
    cat "$error_path"
  fi

  if ((status != 0)); then
    return "$status"
  fi
  return "$summary_status"
}

shellcheck_check() {
  local scripts=()
  local script_path
  local output
  local status

  while IFS= read -r -d '' script_path; do
    scripts+=("$script_path")
  done < <(find scripts -maxdepth 1 -type f -name '*.sh' -print0 | sort -z)

  if [[ "${#scripts[@]}" -eq 0 ]]; then
    printf 'no scripts/*.sh files found'
    return 0
  fi

  output=$(shellcheck "${scripts[@]}" 2>&1)
  status=$?

  if ((status == 0)); then
    printf '%d scripts checked' "${#scripts[@]}"
  else
    printf '%s\n' "$output"
  fi

  return "$status"
}

summary() {
  local elapsed

  elapsed=$(elapsed_since "$START_TIME")
  printf '\n'
  rule
  printf '\n'

  if ((FAILED == 0)); then
    printf '  %sAll %d/%d checks passed%s  %s(%s)%s\n' "$GREEN$BOLD" "$PASSED" "$TOTAL" "$RESET" "$DIM" "$elapsed" "$RESET"
    printf '\n'
    return 0
  fi

  printf '  %s%d/%d checks failed%s  %s(%s)%s\n' "$RED$BOLD" "$FAILED" "$TOTAL" "$RESET" "$DIM" "$elapsed" "$RESET"
  printf '\n'

  local failure
  for failure in "${FAILURES[@]}"; do
    printf '    %s  %s\n' "$FAIL" "$failure"
  done
  printf '\n'

  return 1
}

main() {
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    return 0
  fi

  if [[ "$#" -ne 0 ]]; then
    printf '%sUnknown argument:%s %s\n' "$RED" "$RESET" "$1" >&2
    usage >&2
    return 64
  fi

  cd "$REPO_ROOT" || return 1

  header

  if [[ ! -x ./bin/gruff-ts ]]; then
    step "gruff-ts binary"
    fail "gruff-ts binary"
    printf '    %s./bin/gruff-ts is missing or not executable%s\n' "$DIM" "$RESET"
    summary
    return 127
  fi

  run_step "Release version" npm_version_check

  run_step "Dependency audit" npm_audit_check

  run_step "TypeScript + tests" npm_check

  run_step "Gruff full-project scan" gruff_ts_check

  if command -v shellcheck >/dev/null 2>&1; then
    run_step "Shell scripts (shellcheck)" shellcheck_check
  else
    step "Shell scripts (shellcheck)"
    skip "shellcheck not found"
  fi

  summary
}

main "$@"
