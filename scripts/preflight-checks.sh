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
NPM_AUDIT_LEVEL="${NPM_AUDIT_LEVEL:-moderate}"

usage() {
  cat <<'USAGE'
Usage:
  scripts/preflight-checks.sh

Runs the local preflight gate:
  - version surfaces (package.json, package-lock.json, src/constants.ts, CHANGELOG.md) agree
  - npm dependency audit
  - npm run check (TypeScript compile plus unit tests)
  - gruff-ts full-project scan
  - documentation drift (README.md and docs/ agree with list-rules, cite only carried decisions, link only to real pages)
  - documentation drift fixtures (each mutation class is rejected: false-empty, phantom rule, decision-namespace, source-revision, dead link)
  - shellcheck for scripts/*.sh when shellcheck is installed

Environment:
  GRUFF_TS_FAIL_ON   gruff-ts severity that fails static analysis (default: advisory)
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

version_consistency_check() {
  local output
  local status

  output=$(bash scripts/bump-version.sh --check 2>&1)
  status=$?
  if ((status != 0)); then
    printf '%s\n' "$output"
    return "$status"
  fi
  printf '%s' "$output"
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
const findings = summary.findings ?? {};
const composite = score.composite ?? {};
const paths = report.paths ?? {};
const total = Number(findings.total ?? 0);
const advisory = Number(findings.advisory ?? 0);
const warning = Number(findings.warning ?? 0);
const error = Number(findings.error ?? 0);
const grade = String(composite.grade ?? "n/a");
const scoreValue = Number(composite.score ?? 0).toFixed(1);
const analysedFiles = Number(paths.analysedFiles ?? 0);

console.log(`${total} findings (advisory=${advisory}, warning=${warning}, error=${error}), ${grade} ${scoreValue}/100, ${analysedFiles} files`);
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

  # The guardrail hooks decide what an agent is allowed to run, so lint them here too:
  # no other local gate reads them, which is how a policy bypass once reached review.
  while IFS= read -r -d '' script_path; do
    scripts+=("$script_path")
  done < <(find scripts .goat-flow/hooks -maxdepth 2 -type f -name '*.sh' -print0 2>/dev/null | sort -z)

  if [[ "${#scripts[@]}" -eq 0 ]]; then
    printf 'no shell scripts found'
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

# Runs the guardrail corpus that decides which agent commands are blocked or allowed.
# Without it a policy change ships on the strength of tests that never read the policy.
hook_policy_check() {
  local deny_self_test=".goat-flow/hooks/deny-dangerous/deny-dangerous-self-test.sh"
  local post_turn_hook=".goat-flow/hooks/post-turn-safety.sh"
  local summaries=()
  local output
  local status

  if [[ -f "$deny_self_test" ]]; then
    output=$(bash "$deny_self_test" 2>&1)
    status=$?
    if ((status != 0)); then
      printf '%s\n' "$output"
      return "$status"
    fi
    summaries+=("${output##*$'\n'}")
  fi

  # The Stop hook is the last thing standing between a leaked credential and the
  # user's next commit, so prove it still blocks before calling a release ready.
  if [[ -f "$post_turn_hook" ]]; then
    output=$(bash "$post_turn_hook" --self-test 2>&1)
    status=$?
    if ((status != 0)); then
      printf '%s\n' "$output"
      return "$status"
    fi
    summaries+=("${output##*$'\n'}")
  fi

  if [[ "${#summaries[@]}" -eq 0 ]]; then
    printf 'no hook self-tests found'
    return 0
  fi

  local joined="${summaries[0]}"
  local index
  for ((index = 1; index < ${#summaries[@]}; index++)); do
    joined+="; ${summaries[$index]}"
  done
  printf '%s' "$joined"
}

# ---------------------------------------------------------------------------
# Documentation drift (M09 task 14). The owned documentation must agree with the
# live rule catalogue, name only rules that ship, cite only decisions this port
# carries, and link only to pages that exist. Every extraction fails closed: a
# document that states no catalogue size or names no rule is a defect, not a pass.
# ---------------------------------------------------------------------------

# Extract the live catalogue facts once so every drift assertion reads one snapshot.
docs_drift_facts() {
  local catalogue_file="$1"
  node - "$catalogue_file" <<'NODE'
const fs = require("fs");

const listing = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const rules = listing && Array.isArray(listing.rules) ? listing.rules : null;
if (!rules || rules.length === 0) {
  throw new Error("false-empty: list-rules published no rules under rules");
}
const ids = rules.map((rule) => rule.id).sort();
const pillars = [...new Set(rules.map((rule) => rule.pillar))].sort();
console.log("count=" + rules.length);
console.log("pillars=" + pillars.length);
console.log("pillarNames=" + pillars.join("|"));
console.log("ids=" + ids.join(" "));
NODE
}

# Read one fact from the extracted facts block.
docs_fact() {
  local facts="$1"
  local key="$2"
  sed -n "s/^${key}=//p" <<<"$facts"
}

# Capture the live catalogue facts, or the reason the catalogue could not be read.
docs_drift_live_facts() {
  local catalogue
  local facts
  local status

  catalogue=$(make_temp_file json) || return 1
  if ! ./bin/gruff-ts list-rules --format=json >"$catalogue" 2>/dev/null; then
    printf 'docs drift: list-rules --format=json failed'
    return 1
  fi
  facts=$(docs_drift_facts "$catalogue" 2>&1)
  status=$?
  printf '%s' "$facts"
  return "$status"
}

# Compare the owned documentation under one root with the live catalogue facts. Runs against the
# real checkout, and against synthetic copies in the fixture harness, so both share one contract.
docs_drift_check_root() {
  local docs_root="$1"
  local facts="$2"
  local readme="$docs_root/README.md"
  local rules_doc="$docs_root/docs/rules.md"
  local count pillars ids pillar_names
  local claim claims=0 doc token decision link
  local documents=() mentioned=() phantom=() bad_decisions=() dead=()

  count=$(docs_fact "$facts" count)
  pillars=$(docs_fact "$facts" pillars)
  ids=" $(docs_fact "$facts" ids) "
  pillar_names=$(docs_fact "$facts" pillarNames)

  for doc in "$readme" "$rules_doc"; do
    if [[ ! -f "$doc" ]]; then
      printf 'docs drift: false-empty: %s is missing\n' "${doc#"$docs_root"/}"
      return 1
    fi
  done

  # Source-revision claims: every stated catalogue size must equal the live catalogue.
  while IFS= read -r claim; do
    claims=$((claims + 1))
    if [[ "$claim" != "$count rules across $pillars pillars" ]]; then
      printf 'docs drift: source-revision: a document says "%s" but list-rules has %s rules across %s pillars\n' \
        "$claim" "$count" "$pillars"
      return 1
    fi
  done < <(grep -ohE '[0-9]+ rules across [0-9]+ pillars' "$readme" "$rules_doc")
  while IFS= read -r claim; do
    claims=$((claims + 1))
    if [[ "$claim" != "The current catalogue contains $count rules" ]]; then
      printf 'docs drift: source-revision: README.md says "%s" but list-rules has %s rules\n' "$claim" "$count"
      return 1
    fi
  done < <(grep -oE 'The current catalogue contains [0-9]+ rules' "$readme")
  if ((claims == 0)); then
    printf 'docs drift: false-empty: README.md and docs/rules.md state no catalogue size\n'
    return 1
  fi

  # Phantom rule ids: a backticked <pillar>.<slug> in the README or docs must be a rule that
  # ships. UPGRADING.md is history by design, and a line that says retired or removed is too.
  mapfile -t documents < <(find "$docs_root/docs" -maxdepth 1 -name '*.md' 2>/dev/null | sort)
  documents+=("$readme")
  while IFS= read -r token; do
    mentioned+=("$token")
    if [[ "$ids" != *" $token "* ]]; then
      phantom+=("$token")
    fi
  done < <(grep -hvE 'retired|removed' "${documents[@]}" \
    | grep -oE "\`($pillar_names)\.[a-z0-9-]+\`" | tr -d '`' | sort -u)
  if ((${#mentioned[@]} == 0)); then
    printf 'docs drift: false-empty: the documentation names no rule id\n'
    return 1
  fi
  if ((${#phantom[@]} > 0)); then
    printf 'docs drift: phantom rule ids not in list-rules: %s\n' "${phantom[*]}"
    return 1
  fi

  # Decision namespace: every ADR the documentation cites must exist in this port's decisions.
  while IFS= read -r decision; do
    if ! compgen -G "$REPO_ROOT/.goat-flow/learning-loop/decisions/$decision-*.md" >/dev/null; then
      bad_decisions+=("$decision")
    fi
  done < <(cat "${documents[@]}" "$docs_root/UPGRADING.md" 2>/dev/null | grep -oE 'ADR-[0-9]{3}' | sort -u)
  if ((${#bad_decisions[@]} > 0)); then
    printf 'docs drift: decision-namespace: %s cited but absent from .goat-flow/learning-loop/decisions\n' \
      "${bad_decisions[*]}"
    return 1
  fi

  # Entry-page links: every relative link from the README must resolve inside the checkout. A
  # fixture copy carries only the documentation, so a link to any other checked-in file still
  # resolves against the real repository root.
  while IFS= read -r link; do
    if [[ ! -e "$docs_root/$link" && ! -e "$REPO_ROOT/$link" ]]; then
      dead+=("$link")
    fi
  done < <(grep -oE '\]\([^)#[:space:]]+' "$readme" | sed 's/^](//' | grep -vE '^(https?://|mailto:)' | sort -u)
  if ((${#dead[@]} > 0)); then
    printf 'docs drift: entry-page link does not resolve: %s\n' "${dead[*]}"
    return 1
  fi

  printf '%s rules, %s pillars; %s rule ids and every cited decision resolve' \
    "$count" "$pillars" "${#mentioned[@]}"
}

docs_drift_check() {
  local facts
  local status

  facts=$(docs_drift_live_facts)
  status=$?
  if ((status != 0)); then
    printf '%s' "$facts"
    return "$status"
  fi
  docs_drift_check_root "$REPO_ROOT" "$facts"
}

# Run the drift check against one mutated copy and require the named rejection.
expect_docs_drift_rejection() {
  local case_name="$1"
  local expected="$2"
  local docs_root="$3"
  local facts="$4"
  local output

  if output=$(docs_drift_check_root "$docs_root" "$facts" 2>&1); then
    printf 'docs drift fixture %s: the mutation passed the gate\n' "$case_name"
    return 1
  fi
  if [[ "$output" != *"$expected"* ]]; then
    printf 'docs drift fixture %s: rejected for the wrong reason; expected "%s", got: %s\n' \
      "$case_name" "$expected" "$output"
    return 1
  fi
}

# Prove the drift gate rejects each mutation class without touching the real documentation
# (M09 task 16): false-empty, phantom rule, decision-namespace, source-revision, dead link.
docs_drift_fixture_check() {
  local facts status harness valid root count first_pillar
  local backtick='`'

  facts=$(docs_drift_live_facts)
  status=$?
  if ((status != 0)); then
    printf '%s' "$facts"
    return "$status"
  fi
  count=$(docs_fact "$facts" count)
  first_pillar=$(docs_fact "$facts" pillarNames)
  first_pillar=${first_pillar%%|*}

  harness=$(mktemp -d "${TMPDIR:-/tmp}/gruff-ts-docs-fixtures.XXXXXX") || return 1
  valid="$harness/valid"
  mkdir -p "$valid"
  cp "$REPO_ROOT/README.md" "$REPO_ROOT/UPGRADING.md" "$valid/"
  cp -R "$REPO_ROOT/docs" "$valid/docs"
  if ! docs_drift_check_root "$valid" "$facts" >/dev/null 2>&1; then
    printf 'docs drift fixture: the unmodified copy failed the gate'
    rm -rf -- "$harness"
    return 1
  fi

  root="$harness/false-empty"
  cp -R "$valid" "$root"
  printf '# gruff-ts\n\nSee the docs.\n' >"$root/README.md"
  printf '# Rules\n\nSee list-rules.\n' >"$root/docs/rules.md"
  expect_docs_drift_rejection false-empty 'false-empty' "$root" "$facts" || { rm -rf -- "$harness"; return 1; }

  root="$harness/phantom-rule"
  cp -R "$valid" "$root"
  printf '\nThe %s%s.phantom-rule%s rule is documented here.\n' "$backtick" "$first_pillar" "$backtick" >>"$root/README.md"
  expect_docs_drift_rejection phantom-rule 'phantom rule ids' "$root" "$facts" || { rm -rf -- "$harness"; return 1; }

  root="$harness/decision-namespace"
  cp -R "$valid" "$root"
  printf '\nSee ADR-999 for the rationale.\n' >>"$root/README.md"
  expect_docs_drift_rejection decision-namespace 'decision-namespace' "$root" "$facts" || { rm -rf -- "$harness"; return 1; }

  root="$harness/source-revision"
  cp -R "$valid" "$root"
  sed -i "s/$count rules across/$((count + 1)) rules across/" "$root/README.md"
  expect_docs_drift_rejection source-revision 'source-revision' "$root" "$facts" || { rm -rf -- "$harness"; return 1; }

  root="$harness/dead-link"
  cp -R "$valid" "$root"
  printf '\n[Missing page](docs/missing-page.md)\n' >>"$root/README.md"
  expect_docs_drift_rejection dead-link 'entry-page link' "$root" "$facts" || { rm -rf -- "$harness"; return 1; }

  rm -rf -- "$harness"
  printf '5 mutations rejected'
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

  run_step "Version consistency" version_consistency_check

  run_step "Dependency audit" npm_audit_check

  run_step "TypeScript + tests" npm_check

  run_step "Gruff full-project scan" gruff_ts_check

  run_step "Documentation drift" docs_drift_check

  run_step "Documentation drift fixtures" docs_drift_fixture_check

  if command -v shellcheck >/dev/null 2>&1; then
    run_step "Shell scripts (shellcheck)" shellcheck_check
  else
    step "Shell scripts (shellcheck)"
    skip "shellcheck not found"
  fi

  run_step "Safety hook policy" hook_policy_check

  summary
}

main "$@"
