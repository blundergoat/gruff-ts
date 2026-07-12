#!/usr/bin/env bash
# Packs the current checkout and verifies the exact tarball a package user would install.
# The gate runs the installed gruff-ts binary in a fresh project against a generated fixture.
# Maintainers use it before publishing to catch missing runtime files, leaked tests, or broken exits.
set -euo pipefail

SCRIPT_DIRECTORY="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPOSITORY_ROOT="$(CDPATH='' cd -- "$SCRIPT_DIRECTORY/.." && pwd)"
TEMPORARY_SMOKE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/gruff-ts-pack-smoke.XXXXXX")"
PACKAGE_OUTPUT_DIRECTORY="$TEMPORARY_SMOKE_ROOT/package-output"
CONSUMER_PROJECT_DIRECTORY="$TEMPORARY_SMOKE_ROOT/consumer"
PACKAGE_CONTENTS_FILE="$TEMPORARY_SMOKE_ROOT/package-contents.txt"
SUCCESS_REPORT_FILE="$TEMPORARY_SMOKE_ROOT/success-report.json"
FAILURE_REPORT_FILE="$TEMPORARY_SMOKE_ROOT/failure-report.json"

# Removes every temporary package and consumer file when the gate succeeds or stops early.
# Users never see residue from this maintainer-only release check in their project.
remove_temporary_smoke_workspace() {
  rm -rf -- "$TEMPORARY_SMOKE_ROOT"
}

# Stops the release gate with a concrete package-consumer failure.
# A missing detail means the gate itself is malformed, so Bash rejects an empty argument.
stop_pack_smoke() {
  # An empty detail would hide which installed-user expectation failed.
  local failure_detail="${1:?pack smoke failure detail is required}"
  printf 'Pack smoke failed: %s\n' "$failure_detail" >&2
  exit 1
}

# Requires one exact path in the packed tarball, such as the CLI launcher or runtime entry point.
# An empty path means the assertion is invalid and stops before a release artifact is accepted.
require_package_entry() {
  # A missing path would turn this check into a meaningless archive search.
  local package_entry="${1:?package entry is required}"

  # If a runtime path is absent, a user could install successfully but fail when launching the CLI.
  if ! grep -Fxq "package/$package_entry" "$PACKAGE_CONTENTS_FILE"; then
    stop_pack_smoke "tarball is missing $package_entry"
  fi
}

# Rejects one path pattern that belongs only to repository development or test fixtures.
# Empty pattern or label values stop the gate instead of silently weakening the package guard.
reject_package_pattern() {
  # A missing pattern would no longer protect the published file set.
  local excluded_pattern="${1:?excluded package pattern is required}"
  # A missing label would make the release failure unclear to its maintainer.
  local excluded_label="${2:?excluded package label is required}"

  # If repository-only files appear, the package manifest has drifted beyond its reviewed surface.
  if grep -Eq "$excluded_pattern" "$PACKAGE_CONTENTS_FILE"; then
    stop_pack_smoke "tarball includes $excluded_label"
  fi
}

# Requires a stable JSON fragment in output produced by the installed binary.
# Empty text or label values stop the gate because they cannot prove a user's report contract.
require_report_text() {
  # Empty report text would make every output look acceptable.
  local expected_report_text="${1:?expected report text is required}"
  # Empty labels would leave the maintainer without a useful failure reason.
  local report_expectation_label="${2:?report expectation label is required}"

  # If installed output omits this fragment, the packaged CLI did not complete the expected scan.
  if ! grep -Fq "$expected_report_text" "$SUCCESS_REPORT_FILE"; then
    stop_pack_smoke "installed report is missing $report_expectation_label"
  fi
}

trap remove_temporary_smoke_workspace EXIT

mkdir -p "$PACKAGE_OUTPUT_DIRECTORY" "$CONSUMER_PROJECT_DIRECTORY/src"

(
  cd "$REPOSITORY_ROOT"
  npm pack --pack-destination "$PACKAGE_OUTPUT_DIRECTORY" --ignore-scripts --loglevel=error >/dev/null
)

shopt -s nullglob
PACKAGE_TARBALLS=("$PACKAGE_OUTPUT_DIRECTORY"/*.tgz)
shopt -u nullglob

# A release invocation must create exactly one installable artifact for the fresh consumer project.
if ((${#PACKAGE_TARBALLS[@]} != 1)); then
  stop_pack_smoke "expected one tarball, found ${#PACKAGE_TARBALLS[@]}"
fi

PACKAGE_TARBALL_PATH="${PACKAGE_TARBALLS[0]}"
tar -tzf "$PACKAGE_TARBALL_PATH" > "$PACKAGE_CONTENTS_FILE"

require_package_entry "package.json"
require_package_entry "bin/gruff-ts"
require_package_entry "src/cli.ts"
reject_package_pattern '^package/src/.*\.test\.ts$' "TypeScript test files"
reject_package_pattern '^package/src/fixtures(/|$)' "source fixture directories"
reject_package_pattern '^package/scripts(/|$)' "maintainer scripts"
reject_package_pattern '^package/(\.agents|\.goat-flow|\.github)(/|$)' "agent or repository workflow files"

(
  cd "$CONSUMER_PROJECT_DIRECTORY"
  npm init --yes --loglevel=error >/dev/null
  npm install "$PACKAGE_TARBALL_PATH" --ignore-scripts --no-audit --no-fund --loglevel=error >/dev/null
)

PACKAGED_BINARY="$CONSUMER_PROJECT_DIRECTORY/node_modules/.bin/gruff-ts"
GENERATED_FIXTURE_PATH="$CONSUMER_PROJECT_DIRECTORY/src/release-smoke.ts"
SECURITY_SINK_NAME='ev''al'

# If npm did not expose the declared binary, a user cannot invoke the package after installation.
if [[ ! -x "$PACKAGED_BINARY" ]]; then
  stop_pack_smoke "installed package did not expose an executable gruff-ts binary"
fi

printf '%s\n' \
  '// File overview: installed package release fixture.' \
  '/** Executes a source expression to exercise one packaged security rule. */' \
  'export function executeSmokeExpression(source: string): unknown {' \
  "  return ${SECURITY_SINK_NAME}(source);" \
  '}' > "$GENERATED_FIXTURE_PATH"

(
  cd "$CONSUMER_PROJECT_DIRECTORY"
  "$PACKAGED_BINARY" analyse "$GENERATED_FIXTURE_PATH" --format=json --fail-on=none --no-config --no-baseline > "$SUCCESS_REPORT_FILE"
)

require_report_text '"schemaVersion": "gruff.analysis.v2"' "analysis schema"
require_report_text '"analysedFiles": 1' "single-file scan count"
require_report_text '"ruleId": "security.eval-call"' "known security finding"

# An error-severity finding must return one so CI users can distinguish findings from usage failures.
if (
  cd "$CONSUMER_PROJECT_DIRECTORY"
  "$PACKAGED_BINARY" analyse "$GENERATED_FIXTURE_PATH" --format=json --fail-on=error --no-config --no-baseline > "$FAILURE_REPORT_FILE"
); then
  stop_pack_smoke "installed binary returned zero despite an error-severity finding"
else
  FINDING_EXIT_STATUS=$?
fi

# Exit two means an operational failure, while any value above two breaks the documented CLI contract.
if ((FINDING_EXIT_STATUS != 1)); then
  stop_pack_smoke "installed binary returned $FINDING_EXIT_STATUS instead of one for a gated finding"
fi

printf 'Pack smoke passed: tarball contents, installed scan output, and finding exit semantics verified.\n'
