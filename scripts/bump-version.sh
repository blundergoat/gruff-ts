#!/usr/bin/env bash
set -euo pipefail

# Bump gruff-ts to a new semver in package.json, package-lock.json, and src/constants.ts.
# The CLI surfaces VERSION from src/constants.ts; package metadata drives `npm publish`.
# Keeping all release version surfaces in lockstep is a release invariant.

usage() {
  cat <<'USAGE'
Usage:
  scripts/bump-version.sh <new-version>
  scripts/bump-version.sh --check

Arguments:
  <new-version>   Target semver, e.g. 0.1.1, 0.2.0, 1.0.0-rc.1.

Options:
  --check         Verify package.json, package-lock.json, and src/constants.ts already agree.
  --help, -h      Show this help.

Notes:
  Edits files in place. Does not commit or tag. Run `npm run check` afterwards.
USAGE
}

die() {
  printf 'bump-version: %s\n' "$*" >&2
  exit 1
}

repo_root() {
  local script_dir
  script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
  CDPATH='' cd -- "$script_dir/.." && pwd
}

read_package_version() {
  awk -F'"' '/^[[:space:]]*"version"[[:space:]]*:/ { print $4; exit }' package.json
}

read_constants_version() {
  awk -F'"' '/^const VERSION = "/ { print $2; exit }' src/constants.ts
}

read_package_lock_version() {
  node -e 'const fs = require("node:fs"); const data = JSON.parse(fs.readFileSync("package-lock.json", "utf8")); process.stdout.write(String(data.version ?? ""));'
}

read_package_lock_package_version() {
  node -e 'const fs = require("node:fs"); const data = JSON.parse(fs.readFileSync("package-lock.json", "utf8")); process.stdout.write(String(data.packages?.[""]?.version ?? ""));'
}

write_package_version() {
  local next_version="$1"
  awk -v target="$next_version" '
    BEGIN { done = 0 }
    /^[[:space:]]*"version"[[:space:]]*:/ && !done {
      sub(/"version"[[:space:]]*:[[:space:]]*"[^"]+"/, "\"version\": \"" target "\"")
      done = 1
    }
    { print }
  ' package.json > package.json.tmp
  mv package.json.tmp package.json
}

write_constants_version() {
  local next_version="$1"
  awk -v target="$next_version" '
    BEGIN { done = 0 }
    /^const VERSION = "/ && !done {
      print "const VERSION = \"" target "\";"
      done = 1
      next
    }
    { print }
  ' src/constants.ts > src/constants.ts.tmp
  mv src/constants.ts.tmp src/constants.ts
}

write_package_lock_version() {
  local next_version="$1"
  node - "$next_version" <<'NODE'
const fs = require("node:fs");

const target = process.argv[2];
const lockPath = "package-lock.json";
const lock = JSON.parse(fs.readFileSync(lockPath, "utf8"));

lock.version = target;
if (!lock.packages || typeof lock.packages !== "object" || !lock.packages[""]) {
  throw new Error('package-lock.json missing packages[""] root package entry');
}
lock.packages[""].version = target;

fs.writeFileSync(`${lockPath}.tmp`, `${JSON.stringify(lock, null, 2)}\n`);
NODE
  mv package-lock.json.tmp package-lock.json
}

validate_semver() {
  local value="$1"
  # Standard semver: MAJOR.MINOR.PATCH with optional prerelease/build metadata.
  local pattern='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?(\+([0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?$'
  [[ "$value" =~ $pattern ]] || die "not a valid semver: $value"
}

check_version_lockstep() {
  local pkg const_ lock lock_package
  pkg="$(read_package_version)" || die "failed to read package.json version"
  const_="$(read_constants_version)" || die "failed to read src/constants.ts VERSION"
  lock="$(read_package_lock_version)" || die "failed to read package-lock.json root version"
  lock_package="$(read_package_lock_package_version)" || die "failed to read package-lock.json package version"
  [[ -n "$pkg" ]] || die "package.json has no \"version\" field"
  [[ -n "$const_" ]] || die "src/constants.ts has no VERSION constant"
  [[ -n "$lock" ]] || die "package-lock.json has no root \"version\" field"
  [[ -n "$lock_package" ]] || die 'package-lock.json has no packages[""].version field'
  if ! [[ "$pkg" == "$const_" && "$pkg" == "$lock" && "$pkg" == "$lock_package" ]]; then
    printf 'version surfaces disagree: package.json=%s src/constants.ts=%s package-lock.json=%s package-lock.json packages[""]=%s\n' "$pkg" "$const_" "$lock" "$lock_package" >&2
    exit 1
  fi
  printf 'package.json, package-lock.json, and src/constants.ts agree on %s\n' "$pkg"
}

main() {
  if [[ "$#" -eq 0 ]]; then
    usage >&2
    exit 2
  fi

  cd "$(repo_root)"
  [[ -f package.json ]] || die "package.json not found"
  [[ -f package-lock.json ]] || die "package-lock.json not found"
  [[ -f src/constants.ts ]] || die "src/constants.ts not found"

  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --check)
      check_version_lockstep
      exit 0
      ;;
  esac

  local next="$1"
  validate_semver "$next"

  local current
  current="$(read_package_version)" || die "failed to read package.json version"
  [[ -n "$current" ]] || die "package.json has no \"version\" field"

  local current_const
  current_const="$(read_constants_version)" || die "failed to read src/constants.ts VERSION"
  [[ -n "$current_const" ]] || die "src/constants.ts has no VERSION constant"

  local current_lock current_lock_package
  current_lock="$(read_package_lock_version)" || die "failed to read package-lock.json root version"
  current_lock_package="$(read_package_lock_package_version)" || die "failed to read package-lock.json package version"
  [[ -n "$current_lock" ]] || die "package-lock.json has no root \"version\" field"
  [[ -n "$current_lock_package" ]] || die 'package-lock.json has no packages[""].version field'

  if ! [[ "$current" == "$current_const" && "$current" == "$current_lock" && "$current" == "$current_lock_package" ]]; then
    die "current versions diverge: package.json=$current src/constants.ts=$current_const package-lock.json=$current_lock package-lock.json packages[\"\"]=$current_lock_package (resolve manually first)"
  fi

  if [[ "$current" == "$next" ]]; then
    printf 'already at %s; nothing to do\n' "$next"
    exit 0
  fi

  write_package_version "$next"
  write_constants_version "$next"
  write_package_lock_version "$next"

  local check_pkg check_const check_lock check_lock_package
  check_pkg="$(read_package_version)"
  check_const="$(read_constants_version)"
  check_lock="$(read_package_lock_version)"
  check_lock_package="$(read_package_lock_package_version)"
  [[ "$check_pkg" == "$next" ]] || die "package.json did not update cleanly (read back: ${check_pkg:-empty})"
  [[ "$check_const" == "$next" ]] || die "src/constants.ts did not update cleanly (read back: ${check_const:-empty})"
  [[ "$check_lock" == "$next" ]] || die "package-lock.json did not update cleanly (read back: ${check_lock:-empty})"
  [[ "$check_lock_package" == "$next" ]] || die "package-lock.json packages[\"\"] did not update cleanly (read back: ${check_lock_package:-empty})"

  printf 'bumped %s -> %s\n' "$current" "$next"
  printf '  package.json\n'
  printf '  package-lock.json\n'
  printf '  src/constants.ts\n'
  # shellcheck disable=SC2016
  printf 'next: update CHANGELOG.md and run `npm run check`\n'
}

main "$@"
