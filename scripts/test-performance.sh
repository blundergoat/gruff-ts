#!/usr/bin/env bash
set -euo pipefail

# gruff-perf.v1 is this script's baseline schema; bump only with a migration path.
SCHEMA_VERSION="gruff-perf.v1"

RUNS=5
TARGET="src"
OUT_PATH="/tmp/gruff-perf-$$.json"
QUIET=0
MATRIX=0
WRITE_BASELINE=0
WRITE_BASELINE_PATH=""
BASELINE_PATH=""
FAIL_ON_REGRESSION=0
REGRESSION_TOLERANCE="25"
REPORT_PATH=""
FORCE=0
CLEANUP=1
TIME_CMD=""
TMP_DIR=""
CURRENT_FIXTURE_DIR=""

DEFAULT_BASELINE_PATH="$(printf '%s/%s/%s\n' ".goat-flow" "scratchpad/perf" "baseline.json")"

usage() {
  cat <<'USAGE'
Use scripts/test-performance.sh --help to see options.

Usage:
  scripts/test-performance.sh [options]

Run modes:
  --runs N                    Repeat count per measured cell (default: 5)
  --target PATH               Single-workload target (default: src)
  --matrix                    Run tiny/self/synthetic workloads across config and format matrix

Baseline:
  --write-baseline [PATH]     Write the current matrix JSON as a baseline
  --baseline PATH             Compare/report against an existing perf baseline
  --fail-on-regression [PCT]  Exit 1 when wall time or RSS regresses above PCT (default: 25)
  --force                     Allow --write-baseline to overwrite an existing file

Output:
  --out PATH                  Write machine JSON to PATH (default: /tmp/gruff-perf-<pid>.json)
  --report PATH               Write the Markdown matrix report to PATH
  --quiet                     Print only the JSON path
  --cleanup                   Remove previous and current synthetic fixtures (default)
  --no-cleanup                Preserve synthetic fixtures for inspection
  --help                      Show this help
USAGE
}

die() {
  local code="$1"
  shift
  printf '%s\n' "$*" >&2
  exit "$code"
}

is_positive_integer() {
  [[ "$1" =~ ^[1-9][0-9]*$ ]]
}

is_nonnegative_number() {
  awk -v value="$1" 'BEGIN { exit(value ~ /^[0-9]+([.][0-9]+)?$/ ? 0 : 1) }'
}

repo_root() {
  local script_dir
  script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
  CDPATH='' cd -- "$script_dir/.." && pwd
}

safe_remove_dir() {
  local path="$1"
  case "$path" in
    /tmp/gruff-perf-work-*|/tmp/gruff-perf-fixture-*)
      rm -rf -- "$path"
      ;;
    *)
      die 2 "refusing to remove unexpected path: $path"
      ;;
  esac
}

cleanup() {
  if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
    safe_remove_dir "$TMP_DIR"
  fi
  if [[ "$CLEANUP" -eq 1 && -n "$CURRENT_FIXTURE_DIR" && -d "$CURRENT_FIXTURE_DIR" ]]; then
    safe_remove_dir "$CURRENT_FIXTURE_DIR"
  fi
}

cleanup_old_fixtures() {
  local fixture
  shopt -s nullglob
  for fixture in /tmp/gruff-perf-fixture-*; do
    if [[ -d "$fixture" ]]; then
      safe_remove_dir "$fixture"
    fi
  done
  shopt -u nullglob
}

parse_args() {
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --runs)
        [[ "$#" -ge 2 ]] || die 2 "--runs requires a value"
        RUNS="$2"
        shift
        ;;
      --runs=*)
        RUNS="${1#*=}"
        ;;
      --target)
        [[ "$#" -ge 2 ]] || die 2 "--target requires a value"
        TARGET="$2"
        shift
        ;;
      --target=*)
        TARGET="${1#*=}"
        ;;
      --out)
        [[ "$#" -ge 2 ]] || die 2 "--out requires a value"
        OUT_PATH="$2"
        shift
        ;;
      --out=*)
        OUT_PATH="${1#*=}"
        ;;
      --matrix)
        MATRIX=1
        ;;
      --write-baseline)
        WRITE_BASELINE=1
        if [[ "$#" -ge 2 && "$2" != --* ]]; then
          WRITE_BASELINE_PATH="$2"
          shift
        else
          WRITE_BASELINE_PATH="$DEFAULT_BASELINE_PATH"
        fi
        ;;
      --write-baseline=*)
        WRITE_BASELINE=1
        WRITE_BASELINE_PATH="${1#*=}"
        ;;
      --baseline)
        [[ "$#" -ge 2 ]] || die 2 "--baseline requires a value"
        BASELINE_PATH="$2"
        shift
        ;;
      --baseline=*)
        BASELINE_PATH="${1#*=}"
        ;;
      --fail-on-regression)
        FAIL_ON_REGRESSION=1
        if [[ "$#" -ge 2 && "$2" != --* ]]; then
          REGRESSION_TOLERANCE="$2"
          shift
        else
          REGRESSION_TOLERANCE="25"
        fi
        ;;
      --fail-on-regression=*)
        FAIL_ON_REGRESSION=1
        REGRESSION_TOLERANCE="${1#*=}"
        ;;
      --report)
        [[ "$#" -ge 2 ]] || die 2 "--report requires a value"
        REPORT_PATH="$2"
        shift
        ;;
      --report=*)
        REPORT_PATH="${1#*=}"
        ;;
      --quiet)
        QUIET=1
        ;;
      --force)
        FORCE=1
        ;;
      --cleanup)
        CLEANUP=1
        ;;
      --no-cleanup)
        CLEANUP=0
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      *)
        die 2 "unknown option: $1"
        ;;
    esac
    shift
  done
}

validate_args() {
  is_positive_integer "$RUNS" || die 2 "--runs must be a positive integer"
  if [[ "$FAIL_ON_REGRESSION" -eq 1 ]]; then
    is_nonnegative_number "$REGRESSION_TOLERANCE" || die 2 "--fail-on-regression must be a non-negative number"
  fi
  if [[ "$WRITE_BASELINE" -eq 1 && "$MATRIX" -ne 1 ]]; then
    die 2 "--write-baseline requires --matrix"
  fi
  if [[ -n "$BASELINE_PATH" && "$MATRIX" -ne 1 ]]; then
    die 2 "--baseline requires --matrix"
  fi
  if [[ "$FAIL_ON_REGRESSION" -eq 1 && -z "$BASELINE_PATH" ]]; then
    die 2 "--fail-on-regression requires --baseline"
  fi
}

require_tools() {
  command -v jq >/dev/null 2>&1 || die 2 "jq is required"
  command -v awk >/dev/null 2>&1 || die 2 "awk is required"
  command -v node >/dev/null 2>&1 || die 2 "node is required"
  [[ -f "./bin/gruff-ts" ]] || die 2 "missing ./bin/gruff-ts"
}

detect_time_cmd() {
  local probe_file="$TMP_DIR/time-probe.txt"
  if [[ -x /usr/bin/time ]] && /usr/bin/time -v bash -c 'exit 0' >/dev/null 2>"$probe_file"; then
    TIME_CMD="/usr/bin/time"
    return
  fi
  if command -v gtime >/dev/null 2>&1 && gtime -v bash -c 'exit 0' >/dev/null 2>"$probe_file"; then
    TIME_CMD="gtime"
    return
  fi
  die 2 "GNU time is required; install gnu-time so /usr/bin/time -v or gtime -v is available"
}

elapsed_to_seconds() {
  awk -v elapsed="$1" '
    BEGIN {
      count = split(elapsed, parts, ":")
      if (count == 2) {
        printf "%.6f\n", (parts[1] * 60) + parts[2]
      } else if (count == 3) {
        printf "%.6f\n", (parts[1] * 3600) + (parts[2] * 60) + parts[3]
      } else {
        exit 1
      }
    }
  '
}

assert_elapsed_parser() {
  local one
  local two
  one="$(elapsed_to_seconds "0:01.50")" || die 2 "elapsed parser rejected m:ss sample"
  two="$(elapsed_to_seconds "1:02:03.25")" || die 2 "elapsed parser rejected h:mm:ss sample"
  [[ "$one" == "1.500000" ]] || die 2 "elapsed parser returned $one for 0:01.50"
  [[ "$two" == "3723.250000" ]] || die 2 "elapsed parser returned $two for 1:02:03.25"
}

parse_elapsed_file() {
  local file="$1"
  local elapsed
  elapsed="$(awk -F': ' '/Elapsed \(wall clock\) time/ { print $NF; found = 1; exit } END { if (!found) exit 1 }' "$file")" \
    || die 2 "could not parse elapsed wall-clock time from $file"
  elapsed_to_seconds "$elapsed" || die 2 "could not convert elapsed wall-clock time: $elapsed"
}

parse_rss_file() {
  local file="$1"
  awk -F': ' '/Maximum resident set size/ { print $NF; found = 1; exit } END { if (!found) exit 1 }' "$file" \
    || die 2 "could not parse max RSS from $file"
}

parse_text_findings() {
  local file="$1"
  awk '
    /Findings:/ {
      line = $0
      sub(/^.*Findings: /, "", line)
      total = 0
      while (match(line, /[0-9]+/)) {
        total += substr(line, RSTART, RLENGTH)
        line = substr(line, RSTART + RLENGTH)
      }
      print total
      found = 1
      exit
    }
    END { if (!found) exit 1 }
  ' "$file" || die 2 "could not parse finding count from text output"
}

parse_findings() {
  local format="$1"
  local file="$2"
  case "$format" in
    json)
      jq -e '.findings | length' "$file" || die 2 "could not parse finding count from JSON output"
      ;;
    text)
      parse_text_findings "$file"
      ;;
    *)
      die 2 "unsupported format: $format"
      ;;
  esac
}

aggregate_samples() {
  local file="$1"
  awk '
    {
      value = $1 + 0
      values[NR] = value
      sum += value
      if (NR == 1 || value < min) {
        min = value
      }
      if (NR == 1 || value > max) {
        max = value
      }
    }
    END {
      if (NR == 0) {
        exit 1
      }
      mean = sum / NR
      for (i = 1; i <= NR; i++) {
        diff = values[i] - mean
        variance += diff * diff
        samples = samples (i == 1 ? "" : ",") sprintf("%.6f", values[i])
      }
      stddev = sqrt(variance / NR)
      printf "{\"mean\":%.6f,\"min\":%.6f,\"max\":%.6f,\"stddev\":%.6f,\"samples\":[%s]}\n", mean, min, max, stddev, samples
    }
  ' "$file" || die 2 "could not aggregate samples from $file"
}

deterministic_finding_count() {
  local file="$1"
  awk '
    NR == 1 { first = $1 }
    $1 != first { deterministic = 0 }
    NR == 1 { deterministic = 1 }
    END {
      if (NR == 0 || !deterministic) {
        exit 1
      }
      print first
    }
  ' "$file" || die 2 "finding count changed across runs"
}

run_cell() {
  local workload="$1"
  local target_path="$2"
  local config_label="$3"
  local config_flag="$4"
  local format="$5"
  local cell_name="${workload//[^[:alnum:]._-]/_}-${config_label//[^[:alnum:]._-]/_}-${format//[^[:alnum:]._-]/_}"
  local cell_tmp="$TMP_DIR/cell-${cell_name}"
  local wall_file="$cell_tmp-wall.txt"
  local rss_file="$cell_tmp-rss.txt"
  local findings_file="$cell_tmp-findings.txt"
  local run
  local run_output
  local run_time
  local elapsed_seconds
  local rss_kb
  local finding_count
  local wall_json
  local rss_json
  local deterministic_count
  local args

  [[ -e "$target_path" ]] || die 2 "target does not exist: $target_path"

  : > "$wall_file"
  : > "$rss_file"
  : > "$findings_file"

  # Warmup policy: include every run; the src spike stayed below 25% variance without dropping sample 1.
  for ((run = 1; run <= RUNS; run++)); do
    run_output="$cell_tmp-run-$run.out"
    run_time="$cell_tmp-run-$run.time"
    args=(analyse "$target_path" "--format=$format" --no-baseline --fail-on=none)
    if [[ -n "$config_flag" ]]; then
      args+=("$config_flag")
    fi

    if ! "$TIME_CMD" -v ./bin/gruff-ts "${args[@]}" >"$run_output" 2>"$run_time"; then
      die 2 "analyse failed for workload=$workload config=$config_label format=$format"
    fi

    elapsed_seconds="$(parse_elapsed_file "$run_time")"
    rss_kb="$(parse_rss_file "$run_time")"
    finding_count="$(parse_findings "$format" "$run_output")"
    printf '%s\n' "$elapsed_seconds" >> "$wall_file"
    printf '%s\n' "$rss_kb" >> "$rss_file"
    printf '%s\n' "$finding_count" >> "$findings_file"
  done

  wall_json="$(aggregate_samples "$wall_file")"
  rss_json="$(aggregate_samples "$rss_file")"
  deterministic_count="$(deterministic_finding_count "$findings_file")"

  jq -n \
    --arg workload "$workload" \
    --arg target "$target_path" \
    --arg config "$config_label" \
    --arg format "$format" \
    --argjson runs "$RUNS" \
    --argjson wall "$wall_json" \
    --argjson rss "$rss_json" \
    --argjson count "$deterministic_count" \
    '{
      workload: $workload,
      target: $target,
      config: $config,
      format: $format,
      runs: $runs,
      wall_seconds: $wall,
      max_rss_kb: $rss,
      findings: { count: $count, deterministic: true }
    }'
}

ensure_parent_dir() {
  local path="$1"
  local parent
  parent="$(dirname -- "$path")"
  mkdir -p -- "$parent"
}

write_single_json() {
  local cell_file="$1"
  ensure_parent_dir "$OUT_PATH"
  jq -n --slurpfile cell "$cell_file" --arg tool "gruff-ts" --arg target "$TARGET" --argjson runs "$RUNS" '
    {
      tool: $tool,
      target: $target,
      runs: $runs,
      wall_seconds: $cell[0].wall_seconds,
      max_rss_kb: $cell[0].max_rss_kb,
      findings: $cell[0].findings
    }
  ' > "$OUT_PATH"
}

print_single_summary() {
  jq -r '
    def r3: (. * 1000 | round / 1000);
    def mb: (. / 1024 * 10 | round / 10);
    "gruff-ts performance",
    "Target: \(.target)",
    "Runs: \(.runs)",
    "Wall: \(.wall_seconds.mean | r3)s +/- \(.wall_seconds.stddev | r3)s (min \(.wall_seconds.min | r3)s, max \(.wall_seconds.max | r3)s)",
    "Max RSS: \(.max_rss_kb.mean | mb) MB +/- \(.max_rss_kb.stddev | mb) MB (min \(.max_rss_kb.min | mb) MB, max \(.max_rss_kb.max | mb) MB)",
    "Findings: \(.findings.count) deterministic",
    "JSON: \($path)"
  ' --arg path "$OUT_PATH" "$OUT_PATH"
}

generate_large_fixture() {
  local target_dir="$1"
  local file_count="$2"
  local index
  local line
  local file

  mkdir -p -- "$target_dir"
  for ((index = 1; index <= file_count; index++)); do
    file="$target_dir/perf-fixture-$index.ts"
    {
      printf 'export class PerfFixture%s {\n' "$index"
      printf '  public name = "fixture-%s";\n' "$index"
      printf '  public process%s(input: string[]): number {\n' "$index"
      printf '    let total = 0;\n'
      for ((line = 1; line <= 192; line++)); do
        printf '    total += input[%s]?.length ?? %s;\n' "$((line % 7))" "$((index + line))"
      done
      printf '    return total;\n'
      printf '  }\n'
      printf '}\n'
    } > "$file"
  done
}

run_matrix() {
  local cells_file="$TMP_DIR/cells.jsonl"
  local matrix_file="$TMP_DIR/matrix.json"
  local generated_at
  local WORKLOADS=("fixtures/sample.ts" "src" "synthetic-large")
  local WORKLOADS_TARGETS
  local config_labels=("--no-config" "default")
  local config_flags=("--no-config" "")
  local formats=("json" "text")
  local wi
  local ci
  local format

  if [[ "$CLEANUP" -eq 1 ]]; then
    cleanup_old_fixtures
  fi

  CURRENT_FIXTURE_DIR="/tmp/gruff-perf-fixture-$$"
  generate_large_fixture "$CURRENT_FIXTURE_DIR" 100
  WORKLOADS_TARGETS=("fixtures/sample.ts" "src" "$CURRENT_FIXTURE_DIR")
  : > "$cells_file"

  for wi in "${!WORKLOADS[@]}"; do
    for ci in "${!config_labels[@]}"; do
      for format in "${formats[@]}"; do
        run_cell "${WORKLOADS[$wi]}" "${WORKLOADS_TARGETS[$wi]}" "${config_labels[$ci]}" "${config_flags[$ci]}" "$format" >> "$cells_file"
      done
    done
  done

  generated_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  jq -s \
    --arg tool "gruff-ts" \
    --arg schemaVersion "$SCHEMA_VERSION" \
    --arg generatedAt "$generated_at" \
    --argjson runs "$RUNS" \
    '{ tool: $tool, schemaVersion: $schemaVersion, generatedAt: $generatedAt, runs: $runs, cells: . }' \
    "$cells_file" > "$matrix_file"

  ensure_parent_dir "$OUT_PATH"
  cp -- "$matrix_file" "$OUT_PATH"
}

validate_baseline_schema() {
  local schema
  [[ -f "$BASELINE_PATH" ]] || die 2 "baseline file does not exist: $BASELINE_PATH"
  schema="$(jq -r '.schemaVersion // ""' "$BASELINE_PATH")" || die 2 "invalid baseline JSON: $BASELINE_PATH"
  [[ "$schema" == "$SCHEMA_VERSION" ]] || die 2 "unsupported perf baseline schema: ${schema:-missing}"
}

write_baseline() {
  ensure_parent_dir "$WRITE_BASELINE_PATH"
  if [[ -e "$WRITE_BASELINE_PATH" && "$FORCE" -ne 1 ]]; then
    die 2 "baseline already exists: $WRITE_BASELINE_PATH (use --force to overwrite)"
  fi
  cp -- "$OUT_PATH" "$WRITE_BASELINE_PATH"
}

empty_baseline_file() {
  local path="$TMP_DIR/empty-baseline.json"
  printf '{"cells":[]}\n' > "$path"
  printf '%s\n' "$path"
}

write_markdown_report() {
  local current_json="$1"
  local baseline_json="$2"
  local destination="$3"
  local report_tmp="$TMP_DIR/perf-report.md"

  jq -r --slurpfile baseline "$baseline_json" '
    def key($cell): $cell.workload + "\u0000" + $cell.config + "\u0000" + $cell.format;
    def r3: (. * 1000 | round / 1000);
    def mb: (. / 1024 * 10 | round / 10);
    def pct($now; $then):
      if ($then == null or $then == 0) then "-"
      else
        (((($now - $then) / $then) * 100 * 10 | round / 10) as $value
          | (if ($value > -0.05 and $value < 0.05) then 0 else $value end) as $display
          | (if $display > 0 then "+" else "" end) + ($display | tostring) + "%")
      end;
    ($baseline[0].cells // [] | map({key: key(.), value: .}) | from_entries) as $base
    | [
        "# gruff-ts perf",
        "",
        "| workload | config | format | wall mean (s) | wall σ | RSS mean (MB) | findings | Δwall vs baseline | Δrss vs baseline |",
        "|---|---|---|---:|---:|---:|---:|---:|---:|",
        (.cells[] as $cell
          | ($base[(key($cell))] // null) as $old
          | "| \($cell.workload) | \($cell.config) | \($cell.format) | \($cell.wall_seconds.mean | r3) | \($cell.wall_seconds.stddev | r3) | \($cell.max_rss_kb.mean | mb) | \($cell.findings.count) | \(pct($cell.wall_seconds.mean; ($old.wall_seconds.mean // null))) | \(pct($cell.max_rss_kb.mean; ($old.max_rss_kb.mean // null))) |")
      ]
    | .[]
  ' "$current_json" > "$report_tmp"

  if [[ -n "$destination" ]]; then
    ensure_parent_dir "$destination"
    cp -- "$report_tmp" "$destination"
  elif [[ "$QUIET" -ne 1 ]]; then
    cat "$report_tmp"
  fi
}

check_missing_baseline_cells() {
  local current_json="$1"
  local missing_file="$TMP_DIR/missing-baseline-cells.txt"
  jq -r --slurpfile baseline "$BASELINE_PATH" '
    def key($cell): $cell.workload + "\u0000" + $cell.config + "\u0000" + $cell.format;
    ($baseline[0].cells // [] | map({key: key(.), value: true}) | from_entries) as $base
    | .cells[]
    | select(($base[(key(.))] // false) | not)
    | "\(.workload) \(.config) \(.format)"
  ' "$current_json" > "$missing_file"
  if [[ -s "$missing_file" ]]; then
    printf 'baseline is missing perf cells:\n' >&2
    while IFS= read -r line; do
      printf -- '- %s\n' "$line" >&2
    done < "$missing_file"
    exit 2
  fi
}

check_regressions() {
  local current_json="$1"
  local regressions_file="$TMP_DIR/perf-regressions.txt"
  jq -r --argjson tolerance "$REGRESSION_TOLERANCE" --slurpfile baseline "$BASELINE_PATH" '
    def key($cell): $cell.workload + "\u0000" + $cell.config + "\u0000" + $cell.format;
    def delta($now; $then):
      if ($then == null or $then == 0) then 0
      else (($now - $then) / $then) * 100
      end;
    def r1: (. * 10 | round / 10);
    ($baseline[0].cells // [] | map({key: key(.), value: .}) | from_entries) as $base
    | .cells[] as $cell
    | ($base[(key($cell))] // null) as $old
    | select($old != null)
    | (delta($cell.wall_seconds.mean; $old.wall_seconds.mean)) as $wall
    | (delta($cell.max_rss_kb.mean; $old.max_rss_kb.mean)) as $rss
    | select($wall > $tolerance or $rss > $tolerance)
    | "\($cell.workload) \($cell.config) \($cell.format): wall \($wall | r1)% rss \($rss | r1)%"
  ' "$current_json" > "$regressions_file"

  if [[ -s "$regressions_file" ]]; then
    printf 'performance regression detected (tolerance %s%%):\n' "$REGRESSION_TOLERANCE" >&2
    while IFS= read -r line; do
      printf -- '- %s\n' "$line" >&2
    done < "$regressions_file"
    exit 1
  fi
}

run_single() {
  local cell_file="$TMP_DIR/single-cell.json"
  run_cell "$TARGET" "$TARGET" "--no-config" "--no-config" "json" > "$cell_file"
  write_single_json "$cell_file"
  if [[ "$QUIET" -eq 1 ]]; then
    printf '%s\n' "$OUT_PATH"
  else
    print_single_summary
  fi
}

main() {
  local root
  local report_baseline

  parse_args "$@"
  validate_args
  root="$(repo_root)"
  cd "$root"
  TMP_DIR="/tmp/gruff-perf-work-$$"
  mkdir -p -- "$TMP_DIR"
  trap cleanup EXIT
  require_tools
  detect_time_cmd
  assert_elapsed_parser

  if [[ -n "$BASELINE_PATH" ]]; then
    validate_baseline_schema
  fi

  if [[ "$MATRIX" -eq 1 ]]; then
    run_matrix
    if [[ "$WRITE_BASELINE" -eq 1 ]]; then
      write_baseline
    fi
    if [[ -n "$BASELINE_PATH" ]]; then
      check_missing_baseline_cells "$OUT_PATH"
      report_baseline="$BASELINE_PATH"
    else
      report_baseline="$(empty_baseline_file)"
    fi
    write_markdown_report "$OUT_PATH" "$report_baseline" "$REPORT_PATH"
    if [[ "$QUIET" -eq 1 ]]; then
      printf '%s\n' "$OUT_PATH"
    fi
    if [[ "$FAIL_ON_REGRESSION" -eq 1 ]]; then
      check_regressions "$OUT_PATH"
    fi
  else
    run_single
  fi
}

main "$@"
