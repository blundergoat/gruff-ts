// Powers `gruff-ts check-ignore`, answering whether gruff would skip each path without running analysis.
//
// Reuses `classifyPathIgnore` from `discovery.ts` so `check-ignore` and `analyse` never disagree:
// - mirrors `git check-ignore` exit codes (0 = at least one ignored, 1 = none ignored, 2 = config error);
// - lets coding-agent hooks and CI scripts check ignore policy in O(1) per path before scanning.
import { cwd } from "node:process";
import { loadConfig } from "./config.ts";
import { classifyPathIgnore, type PathIgnoreClassification } from "./discovery.ts";
import type { AnalysisOptions } from "./types.ts";

/** Output encodings supported by the `check-ignore` command. */
export type CheckIgnoreFormat = "text" | "json";

/**
 * Reads config using the current working directory and classifies each path through discovery ignore rules.
 * Config paths.ignore takes precedence over other ignore sources.
 *
 * @param inputs - File or directory paths to classify against the ignore rules.
 * @param options - Analysis options that select config and control whether ordinary ignore rules are bypassed.
 * @returns One classification per input path in input order, reporting the matching source and pattern when ignored.
 */
export function checkIgnore(inputs: string[], options: AnalysisOptions): PathIgnoreClassification[] {
  const projectRoot = cwd();
  const config = loadConfig(projectRoot, options);
  return inputs.map((input) => classifyPathIgnore(projectRoot, input, options, config));
}

/**
 * Converts path classifications to the `git check-ignore` exit status.
 * The CLI's `runWithConfigErrorHandling` assigns exit 2 for configuration failures.
 *
 * @param results - Path ignore classifications produced by `checkIgnore`.
 * @returns `0` if any path in `results` is ignored, and `1` otherwise, including for an empty list.
 */
export function checkIgnoreExitCode(results: PathIgnoreClassification[]): number {
  return results.some((result) => result.isIgnored) ? 0 : 1;
}

/**
 * Formats path classifications as JSON or tab-delimited text.
 * JSON includes every path with `null` for missing match details; text lists ignored paths with a tab before `source:pattern`.
 *
 * @param results - Path ignore classifications to format.
 * @param format - Output format (`"json"` for all paths, `"text"` for ignored paths only).
 * @returns Formatted classification output, or an empty string in `"text"` format when no path is ignored.
 */
export function renderCheckIgnore(results: PathIgnoreClassification[], format: CheckIgnoreFormat): string {
  if (format === "json") {
    return JSON.stringify(
      results.map((result) => ({
        path: result.path,
        ignored: result.isIgnored,
        source: result.source ?? null,
        pattern: result.pattern ?? null,
      })),
      null,
      2,
    );
  }
  return results
    .filter((result) => result.isIgnored)
    .map((result) => `${result.path}\t${result.source}:${result.pattern}`)
    .join("\n");
}
