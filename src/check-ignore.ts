// `check-ignore` command core: classify each path through the shared discovery ignore engine and
// render the verdict. No analysis is performed - this is an O(1)-per-path config/gitignore/default
// lookup that mirrors `git check-ignore` exit semantics, so a coding-agent hook can ask "will gruff
// skip this changed file?" before running a scan. Single source of truth: `classifyPathIgnore` is the
// exact engine `analyse` discovery uses; this module only loads config and formats the output.
import { cwd } from "node:process";
import { loadConfig } from "./config.ts";
import { classifyPathIgnore, type PathIgnoreClassification } from "./discovery.ts";
import type { AnalysisOptions } from "./types.ts";

/** Output encodings supported by the `check-ignore` command. */
export type CheckIgnoreFormat = "text" | "json";

// Reads config using the current working directory. The options select config and control whether ordinary ignore rules are bypassed.
// Returns one classification per input path in input order. A path with no applicable ignore rule has no source or pattern.
// Config paths.ignore takes precedence. Ignored paths report the source and pattern that caused the skip.
export function checkIgnore(inputs: string[], options: AnalysisOptions): PathIgnoreClassification[] {
  const projectRoot = cwd();
  const config = loadConfig(projectRoot, options);
  return inputs.map((input) => classifyPathIgnore(projectRoot, input, options, config));
}

// Converts path classifications to the git check-ignore status. Returns 0 if any path is ignored and 1 otherwise, including an empty list.
// The CLI's runWithConfigErrorHandling assigns exit 2 for configuration failures.
export function checkIgnoreExitCode(results: PathIgnoreClassification[]): number {
  return results.some((result) => result.isIgnored) ? 0 : 1;
}

// Returns the path classifications in the requested format. JSON includes every path with its ignored flag, source and pattern.
// JSON uses null for missing match details. Text lists ignored paths with a tab before source and pattern, separated by a colon.
// Text returns an empty string when no path is ignored.
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
