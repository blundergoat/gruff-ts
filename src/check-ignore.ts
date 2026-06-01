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

// Resolves config exactly as `analyse` does (`--config` / `--no-config`), then classifies each input
// path. Config `paths.ignore` is authoritative; default and gitignore matches are reported with their
// source too so the caller sees why a path would be skipped.
export function checkIgnore(inputs: string[], options: AnalysisOptions): PathIgnoreClassification[] {
  const projectRoot = cwd();
  const config = loadConfig(projectRoot, options);
  return inputs.map((input) => classifyPathIgnore(projectRoot, input, options, config));
}

// Mirrors `git check-ignore`: exit 0 when at least one path is ignored, 1 when none are. Exit 2 is
// reserved for config/usage errors and is set by the CLI layer via `runWithConfigErrorHandling`.
export function checkIgnoreExitCode(results: PathIgnoreClassification[]): number {
  return results.some((result) => result.isIgnored) ? 0 : 1;
}

// JSON is the agent-facing contract: every input path as `{ path, ignored, source, pattern }`, with
// `source`/`pattern` null when the path is not ignored. Text lists only the ignored paths as
// `<path>\t<source>:<pattern>`, matching `git check-ignore`'s "print the matches" behaviour.
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
