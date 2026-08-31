// Baseline option handling for `analyse`: chooses explicit/default baselines, applies
// suppression, and writes generated baselines while preserving the report metadata shape.
import { existsSync } from "node:fs";
import { join } from "node:path";
import { applyBaseline, DEFAULT_BASELINE, writeBaseline } from "./baseline.ts";
import { absolutize, displayPath } from "./discovery.ts";
import type { AnalysisOptions, AnalysisReport, Finding } from "./types.ts";

/*
 * Result of applying a baseline (suppression) or generating a new one. The optional `baseline`
 * matches native baseline metadata and is present only when a baseline file was used or generated.
 * Invariant: `baseline` is absent unless a file was used or generated; the v3 adapter renames only
 * `suppressed` to `suppressedFindings` at the JSON boundary.
 */
export interface BaselineApplication {
  findings: Finding[];
  baseline?: NonNullable<AnalysisReport["baseline"]>;
}

// Resolved baseline path plus the provenance string emitted in the report. `source` distinguishes
// "explicit" (--baseline flag) from "default" (auto-discovered gruff-baseline.json).
interface BaselineSelection {
  path: string;
  source: string;
}

/*
 * Three-way baseline dispatcher. `--generate-baseline` wins (writes a new file, returns findings
 * unchanged); `--no-baseline` skips entirely; otherwise look for an explicit or default baseline.
 * The stable identity tuple (fingerprint, ruleId, filePath) drives suppression matching.
 */
export function applyBaselineOptions(projectRoot: string, options: AnalysisOptions, findings: Finding[]): BaselineApplication {
  if (options.generateBaseline) {
    return generateBaselineResult(projectRoot, options.generateBaseline, findings);
  }

  if (options.shouldSkipBaseline) {
    return { findings };
  }

  const selected = selectedBaseline(projectRoot, options);
  if (!selected) {
    return { findings };
  }

  return applySelectedBaseline(projectRoot, selected, findings);
}

/*
 * Writes the baseline file via writeBaseline and returns the report-shaped metadata. `suppressed: 0`
 * because generation does not filter findings - every current finding is captured in the stable baseline.
 */
function generateBaselineResult(projectRoot: string, baselineFile: string, findings: Finding[]): BaselineApplication {
  const baselinePath = absolutize(projectRoot, baselineFile);
  writeBaseline(baselinePath, findings);
  return {
    findings,
    baseline: {
      path: displayPath(projectRoot, baselinePath),
      source: "generated",
      suppressed: 0,
      generated: true,
    },
  };
}

// Loads the baseline file and filters findings whose identity tuple matches. `suppressed` is
// computed from the size delta so the stable baseline report metadata stays accurate.
function applySelectedBaseline(projectRoot: string, selected: BaselineSelection, findings: Finding[]): BaselineApplication {
  const before = findings.length;
  const filteredFindings = applyBaseline(selected.path, findings);
  return {
    findings: filteredFindings,
    baseline: {
      path: displayPath(projectRoot, selected.path),
      source: selected.source,
      suppressed: before - filteredFindings.length,
      generated: false,
    },
  };
}

// Picks an explicit `--baseline` path first, then the conventional `gruff-baseline.json` at the
// project root. Returning undefined means "no baseline" - the stable contract preserves report shape.
function selectedBaseline(projectRoot: string, options: AnalysisOptions): BaselineSelection | undefined {
  if (options.baseline) {
    return { path: absolutize(projectRoot, options.baseline), source: "explicit" };
  }
  const defaultBaseline = join(projectRoot, DEFAULT_BASELINE);
  return existsSync(defaultBaseline) ? { path: defaultBaseline, source: "default" } : undefined;
}
