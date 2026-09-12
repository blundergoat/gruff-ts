// Baseline option handling for `analyse`: chooses the explicit or default baseline, hides the debt the user
// already reviewed, carries a 0.5 file forward on request, and writes a generated baseline.
//
// The matching rules live in `baseline-file.ts`; this module is the part a user's flags reach, so it owns which
// action a run takes and what the report says about it.
import { existsSync } from "node:fs";
import { join } from "node:path";
import { applyBaseline, migrateBaseline, requireOverwritableDefaultPath, sensitiveCountOf, writeBaseline, type BaselineCollision } from "./baseline-file.ts";
import { declarationPositionFromSpans, type DeclarationSpan } from "./baseline-identity.ts";
import { DEFAULT_BASELINE } from "./baseline.ts";
import { absolutize, displayPath } from "./discovery.ts";
import type { AnalysisOptions, AnalysisReport, Finding, RunDiagnostic } from "./types.ts";

/*
 * Result of applying, migrating, or generating a baseline. The optional `baseline` matches native baseline
 * metadata and is present only when a file was used or written.
 *
 * Invariant: `baseline` is absent unless a file was used or written; `diagnostics` carries one entry per collision
 * the run could not tell apart, and one entry when the baseline could not be read at all.
 */
export interface BaselineApplication {
  findings: Finding[];
  baseline?: NonNullable<AnalysisReport["baseline"]>;
  diagnostics: RunDiagnostic[];
}

// Resolved baseline path plus the provenance string emitted in the report. `source` distinguishes
// "explicit" (--baseline flag) from "default" (auto-discovered gruff-baseline.json).
interface BaselineSelection {
  path: string;
  source: string;
}

/*
 * Three-way baseline dispatcher. `--generate-baseline` wins (writes a new file, returns findings unchanged);
 * `--no-baseline` skips entirely; otherwise look for an explicit or default baseline and hide the reviewed debt.
 *
 * `declarationSpans` names the declarations this run parsed, so two findings inside one function share an
 * identity while a second same-named function takes its own; an empty map ranks by line instead.
 * Stable contract: generation wins over application, and a run with no baseline returns the findings untouched.
 */
export function applyBaselineOptions(projectRoot: string, options: AnalysisOptions, findings: Finding[], declarationSpans = new Map<string, DeclarationSpan[]>()): BaselineApplication {
  const declarationPosition = declarationPositionFromSpans(declarationSpans);
  if (options.generateBaseline) {
    return generateBaselineResult(projectRoot, options, findings, declarationPosition);
  }

  if (options.shouldSkipBaseline) {
    return { findings, diagnostics: [] };
  }

  const selected = selectedBaseline(projectRoot, options);
  if (!selected) {
    return { findings, diagnostics: [] };
  }

  return applySelectedBaseline(projectRoot, selected, findings, declarationPosition);
}

/*
 * Writes the baseline file and returns the report-shaped metadata. `suppressed: 0` because generation does not
 * hide anything: every current finding is captured and still shown, so the user sees what they just accepted.
 * With `--migrate-baseline` the reviews of a 0.5 file are carried across instead, leaving that file untouched.
 * Stable contract: generation hides nothing, so the user sees every finding they have just accepted.
 */
function generateBaselineResult(projectRoot: string, options: AnalysisOptions, findings: Finding[], declarationPosition: (finding: Finding) => number): BaselineApplication {
  const baselinePath = absolutize(projectRoot, options.generateBaseline ?? DEFAULT_BASELINE);
  // A generate at the shared default path never destroys a 0.5 baseline by accident; --force is the way to mean it.
  requireOverwritableDefaultPath(baselinePath, options.shouldForceBaselineOverwrite === true);
  const migratePath = options.migrateBaseline;
  const written = migratePath
    ? migrateBaseline(absolutize(projectRoot, migratePath), baselinePath, findings, declarationPosition)
    : { entries: writeBaseline(baselinePath, findings, declarationPosition), sensitiveCounted: sensitiveCountOf(findings, declarationPosition) };

  return {
    findings,
    baseline: {
      path: displayPath(projectRoot, baselinePath),
      source: migratePath ? "migrated" : "generated",
      suppressed: 0,
      generated: true,
      entries: written.entries,
      sensitiveCounted: written.sensitiveCounted,
    },
    diagnostics: [],
  };
}

/*
 * Loads the baseline and hides the occurrences the user already reviewed.
 *
 * A collision becomes a non-fatal diagnostic rather than a suppression, and a file that cannot be read at all
 * becomes a baseline-error diagnostic so the run reports the reason instead of silently showing every finding.
 * Stable contract: the reported counts come from the same application that filtered the findings, so they cannot disagree.
 */
function applySelectedBaseline(projectRoot: string, selected: BaselineSelection, findings: Finding[], declarationPosition: (finding: Finding) => number): BaselineApplication {
  const application = applyBaseline(selected.path, findings, declarationPosition);
  return {
    findings: application.findings,
    baseline: {
      path: displayPath(projectRoot, selected.path),
      source: selected.source,
      suppressed: application.counts.unchanged,
      generated: false,
      entries: application.entries,
      newFindings: application.counts.new + application.counts.collision + application.counts.notEligible,
      unchangedFindings: application.counts.unchanged,
      resolvedFindings: application.counts.absent,
    },
    diagnostics: application.collisions.map(collisionDiagnostic),
  };
}

/*
 * Names one identity that covered two declarations, so the user can see which review would have covered the
 * wrong finding. Neither finding is suppressed and the run is not invalidated.
 * The run reports the collision rather than throwing, and the diagnostic is non-fatal, so a collision alone
 * never fails a run.
 */
function collisionDiagnostic(collision: BaselineCollision): RunDiagnostic {
  return {
    diagnosticType: "baseline-collision",
    message: `collision: identity ${collision.identity} covers ${collision.subjects.length} declarations of ${collision.subjects.join(", ")} for rule ${collision.ruleId} in ${collision.path}; none is suppressed`,
    filePath: collision.path,
    invalidatesRun: false,
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
