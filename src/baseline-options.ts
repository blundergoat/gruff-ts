// Baseline option handling for `analyse`: chooses the explicit or default baseline, hides the debt the user
// already reviewed, carries a 0.5 file forward on request, and writes a generated baseline.
//
// The matching rules live in `baseline-file.ts`; this module is the part a user's flags reach, so it owns which
// action a run takes and what the report says about it.
import { existsSync } from "node:fs";
import { join } from "node:path";
import { applyBaseline, BaselineFileError, migrateBaseline, requireOverwritableDefaultPath, sensitiveCountOf, writeBaseline, type BaselineCollision } from "./baseline-file.ts";
import { type DeclarationPositionResolver, declarationPositionFromSpans, type DeclarationSpan } from "./baseline-identity.ts";
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
  // The path as the user wrote it, or the default file name, so a diagnostic never prints this machine's absolute path.
  label: string;
}

/* --generate-baseline takes precedence over --no-baseline so that generation can write without applying an existing baseline. */
/**
 * Apply the stable baseline selection contract to hide reviewed findings. Generation writes a baseline and keeps all findings.
 *
 * @param projectRoot - Directory used to resolve relative baseline paths and locate the default file.
 * @param options - Selects generation, migration, skipping or baseline application and supplies any explicit paths.
 * @param findings - Findings to record in the generated baseline or compare against the selected baseline.
 * @param declarationSpans - Supplies start lines so that same-named declarations rank separately. Unmatched findings use their own lines.
 * @param unusableBaseline - Diagnose mode turns a baseline file error into a fatal diagnostic and keeps all findings. Throw mode is the default.
 * @returns Findings, diagnostics and optional baseline metadata. Skipping or finding no baseline keeps all findings and yields no diagnostics.
 * @throws {BaselineFileError} - When generation or application raises a baseline file error in throw mode.
 * @throws {Error} - When another generation or application error propagates in either mode.
 */
export function applyBaselineOptions(projectRoot: string, options: AnalysisOptions, findings: Finding[], declarationSpans = new Map<string, DeclarationSpan[]>(), unusableBaseline: "throw" | "diagnose" = "throw"): BaselineApplication {
  const declarationPosition = declarationPositionFromSpans(declarationSpans);
  if (options.generateBaseline) {
    try {
      return generateBaselineResult(projectRoot, options, findings, declarationPosition);
    } catch (error) {
      // For example, running `--generate-baseline` over an existing 0.5 default baseline without `--force`, or passing a bad `--migrate-baseline`.
      // In diagnose mode, keep all findings visible and invalidate the run with a path-safe diagnostic.
      if (unusableBaseline === "diagnose" && error instanceof BaselineFileError) {
        return { findings, diagnostics: [{ diagnosticType: "baseline-error", message: sanitizeGenerationErrorMessage(projectRoot, options, error.message) }] };
      }
      throw error;
    }
  }

  if (options.shouldSkipBaseline) {
    return { findings, diagnostics: [] };
  }

  const selected = selectedBaseline(projectRoot, options);
  if (!selected) {
    return { findings, diagnostics: [] };
  }

  try {
    return applySelectedBaseline(projectRoot, selected, findings, declarationPosition);
  } catch (error) {
    // For example, passing `--baseline missing.json` or pointing at a corrupt or wrong-schema baseline file.
    // In diagnose mode, keep all findings visible and report the caller's path label in the fatal diagnostic.
    if (unusableBaseline === "diagnose" && error instanceof BaselineFileError) {
      return { findings, diagnostics: [{ diagnosticType: "baseline-error", message: error.message.replaceAll(selected.path, selected.label) }] };
    }
    throw error;
  }
}

/**
 * Writes eligible baseline entries or carries forward matching reviews with --migrate-baseline while preserving the input file.
 * Stable contract: returns every finding with write metadata, zero suppressions, and an empty diagnostics list.
 *
 * @param projectRoot - Base directory used to resolve relative target and migration paths and format the output display path.
 * @param options - Supplies the generate target path, optional migrate source path, and force-overwrite flag.
 * @param findings - Findings to write or migrate and count for sensitive-data metadata.
 * @param declarationPosition - Resolves enclosing declaration positions for stable baseline identities.
 * @returns Every finding unchanged along with generated or migrated baseline metadata and an empty diagnostics list.
 */
function generateBaselineResult(projectRoot: string, options: AnalysisOptions, findings: Finding[], declarationPosition: DeclarationPositionResolver): BaselineApplication {
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

/**
 * Apply the selected baseline and derive report counts from the same result so that they agree with the filtered findings.
 *
 * @param projectRoot - base used to display the selected baseline path
 * @param selected - baseline path to read and selection source to record
 * @param findings - current findings to match against reviewed counts
 * @param declarationPosition - resolves declaration positions for stable baseline identities
 * @returns Visible findings, baseline metadata, and non-fatal diagnostics for any collisions.
 * @throws {BaselineFileError} - the selected baseline cannot be read or applied.
 */
function applySelectedBaseline(projectRoot: string, selected: BaselineSelection, findings: Finding[], declarationPosition: DeclarationPositionResolver): BaselineApplication {
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

/**
 * Builds a non-fatal diagnostic for a baseline collision.
 * Under the baseline contract, findings sharing the identity stay visible, so their severities can still affect the run's result.
 *
 * @param collision - Collision record providing the shared identity, rule ID, file path, and colliding subjects.
 * @returns Non-fatal diagnostic naming the colliding review's identity, rule, path, and reported subjects.
 */
function collisionDiagnostic(collision: BaselineCollision): RunDiagnostic {
  return {
    diagnosticType: "baseline-collision",
    message: `collision: identity ${collision.identity} covers ${collision.subjects.length} declarations of ${collision.subjects.join(", ")} for rule ${collision.ruleId} in ${collision.path}; none is suppressed`,
    filePath: collision.path,
    invalidatesRun: false,
  };
}

/**
 * Selects the baseline path, source, and display label from options, resolving relative paths against projectRoot.
 * Without an explicit path, selects gruff-baseline.json only if it exists at projectRoot; the no-baseline contract keeps all findings visible.
 *
 * @param projectRoot - Base directory used to resolve explicit relative paths or locate the default baseline file.
 * @param options - Supplies an optional explicit baseline path.
 * @returns Selected baseline path, source, and display label, or undefined when no explicit path is set and no default file exists.
 */
function selectedBaseline(projectRoot: string, options: AnalysisOptions): BaselineSelection | undefined {
  if (options.baseline) {
    return { path: absolutize(projectRoot, options.baseline), source: "explicit", label: options.baseline };
  }
  const defaultBaseline = join(projectRoot, DEFAULT_BASELINE);
  return existsSync(defaultBaseline) ? { path: defaultBaseline, source: "default", label: DEFAULT_BASELINE } : undefined;
}

/**
 * Replaces resolved absolute baseline and migration paths inside a generation diagnostic with the caller's path labels.
 * Keeps host filesystem locations out of machine JSON and SARIF error messages.
 *
 * @param projectRoot - Base directory used to resolve the caller's generate and migrate path arguments.
 * @param options - Analysis options with path labels; omitted `generateBaseline` uses `DEFAULT_BASELINE`, omitted `migrateBaseline` skips it.
 * @param message - Raw baseline file error message produced during generation or migration.
 * @returns Sanitized diagnostic message with resolved paths replaced by their caller-supplied labels.
 */
function sanitizeGenerationErrorMessage(projectRoot: string, options: AnalysisOptions, message: string): string {
  const generateLabel = options.generateBaseline ?? DEFAULT_BASELINE;
  let sanitized = message.replaceAll(absolutize(projectRoot, generateLabel), generateLabel);
  // With --migrate-baseline, the old baseline's path is also shown the way the user typed it.
  if (options.migrateBaseline !== undefined) {
    sanitized = sanitized.replaceAll(absolutize(projectRoot, options.migrateBaseline), options.migrateBaseline);
  }
  return sanitized;
}
