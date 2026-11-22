// File overview: Builds the analysis report used by the CLI, dashboard, and coding-agent hook.
//
// A command such as `gruff-ts analyse src --diff staged` still reads project context before selecting findings from staged changes.
// This module also applies reviewed findings from a baseline and records history after a valid full scan.
import { Buffer, isUtf8 } from "node:buffer";
import { readFileSync, statSync } from "node:fs";
import { cwd } from "node:process";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { recordHistory, sortedUniqueFindings } from "./baseline.ts";
import { declarationPositionFromSpans, findingIdentities, type DeclarationSpan } from "./baseline-identity.ts";
import { applyBaselineOptions, type BaselineApplication } from "./baseline-options.ts";
import { CHANGED_REGION_DIAGNOSTIC_TYPE, ChangedRegionError, changedRegionScope, filterChangedFindings, filterScopedDiagnostics, type ChangedRegionScope } from "./changed-regions.ts";
import { loadConfig, optionBoolean, ruleEnabled, ruleSeverity, threshold } from "./config.ts";
import { applyInlineSuppressions } from "./inline-suppressions.ts";
import { applyBuiltInTestPathSkip, partitionSensitiveExclusions } from "./sensitive-exclusions.ts";
import { VERSION } from "./constants.ts";
import { absolutize, discoverSources, displayPath, type SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import { applyConfiguredSeverity, finding, parameterNames } from "./findings-helpers.ts";
import { commentRecords, type CommentRecord } from "./comment-scanner.ts";
import { catalogueConfidence } from "./rules.ts";
import { analyseArchitectureRules, analyseCircularImportRule, buildProjectIndex, CIRCULAR_IMPORT_RULE_ID, isProductionSourcePath, isTestPath, type ProjectSource } from "./project-rules.ts";
import { analyseBlockMeasures, analyseBlockRules, type BlockRuleContext, blockRuleContext, type FunctionBlock, functionBlocks, measuredOnlyFunctionBlocks } from "./blocks.ts";
import { bandedFields, LOWER_BAND_FILE, SPLIT_FILE } from "./limit-band.ts";
import { analyseClassRules } from "./class-rules.ts";
import { analyseDeadCode, analyseUnreachable, analyseUnusedImports } from "./dead-code-rules.ts";
import { analyseCommentQualityRules } from "./comment-rules.ts";
import { analyseDocRules, analyseFileOverviewDoc, analyseInterfaceDocs } from "./doc-rules.ts";
import { analyseLineRules } from "./line-rules.ts";
import { analyseSecurityFlow } from "./security-flow-rules.ts";
import { pushIdentifierQualityAt, pushShortVariableAt } from "./naming-pushers.ts";
import { analyseTestBlock } from "./test-block-rules.ts";
import { analyseDuplicateTestGroups } from "./duplicate-test-group-rules.ts";
import { analyseGithubActionsRules } from "./github-actions-rules.ts";
import { analyseProjectConfigRules } from "./project-config-rules.ts";
import { ruleDescriptors } from "./rules.ts";
import { scoreReport, summarize } from "./scoring.ts";
import { isExecutionRequested } from "./selectors.ts";
import { analyseSensitiveData } from "./sensitive-data-rules.ts";
import { codeLineFlags, maskDecorators, parseScript, type ParsedScript } from "./parsed-script.ts";
import { maskNonCode, maskTemplateLiteralBodies } from "./source-text.ts";
import type { AnalysisOptions, AnalysisReport, Config, Finding, OutputFormat, Pillar, RunDiagnostic, ScanSurfaceNote, SkippedPath, SuppressedFinding, SuppressionSummary } from "./types.ts";

/*
 * Internal hook view contract: both reports come from one current-tree scan so full-file and
 * changed-region rendering stay stable and cannot drift.
 */
export interface HookAnalysisReports {
  currentReport: AnalysisReport;
  scopedReport: AnalysisReport;
}

/**
 * Build a report for an `analyse`, `summary`, or `report` request.
 * Invariant: an invalid scan or any changed-region scan is excluded from the user's full-scan score history.
 *
 * @param requestedOptions - paths, rules, and scan scope. An empty path list scans the launch directory. Omit history to skip writing it.
 * @returns A report ready for the caller's formatter. An unreadable changed scope returns a diagnostic and an empty findings list.
 * @throws ConfigLoadError for invalid configuration. Unexpected scope errors propagate to the caller.
 */
export function analyse(requestedOptions: AnalysisOptions): AnalysisReport {
  const options = targetsFromLaunchDirectory(requestedOptions);
  const preparation = prepareAnalysis(options);
  let changedScope: ChangedRegionScope | undefined;
  try {
    changedScope = changedRegionScope(options, preparation.projectRoot);
  } catch (error) {
    // A typo in `--changed-ranges` or a missing Git ref can be reported as an invalid scan before writing a baseline.
    if (!(error instanceof ChangedRegionError)) {
      throw error;
    }
    return failedRunReport(preparation.projectRoot, options.format, CHANGED_REGION_DIAGNOSTIC_TYPE, error.message);
  }
  const run = completeAnalysis(preparation, options, "diagnose");
  const changedResult = filterChangedFindings(run.baselineResult.findings, changedScope, run.scanned.sources);

  // Generation uses the full scan, so errors anywhere in that scan must stay visible.
  const diagnostics = options.generateBaseline ? run.diagnostics : filterScopedDiagnostics(run.diagnostics, changedScope);
  const baseline = run.baselineResult.baseline;
  // When a baseline was applied, `--fail-on-new` counts only unreviewed findings that remain in the requested scope.
  const scopedBaseline = {
    ...run.baselineResult,
    findings: changedResult.findings,
    ...(changedScope !== undefined && baseline && !baseline.generated
      ? { baseline: { ...baseline, newFindings: changedResult.findings.length } }
      : {}),
  };
  const report = reportFromRun({ ...run, diagnostics }, options, scopedBaseline, changedResult.suppressedCount);
  // An invalid baseline or a changed-region scan cannot add a point to the user's full-scan trend history.
  if (options.historyFile && changedScope === undefined && !diagnostics.some((diagnostic) => diagnostic.invalidatesRun !== false)) {
    recordHistory(run.projectRoot, options.historyFile, report.score, report.findings.length, diagnostics);
  }
  return report;
}

// Build the full and changed-region views the hook needs to distinguish a new finding from one already covered by a baseline.
// Both views use one read of the user's files. With no change selector, both fields point to that full scan.
export function analyseHookReports(currentOptions: AnalysisOptions, scopedOptions: AnalysisOptions, hasChangedRegion: boolean): HookAnalysisReports {
  currentOptions = targetsFromLaunchDirectory(currentOptions);
  scopedOptions = targetsFromLaunchDirectory(scopedOptions);
  // A hook without `--diff`, `--since`, or `--changed-ranges` has no narrower view to resolve.
  const scopedChangedScope = hasChangedRegion ? changedRegionScope(scopedOptions, projectRootFromTargets(scopedOptions.paths)) : undefined;
  const run = completeAnalysis(prepareAnalysis(currentOptions), currentOptions);
  const currentReport = reportFromRun(run, currentOptions, run.baselineResult);
  // An unscoped hook presents the same findings it uses for baseline comparison.
  if (!hasChangedRegion) {
    return { currentReport, scopedReport: currentReport };
  }
  const scopedChangedResult = filterChangedFindings(run.baselineResult.findings, scopedChangedScope, run.scanned.sources);
  // Same file-scoped diagnostics policy as diff-scoped analyse, so both surfaces agree.
  const scopedReport = reportFromRun({ ...run, diagnostics: filterScopedDiagnostics(run.diagnostics, scopedChangedScope) }, scopedOptions, { ...run.baselineResult, findings: scopedChangedResult.findings }, scopedChangedResult.suppressedCount);
  return { currentReport, scopedReport };
}

/**
 * Choose the directory that owns the user's scan configuration, Git diff, and report paths.
 * Use the launch directory for local targets and the common parent for targets outside it.
 *
 * @param paths - Scan targets resolved from the launch directory; an empty list selects the launch directory.
 * @returns The launch directory or a common ancestor. A lone missing external target uses its parent so JSON can name the missing file.
 * @throws When targets cannot share a filesystem root.
 */
export function projectRootFromTargets(paths: string[]): string {
  const launchDirectory = cwd();

  // No target was named, so the directory the command ran from is the project.
  if (paths.length === 0) {
    return launchDirectory;
  }

  let common: string | null = null;
  // A later usable target can widen the common directory because the root must contain every usable target.
  for (const path of paths) {
    const absolute = resolve(launchDirectory, path);
    let directory = absolute;
    try {
      // A file contributes its containing directory because reported paths need a directory anchor.
      if (!statSync(absolute).isDirectory()) {
        directory = dirname(absolute);
      }
    } catch {
      // A typo such as `analyse ../app/mising.ts` keeps a project-relative diagnostic. A missing file in a list cannot move its root.
      if (paths.length !== 1) {
        continue;
      }
      directory = dirname(absolute);
    }

    // The first target sets the starting answer; later ones can only widen it.
    if (common === null) {
      common = directory;
      continue;
    }
    // Expand the root until all usable targets can share one project-relative report.
    while (!isSameOrDescendant(directory, common)) {
      const parent = dirname(common);
      // Reaching a filesystem root without containing this target means no single root can anchor both paths.
      if (parent === common) {
        throw new Error("scan targets do not share a filesystem root");
      }
      common = parent;
    }
  }

  // Keep the launch directory when no target was usable or their shared root is inside it, preserving config and baseline anchoring.
  if (common === null || isSameOrDescendant(common, launchDirectory)) {
    return launchDirectory;
  }
  return common;
}

/**
 * Invariant: explicit paths keep their launch-directory meaning when a target selects a different project root.
 * For example, `analyse ../app --baseline reviewed.json` still reads `reviewed.json` from the launch directory.
 *
 * @param options - Scan options with paths from the command line. Omitted baseline and history options stay omitted.
 * @returns The original options for a local scan, or a copy with absolute targets and baseline and history paths pointing to the same files.
 */
function targetsFromLaunchDirectory(options: AnalysisOptions): AnalysisOptions {
  const launchDirectory = cwd();
  const projectRoot = projectRootFromTargets(options.paths);
  // Inside the launch directory the root and the operands already agree, so they are passed on exactly as typed.
  if (projectRoot === launchDirectory) {
    return options;
  }
  // Return path unchanged when absolute, or relative to projectRoot when it names a baseline from launchDirectory.
  const fromRoot = (path: string): string => (isAbsolute(path) ? path : relative(projectRoot, resolve(launchDirectory, path)));
  return {
    ...options,
    paths: options.paths.map((path) => resolve(launchDirectory, path)),
    ...(options.baseline ? { baseline: fromRoot(options.baseline) } : {}),
    ...(options.generateBaseline ? { generateBaseline: fromRoot(options.generateBaseline) } : {}),
    ...(options.migrateBaseline ? { migrateBaseline: fromRoot(options.migrateBaseline) } : {}),
    ...(options.historyFile ? { historyFile: fromRoot(options.historyFile) } : {}),
  };
}

/**
 * Check whether a target is inside a launch or scan directory using native path separators.
 * Use this before accepting multiple targets so `/work/apidocs` is treated as a sibling of `/work/api`.
 *
 * @param candidate - Directory being tested.
 * @param ancestor - Directory that may contain it.
 * @returns True when candidate is the ancestor or sits inside it.
 */
function isSameOrDescendant(candidate: string, ancestor: string): boolean {
  const fromAncestor = relative(ancestor, candidate);
  return !isAbsolute(fromAncestor) && fromAncestor !== ".." && !fromAncestor.startsWith(`..${sep}`);
}

// Return the project root, loaded config, discovered inputs and an empty diagnostic array selected by options for a scan.
function prepareAnalysis(options: AnalysisOptions): AnalysisPreparation {
  const projectRoot = projectRootFromTargets(options.paths);
  const config = loadConfig(projectRoot, options);
  const diagnostics: RunDiagnostic[] = [];
  const discovery = discoverSources(projectRoot, options, config);
  return { projectRoot, config, diagnostics, discovery };
}

/**
 * Give a finding its rule's catalogue confidence, so list-rules, the hook gate and the score read one value. A rule helper's
 * default must not override the catalogue. The fingerprint and stable identity do not include confidence, so both stay unchanged.
 *
 * @param finding - scanner result for a rule the catalogue normally lists
 * @returns the same finding when its confidence already matches, a copy carrying the catalogue confidence otherwise, or the
 *   finding unchanged for a rule id the catalogue does not list
 */
function withCatalogueConfidence(finding: Finding): Finding {
  const confidence = catalogueConfidence(finding.ruleId);
  return confidence === undefined || confidence === finding.confidence ? finding : { ...finding, confidence };
}

/**
 * Run the checks for the user's resolved project and apply its exclusions and baseline.
 * Invariant: assign baseline identities before filtering so the hook and SARIF can refer to the same finding.
 *
 * @param preparation - project scope, discovery and config, with the caller's diagnostic array to append to
 * @param options - scope and baseline choices. An unset baseline path lets the scan use the project's default when enabled.
 * @param unusableBaseline - `throw` lets the hook report a refusal. `diagnose` keeps findings and adds a fatal baseline diagnostic.
 * @returns Findings, diagnostics, and suppression counts for rendering. An empty findings list can still have diagnostics.
 * @throws {BaselineFileError} - a baseline file failure in throw mode.
 */
function completeAnalysis(preparation: AnalysisPreparation, options: AnalysisOptions, unusableBaseline: "throw" | "diagnose" = "throw"): AnalysisRun {
  const { projectRoot, config, diagnostics, discovery } = preparation;
  pushMissingPathDiagnostics(discovery.missingPaths, diagnostics);

  const scanned = scanDiscoveredSources(discovery.files, config, diagnostics);
  const allFindings = sortedUniqueFindings([
    ...scanned.findings,
    ...analyseProjectIndex(projectRoot, options, discovery.files, scanned.projectSources, config).filter((finding) => ruleEnabled(config, finding.ruleId)),
  ].map((finding) => applyConfiguredSeverity(config, withCatalogueConfidence(finding))));
  // An approved sensitive exclusion removes the finding from the report and gate, but its audit count still covers the full scan.
  const excluded = partitionSensitiveExclusions(allFindings, config.sensitiveExclusions);
  // A configured entry claims its findings first, so its count stays what the user wrote it for.
  const testPathSkipped = applyBuiltInTestPathSkip(excluded.findings, excluded.suppressions);
  // Assign baseline identities before filtering so hiding one declaration cannot renumber another in SARIF or the hook.
  const spans = declarationSpans(scanned);
  const namedFindings = withBaselineIdentities(testPathSkipped.findings, spans);
  // Apply inline suppressions to findings with identities so SARIF can still identify a suppressed result.
  const inline = applyInlineSuppressions(namedFindings, testPathSkipped.suppressions, scanned.sources);
  // A missing file or parse error makes `--generate-baseline` unsafe because it would save a partial review.
  const baselineResult = options.generateBaseline && diagnostics.some((diagnostic) => diagnostic.invalidatesRun !== false)
    ? { findings: inline.findings, diagnostics: [] }
    : applyBaselineOptions(projectRoot, options, inline.findings, spans, unusableBaseline);
  // A baseline collision records a non-fatal diagnostic and leaves every finding with that identity visible.
  diagnostics.push(...baselineResult.diagnostics);
  const notes = [...discovery.notes, ...scanned.notes];
  // A selective scan scores only pillars backed by enabled rules. Omitting selectors keeps the normal score denominator.
  const evaluatedPillars = options.execution && isExecutionRequested(options.execution)
    ? ruleDescriptors().filter((rule) => ruleEnabled(config, rule.ruleId)).map((rule) => rule.pillar)
    : undefined;
  return { projectRoot, discovery, diagnostics, scanned, baselineResult, notes, evaluatedPillars, suppressions: inline.suppressions, suppressedFindings: inline.suppressed };
}

/**
 * Builds the analysis report from the findings selected for this command.
 * Invariant: suppression audit counts cover the full scan, even when the report shows only the requested changes.
 *
 * @param run - completed scan supplying discovery totals, diagnostics, notes and suppression records
 * @param options - request inputs and threshold. No explicit inputs are shown as "." for a project scan.
 * @param baselineResult - the selected findings and any baseline details. No baseline leaves out the review section.
 * @param suppressedCount - number of findings omitted by changed-region filtering. Omit it to leave the field out of the report.
 * @returns Native report state with the supplied findings, scan totals, and any baseline or changed-region count supplied.
 */
function reportFromRun(run: AnalysisRun, options: AnalysisOptions, baselineResult: BaselineApplication, suppressedCount?: number): AnalysisReport {
  const findings = baselineResult.findings;
  return {
    schemaVersion: "gruff.analysis.v3",
    tool: { name: "gruff-ts", version: VERSION },
    run: {
      projectRoot: run.projectRoot,
      format: options.format,
      failOn: options.failOn,
      generatedAt: new Date().toISOString(),
      // Record explicit inputs as absolute paths so they keep their launch-directory meaning if the project root differs.
      // With no explicit input, a single dot denotes the default project scan.
      inputs: options.paths.length === 0 ? ["."] : options.paths.map((path) => resolve(cwd(), path)),
      ...(options.config === undefined ? {} : { config: resolve(cwd(), options.config) }),
      ...(options.shouldIncludeIgnored ? { includeIgnored: true as const } : {}),
    },
    summary: summarize(findings),
    paths: {
      analysedFiles: run.discovery.files.length,
      ignoredPaths: run.discovery.ignoredPaths,
      skipped: run.discovery.skipped,
      missingPaths: run.discovery.missingPaths,
    },
    diagnostics: run.diagnostics,
    ...(run.notes.length === 0 ? {} : { notes: run.notes }),
    suppressions: run.suppressions,
    suppressedFindings: run.suppressedFindings,
    findings,
    ...(suppressedCount === undefined ? {} : { suppressedCount }),
    // Score uses evaluated script files. The analysed file count also includes text assets that received raw-text checks.
    score: scoreReport(findings, run.scanned.evaluatedFiles, run.evaluatedPillars),
    ...(baselineResult.baseline ? { baseline: baselineResult.baseline } : {}),
  };
}

// The type every port publishes when it cannot load the configuration it was given.
export const CONFIG_ERROR_DIAGNOSTIC_TYPE = "config-error";

// The type every port publishes when it refuses the targets it was given, such as several outside the launch directory.
export const TARGET_ERROR_DIAGNOSTIC_TYPE = "target-error";

/**
 * Identify a multi-target request that violates the launch-directory boundary so the caller can refuse it before reporting.
 * A single external target is allowed; every target in a multi-target request must stay inside the launch directory.
 *
 * @param paths - Scan targets resolved from the launch directory for this boundary check.
 * @returns The first outside target in a multi-target request, or null when no request boundary is violated.
 */
export function targetOutsideLaunchDirectory(paths: string[]): string | null {
  // A single target, or none, always has a root the run can report against.
  if (paths.length < 2) {
    return null;
  }
  const launchDirectory = cwd();
  // Multi-target requests are refused as soon as any operand lies outside the launch directory.
  return paths.find((path) => !isSameOrDescendant(resolve(launchDirectory, path), launchDirectory)) ?? null;
}

/**
 * Build a stable gruff.analysis.v3 report for a run refused before discovery so machine consumers can read the failure.
 *
 * @param projectRoot - project path to record for the refused run
 * @param format - requested output format to record in run metadata
 * @param diagnosticType - category that identifies why the run was refused
 * @param message - explanation to include in the diagnostic
 * @returns A report with one run diagnostic, zero analysed files and no findings.
 */
export function failedRunReport(projectRoot: string, format: OutputFormat, diagnosticType: string, message: string): AnalysisReport {
  return {
    schemaVersion: "gruff.analysis.v3",
    tool: { name: "gruff-ts", version: VERSION },
    // Use the analyse default threshold because the caller handles the refusal status separately.
    run: { projectRoot, format, failOn: "advisory", generatedAt: new Date().toISOString() },
    summary: summarize([]),
    paths: { analysedFiles: 0, ignoredPaths: [], skipped: [], missingPaths: [] },
    diagnostics: [{ diagnosticType, message }],
    suppressions: [],
    findings: [],
    score: scoreReport([], 0),
  };
}

// Subset of discovery output that survives diff filtering. Held as its own type so the diff
// filter can mutate `files` in place without exposing the whole `SourceDiscoveryResult` shape.
interface DiscoverySummary {
  files: SourceFile[];
  ignoredPaths: string[];
  skipped: SkippedPath[];
  missingPaths: string[];
  notes: ScanSurfaceNote[];
}

// Output of the per-file scan pass - both the findings produced and the cached source bodies that
// later project-level rules need to operate against the deterministic stable shape used by baselines.
// Contract invariant: `notes` records non-text scan-surface changes without changing finding order.
interface SourceScanResult {
  findings: Finding[];
  evaluatedFiles: number;
  projectSources: ProjectSource[];
  sources: Map<string, { file: SourceFile; source: string; parsed?: ParsedScript }>;
  notes: ScanSurfaceNote[];
}

// Prepared inputs for one analysis run. Discovery stays separate from scanning so hook mode can
// reuse setup without re-reading config.
interface AnalysisPreparation {
  projectRoot: string;
  config: Config;
  diagnostics: RunDiagnostic[];
  discovery: DiscoverySummary;
}

// Completed scan state before final report rendering. Stable contract: the baseline result is
// carried separately so changed-region filtering can project findings without losing baseline
// metadata, and the suppression rows stay whole-scan counts rather than a projection of them.
interface AnalysisRun {
  projectRoot: string;
  discovery: DiscoverySummary;
  diagnostics: RunDiagnostic[];
  scanned: SourceScanResult;
  evaluatedPillars: Pillar[] | undefined;
  baselineResult: BaselineApplication;
  notes: ScanSurfaceNote[];
  // Configured sensitive-exclusion rows, then built-in test-path and section 13c rows, counted over the full scan
  // so a changed-region projection cannot understate what a suppression actually hid.
  suppressions: SuppressionSummary[];
  // Findings section 13c removed, kept so SARIF can show each as suppressed.
  suppressedFindings: SuppressedFinding[];
}

// Append one missing-path diagnostic to diagnostics for each requested path in missingPaths that discovery could not resolve.
// Returns nothing. These diagnostics invalidate the run and force exit 2. An empty list adds nothing.
function pushMissingPathDiagnostics(missingPaths: string[], diagnostics: RunDiagnostic[]): void {
  for (const missingPath of missingPaths) {
    diagnostics.push({
      diagnosticType: "missing-path",
      message: `Input path does not exist: ${missingPath}`,
      filePath: missingPath,
    });
  }
}

/**
 * Read and scan inputs in stable discovery order so that project-index snapshots keep their graph anchors.
 * Record failures caught during a file's read or scan as read-error diagnostics so the remaining files can still be checked.
 *
 * @param files - discovered inputs in a stable order. An empty list leaves the scan with no files to score.
 * @param config - scan budget, rule settings and project-source selection settings
 * @param diagnostics - caller's array for budget, parser and caught file-scan diagnostics
 * @returns Findings, retained project snapshots, text sources with optional parses, and notes for skipped non-text inputs.
 */
function scanDiscoveredSources(files: SourceFile[], config: Config, diagnostics: RunDiagnostic[]): SourceScanResult {
  const findings: Finding[] = [];
  let evaluatedFiles = 0;
  const projectSources: ProjectSource[] = [];
  const sources = new Map<string, { file: SourceFile; source: string; parsed?: ParsedScript }>();
  const notes: ScanSurfaceNote[] = [];
  // Check each supported input so one unreadable file can be diagnosed without discarding the other files' findings.
  for (const file of files) {
    try {
      const fileBytes = readFileSync(file.absolutePath);
      // Non-text bytes cannot produce trustworthy findings; the note explains why the file was skipped.
      if (!isUtf8(fileBytes) || fileBytes.includes(0)) {
        notes.push({
          noteType: "non-text-file",
          path: file.displayPath,
          message: "File was skipped before parsing because it contains invalid UTF-8 or NUL bytes.",
        });
        continue;
      }
      const source = fileBytes.toString("utf8");
      const budgetDiagnostic = deepScanBudgetDiagnostic(file, source, config);
      // Over-budget scripts skip parsing and project snapshots but still get enabled text checks. Other scripts share one parse.
      const parsed = budgetDiagnostic ? undefined : parseScript(file, source);
      sources.set(file.displayPath, { file, source, ...(parsed ? { parsed } : {}) });
      // The user can still see text findings from a script that exceeds the deep-scan budget.
      if (budgetDiagnostic) {
        diagnostics.push(budgetDiagnostic);
      } else {
        // Retain files that can contribute to cross-file findings such as import cycles.
        if (shouldRetainProjectSource(file, source)) {
          projectSources.push(projectSource(file, source, parsed));
        }
        diagnostics.push(...(parsed?.diagnostics ?? []));
      }
      findings.push(...analyseSource(file, source, config, budgetDiagnostic === undefined, parsed));
      // Text assets can produce findings, but only evaluated scripts contribute to the file count used for scoring.
      if (file.isScript) {
        evaluatedFiles += 1;
      }
    } catch (error) {
      // A file deleted during the scan produces a diagnostic. Findings from other files remain available.
      diagnostics.push({
        diagnosticType: "read-error",
        message: `Unable to read file: ${String(error)}`,
        filePath: file.displayPath,
        line: 1,
      });
    }
  }
  return { findings, evaluatedFiles, projectSources, sources, notes };
}

/**
 * Attach baseline identities and subjects before filtering so that SARIF and baseline matching share the same stable fingerprint identity.
 *
 * @param findings - findings to name together before any reporting view narrows the list
 * @param spansByFile - parsed declaration spans used to assign positions and ordinals
 * @returns A new array in input order. Findings with identities gain native identity and subject fields, and unnamed findings stay unchanged.
 */
function withBaselineIdentities(findings: Finding[], spansByFile: Map<string, DeclarationSpan[]>): Finding[] {
  const identities = findingIdentities(findings, declarationPositionFromSpans(spansByFile));
  return findings.map((finding, index) => {
    const named = identities[index];
    // Publishing the subject beside the identity is what lets the hook state the ordinal instead of re-deriving it.
    return named === undefined ? finding : { ...finding, baselineIdentity: named.identity, baselineSubject: named.subject };
  });
}

/*
 * Collect declaration positions so a baseline can distinguish same-named functions in one file.
 * Files with no syntax tree use finding positions, including scripts scanned under the deep-scan budget limit.
 */
function declarationSpans(scanned: SourceScanResult): Map<string, DeclarationSpan[]> {
  const spansByFile = new Map<string, DeclarationSpan[]>();
  // Rank declarations per file so a same-named function in another file has its own reviewed identity.
  for (const [displayPath, entry] of scanned.sources) {
    // A text-only file or budget-limited script has no syntax tree and cannot supply declaration positions.
    if (!entry.parsed) {
      continue;
    }
    const blocks = functionBlocks(entry.source, entry.source, entry.parsed);
    // Keep positions for measured inline functions too, so two functions named `<iife>` can have separate baseline entries.
    const measuredOnly = measuredOnlyFunctionBlocks(entry.source, maskNonCode(entry.source), entry.parsed);
    spansByFile.set(
      displayPath,
      [...blocks, ...measuredOnly].map((block) => ({ name: block.name, startLine: block.startLine, endLine: block.startLine + block.lineCount - 1 })),
    );
  }
  return spansByFile;
}

// Return a non-fatal budget diagnostic for script file and source using config.deepScanBudget.
// Return undefined for non-scripts, a disabled budget or source within both limits; a diagnostic requests skipping deep script checks.
function deepScanBudgetDiagnostic(file: SourceFile, source: string, config: Config): RunDiagnostic | undefined {
  const budget = config.deepScanBudget;
  if (!file.isScript || !budget.enabled) {
    return undefined;
  }
  const lines = lineCount(source);
  const bytes = Buffer.byteLength(source, "utf8");
  if (lines <= budget.maxLines && bytes <= budget.maxBytes) {
    return undefined;
  }
  return {
    diagnosticType: "bounded-deep-scan",
    filePath: file.displayPath,
    line: 1,
    invalidatesRun: false,
    message: `path=${file.displayPath}; lines=${lines}; bytes=${bytes}; maxLines=${budget.maxLines}; maxBytes=${budget.maxBytes}; override=${budget.override}. Text-level rules (size, sensitive-data, config) still ran; masking, block parsing, AST walking, and other deep script analysis were skipped.`,
  };
}

// Return whether script file belongs in the project index: production code, tests or source with possible import/export edges.
// Non-script files are excluded; the retained categories support exported-surface, test-coverage and graph rules.
function shouldRetainProjectSource(file: SourceFile, source: string): boolean {
  return file.isScript && (isProductionSourcePath(file.displayPath) || isTestPath(file.displayPath) || hasImportSyntaxCandidate(source));
}

// Return project-index data for file and raw source, including line views and a code-line count.
// Use parsed to exclude decorator text from the count. Without it, decorator-only lines count.
// Mask template bodies only for import candidates so template fixture text cannot become graph edges; otherwise reuse raw lines.
function projectSource(file: SourceFile, source: string, parsed?: ParsedScript): ProjectSource {
  const lines = source.split(/\r?\n/);
  const templateMaskedLines = hasImportSyntaxCandidate(source) ? maskTemplateLiteralBodies(source).split(/\r?\n/) : lines;
  return { file, lines, templateMaskedLines, codeLineCount: codeLineFlags(source, parsed).filter(Boolean).length };
}

// Cheap prefilter for files that might contain real import/export edges or fixture strings that
// mention them. False positives are acceptable; false negatives would drop graph edges.
function hasImportSyntaxCandidate(source: string): boolean {
  return source.includes("import") || source.includes("from");
}

/**
 * Run the text pass first and preserve stable rule order. Generated sources skip documentation and naming findings to avoid noise.
 *
 * @param file - input path and script classification used by the rule passes
 * @param source - original file text to check and inspect for generated markers
 * @param config - selects rules and supplies their settings
 * @param isWithinDeepScanBudget - allows deeper rules for scripts small enough to scan
 * @param parsed - shared script parse when available for syntax-backed checks
 * @returns Enabled findings in emission order. Generated input retains eligible safety findings under the same filtering contract.
 */
function analyseSource(file: SourceFile, source: string, config: Config, isWithinDeepScanBudget: boolean, parsed?: ParsedScript): Finding[] {
  const findings: Finding[] = [];
  // Size and documentation rules share one comment scan so code-only line counts do not add a second pass.
  const comments = file.isScript && (ruleEnabled(config, "size.file-length") || isAnyRuleEnabled(config, COMMENT_QUALITY_RULE_IDS)) ? commentRecords(source) : [];
  analyseTextRules(file, source, comments, config, findings, parsed);
  if (file.isScript && isWithinDeepScanBudget) {
    analyseTypeScriptRules(file, source, comments, config, findings, parsed);
  }
  const isGenerated = isGeneratedSource(source);
  return findings.filter((finding) => ruleEnabled(config, finding.ruleId) && !(isGenerated && GENERATED_SKIPPED_PILLARS.has(finding.pillar)));
}

// D6 generated-surface policy: docs/naming findings are skipped for generated files because no
// maintainer authors that text; every other pillar (security, sensitive-data, size, complexity,
// test-quality...) still applies - a generated file can leak a real credential.
const GENERATED_SKIPPED_PILLARS = new Set<Pillar>(["documentation", "naming"]);

// Marker-based generated/copied classification over the file's opening lines. Deliberately
// requires an explicit marker rather than path hints - a `fixtures/` path alone must never change
// rule behaviour, and `classifyIgnore` in discovery.ts stays the only directory-level exclusion surface.
function isGeneratedSource(source: string): boolean {
  return source.split(/\r?\n/, 10).some((line) => /AUTO-?GENERATED|@generated\b|GENERATED FILE|Code generated|Generated by|DO NOT EDIT|Copied from/i.test(line));
}

/**
 * Run cross-file checks after per-file analysis. Root graph context keeps cycles through requested files visible while preserving report scope.
 * Unreadable files encountered while gathering root graph context are skipped so a scoped scan can continue.
 *
 * @param projectRoot - root for deciding and discovering circular-import context
 * @param options - requested scope and discovery settings for root context
 * @param scopedFiles - discovered files whose paths define which root cycles to keep
 * @param projectSources - scanned source snapshots for the scoped project index
 * @param config - enables cross-file rules and supplies their settings
 * @returns Cross-file findings under the scoped reporting contract, or an empty list if no pass runs or produces a finding.
 */
function analyseProjectIndex(projectRoot: string, options: AnalysisOptions, scopedFiles: SourceFile[], projectSources: ProjectSource[], config: Config): Finding[] {
  const shouldUseRootCircularContext = ruleEnabled(config, CIRCULAR_IMPORT_RULE_ID) && shouldBuildRootCircularContext(projectRoot, options, scopedFiles);
  const shouldUseScopedIndex = isAnyRuleEnabled(config, SCOPED_PROJECT_INDEX_RULE_IDS) || (ruleEnabled(config, CIRCULAR_IMPORT_RULE_ID) && !shouldUseRootCircularContext);
  if (!shouldUseScopedIndex && !shouldUseRootCircularContext) {
    return [];
  }
  const findings: Finding[] = [];
  if (shouldUseScopedIndex) {
    const index = buildProjectIndex(projectSources);
    analyseArchitectureRules(index, config, findings, { shouldSkipCircularImports: shouldUseRootCircularContext });
  }
  if (shouldUseRootCircularContext) {
    findings.push(...rootCircularImportFindings(projectRoot, options, scopedFiles, config));
  }
  return findings;
}

const PROJECT_INDEX_RULE_IDS = [
  CIRCULAR_IMPORT_RULE_ID,
  "design.large-module-concentration",
] as const;
const SCOPED_PROJECT_INDEX_RULE_IDS = [
  "design.large-module-concentration",
] as const;

// Return whether options' targets need extra graph context rooted at projectRoot to find cycles through scopedFiles.
// No scopedFiles, no explicit targets, or a target resolving to projectRoot means no extra scan.
function shouldBuildRootCircularContext(projectRoot: string, options: AnalysisOptions, scopedFiles: SourceFile[]): boolean {
  if (scopedFiles.length === 0 || options.paths.length === 0) {
    return false;
  }
  return options.paths.every((input) => displayPath(projectRoot, absolutize(projectRoot, input)) !== ".");
}

/**
 * Read root graph context so that a scoped scan can detect a cycle passing through files outside the request.
 *
 * @param projectRoot - root directory for graph discovery
 * @param options - discovery settings to keep while clearing the requested path operands
 * @param scopedFiles - requested files whose display paths qualify a cycle for the report
 * @param config - discovery and project-source settings for the root scan
 * @returns Stable circular-import findings touching a requested file, or an empty list if no cycle qualifies.
 */
function rootCircularImportFindings(projectRoot: string, options: AnalysisOptions, scopedFiles: SourceFile[], config: Config): Finding[] {
  const requestedFiles = new Set(scopedFiles.map((file) => file.displayPath));
  const rootDiscovery = discoverSources(projectRoot, { ...options, paths: [] }, config);
  const rootProjectSources = graphProjectSources(rootDiscovery.files, config);
  const findings: Finding[] = [];
  analyseCircularImportRule(buildProjectIndex(rootProjectSources), findings);
  return findings.filter((finding) => circularImportFindingTouchesRequestedFile(finding, requestedFiles));
}

// Read root-context candidates from files and return retained script snapshots that satisfy config's deep-scan budget.
// Unreadable or unprocessable candidates are skipped; the primary scoped scan owns requested-file diagnostics.
function graphProjectSources(files: SourceFile[], config: Config): ProjectSource[] {
  const projectSources: ProjectSource[] = [];
  for (const file of files) {
    try {
      const source = readFileSync(file.absolutePath, "utf8");
      if (!deepScanBudgetDiagnostic(file, source, config) && shouldRetainProjectSource(file, source)) {
        projectSources.push(projectSource(file, source));
      }
    } catch {
      // Root context is supplemental; the primary scan reports requested-file failures, so this pass adds no duplicate diagnostic.
    }
  }
  return projectSources;
}

// Returns whether a circular-import finding lists a requested display path among its cycle members.
// The scope contract falls back to the finding's path for a missing or non-array list. Empty arrays and non-string members never match.
function circularImportFindingTouchesRequestedFile(finding: Finding, requestedFiles: Set<string>): boolean {
  const files = Array.isArray(finding.metadata.files) ? finding.metadata.files : [finding.filePath];
  return files.some((file) => typeof file === "string" && requestedFiles.has(file));
}

const RULE_IDS_BY_PILLAR = ruleIdsByPillar();
const COMPLEXITY_RULE_IDS = ruleIdsForPillar("complexity");
const DEAD_CODE_RULE_IDS = ruleIdsForPillar("dead-code");
const DOCUMENTATION_RULE_IDS = ruleIdsForPillar("documentation");
const MAINTAINABILITY_RULE_IDS = ruleIdsForPillar("maintainability");
const MODERNISATION_RULE_IDS = ruleIdsForPillar("modernisation");
const NAMING_RULE_IDS = ruleIdsForPillar("naming");
const SECURITY_RULE_IDS = ruleIdsForPillar("security");
const SENSITIVE_DATA_RULE_IDS = ruleIdsForPillar("sensitive-data");
const SIZE_RULE_IDS = ruleIdsForPillar("size");
const TEST_QUALITY_RULE_IDS = ruleIdsForPillar("test-quality");

const GITHUB_ACTIONS_RULE_IDS = [
  "security.github-actions-pull-request-target",
  "security.github-actions-remote-shell",
  "security.github-actions-secrets-in-pr",
  "security.github-actions-unpinned-action",
] as const;

const PROJECT_CONFIG_RULE_IDS = [
  "security.remote-install-script",
  "security.url-dependency",
  "waste.broad-runtime-version",
  "design.package-bin-missing",
  "design.package-bin-not-executable",
] as const;

// The size and complexity block rules, the only rules that also run on the measure-only callable forms.
const BLOCK_MEASURE_RULE_IDS = [
  "size.function-length",
  "size.parameter-count",
  "complexity.cyclomatic",
] as const;

const BLOCK_RULE_IDS = [
  ...BLOCK_MEASURE_RULE_IDS,
  "docs.missing-exported-function-doc",
  "docs.missing-internal-function-doc",
  "waste.useless-return",
] as const;

const PARAMETER_NAMING_RULE_IDS = [
  "naming.identifier-quality",
  "naming.short-variable",
] as const;

const DOCBLOCK_RULE_IDS = [
  "docs.missing-param-tag",
  "docs.missing-return-tag",
  "docs.stale-param-tag",
] as const;

// Every rule id `analyseCommentQualityRules` can emit - including `docs.fixture-purpose-missing`
// via `pushFixturePurposeFindings` - so the group gate never silences an enabled rule.
const COMMENT_QUALITY_RULE_IDS = [
  "docs.fixture-purpose-missing",
  "docs.missing-error-behavior-doc",
  "docs.missing-invariant-doc",
  "docs.missing-side-effect-doc",
  "docs.missing-why-for-complex-code",
  "docs.suppression-without-rationale",
  "docs.todo-without-tracking",
] as const;

const CLASS_RULE_IDS = [
  "docs.missing-public-doc",
  "naming.class-file-mismatch",
  "modernisation.readonly-property-candidate",
] as const;

const SECURITY_FLOW_RULE_IDS = [
  "security.dynamic-regexp",
  "security.open-redirect-candidate",
  "security.path-traversal-candidate",
  "security.ssrf-candidate",
  "security.unsafe-deserialization",
  "security.xxe-candidate",
] as const;

const LINE_RULE_IDS = [
  ...SECURITY_RULE_IDS,
  ...MAINTAINABILITY_RULE_IDS,
  ...MODERNISATION_RULE_IDS,
  ...NAMING_RULE_IDS,
];

const BLOCK_DEPENDENT_RULE_IDS = [
  ...BLOCK_RULE_IDS,
  ...PARAMETER_NAMING_RULE_IDS,
  ...TEST_QUALITY_RULE_IDS,
  ...COMMENT_QUALITY_RULE_IDS,
];

const TYPESCRIPT_RULE_IDS = [
  ...COMPLEXITY_RULE_IDS,
  ...DEAD_CODE_RULE_IDS,
  ...DOCUMENTATION_RULE_IDS,
  ...MAINTAINABILITY_RULE_IDS,
  ...MODERNISATION_RULE_IDS,
  ...NAMING_RULE_IDS,
  ...SECURITY_RULE_IDS,
  ...SIZE_RULE_IDS,
  ...TEST_QUALITY_RULE_IDS,
];

// Groups rule ids from the public catalogue once so broad pass gates stay aligned with profiles.
function ruleIdsByPillar(): ReadonlyMap<Pillar, readonly string[]> {
  const byPillar = new Map<Pillar, string[]>();
  for (const descriptor of ruleDescriptors()) {
    const ruleIds = byPillar.get(descriptor.pillar) ?? [];
    ruleIds.push(descriptor.ruleId);
    byPillar.set(descriptor.pillar, ruleIds);
  }
  return byPillar;
}

// Looks up a precomputed pillar group; missing groups are empty so callers can stay branch-free.
function ruleIdsForPillar(pillar: Pillar): readonly string[] {
  return RULE_IDS_BY_PILLAR.get(pillar) ?? [];
}

// Return whether any id in ruleIds is enabled by config, including profile and explicit overrides; an empty group returns false.
function isAnyRuleEnabled(config: Config, ruleIds: readonly string[]): boolean {
  return ruleIds.some((ruleId) => ruleEnabled(config, ruleId));
}

/**
 * Check source text before deeper script passes so that text inputs are covered too. Keep the rule order stable for tied findings.
 *
 * @param file - input path for findings and script classification for the size check
 * @param source - raw text to measure or check for sensitive data, workflow and configuration issues
 * @param comments - comment records used to count substantive script lines
 * @param config - enables checks and supplies the size threshold and severity
 * @param findings - caller's array to append results to
 * @param parsed - shared script parse used to exclude decorator text. Without it, decorator-only lines count.
 * @returns Nothing. Appends size findings when enabled and text findings from each group with at least one enabled rule.
 */
function analyseTextRules(file: SourceFile, source: string, comments: CommentRecord[], config: Config, findings: Finding[], parsed?: ParsedScript): void {
  // The file-length threshold applies to scripts because it measures code size. Other inputs still receive enabled text checks.
  // The size bands follow FAMILY-CONTRACT.md section 12 under Size and complexity findings in two bands.
  if (file.isScript && ruleEnabled(config, "size.file-length")) {
    const lines = substantiveLineCount(source, comments, parsed);
    const fileLengthThreshold = threshold(config, "size.file-length", 1000);
    if (lines > fileLengthThreshold) {
      const band = bandedFields(lines, fileLengthThreshold, ruleSeverity(config, "size.file-length", "error"), LOWER_BAND_FILE, SPLIT_FILE);
      findings.push(
        makeFinding({
          ruleId: "size.file-length",
          message: `File has ${lines} substantive lines, above the threshold of ${fileLengthThreshold}.`,
          filePath: file.displayPath,
          line: 1,
          severity: band.severity,
          pillar: "size",
          confidence: "high",
          remediation: band.remediation,
          metadata: { lines, threshold: fileLengthThreshold, limitBand: band.limitBand },
        }),
      );
    }
  }

  if (isAnyRuleEnabled(config, SENSITIVE_DATA_RULE_IDS)) {
    analyseSensitiveData(file, source, findings);
  }
  if (isAnyRuleEnabled(config, GITHUB_ACTIONS_RULE_IDS)) {
    analyseGithubActionsRules(file, source, findings);
  }
  if (isAnyRuleEnabled(config, PROJECT_CONFIG_RULE_IDS)) {
    analyseProjectConfigRules(file, source, findings);
  }
}

// Return the nonblank source line count after masking comments at their recorded spans. Skip any trimmed line that starts with #!.
// parsed enables masking decorator text. Without it, decorator-only lines count. String text otherwise counts. Empty source returns zero.
function substantiveLineCount(source: string, comments: CommentRecord[], parsed?: ParsedScript): number {
  const withoutComments = maskRecordedComments(source, comments);
  // Mask only the decorator spans so code sharing a line with a decorator still counts.
  // See FAMILY-CONTRACT.md section 12 under Code lines in every line count.
  const withoutDecorators = parsed ? maskDecorators(withoutComments, parsed) : withoutComments;
  return withoutDecorators
    .split(/\r?\n/)
    .filter((line) => isSubstantiveLine(line))
    .length;
}

// Replaces comment text with spaces while retaining newlines and UTF-16 offsets from CommentRecord.
function maskRecordedComments(source: string, comments: CommentRecord[]): string {
  let cursor = 0;
  let masked = "";
  for (const comment of comments) {
    const end = comment.kind === "block" ? Math.min(source.length, comment.endIndex + 1) : comment.endIndex;
    masked += source.slice(cursor, comment.startIndex);
    masked += source.slice(comment.startIndex, end).replace(/[^\r\n]/g, " ");
    cursor = end;
  }
  return masked + source.slice(cursor);
}

// A blank line and a `#!` interpreter line are free; a TypeScript private field such as `#count = 0;` still counts.
function isSubstantiveLine(line: string): boolean {
  const trimmed = line.trim();
  return trimmed !== "" && !trimmed.startsWith("#!");
}

// Return the logical line count of source without allocating a split array; empty source is one line and a trailing newline adds one.
function lineCount(source: string): number {
  let count = 1;
  for (let index = 0; index < source.length; index += 1) {
    if (source.charCodeAt(index) === 10) {
      count += 1;
    }
  }
  return count;
}

/**
 * Run enabled script checks in a stable order so that reports remain reproducible. Skip passes that require a parse when it is unavailable.
 *
 * @param file - script being checked and the path used in its findings
 * @param source - original script text used by lexical and text checks
 * @param comments - comment locations and text available to comment quality checks
 * @param config - selects rule passes and their settings
 * @param findings - caller's array to append script findings to
 * @param parsed - shared script parse when available for syntax-backed checks
 * @returns Nothing. Appends findings from enabled passes to the caller's array.
 */
function analyseTypeScriptRules(file: SourceFile, source: string, comments: CommentRecord[], config: Config, findings: Finding[], parsed?: ParsedScript): void {
  if (!isAnyRuleEnabled(config, TYPESCRIPT_RULE_IDS)) {
    return;
  }
  const codeSource = maskNonCode(source);
  const blocks = isAnyRuleEnabled(config, BLOCK_DEPENDENT_RULE_IDS) ? functionBlocks(source, codeSource, parsed) : [];
  runRulePass(config, "docs.missing-file-overview", () => analyseFileOverviewDoc(file, source, findings));
  analyseBlocks(file, source, codeSource, blocks, config, findings);
  runRulePass(config, "test-quality.duplicate-test-body", () => {
    if (parsed) {
      analyseDuplicateTestGroups(file, parsed, findings);
    }
  });
  // Callables only the size and complexity rules measure; the documentation and naming rules never see them.
  runRuleGroupPass(config, BLOCK_MEASURE_RULE_IDS, () => {
    if (parsed) {
      for (const block of measuredOnlyFunctionBlocks(source, codeSource, parsed)) {
        analyseBlockMeasures(blockRuleContext(file, block, config, findings));
      }
    }
  });
  runRulePass(config, "waste.unused-import", () => analyseUnusedImports(file, codeSource, source, findings));
  runRuleGroupPass(config, LINE_RULE_IDS, () => analyseLineRules(file, source, codeSource, config, findings, parsed));
  runRuleGroupPass(config, SECURITY_FLOW_RULE_IDS, () => analyseSecurityFlow(file, source, findings, parsed?.sourceFile));
  runRulePass(config, "waste.unreachable-code", () => analyseUnreachable(file, codeSource, findings));
  // Without a parse, skip docblock checks because they need reliable callable signatures.
  runRuleGroupPass(config, DOCBLOCK_RULE_IDS, () => {
    if (parsed) {
      analyseDocRules(file, findings, parsed, {
        isParamTagEveryCallable: optionBoolean(config, "docs.missing-param-tag", "everyCallable", true),
        isReturnTagEveryCallable: optionBoolean(config, "docs.missing-return-tag", "everyCallable", true),
      });
    }
  });
  runRulePass(config, "docs.missing-interface-doc", () => analyseInterfaceDocs(file, source, codeSource, findings));
  runRuleGroupPass(config, COMMENT_QUALITY_RULE_IDS, () => analyseCommentQualityRules({ file, source, codeSource, blocks, comments, config, findings }));
  runRuleGroupPass(config, CLASS_RULE_IDS, () => analyseClassRules(file, source, codeSource, config, findings, parsed));
  runRulePass(config, "dead-code.unused-private-method", () => analyseDeadCode(file, codeSource, findings));
}

// Returns nothing. Runs action, the pass for ruleId, only when config enables that rule.
function runRulePass(config: Config, ruleId: string, action: () => void): void {
  if (ruleEnabled(config, ruleId)) {
    action();
  }
}

// Returns nothing. Runs action for the group only when config enables at least one of the rules named by ruleIds.
function runRuleGroupPass(config: Config, ruleIds: readonly string[], action: () => void): void {
  if (isAnyRuleEnabled(config, ruleIds)) {
    action();
  }
}

/**
 * Dispatch enabled rules for each parsed callable. Keep emission order stable because the report sort can preserve it for tied findings.
 *
 * @param file - source file whose path identifies the findings
 * @param source - original source text for test checks
 * @param codeSource - source with comments and literals masked for test checks
 * @param blocks - parsed callables to check
 * @param config - selects enabled rule groups and their settings
 * @param findings - caller's array to append rule results to
 * @returns Nothing. Appends enabled block, parameter naming and test findings to the caller's array.
 */
function analyseBlocks(file: SourceFile, source: string, codeSource: string, blocks: FunctionBlock[], config: Config, findings: Finding[]): void {
  const shouldAnalyseBlockRules = isAnyRuleEnabled(config, BLOCK_RULE_IDS);
  const shouldAnalyseParameterNaming = isAnyRuleEnabled(config, PARAMETER_NAMING_RULE_IDS);
  const shouldAnalyseTestQuality = isAnyRuleEnabled(config, TEST_QUALITY_RULE_IDS);
  for (const block of blocks) {
    let context: BlockRuleContext | undefined;
    if (shouldAnalyseBlockRules) {
      context = blockRuleContext(file, block, config, findings);
      analyseBlockRules(context);
    }
    if (shouldAnalyseParameterNaming) {
      context ??= blockRuleContext(file, block, config, findings);
      pushParameterNamingFindings(context);
    }
    if (shouldAnalyseTestQuality && block.isTest) {
      analyseTestBlock(file, block, findings, { source, codeSource, startLine: 1 });
    }
  }
}

/**
 * The naming contract exempts local bindings, tests and recognized comparator pairs from short-name checks.
 * Placeholder checks still cover every parameter.
 *
 * @param context - callable and location to check, configured rules, and destination findings array
 * @returns Nothing. Appends applicable parameter-name findings to the caller's array.
 */
function pushParameterNamingFindings(context: BlockRuleContext): void {
  const line = context.block.declarationLine;
  const params = parameterNames(context.block.params);
  const hasLocallyBoundParameters = isLocallyBoundParameterOwner(context.block);
  for (const parameter of params) {
    if (!hasLocallyBoundParameters && !isComparatorShortParameter(context, params, parameter.name)) {
      pushShortVariableAt(context.file, line, parameter.name, context.config, context.findings, "parameter");
    }
    pushIdentifierQualityAt(context.file, line, parameter.name, context.config, context.findings, "parameter");
  }
}

// Return whether block is a test callback or non-exported const/let-bound callable, exempting its parameters from short-name checks.
// Exported bindings, declarations, methods and unrecognized binding syntax remain covered.
function isLocallyBoundParameterOwner(block: FunctionBlock): boolean {
  if (block.isTest) {
    return true;
  }
  // An exported binding is the cross-file API this exemption exists to keep covered, so
  // `export const transform = (x) => ...` is judged like `export function transform(x)`.
  if (block.isExported) {
    return false;
  }
  const declarationOffset = block.declarationLine - block.startLine;
  const declarationLine = block.codeBody.split(/\r?\n/)[declarationOffset] ?? "";
  const bindingName = declarationLine.match(/\b(?:const|let)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=/)?.[1];
  return bindingName === block.name;
}

// Return whether parameter name may use the conventional comparator exemption for the callable in context.
// params must contain exactly a then b, and the callable's name or body must match comparator heuristics.
function isComparatorShortParameter(context: BlockRuleContext, params: Array<{ name: string; raw: string }>, name: string): boolean {
  const names = params.map((parameter) => parameter.name);
  if (names.length !== 2 || names[0] !== "a" || names[1] !== "b" || (name !== "a" && name !== "b")) {
    return false;
  }
  return isComparatorCallable(context.block.name, context.block.codeBody);
}

// Return whether the callable name or codeBody matches comparator heuristics used to permit conventional short parameters.
// A dotted localeCompare matches with or without whitespace before the opening parenthesis, regardless of receiver or arguments.
function isComparatorCallable(name: string, codeBody: string): boolean {
  return (
    /^(?:compare[A-Z0-9_]?|.*Comparator$|by[A-Z])/.test(name) ||
    /\.localeCompare\s*\(/.test(codeBody) ||
    /\breturn\s+a\b[\s\S]*?(?:-\s*b\b|[<>]=?\s*b\b)/.test(codeBody) ||
    /\breturn\s+b\b[\s\S]*?(?:-\s*a\b|[<>]=?\s*a\b)/.test(codeBody)
  );
}
