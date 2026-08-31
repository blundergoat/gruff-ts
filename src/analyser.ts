// Analyser pipeline behind `gruff-ts analyse`, and the module the CLI shell calls into.
//
// It walks the discovered sources, runs every rule pass across the eleven pillars, and aggregates the
// results into native report state for the `gruff.analysis.v3` machine adapter to serialise.
import { Buffer, isUtf8 } from "node:buffer";
import { readFileSync, statSync } from "node:fs";
import { cwd } from "node:process";
import { basename, dirname, extname, resolve } from "node:path";
import { recordHistory, sortedUniqueFindings } from "./baseline.ts";
import { applyBaselineOptions, type BaselineApplication } from "./baseline-options.ts";
import { changedRegionScope, filterChangedFindings, filterScopedDiagnostics } from "./changed-regions.ts";
import { loadConfig, optionNumber, ruleEnabled, ruleSeverity, threshold } from "./config.ts";
import { partitionSensitiveExclusions } from "./sensitive-exclusions.ts";
import { VERSION } from "./constants.ts";
import { absolutize, discoverSources, displayPath, type SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import { applyConfiguredSeverity, finding, parameterNames } from "./findings-helpers.ts";
import { commentRecords, type CommentRecord } from "./comment-scanner.ts";
import { analyseArchitectureRules, analyseCircularImportRule, buildProjectIndex, CIRCULAR_IMPORT_RULE_ID, isProductionSourcePath, isTestPath, type ProjectSource } from "./project-rules.ts";
import { analyseBlockRules, type BlockRuleContext, blockRuleContext, type FunctionBlock, functionBlocks } from "./blocks.ts";
import { analyseClassRules, analyseAcronymCase, analyseInconsistentCasing, analyseInterfaceFields, collectDeclaredIdentifiers } from "./class-rules.ts";
import { analyseDeadCode, analyseUnreachable, analyseUnusedImports } from "./dead-code-rules.ts";
import { analyseCommentQualityRules } from "./comment-rules.ts";
import { analyseDocRules, analyseFileOverviewDoc, analyseInterfaceDocs } from "./doc-rules.ts";
import { analyseLineRules } from "./line-rules.ts";
import { analyseSecurityFlow } from "./security-flow-rules.ts";
import { pushBooleanPrefixAt, pushIdentifierQualityAt, pushNegativeBooleanAt, pushShortVariableAt } from "./naming-pushers.ts";
import { analyseTestBlock } from "./test-block-rules.ts";
import { analyseGithubActionsRules } from "./github-actions-rules.ts";
import { analyseProjectConfigRules } from "./project-config-rules.ts";
import { ruleDescriptors } from "./rules.ts";
import { scoreReport, summarize } from "./scoring.ts";
import { analyseSensitiveData } from "./sensitive-data-rules.ts";
import { parseScript, type ParsedScript } from "./parsed-script.ts";
import { maskNonCode, maskTemplateLiteralBodies } from "./source-text.ts";
import type { AnalysisOptions, AnalysisReport, Config, Finding, Pillar, RunDiagnostic, ScanSurfaceNote, SkippedPath, SuppressionSummary } from "./types.ts";

/*
 * Internal hook view contract: both reports come from one current-tree scan so full-file and
 * changed-region rendering stay stable and cannot drift.
 */
export interface HookAnalysisReports {
  currentReport: AnalysisReport;
  scopedReport: AnalysisReport;
}

/**
 * Analyse the configured paths and return the stable gruff.analysis.v3 report state.
 *
 * @param options Normalised analysis options from the CLI or direct callers.
 * @returns Versioned report with fingerprinted findings, diagnostics, paths, and score data.
 */
export function analyse(options: AnalysisOptions): AnalysisReport {
  const preparation = prepareAnalysis(options);
  const changedScope = changedRegionScope(options);
  const run = completeAnalysis(preparation, options);
  const changedResult = filterChangedFindings(run.baselineResult.findings, changedScope, run.scanned.sources);

  if (options.historyFile) {
    recordHistory(run.projectRoot, options.historyFile, changedResult.findings, run.diagnostics);
  }

  // File-scoped policy: diff runs report and fail on diagnostics from changed target files only.
  return reportFromRun({ ...run, diagnostics: filterScopedDiagnostics(run.diagnostics, changedScope) }, options, { ...run.baselineResult, findings: changedResult.findings }, changedResult.suppressedCount);
}

// Builds the hook's full and changed-region reports from one scan. The diff-base replay still uses
// the ordinary runner because it analyses different file contents.
export function analyseHookReports(currentOptions: AnalysisOptions, scopedOptions: AnalysisOptions, hasChangedRegion: boolean): HookAnalysisReports {
  const run = completeAnalysis(prepareAnalysis(currentOptions), currentOptions);
  const currentReport = reportFromRun(run, currentOptions, run.baselineResult);
  if (!hasChangedRegion) {
    return { currentReport, scopedReport: currentReport };
  }
  const scopedChangedScope = changedRegionScope(scopedOptions);
  const scopedChangedResult = filterChangedFindings(run.baselineResult.findings, scopedChangedScope, run.scanned.sources);
  // Same file-scoped diagnostics policy as diff-scoped analyse, so both surfaces agree.
  const scopedReport = reportFromRun({ ...run, diagnostics: filterScopedDiagnostics(run.diagnostics, scopedChangedScope) }, scopedOptions, { ...run.baselineResult, findings: scopedChangedResult.findings }, scopedChangedResult.suppressedCount);
  return { currentReport, scopedReport };
}

/**
 * Pick the directory that every reported path is written relative to.
 *
 * Run `gruff-ts analyse .` inside a project and the answer is that directory. Run `gruff-ts analyse /srv/checkout` from a
 * home directory, as CI and scripted scans do, and the answer is /srv/checkout, so findings still read as short project-relative
 * paths rather than absolute ones.
 *
 * @param paths Scan targets as typed on the command line; empty means no target was named, so the launch directory is the project.
 * @returns Directory to treat as the project root; never empty.
 * @throws When targets sit under different filesystem roots, such as `analyse /srv/api /opt/tools`, leaving no single project.
 */
function projectRootFromTargets(paths: string[]): string {
  const launchDirectory = cwd();

  // No target was named, so the directory the command ran from is the project.
  if (paths.length === 0) {
    return launchDirectory;
  }

  let common: string | null = null;
  // Each target narrows the answer: the root must be a directory that contains all of them.
  for (const path of paths) {
    const absolute = resolve(launchDirectory, path);
    let directory = absolute;
    try {
      // Naming one file means the project is the folder holding it, not the file itself.
      if (!statSync(absolute).isDirectory()) {
        directory = dirname(absolute);
      }
    } catch {
      // The caller named a path that does not exist, such as a typo; discovery reports it as missing instead.
      continue;
    }

    // The first target sets the starting answer; later ones can only widen it.
    if (common === null) {
      common = directory;
      continue;
    }
    while (!isSameOrDescendant(directory, common)) {
      const parent = dirname(common);
      // Walking up hit the filesystem root, so these targets live in unrelated projects.
      if (parent === common) {
        throw new Error("scan targets do not share a filesystem root");
      }
      common = parent;
    }
  }

  // Targets sit inside the launch directory, so it stays the root. Moving the root down to a target's own folder would
  // re-anchor config discovery, ignore patterns, and baseline paths.
  if (common === null || isSameOrDescendant(common, launchDirectory)) {
    return launchDirectory;
  }
  return common;
}

/**
 * Report whether one directory is another or sits inside it.
 *
 * Comparison is by whole path segment, so a sibling folder such as /work/apidocs is never mistaken for something inside /work/api.
 *
 * @param candidate Directory being tested.
 * @param ancestor Directory that may contain it.
 * @returns True when candidate is the ancestor or sits inside it.
 */
function isSameOrDescendant(candidate: string, ancestor: string): boolean {
  return candidate === ancestor || candidate.startsWith(ancestor.replace(/\/+$/u, "") + "/");
}

// Loads config and discovers inputs once so direct analysis and hook reuse share the same setup.
function prepareAnalysis(options: AnalysisOptions): AnalysisPreparation {
  const projectRoot = projectRootFromTargets(options.paths);
  const config = loadConfig(projectRoot, options);
  const diagnostics: RunDiagnostic[] = [];
  const discovery = discoverSources(projectRoot, options, config);
  return { projectRoot, config, diagnostics, discovery };
}

// Runs per-file and project-level rules before applying baseline suppression; finding order remains stable.
function completeAnalysis(preparation: AnalysisPreparation, options: AnalysisOptions): AnalysisRun {
  const { projectRoot, config, diagnostics, discovery } = preparation;
  pushMissingPathDiagnostics(discovery.missingPaths, diagnostics);

  const scanned = scanDiscoveredSources(discovery.files, config, diagnostics);
  const allFindings = sortedUniqueFindings([
    ...scanned.findings,
    ...analyseProjectIndex(projectRoot, options, discovery.files, scanned.projectSources, config).filter((finding) => ruleEnabled(config, finding.ruleId)),
  ].map((finding) => applyConfiguredSeverity(config, finding)));
  // Reviewed sensitive exclusions apply before the baseline so a suppressed finding never reaches
  // the report, the score, or the exit code, and each entry's count covers the whole scan.
  const excluded = partitionSensitiveExclusions(allFindings, config.sensitiveExclusions);
  const baselineResult = applyBaselineOptions(projectRoot, options, excluded.findings);
  const notes = [...discovery.notes, ...scanned.notes];
  return { projectRoot, discovery, diagnostics, scanned, baselineResult, notes, suppressions: excluded.suppressions };
}

/*
 * Converts a completed run into native report state, or into a changed-region projection when the caller passed `--diff`.
 *
 * The JSON adapter owns the stable `gruff.analysis.v3` wire shape.
 * `suppressions` carries one audit row per configured sensitive exclusion and is counted across the whole scan, so a
 * changed-region view never understates what a suppression hid.
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
      inputs: options.paths.length === 0 ? ["."] : [...options.paths],
      ...(options.config === undefined ? {} : { config: options.config }),
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
    findings,
    ...(suppressedCount === undefined ? {} : { suppressedCount }),
    score: scoreReport(findings),
    ...(baselineResult.baseline ? { baseline: baselineResult.baseline } : {}),
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
  baselineResult: BaselineApplication;
  notes: ScanSurfaceNote[];
  // One audit row per configured sensitive exclusion, counted over every finding the scan produced
  // so a changed-region projection cannot understate what a suppression actually hid.
  suppressions: SuppressionSummary[];
}

// Emits a `missing-path` diagnostic per path that the user requested but discovery could not
// resolve. Diagnostics force a non-zero exit (see `exitFor`); never throws - partial scans should still report.
function pushMissingPathDiagnostics(missingPaths: string[], diagnostics: RunDiagnostic[]): void {
  for (const missingPath of missingPaths) {
    diagnostics.push({
      diagnosticType: "missing-path",
      message: `Input path does not exist: ${missingPath}`,
      filePath: missingPath,
    });
  }
}

/*
 * Per-file read + scan loop. Reports read failures as diagnostics because CLI users need partial
 * results from the rest of the tree, but the stable discovered-file order still feeds project-index
 * snapshots before the final canonical sort. Changing that contract can churn graph-rule anchors.
 */
function scanDiscoveredSources(files: SourceFile[], config: Config, diagnostics: RunDiagnostic[]): SourceScanResult {
  const findings: Finding[] = [];
  const projectSources: ProjectSource[] = [];
  const sources = new Map<string, { file: SourceFile; source: string; parsed?: ParsedScript }>();
  const notes: ScanSurfaceNote[] = [];
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
      // One parse per script per run: every deep consumer shares this result; over-budget files skip it.
      const parsed = budgetDiagnostic ? undefined : parseScript(file, source);
      sources.set(file.displayPath, { file, source, ...(parsed ? { parsed } : {}) });
      if (budgetDiagnostic) {
        diagnostics.push(budgetDiagnostic);
      } else {
        if (shouldRetainProjectSource(file, source)) {
          projectSources.push(projectSource(file, source));
        }
        diagnostics.push(...(parsed?.diagnostics ?? []));
      }
      findings.push(...analyseSource(file, source, config, budgetDiagnostic === undefined, parsed));
    } catch (error) {
      diagnostics.push({
        diagnosticType: "read-error",
        message: `Unable to read file: ${String(error)}`,
        filePath: file.displayPath,
        line: 1,
      });
    }
  }
  return { findings, projectSources, sources, notes };
}

// Returns diagnostic metadata for a visible, non-fatal breach of either effective deep-scan bound.
// Source classification happens first, so config and other non-code text files never enter this guard.
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

// Retains production files for exported-surface checks, tests for central-suite import coverage,
// and import/export candidates for graph edges. Dropping any class here makes a project rule blind.
function shouldRetainProjectSource(file: SourceFile, source: string): boolean {
  return file.isScript && (isProductionSourcePath(file.displayPath) || isTestPath(file.displayPath) || hasImportSyntaxCandidate(source));
}

// Stores the raw line view and, only when needed, a template-masked line view. The conditional mask
// avoids paying lexer cost for files that cannot affect import edges while keeping fixtures invisible.
function projectSource(file: SourceFile, source: string): ProjectSource {
  const lines = source.split(/\r?\n/);
  const templateMaskedLines = hasImportSyntaxCandidate(source) ? maskTemplateLiteralBodies(source).split(/\r?\n/) : lines;
  return { file, lines, templateMaskedLines };
}

// Cheap prefilter for files that might contain real import/export edges or fixture strings that
// mention them. False positives are acceptable; false negatives would drop graph edges.
function hasImportSyntaxCandidate(source: string): boolean {
  return source.includes("import") || source.includes("from");
}

// Per-file rule pipeline, run once for every discovered file.
//
// - Text rules run on every file, including config and YAML; TypeScript rules run only on scripts inside the deep-scan budget.
// - The fixed rule order is part of the stable fingerprint contract, so baselines keep matching across runs.
// - Generated and copied files keep every security and sensitive-data finding, but drop documentation and naming ones:
//   nobody hand-wrote that code, so asking a reviewer to fix its docstrings is noise.
//
// Contract invariant: skipping docs and naming must never suppress a safety pillar or reorder rules.
function analyseSource(file: SourceFile, source: string, config: Config, isWithinDeepScanBudget: boolean, parsed?: ParsedScript): Finding[] {
  const findings: Finding[] = [];
  // Size and documentation rules share one comment scan so code-only line counts do not add a second pass.
  const comments = (ruleEnabled(config, "size.file-length") && usesCStyleComments(file)) || (file.isScript && isAnyRuleEnabled(config, COMMENT_QUALITY_RULE_IDS)) ? commentRecords(source) : [];
  analyseTextRules(file, source, comments, config, findings);
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
// rule behaviour, and `isDefaultIgnoredDir` stays the only directory-level exclusion surface.
function isGeneratedSource(source: string): boolean {
  return source.split(/\r?\n/, 10).some((line) => /AUTO-?GENERATED|@generated\b|GENERATED FILE|Code generated|Generated by|DO NOT EDIT|Copied from/i.test(line));
}

/*
 * Cross-file rule pipeline, run once after every file has been analysed on its own.
 *
 * Contract invariant: a scoped run keeps `paths.analysedFiles` scoped, while circular-import may still build root graph
 * context so a cycle passing through the requested files stays visible.
 *
 * Errors: `graphProjectSources` swallows a read failure on an unrelated root file, so one unreadable file elsewhere in the
 * project cannot fail a narrow scan. No other error is handled here.
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
  "design.deep-relative-import",
  CIRCULAR_IMPORT_RULE_ID,
  "design.large-module-concentration",
] as const;
const SCOPED_PROJECT_INDEX_RULE_IDS = [
  "design.deep-relative-import",
  "design.large-module-concentration",
] as const;

// Root graph context is needed only for narrow path operands; full-root scans already have context.
function shouldBuildRootCircularContext(projectRoot: string, options: AnalysisOptions, scopedFiles: SourceFile[]): boolean {
  if (scopedFiles.length === 0 || options.paths.length === 0) {
    return false;
  }
  return options.paths.every((input) => displayPath(projectRoot, absolutize(projectRoot, input)) !== ".");
}

// Builds stable circular-import findings from the repository root, then filters back to requested files.
function rootCircularImportFindings(projectRoot: string, options: AnalysisOptions, scopedFiles: SourceFile[], config: Config): Finding[] {
  const requestedFiles = new Set(scopedFiles.map((file) => file.displayPath));
  const rootDiscovery = discoverSources(projectRoot, { ...options, paths: [] }, config);
  const rootProjectSources = graphProjectSources(rootDiscovery.files, config);
  const findings: Finding[] = [];
  analyseCircularImportRule(buildProjectIndex(rootProjectSources), findings);
  return findings.filter((finding) => circularImportFindingTouchesRequestedFile(finding, requestedFiles));
}

// Reads just the root files needed for import graph context and swallows unrelated read failures.
function graphProjectSources(files: SourceFile[], config: Config): ProjectSource[] {
  const projectSources: ProjectSource[] = [];
  for (const file of files) {
    try {
      const source = readFileSync(file.absolutePath, "utf8");
      if (!deepScanBudgetDiagnostic(file, source, config) && shouldRetainProjectSource(file, source)) {
        projectSources.push(projectSource(file, source));
      }
    } catch {
      // ignore hidden root-context read failures; scoped scans still report requested-file errors.
    }
  }
  return projectSources;
}

// Contract filter: root-context circular findings survive only when the SCC contains a requested file.
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

/*
 * Sensitive-data rules that infer a secret from shape rather than value, which generated dependency metadata defeats.
 *
 * Every integrity digest looks high-entropy, and a package named `gtoken` turns `gtoken: 8.0.0(supports-color@11.0.0)`
 * into what reads as a credential assignment.
 * These are suppressed for lockfiles only; every value-shaped detector still runs there.
 */
const LOCKFILE_SUPPRESSED_SENSITIVE_RULE_IDS = new Set([
  "sensitive-data.high-entropy-string",
  "sensitive-data.hardcoded-env-value",
]);

const GITHUB_ACTIONS_RULE_IDS = [
  "security.github-actions-broad-permissions",
  "security.github-actions-pull-request-target",
  "security.github-actions-remote-shell",
  "security.github-actions-secrets-in-pr",
  "security.github-actions-unpinned-action",
] as const;

const PROJECT_CONFIG_RULE_IDS = [
  "security.remote-install-script",
  "security.risky-lifecycle-script",
  "security.url-dependency",
  "waste.broad-runtime-version",
  "design.package-bin-missing",
  "design.package-bin-not-executable",
] as const;

const BLOCK_RULE_IDS = [
  "size.function-length",
  "size.parameter-count",
  "complexity.cyclomatic",
  "complexity.cognitive",
  "naming.generic-function",
  "docs.missing-exported-function-doc",
  "docs.missing-internal-function-doc",
  "waste.empty-function",
  "waste.unused-parameter",
  "waste.redundant-variable",
  "waste.useless-return",
] as const;

const PARAMETER_NAMING_RULE_IDS = [
  "naming.boolean-prefix",
  "naming.generic-parameter",
  "naming.identifier-quality",
  "naming.negative-boolean",
  "naming.short-variable",
] as const;

const DOCBLOCK_RULE_IDS = [
  "docs.missing-param-tag",
  "docs.missing-return-tag",
  "docs.stale-param-tag",
  "docs.useless-docblock",
] as const;

const INTERFACE_FIELD_RULE_IDS = [
  "naming.boolean-prefix",
  "naming.negative-boolean",
] as const;

// Every rule id `analyseCommentQualityRules` can emit - including `docs.fixture-purpose-missing`
// via `pushFixturePurposeFindings` - so the group gate never silences an enabled rule.
const COMMENT_QUALITY_RULE_IDS = [
  "docs.fixture-purpose-missing",
  "docs.magic-threshold-without-rationale",
  "docs.missing-error-behavior-doc",
  "docs.missing-invariant-doc",
  "docs.missing-side-effect-doc",
  "docs.missing-why-for-complex-code",
  "docs.stale-comment",
  "docs.suppression-without-rationale",
  "docs.todo-without-tracking",
  "docs.useless-docblock",
] as const;

const CLASS_RULE_IDS = [
  "docs.missing-public-doc",
  "naming.class-file-mismatch",
  "modernisation.public-property",
  "modernisation.readonly-property-candidate",
] as const;

const IDENTIFIER_INVENTORY_RULE_IDS = [
  "naming.acronym-case",
  "naming.inconsistent-casing",
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
  ...IDENTIFIER_INVENTORY_RULE_IDS,
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

// Checks a rule-id group through the resolved config map so profiles and explicit overrides share one gate.
function isAnyRuleEnabled(config: Config, ruleIds: readonly string[]): boolean {
  return ruleIds.some((ruleId) => ruleEnabled(config, ruleId));
}

/*
 * Per-file text-pillar rules run before script-only rules because config, workflow, and
 * secret surfaces are not TypeScript. The order is a stable baseline contract: reshuffling these
 * checks changes same-line finding order for machine reports.
 */
function analyseTextRules(file: SourceFile, source: string, comments: CommentRecord[], config: Config, findings: Finding[]): void {
  if (ruleEnabled(config, "size.file-length") && !isGeneratedLockfile(file.displayPath)) {
    const lines = substantiveLineCount(file, source, comments);
    const fileLengthThreshold = threshold(config, "size.file-length", 1000);
    if (lines > fileLengthThreshold) {
      findings.push(
        makeFinding({
          ruleId: "size.file-length",
          message: `File has ${lines} substantive lines, above the threshold of ${fileLengthThreshold}.`,
          filePath: file.displayPath,
          line: 1,
          severity: ruleSeverity(config, "size.file-length", "error"),
          pillar: "size",
          confidence: "high",
          remediation: "Split unrelated responsibilities into smaller files. Or raise rules.size.file-length.threshold in .gruff-ts.yaml if the bound is wrong for this project.",
          metadata: { lines, threshold: fileLengthThreshold },
        }),
      );
    }
  }

  if (isAnyRuleEnabled(config, SENSITIVE_DATA_RULE_IDS)) {
    const sensitiveFindings: Finding[] = [];
    analyseSensitiveData(file, source, config, sensitiveFindings);
    // Generated dependency metadata defeats the two shape-based detectors, so they are dropped for lockfiles only.
    // The value-shaped detectors still run, because a credential inside a `resolved` URL is the real leak risk here.
    const isLockfile = isGeneratedLockfile(file.displayPath);
    for (const sensitiveFinding of sensitiveFindings) {
      if (!isLockfile || !LOCKFILE_SUPPRESSED_SENSITIVE_RULE_IDS.has(sensitiveFinding.ruleId)) {
        findings.push(sensitiveFinding);
      }
    }
  }
  if (isAnyRuleEnabled(config, GITHUB_ACTIONS_RULE_IDS)) {
    analyseGithubActionsRules(file, source, findings);
  }
  if (isAnyRuleEnabled(config, PROJECT_CONFIG_RULE_IDS)) {
    analyseProjectConfigRules(file, source, findings);
  }
}

// Counts nonblank lines after removing C-style and XML comments, then applies config-format
// full-line markers. Strings remain intact, so a line containing only a string literal still counts.
function substantiveLineCount(file: SourceFile, source: string, comments: CommentRecord[]): number {
  const withoutCStyleComments = maskRecordedComments(source, comments);
  const withoutComments = extname(file.displayPath).toLowerCase() === ".xml" ? maskXmlComments(withoutCStyleComments) : withoutCStyleComments;
  return withoutComments
    .split(/\r?\n/)
    .filter((line) => isSubstantiveLine(file, line))
    .length;
}

// C-style comments are valid on script/CSS surfaces and common in JSON-with-comments configs.
// Other supported text formats use their own full-line markers and must keep literal slash pairs.
function usesCStyleComments(file: SourceFile): boolean {
  const extension = extname(file.displayPath).toLowerCase();
  return file.isScript || extension === ".css" || extension === ".json";
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

// XML comments are outside the JavaScript lexer; preserving their newlines keeps line accounting stable.
function maskXmlComments(source: string): string {
  return source.replace(/<!--[\s\S]*?(?:-->|$)/g, (comment) => comment.replace(/[^\r\n]/g, " "));
}

// Hash and semicolon markers are restricted to formats where they are comments, so TypeScript
// private fields and ordinary semicolon statements remain substantive.
function isSubstantiveLine(file: SourceFile, line: string): boolean {
  const trimmed = line.trim();
  if (!trimmed) {
    return false;
  }
  const name = basename(file.displayPath).toLowerCase();
  const extension = extname(name);
  const usesHashComments = [".yaml", ".yml", ".toml"].includes(extension) || name === ".npmrc" || name.startsWith(".env");
  if ((usesHashComments || (file.isScript && trimmed.startsWith("#!"))) && trimmed.startsWith("#")) {
    return false;
  }
  const usesSemicolonComments = extension === ".ini" || name === ".npmrc";
  return !(usesSemicolonComments && trimmed.startsWith(";"));
}

// Counts the same logical lines as `source.split(/\r?\n/)` without allocating the full line array.
function lineCount(source: string): number {
  let count = 1;
  for (let index = 0; index < source.length; index += 1) {
    if (source.charCodeAt(index) === 10) {
      count += 1;
    }
  }
  return count;
}

// Package-manager lockfiles contain generated dependency metadata, including public integrity digests.
// Discovery retains them; `size.file-length` skips them outright and the sensitive-data pass uses this
// predicate to drop only `sensitive-data.high-entropy-string`, so lockfile credentials still report.
function isGeneratedLockfile(filePath: string): boolean {
  const fileName = basename(filePath);
  return fileName === "package-lock.json" || fileName === "npm-shrinkwrap.json" || fileName === "yarn.lock" || fileName === "pnpm-lock.yaml" || fileName === "bun.lockb";
}

/*
 * TypeScript-only rule pipeline. Masks comments and literals once, parses callable blocks once,
 * then walks every rule pack in a stable, deterministic order so reports and baselines remain reproducible.
 */
function analyseTypeScriptRules(file: SourceFile, source: string, comments: CommentRecord[], config: Config, findings: Finding[], parsed?: ParsedScript): void {
  if (!isAnyRuleEnabled(config, TYPESCRIPT_RULE_IDS)) {
    return;
  }
  const codeSource = maskNonCode(source);
  const blocks = isAnyRuleEnabled(config, BLOCK_DEPENDENT_RULE_IDS) ? functionBlocks(source, codeSource, parsed) : [];
  runRulePass(config, "docs.missing-file-overview", () => analyseFileOverviewDoc(file, source, findings));
  analyseBlocks(file, source, codeSource, blocks, config, findings);
  runRulePass(config, "waste.unused-import", () => analyseUnusedImports(file, codeSource, source, findings));
  runRuleGroupPass(config, LINE_RULE_IDS, () => analyseLineRules(file, source, codeSource, config, findings));
  runRuleGroupPass(config, SECURITY_FLOW_RULE_IDS, () => analyseSecurityFlow(file, source, findings, parsed?.sourceFile));
  runRulePass(config, "waste.unreachable-code", () => analyseUnreachable(file, codeSource, findings));
  // Docblock rules read real AST signatures; a bounded-deep-scan file without a parse skips them
  // like the other syntax-backed passes instead of falling back to a lossy regex walk.
  runRuleGroupPass(config, DOCBLOCK_RULE_IDS, () => {
    if (parsed) {
      analyseDocRules(file, findings, parsed);
    }
  });
  runRulePass(config, "docs.missing-interface-doc", () => analyseInterfaceDocs(file, source, codeSource, findings));
  runRuleGroupPass(config, INTERFACE_FIELD_RULE_IDS, () => analyseInterfaceFields(file, source, codeSource, config, findings));
  runRuleGroupPass(config, COMMENT_QUALITY_RULE_IDS, () => analyseCommentQualityRules({ file, source, codeSource, blocks, comments, config, findings }));
  runRuleGroupPass(config, CLASS_RULE_IDS, () => analyseClassRules(file, source, codeSource, config, findings, parsed));
  runRulePass(config, "dead-code.unused-private-method", () => analyseDeadCode(file, codeSource, findings));
  runRuleGroupPass(config, IDENTIFIER_INVENTORY_RULE_IDS, () => {
    // A normal deep script scan always supplies the shared parse; a missing result must not reparse.
    if (!parsed) {
      return;
    }
    const inventory = collectDeclaredIdentifiers(source, codeSource, parsed);
    runRulePass(config, "naming.inconsistent-casing", () => analyseInconsistentCasing(file, inventory, config, findings));
    runRulePass(config, "naming.acronym-case", () => analyseAcronymCase(file, inventory, config, findings));
  });
}

// Runs a single-rule pass only when that exact resolved rule id is enabled.
function runRulePass(config: Config, ruleId: string, action: () => void): void {
  if (ruleEnabled(config, ruleId)) {
    action();
  }
}

// Runs a shared pass only when at least one rule it can emit is enabled.
function runRuleGroupPass(config: Config, ruleIds: readonly string[], action: () => void): void {
  if (isAnyRuleEnabled(config, ruleIds)) {
    action();
  }
}

// One pass over the file's parsed callables.
//
// Naming and test-block fanouts are dispatched separately so `blocks.ts` stays independent of the naming-pusher and
// test-block-rule modules. The per-rule emission order from `analyseBlockRules` is the stable fingerprint contract every
// finding depends on for deterministic baseline matching.
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

/*
 * Per-parameter naming-rule fanout. Each parameter is checked for short-name / placeholder forms;
 * typed booleans get the extra prefix and negative-name checks. Reports findings to the shared sink.
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
    if (isBooleanParameter(parameter.raw)) {
      pushBooleanPrefixAt(context.file, line, parameter.name, context.config, context.findings, "parameter");
      pushNegativeBooleanAt(context.file, line, parameter.name, context.config, context.findings, "parameter");
    }
    if (isGenericParameterCandidate(context, params.length, parameter.name)) {
      pushGenericParameterAt(context.file, line, parameter.name, context.findings);
    }
  }
}

// Variable-bound callables and test callbacks keep their parameters beside the implementation,
// so short closure names do not create the cross-file review cost this rule is meant to surface.
// Declared functions and methods remain covered. Other parameter naming rules still run here.
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

// `(a, b)` is a conventional comparator pair when the callable is explicitly shaped like sorting.
// Keep the exemption narrow so arbitrary two-parameter helpers still need domain names.
function isComparatorShortParameter(context: BlockRuleContext, params: Array<{ name: string; raw: string }>, name: string): boolean {
  const names = params.map((parameter) => parameter.name);
  if (names.length !== 2 || names[0] !== "a" || names[1] !== "b" || (name !== "a" && name !== "b")) {
    return false;
  }
  return isComparatorCallable(context.block.name, context.block.codeBody);
}

// Comparator-shaped callables are either named for ordering (`compare*`, `*Comparator`, `byName`) or
// their body performs the standard locale/numeric ordering expression over both parameters.
function isComparatorCallable(name: string, codeBody: string): boolean {
  return (
    /^(?:compare[A-Z0-9_]?|.*Comparator$|by[A-Z])/.test(name) ||
    /\.localeCompare\s*\(/.test(codeBody) ||
    /\breturn\s+a\b[\s\S]*?(?:-\s*b\b|[<>]=?\s*b\b)/.test(codeBody) ||
    /\breturn\s+b\b[\s\S]*?(?:-\s*a\b|[<>]=?\s*a\b)/.test(codeBody)
  );
}

// Generic-parameter rule is context-gated: only fires when the surrounding function is itself
// large enough to deserve attention (long, complex, or many parameters). Keeps noise down on
// trivial helpers that legitimately accept a `value` argument.
function isGenericParameterCandidate(context: BlockRuleContext, paramCount: number, name: string): boolean {
  if (!context.config.placeholderNames.has(name.toLowerCase())) {
    return false;
  }
  const minParameters = optionNumber(context.config, "naming.generic-parameter", "minParameters", 3);
  const minLineCount = optionNumber(context.config, "naming.generic-parameter", "minLineCount", 30);
  const minCyclomatic = optionNumber(context.config, "naming.generic-parameter", "minCyclomatic", 8);
  return (
    paramCount >= minParameters ||
    context.block.lineCount >= minLineCount ||
    context.cyclomatic >= minCyclomatic
  );
}

// Only called after `isGenericParameterCandidate` has gated the placeholder check on the function's
// complexity and length - reaching this helper means the rule decided the finding is wanted.
// Reports the stable `naming.generic-parameter` finding.
function pushGenericParameterAt(file: SourceFile, line: number, name: string, findings: Finding[]): void {
  findings.push(
    makeFinding({
      ruleId: "naming.generic-parameter",
      message: `Parameter \`${name}\` uses a placeholder name in a function that meets context-gating thresholds.`,
      filePath: file.displayPath,
      line,
      severity: "advisory",
      pillar: "naming",
      confidence: "medium",
      symbol: name,
      remediation: "Use a name that describes the parameter's role.",
      metadata: { identifierName: name, surface: "parameter" },
    }),
  );
}

// Two positive cases: explicit `: boolean` annotation, or a default value of `true`/`false`.
// Explicit `as` casts are rejected so generic-call sites don't trip the boolean-name checks.
function isBooleanParameter(raw: string): boolean {
  if (/:\s*boolean\b/.test(raw)) {
    return true;
  }
  if (/\bas\b/.test(raw)) {
    return false;
  }
  return /=\s*(?:true|false)\s*$/.test(raw);
}
