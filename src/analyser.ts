// Analyser pipeline: walks discovered sources, runs every rule pass (complexity, dead-code, design,
// documentation, maintainability, modernisation, naming, security, sensitive-data, size, test-quality),
// aggregates findings into the `gruff.analysis.v2` schema, and exposes `analyse` to the CLI shell.
import { Buffer } from "node:buffer";
import { readFileSync } from "node:fs";
import { cwd } from "node:process";
import { basename } from "node:path";
import { dedupeFindings, recordHistory } from "./baseline.ts";
import { applyBaselineOptions, type BaselineApplication } from "./baseline-options.ts";
import { changedRegionScope, filterChangedFindings } from "./changed-regions.ts";
import { loadConfig, optionNumber, ruleEnabled, ruleSeverity, threshold } from "./config.ts";
import { VERSION } from "./constants.ts";
import { absolutize, discoverSources, displayPath, type SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import { finding } from "./findings-helpers.ts";
import { commentRecords } from "./comment-scanner.ts";
import { analyseArchitectureRules, analyseCircularImportRule, buildProjectIndex, CIRCULAR_IMPORT_RULE_ID, isProductionSourcePath, isTestPath, type ProjectSource } from "./project-rules.ts";
import { analyseBlockRules, type BlockRuleContext, blockRuleContext, type FunctionBlock, functionBlocks, parameterNames } from "./blocks.ts";
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
import { maskNonCode, maskTemplateLiteralBodies, parseDiagnostics } from "./source-text.ts";
import type { AnalysisOptions, AnalysisReport, Config, Finding, Pillar, RunDiagnostic, ScanSurfaceNote, SkippedPath } from "./types.ts";

/*
 * Internal hook view contract: both reports come from one current-tree scan so full-file and
 * changed-region rendering stay stable and cannot drift.
 */
export interface HookAnalysisReports {
  currentReport: AnalysisReport;
  scopedReport: AnalysisReport;
}

/**
 * Analyse the configured paths and return the stable gruff.analysis.v2 report contract.
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

  return reportFromRun(run, options, { ...run.baselineResult, findings: changedResult.findings }, changedResult.suppressedCount);
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
  const scopedReport = reportFromRun(run, scopedOptions, { ...run.baselineResult, findings: scopedChangedResult.findings }, scopedChangedResult.suppressedCount);
  return { currentReport, scopedReport };
}

// Loads config and discovers inputs once so direct analysis and hook reuse share the same setup.
function prepareAnalysis(options: AnalysisOptions): AnalysisPreparation {
  const projectRoot = cwd();
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
  ]);
  const baselineResult = applyBaselineOptions(projectRoot, options, allFindings);
  const notes = [...discovery.notes, ...scanned.notes];
  return { projectRoot, discovery, diagnostics, scanned, baselineResult, notes };
}

// Converts a completed run into a stable report contract or changed-region projection.
function reportFromRun(run: AnalysisRun, options: AnalysisOptions, baselineResult: BaselineApplication, suppressedCount?: number): AnalysisReport {
  return buildAnalysisReport(run.projectRoot, options, run.discovery, run.diagnostics, baselineResult, run.notes, suppressedCount);
}

function buildAnalysisReport(
  projectRoot: string,
  options: AnalysisOptions,
  discovery: DiscoverySummary,
  diagnostics: RunDiagnostic[],
  baselineResult: BaselineApplication,
  notes: ScanSurfaceNote[],
  suppressedCount?: number,
): AnalysisReport {
  const findings = baselineResult.findings;
  return {
    schemaVersion: "gruff.analysis.v2",
    tool: { name: "gruff-ts", version: VERSION },
    run: {
      projectRoot,
      format: options.format,
      failOn: options.failOn,
      generatedAt: new Date().toISOString(),
    },
    summary: summarize(findings),
    paths: {
      analysedFiles: discovery.files.length,
      ignoredPaths: discovery.ignoredPaths,
      skipped: discovery.skipped,
      missingPaths: discovery.missingPaths,
    },
    diagnostics,
    ...(notes.length === 0 ? {} : { notes }),
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
// Contract invariant: `notes` records bounded deep scans without changing finding order.
interface SourceScanResult {
  findings: Finding[];
  projectSources: ProjectSource[];
  sources: Map<string, { file: SourceFile; source: string }>;
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

// Completed scan state before final report rendering. The baseline result is carried separately so
// changed-region filtering can project findings without losing baseline metadata.
interface AnalysisRun {
  projectRoot: string;
  discovery: DiscoverySummary;
  diagnostics: RunDiagnostic[];
  scanned: SourceScanResult;
  baselineResult: BaselineApplication;
  notes: ScanSurfaceNote[];
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
  const sources = new Map<string, { file: SourceFile; source: string }>();
  const notes: ScanSurfaceNote[] = [];
  for (const file of files) {
    try {
      const source = readFileSync(file.absolutePath, "utf8");
      sources.set(file.displayPath, { file, source });
      const budgetNote = deepScanBudgetNote(file, source);
      if (budgetNote) {
        notes.push(budgetNote);
      } else {
        if (shouldRetainProjectSource(file, source)) {
          projectSources.push(projectSource(file, source));
        }
        diagnostics.push(...parseDiagnostics(file, source));
      }
      findings.push(...analyseSource(file, source, config, budgetNote === undefined));
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

// Scan budget for deep (masking, block-parsing, AST-walking) script analysis. Copied perf-test
// fixtures of 100k+ lines time out whole scans, so files above either bound keep text-level rules.
const DEEP_SCAN_MAX_LINES = 20_000; // Budget limit: bounds copied perf fixtures before deep passes.
const DEEP_SCAN_MAX_BYTES = 2_000_000; // Budget limit: catches minified/long-line scripts too.

// Returns the bounded-deep-scan note when a script file exceeds the budget, undefined otherwise.
// The file still counts as analysed - silence is the failure mode this guard exists to remove.
function deepScanBudgetNote(file: SourceFile, source: string): ScanSurfaceNote | undefined {
  if (!file.isScript) {
    return undefined;
  }
  const lines = lineCount(source);
  const bytes = Buffer.byteLength(source, "utf8");
  if (lines <= DEEP_SCAN_MAX_LINES && bytes <= DEEP_SCAN_MAX_BYTES) {
    return undefined;
  }
  return {
    noteType: "bounded-deep-scan",
    path: file.displayPath,
    message: `File exceeds the deep-scan budget (${lines} lines, ${bytes} bytes; limits ${DEEP_SCAN_MAX_LINES} lines / ${DEEP_SCAN_MAX_BYTES} bytes). Text-level rules (size, sensitive-data, config) still ran; deep script analysis was skipped.`,
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

// Canonical finding ordering: (filePath, line, ruleId, message). The same tuple is part of the
// stable baseline matching contract, so changing the comparator would churn every existing baseline.
function sortedUniqueFindings(findings: Finding[]): Finding[] {
  findings.sort(
    (left, right) =>
      left.filePath.localeCompare(right.filePath) ||
      (left.line ?? 0) - (right.line ?? 0) ||
      left.ruleId.localeCompare(right.ruleId) ||
      left.message.localeCompare(right.message),
  );
  return dedupeFindings(findings);
}

// Per-file rule pipeline. Text rules run on every file (including config/yaml); TypeScript rules
// run only on scripts within the deep-scan budget. Fixed order is part of the stable fingerprint
// contract. Generated/copied files keep every security and sensitive-data finding but drop
// documentation and naming findings - generated code is not maintainer-authored source, so pushing
// doc/naming work at a human reviewer is unactionable noise.
// Contract invariant: doc/naming skips must not suppress safety pillars or change rule order.
function analyseSource(file: SourceFile, source: string, config: Config, isWithinDeepScanBudget: boolean): Finding[] {
  const findings: Finding[] = [];
  analyseTextRules(file, source, config, findings);
  if (file.isScript && isWithinDeepScanBudget) {
    analyseTypeScriptRules(file, source, config, findings);
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
 * Cross-file rule pipeline. Contract invariant: scoped runs keep `paths.analysedFiles` scoped while
 * circular-import may build root graph context so cycles through requested files stay visible. It
 * swallows hidden root-context read failures in `graphProjectSources` so unrelated unreadable files
 * do not break a narrow scan.
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
  const rootProjectSources = graphProjectSources(rootDiscovery.files);
  const findings: Finding[] = [];
  analyseCircularImportRule(buildProjectIndex(rootProjectSources), findings);
  return findings.filter((finding) => circularImportFindingTouchesRequestedFile(finding, requestedFiles));
}

// Reads just the root files needed for import graph context and swallows unrelated read failures.
function graphProjectSources(files: SourceFile[]): ProjectSource[] {
  const projectSources: ProjectSource[] = [];
  for (const file of files) {
    try {
      const source = readFileSync(file.absolutePath, "utf8");
      if (!deepScanBudgetNote(file, source) && shouldRetainProjectSource(file, source)) {
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
function analyseTextRules(file: SourceFile, source: string, config: Config, findings: Finding[]): void {
  const lines = lineCount(source);
  if (ruleEnabled(config, "size.file-length") && !isGeneratedLockfile(file.displayPath)) {
    const fileLengthThreshold = threshold(config, "size.file-length", 750);
    if (lines > fileLengthThreshold) {
      findings.push(
        makeFinding({
          ruleId: "size.file-length",
          message: `File has ${lines} lines, above the threshold of ${fileLengthThreshold}.`,
          filePath: file.displayPath,
          line: 1,
          severity: ruleSeverity(config, "size.file-length", "warning"),
          pillar: "size",
          confidence: "high",
          remediation: "Split unrelated responsibilities into smaller files. Or raise rules.size.file-length.threshold in .gruff-ts.yaml if the bound is wrong for this project.",
          metadata: { lines, threshold: fileLengthThreshold },
        }),
      );
    }
  }

  if (isAnyRuleEnabled(config, SENSITIVE_DATA_RULE_IDS)) {
    analyseSensitiveData(file, source, config, findings);
  }
  if (isAnyRuleEnabled(config, GITHUB_ACTIONS_RULE_IDS)) {
    analyseGithubActionsRules(file, source, findings);
  }
  if (isAnyRuleEnabled(config, PROJECT_CONFIG_RULE_IDS)) {
    analyseProjectConfigRules(file, source, findings);
  }
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

// Exact-name match against the five major package managers. Lockfiles routinely break size and
// sensitive-data thresholds without being meaningful project code, so they get excluded by file rules.
function isGeneratedLockfile(path: string): boolean {
  const name = basename(path);
  return name === "package-lock.json" || name === "npm-shrinkwrap.json" || name === "yarn.lock" || name === "pnpm-lock.yaml" || name === "bun.lockb";
}

/*
 * TypeScript-only rule pipeline. Masks comments and literals once, parses callable blocks once,
 * then walks every rule pack in a stable, deterministic order so reports and baselines remain reproducible.
 */
function analyseTypeScriptRules(file: SourceFile, source: string, config: Config, findings: Finding[]): void {
  if (!isAnyRuleEnabled(config, TYPESCRIPT_RULE_IDS)) {
    return;
  }
  const codeSource = maskNonCode(source);
  const blocks = isAnyRuleEnabled(config, BLOCK_DEPENDENT_RULE_IDS) ? functionBlocks(source, codeSource) : [];
  runRulePass(config, "docs.missing-file-overview", () => analyseFileOverviewDoc(file, source, findings));
  analyseBlocks(file, source, codeSource, blocks, config, findings);
  runRulePass(config, "waste.unused-import", () => analyseUnusedImports(file, codeSource, source, findings));
  runRuleGroupPass(config, LINE_RULE_IDS, () => analyseLineRules(file, source, codeSource, config, findings));
  runRuleGroupPass(config, SECURITY_FLOW_RULE_IDS, () => analyseSecurityFlow(file, source, findings));
  runRulePass(config, "waste.unreachable-code", () => analyseUnreachable(file, codeSource, findings));
  runRuleGroupPass(config, DOCBLOCK_RULE_IDS, () => analyseDocRules(file, source, codeSource, findings));
  runRulePass(config, "docs.missing-interface-doc", () => analyseInterfaceDocs(file, source, codeSource, findings));
  runRuleGroupPass(config, INTERFACE_FIELD_RULE_IDS, () => analyseInterfaceFields(file, source, codeSource, config, findings));
  runRuleGroupPass(config, COMMENT_QUALITY_RULE_IDS, () => analyseCommentQualityRules({ file, source, codeSource, blocks, comments: commentRecords(source), config, findings }));
  runRuleGroupPass(config, CLASS_RULE_IDS, () => analyseClassRules(file, source, codeSource, findings));
  runRulePass(config, "dead-code.unused-private-method", () => analyseDeadCode(file, codeSource, findings));
  runRuleGroupPass(config, IDENTIFIER_INVENTORY_RULE_IDS, () => {
    const inventory = collectDeclaredIdentifiers(source, codeSource, blocks);
    runRulePass(config, "naming.inconsistent-casing", () => analyseInconsistentCasing(file, inventory, findings));
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

// One pass over the file's parsed callables. The naming and test-block fanouts are dispatched
// separately so blocks.ts can stay independent of the naming-pusher and test-block-rule modules;
// the per-rule emission order from `analyseBlockRules` is the stable fingerprint contract every
// Finding depends on for deterministic baseline matching.
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
  for (const parameter of params) {
    if (!isComparatorShortParameter(context, params, parameter.name)) {
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
