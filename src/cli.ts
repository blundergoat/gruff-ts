#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { argv, cwd } from "node:process";
import { basename, dirname as dirnamePath, extname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { applyBaseline, dedupeFindings, DEFAULT_BASELINE, recordHistory, writeBaseline } from "./baseline.ts";
import { buildProgram as buildCliProgram } from "./cli-program.ts";
import { isString, loadConfig, optionNumber, ruleEnabled, ruleSeverity, threshold } from "./config.ts";
import { VERSION } from "./constants.ts";
import { absolutize, discoverSources, displayPath, type SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import { analyseProjectConfigRules } from "./project-config-rules.ts";
import { renderReport } from "./report-renderers.ts";
import { scoreReport, summarize } from "./scoring.ts";
import { ruleDescriptors } from "./rules.ts";
import { analyseSensitiveData } from "./sensitive-data-rules.ts";
import { codeLineForMatching, maskNonCode, parseDiagnostics } from "./source-text.ts";
import { byteLine, countMatches, todoMarkerSummary } from "./text-scans.ts";
import type { AnalysisOptions, AnalysisReport, Config, Finding, OutputFormat, Pillar, RunDiagnostic, Severity } from "./types.ts";
export type { AnalysisReport, Finding, OutputFormat, Pillar, RuleDescriptor, Severity } from "./types.ts";

const NPATH_CAP = 1_000_000;
const FIXTURE_PURPOSE_MIN_LINES = 12;

// Read-once snapshot of a discovered file. Lines are cached because cross-file project rules
// scan each source repeatedly — splitting once amortises the cost across rule passes.
interface ProjectSource {
  file: SourceFile;
  source: string;
  lines: string[];
}

// Project-wide aggregate built once per scan and reused by every architecture rule (cycle detection,
// large-module concentration, deep-relative-import). `scriptSources` is a pre-filtered view of
// `sources` so per-rule code paths don't repeat the script-file check.
interface ProjectIndex {
  sources: ProjectSource[];
  scriptSources: ProjectSource[];
  sourcePaths: Set<string>;
  importsByFile: Map<string, ImportEdge[]>;
}

// One import statement in the graph. `parentSegments` counts `../` hops for the deep-relative-import
// rule; `targetPath` is set only when the specifier resolves to a file gruff has actually discovered.
interface ImportEdge {
  specifier: string;
  line: number;
  parentSegments: number;
  targetPath?: string;
}

// Ordered list of files participating in a cycle. Order is significant — the first edge is the
// anchor reported in the finding, so rotating the list would shift the finding's source line.
interface ImportCycle {
  files: string[];
}

// Resolved thresholds passed into the large-module-concentration check. Holding them together
// keeps the call surface narrow and prevents accidental field reorders.
interface LargeModuleThresholds {
  minFiles: number;
  minLines: number;
  maxSharePercent: number;
}

// One file's production line count, threaded through the large-module pipeline so the source
// reference survives sorting and filtering.
interface ModuleLineCount {
  source: ProjectSource;
  lines: number;
}

// Single struct holding the largest module + project totals + thresholds so the finding builder
// has every piece of metadata in one place.
interface LargeModuleCandidate extends ModuleLineCount {
  totalLines: number;
  sharePercent: number;
  thresholds: LargeModuleThresholds;
}

// Parsed callable body shared by every block-level rule (size, complexity, naming, docs). The
// `body` / `codeBody` split (raw text vs. comment-masked) lets rules choose between literal
// inspection and code-only matching without re-running the masker.
interface FunctionBlock {
  name: string;
  params: string;
  startLine: number;
  lineCount: number;
  body: string;
  codeBody: string;
  isPublic: boolean;
  isTest: boolean;
  hasLeadingComment: boolean;
  declarationLine: number;
}

// Working state for the function-block parser. Patterns are precompiled once per file so each
// callable detection doesn't re-instantiate the same RegExp objects.
interface FunctionBlockScan {
  lines: string[];
  codeLines: string[];
  patterns: RegExp[];
}

// Tiny lexer for finding the closing brace of a callable. `hasSeenOpen` matters because the depth
// counter would otherwise hit zero before the body ever opened (arrow functions with a default body).
interface FunctionBodyScanState {
  depth: number;
  hasSeenOpen: boolean;
}

// One comment block extracted by `commentRecords`. `endLine` differs from `line` for block
// comments; documentation rules need both to compute the gap between comment and declaration.
interface CommentRecord {
  kind: "line" | "block";
  text: string;
  line: number;
  endLine: number;
  startIndex: number;
  endIndex: number;
}

/** Tracks comment lexer state so string and regex contents are not treated as comments. */
interface CommentScanState {
  quote: string | undefined;
  isEscaped: boolean;
  isRegex: boolean;
  isRegexEscaped: boolean;
  isRegexCharClass: boolean;
  previousCode: string;
  line: number;
}

type CommentScanHandler = (source: string, index: number, state: CommentScanState, records: CommentRecord[]) => number | undefined;

// Generic declaration shape used by both function and interface comment-quality rules so they can
// share `pushStaleDeclarationCommentFinding` and `pushRestatingSignatureCommentFinding` logic.
interface CommentedDeclaration {
  kind: "function" | "interface";
  name: string;
  line: number;
  isPublic: boolean;
}

type CommentQualityRuleInput = {
  file: SourceFile;
  source: string;
  codeSource: string;
  blocks: FunctionBlock[];
  comments: CommentRecord[];
  config: Config;
  findings: Finding[];
};

type FunctionContextCommentQualityInput = {
  file: SourceFile;
  lines: string[];
  comments: CommentRecord[];
  blocks: FunctionBlock[];
  config: Config;
  findings: Finding[];
};

type ContextDocFindingDetails = {
  symbol: string;
  ruleId: string;
  message: string;
  remediation: string;
  metadata: Record<string, string>;
};

type ContextDocFindingInput = ContextDocFindingDetails & {
  file: SourceFile;
  comment: CommentRecord;
};

type MagicThresholdCandidate = {
  label: string;
  value: string;
  kind: string;
};

// A potential `docs.fixture-purpose-missing` finding location. `targetKind` distinguishes
// template fixtures from generated fixtures so the metadata stays useful for downstream tooling.
interface FixturePurposeCandidate {
  line: number;
  symbol: string;
  targetKind: string;
  lineCount: number;
}

// Provisional rule output gathered during a test-block walk. Built before the surrounding context
// (file, line) is known, then promoted into a real Finding by the caller.
interface TestBlockCheck {
  ruleId: string;
  message: string;
  severity: Severity;
}

// Precomputed inputs for every block-level rule. Computing cyclomatic / functionBody once and
// reusing the values keeps each rule's deterministic per-block work down to a single pattern test.
interface BlockRuleContext {
  file: SourceFile;
  block: FunctionBlock;
  config: Config;
  findings: Finding[];
  cyclomatic: number;
  functionBody: string;
}

// NPath approximation result. `capped: true` signals the value hit `NPATH_CAP` and is a lower
// bound — the finding message uses this to mark capped values rather than implying precision.
interface NpathResult {
  value: number;
  capped: boolean;
}

// Descriptor for one regex-backed line rule. `pattern` is the cheap test and `globalPattern`
// (optional) is used when the rule needs all matches for emission, not just the first hit.
interface LineRuleCheck {
  ruleId: string;
  pattern: RegExp;
  globalPattern?: RegExp;
  message: string;
  severity: Severity;
  pillar: Pillar;
}

/*
 * Per-line scratch state shared across every line rule in a single pass. `codeLine` is the
 * comment-masked variant — checks that must stay stable against literal content operate on it.
 */
interface LineRuleContext {
  file: SourceFile;
  line: string;
  codeLine: string;
  lineNumber: number;
  config: Config;
  findings: Finding[];
  codeChecks: LineRuleCheck[];
  literalChecks: LineRuleCheck[];
  variables: RegExp;
}

/**
 * Analyse the configured paths and return the stable gruff.analysis.v1 report contract.
 *
 * @param options Normalised analysis options from the CLI or direct callers.
 * @returns Versioned report with fingerprinted findings, diagnostics, paths, and score data.
 */
export function analyse(options: AnalysisOptions): AnalysisReport {
  const projectRoot = cwd();
  const config = loadConfig(projectRoot, options);
  const diagnostics: RunDiagnostic[] = [];
  const discovery = discoverSources(projectRoot, options, config);
  filterDiffSources(discovery, options);
  pushMissingPathDiagnostics(discovery.missingPaths, diagnostics);

  const scanned = scanDiscoveredSources(discovery.files, config, diagnostics);
  const allFindings = sortedUniqueFindings([
    ...scanned.findings,
    ...analyseProjectIndex(scanned.projectSources, config).filter((finding) => ruleEnabled(config, finding.ruleId)),
  ]);
  const baselineResult = applyBaselineOptions(projectRoot, options, allFindings);

  if (options.historyFile) {
    recordHistory(projectRoot, options.historyFile, baselineResult.findings, diagnostics);
  }

  return buildAnalysisReport(projectRoot, options, discovery, diagnostics, baselineResult);
}

function buildAnalysisReport(
  projectRoot: string,
  options: AnalysisOptions,
  discovery: DiscoverySummary,
  diagnostics: RunDiagnostic[],
  baselineResult: BaselineApplication,
): AnalysisReport {
  const findings = baselineResult.findings;
  return {
    schemaVersion: "gruff.analysis.v1",
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
      missingPaths: discovery.missingPaths,
    },
    diagnostics,
    findings,
    score: scoreReport(findings),
    ...(baselineResult.baseline ? { baseline: baselineResult.baseline } : {}),
  };
}

// Subset of discovery output that survives diff filtering. Held as its own type so the diff
// filter can mutate `files` in place without exposing the whole `SourceDiscoveryResult` shape.
interface DiscoverySummary {
  files: SourceFile[];
  ignoredPaths: string[];
  missingPaths: string[];
}

// Output of the per-file scan pass — both the findings produced and the cached source bodies that
// later project-level rules need to operate against the deterministic stable shape used by baselines.
interface SourceScanResult {
  findings: Finding[];
  projectSources: ProjectSource[];
}

/*
 * Result of applying a baseline (suppression) or generating a new one. The optional `baseline`
 * matches the `gruff.analysis.v1` schema's baseline metadata — present only when a baseline file
 * was actually used or generated, so the report stays stable across baseline-disabled runs.
 */
interface BaselineApplication {
  findings: Finding[];
  baseline?: NonNullable<AnalysisReport["baseline"]>;
}

// Resolved baseline path plus the provenance string emitted in the report. `source` distinguishes
// "explicit" (--baseline flag) from "default" (auto-discovered gruff-baseline.json).
interface BaselineSelection {
  path: string;
  source: string;
}

// Mutates `discovery.files` in place to retain only paths that changed against the diff base.
// Required when `--diff` is set so the scan does not waste time on unchanged files; no-op otherwise.
function filterDiffSources(discovery: DiscoverySummary, options: AnalysisOptions): void {
  if (!options.diff) {
    return;
  }
  const changed = changedFiles(options.diff);
  discovery.files = discovery.files.filter((file) => changed.has(file.displayPath));
}

// Emits a `missing-path` diagnostic per path that the user requested but discovery could not
// resolve. Diagnostics force a non-zero exit (see `exitFor`); never throws — partial scans should still report.
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
 * Per-file read + scan loop. Reports read failures as `read-error` diagnostics rather than throws
 * so one corrupt file cannot abort the whole run. Findings are accumulated in stable file order
 * so the downstream sort is the only place finding ordering becomes canonical.
 */
function scanDiscoveredSources(files: SourceFile[], config: Config, diagnostics: RunDiagnostic[]): SourceScanResult {
  const findings: Finding[] = [];
  const projectSources: ProjectSource[] = [];
  for (const file of files) {
    try {
      const source = readFileSync(file.absolutePath, "utf8");
      const lines = source.split(/\r?\n/);
      projectSources.push({ file, source, lines });
      diagnostics.push(...parseDiagnostics(file, source));
      findings.push(...analyseSource(file, source, config));
    } catch (error) {
      diagnostics.push({
        diagnosticType: "read-error",
        message: `Unable to read file: ${String(error)}`,
        filePath: file.displayPath,
        line: 1,
      });
    }
  }
  return { findings, projectSources };
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

/*
 * Three-way baseline dispatcher. `--generate-baseline` wins (writes a new file, returns findings
 * unchanged); `--no-baseline` skips entirely; otherwise look for an explicit or default baseline.
 * The stable identity tuple (fingerprint, ruleId, filePath) drives suppression matching.
 */
function applyBaselineOptions(projectRoot: string, options: AnalysisOptions, findings: Finding[]): BaselineApplication {
  if (options.generateBaseline) {
    return generateBaselineResult(projectRoot, options.generateBaseline, findings);
  }

  if (options.noBaseline) {
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
 * because generation does not filter findings — every current finding is captured in the stable baseline.
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
// project root. Returning undefined means "no baseline" — the stable contract preserves report shape.
function selectedBaseline(projectRoot: string, options: AnalysisOptions): BaselineSelection | undefined {
  if (options.baseline) {
    return { path: absolutize(projectRoot, options.baseline), source: "explicit" };
  }
  const defaultBaseline = join(projectRoot, DEFAULT_BASELINE);
  return existsSync(defaultBaseline) ? { path: defaultBaseline, source: "default" } : undefined;
}

// Per-file rule pipeline. Text rules run on every file (including config/yaml); TypeScript rules
// run only on scripts. Fixed order is part of the stable fingerprint contract.
function analyseSource(file: SourceFile, source: string, config: Config): Finding[] {
  const findings: Finding[] = [];
  analyseTextRules(file, source, config, findings);
  if (file.isScript) {
    analyseTypeScriptRules(file, source, config, findings);
  }
  return findings.filter((finding) => ruleEnabled(config, finding.ruleId));
}

// Cross-file rule pipeline that runs after every per-file scan completes. The index is built once
// and reused across architecture and test-adequacy rules to keep the stable, deterministic order.
function analyseProjectIndex(projectSources: ProjectSource[], config: Config): Finding[] {
  const index = buildProjectIndex(projectSources);
  const findings: Finding[] = [];
  analyseArchitectureRules(index, config, findings);
  analyseTestAdequacyRules(index, findings);
  return findings;
}

// Sorts sources by display path so every cross-file rule sees the same order regardless of which
// filesystem yielded what entries first — the stable input ordering is what keeps reports deterministic.
function buildProjectIndex(projectSources: ProjectSource[]): ProjectIndex {
  const sources = [...projectSources].sort((left, right) => left.file.displayPath.localeCompare(right.file.displayPath));
  const scriptSources = sources.filter((source) => source.file.isScript);
  const sourcePaths = new Set(scriptSources.map((source) => source.file.displayPath));
  const importsByFile = new Map<string, ImportEdge[]>();
  for (const source of scriptSources) {
    importsByFile.set(source.file.displayPath, importEdgesForSource(source, sourcePaths));
  }
  return { sources, scriptSources, sourcePaths, importsByFile };
}

// Three architecture rules, evaluated in their stable contract order: deep imports, cycles, then
// large-module concentration. Reordering shuffles the deterministic fingerprint output.
function analyseArchitectureRules(index: ProjectIndex, config: Config, findings: Finding[]): void {
  analyseDeepRelativeImports(index, config, findings);
  analyseCircularImports(index, findings);
  analyseLargeModuleConcentration(index, config, findings);
}

// Container for test-adequacy rules. Just one rule today; existing as a stable shape so additions
// inherit the same project-index contract without each touching the entry point.
function analyseTestAdequacyRules(index: ProjectIndex, findings: Finding[]): void {
  analyseMissingNearbyTests(index, findings);
}

/*
 * Reports imports that climb more than `maxParentSegments` `../` hops, anchored at the edge line
 * in the importing file. The double loop exists intentionally because `..` and `../foo` look
 * identical to a regex pass, so the parsed edge metadata is the only stable way to count depth
 * without false positives.
 */
function analyseDeepRelativeImports(index: ProjectIndex, config: Config, findings: Finding[]): void {
  const maxParentSegments = threshold(config, "design.deep-relative-import", 2);
  const severity = ruleSeverity(config, "design.deep-relative-import", "advisory");
  for (const source of index.scriptSources) {
    const edges = index.importsByFile.get(source.file.displayPath) ?? [];
    for (const edge of edges) {
      if (edge.parentSegments <= maxParentSegments) {
        continue;
      }
      findings.push(
        makeFinding({
          ruleId: "design.deep-relative-import",
          message: `Relative import \`${edge.specifier}\` climbs ${edge.parentSegments} directories.`,
          filePath: source.file.displayPath,
          line: edge.line,
          severity,
          pillar: "design",
          confidence: "medium",
          symbol: edge.specifier,
          remediation: "Move the shared module closer to the caller or introduce a local barrel/module boundary.",
          metadata: { specifier: edge.specifier, parentSegments: edge.parentSegments, maxParentSegments },
        }),
      );
    }
  }
}

/*
 * Reports one finding per detected cycle. The cycle list comes back already deterministic from
 * `importCycles`, so the resulting fingerprints are reproducible across runs.
 */
function analyseCircularImports(index: ProjectIndex, findings: Finding[]): void {
  for (const cycle of importCycles(index)) {
    const finding = circularImportFinding(index, cycle);
    if (finding) {
      findings.push(finding);
    }
  }
}

/*
 * Anchors the finding at the first file in the cycle so the stable fingerprint and reported line
 * match across reruns. Returns undefined when the anchor file dropped out of the index.
 */
function circularImportFinding(index: ProjectIndex, cycle: ImportCycle): Finding | undefined {
  const anchorPath = cycle.files[0] ?? "";
  const anchorSource = index.scriptSources.find((source) => source.file.displayPath === anchorPath);
  if (!anchorSource) {
    return undefined;
  }
  return makeFinding({
    ruleId: "design.circular-import",
    message: `Import cycle detected among ${cycle.files.join(", ")}.`,
    filePath: anchorSource.file.displayPath,
    line: circularImportLine(index, anchorPath, cycle),
    severity: "warning",
    pillar: "design",
    confidence: "medium",
    symbol: cycle.files.join(" -> "),
    remediation: "Extract the shared contract or move one dependency behind an explicit boundary.",
    metadata: { files: cycle.files },
  });
}

// Finds the first import edge in the anchor file that points into another cycle member. Line 1
// fallback keeps finding metadata stable when no edge could be located on the parsed source.
function circularImportLine(index: ProjectIndex, anchorPath: string, cycle: ImportCycle): number {
  const anchorEdges = index.importsByFile.get(anchorPath) ?? [];
  return anchorEdges.find((edge) => edge.targetPath && cycle.files.includes(edge.targetPath))?.line ?? 1;
}

/*
 * Reports the largest directory if it crosses the configured share-of-project threshold. Single
 * stable finding (the worst case) rather than one per directory — keeps the rule a noise-tolerant signal.
 */
function analyseLargeModuleConcentration(index: ProjectIndex, config: Config, findings: Finding[]): void {
  const candidate = largeModuleCandidate(index, largeModuleThresholds(config));
  if (!candidate) {
    return;
  }
  findings.push(largeModuleConcentrationFinding(candidate, ruleSeverity(config, "design.large-module-concentration", "advisory")));
}

// Three thresholds drive the rule: minimum file count to consider a project worth checking,
// minimum line count for the largest directory, and a share-percent cap. All three must hold.
function largeModuleThresholds(config: Config): LargeModuleThresholds {
  return {
    minFiles: optionNumber(config, "design.large-module-concentration", "minFiles", 4),
    minLines: optionNumber(config, "design.large-module-concentration", "minLines", 80),
    maxSharePercent: threshold(config, "design.large-module-concentration", 55),
  };
}

// Finds the directory with the most production lines and returns it only if it crosses every
// threshold. Returns undefined when the project is too small or the largest module is below the cap.
function largeModuleCandidate(index: ProjectIndex, thresholds: LargeModuleThresholds): LargeModuleCandidate | undefined {
  const modules = productionModuleLineCounts(index);
  if (modules.length < thresholds.minFiles) {
    return undefined;
  }
  const totalLines = modules.reduce((sum, module) => sum + module.lines, 0);
  const largest = modules[0];
  if (!largest) {
    return undefined;
  }
  if (totalLines === 0) {
    return undefined;
  }
  const sharePercent = Math.round((largest.lines / totalLines) * 1000) / 10;
  if (!exceedsLargeModuleThresholds(largest, sharePercent, thresholds)) {
    return undefined;
  }
  return { ...largest, totalLines, sharePercent, thresholds };
}

// Both conditions are required: a small but proportionally dominant module is still suspicious,
// but a tiny single-file project shouldn't trip the rule just by having one module.
function exceedsLargeModuleThresholds(largest: ModuleLineCount, sharePercent: number, thresholds: LargeModuleThresholds): boolean {
  return largest.lines >= thresholds.minLines && sharePercent > thresholds.maxSharePercent;
}

// Counts only production sources (tests, fixtures, declarations excluded) sorted by descending
// line count so the caller can take the head without re-scanning — keeps the rule deterministic and stable.
function productionModuleLineCounts(index: ProjectIndex): ModuleLineCount[] {
  return index.scriptSources
    .filter((source) => isProductionSourcePath(source.file.displayPath))
    .map((source) => ({ source, lines: source.lines.length }))
    .sort((left, right) => right.lines - left.lines || left.source.file.displayPath.localeCompare(right.source.file.displayPath));
}

// Single makeFinding site for the rule. All threshold values are surfaced in metadata so reviewers
// can see why the rule fired without re-running with the same config — keeps reports stable for audits.
function largeModuleConcentrationFinding(candidate: LargeModuleCandidate, severity: Severity): Finding {
  return makeFinding({
    ruleId: "design.large-module-concentration",
    message: `Module \`${candidate.source.file.displayPath}\` contains ${candidate.sharePercent}% of production source lines.`,
    filePath: candidate.source.file.displayPath,
    line: 1,
    severity,
    pillar: "design",
    confidence: "medium",
    symbol: fileBaseName(candidate.source.file.displayPath),
    remediation: "Split unrelated responsibilities into smaller modules once stable seams are visible.",
    metadata: {
      lines: candidate.lines,
      totalLines: candidate.totalLines,
      sharePercent: candidate.sharePercent,
      minFiles: candidate.thresholds.minFiles,
      minLines: candidate.thresholds.minLines,
      maxSharePercent: candidate.thresholds.maxSharePercent,
    },
  });
}

// Per-file regex pass over the cached source lines. The resulting edges are sorted by (line,
// specifier) so the import graph and cycle detection both see the same stable, deterministic order.
function importEdgesForSource(source: ProjectSource, sourcePaths: Set<string>): ImportEdge[] {
  const edges: ImportEdge[] = [];
  for (const [index, line] of source.lines.entries()) {
    edges.push(...importEdgesForLine(source.file.displayPath, line, index + 1, sourcePaths));
  }
  return edges.sort((left, right) => left.line - right.line || left.specifier.localeCompare(right.specifier));
}

// Single line may contain multiple imports (e.g., `import a;export b from 'x'`); the regex
// captures every `from "specifier"` form. Non-relative specifiers are dropped because the rule
// only cares about intra-project edges.
function importEdgesForLine(importerPath: string, lineSource: string, line: number, sourcePaths: Set<string>): ImportEdge[] {
  const edges: ImportEdge[] = [];
  for (const match of lineSource.matchAll(/\b(?:import|export)\b(?:[^"'`]*?\bfrom\s*)?\s*["']([^"']+)["']/g)) {
    const edge = importEdgeForSpecifier(importerPath, match[1] ?? "", line, sourcePaths);
    if (edge) {
      edges.push(edge);
    }
  }
  return edges;
}

// Builds an edge with `parentSegments` (counted from `..` hops) and an optional `targetPath` that
// points to a file gruff has actually discovered. Used by both the cycle detector and the deep-import rule.
function importEdgeForSpecifier(importerPath: string, specifier: string, line: number, sourcePaths: Set<string>): ImportEdge | undefined {
  if (!specifier.startsWith(".")) {
    return undefined;
  }
  const targetPath = resolveRelativeImport(importerPath, specifier, sourcePaths);
  return {
    specifier,
    line,
    parentSegments: specifier.split("/").filter((segment) => segment === "..").length,
    ...(targetPath ? { targetPath } : {}),
  };
}

// Tries every extension / barrel form (see `importPathCandidates`). The first match wins because
// Node's resolution is deterministic and a stable choice keeps cycle output reproducible.
function resolveRelativeImport(importerPath: string, specifier: string, sourcePaths: Set<string>): string | undefined {
  const basePath = normalizeDisplayPath(join(dirnamePath(importerPath), specifier));
  for (const candidate of importPathCandidates(basePath)) {
    if (sourcePaths.has(candidate)) {
      return candidate;
    }
  }
  return undefined;
}

// Generates every plausible filename for the import: the bare path, each script extension, and
// `index.<ext>` variants. Set-deduplication keeps the candidate list small for the resolver loop.
function importPathCandidates(basePath: string): string[] {
  const extensions = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"];
  const candidates = new Set<string>();
  if (extname(basePath)) {
    candidates.add(basePath);
    const withoutExtension = basePath.slice(0, -extname(basePath).length);
    for (const extension of extensions) {
      candidates.add(`${withoutExtension}${extension}`);
    }
  } else {
    for (const extension of extensions) {
      candidates.add(`${basePath}${extension}`);
      candidates.add(`${basePath}/index${extension}`);
    }
  }
  return [...candidates].map(normalizeDisplayPath);
}

// DFS over the import graph. Path length capped at 12 (see `visitImportCycle`) because beyond that
// cycle detection becomes a search problem, not a useful signal. Output is sorted so report
// ordering stays deterministic across runs.
function importCycles(index: ProjectIndex): ImportCycle[] {
  const cycles = new Map<string, string[]>();
  const paths = [...index.importsByFile.keys()].sort();
  for (const start of paths) {
    visitImportCycle(index, start, start, [start], new Set([start]), cycles);
  }
  return [...cycles.values()]
    .map((files) => ({ files }))
    .sort((left, right) => left.files.join("\0").localeCompare(right.files.join("\0")));
}

function visitImportCycle(
  index: ProjectIndex,
  start: string,
  current: string,
  path: string[],
  seen: Set<string>,
  cycles: Map<string, string[]>,
): void {
  const targets = [...new Set((index.importsByFile.get(current) ?? []).map((edge) => edge.targetPath).filter(isString))].sort();
  for (const target of targets) {
    if (target === start && path.length > 1) {
      const files = [...path].sort();
      cycles.set(files.join("\0"), files);
      continue;
    }
    if (seen.has(target) || path.length >= 12) {
      continue;
    }
    seen.add(target);
    visitImportCycle(index, start, target, [...path, target], seen, cycles);
    seen.delete(target);
  }
}

// Production = not a test, not a `.d.ts`, not a fixture, not under `generated/`. Conservative on
// purpose — adding a path category here changes the rule surface of every production-only rule.
function isProductionSourcePath(path: string): boolean {
  return !isTestPath(path) && !isDeclarationPath(path) && !isFixtureLikePath(path) && !path.split("/").includes("generated");
}

/*
 * Reports exported callables whose file has no neighbouring `.test.ts` / `.spec.ts`. The stable
 * neighbour rules (`hasNearbyTest`) define what counts — false positives are likelier than missed
 * cases, so the rule is intentionally conservative.
 */
function analyseMissingNearbyTests(index: ProjectIndex, findings: Finding[]): void {
  const testPaths = new Set(index.scriptSources.filter((source) => isTestPath(source.file.displayPath)).map((source) => source.file.displayPath));
  for (const source of index.scriptSources.filter((candidate) => isProductionSourcePath(candidate.file.displayPath))) {
    const exported = exportedSurface(source.source);
    if (!exported || hasNearbyTest(source.file.displayPath, testPaths)) {
      continue;
    }
    findings.push(
      makeFinding({
        ruleId: "test-quality.missing-nearby-test",
        message: `Exported source file \`${source.file.displayPath}\` has no nearby test file.`,
        filePath: source.file.displayPath,
        line: exported.line,
        severity: "advisory",
        pillar: "test-quality",
        confidence: "medium",
        symbol: exported.symbol,
        remediation: "Add a focused test beside the source file or under a nearby __tests__/tests directory.",
        metadata: { expectedTestBase: fileBaseName(source.file.displayPath) },
      }),
    );
  }
}

// Returns the first exported callable/value seen — one finding per file is sufficient because
// the rule's signal is "this file ships an API surface", not "every export is untested".
function exportedSurface(source: string): { symbol: string; line: number } | undefined {
  const match = source.match(/\bexport\s+(?:default\s+)?(?:async\s+)?(?:function|class|interface|type|enum|const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)/);
  if (!match?.[1]) {
    return undefined;
  }
  return { symbol: match[1], line: byteLine(source, match.index ?? 0) };
}

// True when a same-name test file exists alongside the source, in a sibling `__tests__`/`tests`
// directory, or anywhere under a top-level `test`/`tests` tree. Mirrors common project layouts;
// expanding this list widens what counts as "tested".
function hasNearbyTest(sourcePath: string, testPaths: Set<string>): boolean {
  const sourceBase = stripSourceExtension(sourcePath);
  const sourceName = basename(sourceBase);
  const sourceDir = displayDir(sourcePath);
  const nearbyDirs = new Set([sourceDir, joinDisplay(sourceDir, "__tests__"), joinDisplay(sourceDir, "tests"), "test", "tests"]);
  for (const testPath of testPaths) {
    const testBase = stripTestMarker(stripSourceExtension(testPath));
    if (basename(testBase) !== sourceName) {
      continue;
    }
    if (testBase === sourceBase || nearbyDirs.has(displayDir(testPath))) {
      return true;
    }
  }
  return false;
}

// Drops the trailing `.ts`/`.tsx`/`.js`/`.jsx`/`.mts`/`.cjs`/`.mjs` extension so source-and-test
// filename comparison is extension-agnostic. Used together with `stripTestMarker`.
function stripSourceExtension(path: string): string {
  return path.replace(/\.[cm]?[tj]sx?$/, "");
}

// Drops the conventional `.test` / `.spec` suffix before comparing a test path to a source path.
function stripTestMarker(path: string): string {
  return path.replace(/\.(?:test|spec)$/, "");
}

// Collapses a path's directory portion to the empty string at the project root so
// `hasNearbyTest`'s nearbyDirs lookup uses one canonical key for root-level files.
function displayDir(path: string): string {
  const dir = normalizeDisplayPath(dirnamePath(path));
  return dir === "." ? "" : dir;
}

// POSIX-style join that handles the empty-prefix case so `joinDisplay("", "x")` returns `"x"`,
// not `"/x"` — needed for paths that live directly at the project root.
function joinDisplay(left: string, right: string): string {
  return left ? `${left}/${right}` : right;
}

// `__tests__/` and `tests/` directories, plus `.test.ts` / `.spec.ts` filename suffix. The same
// patterns drive the production-source filter, so adding a layout here widens every test-aware rule.
function isTestPath(path: string): boolean {
  return /(?:^|\/)(?:__tests__|tests?|spec)\//.test(path) || /\.(?:test|spec)\.[cm]?[tj]sx?$/.test(path);
}

// `.d.ts` family. Declaration files don't carry runtime behaviour, so most rules skip them.
function isDeclarationPath(path: string): boolean {
  return /\.d\.[cm]?ts$/.test(path);
}

// Conventional fixture directories. Only `docs.fixture-purpose-missing` opts in to fixture paths;
// every other rule should treat them as test infrastructure.
function isFixtureLikePath(path: string): boolean {
  return /(?:^|\/)(?:__fixtures__|fixtures?|testdata)\//.test(path);
}

// Converts platform-native paths to the POSIX-style report shape used in every Finding. Must be
// idempotent — repeated normalisation must produce the same string.
function normalizeDisplayPath(path: string): string {
  return path.replaceAll("\\", "/").replace(/^\.\//, "");
}

/*
 * Per-file text-pillar rules: size, task-marker density, sensitive-data, project-config. The order
 * is the public stable contract — fingerprints are anchored on (filePath, line, ruleId) and
 * reshuffling the rule order would shift baselines unnecessarily. Reports findings via the shared
 * `findings.push` channel.
 */
function analyseTextRules(file: SourceFile, source: string, config: Config, findings: Finding[]): void {
  const lines = source.split(/\r?\n/).length;
  const fileLengthThreshold = threshold(config, "size.file-length", 750);
  if (!isGeneratedLockfile(file.displayPath)) {
    if (lines > fileLengthThreshold) {
      findings.push(finding({ ruleId: "size.file-length", message: `File has ${lines} lines, above the threshold of ${fileLengthThreshold}.`, file, line: 1, severity: ruleSeverity(config, "size.file-length", "warning"), pillar: "size" }));
    }
  }

  const todoMarkers = todoMarkerSummary(source, file.isScript);
  if (todoMarkers.count >= threshold(config, "docs.todo-density", 4)) {
    findings.push(finding({ ruleId: "docs.todo-density", message: `File contains ${todoMarkers.count} TODO/FIXME markers.`, file, line: todoMarkers.firstLine, severity: ruleSeverity(config, "docs.todo-density", "advisory"), pillar: "documentation" }));
  }

  analyseSensitiveData(file, source, config, findings);
  analyseProjectConfigRules(file, source, findings);
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
  const codeSource = maskNonCode(source);
  const blocks = functionBlocks(source, codeSource);
  const comments = commentRecords(source);
  analyseFileOverviewDoc(file, source, findings);
  analyseBlocks(file, blocks, config, findings);
  analyseLineRules(file, source, codeSource, config, findings);
  analyseDocRules(file, source, codeSource, findings);
  analyseInterfaceDocs(file, source, codeSource, findings);
  analyseInterfaceFields(file, source, codeSource, config, findings);
  analyseCommentQualityRules({ file, source, codeSource, blocks, comments, config, findings });
  analyseClassRules(file, source, codeSource, findings);
  analyseDeadCode(file, codeSource, findings);
  const inventory = collectDeclaredIdentifiers(source, codeSource, blocks);
  analyseInconsistentCasing(file, inventory, findings);
  analyseAcronymCase(file, inventory, config, findings);
}

// One identifier observation. `line` is the declaration line in the original source so the casing
// and acronym rules can report a stable, reproducible location.
interface DeclaredIdentifier {
  name: string;
  line: number;
}

// Aggregates `const`/`let`/`var` declarations, callable parameters, and interface fields into a
// single de-duplicated list. The naming rules walk this once instead of re-parsing the file.
function collectDeclaredIdentifiers(source: string, codeSource: string, blocks: FunctionBlock[]): DeclaredIdentifier[] {
  const inventory: DeclaredIdentifier[] = [];
  const seen = new Set<string>();
  const push = (name: string, line: number): void => {
    if (!name) return;
    const key = `${name}@${line}`;
    if (seen.has(key)) return;
    seen.add(key);
    inventory.push({ name, line });
  };

  for (const match of codeSource.matchAll(/\b(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)/g)) {
    push(match[1] ?? "", byteLine(source, match.index ?? 0));
  }
  for (const block of blocks) {
    for (const parameter of parameterNames(block.params)) {
      push(parameter.name, block.declarationLine);
    }
  }
  for (const fieldMatch of collectInterfaceFieldDeclarations(source, codeSource)) {
    push(fieldMatch.name, fieldMatch.line);
  }
  return inventory;
}

// Walks every interface body line and matches the field declaration regex. Used both for the
// naming inventory (above) and for the per-field interface rules (boolean prefix, abbreviation).
function collectInterfaceFieldDeclarations(source: string, codeSource: string): DeclaredIdentifier[] {
  const fieldRegex = /^[ \t]*(?:readonly\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\??\s*:/;
  const out: DeclaredIdentifier[] = [];
  for (const { lineIndex, sourceLine } of walkInterfaceBodyLines(source, codeSource)) {
    const name = sourceLine.match(fieldRegex)?.[1] ?? "";
    if (name) out.push({ name, line: lineIndex + 1 });
  }
  return out;
}

// Strips separators and digits so `userId`, `user_id`, and `userID` all collapse to `userid`.
// Two names sharing this key but differing in original form are the casing-drift signal.
function casingCanonicalKey(name: string): string {
  return name.toLowerCase().replace(/[_\-0-9]/g, "");
}

/*
 * Groups identifiers by their canonical key and reports the second-seen variant whenever two or
 * more spellings exist. The "second variant" anchor keeps the stable fingerprint on the diverging
 * identifier rather than the original — useful when the original form is the project convention.
 */
function analyseInconsistentCasing(file: SourceFile, inventory: DeclaredIdentifier[], findings: Finding[]): void {
  const groups = new Map<string, DeclaredIdentifier[]>();
  for (const entry of inventory) {
    const key = casingCanonicalKey(entry.name);
    if (!key) continue;
    const list = groups.get(key) ?? [];
    list.push(entry);
    groups.set(key, list);
  }
  for (const [, entries] of groups) {
    const surfaces = new Set(entries.map((entry) => entry.name));
    if (surfaces.size < 2) continue;
    const sorted = [...entries].sort((a, b) => a.line - b.line);
    const second = sorted.find((entry, index) => index > 0 && entry.name !== sorted[0]?.name);
    if (!second) continue;
    findings.push(
      makeFinding({
        ruleId: "naming.inconsistent-casing",
        message: `Identifier \`${second.name}\` shares a canonical key with \`${sorted[0]?.name}\` in the same file.`,
        filePath: file.displayPath,
        line: second.line,
        severity: "advisory",
        pillar: "naming",
        confidence: "medium",
        symbol: second.name,
        remediation: "Choose one form and use it consistently within the file.",
        metadata: { variants: [...surfaces].sort() },
      }),
    );
  }
}

// Splits camelCase, PascalCase, snake_case, and kebab-case into tokens. The regex preserves
// uppercase runs as a single token so the acronym detector sees `URL` and `url` as the same word.
function tokensForAcronymCheck(name: string): string[] {
  const split = name.split(/[_\-]+/).filter(Boolean);
  const tokens: string[] = [];
  for (const part of split) {
    const matches = part.match(/[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z0-9]+|[A-Z]+/g);
    if (matches) tokens.push(...matches);
    else tokens.push(part);
  }
  return tokens;
}

// Three-bucket classification used to detect when one project uses both `URL` and `Url` styles —
// the rule flags drift when two of the three buckets are seen for the same acronym in one file.
function acronymCaseClass(token: string): "upper" | "lower" | "title" {
  if (token === token.toUpperCase()) return "upper";
  if (token === token.toLowerCase()) return "lower";
  return "title";
}

/*
 * Reports when an acronym from `config.knownAcronyms` appears in two or more case forms in one
 * file. Like `analyseInconsistentCasing`, the finding anchors on the second occurrence so the
 * stable fingerprint sticks to the divergence rather than the established style.
 */
function analyseAcronymCase(file: SourceFile, inventory: DeclaredIdentifier[], config: Config, findings: Finding[]): void {
  const observed = new Map<string, Map<string, { name: string; line: number }>>();
  for (const entry of inventory) {
    for (const token of tokensForAcronymCheck(entry.name)) {
      const lower = token.toLowerCase();
      if (!config.knownAcronyms.has(lower)) continue;
      const cases = observed.get(lower) ?? new Map();
      const caseKey = acronymCaseClass(token);
      if (!cases.has(caseKey)) cases.set(caseKey, { name: entry.name, line: entry.line });
      observed.set(lower, cases);
    }
  }
  for (const [acronym, cases] of observed) {
    if (cases.size < 2) continue;
    const occurrences = [...cases.values()].sort((a, b) => a.line - b.line);
    const second = occurrences[1];
    if (!second) continue;
    findings.push(
      makeFinding({
        ruleId: "naming.acronym-case",
        message: `Acronym \`${acronym.toUpperCase()}\` appears in multiple cases in this file.`,
        filePath: file.displayPath,
        line: second.line,
        severity: "advisory",
        pillar: "naming",
        confidence: "medium",
        symbol: second.name,
        remediation: "Use one casing for each acronym throughout the file.",
        metadata: { acronym: acronym.toUpperCase(), variants: [...cases.keys()].sort() },
      }),
    );
  }
}

/*
 * Walks every interface field and runs three checks per field: abbreviation, boolean prefix,
 * negative boolean. The stable ordering matches `pushAbbreviationAt` → `pushBooleanPrefixAt` →
 * `pushNegativeBooleanAt` so multiple findings on one field surface in a deterministic sequence.
 */
function analyseInterfaceFields(file: SourceFile, source: string, codeSource: string, config: Config, findings: Finding[]): void {
  const fieldRegex = /^[ \t]*(?:readonly\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\??\s*:\s*([^;]+)/;
  for (const { lineIndex, sourceLine } of walkInterfaceBodyLines(source, codeSource)) {
    const match = sourceLine.match(fieldRegex);
    const name = match?.[1] ?? "";
    if (!name) continue;
    pushAbbreviationAt(file, lineIndex + 1, name, config, findings, "interface-field");
    if (/^\s*boolean\b/.test(match?.[2] ?? "")) {
      pushBooleanPrefixAt(file, lineIndex + 1, name, config, findings, "interface-field");
      pushNegativeBooleanAt(file, lineIndex + 1, name, config, findings, "interface-field");
    }
  }
}

const INTERFACE_HEADER_REGEX = /\b(?:export\s+)?(?:interface\s+[A-Za-z_$][A-Za-z0-9_$]*(?:\s*<[^>]*>)?(?:\s+extends\s+[^{]+)?|type\s+[A-Za-z_$][A-Za-z0-9_$]*(?:\s*<[^>]*>)?\s*=\s*)\s*\{/g;

function* walkInterfaceBodyLines(source: string, codeSource: string): Generator<{ lineIndex: number; sourceLine: string }> {
  const codeLines = codeSource.split(/\r?\n/);
  const sourceLines = source.split(/\r?\n/);
  for (const header of codeSource.matchAll(INTERFACE_HEADER_REGEX)) {
    const headerEnd = (header.index ?? 0) + header[0].length;
    if (codeSource.slice(headerEnd, headerEnd + 30).trimStart().startsWith("[")) {
      continue;
    }
    const headerLineIndex = byteLine(source, headerEnd - 1) - 1;
    const headerLine = codeLines[headerLineIndex] ?? "";
    let depth = 1 + countBraceChange(headerLine.slice(headerLine.lastIndexOf("{") + 1));
    for (let lineIndex = headerLineIndex + 1; depth > 0 && lineIndex < codeLines.length; lineIndex += 1) {
      const codeLine = codeLines[lineIndex] ?? "";
      if (depth === 1) {
        yield { lineIndex, sourceLine: sourceLines[lineIndex] ?? "" };
      }
      depth += countBraceChange(codeLine);
    }
  }
}

/*
 * Reports `naming.abbreviation` when the name is on `abbreviationDenylist` and not on the user's
 * `acceptedAbbreviations` allowlist. `surface` distinguishes parameter / variable / interface-field
 * — same stable rule contract, different metadata, so consumers can filter on origin.
 */
function pushAbbreviationAt(file: SourceFile, line: number, name: string, config: Config, findings: Finding[], surface: NamingSurface): void {
  if (config.rules.get("naming.abbreviation")?.enabled !== true) {
    return;
  }
  if (config.acceptedAbbreviations.has(name.toLowerCase())) {
    return;
  }
  if (!config.abbreviationDenylist.has(name.toLowerCase())) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "naming.abbreviation",
      message: `Identifier \`${name}\` uses an opaque abbreviation.`,
      filePath: file.displayPath,
      line,
      severity: "advisory",
      pillar: "naming",
      confidence: "medium",
      symbol: name,
      remediation: "Use the full domain term or add the abbreviation to allowlists.acceptedAbbreviations.",
      metadata: { identifierName: name, surface },
    }),
  );
}

// Net brace delta (`{` minus `}`) for a slice of text. Used by the function-block parser to track
// nesting depth without parsing the source twice.
function countBraceChange(text: string): number {
  let delta = 0;
  for (const character of text) {
    if (character === "{") {
      delta += 1;
    } else if (character === "}") {
      delta -= 1;
    }
  }
  return delta;
}

// One pass over the file's parsed callables. The per-block ordering is fixed (see `analyseBlockRules`)
// so the same block always emits the same stable, deterministic finding sequence across runs.
function analyseBlocks(file: SourceFile, blocks: FunctionBlock[], config: Config, findings: Finding[]): void {
  for (const block of blocks) {
    analyseBlockRules(blockRuleContext(file, block, config, findings));
  }
}

// Computes cyclomatic and function-body once and threads them through the per-block rule pipeline.
// Pre-computing here keeps each rule's per-block work to a single threshold comparison; the
// resulting struct is part of the stable rule-context contract every per-block helper consumes.
function blockRuleContext(file: SourceFile, block: FunctionBlock, config: Config, findings: Finding[]): BlockRuleContext {
  return {
    file,
    block,
    config,
    findings,
    cyclomatic: countMatches(block.codeBody, /\b(if|else if|switch|case|for|while|catch)\b|\?|&&|\|\|/g) + 1,
    functionBody: functionBodyContent(block.codeBody),
  };
}

/*
 * Per-block rule sequence. The ordering is the stable baseline contract — every block emits its
 * findings in this exact deterministic order, so reshuffling the call list churns fingerprints
 * even when no rule changes.
 */
function analyseBlockRules(context: BlockRuleContext): void {
  pushFunctionLengthFinding(context);
  pushParameterCountFinding(context);
  pushCyclomaticFinding(context);
  pushCognitiveFinding(context);
  pushNpathFinding(context);
  pushGodFunctionFinding(context);
  pushGenericFunctionFinding(context);
  pushMissingFunctionDocFinding(context);
  pushEmptyFunctionFinding(context);
  pushUnusedParameterFindings(context);
  pushParameterNamingFindings(context);
  pushRedundantVariableFindings(context);
  pushUselessReturnFindings(context);
  if (context.block.isTest) {
    analyseTestBlock(context.file, context.block, context.config, context.findings);
  }
}

/*
 * Per-parameter naming-rule fanout. Each parameter is checked for short-name / opaque-abbreviation
 * / placeholder forms; typed booleans get the extra prefix and negative-name checks. Reports findings
 * to the shared sink.
 */
function pushParameterNamingFindings(context: BlockRuleContext): void {
  const line = context.block.declarationLine;
  const params = parameterNames(context.block.params);
  for (const parameter of params) {
    pushShortVariableAt(context.file, line, parameter.name, context.config, context.findings, "parameter");
    pushIdentifierQualityAt(context.file, line, parameter.name, context.config, context.findings, "parameter");
    pushAbbreviationAt(context.file, line, parameter.name, context.config, context.findings, "parameter");
    if (isBooleanParameter(parameter.raw)) {
      pushBooleanPrefixAt(context.file, line, parameter.name, context.config, context.findings, "parameter");
      pushNegativeBooleanAt(context.file, line, parameter.name, context.config, context.findings, "parameter");
    }
    if (isGenericParameterCandidate(context, params.length, parameter.name)) {
      pushGenericParameterAt(context.file, line, parameter.name, context.findings);
    }
  }
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
// complexity and length — reaching this helper means the rule decided the finding is wanted.
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

// Default threshold 200, default severity `warning` — functions past that length are usually a
// maintenance signal, not a stylistic preference. Reports `size.function-length` when the block exceeds the limit.
function pushFunctionLengthFinding(context: BlockRuleContext): void {
  const functionLengthThreshold = threshold(context.config, "size.function-length", 200);
  if (context.block.lineCount > functionLengthThreshold) {
    context.findings.push(blockFinding({ ruleId: "size.function-length", message: `Function \`${context.block.name}\` has ${context.block.lineCount} lines, above the threshold of ${functionLengthThreshold}.`, file: context.file, block: context.block, severity: ruleSeverity(context.config, "size.function-length", "warning"), pillar: "size" }));
  }
}

// Default threshold 7. Comma-counts on `block.params` rather than parsing because the parser
// already validated the signature shape upstream. Reports `size.parameter-count` when exceeded.
function pushParameterCountFinding(context: BlockRuleContext): void {
  const params = context.block.params.split(",").map((value) => value.trim()).filter(Boolean).length;
  if (params > threshold(context.config, "size.parameter-count", 7)) {
    context.findings.push(blockFinding({ ruleId: "size.parameter-count", message: `Function \`${context.block.name}\` declares ${params} parameters.`, file: context.file, block: context.block, severity: ruleSeverity(context.config, "size.parameter-count", "warning"), pillar: "size" }));
  }
}

// Default threshold 15. Counts conditional keywords + boolean operators in the code body — see
// `blockRuleContext` for the pre-computed value. Reports `complexity.cyclomatic` when exceeded.
function pushCyclomaticFinding(context: BlockRuleContext): void {
  if (context.cyclomatic > threshold(context.config, "complexity.cyclomatic", 15)) {
    context.findings.push(blockFinding({ ruleId: "complexity.cyclomatic", message: `Function \`${context.block.name}\` has cyclomatic complexity ${context.cyclomatic}.`, file: context.file, block: context.block, severity: ruleSeverity(context.config, "complexity.cyclomatic", "warning"), pillar: "complexity" }));
  }
}

// Default threshold 15. Cognitive complexity is cyclomatic + max nesting depth — captures the
// "deeply nested" intuition pure cyclomatic misses. Reports `complexity.cognitive` when exceeded.
function pushCognitiveFinding(context: BlockRuleContext): void {
  const cognitive = context.cyclomatic + maxNestingDepth(context.block.codeBody);
  if (cognitive > threshold(context.config, "complexity.cognitive", 15)) {
    context.findings.push(blockFinding({ ruleId: "complexity.cognitive", message: `Function \`${context.block.name}\` has cognitive complexity ${cognitive}.`, file: context.file, block: context.block, severity: ruleSeverity(context.config, "complexity.cognitive", "warning"), pillar: "complexity" }));
  }
}

// Default threshold 200. NPath is the number of possible execution paths; the message marks
// `capped` when the calculation hit `NPATH_CAP` so reviewers know it's a lower bound. Reports `complexity.npath`.
function pushNpathFinding(context: BlockRuleContext): void {
  const npath = approximateNpath(context.functionBody);
  const npathThreshold = threshold(context.config, "complexity.npath", 200);
  if (npath.value > npathThreshold) {
    context.findings.push(npathFinding(context, npath, npathThreshold, ruleSeverity(context.config, "complexity.npath", "warning")));
  }
}

/*
 * Stable `complexity.npath` finding factory. `capped` and `cap` are surfaced in metadata so
 * downstream tooling can distinguish "5000" from "≥ NPATH_CAP" — both would render as the same
 * value otherwise.
 */
function npathFinding(context: BlockRuleContext, npath: NpathResult, thresholdValue: number, severity: Severity): Finding {
  return blockFindingWithMetadata({
    ruleId: "complexity.npath",
    message: `Function \`${context.block.name}\` has approximate NPath complexity ${npath.value} above the threshold of ${thresholdValue} (capped at ${NPATH_CAP}).`,
    file: context.file,
    block: context.block,
    severity,
    pillar: "complexity",
    metadata: { npath: npath.value, capped: npath.capped, cap: NPATH_CAP, threshold: thresholdValue },
  });
}

// Combined-shape rule: long (>45 lines) AND complex (cyclomatic >10). Thresholds are hard-coded
// because "god function" is a design heuristic, not a per-rule tunable. Reports `design.god-function`.
function pushGodFunctionFinding(context: BlockRuleContext): void {
  if (context.block.lineCount > 45 && context.cyclomatic > 10) {
    context.findings.push(blockFinding({ ruleId: "design.god-function", message: `Function \`${context.block.name}\` is both long and complex.`, file: context.file, block: context.block, severity: "warning", pillar: "design" }));
  }
}

// Names like `process`, `handle`, `run` from `config.bannedGenericNames`. The list is user-configurable;
// the rule body itself just consults the config. Reports `naming.generic-function`.
function pushGenericFunctionFinding(context: BlockRuleContext): void {
  if (isGenericName(context.block.name, context.config.bannedGenericNames)) {
    context.findings.push(blockFinding({ ruleId: "naming.generic-function", message: `Function \`${context.block.name}\` is too generic to explain intent.`, file: context.file, block: context.block, severity: "advisory", pillar: "naming" }));
  }
}

// Every non-test function must carry a leading comment. Test blocks are exempted because their
// `test("name", …)` description already documents intent. Reports `docs.missing-function-doc`.
function pushMissingFunctionDocFinding(context: BlockRuleContext): void {
  if (!context.block.isTest && !context.block.hasLeadingComment) {
    context.findings.push(blockFinding({ ruleId: "docs.missing-function-doc", message: `Function \`${context.block.name}\` is missing a leading maintainer comment.`, file: context.file, block: context.block, severity: "advisory", pillar: "documentation" }));
  }
}

// Empty bodies are sometimes intentional placeholders, hence the advisory severity rather than
// warning. Reports `waste.empty-function` when the body strips to whitespace/comments only.
function pushEmptyFunctionFinding(context: BlockRuleContext): void {
  if (isEmptyFunctionBody(context.block.codeBody)) {
    context.findings.push(blockFinding({ ruleId: "waste.empty-function", message: `Function \`${context.block.name}\` has no executable body.`, file: context.file, block: context.block, severity: "advisory", pillar: "waste" }));
  }
}

// `_`-prefixed parameters are exempted (the standard "intentionally unused" convention).
// Reports `waste.unused-parameter` for parameter names that never appear in the callable body.
function pushUnusedParameterFindings(context: BlockRuleContext): void {
  for (const parameter of parameterNames(context.block.params)) {
    if (!isUnusedParameter(context, parameter.name)) {
      continue;
    }
    context.findings.push(unusedParameterFinding(context, parameter.name));
  }
}

// Word-boundary regex against the masked function body. The body is masked so a parameter mentioned
// only in a string literal would still count as unused — that matches the intent of the rule.
function isUnusedParameter(context: BlockRuleContext, parameterName: string): boolean {
  return !parameterName.startsWith("_") && !new RegExp(`\\b${escapeRegex(parameterName)}\\b`).test(context.functionBody);
}

/*
 * Stable `waste.unused-parameter` finding shape. `block.startLine` is the anchor so the fingerprint
 * stays at the callable's declaration line, not at the parameter's column position.
 */
function unusedParameterFinding(context: BlockRuleContext, parameterName: string): Finding {
  return makeFinding({
    ruleId: "waste.unused-parameter",
    message: `Parameter \`${parameterName}\` does not appear to be used.`,
    filePath: context.file.displayPath,
    line: context.block.startLine,
    severity: "advisory",
    pillar: "waste",
    confidence: "medium",
    symbol: context.block.name,
    remediation: "Remove the parameter or prefix it with _ if it is intentionally unused.",
    metadata: { parameter: parameterName },
  });
}

// Targets `const x = expr; return x;` patterns. The detector walks the function source once and
// reports each variable whose only use is the trailing return as `waste.redundant-variable`.
function pushRedundantVariableFindings(context: BlockRuleContext): void {
  for (const redundant of redundantVariableReturns(context.block.codeBody)) {
    context.findings.push(
      makeFinding({
        ruleId: "waste.redundant-variable",
        message: `Variable \`${redundant.name}\` is returned immediately after assignment.`,
        filePath: context.file.displayPath,
        line: context.block.startLine + redundant.lineOffset,
        severity: "advisory",
        pillar: "waste",
        confidence: "medium",
        symbol: redundant.name,
        remediation: "Return the expression directly.",
        metadata: { variable: redundant.name },
      }),
    );
  }
}

// Caller adds the block's start line to the relative offset so the finding anchors at the actual
// return statement. Reports `waste.useless-return` for bare `return;` as the final statement.
function pushUselessReturnFindings(context: BlockRuleContext): void {
  for (const lineOffset of terminalBareReturnLines(context.block.codeBody)) {
    context.findings.push(
      makeFinding({
        ruleId: "waste.useless-return",
        message: `Function \`${context.block.name}\` ends with a redundant bare return.`,
        filePath: context.file.displayPath,
        line: context.block.startLine + lineOffset,
        severity: "advisory",
        pillar: "waste",
        confidence: "medium",
        symbol: context.block.name,
        remediation: "Remove the final return statement.",
      }),
    );
  }
}

/*
 * Reached when `block.isTest` is true. Four sub-passes in a stable, deterministic order: assertion
 * quality, mock quality, setup bloat, structural rules.
 */
function analyseTestBlock(file: SourceFile, block: FunctionBlock, config: Config, findings: Finding[]): void {
  const body = block.codeBody;
  analyseAssertionQuality(file, block, body, findings);
  analyseMockQuality(file, block, body, findings);
  analyseSetupBloat(file, block, body, config, findings);
  analyseTestStructureChecks(file, block, body, findings);
}

// Five assertion-shape checks (no-assertions, trivial, snapshot-only, no-throw-only, exception-type-only)
// plus the magic-number sub-pass. Reports findings with stable test-block metadata.
function analyseAssertionQuality(file: SourceFile, block: FunctionBlock, body: string, findings: Finding[]): void {
  for (const check of assertionQualityChecks(block, body)) {
    findings.push(blockFinding({ ruleId: check.ruleId, message: check.message, file, block, severity: check.severity, pillar: "test-quality" }));
  }
  pushMagicNumberAssertionFindings(file, block, body, findings);
}

// Lazy evaluation: only checks whose `active` predicate fired are returned. The five rule IDs are
// part of the public test-quality pillar; their ordering here is the stable emission order.
function assertionQualityChecks(block: FunctionBlock, body: string): TestBlockCheck[] {
  const testName = block.name;
  const checks: Array<TestBlockCheck & { active: boolean }> = [
    { active: !hasAssertion(body), ruleId: "test-quality.no-assertions", message: `Test \`${testName}\` does not appear to make an assertion.`, severity: "warning" },
    { active: hasTrivialAssertion(body), ruleId: "test-quality.trivial-assertion", message: `Test \`${testName}\` contains an assertion that compares a value to itself.`, severity: "warning" },
    { active: isSnapshotOnlyTest(body), ruleId: "test-quality.snapshot-only-test", message: `Test \`${testName}\` relies only on snapshot assertions.`, severity: "advisory" },
    { active: isNoThrowOnlyTest(body), ruleId: "test-quality.no-throw-only-test", message: `Test \`${testName}\` only verifies that code does not throw.`, severity: "advisory" },
    { active: hasExceptionTypeOnlyAssertion(body), ruleId: "test-quality.exception-type-only", message: `Test \`${testName}\` checks only the exception type.`, severity: "advisory" },
  ];
  return checks.filter((check) => check.active).map(({ active: _active, ...check }) => check);
}

/*
 * Targets `expect(x).toBe(42)` / `assert.equal(x, 42)` patterns where 42 has no name. Reports
 * `test-quality.magic-number-assertion` with stable literal metadata for downstream review tools.
 */
function pushMagicNumberAssertionFindings(file: SourceFile, block: FunctionBlock, body: string, findings: Finding[]): void {
  for (const assertion of magicNumberAssertions(body)) {
    findings.push(
      blockFindingWithMetadata({
        ruleId: "test-quality.magic-number-assertion",
        message: `Test \`${block.name}\` asserts against unexplained numeric literal ${assertion.value}.`,
        file,
        block,
        severity: "advisory",
        pillar: "test-quality",
        metadata: { value: assertion.value },
      }),
    );
  }
}

// Two distinct findings emitted from one walk: per-unused-mock and a single mock-only flag.
// Reports `test-quality.unused-mock` / `test-quality.mock-only-test` with stable test-block metadata.
function analyseMockQuality(file: SourceFile, block: FunctionBlock, body: string, findings: Finding[]): void {
  const unusedMocks = unusedMockVariables(body);
  for (const mock of unusedMocks) {
    findings.push(
      blockFindingWithMetadata({
        ruleId: "test-quality.unused-mock",
        message: `Mock \`${mock}\` is created but not used.`,
        file,
        block,
        severity: "advisory",
        pillar: "test-quality",
        metadata: { mockName: mock },
      }),
    );
  }
  if (isMockOnlyTest(body)) {
    findings.push(blockFinding({ ruleId: "test-quality.mock-only-test", message: `Test \`${block.name}\` only verifies mock interaction.`, file, block, severity: "advisory", pillar: "test-quality" }));
  }
}

/*
 * Two rules off one pass: `test-quality.global-state-mutation` for tests that touch process state,
 * and `test-quality.setup-bloat` (threshold 12) for excessive arrange before the first assertion.
 * Reports both with stable metadata so downstream tooling can track the setup-line counts.
 */
function analyseSetupBloat(file: SourceFile, block: FunctionBlock, body: string, config: Config, findings: Finding[]): void {
  if (hasGlobalStateMutation(body)) {
    findings.push(blockFinding({ ruleId: "test-quality.global-state-mutation", message: `Test \`${block.name}\` mutates global process or runtime state.`, file, block, severity: "warning", pillar: "test-quality" }));
  }
  const setupLines = setupLineCount(body);
  const maxSetupLines = threshold(config, "test-quality.setup-bloat", 12);
  if (setupLines > maxSetupLines) {
    findings.push(
      blockFindingWithMetadata({
        ruleId: "test-quality.setup-bloat",
        message: `Test \`${block.name}\` has ${setupLines} setup lines before its first assertion.`,
        file,
        block,
        severity: ruleSeverity(config, "test-quality.setup-bloat", "advisory"),
        pillar: "test-quality",
        metadata: { setupLines, maxSetupLines },
      }),
    );
  }
}

// Pattern-driven checks for sleep/loop/conditional logic plus the `.only`/`.skip` commit gate.
// Reports each detected structural issue as a stable test-quality finding.
function analyseTestStructureChecks(file: SourceFile, block: FunctionBlock, body: string, findings: Finding[]): void {
  const checks: Array<[string, RegExp, string]> = [
    ["test-quality.sleep-in-test", /\b(setTimeout|sleep|waitForTimeout)\s*\(/, "Test sleeps instead of synchronising on behaviour."],
    ["test-quality.loop-in-test", /\b(for|while)\b/, "Test contains loop logic."],
    ["test-quality.conditional-logic", /\b(if|switch)\b/, "Test contains conditional logic."],
    ["test-quality.only-skip", /\.(only|skip)\s*\(/, "Focused or skipped test is committed."],
  ];
  for (const [ruleId, pattern, message] of checks) {
    if (pattern.test(body)) {
      findings.push(blockFinding({ ruleId, message, file, block, severity: "advisory", pillar: "test-quality" }));
    }
  }
}

/*
 * Per-line rule pipeline. Walks every source line through the shared `LineRuleContext` then runs
 * the three multi-line catchers (useless catches, swallowed catches, unreachable) afterwards.
 * Ordering is the stable contract; reshuffling churns baselines.
 */
function analyseLineRules(file: SourceFile, source: string, codeSource: string, config: Config, findings: Finding[]): void {
  analyseUnusedImports(file, codeSource, findings);
  const sourceLines = source.split(/\r?\n/);
  const codeLines = codeSource.split(/\r?\n/);
  const sharedContext = {
    file,
    config,
    findings,
    codeChecks: codeLineChecks(),
    literalChecks: literalLineChecks(),
    variables: /\b(?:const|let|for\s*\(\s*const|for\s*\(\s*let)\s+([A-Za-z_$][A-Za-z0-9_$]*)/g,
  };
  sourceLines.forEach((line, index) => {
    analyseLineRuleContext({ ...sharedContext, line, codeLine: codeLines[index] ?? codeLineForMatching(line), lineNumber: index + 1 });
  });

  analyseUselessCatches(file, codeSource, findings);
  analyseSwallowedCatches(file, codeSource, findings);
  analyseUnreachable(file, codeSource, findings);
}

// All per-line checks for a single line in their stable, deterministic emission order. Each helper
// either no-ops (rule skipped or no match) or appends to `findings`.
function analyseLineRuleContext(context: LineRuleContext): void {
  analyseTypeSafetyLine(context.file, context.line, context.codeLine, context.lineNumber, context.findings);
  analyseReliabilityLine(context.file, context.codeLine, context.lineNumber, context.findings);
  pushCommentedOutCodeFinding(context);
  pushBooleanPrefixFinding(context);
  pushHungarianNotationFindings(context);
  pushOptionalChainingFindings(context);
  pushNullishCoalescingFindings(context);
  pushLooseEqualityFinding(context);
  pushStringTimerFinding(context);
  pushProcessExecFinding(context);
  pushPatternCheckFindings(context);
  pushVariableNameFindings(context);
}

// Code-shape rules: those that must match against the masked code (no comment or literal noise).
// Targets the eval / new-Function / Math.random / innerHTML / proto-access family of security/waste signals.
function codeLineChecks(): LineRuleCheck[] {
  return [
    { ruleId: "security.eval-call", pattern: /\beval\s*\(/, message: "eval() executes dynamic code.", severity: "error", pillar: "security" },
    { ruleId: "security.new-function", pattern: /\bnew\s+Function\s*\(|(?:^|[=(:,])\s*Function\s*\(/, message: "Function constructor executes dynamic code.", severity: "error", pillar: "security" },
    { ruleId: "security.insecure-random", pattern: /\bMath\.random\s*\(/, message: "Math.random() is not suitable for security-sensitive randomness.", severity: "warning", pillar: "security" },
    { ruleId: "security.inner-html", pattern: /\.innerHTML\s*=|\bdangerouslySetInnerHTML\b/, message: "HTML injection sink can introduce XSS.", severity: "warning", pillar: "security" },
    { ruleId: "security.proto-access", pattern: /\.__proto__\b/, message: "Direct __proto__ access can enable prototype pollution.", severity: "warning", pillar: "security" },
    { ruleId: "security.document-write", pattern: /\bdocument\.write\s*\(/, message: "document.write() can introduce injection risks.", severity: "warning", pillar: "security" },
    { ruleId: "waste.redundant-boolean-cast", pattern: /\b(?:if|while)\s*\(\s*(?:!!\s*[A-Za-z_$][A-Za-z0-9_$.]*|Boolean\s*\()/, message: "Condition contains a redundant boolean cast.", severity: "advisory", pillar: "waste" },
  ];
}

// Rules that need to see the raw line including literals (e.g., `"javascript:"` URL detection,
// `"md5"` weak-crypto match). Global patterns are auto-generated so global-match operations stay
// safe — see `withGlobalPattern`.
function literalLineChecks(): LineRuleCheck[] {
  const checks: LineRuleCheck[] = [
    { ruleId: "security.weak-crypto", pattern: /\b(?:createHash|createHmac)\s*\(\s*["'](?:md5|sha1)["']|\bcreateCipher\s*\(|\b(?:secureProtocol|minVersion|maxVersion)\s*:\s*["'](?:SSLv2_method|SSLv3_method|TLSv1(?:_method)?|TLSv1\.1)["']/i, message: "Weak cryptographic primitive is used.", severity: "warning", pillar: "security" },
    { ruleId: "security.disabled-tls-verification", pattern: /\b(?:process\.env\.)?NODE_TLS_REJECT_UNAUTHORIZED\b\s*=\s*["']0["']|\brejectUnauthorized\s*:\s*false\b/i, message: "TLS certificate verification is disabled.", severity: "error", pillar: "security" },
    { ruleId: "security.javascript-url", pattern: /["'`]\s*javascript\s*:(?!\s+URL\b)/i, message: "javascript: URL literal can execute script.", severity: "error", pillar: "security" },
    { ruleId: "security.proto-access", pattern: /\[\s*["']__proto__["']\s*\]/, message: "Direct __proto__ access can enable prototype pollution.", severity: "warning", pillar: "security" },
    { ruleId: "security.sql-concatenation", pattern: /\b(?:query|execute|raw)\s*\(\s*(?:`[^`]*(?:SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{|["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)[^"']*["']\s*\+)/i, message: "SQL text is composed with runtime string interpolation.", severity: "warning", pillar: "security" },
    { ruleId: "modernisation.date-now-candidate", pattern: /\bnew\s+Date\s*\(\s*\)\s*\.getTime\s*\(\s*\)|\bNumber\s*\(\s*new\s+Date\s*\(\s*\)\s*\)/, message: "Current-time expression can use Date.now().", severity: "advisory", pillar: "modernisation" },
    { ruleId: "modernisation.object-spread-candidate", pattern: /\bObject\.assign\s*\(\s*\{\s*\}\s*,/, message: "Object.assign clone can usually use object spread.", severity: "advisory", pillar: "modernisation" },
    { ruleId: "waste.console-log", pattern: /\bconsole\.(log|debug)\s*\(/, message: "console logging is committed in source.", severity: "advisory", pillar: "waste" },
    { ruleId: "waste.any-type", pattern: /:\s*any\b|as\s+any\b/, message: "any weakens TypeScript's type guarantees.", severity: "warning", pillar: "waste" },
    { ruleId: "modernisation.var-declaration", pattern: /\bvar\s+[A-Za-z_$]/, message: "var declaration should usually be let or const.", severity: "advisory", pillar: "modernisation" },
  ];
  return checks.map(withGlobalPattern);
}

// Returns a new check whose `globalPattern` has the `g` flag, leaving the original `pattern`
// untouched. Required because `pattern.exec` stateful iteration would corrupt callers that share
// a check across multiple files.
function withGlobalPattern(check: LineRuleCheck): LineRuleCheck {
  return {
    ...check,
    globalPattern: check.pattern.flags.includes("g") ? check.pattern : new RegExp(check.pattern.source, `${check.pattern.flags}g`),
  };
}

/*
 * Targets `// const x = …;`-style commented-out code. The detector is intentionally conservative
 * because clever false positives drown the rule. Reports the stable `waste.commented-out-code` finding.
 */
function pushCommentedOutCodeFinding(context: LineRuleContext): void {
  if (isCommentedOutCode(context.line)) {
    context.findings.push(finding({ ruleId: "waste.commented-out-code", message: "Comment appears to contain disabled source code.", file: context.file, line: context.lineNumber, severity: "advisory", pillar: "waste" }));
  }
}

type NamingSurface = "declaration" | "parameter" | "destructure" | "interface-field";

// Detects typed boolean declarations (or those with a literal true/false initializer) and runs
// the boolean-prefix and negative-boolean checks. Surface is fixed to "declaration".
function pushBooleanPrefixFinding(context: LineRuleContext): void {
  const booleanDeclaration = context.codeLine.match(/\b(?:const|let|var|public|private|protected)\s+([A-Za-z_$][A-Za-z0-9_$]*)\??(?:\s*:\s*boolean|\s*=\s*(?:true|false)\b)/);
  const name = booleanDeclaration?.[1] ?? "";
  if (!name) {
    return;
  }
  pushBooleanPrefixAt(context.file, context.lineNumber, name, context.config, context.findings, "declaration");
  pushNegativeBooleanAt(context.file, context.lineNumber, name, context.config, context.findings, "declaration");
}

/*
 * Negative-framed booleans (disableX, noX, preventX, …) read as double negations at call sites.
 * `negativeBooleanAllowed` is the user-curated exemption list. Reports the stable
 * `naming.negative-boolean` finding.
 */
function pushNegativeBooleanAt(file: SourceFile, line: number, name: string, config: Config, findings: Finding[], surface: NamingSurface): void {
  if (!/^(?:disable|no|not|prevent|skip|disallow)[A-Z]/.test(name)) {
    return;
  }
  if (config.negativeBooleanAllowed.has(name.toLowerCase())) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "naming.negative-boolean",
      message: `Boolean identifier \`${name}\` is framed as a negation.`,
      filePath: file.displayPath,
      line,
      severity: "advisory",
      pillar: "naming",
      confidence: "medium",
      symbol: name,
      remediation: "Invert the framing so callers do not read a double negation.",
      metadata: { identifierName: name, surface },
    }),
  );
}

/*
 * Booleans should announce their boolean-ness with an `is`/`has`/`can`/… prefix. The accepted set
 * lives in `config.booleanPrefixes` so projects can tune it. Reports the stable
 * `naming.boolean-prefix` finding.
 */
function pushBooleanPrefixAt(file: SourceFile, line: number, name: string, config: Config, findings: Finding[], surface: NamingSurface): void {
  if (hasBooleanPrefix(name, config.booleanPrefixes)) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "naming.boolean-prefix",
      message: `Boolean identifier \`${name}\` should use an intent-revealing prefix.`,
      filePath: file.displayPath,
      line,
      severity: "advisory",
      pillar: "naming",
      confidence: "medium",
      symbol: name,
      remediation: "Use a prefix such as is, has, can, should, or will.",
      metadata: { identifierName: name, surface },
    }),
  );
}

// Walks all `strFoo` / `intBar` / `arrBaz` identifiers on the line. The prefix regex is
// auto-generated from `config.hungarianPrefixes`. Reports `naming.hungarian-notation`.
function pushHungarianNotationFindings(context: LineRuleContext): void {
  const regex = hungarianPrefixRegex(context.config.hungarianPrefixes);
  if (regex === null) {
    return;
  }
  for (const hungarian of context.codeLine.matchAll(regex)) {
    const name = hungarian[1] ?? "";
    context.findings.push(
      makeFinding({
        ruleId: "naming.hungarian-notation",
        message: `Identifier \`${name}\` uses type-style Hungarian notation.`,
        filePath: context.file.displayPath,
        line: context.lineNumber,
        severity: "advisory",
        pillar: "naming",
        confidence: "medium",
        symbol: name,
        remediation: "Name the domain concept instead of the storage type.",
        metadata: { identifierName: name },
      }),
    );
  }
}

// Detects `foo && foo.bar` patterns where `foo?.bar` would say the same thing. Backreference
// in the regex enforces identical identifiers on both sides. Reports `modernisation.optional-chaining-candidate`.
function pushOptionalChainingFindings(context: LineRuleContext): void {
  for (const optional of context.codeLine.matchAll(/\b([A-Za-z_$][A-Za-z0-9_$]*)\s*&&\s*\1\.[A-Za-z_$][A-Za-z0-9_$]*/g)) {
    const name = optional[1] ?? "";
    context.findings.push(
      makeFinding({
        ruleId: "modernisation.optional-chaining-candidate",
        message: `Guarded property access on \`${name}\` can usually use optional chaining.`,
        filePath: context.file.displayPath,
        line: context.lineNumber,
        severity: "advisory",
        pillar: "modernisation",
        confidence: "medium",
        symbol: name,
        remediation: "Use optional chaining for the guarded property access.",
      }),
    );
  }
}

// Targets `x || defaultValue` patterns where the fallback is a literal — `??` would preserve
// legitimately-falsy values (0, "", false). Reports `modernisation.nullish-coalescing-candidate`.
function pushNullishCoalescingFindings(context: LineRuleContext): void {
  for (const fallback of context.codeLine.matchAll(/=\s*([A-Za-z_$][A-Za-z0-9_$.]*)\s*\|\|\s*(["'`]\s*["'`]|\d+|true|false)/g)) {
    const name = fallback[1] ?? "";
    context.findings.push(
      makeFinding({
        ruleId: "modernisation.nullish-coalescing-candidate",
        message: `Fallback for \`${name}\` can usually use nullish coalescing to preserve falsy values.`,
        filePath: context.file.displayPath,
        line: context.lineNumber,
        severity: "advisory",
        pillar: "modernisation",
        confidence: "medium",
        symbol: name,
        remediation: "Use ?? when only null or undefined should trigger the fallback.",
      }),
    );
  }
}

/*
 * Loose `==` / `!=` against non-null operands. The `looseEqualityOperator` helper excludes intentional
 * `x == null` checks (which legitimately match null and undefined). Reports the stable
 * `modernisation.loose-equality` finding.
 */
function pushLooseEqualityFinding(context: LineRuleContext): void {
  const looseOperator = looseEqualityOperator(context.codeLine);
  if (looseOperator) {
    context.findings.push(finding({ ruleId: "modernisation.loose-equality", message: `Loose equality operator ${looseOperator} may coerce values.`, file: context.file, line: context.lineNumber, severity: "advisory", pillar: "modernisation" }));
  }
}

/*
 * `setTimeout("alert(1)", …)` and friends evaluate the string as code, an `eval`-equivalent.
 * Reports the stable `security.string-timer` finding when a literal string callback is detected.
 */
function pushStringTimerFinding(context: LineRuleContext): void {
  if (stringTimerCandidate(context.codeLine)) {
    context.findings.push(finding({ ruleId: "security.string-timer", message: "Timer callback is provided as a string.", file: context.file, line: context.lineNumber, severity: "warning", pillar: "security" }));
  }
}

/*
 * `exec` / `execSync` / `spawn` with potentially user-influenced arguments. The local-harness
 * escape hatch keeps gruff's own test process invocations quiet. Reports the stable
 * `security.process-exec` finding.
 */
function pushProcessExecFinding(context: LineRuleContext): void {
  if (processExecCandidate(context.codeLine) && !isFixedLocalProcessHarness(context.file, context.line, context.codeLine)) {
    context.findings.push(finding({ ruleId: "security.process-exec", message: "Child-process execution is used; validate arguments are not user-controlled.", file: context.file, line: context.lineNumber, severity: "warning", pillar: "security" }));
  }
}

// Runs the descriptor-driven line checks split into code-shape vs literal-aware. Literal checks
// use `rawPatternStartsInCode` to confirm the match starts in real code, not inside a comment.
// Reports each matching rule's stable line-anchored finding.
function pushPatternCheckFindings(context: LineRuleContext): void {
  for (const check of context.codeChecks) {
    if (check.pattern.test(context.codeLine)) {
      context.findings.push(finding({ ruleId: check.ruleId, message: check.message, file: context.file, line: context.lineNumber, severity: check.severity, pillar: check.pillar }));
    }
  }
  for (const check of context.literalChecks) {
    if (rawPatternStartsInCode(context.line, context.codeLine, check.globalPattern ?? check.pattern)) {
      context.findings.push(finding({ ruleId: check.ruleId, message: check.message, file: context.file, line: context.lineNumber, severity: check.severity, pillar: check.pillar }));
    }
  }
}

// Per-line variable-name pass that runs short/identifier-quality/abbreviation checks on both
// regular `const`/`let` declarations and destructured names. Reports any findings produced.
function pushVariableNameFindings(context: LineRuleContext): void {
  for (const match of context.codeLine.matchAll(context.variables)) {
    const name = match[1] ?? "";
    pushShortVariableFinding(context, name);
    pushIdentifierQualityFinding(context, name);
    pushAbbreviationAt(context.file, context.lineNumber, name, context.config, context.findings, "declaration");
  }
  for (const name of destructuredLocalNames(context.codeLine)) {
    pushShortVariableAt(context.file, context.lineNumber, name, context.config, context.findings, "destructure");
    pushIdentifierQualityAt(context.file, context.lineNumber, name, context.config, context.findings, "destructure");
    pushAbbreviationAt(context.file, context.lineNumber, name, context.config, context.findings, "destructure");
  }
}

// Walks `const { foo, bar: alias } = ...` patterns. Aliased names (the part after `:`) become the
// local binding; defaults are stripped. Required because the naming rules check the local name only.
function destructuredLocalNames(codeLine: string): string[] {
  const names: string[] = [];
  for (const block of codeLine.matchAll(/\b(?:const|let)\s+\{([^}]+)\}\s*=/g)) {
    const inner = block[1] ?? "";
    for (const part of inner.split(",")) {
      const trimmed = part.trim().replace(/\s*=[^,]*$/, "");
      const aliased = trimmed.match(/[A-Za-z_$][A-Za-z0-9_$]*\s*:\s*([A-Za-z_$][A-Za-z0-9_$]*)/);
      const plain = trimmed.match(/^([A-Za-z_$][A-Za-z0-9_$]*)$/);
      const name = aliased?.[1] ?? plain?.[1];
      if (name) {
        names.push(name);
      }
    }
  }
  return names;
}

// Thin wrapper that fills in `"declaration"` for the surface field. Same back-end as parameter
// and destructure callers, which use their own surface labels.
function pushShortVariableFinding(context: LineRuleContext, name: string): void {
  pushShortVariableAt(context.file, context.lineNumber, name, context.config, context.findings, "declaration");
}

/*
 * Allows the standard `i`, `j`, `k` loop counters and anything on `acceptedAbbreviations`. Reports
 * `naming.short-variable` for any other one or two character name as a stable advisory finding.
 */
function pushShortVariableAt(file: SourceFile, line: number, name: string, config: Config, findings: Finding[], surface: NamingSurface): void {
  if (name.length > 2 || ["i", "j", "k"].includes(name) || config.acceptedAbbreviations.has(name.toLowerCase())) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "naming.short-variable",
      message: `Variable \`${name}\` is too short to explain intent.`,
      filePath: file.displayPath,
      line,
      severity: "advisory",
      pillar: "naming",
      confidence: "medium",
      symbol: name,
      remediation: "Use a name that describes the domain role.",
      metadata: { surface },
    }),
  );
}

// Thin wrapper that fills in `"declaration"` for the surface field; parameter and destructure
// callers use their own surface labels via the underlying `pushIdentifierQualityAt`.
function pushIdentifierQualityFinding(context: LineRuleContext, name: string): void {
  pushIdentifierQualityAt(context.file, context.lineNumber, name, context.config, context.findings, "declaration");
}

/*
 * Reports `naming.identifier-quality` when a name resolves to a generic variant via
 * `identifierQualityVariant` (placeholder names from config, or built-in low-info forms like `data`).
 * The stable `variant` metadata lets downstream tools group by category.
 */
function pushIdentifierQualityAt(file: SourceFile, line: number, name: string, config: Config, findings: Finding[], surface: NamingSurface): void {
  const variant = identifierQualityVariant(name, config.placeholderNames);
  if (!variant) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "naming.identifier-quality",
      message: `Identifier \`${name}\` is a ${variant} name that does not explain domain intent.`,
      filePath: file.displayPath,
      line,
      severity: "advisory",
      pillar: "naming",
      confidence: "medium",
      symbol: name,
      remediation: "Use an identifier that names the domain role.",
      metadata: { identifierName: name, variant, surface },
    }),
  );
}

// True iff the pattern matches somewhere on the raw line *and* the match's start position falls on
// a code character in `codeLine`. Required for literal-rule checks where the raw line is needed to
// see the literal content, but the match must still begin in executable code (not inside a comment).
function rawPatternStartsInCode(rawLine: string, codeLine: string, pattern: RegExp): boolean {
  const globalPattern = pattern;
  let match: RegExpExecArray | null;
  globalPattern.lastIndex = 0;
  while ((match = globalPattern["exec"](rawLine)) !== null) {
    const index = match.index ?? 0;
    if (isNonWhitespaceCharacter(codeLine[index] ?? "")) {
      return true;
    }
    if (match[0] === "") {
      globalPattern.lastIndex += 1;
    }
  }
  return false;
}

// Used by `rawPatternStartsInCode` to confirm a position holds executable code rather than the
// space character produced by `maskNonCode`.
function isNonWhitespaceCharacter(character: string): boolean {
  return character !== "" && character !== " " && character !== "\t" && character !== "\r" && character !== "\n";
}

// Returns the loose operator (`==` or `!=`) when present and not part of `===`/`!==`/null check.
// Used by the modernisation rule; sufficient context lookback keeps `x == null` quiet.
function looseEqualityOperator(codeLine: string): string | undefined {
  for (const match of codeLine.matchAll(/[=!]=/g)) {
    const index = match.index ?? 0;
    const operator = match[0] ?? "";
    if (!isLooseEqualityCandidate(codeLine, index, operator)) {
      continue;
    }
    return operator;
  }
  return undefined;
}

// Two-pass filter: reject `===`/`!==` (strict equality) and reject `x == null` (intentional double-test).
function isLooseEqualityCandidate(codeLine: string, index: number, operator: string): boolean {
  return !isStrictEqualityOperator(codeLine, index, operator) && !isNullEqualityComparison(codeLine, index, operator);
}

// Looks one char before and after — `===` shows up as `==` plus a trailing `=`. The leading `!` /
// `=` check catches `!==` and `===` from either side.
function isStrictEqualityOperator(codeLine: string, index: number, operator: string): boolean {
  const before = codeLine[index - 1] ?? "";
  const after = codeLine[index + operator.length] ?? "";
  return before === "=" || before === "!" || after === "=";
}

// `x == null` matches both null and undefined and is a documented idiom — exempting it is the
// rule's intentional false-positive escape hatch. 24-character lookback window is large enough to
// span `someObject.field == null` without matching unrelated tokens.
function isNullEqualityComparison(codeLine: string, index: number, operator: string): boolean {
  const left = codeLine.slice(Math.max(0, index - 24), index).trimEnd();
  const right = codeLine.slice(index + operator.length, Math.min(codeLine.length, index + operator.length + 24)).trimStart();
  return /\bnull$/.test(left) || /^null\b/.test(right);
}

// Two cases: a bare `setTimeout("…")` call, or one accessed via window/self/globalThis. Both
// invoke `eval`-equivalent string-to-code semantics in browsers.
function stringTimerCandidate(codeLine: string): boolean {
  return (
    /(?:^|[^.\w$])(?:setTimeout|setInterval|execScript)\s*\(\s*["'`]/.test(codeLine) ||
    /\b(?:window|self|globalThis)\.(?:setTimeout|setInterval|execScript)\s*\(\s*["'`]/.test(codeLine)
  );
}

// Triggers on any `exec`, `spawn`, or `execFile` call. Conservative on purpose — pairs with
// `isFixedLocalProcessHarness` which carves out the safe local-harness case.
function processExecCandidate(codeLine: string): boolean {
  return /\b(?:exec|spawn|execFile)\s*\(/.test(codeLine);
}

// False-positive escape hatch for gruff's own tests: spawning a literal relative path with an array
// of args (the safe `spawn("./bin", ["…"])` form) inside a test file does not need to be flagged.
function isFixedLocalProcessHarness(file: SourceFile, rawLine: string, codeLine: string): boolean {
  return isTestPath(file.displayPath) && /\b(?:spawn|execFile)\s*\(/.test(codeLine) && /\b(?:spawn|execFile)\s*\(\s*["']\.{1,2}\/[^"']*["']\s*,\s*\[/.test(rawLine);
}

// Four-rule TypeScript safety pass: directive comment, non-null assertion, double cast, exported any.
// Stable, deterministic ordering keeps the per-line findings in a known sequence.
function analyseTypeSafetyLine(file: SourceFile, line: string, codeLine: string, lineNumber: number, findings: Finding[]): void {
  pushTsDirectiveFinding(file, line, lineNumber, findings);
  pushNonNullAssertionFindings(file, codeLine, lineNumber, findings);
  pushDoubleCastFindings(file, codeLine, lineNumber, findings);
  pushExportedAnyFinding(file, codeLine, lineNumber, findings);
}

/*
 * `@ts-ignore` / `@ts-expect-error` without an explanatory note. `tsDirectiveWithoutRationale`
 * applies the rationale heuristic. Reports the stable `modernisation.ts-comment-without-rationale`
 * finding.
 */
function pushTsDirectiveFinding(file: SourceFile, line: string, lineNumber: number, findings: Finding[]): void {
  const directive = tsDirectiveWithoutRationale(line);
  if (!directive) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "modernisation.ts-comment-without-rationale",
      message: `${directive.directive} suppresses TypeScript without a nearby rationale.`,
      filePath: file.displayPath,
      line: lineNumber,
      severity: "warning",
      pillar: "modernisation",
      confidence: "medium",
      remediation: "Add a short reason after the directive or remove the suppression.",
      metadata: { directive: directive.directive },
    }),
  );
}

// Walks every `foo.bar!` non-null assertion on the line. The lookahead enforces a real expression
// boundary so `!=` doesn't get misread. Reports `modernisation.non-null-assertion` with stable metadata.
function pushNonNullAssertionFindings(file: SourceFile, codeLine: string, lineNumber: number, findings: Finding[]): void {
  for (const match of codeLine.matchAll(/\b([A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)!(?=\.|\[|\)|,|;|\s+(?:as|in|instanceof)\b|\s*$)/g)) {
    const expression = match[1] ?? "";
    findings.push(
      makeFinding({
        ruleId: "modernisation.non-null-assertion",
        message: `Non-null assertion on \`${expression}\` bypasses TypeScript's null checks.`,
        filePath: file.displayPath,
        line: lineNumber,
        severity: "warning",
        pillar: "modernisation",
        confidence: "medium",
        symbol: expression,
        remediation: "Narrow the value with a guard or handle the null/undefined case explicitly.",
        metadata: { expression },
      }),
    );
  }
}

// `as unknown as Foo` and `as any as Foo` double-cast patterns. Both source and target types are
// captured in stable metadata so reviewers can see what's being coerced. Reports `modernisation.double-cast`.
function pushDoubleCastFindings(file: SourceFile, codeLine: string, lineNumber: number, findings: Finding[]): void {
  for (const match of codeLine.matchAll(/\bas\s+(unknown|any)\s+as\s+([^;,\n]+)/g)) {
    const sourceType = match[1] ?? "";
    const targetType = (match[2] ?? "").trim().replace(/[.)]+$/, "");
    findings.push(
      makeFinding({
        ruleId: "modernisation.double-cast",
        message: `Double cast through \`${sourceType}\` bypasses structural type checks.`,
        filePath: file.displayPath,
        line: lineNumber,
        severity: "warning",
        pillar: "modernisation",
        confidence: "medium",
        remediation: "Prefer a typed parser, type guard, or narrower assertion at the trust boundary.",
        metadata: { sourceType, targetType },
      }),
    );
  }
}

/*
 * `any` in an exported declaration's public surface. Only one finding per line because a single
 * `export` with multiple any-typed fields is one design problem, not many. Reports the stable
 * `waste.exported-any` finding.
 */
function pushExportedAnyFinding(file: SourceFile, codeLine: string, lineNumber: number, findings: Finding[]): void {
  const exportedAny = exportedAnySymbol(codeLine);
  if (!exportedAny) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "waste.exported-any",
      message: `Exported API \`${exportedAny}\` exposes \`any\` in its public contract.`,
      filePath: file.displayPath,
      line: lineNumber,
      severity: "warning",
      pillar: "waste",
      confidence: "medium",
      symbol: exportedAny,
      remediation: "Use a named interface, unknown plus validation, or a precise generic type.",
      metadata: { symbolName: exportedAny },
    }),
  );
}

// Three reliability rules per line: async-forEach, floating-promise, non-Error throw. Order is
// the stable contract — reshuffling shifts per-block emission and churns baselines.
function analyseReliabilityLine(file: SourceFile, codeLine: string, lineNumber: number, findings: Finding[]): void {
  pushAsyncForEachFinding(file, codeLine, lineNumber, findings);
  pushFloatingPromiseFinding(file, codeLine, lineNumber, findings);
  pushNonErrorThrowFinding(file, codeLine, lineNumber, findings);
}

// `arr.forEach(async …)` is a near-universal anti-pattern: the array iterator does not await the
// returned promise, so errors swallow silently. Reports the stable `security.async-foreach` finding.
function pushAsyncForEachFinding(file: SourceFile, codeLine: string, lineNumber: number, findings: Finding[]): void {
  if (!/\.forEach\s*\(\s*async\b/.test(codeLine)) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "security.async-foreach",
      message: "async callbacks passed to forEach are not awaited by the caller.",
      filePath: file.displayPath,
      line: lineNumber,
      severity: "warning",
      pillar: "security",
      confidence: "medium",
      remediation: "Use for...of with await, Promise.all, or an explicit queue.",
      metadata: { callName: "forEach" },
    }),
  );
}

/*
 * A promise-shaped call started as a bare statement, with no `await`, `return`, `void`, or chain.
 * Such promises lose their reject path — exceptions land in an unhandled-rejection. Reports
 * the stable `security.floating-promise` finding.
 */
function pushFloatingPromiseFinding(file: SourceFile, codeLine: string, lineNumber: number, findings: Finding[]): void {
  const floating = floatingPromiseCall(codeLine);
  if (!floating) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "security.floating-promise",
      message: `Promise-like call \`${floating}\` is started without await, return, or void.`,
      filePath: file.displayPath,
      line: lineNumber,
      severity: "warning",
      pillar: "security",
      confidence: "medium",
      symbol: floating,
      remediation: "Await it, return it, or prefix with void when fire-and-forget is intentional.",
      metadata: { callName: floating },
    }),
  );
}

/*
 * `throw "string"` / `throw { …object }` / `throw 42`. JavaScript permits it but the stack trace
 * is missing and the caller can't pattern-match an Error subclass. Reports the stable
 * `security.throw-non-error` finding.
 */
function pushNonErrorThrowFinding(file: SourceFile, codeLine: string, lineNumber: number, findings: Finding[]): void {
  const thrown = nonErrorThrowExpression(codeLine);
  if (!thrown) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "security.throw-non-error",
      message: "Throwing non-Error values loses stack and error-shape information.",
      filePath: file.displayPath,
      line: lineNumber,
      severity: "warning",
      pillar: "security",
      confidence: "medium",
      remediation: "Throw an Error subclass with a clear message and structured properties.",
      metadata: { expression: thrown },
    }),
  );
}

/*
 * `catch (e) { throw e; }` patterns. The backreference enforces "same binding name" so a real
 * `catch (e) { throw new Wrapped(e); }` does not trip. Reports the stable `waste.useless-catch` finding.
 */
function analyseUselessCatches(file: SourceFile, source: string, findings: Finding[]): void {
  for (const match of source.matchAll(/\bcatch\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\)\s*\{\s*throw\s+\1\s*;?\s*\}/g)) {
    const binding = match[1] ?? "";
    findings.push(
      makeFinding({
        ruleId: "waste.useless-catch",
        message: `catch block only rethrows \`${binding}\` without adding handling.`,
        filePath: file.displayPath,
        line: byteLine(source, match.index ?? 0),
        severity: "advisory",
        pillar: "waste",
        confidence: "high",
        remediation: "Remove the catch block or add meaningful handling.",
        metadata: { binding },
      }),
    );
  }
}

/*
 * Empty / comment-only catch bodies. Strips comments before testing, because a catch body with
 * only `// intentional` is still a swallowed catch but a real `console.error` is not. Reports
 * the stable `waste.swallowed-catch` finding.
 */
function analyseSwallowedCatches(file: SourceFile, source: string, findings: Finding[]): void {
  for (const match of source.matchAll(/\bcatch\s*(?:\(([^)]*)\))?\s*\{([\s\S]*?)\}/g)) {
    const body = match[2] ?? "";
    if (!isSwallowedCatchBody(body)) {
      continue;
    }
    const binding = (match[1] ?? "").trim();
    findings.push(
      makeFinding({
        ruleId: "waste.swallowed-catch",
        message: "catch block swallows an error without rethrowing, returning, or reporting it.",
        filePath: file.displayPath,
        line: byteLine(source, match.index ?? 0),
        severity: "warning",
        pillar: "waste",
        confidence: "medium",
        remediation: "Handle the error explicitly, rethrow it, or document an intentional ignore path.",
        metadata: { ...(binding ? { binding } : {}) },
      }),
    );
  }
}

// Returns the directive name only when the suffix (the text after `@ts-ignore` / `@ts-expect-error`)
// has no meaningful rationale. Heuristic is intentionally lenient — three real words usually means
// the maintainer wrote a reason.
function tsDirectiveWithoutRationale(line: string): { directive: string } | undefined {
  const match = line.match(/@ts-(ignore|expect-error)\b(.*)$/);
  if (!match?.[1]) {
    return undefined;
  }
  const rationale = match[2] ?? "";
  if (hasDirectiveRationale(rationale)) {
    return undefined;
  }
  return { directive: `@ts-${match[1]}` };
}

// Two-way pass: an explicit suppression rationale token (tracking URL / issue ID / owner / date)
// or at least three real English-shaped words. The disjunction keeps maintainers from having to
// remember a specific format.
function hasDirectiveRationale(value: string): boolean {
  const cleaned = value.replace(/^[-:\s]+/, "").trim();
  const words = cleaned.match(/[A-Za-z]{3,}/g) ?? [];
  return hasSuppressionRationale(cleaned) || words.length >= 3;
}

// Two-shot scan: line must have both `export` and `any` before the regex is invoked, because the
// regex is expensive and most lines do not have both.
function exportedAnySymbol(codeLine: string): string | undefined {
  if (!/\bexport\b/.test(codeLine) || !/\bany\b/.test(codeLine)) {
    return undefined;
  }
  const match = codeLine.match(/\bexport\s+(?:async\s+)?(?:function|const|let|var|class|interface|type)\s+([A-Za-z_$][A-Za-z0-9_$]*)/);
  return match?.[1];
}

// Two predicates compose: must be a bare statement (not handled), and must be a promise-shaped
// call. Returning undefined keeps the per-line emission stable when either gate fails.
function floatingPromiseCall(codeLine: string): string | undefined {
  const trimmed = codeLine.trim();
  if (isHandledPromiseStatement(trimmed)) {
    return undefined;
  }
  const callName = leadingCallName(trimmed);
  if (!callName) {
    return undefined;
  }
  return isPromiseLikeCall(callName) ? callName : undefined;
}

// Five "this is intentional" forms: await, return, void, throw, yield, or a binding. Any one keeps
// the line out of floating-promise reporting.
function isHandledPromiseStatement(trimmedLine: string): boolean {
  return trimmedLine.length === 0 || /^(?:await|return|void|throw|yield)\b/.test(trimmedLine) || /^(?:const|let|var)\s+/.test(trimmedLine);
}

// Picks the dotted callable name at the start of the line. Empty string for non-call statements
// signals "not a candidate" to the caller without throwing.
function leadingCallName(trimmedLine: string): string {
  const match = trimmedLine.match(/^([A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)\s*\(/);
  return match?.[1] ?? "";
}

// Heuristic: `fetch`, anything ending in `Async`, or anything ending in `Promise`. False positives
// are tolerated because the rule's remediation ("await or void it") is also the universal best practice.
function isPromiseLikeCall(callName: string): boolean {
  const localName = callName.split(".").at(-1) ?? callName;
  return callName === "fetch" || /(?:Async|Promise)$/.test(localName);
}

// Allow `throw new XxxError(...)` and `throw e` (bare identifier — usually a rethrow), reject literals.
// Returns a truncated preview because the full expression can be arbitrarily long.
function nonErrorThrowExpression(codeLine: string): string | undefined {
  const match = codeLine.match(/\bthrow\s+(.+?);?$/);
  const expression = (match?.[1] ?? "").trim();
  if (!expression) {
    return undefined;
  }
  if (/^(?:new\s+[A-Za-z_$][A-Za-z0-9_$]*Error\b|[A-Za-z_$][A-Za-z0-9_$]*)/.test(expression)) {
    return undefined;
  }
  return /^(?:["'`]|\d|\{|\[|true\b|false\b|null\b|undefined\b)/.test(expression) ? expression.slice(0, 40) : undefined;
}

// Strips both line and block comments before testing for emptiness. A catch body holding only a
// throwaway placeholder comment reads as a deliberate swallow but documents nothing about the
// recovery path — that is still the rule's signal.
function isSwallowedCatchBody(body: string): boolean {
  const meaningful = body
    .replace(/\/\/.*$/gm, "")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .trim();
  return meaningful === "";
}

// Lightweight shape used by both public-doc and class/file-mismatch rules. Holds the declaration
// keyword (`class`, `interface`, …), the symbol name, and the declaration line for finding anchors.
interface ExportedDeclaration {
  kind: string;
  name: string;
  line: number;
}

/*
 * Three class-pillar rules in their stable, deterministic emission order: exported-declaration
 * docs and file-name mismatch, public-property, readonly candidates.
 */
function analyseClassRules(file: SourceFile, source: string, codeSource: string, findings: Finding[]): void {
  analyseExportedDeclarations(file, source, codeSource, findings);
  analysePublicProperties(file, source, codeSource, findings);
  analyseReadonlyCandidates(file, source, codeSource, findings);
}

/*
 * Two rules per exported declaration. Both fire from one walk so the file isn't re-scanned for
 * each rule. Reports the stable `docs.missing-public-doc` and `naming.class-file-mismatch`
 * findings per declaration.
 */
function analyseExportedDeclarations(file: SourceFile, source: string, codeSource: string, findings: Finding[]): void {
  for (const declaration of exportedDeclarations(source, codeSource)) {
    pushMissingPublicDocFinding(file, source, declaration, findings);
    pushClassFileMismatchFinding(file, declaration, findings);
  }
}

// Scans the masked code for the five exportable kinds. The order returned matches source order
// because `matchAll` walks left-to-right, which is what downstream rules depend on.
function exportedDeclarations(source: string, codeSource: string): ExportedDeclaration[] {
  return [...codeSource.matchAll(/\bexport\s+(class|interface|type|enum|function)\s+([A-Za-z_$][A-Za-z0-9_$]*)/g)].map((match) => ({
    kind: match[1] ?? "",
    name: match[2] ?? "",
    line: byteLine(source, match.index ?? 0),
  }));
}

/*
 * Skips functions and interfaces — those have dedicated rules (`docs.missing-function-doc`,
 * `docs.missing-interface-doc`). Reports the stable `docs.missing-public-doc` finding for
 * classes/types/enums without a leading JSDoc-style block comment.
 */
function pushMissingPublicDocFinding(file: SourceFile, source: string, declaration: ExportedDeclaration, findings: Finding[]): void {
  if (declaration.kind === "function" || declaration.kind === "interface") {
    return;
  }
  if (hasDocCommentBeforeLine(source, declaration.line)) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "docs.missing-public-doc",
      message: `Exported item \`${declaration.name}\` is missing a doc comment.`,
      filePath: file.displayPath,
      line: declaration.line,
      severity: "advisory",
      pillar: "documentation",
      confidence: "medium",
      symbol: declaration.name,
      remediation: "Add a /** ... */ comment explaining the exported API.",
    }),
  );
}

// Anchors the finding at line 1 because the overview comment is expected at the very top of the
// file. Reports the stable `docs.missing-file-overview` finding when no top-of-file comment exists.
function analyseFileOverviewDoc(file: SourceFile, source: string, findings: Finding[]): void {
  if (hasFileOverviewComment(source)) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "docs.missing-file-overview",
      message: `Source file \`${file.displayPath}\` is missing a top-of-file purpose comment.`,
      filePath: file.displayPath,
      line: 1,
      severity: "advisory",
      pillar: "documentation",
      confidence: "medium",
      remediation: "Add a brief /** ... */ overview before imports or declarations.",
      metadata: {},
    }),
  );
}

/*
 * Same shape as `pushMissingFunctionDocFinding` but for interfaces. The stable
 * `docs.missing-interface-doc` rule reports any exported interface without a leading comment block.
 */
function analyseInterfaceDocs(file: SourceFile, source: string, codeSource: string, findings: Finding[]): void {
  for (const declaration of interfaceDeclarations(source, codeSource)) {
    if (hasLeadingCommentBeforeLine(source, declaration.line)) {
      continue;
    }
    findings.push(
      makeFinding({
        ruleId: "docs.missing-interface-doc",
        message: `Interface \`${declaration.name}\` is missing a leading maintainer comment.`,
        filePath: file.displayPath,
        line: declaration.line,
        severity: "advisory",
        pillar: "documentation",
        confidence: "medium",
        symbol: declaration.name,
        remediation: "Add a short /** ... */ or // comment explaining the interface contract.",
        metadata: { interfaceName: declaration.name },
      }),
    );
  }
}

// Line-anchored regex (`^[ \t]*` + `gm` flag) so the match start is the declaration line, not the
// first character of the keyword inside another construct. See lessons file for the indent-newline trap.
function interfaceDeclarations(source: string, codeSource: string): ExportedDeclaration[] {
  return [...codeSource.matchAll(/^[ \t]*(?:export[ \t]+)?interface[ \t]+([A-Za-z_$][A-Za-z0-9_$]*)\b/gm)].map((match) => ({
    kind: "interface",
    name: match[1] ?? "",
    line: byteLine(source, match.index ?? 0),
  }));
}

/*
 * Coordinator for every comment-quality rule. Comments and declarations are parsed once and the
 * rule descriptor + CLI flag sets are computed once, so every sub-rule sees the same stable inputs.
 */
function analyseCommentQualityRules(input: CommentQualityRuleInput): void {
  const { file, source, codeSource, blocks, comments, config, findings } = input;
  const lines = source.split(/\r?\n/);
  const descriptorIds = new Set(ruleDescriptors().map((descriptor) => descriptor.ruleId));
  const cliFlags = knownCliFlags();
  const declarations = commentedDeclarations(blocks, interfaceDeclarations(source, codeSource));

  analyseStandaloneCommentQuality(file, comments, descriptorIds, cliFlags, findings);
  analyseCommentedDeclarationQuality(file, lines, comments, declarations, findings);
  analyseFunctionContextCommentQuality({ file, lines, comments, blocks, config, findings });
  pushMagicThresholdFindings(file, source, codeSource, comments, findings);
  pushFixturePurposeFindings({ file, source, codeSource, lines, comments, blocks, config, findings });
}

/*
 * Argument bundle for `pushFixturePurposeFindings`. The eight-field call surface is kept as a
 * stable struct so adding a new input does not silently break every per-block helper's positional
 * argument list.
 */
interface FixturePurposeInput {
  file: SourceFile;
  source: string;
  codeSource: string;
  lines: string[];
  comments: CommentRecord[];
  blocks: FunctionBlock[];
  config: Config;
  findings: Finding[];
}

/*
 * Five per-comment rules (task tracking, suppression rationale, stale file refs, stale rule refs,
 * stale CLI flag refs) that run on every comment regardless of whether it documents a declaration.
 * Stable, deterministic emission order across the five sub-checks.
 */
function analyseStandaloneCommentQuality(file: SourceFile, comments: CommentRecord[], descriptorIds: Set<string>, cliFlags: Set<string>, findings: Finding[]): void {
  for (const comment of comments) {
    pushTodoWithoutTrackingFinding(file, comment, findings);
    pushSuppressionWithoutRationaleFinding(file, comment, findings);
    pushStaleFileReferenceFindings(file, comment, findings);
    pushStaleRuleReferenceFindings(file, comment, descriptorIds, findings);
    pushStaleCliFlagReferenceFindings(file, comment, cliFlags, findings);
  }
}

/*
 * Per-declaration rules that need both the declaration metadata and its leading comment. Each
 * declaration is checked against three rules (stale reference, restating signature, context-doc)
 * in their stable, deterministic order.
 */
function analyseCommentedDeclarationQuality(file: SourceFile, lines: string[], comments: CommentRecord[], declarations: CommentedDeclaration[], findings: Finding[]): void {
  for (const declaration of declarations) {
    const comment = leadingCommentForLine(lines, comments, declaration.line);
    if (!comment) {
      continue;
    }
    pushStaleDeclarationCommentFinding(file, comment, declaration, findings);
    pushRestatingSignatureCommentFinding(file, comment, declaration, findings);
    pushDeclarationContextFindings(file, lines, declaration, comment, findings);
  }
}

// Function-only context-doc rule. Restating-signature comments are skipped first because the
// useless-docblock rule has already flagged them; running context checks on top would be redundant noise.
function analyseFunctionContextCommentQuality(input: FunctionContextCommentQualityInput): void {
  const { file, lines, comments, blocks, config, findings } = input;
  for (const block of blocks) {
    const comment = leadingCommentForLine(lines, comments, block.declarationLine);
    if (!comment || isRestatingSignatureComment(comment.text, block.name, "function")) {
      continue;
    }
    pushFunctionContextFindings(file, block, comment, config, findings);
  }
}

// Test/fixture paths only — gated up front so production source never reports fixture-purpose
// findings. Reports the stable `docs.fixture-purpose-missing` finding for each candidate.
function pushFixturePurposeFindings(input: FixturePurposeInput): void {
  const { file, source, codeSource, lines, comments, blocks, config, findings } = input;
  if (!isTestPath(file.displayPath) && !isFixtureLikePath(file.displayPath)) {
    return;
  }
  for (const candidate of fixturePurposeCandidates(source, codeSource, blocks, config)) {
    if (hasFixturePurposeComment(lines, comments, candidate.line)) {
      continue;
    }
    findings.push(
      makeFinding({
        ruleId: "docs.fixture-purpose-missing",
        message: `Large fixture source near \`${candidate.symbol}\` is missing a purpose comment.`,
        filePath: file.displayPath,
        line: candidate.line,
        severity: "advisory",
        pillar: "documentation",
        confidence: "medium",
        symbol: candidate.symbol,
        remediation: "Add a nearby comment explaining what scanner path, regression, or fixture behavior this source covers.",
        metadata: {
          targetKind: candidate.targetKind,
          fixtureLines: candidate.lineCount,
        },
      }),
    );
  }
}

// Three candidate kinds collected in one pass: template-literal fixtures, generated array fixtures,
// and test setup blocks. `occupiedLines` tracks the first two so the third doesn't double-report.
function fixturePurposeCandidates(source: string, codeSource: string, blocks: FunctionBlock[], config: Config): FixturePurposeCandidate[] {
  const candidates: FixturePurposeCandidate[] = [];
  const seen = new Set<string>();
  const occupiedLines = new Set<number>();
  const lines = source.split(/\r?\n/);
  const codeLines = codeSource.split(/\r?\n/);
  const lineOffsets = sourceLineStartOffsets(source);

  codeLines.forEach((codeLine, index) => {
    const lineNumber = index + 1;
    const templateCandidate = fixtureTemplateCandidate(source, lineOffsets, codeLine, lineNumber);
    if (templateCandidate) {
      pushUniqueFixturePurposeCandidate(candidates, seen, templateCandidate);
      occupiedLines.add(templateCandidate.line);
    }
    const generatedCandidate = generatedFixtureCandidate(lines[index] ?? "", codeLine, lineNumber);
    if (generatedCandidate) {
      pushUniqueFixturePurposeCandidate(candidates, seen, generatedCandidate);
      occupiedLines.add(generatedCandidate.line);
    }
  });

  for (const candidate of fixtureTestBlockCandidates(blocks, config, occupiedLines)) {
    pushUniqueFixturePurposeCandidate(candidates, seen, candidate);
  }

  return candidates.filter((candidate) => candidate.line <= lines.length);
}

// Composite key prevents two fixture candidates landing at the same line/symbol/kind tuple — a
// real case when one declaration triggers both a template-literal match and a generated-array match.
function pushUniqueFixturePurposeCandidate(candidates: FixturePurposeCandidate[], seen: Set<string>, candidate: FixturePurposeCandidate): void {
  const key = `${candidate.line}\0${candidate.symbol}\0${candidate.targetKind}`;
  if (seen.has(key)) {
    return;
  }
  seen.add(key);
  candidates.push(candidate);
}

// Two-stage gate: detect the call-site trigger (`analyseFixture`, `analyseProject`, etc.), then
// extract the adjacent template literal and confirm it is large enough to need documentation.
function fixtureTemplateCandidate(source: string, lineOffsets: number[], codeLine: string, lineNumber: number): FixturePurposeCandidate | undefined {
  const trigger = fixtureTemplateTrigger(codeLine);
  if (!trigger) {
    return undefined;
  }
  const text = templateLiteralAtLine(source, lineOffsets, lineNumber);
  if (!text || !isLargeSourceFixtureText(text)) {
    return undefined;
  }
  return {
    line: lineNumber,
    symbol: trigger.symbol,
    targetKind: trigger.targetKind,
    lineCount: fixtureLineCount(text),
  };
}

// Four trigger forms in priority order: `analyseFixture(`, `analyseProject(`, `writeFileSync(`,
// or a `*Fixture` / `*FIXTURE` constant declaration. The `targetKind` differentiates them in metadata.
function fixtureTemplateTrigger(codeLine: string): { symbol: string; targetKind: string } | undefined {
  if (/\banalyseFixture\s*\(/.test(codeLine)) {
    return { symbol: "analyseFixture", targetKind: "inline-source" };
  }
  if (/\banalyseProject\s*\(/.test(codeLine)) {
    return { symbol: "analyseProject", targetKind: "inline-project" };
  }
  if (/\bwriteFileSync\s*\(/.test(codeLine)) {
    return { symbol: "writeFileSync", targetKind: "written-source" };
  }
  const fixtureName = fixtureConstantName(codeLine);
  return fixtureName ? { symbol: fixtureName, targetKind: "fixture-constant" } : undefined;
}

// Identifier names matching `*Fixture` or `*FIXTURE` are treated as opt-in markers — projects
// signal "this is fixture data" with that suffix, so it's the natural trigger for the rule.
function fixtureConstantName(codeLine: string): string | undefined {
  return codeLine.match(/\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*(?:Fixture|FIXTURE)[A-Za-z0-9_$]*)\b[^=\n]*=/)?.[1];
}

// `Array.from({ length: N })` style generated fixtures. Requires both a `*Fixture` constant name
// and N > FIXTURE_PURPOSE_MIN_LINES so trivial test arrays don't trip the rule.
function generatedFixtureCandidate(rawLine: string, codeLine: string, lineNumber: number): FixturePurposeCandidate | undefined {
  const fixtureName = fixtureConstantName(codeLine) ?? (/\b(?:const|let|var)\b/.test(codeLine) ? fixtureConstantName(rawLine) : undefined);
  const generatedLength = Number((codeLine.match(/\bArray\.from\s*\(\s*\{\s*length\s*:\s*(\d+)/) ?? rawLine.match(/\bArray\.from\s*\(\s*\{\s*length\s*:\s*(\d+)/))?.[1] ?? 0);
  if (!fixtureName || generatedLength <= FIXTURE_PURPOSE_MIN_LINES) {
    return undefined;
  }
  return {
    line: lineNumber,
    symbol: fixtureName,
    targetKind: "generated-fixture",
    lineCount: generatedLength,
  };
}

// Test blocks with high setup-line counts AND a fixture-shape signal. Excludes blocks whose setup
// already produced a template-literal or generated-array candidate at the same line.
function fixtureTestBlockCandidates(blocks: FunctionBlock[], config: Config, occupiedLines: Set<number>): FixturePurposeCandidate[] {
  const candidates: FixturePurposeCandidate[] = [];
  for (const block of blocks) {
    if (!block.isTest || fixtureLineInsideBlock(block, occupiedLines)) {
      continue;
    }
    const setupLines = setupLineCount(block.codeBody);
    if (setupLines <= threshold(config, "test-quality.setup-bloat", 12) || !hasFixtureSetupSignal(block.codeBody)) {
      continue;
    }
    candidates.push({
      line: block.declarationLine,
      symbol: block.name,
      targetKind: "test-setup",
      lineCount: setupLines,
    });
  }
  return candidates;
}

// Returns true if any occupied line falls inside the block's line range. Prevents test blocks
// from double-reporting on a fixture that was already detected as a template literal.
function fixtureLineInsideBlock(block: FunctionBlock, occupiedLines: Set<number>): boolean {
  const endLine = block.startLine + block.lineCount - 1;
  for (const line of occupiedLines) {
    if (line >= block.startLine && line <= endLine) {
      return true;
    }
  }
  return false;
}

// Either the canonical fixture-generation calls (analyseFixture / writeFileSync / mkdtempSync /
// Array.from) or an identifier containing "fixture". The narrow allowlist is deliberate — broader
// matchers would catch ordinary production code that happens to construct test data.
function hasFixtureSetupSignal(source: string): boolean {
  return /\b(?:analyseFixture|writeFileSync|mkdtempSync|Array\.from)\s*\(/.test(source) || hasFixtureIdentifier(source);
}

// Substring (not word boundary) match because fixture identifiers in real projects include forms
// like `userFixtureA`, `manyFixtureRows`, etc. Lowercased so casing variants all match.
function hasFixtureIdentifier(source: string): boolean {
  for (const match of source.matchAll(/\b[A-Za-z_$][A-Za-z0-9_$]*\b/g)) {
    if ((match[0] ?? "").toLowerCase().includes("fixture")) {
      return true;
    }
  }
  return false;
}

// Two conjoint conditions: enough lines AND at least one declarative keyword. Short strings or
// pure prose templates don't need a purpose comment; only code-shaped fixtures do.
function isLargeSourceFixtureText(text: string): boolean {
  return fixtureLineCount(text) > FIXTURE_PURPOSE_MIN_LINES && /\b(?:function|class|interface|type|enum|const|let|var|import|export|test|it)\b/.test(text);
}

// Newline-count, not "nonblank-line count" — the rule cares about apparent fixture size as the
// maintainer sees it, including blank padding.
function fixtureLineCount(text: string): number {
  return text.split(/\r?\n/).length;
}

// Index → line lookup support. Used by the fixture-template detector to map a byte offset to a
// (line, column) coordinate without splitting the whole source on every query.
function sourceLineStartOffsets(source: string): number[] {
  const offsets = [0];
  for (let index = 0; index < source.length; index += 1) {
    if (source[index] === "\n") {
      offsets.push(index + 1);
    }
  }
  return offsets;
}

// Walks forward from the line's start offset to find the opening backtick on that line, then
// searches for its match. Returns undefined when no template starts on the line.
function templateLiteralAtLine(source: string, lineOffsets: number[], lineNumber: number): string | undefined {
  const start = lineOffsets[lineNumber - 1];
  if (start === undefined) {
    return undefined;
  }
  const nextLineStart = lineOffsets[lineNumber] ?? source.length + 1;
  const firstBacktick = source.indexOf("`", start);
  if (firstBacktick < 0 || firstBacktick >= nextLineStart) {
    return undefined;
  }
  const end = closingTemplateLiteralIndex(source, firstBacktick + 1);
  return end === undefined ? undefined : source.slice(firstBacktick + 1, end);
}

// Linear walk respecting `\`` escapes. Does NOT handle `${…}` interpolation specially — fixture
// templates rarely contain nested backticks, and a stricter parse would not help the rule's signal.
function closingTemplateLiteralIndex(source: string, startIndex: number): number | undefined {
  let isEscaped = false;
  for (let index = startIndex; index < source.length; index += 1) {
    const character = source[index] ?? "";
    if (isEscaped) {
      isEscaped = false;
      continue;
    }
    if (character === "\\") {
      isEscaped = true;
      continue;
    }
    if (character === "`") {
      return index;
    }
  }
  return undefined;
}

// Two acceptable positions: a comment on the candidate line itself, or one directly above with
// nothing but blank lines in between. Anything farther away cannot be claimed as documentation.
function hasFixturePurposeComment(lines: string[], comments: CommentRecord[], line: number): boolean {
  const sameLine = comments.find((comment) => comment.line <= line && comment.endLine >= line);
  if (sameLine && hasFixturePurposeMarker(sameLine.text)) {
    return true;
  }
  const leading = leadingFixturePurposeComment(lines, comments, line);
  return Boolean(leading && hasFixturePurposeMarker(leading.text));
}

// Like `leadingCommentForLine` but with the fixture-specific blank-gap predicate that allows for
// slightly more spacing than the documentation-rule version.
function leadingFixturePurposeComment(lines: string[], comments: CommentRecord[], line: number): CommentRecord | undefined {
  for (let index = comments.length - 1; index >= 0; index -= 1) {
    const comment = comments[index];
    if (!comment || comment.endLine >= line) {
      continue;
    }
    if (hasOnlyBlankFixturePurposeGap(lines, comment.endLine + 1, line - 1)) {
      return comment;
    }
    return undefined;
  }
  return undefined;
}

// Identical to `hasOnlyBlankLines` but with an inclusive upper bound — fixtures may have one
// extra blank line of breathing room above them that ordinary declaration comments do not.
function hasOnlyBlankFixturePurposeGap(lines: string[], startLine: number, endLine: number): boolean {
  for (let line = startLine; line <= endLine; line += 1) {
    if ((lines[line - 1] ?? "").trim() !== "") {
      return false;
    }
  }
  return true;
}

// Vocabulary list of words a meaningful fixture-purpose comment is expected to use (fixture,
// covers, regression, baseline, fingerprint, …). Project task references count as well.
function hasFixturePurposeMarker(text: string): boolean {
  return /\b(?:fixture|covers|reproduces|regression|scanner|parse|baseline|fingerprint|noise|valid case|invalid case|because|M\d{1,3})\b/i.test(text) || /\.goat-flow\/tasks\//.test(text);
}

// Combines callable blocks and exported interfaces into one homogeneous list for the comment-quality
// rules. Test blocks are excluded because their `test("…")` description is the documentation.
function commentedDeclarations(blocks: FunctionBlock[], interfaces: ExportedDeclaration[]): CommentedDeclaration[] {
  return [
    ...blocks
      .filter((block) => !block.isTest)
      .map((block) => ({ kind: "function" as const, name: block.name, line: block.declarationLine, isPublic: block.isPublic })),
    ...interfaces.map((declaration) => ({ kind: "interface" as const, name: declaration.name, line: declaration.line, isPublic: true })),
  ];
}

/*
 * One finding per comment containing an untracked task marker. The reported marker keyword is
 * preserved in stable metadata so consumers can group by marker kind. Reports the stable
 * untracked-task-marker finding when no tracking reference is attached.
 */
function pushTodoWithoutTrackingFinding(file: SourceFile, comment: CommentRecord, findings: Finding[]): void {
  const marker = todoMarker(comment.text);
  if (!marker || hasTodoTracking(comment.text)) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "docs.todo-without-tracking",
      message: `${marker} comment is missing an issue, owner, date, ADR, or task reference.`,
      filePath: file.displayPath,
      line: comment.line,
      severity: "advisory",
      pillar: "documentation",
      confidence: "high",
      remediation: "Attach a tracking URL, issue id, owner, date, ADR, or .goat-flow task reference.",
      metadata: { marker },
    }),
  );
}

// Four canonical task-marker words, returned in uppercase so the finding message reads consistently
// regardless of how the maintainer wrote them.
function todoMarker(text: string): string | undefined {
  return text.match(/\b(TODO|FIXME|HACK|XXX)\b/i)?.[1]?.toUpperCase();
}

const TODO_TRACKING_PATTERNS = [
  /https?:\/\//i,
  /(?:^|\s)#\d+\b/,
  /\bGH-\d+\b/i,
  /\bM\d{1,3}\b/,
  /\.goat-flow\/tasks\//,
  /\bADR-\d{3}\b/i,
  /\b\d{4}-\d{2}-\d{2}\b/,
  /\bowner\s*:/i,
] as const;

// Eight accepted tracking forms (URL, #123, GH-123, M123, .goat-flow/tasks, ADR-001, ISO date,
// `owner:`). The stable set is intentionally generous so projects with different ticketing systems
// can comply without changing their conventions.
function hasTodoTracking(text: string): boolean {
  return TODO_TRACKING_PATTERNS.some((pattern) => pattern.test(text));
}

/*
 * Targets `eslint-disable`, `biome-ignore`, coverage `istanbul ignore`, etc. when no maintainer
 * rationale is attached — the false-positive escape hatch is explicit because TS suppression
 * directives have their own dedicated rule. Reports the stable `docs.suppression-without-rationale` finding.
 */
function pushSuppressionWithoutRationaleFinding(file: SourceFile, comment: CommentRecord, findings: Finding[]): void {
  const suppression = suppressionDirective(comment.text);
  if (!suppression || hasSuppressionRationale(comment.text)) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "docs.suppression-without-rationale",
      message: `${suppression} suppression is missing a maintainer rationale.`,
      filePath: file.displayPath,
      line: comment.line,
      severity: "advisory",
      pillar: "documentation",
      confidence: "medium",
      remediation: "Explain why the suppression is intentional, a false positive, or tracked elsewhere.",
      metadata: { suppression },
    }),
  );
}

// Returns the suppression keyword that triggered the rule. `@ts-*` directives are explicitly
// excluded — they have their own dedicated rule (`pushTsDirectiveFinding`).
function suppressionDirective(text: string): string | undefined {
  if (/@ts-(?:ignore|expect-error|nocheck|check)\b/.test(text)) {
    return undefined;
  }
  const match = text.match(/\b(eslint-disable(?:-next-line|-line)?|biome-ignore|oxlint-disable|istanbul ignore|c8 ignore|v8 ignore|prettier-ignore)\b/i);
  return match?.[1];
}

// Accepted rationale forms: explanatory keywords (because, intentional, false positive, tracked in),
// project task markers (M123, ADR-XXX, GH-123), explicit `reason:`, a tracking URL, or a #issue.
function hasSuppressionRationale(text: string): boolean {
  return /\b(?:because|intentional|false positive|tracked in|M\d{1,3}|ADR-\d{3}|GH-\d+)\b/i.test(text) || /\breason\s*:/i.test(text) || /(?:^|\s)#\d+\b/.test(text) || /https?:\/\//i.test(text) || /\.goat-flow\/tasks\//.test(text);
}

/*
 * Scans the comment text for path-shaped references and reports any that resolve to nothing on
 * disk. Historical-context comments (migration notes, legacy markers) are exempted on purpose
 * because they intentionally name removed files. Reports the stable `docs.stale-comment` finding.
 */
function pushStaleFileReferenceFindings(file: SourceFile, comment: CommentRecord, findings: Finding[]): void {
  if (isHistoricalContextComment(comment.text)) {
    return;
  }
  for (const match of comment.text.matchAll(/[`'"]((?:\.{1,2}\/|src\/|bin\/|scripts\/|docs\/|fixtures\/|\.goat-flow\/)[A-Za-z0-9_./-]+\.(?:ts|tsx|js|json|ya?ml|toml|md|sh))[`'"]/g)) {
    const referencedPath = match[1] ?? "";
    if (referencedPathExists(file, referencedPath)) {
      continue;
    }
    findings.push(staleCommentFinding(file, comment, `Comment references missing path \`${referencedPath}\`.`, { staleReference: referencedPath, referenceType: "path" }));
  }
}

// Tries both the project-root and same-directory interpretations because comments are inconsistent
// about which they imply. Either match is enough to consider the reference live.
function referencedPathExists(file: SourceFile, referencedPath: string): boolean {
  const fromProject = resolve(cwd(), referencedPath);
  const fromFile = resolve(dirnamePath(file.absolutePath), referencedPath);
  return existsSync(fromProject) || existsSync(fromFile);
}

/*
 * Walks every `pillar.rule-id` shape in the comment and reports those not in the descriptor set.
 * Historical-context comments stay exempt so removed rules can remain referenced in lessons text.
 * Reports the stable `docs.stale-comment` finding for each stale rule id.
 */
function pushStaleRuleReferenceFindings(file: SourceFile, comment: CommentRecord, descriptorIds: Set<string>, findings: Finding[]): void {
  if (isHistoricalContextComment(comment.text)) {
    return;
  }
  for (const match of comment.text.matchAll(/\b((?:complexity|dead-code|design|docs|modernisation|naming|security|sensitive-data|size|test-quality|waste)\.[a-z0-9-]+)\b/g)) {
    const ruleId = match[1] ?? "";
    if (descriptorIds.has(ruleId)) {
      continue;
    }
    findings.push(staleCommentFinding(file, comment, `Comment references unknown rule id \`${ruleId}\`.`, { staleReference: ruleId, referenceType: "ruleId" }));
  }
}

/*
 * Each double-dash option in a comment must appear in `cliFlags` (parsed from the CLI source) or
 * it counts as a stale reference. Historical context comments stay exempt by design. Reports the
 * stable `docs.stale-comment` finding for each unknown option name.
 */
function pushStaleCliFlagReferenceFindings(file: SourceFile, comment: CommentRecord, cliFlags: Set<string>, findings: Finding[]): void {
  if (isHistoricalContextComment(comment.text)) {
    return;
  }
  for (const match of comment.text.matchAll(/(?<![A-Za-z0-9])--[a-z][a-z0-9-]*/g)) {
    const flag = match[0] ?? "";
    if (cliFlags.has(flag)) {
      continue;
    }
    findings.push(staleCommentFinding(file, comment, `Comment references unknown CLI flag \`${flag}\`.`, { staleReference: flag, referenceType: "cliFlag" }));
  }
}

// Static list of valid CLI options. Hand-curated rather than parsed from the Commander definition
// at runtime because the stale-CLI-flag rule must not depend on import order — both files would
// otherwise have to load the analyser to power their checks.
function knownCliFlags(): Set<string> {
  return new Set([
    "--ansi",
    "--baseline",
    "--config",
    "--diff",
    "--fail-on",
    "--format",
    "--generate-baseline",
    "--help",
    "--history-file",
    "--host",
    "--include-ignored",
    "--no-ansi",
    "--no-baseline",
    "--no-config",
    "--no-interaction",
    "--output",
    "--port",
    "--project-root",
    "--quiet",
    "--silent",
    "--verbose",
    "--version",
  ]);
}

// A comment whose prose names a different symbol than the declaration directly below it. The
// historical-context escape hatch keeps migration notes (which intentionally name removed symbols)
// quiet. Reports `docs.stale-comment` with stable metadata.
function pushStaleDeclarationCommentFinding(file: SourceFile, comment: CommentRecord, declaration: CommentedDeclaration, findings: Finding[]): void {
  if (isHistoricalContextComment(comment.text)) {
    return;
  }
  const referencedName = referencedDeclarationName(comment.text, declaration.kind);
  if (!referencedName || referencedName === declaration.name) {
    return;
  }
  findings.push(staleCommentFinding(file, comment, `Comment names \`${referencedName}\` but documents \`${declaration.name}\`.`, { staleReference: referencedName, referenceType: declaration.kind, symbol: declaration.name }));
}

// Two-pass match: either `<kind> name` (e.g., "function fooBar") or leading `name <kind|helper|
// method|contract|type>`. Both forms appear in real comments and either is sufficient evidence
// that the comment intends to name a specific symbol.
function referencedDeclarationName(text: string, kind: CommentedDeclaration["kind"]): string | undefined {
  const identifier = "([A-Za-z_$][A-Za-z0-9_$]*)";
  const direct = text.match(new RegExp(["\\b", kind, "\\s+`?", identifier, "`?"].join(""), "i"));
  if (direct?.[1]) {
    return direct[1];
  }
  const leading = text.match(new RegExp(["^`?", identifier, "`?\\s+(?:", kind, "|helper|method|contract|type)\\b"].join(""), "i"));
  return leading?.[1];
}

/*
 * Public block-doc comments are exempted on purpose because their first words usually mirror the
 * API surface — that's the documented JSDoc convention, not a useless docblock. Reports the stable
 * `docs.useless-docblock` finding otherwise.
 */
function pushRestatingSignatureCommentFinding(file: SourceFile, comment: CommentRecord, declaration: CommentedDeclaration, findings: Finding[]): void {
  if (declaration.kind === "function" && declaration.isPublic && comment.kind === "block") {
    return;
  }
  if (!isRestatingSignatureComment(comment.text, declaration.name, declaration.kind)) {
    return;
  }
  findings.push(docFinding({ ruleId: "docs.useless-docblock", message: `Comment for \`${declaration.name}\` only restates the signature.`, file, line: comment.line, symbol: declaration.name }));
}

// Materialises one finding per missing context class. Each callable can theoretically produce
// four (complex, side-effect, error-behavior, invariant) — the four classes are independent signals.
// Reports each detected gap as a stable doc-context finding.
function pushFunctionContextFindings(file: SourceFile, block: FunctionBlock, comment: CommentRecord, config: Config, findings: Finding[]): void {
  for (const detail of functionContextDocFindings(block, comment.text, config)) {
    findings.push(contextDocFinding({ file, comment, ...detail }));
  }
}

// Evaluates four context classes independently — collected into a list rather than emitted directly
// so the caller can apply a single stable mapping over them.
function functionContextDocFindings(block: FunctionBlock, commentText: string, config: Config): ContextDocFindingDetails[] {
  const details: ContextDocFindingDetails[] = [];
  const body = block.codeBody;
  const complex = complexFunctionContextDocFinding(block, commentText, config);
  const sideEffect = sideEffectContextDocFinding(block, body, commentText);
  const errorBehavior = errorBehaviorContextDocFinding(block, body, commentText);
  const invariant = invariantContextDocFinding(block, commentText);
  if (complex) {
    details.push(complex);
  }
  if (sideEffect) {
    details.push(sideEffect);
  }
  if (errorBehavior) {
    details.push(errorBehavior);
  }
  if (invariant) {
    details.push(invariant);
  }
  return details;
}

// Requires "why" context only after callable complexity crosses the configured threshold.
function complexFunctionContextDocFinding(block: FunctionBlock, commentText: string, config: Config): ContextDocFindingDetails | undefined {
  if (!isComplexContextCandidate(block, config) || hasComplexWhyMarker(commentText)) {
    return undefined;
  }
  return contextDocDetails(block.name, "docs.missing-why-for-complex-code", `Complex function \`${block.name}\` has a comment, but it does not explain why the control flow exists.`, "Explain the tradeoff, compatibility reason, or invariant behind the complex control flow.", "complex-code");
}

// Documents externally observable mutations when the comment does not mention them.
function sideEffectContextDocFinding(block: FunctionBlock, body: string, commentText: string): ContextDocFindingDetails | undefined {
  if (!hasSideEffectSignal(block.name, body) || hasSideEffectMarker(commentText)) {
    return undefined;
  }
  return contextDocDetails(block.name, "docs.missing-side-effect-doc", `Function \`${block.name}\` performs side effects that its comment does not describe.`, "Name the observable side effect such as filesystem, process, environment, or network mutation.", "side-effect");
}

// Keeps thrown, diagnostic, and recovery behavior visible in maintainer comments.
function errorBehaviorContextDocFinding(block: FunctionBlock, body: string, commentText: string): ContextDocFindingDetails | undefined {
  if (!hasErrorBehaviorSignal(body) || hasErrorBehaviorMarker(commentText)) {
    return undefined;
  }
  return contextDocDetails(block.name, "docs.missing-error-behavior-doc", `Function \`${block.name}\` has error behavior that its comment does not describe.`, "Document thrown errors, diagnostics, exits, reports, or recovery behavior.", "error-behavior");
}

// Protects schema and fingerprint invariants from becoming implicit tribal knowledge.
function invariantContextDocFinding(block: FunctionBlock, commentText: string): ContextDocFindingDetails | undefined {
  if (!hasInvariantFunctionSignal(block) || hasInvariantMarker(commentText)) {
    return undefined;
  }
  return contextDocDetails(block.name, "docs.missing-invariant-doc", `Function \`${block.name}\` maintains a public contract that its comment does not describe.`, "Document the schema, fingerprint, baseline, sorting, or determinism invariant.", "invariant");
}

// Bundles the per-context-class metadata so the four detector helpers share one stable shape.
// `contextClass` is the discriminator surfaced in finding metadata.
function contextDocDetails(symbol: string, ruleId: string, message: string, remediation: string, contextClass: string): ContextDocFindingDetails {
  return {
    symbol,
    ruleId,
    message,
    remediation,
    metadata: { contextClass },
  };
}

/*
 * Interface-only context-doc rule. Skips when the comment is a signature restatement so the
 * useless-docblock rule's stable finding doesn't get duplicated by this one. Reports
 * `docs.missing-invariant-doc` for interfaces that carry public-contract signals.
 */
function pushDeclarationContextFindings(file: SourceFile, lines: string[], declaration: CommentedDeclaration, comment: CommentRecord, findings: Finding[]): void {
  if (declaration.kind !== "interface" || isRestatingSignatureComment(comment.text, declaration.name, declaration.kind)) {
    return;
  }
  if (!hasInvariantInterfaceSignal(lines, declaration) || hasInvariantMarker(comment.text)) {
    return;
  }
  findings.push(
    contextDocFinding({
      file,
      comment,
      ...contextDocDetails(declaration.name, "docs.missing-invariant-doc", `Interface \`${declaration.name}\` defines a public contract that its comment does not describe.`, "Document the schema, fingerprint, baseline, report, or determinism invariant.", "invariant"),
    }),
  );
}

// Anchors every context-doc finding at the comment line (not the declaration line) so the
// reviewer's eye lands on the documentation that needs editing. Reports a stable finding.
function contextDocFinding(input: ContextDocFindingInput): Finding {
  const { file, comment, symbol, ruleId, message, remediation, metadata } = input;
  return makeFinding({
    ruleId,
    message,
    filePath: file.displayPath,
    line: comment.line,
    severity: "advisory",
    pillar: "documentation",
    confidence: "medium",
    symbol,
    remediation,
    metadata,
  });
}

// Composite gate: any one of size, cyclomatic, cognitive, NPath, or nesting depth crossing the
// configured stable threshold qualifies a callable as "complex enough to need WHY context".
function isComplexContextCandidate(block: FunctionBlock, config: Config): boolean {
  const cyclomatic = countMatches(block.codeBody, /\b(if|else if|switch|case|for|while|catch)\b|\?|&&|\|\|/g) + 1;
  const cognitive = cyclomatic + maxNestingDepth(block.codeBody);
  const npath = approximateNpath(functionBodyContent(block.codeBody));
  return (
    block.lineCount > threshold(config, "size.function-length", 200) ||
    cyclomatic > threshold(config, "complexity.cyclomatic", 15) ||
    cognitive > threshold(config, "complexity.cognitive", 15) ||
    npath.value > threshold(config, "complexity.npath", 200) ||
    maxNestingDepth(block.codeBody) > 3
  );
}

// Vocabulary list signalling "the comment explains why" — the missing-why rule passes when any
// listed word appears. Adding entries here loosens the rule; removing them tightens it.
function hasComplexWhyMarker(text: string): boolean {
  return /\b(?:because|why|intentional|tradeoff|compat|avoid|preserve)\b/i.test(text);
}

// Vocabulary for "comment names a side effect". Pairs with `SIDE_EFFECT_BODY_PATTERNS` — if the
// body matches and none of these words appear, the missing-side-effect rule fires.
function hasSideEffectMarker(text: string): boolean {
  return /\b(?:writes|reads|persists|mutates|starts|spawns|network|filesystem|environment)\b/i.test(text);
}

// Vocabulary for "comment names error behaviour". Matches throws/reports/exits/swallows/fallback/
// recover and the multi-word "returns diagnostic". Pairs with `hasErrorBehaviorSignal`.
function hasErrorBehaviorMarker(text: string): boolean {
  return /\b(?:throws|returns diagnostic|reports|exits|swallows|fallback|recover)\b/i.test(text);
}

// Vocabulary for "comment names a public contract". Seven canonical words; the rule fires when
// the callable carries invariant signals (Finding/baseline/fingerprint references) but none of these.
function hasInvariantMarker(text: string): boolean {
  return /\b(?:invariant|contract|must|stable|deterministic|schema|fingerprint)\b/i.test(text);
}

// Vocabulary used by the magic-threshold rule. A numeric constant followed by a comment containing
// any of these words is treated as "explained".
function hasThresholdRationaleMarker(text: string): boolean {
  return /\b(?:threshold|limit|cap|budget|tuned|default|because|empirical)\b/i.test(text);
}

const SIDE_EFFECT_BODY_PATTERNS = [
  /\b(?:writeFile(?:Sync)?|appendFile(?:Sync)?|mkdir(?:Sync)?|rm(?:Sync)?|rename(?:Sync)?|createWriteStream)\s*\(/,
  /\bprocess\.chdir\s*\(/,
  /\bprocess\.env\.[A-Za-z0-9_]+\s*=/,
  /\b(?:exec|execFile|spawn)(?:Sync)?\s*\(/,
  /\b(?:response|res)\.(?:write|end|setHeader|writeHead)\s*\(/,
  /\bcreateServer\s*\(|\.listen\s*\(/,
] as const;

// Two pathways: a body pattern match (writeFile, exec, listen, response.write, …) or a name
// pattern (functions starting with write/recordHistory/startDashboard). Either is sufficient
// evidence that the callable has externally observable effects.
function hasSideEffectSignal(name: string, body: string): boolean {
  return SIDE_EFFECT_BODY_PATTERNS.some((pattern) => pattern.test(body)) || /^(?:write|recordHistory|startDashboard)\b/.test(name);
}

// Detects throw, catch, process.exit, diagnostic emission, or finding/diagnostic push patterns —
// the five places error behaviour can hide inside a callable body.
function hasErrorBehaviorSignal(body: string): boolean {
  return /\bthrow\b|\bcatch\b|\bprocess\.exit\s*\(|\bdiagnosticType\s*:|\b(?:findings|diagnostics)\.push\s*\(/.test(body);
}

// Searches both the callable name and body for vocabulary tied to the analyser's stable contracts
// (fingerprint, schemaVersion, baseline, AnalysisReport, Finding, dedupe, sort). Any match
// triggers the invariant-doc rule's expectation that the comment will name an invariant.
function hasInvariantFunctionSignal(block: FunctionBlock): boolean {
  const signalText = [block.name, block.codeBody].join("\n");
  return /\b(?:fingerprint|schemaVersion|baseline|AnalysisReport|Finding|stable sort|deterministic|dedupe|sort)\b/i.test(signalText);
}

// Same idea as `hasInvariantFunctionSignal` but reads the interface body via `declarationBlockText`.
// The contract vocabulary is slightly wider (`Baseline`, `report`) because interfaces often shape
// public report types.
function hasInvariantInterfaceSignal(lines: string[], declaration: CommentedDeclaration): boolean {
  const blockText = declarationBlockText(lines, declaration.line);
  const signalText = `${declaration.name}\n${blockText}`;
  return /\b(?:fingerprint|schemaVersion|baseline|report|Finding|AnalysisReport|Baseline|stable|deterministic)\b/i.test(signalText);
}

// Collects lines from the declaration until the first `}` at column 0 — used to feed the interface
// body to vocabulary detectors. A more precise parser would help but is unnecessary for word matches.
function declarationBlockText(lines: string[], line: number): string {
  const start = Math.max(0, line - 1);
  const collected: string[] = [];
  for (let index = start; index < lines.length; index += 1) {
    const current = lines[index] ?? "";
    collected.push(current);
    if (current.trim() === "}") {
      break;
    }
  }
  return collected.join("\n");
}

/*
 * Test files are exempt because their `expect(x).toBe(42)` patterns legitimately contain
 * unexplained numbers. For every production source line, the rule looks for either a named
 * threshold/limit/cap or a `threshold(config, …)` default call, then checks that a nearby comment
 * explains it. Reports the stable `docs.magic-threshold-without-rationale` finding.
 */
function pushMagicThresholdFindings(file: SourceFile, source: string, codeSource: string, comments: CommentRecord[], findings: Finding[]): void {
  if (isTestPath(file.displayPath)) {
    return;
  }
  const lines = source.split(/\r?\n/);
  const codeLines = codeSource.split(/\r?\n/);
  codeLines.forEach((codeLine, index) => {
    const candidate = magicThresholdCandidate(lines[index] ?? "", codeLine);
    if (!candidate || hasNearbyThresholdRationale(lines, comments, index + 1)) {
      return;
    }
    findings.push(
      makeFinding({
        ruleId: "docs.magic-threshold-without-rationale",
        message: `Threshold-like value \`${candidate.label}\` lacks a nearby rationale comment.`,
        filePath: file.displayPath,
        line: index + 1,
        severity: "advisory",
        pillar: "documentation",
        confidence: "medium",
        symbol: candidate.label,
        remediation: "Add a nearby comment explaining the threshold, limit, budget, or default.",
        metadata: { value: candidate.value, thresholdKind: candidate.kind },
      }),
    );
  });
}

// Two candidate sources: a named constant (`const maxThings = N`) or a `threshold()` default call.
// Either is treated as policy-shaped numeric — ordinary arithmetic constants stay quiet.
function magicThresholdCandidate(rawLine: string, codeLine: string): MagicThresholdCandidate | undefined {
  return namedThresholdCandidate(rawLine) ?? configDefaultThresholdCandidate(rawLine, codeLine);
}

// Identifiers ending in Threshold/Limit/Cap/Budget/Timeout/Tolerance/Weight/Score/Max/Min/Default/
// Entropy/Length signal "policy number". `-1`, `0`, `1`, `2` are exempt because they're usually sentinels.
function namedThresholdCandidate(rawLine: string): MagicThresholdCandidate | undefined {
  const named = rawLine.match(/\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*(?:Threshold|Limit|Cap|Budget|Timeout|Tolerance|Weight|Score|Max|Min|Default|Entropy|Length)[A-Za-z0-9_$]*)\b[^=\n]*=\s*(-?\d+(?:\.\d+)?)/i);
  const label = named?.[1];
  const thresholdValue = named?.[2];
  if (!label) {
    return undefined;
  }
  if (!thresholdValue || isCommonSafeNumber(thresholdValue)) {
    return undefined;
  }
  return { label, value: thresholdValue, kind: "named-threshold" };
}

// Cheap gate first: only look for the four-arg `threshold(config, "rule", "key", N)` form when the
// masked code actually contains `threshold(`. Required because labels come from raw text but the
// call shape must originate in executable code — masked code is the only stable signal for that.
function configDefaultThresholdCandidate(rawLine: string, codeLine: string): MagicThresholdCandidate | undefined {
  if (!/\bthreshold\s*\(/.test(codeLine)) {
    return undefined;
  }
  const thresholdDefault = rawLine.match(/\bthreshold\s*\([^)]*,\s*["']([^"']+)["']\s*,\s*["']([^"']+)["']\s*,\s*(-?\d+(?:\.\d+)?)\s*\)/);
  const ruleId = thresholdDefault?.[1];
  const key = thresholdDefault?.[2];
  const thresholdValue = thresholdDefault?.[3];
  if (!ruleId || !key) {
    return undefined;
  }
  if (!thresholdValue || isCommonSafeNumber(thresholdValue)) {
    return undefined;
  }
  return { label: `${ruleId}.${key}`, value: thresholdValue, kind: "config-default" };
}

// Four sentinel values that recur as "counter starts", "boolean toggle as int", and "default
// count" without being policy decisions. Anything outside this set is treated as a threshold.
function isCommonSafeNumber(value: string): boolean {
  return ["-1", "0", "1", "2"].includes(value);
}

// Two acceptable positions for the explanatory comment: same line as the constant, or directly
// above with a blank-line gap. Mirrors `hasFixturePurposeComment` adjacency rules.
function hasNearbyThresholdRationale(lines: string[], comments: CommentRecord[], line: number): boolean {
  const sameLine = comments.find((comment) => comment.line <= line && comment.endLine >= line);
  if (sameLine && hasThresholdRationaleMarker(sameLine.text)) {
    return true;
  }
  const leading = leadingCommentForLine(lines, comments, line);
  return Boolean(leading && hasThresholdRationaleMarker(leading.text));
}

// Three-tier test: useful-context vocabulary short-circuits as "not restating"; identical
// word sequences are restating; near-identical sequences (one extra trailing word) are restating.
// The result drives the `docs.useless-docblock` rule.
function isRestatingSignatureComment(text: string, name: string, kind: CommentedDeclaration["kind"]): boolean {
  if (hasUsefulCommentContext(text)) {
    return false;
  }
  const words = normalizedCommentWords(text).filter((word) => !restatementStopWords(kind).has(word)).map(stemCommentWord);
  const nameWords = splitIdentifierWords(name).map(stemCommentWord);
  if (words.length === 0) {
    return true;
  }
  if (sameWords(words, nameWords)) {
    return true;
  }
  return words.length <= nameWords.length + 1 && sameWords(words.slice(0, nameWords.length), nameWords);
}

// Strips backticks, splits on non-identifier characters, then further splits each fragment into
// identifier-style words. The flat list lets the comparator compare on a per-word basis.
function normalizedCommentWords(text: string): string[] {
  return text
    .replace(/`/g, " ")
    .replace(/[^A-Za-z0-9_$]+/g, " ")
    .trim()
    .split(/\s+/)
    .flatMap(splitIdentifierWords)
    .filter(Boolean);
}

// Stop-word list that filters out grammatical scaffolding before name comparison. Includes the
// declaration kind itself so a kind-and-name pair is judged on the name alone.
function restatementStopWords(kind: CommentedDeclaration["kind"]): Set<string> {
  return new Set(["a", "an", "the", "this", "that", "function", "method", "helper", "type", "declaration", kind]);
}

// Trailing-`s` stripping for words longer than 3 characters. Crude but adequate for restating-
// signature detection — covers `findings`/`finding`, `imports`/`import`, etc.
function stemCommentWord(word: string): string {
  return word.length > 3 && word.endsWith("s") ? word.slice(0, -1) : word;
}

// Pointwise equality between two stemmed word arrays. Used by `isRestatingSignatureComment` to
// compare the comment's first words against the declaration name's words.
function sameWords(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((word, index) => word === right[index]);
}

// The shared "this comment carries real signal" vocabulary. Any match here exempts the comment
// from the useless-docblock and stale-reference rules.
function hasUsefulCommentContext(text: string): boolean {
  return /\b(?:because|why|intentional|tradeoff|compat|avoid|preserve|invariant|contract|side effect|throws|writes|reads|persists|fallback|recover|stable|deterministic|schema|fingerprint)\b/i.test(text);
}

// Five vocabulary markers signal "this comment is intentionally about removed/old code". The
// stale-reference rules all consult this so legacy notes can keep naming removed paths/symbols.
function isHistoricalContextComment(text: string): boolean {
  return /\b(?:previously|legacy|compat|migration|ADR)\b/i.test(text);
}

// Single makeFinding factory for every stale-comment variant. `symbol` is omitted (not set to
// undefined) via conditional spread because exactOptionalPropertyTypes treats the two as different
// shapes — the omission keeps stable fingerprints round-tripping across baseline reads and writes.
function staleCommentFinding(file: SourceFile, comment: CommentRecord, message: string, metadata: Record<string, string>): Finding {
  const symbol = metadata["symbol"];
  return makeFinding({
    ruleId: "docs.stale-comment",
    message,
    filePath: file.displayPath,
    line: comment.line,
    severity: "advisory",
    pillar: "documentation",
    confidence: "medium",
    ...(symbol ? { symbol } : {}),
    remediation: "Update the comment reference or add historical context that explains why it remains useful.",
    metadata,
  });
}

// Reverse scan through the comment list — the closest comment whose `endLine < line` wins, but
// only when nothing but blank lines sits between them. Anything else means the comment documents
// a different declaration.
function leadingCommentForLine(lines: string[], comments: CommentRecord[], line: number): CommentRecord | undefined {
  for (let index = comments.length - 1; index >= 0; index -= 1) {
    const comment = comments[index];
    if (!comment || comment.endLine >= line) {
      continue;
    }
    if (hasOnlyBlankLines(lines, comment.endLine + 1, line - 1)) {
      return comment;
    }
    return undefined;
  }
  return undefined;
}

// Tighter sibling of `hasOnlyBlankFixturePurposeGap` — exclusive upper bound. Used by
// `leadingCommentForLine` to confirm no executable token sits between a comment and its declaration.
function hasOnlyBlankLines(lines: string[], startLine: number, endLine: number): boolean {
  for (let line = startLine; line < endLine; line += 1) {
    if ((lines[line - 1] ?? "").trim() !== "") {
      return false;
    }
  }
  return true;
}

// Source-text comment lexer. Produces the stable list of CommentRecords every documentation rule
// consumes. Walks the file once via the prioritised handler chain (`COMMENT_SCAN_HANDLERS`).
function commentRecords(source: string): CommentRecord[] {
  const records: CommentRecord[] = [];
  const state = initialCommentScanState();

  for (let index = 0; index < source.length; index += 1) {
    index = advanceCommentRecordScan(source, index, state, records);
  }
  return records;
}

/** Ordered comment lexer steps keep comment detection deterministic and branch-light. */
const COMMENT_SCAN_HANDLERS: CommentScanHandler[] = [
  scanCommentLineBreak,
  scanQuotedCommentStep,
  scanRegexCommentStep,
  scanCommentRecordStep,
  scanQuoteStartStep,
  scanRegexStartStep,
];

/** Runs the first lexer step that can consume the current source character. */
function advanceCommentRecordScan(source: string, index: number, state: CommentScanState, records: CommentRecord[]): number {
  for (const handler of COMMENT_SCAN_HANDLERS) {
    const nextIndex = handler(source, index, state, records);
    if (typeof nextIndex === "number") {
      return nextIndex;
    }
  }
  updateCommentScanPreviousCode(state, source[index] ?? "");
  return index;
}

/** Creates a fresh comment lexer state for a single source file scan. */
function initialCommentScanState(): CommentScanState {
  return {
    quote: undefined,
    isEscaped: false,
    isRegex: false,
    isRegexEscaped: false,
    isRegexCharClass: false,
    previousCode: "",
    line: 1,
  };
}

/** Consumes newlines and resets quote/regex state that cannot cross lines. */
function scanCommentLineBreak(source: string, index: number, state: CommentScanState): number | undefined {
  if ((source[index] ?? "") !== "\n") {
    return undefined;
  }
  advanceCommentScanLine(state);
  return index;
}

/** Advances the lexer after a newline has been consumed. */
function advanceCommentScanLine(state: CommentScanState): void {
  state.line += 1;
  if (state.quote !== "`") {
    state.quote = undefined;
  }
  state.isRegex = false;
  state.isRegexEscaped = false;
  state.isRegexCharClass = false;
}

/** Keeps quoted text from being reported as a real source comment. */
function scanQuotedCommentStep(source: string, index: number, state: CommentScanState): number | undefined {
  return scanActiveQuotedCommentState(state, source[index] ?? "") ? index : undefined;
}

/** Updates quote escape/close state when the lexer is inside a string. */
function scanActiveQuotedCommentState(state: CommentScanState, character: string): boolean {
  if (!state.quote) {
    return false;
  }
  const nextState = scanQuotedCommentCharacter(character, state.quote, state.isEscaped);
  state.quote = nextState.quote;
  state.isEscaped = nextState.isEscaped;
  return true;
}

/** Keeps regex literal bodies from being reported as real source comments. */
function scanRegexCommentStep(source: string, index: number, state: CommentScanState): number | undefined {
  return scanActiveRegexCommentState(state, source[index] ?? "") ? index : undefined;
}

/** Updates regex escape, character-class, and close state. */
function scanActiveRegexCommentState(state: CommentScanState, character: string): boolean {
  if (!state.isRegex) {
    return false;
  }
  const nextState = scanRegexCommentCharacter(character, state.isRegexEscaped, state.isRegexCharClass);
  state.isRegex = nextState.isRegex;
  state.isRegexEscaped = nextState.isEscaped;
  state.isRegexCharClass = nextState.isCharClass;
  return true;
}

/** Records a line or block comment and returns the consumed source index. */
function scanCommentRecordStep(source: string, index: number, state: CommentScanState, records: CommentRecord[]): number | undefined {
  const record = commentRecordAt(source, index, state.line);
  if (!record) {
    return undefined;
  }
  records.push(record);
  state.line = record.endLine;
  return record.kind === "line" ? record.endIndex - 1 : record.endIndex;
}

/** Detects whether the current slash pair begins a source comment. */
function commentRecordAt(source: string, index: number, line: number): CommentRecord | undefined {
  const character = source[index] ?? "";
  const next = source[index + 1] ?? "";
  if (character === "/" && next === "/") {
    return lineCommentRecord(source, index, line);
  }
  if (character === "/" && next === "*") {
    return blockCommentRecord(source, index, line);
  }
  return undefined;
}

/** Opens string/template quote state when the current character starts a literal. */
function scanQuoteStartStep(source: string, index: number, state: CommentScanState): number | undefined {
  return openCommentScanQuote(state, source[index] ?? "") ? index : undefined;
}

/** Mutates quote state after a quote-start character is found. */
function openCommentScanQuote(state: CommentScanState, character: string): boolean {
  if (character !== "\"" && character !== "'" && character !== "`") {
    return false;
  }
  state.quote = character;
  state.isEscaped = false;
  state.previousCode = character;
  return true;
}

/** Opens regex state for slash tokens that follow expression-start syntax. */
function scanRegexStartStep(source: string, index: number, state: CommentScanState): number | undefined {
  return openCommentScanRegex(state, source, index, source[index] ?? "") ? index : undefined;
}

/** Mutates regex state after a regex literal start is found. */
function openCommentScanRegex(state: CommentScanState, source: string, index: number, character: string): boolean {
  if (character !== "/" || !isCommentRegexStart(state.previousCode, source.slice(Math.max(0, index - 40), index))) {
    return false;
  }
  state.isRegex = true;
  state.isRegexEscaped = false;
  state.isRegexCharClass = false;
  state.previousCode = character;
  return true;
}

/** Remembers the last non-whitespace code token for regex/comment disambiguation. */
function updateCommentScanPreviousCode(state: CommentScanState, character: string): void {
  if (/\S/.test(character)) {
    state.previousCode = character;
  }
}

// Pure function returning the next quote state. Pure because callers thread the state explicitly,
// which keeps the comment-lexer testable in isolation from the surrounding mutation.
function scanQuotedCommentCharacter(character: string, quote: string, isEscaped: boolean): { quote: string | undefined; isEscaped: boolean } {
  if (isEscaped) {
    return { quote, isEscaped: false };
  }
  if (character === "\\") {
    return { quote, isEscaped: true };
  }
  if (character === quote) {
    return { quote: undefined, isEscaped: false };
  }
  return { quote, isEscaped: false };
}

// Pure step that yields the next regex state. Same isolation pattern as `scanQuotedCommentCharacter`.
function scanRegexCommentCharacter(character: string, isEscaped: boolean, isCharClass: boolean): { isRegex: boolean; isEscaped: boolean; isCharClass: boolean } {
  if (isEscaped) {
    return { isRegex: true, isEscaped: false, isCharClass };
  }
  if (character === "\\") {
    return { isRegex: true, isEscaped: true, isCharClass };
  }
  if (character === "[") {
    return { isRegex: true, isEscaped: false, isCharClass: true };
  }
  if (character === "]") {
    return { isRegex: true, isEscaped: false, isCharClass: false };
  }
  if (character === "/" && !isCharClass) {
    return { isRegex: false, isEscaped: false, isCharClass: false };
  }
  return { isRegex: true, isEscaped: false, isCharClass };
}

// Same regex-vs-division heuristic as `source-text.ts:isRegexLiteralStart`. Duplicated here so the
// comment lexer stays a leaf with no cross-module dependency on the masking pass.
function isCommentRegexStart(previousCode: string, beforeSlash: string): boolean {
  return previousCode === "" || "([{=,:!&|?;".includes(previousCode) || /\breturn$/.test(beforeSlash.trimEnd());
}

// Line-comment record. `line === endLine` because line comments cannot span newlines. Text is
// captured trimmed so leading/trailing whitespace doesn't enter rule comparisons.
function lineCommentRecord(source: string, startIndex: number, line: number): CommentRecord {
  const newline = source.indexOf("\n", startIndex + 2);
  const endIndex = newline === -1 ? source.length : newline;
  return {
    kind: "line",
    text: source.slice(startIndex + 2, endIndex).trim(),
    line,
    endLine: line,
    startIndex,
    endIndex,
  };
}

// Block-comment record. `endLine > line` is normal for multi-line blocks. `text` is normalised
// (leading-asterisk decoration stripped) so JSDoc-style and plain-block comments compare equally.
function blockCommentRecord(source: string, startIndex: number, line: number): CommentRecord {
  let endIndex = source.length - 1;
  let endLine = line;
  for (let index = startIndex + 2; index < source.length; index += 1) {
    if (source[index] === "\n") {
      endLine += 1;
    }
    if (source[index] === "*" && source[index + 1] === "/") {
      endIndex = index + 1;
      break;
    }
  }
  return {
    kind: "block",
    text: normalizedBlockCommentText(source.slice(startIndex + 2, Math.max(startIndex + 2, endIndex - 1))),
    line,
    endLine,
    startIndex,
    endIndex,
  };
}

// Strips the `* ` JSDoc-style line decoration so `/** foo */`, `/* foo */`, and `// foo` all
// produce the same `text` payload for rule comparison.
function normalizedBlockCommentText(text: string): string {
  return text
    .split(/\r?\n/)
    .map((line) => line.replace(/^[ \t]*\*[ \t]?/, "").trim())
    .filter((line) => line !== "")
    .join(" ")
    .trim();
}

/*
 * Compares normalised forms (lowercased, no underscores) so `UserProfile` and `user-profile.ts`
 * match. Reports the stable `naming.class-file-mismatch` finding when the exported class diverges
 * from the file name.
 */
function pushClassFileMismatchFinding(file: SourceFile, declaration: ExportedDeclaration, findings: Finding[]): void {
  const fileName = fileBaseName(file.displayPath);
  if (declaration.kind !== "class" || normalizedIdentifier(declaration.name) === normalizedIdentifier(fileName)) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "naming.class-file-mismatch",
      message: `Exported class \`${declaration.name}\` does not match file name \`${fileName}\`.`,
      filePath: file.displayPath,
      line: declaration.line,
      severity: "advisory",
      pillar: "naming",
      confidence: "medium",
      symbol: declaration.name,
      remediation: "Rename the class or file so the primary export is easy to locate.",
      metadata: { className: declaration.name, fileName },
    }),
  );
}

// Targets `public foo =` and `public foo:` patterns. The rule message recommends `readonly` or
// accessors because both preserve the field's invariant better than a raw public field, and
// reports each match as a stable `modernisation.public-property` finding.
function analysePublicProperties(file: SourceFile, source: string, codeSource: string, findings: Finding[]): void {
  const publicProperty = /\bpublic\s+[A-Za-z_$][A-Za-z0-9_$]*\s*[=:]/g;
  for (const match of codeSource.matchAll(publicProperty)) {
    findings.push(finding({ ruleId: "modernisation.public-property", message: "Public class property exposes representation; prefer readonly or accessors when invariants matter.", file, line: byteLine(source, match.index ?? 0), severity: "advisory", pillar: "modernisation" }));
  }
}

// Visibility-modifier fields without `readonly`. The negative lookahead skips already-readonly
// properties; each remaining match reports a stable `modernisation.readonly-property-candidate`.
function analyseReadonlyCandidates(file: SourceFile, source: string, codeSource: string, findings: Finding[]): void {
  const readonlyCandidate = /\b(?:public|private|protected)\s+(?!readonly\b)([A-Za-z_$][A-Za-z0-9_$]*)\s*:\s*[^;=\n]+;/g;
  for (const match of codeSource.matchAll(readonlyCandidate)) {
    const name = match[1] ?? "";
    findings.push(
      makeFinding({
        ruleId: "modernisation.readonly-property-candidate",
        message: `Property \`${name}\` can be marked readonly if it is only assigned during construction.`,
        filePath: file.displayPath,
        line: byteLine(source, match.index ?? 0),
        severity: "advisory",
        pillar: "modernisation",
        confidence: "medium",
        symbol: name,
        remediation: "Mark the property readonly when mutation is not part of the type contract.",
      }),
    );
  }
}

// Precomputed JSDoc + signature pair used by every docblock rule (stale-param, missing-param,
// missing-return, useless-docblock) so the parser runs only once per source file.
interface DocumentedExportBlock {
  doc: string;
  name: string;
  params: string[];
  paramTags: string[];
  line: number;
  returnType: string;
}

// Argument bundle shared by every docblock-related finding builder. `parameter` is optional
// because some docblock rules anchor on the symbol alone, not a specific parameter.
interface DocFindingInput {
  ruleId: string;
  message: string;
  file: SourceFile;
  line: number;
  symbol: string;
  parameter?: string;
}

// Four docblock rules in fixed emission order: stale param, missing param, missing return,
// useless docblock. Reordering would shift the deterministic fingerprint contract without any
// real behaviour change, so this loop is part of the stable analyzer schema.
function analyseDocRules(file: SourceFile, source: string, codeSource: string, findings: Finding[]): void {
  for (const documentedExport of documentedExportBlocks(source, codeSource)) {
    pushStaleParamFindings(file, documentedExport, findings);
    pushMissingParamFindings(file, documentedExport, findings);
    pushMissingReturnFinding(file, documentedExport, findings);
    pushUselessDocblockFinding(file, documentedExport, findings);
  }
}

// Walks every `/** … */ export function …` pair in the source. Skips matches whose `export`
// keyword is inside a string/regex by confirming it shows up in the masked code as well.
function documentedExportBlocks(source: string, codeSource: string): DocumentedExportBlock[] {
  const blocks: DocumentedExportBlock[] = [];
  const documentedExport = /\/\*\*((?:(?!\*\/)[\s\S])*?)\*\/\s*export\s+function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)\s*(?::\s*([^\x7b\n]+))?/g;
  for (const match of source.matchAll(documentedExport)) {
    const block = documentedExportBlock(source, codeSource, match);
    if (block) {
      blocks.push(block);
    }
  }
  return blocks;
}

// Promotes a regex match into the structured block consumed by docblock rules. Returns undefined
// when the matched `export` keyword is actually inside a string literal in the masked source.
function documentedExportBlock(source: string, codeSource: string, match: RegExpMatchArray): DocumentedExportBlock | undefined {
  const matchStart = regexMatchStart(match);
  const exportIndex = source.indexOf("export", matchStart);
  if (!isDocumentedExportInCode(codeSource, exportIndex)) {
    return undefined;
  }
  const doc = regexGroup(match, 1);
  return {
    doc,
    name: regexGroup(match, 2),
    params: parameterNames(regexGroup(match, 3)).map((parameter) => parameter.name),
    paramTags: docParamTags(doc),
    line: byteLine(source, matchStart),
    returnType: regexGroup(match, 4).trim(),
  };
}

// `index ?? 0` adapter for the standard regex API — match.index is technically optional under
// strict TypeScript even though every real match has it.
function regexMatchStart(match: RegExpMatchArray): number {
  return match.index ?? 0;
}

// `match[index] ?? ""` adapter — keeps callers from sprinkling default-empty handling.
function regexGroup(match: RegExpMatchArray, index: number): string {
  return match[index] ?? "";
}

// Confirms the captured `export` keyword is in real code, not inside a masked comment or string.
// The mask preserves the first letter of code tokens, so checking for `e` is sufficient.
function isDocumentedExportInCode(codeSource: string, exportIndex: number): boolean {
  return exportIndex >= 0 && codeSource[exportIndex] === "e";
}

// Walks every docblock `@param tagName` that no longer matches a real parameter. Each orphan
// reports a stable `docs.stale-param-tag` finding with `parameter` metadata in the payload.
function pushStaleParamFindings(file: SourceFile, block: DocumentedExportBlock, findings: Finding[]): void {
  for (const tag of block.paramTags) {
    if (!block.params.includes(tag)) {
      findings.push(docFinding({ ruleId: "docs.stale-param-tag", message: `Docblock for \`${block.name}\` has stale @param tag \`${tag}\`.`, file, line: block.line, symbol: block.name, parameter: tag }));
    }
  }
}

// Each parameter declared in the signature must have a matching `@param` tag in the docblock.
// Reports the stable `docs.missing-param-tag` finding for each orphan.
function pushMissingParamFindings(file: SourceFile, block: DocumentedExportBlock, findings: Finding[]): void {
  for (const param of block.params) {
    if (!block.paramTags.includes(param)) {
      findings.push(docFinding({ ruleId: "docs.missing-param-tag", message: `Docblock for \`${block.name}\` is missing @param for \`${param}\`.`, file, line: block.line, symbol: block.name, parameter: param }));
    }
  }
}

// `@returns` only required when the signature declares a non-void return type. `void` is exempt
// because documenting "returns nothing" is noise. Reports the stable `docs.missing-return-tag`.
function pushMissingReturnFinding(file: SourceFile, block: DocumentedExportBlock, findings: Finding[]): void {
  if (!needsReturnTag(block)) {
    return;
  }
  findings.push(docFinding({ ruleId: "docs.missing-return-tag", message: `Docblock for \`${block.name}\` is missing @returns.`, file, line: block.line, symbol: block.name }));
}

// Three conditions: a declared return type exists, it isn't void, and the docblock doesn't already
// have a `@returns` tag. Annotation-less and void returns are exempt.
function needsReturnTag(block: DocumentedExportBlock): boolean {
  return block.returnType !== "" && !/^void\b/.test(block.returnType) && !/@returns?\b/.test(block.doc);
}

// Docblock-flavoured useless-docblock rule. Targets `/** Foo */ export function foo` shapes
// that fail the same restate test as line-comment docs, then reports a stable `docs.useless-docblock`.
function pushUselessDocblockFinding(file: SourceFile, block: DocumentedExportBlock, findings: Finding[]): void {
  if (isUselessDocblock(block.doc, block.name)) {
    findings.push(docFinding({ ruleId: "docs.useless-docblock", message: `Docblock for \`${block.name}\` only restates the signature.`, file, line: block.line, symbol: block.name }));
  }
}

// Single makeFinding factory for every docblock-rule finding. `parameter` is omitted (not set to
// undefined) under exactOptionalPropertyTypes so the metadata shape stays stable and each
// baseline fingerprint round-trips cleanly across runs.
function docFinding(input: DocFindingInput): Finding {
  return makeFinding({
    ruleId: input.ruleId,
    message: input.message,
    filePath: input.file.displayPath,
    line: input.line,
    severity: "advisory",
    pillar: "documentation",
    confidence: "medium",
    symbol: input.symbol,
    remediation: "Update the JSDoc so it documents the current signature and return value.",
    metadata: { ...(input.parameter ? { parameter: input.parameter } : {}) },
  });
}

// Single-file unused-private-method scan. Counts `name(` occurrences and reports when the only
// occurrence is the declaration itself — confidence stays `low` because subclass overrides or
// reflection callers can hide real usage. Reports `dead-code.unused-private-method` with stable anchors.
function analyseDeadCode(file: SourceFile, source: string, findings: Finding[]): void {
  for (const match of source.matchAll(/\bprivate\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/g)) {
    const name = match[1] ?? "";
    if (countMatches(source, new RegExp(`${escapeRegex(name)}\\s*\\(`, "g")) <= 1) {
      findings.push(
        makeFinding({
          ruleId: "dead-code.unused-private-method",
          message: `Private method \`${name}\` appears to be unused in this file.`,
          filePath: file.displayPath,
          line: byteLine(source, match.index ?? 0),
          severity: "advisory",
          pillar: "dead-code",
          confidence: "low",
          symbol: name,
          remediation: "Remove the method or add a real call site.",
        }),
      );
    }
  }
}

// Line-by-line walker that resets the terminator flag at every `case:` / `default:` so dead-code
// detection respects control-flow boundaries. Each line is walked once in source order, then
// reports `waste.unreachable-code` with stable, deterministic fingerprint anchors.
function analyseUnreachable(file: SourceFile, source: string, findings: Finding[]): void {
  let didPreviousTerminate = false;
  source.split(/\r?\n/).forEach((line, index) => {
    const trimmed = line.trim();
    const branchLabel = isBranchLabel(trimmed);
    if (branchLabel) {
      didPreviousTerminate = false;
    }
    if (isUnreachableStatement(trimmed, didPreviousTerminate, branchLabel)) {
      findings.push(finding({ ruleId: "waste.unreachable-code", message: "Statement appears after a terminating statement.", file, line: index + 1, severity: "warning", pillar: "waste" }));
    }
    didPreviousTerminate = isTerminatingStatement(trimmed);
  });
}

// `case X:` / `default:` open a new control path, so the unreachable walker must reset its
// terminator flag here — otherwise the first statement in a fallthrough case looks dead.
function isBranchLabel(trimmedLine: string): boolean {
  return /^(?:case\b.*:|default\s*:)$/.test(trimmedLine);
}

// Three conditions must hold to flag a line: the prior statement terminated, this line has real
// content, and it's not a `}` closer or a branch label. The `}` exclusion matters because the
// closing brace of the terminating block looks like a statement to a naive walker.
function isUnreachableStatement(trimmedLine: string, didPreviousTerminate: boolean, branchLabel: boolean): boolean {
  return didPreviousTerminate && /\S/.test(trimmedLine) && !trimmedLine.startsWith(String.fromCharCode(125)) && !branchLabel;
}

// `return`, `throw`, and `process.exit(...)` exit the current control path. The trailing `;`
// requirement filters out expressions like `return foo()` split across lines — without it the
// walker would falsely flag the continuation as unreachable.
function isTerminatingStatement(trimmedLine: string): boolean {
  return /^(?:return|throw|process\.exit)\b/.test(trimmedLine) && trimmedLine.endsWith(";");
}

// Reports `waste.unused-import` for every named specifier whose local name appears nowhere else
// in the file. Default imports and namespace imports are out of scope because the regex anchors
// on `{ … }`; walking lines in source order keeps the reports stable and deterministic.
function analyseUnusedImports(file: SourceFile, source: string, findings: Finding[]): void {
  const lines = source.split(/\r?\n/);
  for (const [index, line] of lines.entries()) {
    for (const specifier of namedImportSpecifiers(line)) {
      const name = unusedImportName(source, specifier);
      if (!name) {
        continue;
      }
      findings.push(unusedImportFinding(file, name, index + 1));
    }
  }
}

// Slices the `{ a, b as c }` body out of a named-import line and splits on commas. No AST: a
// regex-light approach is sufficient because `analyseUnusedImports` runs after the comment mask,
// so commas inside string defaults never reach this function.
function namedImportSpecifiers(line: string): string[] {
  const trimmed = line.trim();
  if (!isNamedImportLine(trimmed)) {
    return [];
  }
  const openBrace = trimmed.indexOf(String.fromCharCode(123));
  const closeBrace = trimmed.indexOf(String.fromCharCode(125), openBrace + 1);
  if (!hasNamedImportBraces(openBrace, closeBrace)) {
    return [];
  }
  return trimmed.slice(openBrace + 1, closeBrace).split(",");
}

// `import … from "…"` shape gate. `from` must be present — bare side-effect imports like
// `import "./polyfill"` have no named specifiers to analyse and are excluded here.
function isNamedImportLine(trimmedLine: string): boolean {
  return trimmedLine.startsWith("import ") && trimmedLine.includes(" from ");
}

// Both braces present and well-ordered. Indexes come from raw `indexOf` calls, so this guards
// against the malformed slice that would otherwise feed an empty or reversed specifier list.
function hasNamedImportBraces(openBrace: number, closeBrace: number): boolean {
  return openBrace !== -1 && closeBrace !== -1 && closeBrace > openBrace;
}

// The local binding (after `as`, if present) must appear in the source exactly once — the
// declaration itself. More than one match means the import is referenced somewhere and is not
// dead; returning undefined suppresses the finding.
function unusedImportName(source: string, specifier: string): string | undefined {
  const name = localImportName(specifier);
  if (!name || countMatches(source, new RegExp(`\\b${escapeRegex(name)}\\b`, "g")) > 1) {
    return undefined;
  }
  return name;
}

// Single makeFinding factory for `waste.unused-import`. The local binding name lands in both the
// message and `metadata.importName` so downstream tooling can group by symbol while the stable
// fingerprint identity remains (ruleId, filePath, line).
function unusedImportFinding(file: SourceFile, name: string, line: number): Finding {
  return makeFinding({
    ruleId: "waste.unused-import",
    message: `Imported symbol \`${name}\` does not appear to be used.`,
    filePath: file.displayPath,
    line,
    severity: "advisory",
    pillar: "waste",
    confidence: "medium",
    symbol: name,
    remediation: "Remove the unused import.",
    metadata: { importName: name },
  });
}

// Returns the right-hand side of `as` when present, otherwise the specifier itself. The trailing
// identifier regex protects against type-only specifiers that include extra tokens.
function localImportName(specifier: string): string | undefined {
  const parts = specifier.trim().split(/\s+as\s+/);
  const candidate = parts[1] ?? parts[0] ?? "";
  const match = candidate.trim().match(/^[A-Za-z_$][A-Za-z0-9_$]*/);
  return match?.[0];
}

// Approximation: each decision keyword (`if`, `case`, `catch`, loops) and short-circuit operator
// doubles the count. Optional chaining is stripped first so `a?.b` and `??` don't inflate the
// signal. Capped at `NPATH_CAP` — the `capped` flag tells callers to report the value as ≥, not =.
function approximateNpath(source: string): NpathResult {
  let pathCount = 1;
  let isCapped = false;
  const normalized = source.replace(/\?\./g, "").replace(/\?\?/g, "");
  const decisionCount = countMatches(normalized, /\b(if|else if|case|catch|for|while)\b|\?|&&|\|\|/g);
  for (let index = 0; index < decisionCount; index += 1) {
    pathCount *= 2;
    if (pathCount >= NPATH_CAP) {
      pathCount = NPATH_CAP;
      isCapped = true;
      break;
    }
  }
  return { value: pathCount, capped: isCapped };
}

// Strips line and block comments before measuring — a body containing only documentation is still
// considered empty for the `waste.empty-function` check, since no executable statements run.
function isEmptyFunctionBody(source: string): boolean {
  const body = functionBodyContent(source)
    .replace(/\/\/.*$/gm, "")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .trim();
  return body === "";
}

// Two shapes: block-body callables return the text between the outermost `{` and `}`; expression
// arrow functions fall back to the slice after `=>`. The trailing-`;` strip keeps the arrow
// branch usable for downstream regex tests that anchor on statement boundaries.
function functionBodyContent(source: string): string {
  const start = source.indexOf("{");
  const end = source.lastIndexOf("}");
  if (start === -1 || end <= start) {
    const arrow = source.indexOf("=>");
    return arrow === -1 ? "" : source.slice(arrow + 2).replace(/;?\s*$/, "");
  }
  return source.slice(start + 1, end);
}

// Walks upward past blank lines and the closing `}` looking for a final `return;`. Returns the
// line offset of that statement (zero-based) or an empty list if the last real line is anything
// else — used by `waste.redundant-variable` so the finding anchors on the actual statement.
function terminalBareReturnLines(source: string): number[] {
  const lines = source.split(/\r?\n/);
  let current = lines.length - 1;
  while (current >= 0) {
    const trimmed = lines[current]?.trim() ?? "";
    if (trimmed === "" || trimmed === "}") {
      current -= 1;
      continue;
    }
    return /^return\s*;?$/.test(trimmed) ? [current] : [];
  }
  return [];
}

// Splits on `,` then strips visibility modifiers, `...rest`, default values, and type annotations
// in that order. Final filter rejects entries whose name isn't a plain identifier — destructured
// parameters land in that bucket and are intentionally invisible to per-parameter rules.
function parameterNames(params: string): Array<{ name: string; raw: string }> {
  return params
    .split(",")
    .map((parameter) => parameter.trim())
    .filter(Boolean)
    .map((raw) => {
      const stripped = raw.replace(/^(?:public|private|protected|readonly)\s+/, "").replace(/^\.\.\./, "");
      const name = stripped.split(/[?:=]/)[0]?.trim() ?? "";
      return { name, raw: stripped };
    })
    .filter((parameter) => /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(parameter.name));
}

// Detects the `const x = expr; return x;` pattern. The regex backreference `\1` enforces that the
// returned identifier matches the declared one — used by `waste.redundant-variable` to surface
// pointless temporaries with deterministic line offsets.
function redundantVariableReturns(source: string): Array<{ name: string; lineOffset: number }> {
  const results: Array<{ name: string; lineOffset: number }> = [];
  for (const match of source.matchAll(/\b(?:const|let)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*[^;]+;\s*return\s+\1\s*;/g)) {
    results.push({ name: match[1] ?? "", lineOffset: lineOffset(source, match.index ?? 0) });
  }
  return results.filter((result) => result.name !== "");
}

// Counts newlines before the offset to get a 0-based line number. `Math.max(0, …)` guards against
// negative input — callers occasionally pass `match.index` which is typed as optional.
function lineOffset(source: string, index: number): number {
  return source.slice(0, Math.max(0, index)).split("\n").length - 1;
}

// Two-stage detector for `waste.commented-out-code`: first checks for a leading code keyword
// (`const`, `function`, `if`, etc.), then falls back to a `foo()` / `foo.bar()` call shape.
// The keyword list is intentionally conservative to avoid flagging prose that starts with `if`.
function isCommentedOutCode(line: string): boolean {
  const trimmed = line.trim();
  if (!trimmed.startsWith("//")) {
    return false;
  }
  const uncommented = trimmed.replace(/^\/\/+\s?/, "");
  if (/^(const|let|var|function|class|interface|type|enum|import|export|if|for|while|switch|return|throw|await)\b/.test(uncommented)) {
    return true;
  }
  return /^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)?\s*\([^)]*\);?$/.test(uncommented);
}

// Returns `"generic"` for low-information names from the configured set, `"numbered"` for
// `foo1` / `bar2` style trailing-digit identifiers, or undefined when the name is acceptable.
// The variant string lands in finding metadata so consumers can split the two failure modes.
function identifierQualityVariant(name: string, placeholderNames: Set<string>): string | undefined {
  if (placeholderNames.has(name.toLowerCase())) {
    return "generic";
  }
  if (/^[A-Za-z_$]+[0-9]+$/.test(name)) {
    return "numbered";
  }
  return undefined;
}

const BOOLEAN_PREFIX_REGEX_CACHE = new WeakMap<Set<string>, RegExp | null>();
const HUNGARIAN_PREFIX_REGEX_CACHE = new WeakMap<Set<string>, RegExp | null>();

// Tests the cached prefix regex from `booleanPrefixRegex`. A null regex (empty prefix set) is
// treated as "no rule configured" so the boolean-prefix check fires only when configured.
function hasBooleanPrefix(name: string, prefixes: Set<string>): boolean {
  const regex = booleanPrefixRegex(prefixes);
  return regex !== null && regex.test(name);
}

// Cached per prefix Set via a WeakMap so each rule pass reuses the compiled regex instead of
// rebuilding it for every identifier. The trailing `[A-Z_]` requirement keeps single-letter
// names like `is` from falsely matching the prefix-followed-by-name pattern.
function booleanPrefixRegex(prefixes: Set<string>): RegExp | null {
  if (BOOLEAN_PREFIX_REGEX_CACHE.has(prefixes)) {
    return BOOLEAN_PREFIX_REGEX_CACHE.get(prefixes) ?? null;
  }
  const regex = prefixes.size === 0 ? null : new RegExp(`^(?:${[...prefixes].map(escapeRegex).join("|")})[A-Z_]`);
  BOOLEAN_PREFIX_REGEX_CACHE.set(prefixes, regex);
  return regex;
}

// Counterpart to `booleanPrefixRegex` for the `naming.hungarian-notation` rule. Returns a global
// regex (callers iterate matches) anchored to declaration keywords + visibility modifiers, so a
// reference to `IUser` inside a comment is not flagged — the regex is part of the stable contract.
function hungarianPrefixRegex(prefixes: Set<string>): RegExp | null {
  if (HUNGARIAN_PREFIX_REGEX_CACHE.has(prefixes)) {
    return HUNGARIAN_PREFIX_REGEX_CACHE.get(prefixes) ?? null;
  }
  const regex = prefixes.size === 0 ? null : new RegExp(`\\b(?:const|let|var|public|private|protected)\\s+((?:${[...prefixes].map(escapeRegex).join("|")})[A-Z][A-Za-z0-9_$]*)`, "g");
  HUNGARIAN_PREFIX_REGEX_CACHE.set(prefixes, regex);
  return regex;
}

// Strips directory and trailing extension. Used by `naming.class-file-mismatch` so the exported
// symbol name and the file stem normalise to the same shape — both sides must agree on this
// canonical form for the deterministic comparison to be meaningful.
function fileBaseName(path: string): string {
  return basename(path).replace(/\.[^.]+$/, "");
}

// Lowercase-and-strip-separators canonical form. Treats `FooBar`, `foo_bar`, and `foo-bar` as
// the same key so naming rules can compare across case styles without baking the convention in.
function normalizedIdentifier(value: string): string {
  return value.replace(/[^A-Za-z0-9]/g, "").toLowerCase();
}

// Pulls every `@param name` tag's name from a docblock. Order is preserved so callers can spot
// duplicate tags by simple list comparison rather than set membership.
function docParamTags(doc: string): string[] {
  const names: string[] = [];
  for (const line of doc.split(/\r?\n/)) {
    const name = docParamTagName(line);
    if (name) {
      names.push(name);
    }
  }
  return names;
}

// Skips the `{Type}` braces before reading the identifier. The two-step approach lets the type
// portion be arbitrarily complex (unions, generics) without breaking the identifier extraction.
function docParamTagName(line: string): string | undefined {
  const marker = line.indexOf("@param");
  if (marker === -1) {
    return undefined;
  }
  const rest = stripDocParamType(line.slice(marker + "@param".length).trim());
  return rest.match(/^([A-Za-z_$][A-Za-z0-9_$]*)/)?.[1];
}

// Removes a leading `{Type}` cluster from a `@param` tag tail. Returns the empty string when the
// braces are unbalanced — a malformed tag should not contribute a phantom parameter name.
function stripDocParamType(rest: string): string {
  if (!rest.startsWith(String.fromCharCode(123))) {
    return rest;
  }
  const end = rest.indexOf(String.fromCharCode(125));
  return end === -1 ? "" : rest.slice(end + 1).trim();
}

// Normalises the docblock to its lowercase word run and compares against the symbol's expanded
// word list. Empty docblocks are considered useless; the equality fallback on
// `normalizedIdentifier` catches the case where punctuation alone separates the two.
function isUselessDocblock(doc: string, symbol: string): boolean {
  const words = doc
    .split(/\r?\n/)
    .map((line) => line.replace(/^\s*\*\s?/, "").trim())
    .filter((line) => line !== "" && !line.startsWith("@"))
    .join(" ")
    .toLowerCase()
    .replace(/[^a-z0-9 ]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (!words) {
    return true;
  }
  return words === splitIdentifierWords(symbol).join(" ") || normalizedIdentifier(words) === normalizedIdentifier(symbol);
}

// Inserts a space at every camelCase boundary, then splits on any non-alphanumeric run. Acronym
// runs (`HTTPServer`) stay intact because the inserted boundary is `lower → Upper`, not
// `Upper → Upper` — callers comparing word lists rely on this to keep tokens aligned.
function splitIdentifierWords(value: string): string[] {
  return value
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .split(/[^A-Za-z0-9]+/)
    .map((word) => word.toLowerCase())
    .filter(Boolean);
}

// Aggregator over the three trivial-assertion shapes — literal-comparison, mirrored-`assert`
// arguments, mirrored-`expect` arguments. Splitting the checks keeps each regex focused and
// debuggable while this top-level keeps the call site for `test-quality.trivial-assertion` short.
function hasTrivialAssertion(source: string): boolean {
  return hasLiteralTrivialAssertion(source) || hasRepeatedAssertArgument(source) || hasRepeatedExpectArgument(source);
}

// Targets `assert.ok(true)` and `assert.equal(literal, sameLiteral)` shapes — both prove nothing
// at runtime. The backreference `\1` is what makes the second pattern detect mirrored literals
// across the supported `equal` / `strictEqual` / `deepEqual` variants.
function hasLiteralTrivialAssertion(source: string): boolean {
  return (
    /\bassert\.ok\s*\(\s*true\s*\)/.test(source) ||
    /\bassert\.(?:equal|strictEqual|deepEqual)\s*\(\s*(true|false|null|undefined|\d+|["'][^"']*["'])\s*,\s*\1\s*\)/.test(source)
  );
}

// Walks every `assert.equal(a, b)` call and normalises both arguments before comparison so that
// `foo;` and `foo` collapse to the same key. Mirrored expressions indicate the assertion would
// pass regardless of behaviour — reports as a trivial assertion.
function hasRepeatedAssertArgument(source: string): boolean {
  for (const match of source.matchAll(/\bassert\.(?:equal|strictEqual|deepEqual)\s*\(\s*([^,\n]+?)\s*,\s*([^,\n)]+?)(?:\s*,|\s*\))/g)) {
    if (normalizeAssertionExpression(match[1] ?? "") === normalizeAssertionExpression(match[2] ?? "")) {
      return true;
    }
  }
  return false;
}

// Jest/Vitest counterpart to `hasRepeatedAssertArgument`. Targets `expect(a).toBe(b)` and the
// equality variants; the matcher set is intentionally narrow so async / negation forms don't
// produce false positives on argument equality.
function hasRepeatedExpectArgument(source: string): boolean {
  for (const match of source.matchAll(/\bexpect\s*\(\s*([^)]+?)\s*\)\s*\.\s*to(?:Be|Equal|StrictEqual)\s*\(\s*([^)]+?)\s*\)/g)) {
    if (normalizeAssertionExpression(match[1] ?? "") === normalizeAssertionExpression(match[2] ?? "")) {
      return true;
    }
  }
  return false;
}

// Trims whitespace and strips a trailing semicolon so that `foo;` and `foo` compare as equal —
// preserves the deterministic mirrored-argument detection across whitespace variations.
function normalizeAssertionExpression(expression: string): string {
  return expression.trim().replace(/;$/, "");
}

// Generic "is there any assertion at all" probe used by missing-assertion rules. Accepts both
// `assert(...)`/`assert.foo(...)` and `expect(...)`, including the assertion-count helpers
// `expect.assertions()` / `expect.hasAssertions()` so tests that delegate counting still pass.
function hasAssertion(source: string): boolean {
  return /\bassert(?:\.[A-Za-z]+)?\s*\(/.test(source) || /\bexpect(?:\.(?:assertions|hasAssertions))?\s*\(/.test(source);
}

// Strips every snapshot-shaped assertion plus `expect.assertions(...)` and re-checks whether any
// assertion remains. A body that empties out is flagged for `test-quality.snapshot-only-test`,
// since snapshot fixtures alone don't constrain behaviour.
function isSnapshotOnlyTest(source: string): boolean {
  if (!/\.\s*toMatch(?:Inline)?Snapshot\s*\(/.test(source)) {
    return false;
  }
  const withoutSnapshots = source
    .replace(/\bexpect\s*\([\s\S]*?\)\s*\.\s*toMatch(?:Inline)?Snapshot\s*\([^)]*\)\s*;?/g, "")
    .replace(/\bexpect\.(?:assertions|hasAssertions)\s*\([^)]*\)\s*;?/g, "");
  return !hasAssertion(withoutSnapshots);
}

// Same shape as `isSnapshotOnlyTest` but for `doesNotThrow` / `not.toThrow`. A test that asserts
// only the absence of an exception is weak — `test-quality.no-throw-only-test` reports it so
// authors can add a real behaviour assertion alongside.
function isNoThrowOnlyTest(source: string): boolean {
  if (!/\bassert\.doesNotThrow\s*\(|\.\s*not\s*\.\s*toThrow\s*\(/.test(source)) {
    return false;
  }
  const withoutNoThrow = source
    .replace(/\bassert\.doesNotThrow\s*\([\s\S]*?\)\s*;?/g, "")
    .replace(/\bexpect\s*\([\s\S]*?\)\s*\.\s*not\s*\.\s*toThrow\s*\([^)]*\)\s*;?/g, "")
    .replace(/\bexpect\.(?:assertions|hasAssertions)\s*\([^)]*\)\s*;?/g, "");
  return !hasAssertion(withoutNoThrow);
}

// Pulls every numeric expected value out of `expect(...).toBe(n)` and `assert.equal(actual, n)`
// shapes. `-1`, `0`, `1` are excluded because they're universally idiomatic — the intent is to
// avoid noise on neutral values and surface only literals whose meaning a maintainer must look up.
function magicNumberAssertions(source: string): Array<{ value: number }> {
  const results: Array<{ value: number }> = [];
  const ignored = new Set([-1, 0, 1]);
  const patterns = [
    /\bexpect\s*\([^)]+\)\s*\.\s*to(?:Be|Equal|HaveLength|HaveCount)\s*\(\s*(-?\d+(?:\.\d+)?)\s*\)/g,
    /\bassert\.(?:equal|strictEqual|deepEqual)\s*\(\s*[^,\n]+,\s*(-?\d+(?:\.\d+)?)(?:\s*,|\s*\))/g,
  ];
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) {
      const expectedNumber = Number(match[1] ?? "0");
      if (!ignored.has(expectedNumber)) {
        results.push({ value: expectedNumber });
      }
    }
  }
  return results;
}

// `const mockX = vi.fn(...)` declarations whose binding appears only once in the body — that one
// occurrence is the declaration itself, so the mock is created but never wired in. Reports the
// names for `test-quality.unused-mock` to anchor on.
function unusedMockVariables(source: string): string[] {
  const names: string[] = [];
  for (const match of source.matchAll(/\bconst\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:(?:vi|jest)\.fn|sinon\.stub|createMock|mock)\s*\(/g)) {
    const name = match[1] ?? "";
    if (name && countMatches(source, new RegExp(`\\b${escapeRegex(name)}\\b`, "g")) <= 1) {
      names.push(name);
    }
  }
  return names;
}

// Three gates in order: a mock factory must exist, a mock-call matcher must be asserted, and
// *every* `expect(target)` argument must look like a mock/stub/spy name. All three together
// signal a test that only verifies its own scaffolding — flagged for `test-quality.mock-only-test`.
function isMockOnlyTest(source: string): boolean {
  if (!/\b(?:vi|jest)\.fn\s*\(|\b(?:createMock|mock|sinon\.stub)\s*\(/.test(source)) {
    return false;
  }
  if (!/\.(?:toHaveBeenCalled|toHaveBeenCalledWith|toHaveBeenNthCalledWith|toBeCalled|toBeCalledWith)\s*\(/.test(source)) {
    return false;
  }
  const targets = [...source.matchAll(/\bexpect\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\)/g)].map((match) => match[1] ?? "");
  return targets.length > 0 && targets.every((target) => /(?:mock|stub|spy)$/i.test(target));
}

// `toThrow(Error)` / `assert.throws(fn, Error)` constrain only the constructor, not the message
// or properties. Reports `test-quality.exception-type-only` so authors tighten the assertion.
function hasExceptionTypeOnlyAssertion(source: string): boolean {
  return /\.toThrow\s*\(\s*(?:Error|[A-Z][A-Za-z0-9_$]*Error)\s*\)/.test(source) || /\bassert\.throws\s*\([^,\n]+,\s*(?:Error|[A-Z][A-Za-z0-9_$]*Error)\s*\)/.test(source);
}

// Three known anti-patterns: writing to `process.env`, writing to `globalThis.*`, or reassigning
// `Date.now` / `Math.random`. Each leaks state across tests; reports
// `test-quality.global-state-mutation` so the author isolates the fixture.
function hasGlobalStateMutation(source: string): boolean {
  return /\bprocess\.env\.[A-Za-z0-9_]+\s*=/.test(source) || /\bglobalThis\.[A-Za-z0-9_$]+\s*=/.test(source) || /\b(?:Date\.now|Math\.random)\s*=/.test(source);
}

// Setup-bloat metric: counts non-ignorable lines preceding the first assertion in the body. Stops
// as soon as an assertion appears, so the value never overshoots the actual prologue length used
// by `test-quality.setup-bloat`.
function setupLineCount(source: string): number {
  let count = 0;
  for (const line of functionBodyContent(source).split(/\r?\n/)) {
    const trimmed = line.trim();
    if (isIgnorableSetupLine(trimmed)) {
      continue;
    }
    if (hasAssertion(trimmed)) {
      break;
    }
    count += 1;
  }
  return count;
}

// Filter for `setupLineCount`. Blank lines plus the two closer shapes (`}` and `});`) shouldn't
// inflate the count — those are syntax, not setup work.
function isIgnorableSetupLine(trimmedLine: string): boolean {
  return trimmedLine.length === 0 || trimmedLine === "});" || trimmedLine === "}";
}

// Matches `test("…", …)` and `it("…", …)` openers. Used both by the function-block parser to
// pick the right pattern and by setup detection to skip the test wrapper line itself.
function isTestInvocationLine(line: string): boolean {
  return /^\s*(?:test|it)\s*\(/.test(line);
}

// Top-level driver: precompiles patterns once, then walks the masked code lines so commented-out
// declarations don't fire. The two-source split (`source` / `codeSource`) keeps raw line text
// available for body extraction while preserving stable, comment-masked matching.
function functionBlocks(source: string, codeSource = source): FunctionBlock[] {
  const scan: FunctionBlockScan = {
    lines: source.split(/\r?\n/),
    codeLines: codeSource.split(/\r?\n/),
    patterns: functionBlockPatterns(),
  };
  const blocks: FunctionBlock[] = [];
  scan.codeLines.forEach((line, index) => {
    const match = functionBlockMatch(scan, line, index);
    if (!match) {
      return;
    }
    blocks.push(functionBlockFromMatch(scan, match, index));
  });
  return blocks;
}

// Four callable shapes in the order `functionBlockMatch` tries them: `test()` / `it()` bodies,
// `function` declarations, class methods, and arrow assignments. Pattern[0] is intentionally
// first because test bodies must match before the generic arrow pattern claims them.
function functionBlockPatterns(): RegExp[] {
  return [
    /^\s*(?:test|it)\s*\(\s*["'`]([^"'`]+)["'`]\s*,\s*(?:async\s*)?\(([^)]*)\)\s*=>/,
    /^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)/,
    /^\s*(?:public|private|protected)?\s*(?:async\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)\s*[:{]/,
    /^\s*(?:const|let)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>/,
  ];
}

// Tries each compiled pattern in order and returns the first hit. The loop bails when a pattern
// slot is missing (defensive guard for the precompiled list) and uses the patternIndex to let
// `functionPatternMatch` pick raw vs. masked text per pattern.
function functionBlockMatch(scan: FunctionBlockScan, line: string, index: number): RegExpMatchArray | undefined {
  const rawLine = scan.lines[index] ?? "";
  for (let patternIndex = 0; patternIndex < scan.patterns.length; patternIndex += 1) {
    const pattern = scan.patterns[patternIndex];
    if (!pattern) {
      continue;
    }
    const match = functionPatternMatch(pattern, patternIndex, line, rawLine);
    if (match) {
      return match;
    }
  }
  return undefined;
}

// Pattern[0] (`test`/`it`) needs the raw line because the test name lives inside a string
// literal that the masker would otherwise blank out. Everything else runs against the masked
// `line`. Filters out control-block keywords so `if(...) {` doesn't register as a callable.
function functionPatternMatch(pattern: RegExp, patternIndex: number, line: string, rawLine: string): RegExpMatchArray | undefined {
  const candidate = patternIndex === 0 && isTestInvocationLine(line) ? rawLine : line;
  const match = candidate.match(pattern);
  if (!match?.[1] || isControlBlockName(match[1])) {
    return undefined;
  }
  return match;
}

// Promotes a regex match into a `FunctionBlock`. `start` walks up to capture leading docblock /
// decorator lines so size and documentation rules see the full declaration footprint; the
// `isPublic` check scans that same range so `export` / `public` modifiers above the line count.
function functionBlockFromMatch(scan: FunctionBlockScan, match: RegExpMatchArray, index: number): FunctionBlock {
  const start = functionStartIndex(scan.lines, index);
  const end = functionEndIndex(scan, index);
  const body = scan.lines.slice(start, end + 1).join("\n");
  const codeBody = scan.codeLines.slice(start, end + 1).join("\n");
  return {
    name: match[1] ?? "",
    params: match[2] ?? "",
    startLine: start + 1,
    lineCount: end - start + 1,
    body,
    codeBody,
    isPublic: /\bexport\b|\bpublic\b/.test(scan.codeLines.slice(start, index + 1).join("\n")),
    isTest: isTestInvocationLine(scan.codeLines[index] ?? ""),
    hasLeadingComment: hasLeadingCommentBeforeLines(scan.lines, index + 1),
    declarationLine: index + 1,
  };
}

// Two callable shapes share one entry point: single-expression arrows return early via
// `expressionArrowEndIndex`, everything else falls into the brace-depth walker. Returning the
// wrong end index would slice the wrong body and silently corrupt every per-block rule's input.
function functionEndIndex(scan: FunctionBlockScan, index: number): number {
  return expressionArrowEndIndex(scan.codeLines, index) ?? blockFunctionEndIndex(scan, index);
}

// Brace-depth walker over masked code lines. Operates on `codeLines` so braces inside strings or
// comments don't disturb the depth counter — the masker preserves brace positions in real code
// and neutralises them everywhere else, keeping the body slice stable.
function blockFunctionEndIndex(scan: FunctionBlockScan, index: number): number {
  const state: FunctionBodyScanState = { depth: 0, hasSeenOpen: false };
  let end = index;
  for (let current = index; current < scan.lines.length; current += 1) {
    for (const character of scan.codeLines[current] ?? "") {
      applyFunctionBodyCharacter(state, character);
    }
    end = current;
    if (isFunctionBodyClosed(state)) {
      break;
    }
  }
  return end;
}

// Per-character transition for the brace-depth walker. Setting `hasSeenOpen` on `{` is the
// invariant `isFunctionBodyClosed` relies on — without it, the walker would treat the
// pre-open state (depth 0) as already closed.
function applyFunctionBodyCharacter(state: FunctionBodyScanState, character: string): void {
  if (character === "{") {
    state.depth += 1;
    state.hasSeenOpen = true;
  } else if (character === "}") {
    state.depth -= 1;
  }
}

// Termination predicate for the brace-depth walker. Requires `hasSeenOpen` so the initial
// pre-body state doesn't read as already closed — the depth counter is only meaningful after the
// first `{`.
function isFunctionBodyClosed(state: FunctionBodyScanState): boolean {
  return state.hasSeenOpen && state.depth <= 0;
}

// Returns the line index where a single-expression arrow body terminates. Detection bails when
// the line contains a `{` after `=>` (a block-bodied arrow); otherwise walks forward until a `;`
// closes the expression or a blank line ends it.
function expressionArrowEndIndex(codeLines: string[], index: number): number | undefined {
  const line = codeLines[index] ?? "";
  const arrowIndex = line.indexOf("=>");
  if (!isExpressionArrowLine(line, arrowIndex)) {
    return undefined;
  }
  for (let current = index; current < codeLines.length; current += 1) {
    const endIndex = expressionArrowEndStep(codeLines, line, arrowIndex, index, current);
    if (endIndex !== undefined) {
      return endIndex;
    }
  }
  return index;
}

// `=>` exists and no `{` follows it — that means the body is a bare expression, not a block.
// The distinction matters because expression bodies need a different end-of-block strategy.
function isExpressionArrowLine(line: string, arrowIndex: number): boolean {
  return arrowIndex !== -1 && !line.slice(arrowIndex + 2).includes("{");
}

// One step of the arrow-expression walker. On the declaration line itself, a trailing `;` closes
// the body immediately. Otherwise: a blank line means we walked past the body (back up one
// index), and a `;`-terminated line is the actual end. Returning undefined means keep walking.
function expressionArrowEndStep(codeLines: string[], line: string, arrowIndex: number, start: number, current: number): number | undefined {
  const trimmed = (codeLines[current] ?? "").trim();
  if (current === start) {
    return line.slice(arrowIndex + 2).trim().endsWith(";") ? current : undefined;
  }
  if (trimmed === "") {
    return current - 1;
  }
  return trimmed.endsWith(";") ? current : undefined;
}

// `if (...) { … }`, `for (...)`, etc. all look like `<name>(` to the pattern walker. The fixed
// exclusion list prevents control-flow blocks from being treated as callables and reported by
// per-block rules.
function isControlBlockName(name: string): boolean {
  return ["if", "for", "while", "switch", "catch"].includes(name);
}

// Walks upward from the declaration line absorbing decorator (`@`), docblock (`/**`, `*`), and
// blank lines so the function block includes its leading documentation. Stops at the first real
// code line above — that boundary becomes the block's start line.
function functionStartIndex(lines: string[], index: number): number {
  let start = index;
  while (start > 0) {
    const previous = lines[start - 1]?.trim() ?? "";
    if (isFunctionPrefixLine(previous)) {
      start -= 1;
      continue;
    }
    break;
  }
  return start;
}

// Predicate that decides whether `functionStartIndex` should keep walking upward. Decorators,
// docblock openers, docblock body lines (`*`), and blank lines all belong to the declaration's
// leading block; anything else marks the boundary.
function isFunctionPrefixLine(trimmedLine: string): boolean {
  return trimmedLine.startsWith("@") || trimmedLine.startsWith("/**") || trimmedLine.startsWith("*") || trimmedLine === "";
}

// Input bundle for `finding()` — the lowest-cost finding factory. Captures everything the caller
// must supply for a line-anchored Finding; shared defaults (confidence "high", empty metadata)
// are added inside the builder so callers don't repeat them at every rule site.
interface LineFindingArgs {
  ruleId: string;
  message: string;
  file: SourceFile;
  line: number;
  severity: Severity;
  pillar: Pillar;
}

// Input bundle for `blockFinding()`. The block reference replaces the explicit line: the builder
// reads `block.startLine` and `block.name` so the stable finding anchor and symbol metadata stay
// in sync with the parsed callable across every block-level rule.
interface BlockFindingArgs {
  ruleId: string;
  message: string;
  file: SourceFile;
  block: FunctionBlock;
  severity: Severity;
  pillar: Pillar;
}

// `BlockFindingArgs` plus a rule-specific metadata payload. Used by rules that need to encode
// numeric thresholds or measurements (size, complexity values) into the Finding so downstream
// consumers can filter without re-running the analyzer.
interface BlockFindingWithMetadataArgs extends BlockFindingArgs {
  metadata: Record<string, unknown>;
}

// Cheapest finding factory: line-anchored, no symbol, confidence "high". Produces the
// (ruleId, filePath, line) tuple that every per-line emission relies on — this tuple is the
// stable fingerprint that drives baseline matching and report determinism.
function finding(args: LineFindingArgs): Finding {
  return makeFinding({ ruleId: args.ruleId, message: args.message, filePath: args.file.displayPath, line: args.line, severity: args.severity, pillar: args.pillar, confidence: "high" });
}

// Block-anchored finding factory: pulls line + symbol from the parsed callable so every
// block-level rule reports against the same anchor. Default confidence is "high"; callers
// needing metadata or lower confidence go through `blockFindingWithMetadata` to keep the
// per-rule fingerprint shape stable.
function blockFinding(args: BlockFindingArgs): Finding {
  return makeFinding({ ruleId: args.ruleId, message: args.message, filePath: args.file.displayPath, line: args.block.startLine, severity: args.severity, pillar: args.pillar, confidence: "high", symbol: args.block.name });
}

// Block-anchored variant that ships rule-specific metadata. Confidence defaults to "medium"
// because metadata-carrying rules (size, complexity, NPath) report measurements rather than
// definitive defects; the metadata payload is part of each rule's stable fingerprint contract.
function blockFindingWithMetadata(args: BlockFindingWithMetadataArgs): Finding {
  return makeFinding({ ruleId: args.ruleId, message: args.message, filePath: args.file.displayPath, line: args.block.startLine, severity: args.severity, pillar: args.pillar, confidence: "medium", symbol: args.block.name, metadata: args.metadata });
}

// Diff-aware discovery: uses `execFileSync` (not `execSync`) so the `mode` value is passed as
// an argv entry and a malicious value cannot inject shell metacharacters. Spawns `git diff`,
// reads the output, and normalises path separators to `/` for clean display-path joins.
function changedFiles(mode: string): Set<string> {
  const args = ["diff", "--name-only"];
  if (mode === "staged") {
    args.push("--cached");
  } else if (mode !== "working-tree" && mode !== "unstaged") {
    args.push(mode);
  }
  return new Set(execFileSync("git", args, { encoding: "utf8" }).split(/\r?\n/).filter(Boolean).map((line) => line.replaceAll("\\", "/")));
}

// Deepest `{` / `}` nesting reached across the body, minus one so the body's own outer braces
// don't count. The `Math.max(0, …)` clamp protects against unbalanced inputs — feeds the nesting
// component of `complexity.cognitive` and must stay deterministic across runs.
function maxNestingDepth(source: string): number {
  let depth = 0;
  let maxDepth = 0;
  for (const character of source) {
    if (character === "{") {
      depth += 1;
      maxDepth = Math.max(maxDepth, depth);
    } else if (character === "}") {
      depth = Math.max(0, depth - 1);
    }
  }
  return Math.max(0, maxDepth - 1);
}

// Walks upward from the declaration looking for `/** */` or `*` continuation lines. The boundary
// predicate stops the search at the first real code or non-doc text, so docblocks from earlier
// declarations don't leak across.
function hasDocCommentBeforeLine(source: string, line: number): boolean {
  const lines = source.split(/\r?\n/);
  let index = line - 2;
  while (index >= 0) {
    const current = lines[index]?.trim() ?? "";
    if (isDocCommentLine(current)) {
      return true;
    }
    if (isDocCommentSearchBoundary(current)) {
      return false;
    }
    index -= 1;
  }
  return false;
}

// `/**` openers and `*` continuation lines are both docblock material. Plain `//` comments are
// intentionally excluded — those are tracked separately by `hasLeadingCommentBeforeLine`.
function isDocCommentLine(trimmedLine: string): boolean {
  return trimmedLine.startsWith("/**") || trimmedLine.startsWith("*");
}

// Halts the docblock walker when the upward search lands on real code. `@` lines are allowed
// through because JSDoc tags appear inside the docblock body and shouldn't terminate the scan.
function isDocCommentSearchBoundary(trimmedLine: string): boolean {
  return trimmedLine !== "" && !trimmedLine.startsWith("@");
}

// File-overview presence check for `docs.missing-file-overview`. Skips a shebang first because
// scripts conventionally place `#!` on line 1, then asks whether the first real line is a
// comment — that is the contract the rule reports against.
function hasFileOverviewComment(source: string): boolean {
  const lines = source.split(/\r?\n/);
  let index = firstMeaningfulLineIndex(lines);
  if (index === undefined) {
    return false;
  }
  if (lines[index]?.startsWith("#!")) {
    index = firstMeaningfulLineIndex(lines, index + 1);
  }
  return index !== undefined && commentTextAtLine(lines, index) !== undefined;
}

// Returns the index of the first non-blank line at or after `start`. The implementation does
// not skip comments — callers asking for "first meaningful line" treat comment text as a
// meaningful signal (file-overview detection wants to land on the comment itself).
function firstMeaningfulLineIndex(lines: string[], start = 0): number | undefined {
  for (let index = start; index < lines.length; index += 1) {
    if ((lines[index] ?? "").trim() !== "") {
      return index;
    }
  }
  return undefined;
}

// String-input wrapper around `hasLeadingCommentBeforeLines`. Keeps call sites that already hold
// a split line array from re-splitting on every lookup.
function hasLeadingCommentBeforeLine(source: string, line: number): boolean {
  return hasLeadingCommentBeforeLines(source.split(/\r?\n/), line);
}

// Skips blank padding above the declaration and asks whether the immediately preceding non-blank
// line is any comment shape (`//`, `/*`, or `*/`). Underlies the missing-comment rules across
// functions, interfaces, and exported declarations.
function hasLeadingCommentBeforeLines(lines: string[], line: number): boolean {
  let index = line - 2;
  while (index >= 0 && (lines[index] ?? "").trim() === "") {
    index -= 1;
  }
  return index >= 0 && commentTextAtLine(lines, index) !== undefined;
}

// Three comment shapes resolved here: `//` line comments, `/* … */` opener lines, and lines that
// only contain the `*/` closer (call delegates upward to find the opener). Returns undefined for
// non-comment lines and for empty comments, so callers can use truthiness as the "has text" gate.
function commentTextAtLine(lines: string[], index: number): string | undefined {
  const trimmedLine = (lines[index] ?? "").trim();
  if (trimmedLine.startsWith("//")) {
    const text = trimmedLine.slice(2).trim();
    return text === "" ? undefined : text;
  }
  if (trimmedLine.startsWith("/*")) {
    return blockCommentText(lines, index);
  }
  if (trimmedLine.endsWith("*/")) {
    return blockCommentTextEndingAt(lines, index);
  }
  return undefined;
}

// Walks upward from a `*/` closer to its matching `/*` opener, then delegates to
// `blockCommentText` to extract the joined body. Used when a declaration's leading comment is a
// block comment whose closer sits on the line above the declaration.
function blockCommentTextEndingAt(lines: string[], endIndex: number): string | undefined {
  for (let index = endIndex; index >= 0; index -= 1) {
    if ((lines[index] ?? "").trim().startsWith("/*")) {
      return blockCommentText(lines, index, endIndex);
    }
  }
  return undefined;
}

// Joins a block comment's lines into one normalised text run: strips `/*` / `*/` / leading `*`,
// drops `@tag` lines, and collapses whitespace. The `knownEndIndex` parameter lets
// `blockCommentTextEndingAt` skip the scan when the closer line is already known.
function blockCommentText(lines: string[], startIndex: number, knownEndIndex?: number): string | undefined {
  const endIndex = knownEndIndex ?? blockCommentEndIndex(lines, startIndex);
  if (endIndex === undefined) {
    return undefined;
  }
  const text = lines
    .slice(startIndex, endIndex + 1)
    .map((line) => line.replace(/^\s*\/\*\*?/, "").replace(/\*\/\s*$/, "").replace(/^\s*\*\s?/, "").trim())
    .filter((line) => line !== "" && !line.startsWith("@"))
    .join(" ")
    .trim();
  return text === "" ? undefined : text;
}

// Forward scan for the next line containing `*/`. Returns undefined for unterminated comments,
// which the caller treats as "no useful text" rather than throwing — partial-scan robustness.
function blockCommentEndIndex(lines: string[], startIndex: number): number | undefined {
  for (let index = startIndex; index < lines.length; index += 1) {
    if ((lines[index] ?? "").includes("*/")) {
      return index;
    }
  }
  return undefined;
}

// Lowercase membership test against the configured banned-names set. Drives the
// `naming.identifier-quality` predicate so the rule stays a single Set lookup per identifier.
function isGenericName(name: string, bannedNames: Set<string>): boolean {
  return bannedNames.has(name.toLowerCase());
}


// Escapes the standard regex metacharacters so user-supplied strings (rule IDs, identifiers,
// paths) can be embedded in dynamic patterns without altering their meaning. Hot path —
// used by every rule that builds a per-source RegExp.
function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const buildProgram = (): ReturnType<typeof buildCliProgram> => buildCliProgram(analyse);

if (import.meta.url === pathToFileURL(argv[1] ?? "").href) {
  buildProgram().parse(argv);
}

export { absolutize, buildProgram, displayPath, renderReport, ruleDescriptors };
