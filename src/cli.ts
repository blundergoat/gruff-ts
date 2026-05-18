#!/usr/bin/env node
import { Command, Help } from "commander";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { argv, cwd } from "node:process";
import { basename, dirname as dirnamePath, extname, isAbsolute, join, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { applyBaseline, dedupeFindings, DEFAULT_BASELINE, recordHistory, writeBaseline } from "./baseline.ts";
import { isString, loadConfig, optionNumber, ruleEnabled, ruleSeverity, threshold } from "./config.ts";
import { VERSION } from "./constants.ts";
import { startDashboard } from "./dashboard.ts";
import { makeFinding } from "./findings.ts";
import { analyseProjectConfigRules } from "./project-config-rules.ts";
import { renderReport, renderSummary } from "./report-renderers.ts";
import { completionShell, renderCompletionScript, renderConsoleList, renderRuleList, type CompletionShell, type RuleListFormat } from "./rule-list.ts";
import { exitFor, scoreReport, summarize } from "./scoring.ts";
import { ruleDescriptors } from "./rules.ts";
import { analyseSensitiveData } from "./sensitive-data-rules.ts";
import { codeLineForMatching, maskNonCode, parseDiagnostics } from "./source-text.ts";
import { byteLine, countMatches, todoMarkerSummary } from "./text-scans.ts";
import type { AnalysisOptions, AnalysisReport, Config, Finding, OutputFormat, Pillar, RunDiagnostic, Severity } from "./types.ts";
export type { AnalysisReport, Finding, OutputFormat, Pillar, RuleDescriptor, Severity } from "./types.ts";

const NPATH_CAP = 1_000_000;
const FIXTURE_PURPOSE_MIN_LINES = 12;

interface SourceFile {
  absolutePath: string;
  displayPath: string;
  isScript: boolean;
}

interface SourceDiscovery {
  files: SourceFile[];
  missingPaths: string[];
  ignoredPaths: Set<string>;
}

interface SourceDiscoveryResult {
  files: SourceFile[];
  missingPaths: string[];
  ignoredPaths: string[];
}

interface ProjectSource {
  file: SourceFile;
  source: string;
  lines: string[];
}

interface GitIgnoreRule {
  basePath: string;
  pattern: string;
  negated: boolean;
  directoryOnly: boolean;
  anchored: boolean;
  hasSlash: boolean;
}

interface ProjectIndex {
  sources: ProjectSource[];
  scriptSources: ProjectSource[];
  sourcePaths: Set<string>;
  importsByFile: Map<string, ImportEdge[]>;
}

interface ImportEdge {
  specifier: string;
  line: number;
  parentSegments: number;
  targetPath?: string;
}

interface ImportCycle {
  files: string[];
}

interface LargeModuleThresholds {
  minFiles: number;
  minLines: number;
  maxSharePercent: number;
}

interface ModuleLineCount {
  source: ProjectSource;
  lines: number;
}

interface LargeModuleCandidate extends ModuleLineCount {
  totalLines: number;
  sharePercent: number;
  thresholds: LargeModuleThresholds;
}

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

interface FunctionBlockScan {
  lines: string[];
  codeLines: string[];
  patterns: RegExp[];
}

interface FunctionBodyScanState {
  depth: number;
  hasSeenOpen: boolean;
}

interface CommentRecord {
  kind: "line" | "block";
  text: string;
  line: number;
  endLine: number;
  startIndex: number;
  endIndex: number;
}

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

interface FixturePurposeCandidate {
  line: number;
  symbol: string;
  targetKind: string;
  lineCount: number;
}

interface TestBlockCheck {
  ruleId: string;
  message: string;
  severity: Severity;
}

interface BlockRuleContext {
  file: SourceFile;
  block: FunctionBlock;
  config: Config;
  findings: Finding[];
  cyclomatic: number;
  functionBody: string;
}

interface NpathResult {
  value: number;
  capped: boolean;
}

interface LineRuleCheck {
  ruleId: string;
  pattern: RegExp;
  globalPattern?: RegExp;
  message: string;
  severity: Severity;
  pillar: Pillar;
}

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

interface NormalizeContext {
  allowBaselineFlag: boolean;
}

/**
 * Analyse the configured paths and return findings, diagnostics, and scores.
 *
 * @param options Normalised analysis options from the CLI or direct callers.
 * @returns Versioned analysis report with findings, diagnostics, paths, and score data.
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

interface DiscoverySummary {
  files: SourceFile[];
  ignoredPaths: string[];
  missingPaths: string[];
}

interface SourceScanResult {
  findings: Finding[];
  projectSources: ProjectSource[];
}

interface BaselineApplication {
  findings: Finding[];
  baseline?: NonNullable<AnalysisReport["baseline"]>;
}

interface BaselineSelection {
  path: string;
  source: string;
}

function filterDiffSources(discovery: DiscoverySummary, options: AnalysisOptions): void {
  if (!options.diff) {
    return;
  }
  const changed = changedFiles(options.diff);
  discovery.files = discovery.files.filter((file) => changed.has(file.displayPath));
}

function pushMissingPathDiagnostics(missingPaths: string[], diagnostics: RunDiagnostic[]): void {
  for (const missingPath of missingPaths) {
    diagnostics.push({
      diagnosticType: "missing-path",
      message: `Input path does not exist: ${missingPath}`,
      filePath: missingPath,
    });
  }
}

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

function selectedBaseline(projectRoot: string, options: AnalysisOptions): BaselineSelection | undefined {
  if (options.baseline) {
    return { path: absolutize(projectRoot, options.baseline), source: "explicit" };
  }
  const defaultBaseline = join(projectRoot, DEFAULT_BASELINE);
  return existsSync(defaultBaseline) ? { path: defaultBaseline, source: "default" } : undefined;
}

function discoverSources(projectRoot: string, options: AnalysisOptions, config: Config): SourceDiscoveryResult {
  const discovery: SourceDiscovery = { files: [], missingPaths: [], ignoredPaths: new Set<string>() };
  const inputs = options.paths.length > 0 ? options.paths : ["."];

  for (const input of inputs) {
    discoverSourceInput(projectRoot, input, options, config, discovery);
  }

  discovery.files.sort((left, right) => left.displayPath.localeCompare(right.displayPath));
  return { files: uniqueFiles(discovery.files), missingPaths: discovery.missingPaths, ignoredPaths: [...discovery.ignoredPaths].sort() };
}

function discoverSourceInput(projectRoot: string, input: string, options: AnalysisOptions, config: Config, discovery: SourceDiscovery): void {
  const absolute = absolutize(projectRoot, input);
  if (!existsSync(absolute)) {
    discovery.missingPaths.push(input);
    return;
  }
  const stats = statSync(absolute);
  if (stats.isFile()) {
    pushSourceFile(projectRoot, absolute, discovery.files);
    return;
  }
  const gitIgnoreRules = options.includeIgnored ? [] : gitIgnoreRulesForDirectory(projectRoot, absolute);
  walk(projectRoot, absolute, options, config, discovery.ignoredPaths, discovery.files, gitIgnoreRules);
}

function walk(
  projectRoot: string,
  directory: string,
  options: AnalysisOptions,
  config: Config,
  ignoredPaths: Set<string>,
  files: SourceFile[],
  gitIgnoreRules: GitIgnoreRule[],
): void {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const absolute = join(directory, entry.name);
    const display = displayPath(projectRoot, absolute);
    if (entry.isDirectory() || entry.isFile()) {
      if (isIgnoredDiscoveryPath(display, entry.isDirectory(), options, config, gitIgnoreRules)) {
        ignoredPaths.add(display);
        continue;
      }
    }
    if (entry.isDirectory()) {
      walk(projectRoot, absolute, options, config, ignoredPaths, files, options.includeIgnored ? gitIgnoreRules : appendGitIgnoreRules(projectRoot, absolute, gitIgnoreRules));
    } else if (entry.isFile()) {
      pushSourceFile(projectRoot, absolute, files);
    }
  }
}

function pushSourceFile(projectRoot: string, absolutePath: string, files: SourceFile[]): void {
  const extension = extname(absolutePath).slice(1).toLowerCase();
  const name = basename(absolutePath);
  const isScript = ["ts", "tsx", "js", "jsx", "mjs", "cjs"].includes(extension);
  const isText =
    ["conf", "config", "env", "ini", "json", "toml", "xml", "yaml", "yml"].includes(extension) ||
    name.startsWith(".env");
  if (isScript || isText) {
    files.push({ absolutePath, displayPath: displayPath(projectRoot, absolutePath), isScript });
  }
}
function analyseSource(file: SourceFile, source: string, config: Config): Finding[] {
  const findings: Finding[] = [];
  analyseTextRules(file, source, config, findings);
  if (file.isScript) {
    analyseTypeScriptRules(file, source, config, findings);
  }
  return findings.filter((finding) => ruleEnabled(config, finding.ruleId));
}

function analyseProjectIndex(projectSources: ProjectSource[], config: Config): Finding[] {
  const index = buildProjectIndex(projectSources);
  const findings: Finding[] = [];
  analyseArchitectureRules(index, config, findings);
  analyseTestAdequacyRules(index, findings);
  return findings;
}

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

function analyseArchitectureRules(index: ProjectIndex, config: Config, findings: Finding[]): void {
  analyseDeepRelativeImports(index, config, findings);
  analyseCircularImports(index, findings);
  analyseLargeModuleConcentration(index, config, findings);
}

function analyseTestAdequacyRules(index: ProjectIndex, findings: Finding[]): void {
  analyseMissingNearbyTests(index, findings);
}

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

function analyseCircularImports(index: ProjectIndex, findings: Finding[]): void {
  for (const cycle of importCycles(index)) {
    const finding = circularImportFinding(index, cycle);
    if (finding) {
      findings.push(finding);
    }
  }
}

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

function circularImportLine(index: ProjectIndex, anchorPath: string, cycle: ImportCycle): number {
  const anchorEdges = index.importsByFile.get(anchorPath) ?? [];
  return anchorEdges.find((edge) => edge.targetPath && cycle.files.includes(edge.targetPath))?.line ?? 1;
}

function analyseLargeModuleConcentration(index: ProjectIndex, config: Config, findings: Finding[]): void {
  const candidate = largeModuleCandidate(index, largeModuleThresholds(config));
  if (!candidate) {
    return;
  }
  findings.push(largeModuleConcentrationFinding(candidate, ruleSeverity(config, "design.large-module-concentration", "advisory")));
}

function largeModuleThresholds(config: Config): LargeModuleThresholds {
  return {
    minFiles: optionNumber(config, "design.large-module-concentration", "minFiles", 4),
    minLines: optionNumber(config, "design.large-module-concentration", "minLines", 80),
    maxSharePercent: threshold(config, "design.large-module-concentration", 55),
  };
}

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

function exceedsLargeModuleThresholds(largest: ModuleLineCount, sharePercent: number, thresholds: LargeModuleThresholds): boolean {
  return largest.lines >= thresholds.minLines && sharePercent > thresholds.maxSharePercent;
}

function productionModuleLineCounts(index: ProjectIndex): ModuleLineCount[] {
  return index.scriptSources
    .filter((source) => isProductionSourcePath(source.file.displayPath))
    .map((source) => ({ source, lines: source.lines.length }))
    .sort((left, right) => right.lines - left.lines || left.source.file.displayPath.localeCompare(right.source.file.displayPath));
}

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

function importEdgesForSource(source: ProjectSource, sourcePaths: Set<string>): ImportEdge[] {
  const edges: ImportEdge[] = [];
  for (const [index, line] of source.lines.entries()) {
    edges.push(...importEdgesForLine(source.file.displayPath, line, index + 1, sourcePaths));
  }
  return edges.sort((left, right) => left.line - right.line || left.specifier.localeCompare(right.specifier));
}

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

function resolveRelativeImport(importerPath: string, specifier: string, sourcePaths: Set<string>): string | undefined {
  const basePath = normalizeDisplayPath(join(dirnamePath(importerPath), specifier));
  for (const candidate of importPathCandidates(basePath)) {
    if (sourcePaths.has(candidate)) {
      return candidate;
    }
  }
  return undefined;
}

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

function isProductionSourcePath(path: string): boolean {
  return !isTestPath(path) && !isDeclarationPath(path) && !isFixtureLikePath(path) && !path.split("/").includes("generated");
}

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

function exportedSurface(source: string): { symbol: string; line: number } | undefined {
  const match = source.match(/\bexport\s+(?:default\s+)?(?:async\s+)?(?:function|class|interface|type|enum|const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)/);
  if (!match?.[1]) {
    return undefined;
  }
  return { symbol: match[1], line: byteLine(source, match.index ?? 0) };
}

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

function stripSourceExtension(path: string): string {
  return path.replace(/\.[cm]?[tj]sx?$/, "");
}

function stripTestMarker(path: string): string {
  return path.replace(/\.(?:test|spec)$/, "");
}

function displayDir(path: string): string {
  const dir = normalizeDisplayPath(dirnamePath(path));
  return dir === "." ? "" : dir;
}

function joinDisplay(left: string, right: string): string {
  return left ? `${left}/${right}` : right;
}

function isTestPath(path: string): boolean {
  return /(?:^|\/)(?:__tests__|tests?|spec)\//.test(path) || /\.(?:test|spec)\.[cm]?[tj]sx?$/.test(path);
}

function isDeclarationPath(path: string): boolean {
  return /\.d\.[cm]?ts$/.test(path);
}

function isFixtureLikePath(path: string): boolean {
  return /(?:^|\/)(?:__fixtures__|fixtures?|testdata)\//.test(path);
}

function normalizeDisplayPath(path: string): string {
  return path.replaceAll("\\", "/").replace(/^\.\//, "");
}

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

function isGeneratedLockfile(path: string): boolean {
  const name = basename(path);
  return name === "package-lock.json" || name === "npm-shrinkwrap.json" || name === "yarn.lock" || name === "pnpm-lock.yaml" || name === "bun.lockb";
}

function analyseTypeScriptRules(file: SourceFile, source: string, config: Config, findings: Finding[]): void {
  const codeSource = maskNonCode(source);
  const blocks = functionBlocks(source, codeSource);
  const comments = commentRecords(source);
  analyseFileOverviewDoc(file, source, findings);
  analyseBlocks(file, blocks, config, findings);
  analyseLineRules(file, source, codeSource, config, findings);
  analyseDocRules(file, source, codeSource, findings);
  analyseInterfaceDocs(file, source, codeSource, findings);
  analyseInterfaceBooleanFields(file, source, codeSource, config, findings);
  analyseCommentQualityRules({ file, source, codeSource, blocks, comments, config, findings });
  analyseClassRules(file, source, codeSource, findings);
  analyseDeadCode(file, codeSource, findings);
}

function analyseInterfaceBooleanFields(file: SourceFile, source: string, codeSource: string, config: Config, findings: Finding[]): void {
  const headerRegex = /\b(?:export\s+)?(?:interface\s+[A-Za-z_$][A-Za-z0-9_$]*(?:\s*<[^>]*>)?(?:\s+extends\s+[^{]+)?|type\s+[A-Za-z_$][A-Za-z0-9_$]*(?:\s*<[^>]*>)?\s*=\s*)\s*\{/g;
  const fieldRegex = /^[ \t]*(?:readonly\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\??\s*:\s*boolean\b/;
  const codeLines = codeSource.split(/\r?\n/);
  const sourceLines = source.split(/\r?\n/);

  for (const header of codeSource.matchAll(headerRegex)) {
    const headerEnd = (header.index ?? 0) + header[0].length;
    const peek = codeSource.slice(headerEnd, headerEnd + 30).trimStart();
    if (peek.startsWith("[")) {
      continue;
    }
    const headerLineIndex = byteLine(source, headerEnd - 1) - 1;
    let depth = 1;
    const headerLine = codeLines[headerLineIndex] ?? "";
    const afterOpen = headerLine.slice(headerLine.lastIndexOf("{") + 1);
    depth += countBraceChange(afterOpen);
    for (let lineIndex = headerLineIndex + 1; depth > 0 && lineIndex < codeLines.length; lineIndex += 1) {
      const codeLine = codeLines[lineIndex] ?? "";
      if (depth === 1) {
        const match = (sourceLines[lineIndex] ?? "").match(fieldRegex);
        if (match) {
          const name = match[1] ?? "";
          if (name) {
            pushBooleanPrefixAt(file, lineIndex + 1, name, config, findings, "interface-field");
          }
        }
      }
      depth += countBraceChange(codeLine);
    }
  }
}

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

function analyseBlocks(file: SourceFile, blocks: FunctionBlock[], config: Config, findings: Finding[]): void {
  for (const block of blocks) {
    analyseBlockRules(blockRuleContext(file, block, config, findings));
  }
}

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

function pushParameterNamingFindings(context: BlockRuleContext): void {
  const line = context.block.declarationLine;
  for (const parameter of parameterNames(context.block.params)) {
    pushShortVariableAt(context.file, line, parameter.name, context.config, context.findings, "parameter");
    pushIdentifierQualityAt(context.file, line, parameter.name, context.config, context.findings, "parameter");
    if (isBooleanParameter(parameter.raw)) {
      pushBooleanPrefixAt(context.file, line, parameter.name, context.config, context.findings, "parameter");
    }
  }
}

function isBooleanParameter(raw: string): boolean {
  if (/:\s*boolean\b/.test(raw)) {
    return true;
  }
  if (/\bas\b/.test(raw)) {
    return false;
  }
  return /=\s*(?:true|false)\s*$/.test(raw);
}

function pushFunctionLengthFinding(context: BlockRuleContext): void {
  const functionLengthThreshold = threshold(context.config, "size.function-length", 200);
  if (context.block.lineCount > functionLengthThreshold) {
    context.findings.push(blockFinding({ ruleId: "size.function-length", message: `Function \`${context.block.name}\` has ${context.block.lineCount} lines, above the threshold of ${functionLengthThreshold}.`, file: context.file, block: context.block, severity: ruleSeverity(context.config, "size.function-length", "warning"), pillar: "size" }));
  }
}

function pushParameterCountFinding(context: BlockRuleContext): void {
  const params = context.block.params.split(",").map((value) => value.trim()).filter(Boolean).length;
  if (params > threshold(context.config, "size.parameter-count", 7)) {
    context.findings.push(blockFinding({ ruleId: "size.parameter-count", message: `Function \`${context.block.name}\` declares ${params} parameters.`, file: context.file, block: context.block, severity: ruleSeverity(context.config, "size.parameter-count", "warning"), pillar: "size" }));
  }
}

function pushCyclomaticFinding(context: BlockRuleContext): void {
  if (context.cyclomatic > threshold(context.config, "complexity.cyclomatic", 15)) {
    context.findings.push(blockFinding({ ruleId: "complexity.cyclomatic", message: `Function \`${context.block.name}\` has cyclomatic complexity ${context.cyclomatic}.`, file: context.file, block: context.block, severity: ruleSeverity(context.config, "complexity.cyclomatic", "warning"), pillar: "complexity" }));
  }
}

function pushCognitiveFinding(context: BlockRuleContext): void {
  const cognitive = context.cyclomatic + maxNestingDepth(context.block.codeBody);
  if (cognitive > threshold(context.config, "complexity.cognitive", 15)) {
    context.findings.push(blockFinding({ ruleId: "complexity.cognitive", message: `Function \`${context.block.name}\` has cognitive complexity ${cognitive}.`, file: context.file, block: context.block, severity: ruleSeverity(context.config, "complexity.cognitive", "warning"), pillar: "complexity" }));
  }
}

function pushNpathFinding(context: BlockRuleContext): void {
  const npath = approximateNpath(context.functionBody);
  const npathThreshold = threshold(context.config, "complexity.npath", 200);
  if (npath.value > npathThreshold) {
    context.findings.push(npathFinding(context, npath, npathThreshold, ruleSeverity(context.config, "complexity.npath", "warning")));
  }
}

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

function pushGodFunctionFinding(context: BlockRuleContext): void {
  if (context.block.lineCount > 45 && context.cyclomatic > 10) {
    context.findings.push(blockFinding({ ruleId: "design.god-function", message: `Function \`${context.block.name}\` is both long and complex.`, file: context.file, block: context.block, severity: "warning", pillar: "design" }));
  }
}

function pushGenericFunctionFinding(context: BlockRuleContext): void {
  if (isGenericName(context.block.name, context.config.bannedGenericNames)) {
    context.findings.push(blockFinding({ ruleId: "naming.generic-function", message: `Function \`${context.block.name}\` is too generic to explain intent.`, file: context.file, block: context.block, severity: "advisory", pillar: "naming" }));
  }
}

function pushMissingFunctionDocFinding(context: BlockRuleContext): void {
  if (!context.block.isTest && !context.block.hasLeadingComment) {
    context.findings.push(blockFinding({ ruleId: "docs.missing-function-doc", message: `Function \`${context.block.name}\` is missing a leading maintainer comment.`, file: context.file, block: context.block, severity: "advisory", pillar: "documentation" }));
  }
}

function pushEmptyFunctionFinding(context: BlockRuleContext): void {
  if (isEmptyFunctionBody(context.block.codeBody)) {
    context.findings.push(blockFinding({ ruleId: "waste.empty-function", message: `Function \`${context.block.name}\` has no executable body.`, file: context.file, block: context.block, severity: "advisory", pillar: "waste" }));
  }
}

function pushUnusedParameterFindings(context: BlockRuleContext): void {
  for (const parameter of parameterNames(context.block.params)) {
    if (!isUnusedParameter(context, parameter.name)) {
      continue;
    }
    context.findings.push(unusedParameterFinding(context, parameter.name));
  }
}

function isUnusedParameter(context: BlockRuleContext, parameterName: string): boolean {
  return !parameterName.startsWith("_") && !new RegExp(`\\b${escapeRegex(parameterName)}\\b`).test(context.functionBody);
}

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

function analyseTestBlock(file: SourceFile, block: FunctionBlock, config: Config, findings: Finding[]): void {
  const body = block.codeBody;
  analyseAssertionQuality(file, block, body, findings);
  analyseMockQuality(file, block, body, findings);
  analyseSetupBloat(file, block, body, config, findings);
  analyseTestStructureChecks(file, block, body, findings);
}

function analyseAssertionQuality(file: SourceFile, block: FunctionBlock, body: string, findings: Finding[]): void {
  for (const check of assertionQualityChecks(block, body)) {
    findings.push(blockFinding({ ruleId: check.ruleId, message: check.message, file, block, severity: check.severity, pillar: "test-quality" }));
  }
  pushMagicNumberAssertionFindings(file, block, body, findings);
}

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

function withGlobalPattern(check: LineRuleCheck): LineRuleCheck {
  return {
    ...check,
    globalPattern: check.pattern.flags.includes("g") ? check.pattern : new RegExp(check.pattern.source, `${check.pattern.flags}g`),
  };
}

function pushCommentedOutCodeFinding(context: LineRuleContext): void {
  if (isCommentedOutCode(context.line)) {
    context.findings.push(finding({ ruleId: "waste.commented-out-code", message: "Comment appears to contain disabled source code.", file: context.file, line: context.lineNumber, severity: "advisory", pillar: "waste" }));
  }
}

type NamingSurface = "declaration" | "parameter" | "destructure" | "interface-field";

function pushBooleanPrefixFinding(context: LineRuleContext): void {
  const booleanDeclaration = context.codeLine.match(/\b(?:const|let|var|public|private|protected)\s+([A-Za-z_$][A-Za-z0-9_$]*)\??(?:\s*:\s*boolean|\s*=\s*(?:true|false)\b)/);
  const name = booleanDeclaration?.[1] ?? "";
  if (!name) {
    return;
  }
  pushBooleanPrefixAt(context.file, context.lineNumber, name, context.config, context.findings, "declaration");
}

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

function pushLooseEqualityFinding(context: LineRuleContext): void {
  const looseOperator = looseEqualityOperator(context.codeLine);
  if (looseOperator) {
    context.findings.push(finding({ ruleId: "modernisation.loose-equality", message: `Loose equality operator ${looseOperator} may coerce values.`, file: context.file, line: context.lineNumber, severity: "advisory", pillar: "modernisation" }));
  }
}

function pushStringTimerFinding(context: LineRuleContext): void {
  if (stringTimerCandidate(context.codeLine)) {
    context.findings.push(finding({ ruleId: "security.string-timer", message: "Timer callback is provided as a string.", file: context.file, line: context.lineNumber, severity: "warning", pillar: "security" }));
  }
}

function pushProcessExecFinding(context: LineRuleContext): void {
  if (processExecCandidate(context.codeLine) && !isFixedLocalProcessHarness(context.file, context.line, context.codeLine)) {
    context.findings.push(finding({ ruleId: "security.process-exec", message: "Child-process execution is used; validate arguments are not user-controlled.", file: context.file, line: context.lineNumber, severity: "warning", pillar: "security" }));
  }
}

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

function pushVariableNameFindings(context: LineRuleContext): void {
  for (const match of context.codeLine.matchAll(context.variables)) {
    const name = match[1] ?? "";
    pushShortVariableFinding(context, name);
    pushIdentifierQualityFinding(context, name);
  }
  for (const name of destructuredLocalNames(context.codeLine)) {
    pushShortVariableAt(context.file, context.lineNumber, name, context.config, context.findings, "destructure");
    pushIdentifierQualityAt(context.file, context.lineNumber, name, context.config, context.findings, "destructure");
  }
}

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

function pushShortVariableFinding(context: LineRuleContext, name: string): void {
  pushShortVariableAt(context.file, context.lineNumber, name, context.config, context.findings, "declaration");
}

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

function pushIdentifierQualityFinding(context: LineRuleContext, name: string): void {
  pushIdentifierQualityAt(context.file, context.lineNumber, name, context.config, context.findings, "declaration");
}

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

function isNonWhitespaceCharacter(character: string): boolean {
  return character !== "" && character !== " " && character !== "\t" && character !== "\r" && character !== "\n";
}

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

function isLooseEqualityCandidate(codeLine: string, index: number, operator: string): boolean {
  return !isStrictEqualityOperator(codeLine, index, operator) && !isNullEqualityComparison(codeLine, index, operator);
}

function isStrictEqualityOperator(codeLine: string, index: number, operator: string): boolean {
  const before = codeLine[index - 1] ?? "";
  const after = codeLine[index + operator.length] ?? "";
  return before === "=" || before === "!" || after === "=";
}

function isNullEqualityComparison(codeLine: string, index: number, operator: string): boolean {
  const left = codeLine.slice(Math.max(0, index - 24), index).trimEnd();
  const right = codeLine.slice(index + operator.length, Math.min(codeLine.length, index + operator.length + 24)).trimStart();
  return /\bnull$/.test(left) || /^null\b/.test(right);
}

function stringTimerCandidate(codeLine: string): boolean {
  return (
    /(?:^|[^.\w$])(?:setTimeout|setInterval|execScript)\s*\(\s*["'`]/.test(codeLine) ||
    /\b(?:window|self|globalThis)\.(?:setTimeout|setInterval|execScript)\s*\(\s*["'`]/.test(codeLine)
  );
}

function processExecCandidate(codeLine: string): boolean {
  return /\b(?:exec|spawn|execFile)\s*\(/.test(codeLine);
}

function isFixedLocalProcessHarness(file: SourceFile, rawLine: string, codeLine: string): boolean {
  return isTestPath(file.displayPath) && /\b(?:spawn|execFile)\s*\(/.test(codeLine) && /\b(?:spawn|execFile)\s*\(\s*["']\.{1,2}\/[^"']*["']\s*,\s*\[/.test(rawLine);
}

function analyseTypeSafetyLine(file: SourceFile, line: string, codeLine: string, lineNumber: number, findings: Finding[]): void {
  pushTsDirectiveFinding(file, line, lineNumber, findings);
  pushNonNullAssertionFindings(file, codeLine, lineNumber, findings);
  pushDoubleCastFindings(file, codeLine, lineNumber, findings);
  pushExportedAnyFinding(file, codeLine, lineNumber, findings);
}

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

function analyseReliabilityLine(file: SourceFile, codeLine: string, lineNumber: number, findings: Finding[]): void {
  pushAsyncForEachFinding(file, codeLine, lineNumber, findings);
  pushFloatingPromiseFinding(file, codeLine, lineNumber, findings);
  pushNonErrorThrowFinding(file, codeLine, lineNumber, findings);
}

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

function hasDirectiveRationale(value: string): boolean {
  const cleaned = value.replace(/^[-:\s]+/, "").trim();
  const words = cleaned.match(/[A-Za-z]{3,}/g) ?? [];
  return hasSuppressionRationale(cleaned) || words.length >= 3;
}

function exportedAnySymbol(codeLine: string): string | undefined {
  if (!/\bexport\b/.test(codeLine) || !/\bany\b/.test(codeLine)) {
    return undefined;
  }
  const match = codeLine.match(/\bexport\s+(?:async\s+)?(?:function|const|let|var|class|interface|type)\s+([A-Za-z_$][A-Za-z0-9_$]*)/);
  return match?.[1];
}

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

function isHandledPromiseStatement(trimmedLine: string): boolean {
  return trimmedLine.length === 0 || /^(?:await|return|void|throw|yield)\b/.test(trimmedLine) || /^(?:const|let|var)\s+/.test(trimmedLine);
}

function leadingCallName(trimmedLine: string): string {
  const match = trimmedLine.match(/^([A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)\s*\(/);
  return match?.[1] ?? "";
}

function isPromiseLikeCall(callName: string): boolean {
  const localName = callName.split(".").at(-1) ?? callName;
  return callName === "fetch" || /(?:Async|Promise)$/.test(localName);
}

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

function isSwallowedCatchBody(body: string): boolean {
  const meaningful = body
    .replace(/\/\/.*$/gm, "")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .trim();
  return meaningful === "";
}

interface ExportedDeclaration {
  kind: string;
  name: string;
  line: number;
}

function analyseClassRules(file: SourceFile, source: string, codeSource: string, findings: Finding[]): void {
  analyseExportedDeclarations(file, source, codeSource, findings);
  analysePublicProperties(file, source, codeSource, findings);
  analyseReadonlyCandidates(file, source, codeSource, findings);
}

function analyseExportedDeclarations(file: SourceFile, source: string, codeSource: string, findings: Finding[]): void {
  for (const declaration of exportedDeclarations(source, codeSource)) {
    pushMissingPublicDocFinding(file, source, declaration, findings);
    pushClassFileMismatchFinding(file, declaration, findings);
  }
}

function exportedDeclarations(source: string, codeSource: string): ExportedDeclaration[] {
  return [...codeSource.matchAll(/\bexport\s+(class|interface|type|enum|function)\s+([A-Za-z_$][A-Za-z0-9_$]*)/g)].map((match) => ({
    kind: match[1] ?? "",
    name: match[2] ?? "",
    line: byteLine(source, match.index ?? 0),
  }));
}

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

function interfaceDeclarations(source: string, codeSource: string): ExportedDeclaration[] {
  return [...codeSource.matchAll(/^[ \t]*(?:export[ \t]+)?interface[ \t]+([A-Za-z_$][A-Za-z0-9_$]*)\b/gm)].map((match) => ({
    kind: "interface",
    name: match[1] ?? "",
    line: byteLine(source, match.index ?? 0),
  }));
}

// Shares precomputed comment indexes so documentation checks stay deterministic within one scan.
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
  pushFixturePurposeFindings(file, source, codeSource, lines, comments, blocks, config, findings);
}

// Keeps stale-reference checks separate from declaration-level documentation checks.
function analyseStandaloneCommentQuality(file: SourceFile, comments: CommentRecord[], descriptorIds: Set<string>, cliFlags: Set<string>, findings: Finding[]): void {
  for (const comment of comments) {
    pushTodoWithoutTrackingFinding(file, comment, findings);
    pushSuppressionWithoutRationaleFinding(file, comment, findings);
    pushStaleFileReferenceFindings(file, comment, findings);
    pushStaleRuleReferenceFindings(file, comment, descriptorIds, findings);
    pushStaleCliFlagReferenceFindings(file, comment, cliFlags, findings);
  }
}

// Applies declaration-aware comment rules only when a parsed leading comment exists.
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

// Limits function-context checks to comments that are not just restating the signature.
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

// Targets only large fixture-like source so ordinary tests and short examples stay quiet.
function pushFixturePurposeFindings(file: SourceFile, source: string, codeSource: string, lines: string[], comments: CommentRecord[], blocks: FunctionBlock[], config: Config, findings: Finding[]): void {
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

function pushUniqueFixturePurposeCandidate(candidates: FixturePurposeCandidate[], seen: Set<string>, candidate: FixturePurposeCandidate): void {
  const key = `${candidate.line}\0${candidate.symbol}\0${candidate.targetKind}`;
  if (seen.has(key)) {
    return;
  }
  seen.add(key);
  candidates.push(candidate);
}

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

function fixtureConstantName(codeLine: string): string | undefined {
  return codeLine.match(/\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*(?:Fixture|FIXTURE)[A-Za-z0-9_$]*)\b[^=\n]*=/)?.[1];
}

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

function fixtureLineInsideBlock(block: FunctionBlock, occupiedLines: Set<number>): boolean {
  const endLine = block.startLine + block.lineCount - 1;
  for (const line of occupiedLines) {
    if (line >= block.startLine && line <= endLine) {
      return true;
    }
  }
  return false;
}

function hasFixtureSetupSignal(source: string): boolean {
  return /\b(?:analyseFixture|writeFileSync|mkdtempSync|Array\.from)\s*\(/.test(source) || hasFixtureIdentifier(source);
}

function hasFixtureIdentifier(source: string): boolean {
  for (const match of source.matchAll(/\b[A-Za-z_$][A-Za-z0-9_$]*\b/g)) {
    if ((match[0] ?? "").toLowerCase().includes("fixture")) {
      return true;
    }
  }
  return false;
}

function isLargeSourceFixtureText(text: string): boolean {
  return fixtureLineCount(text) > FIXTURE_PURPOSE_MIN_LINES && /\b(?:function|class|interface|type|enum|const|let|var|import|export|test|it)\b/.test(text);
}

function fixtureLineCount(text: string): number {
  return text.split(/\r?\n/).length;
}

function sourceLineStartOffsets(source: string): number[] {
  const offsets = [0];
  for (let index = 0; index < source.length; index += 1) {
    if (source[index] === "\n") {
      offsets.push(index + 1);
    }
  }
  return offsets;
}

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

function hasFixturePurposeComment(lines: string[], comments: CommentRecord[], line: number): boolean {
  const sameLine = comments.find((comment) => comment.line <= line && comment.endLine >= line);
  if (sameLine && hasFixturePurposeMarker(sameLine.text)) {
    return true;
  }
  const leading = leadingFixturePurposeComment(lines, comments, line);
  return Boolean(leading && hasFixturePurposeMarker(leading.text));
}

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

function hasOnlyBlankFixturePurposeGap(lines: string[], startLine: number, endLine: number): boolean {
  for (let line = startLine; line <= endLine; line += 1) {
    if ((lines[line - 1] ?? "").trim() !== "") {
      return false;
    }
  }
  return true;
}

function hasFixturePurposeMarker(text: string): boolean {
  return /\b(?:fixture|covers|reproduces|regression|scanner|parse|baseline|fingerprint|noise|valid case|invalid case|because|M\d{1,3})\b/i.test(text) || /\.goat-flow\/tasks\//.test(text);
}

function commentedDeclarations(blocks: FunctionBlock[], interfaces: ExportedDeclaration[]): CommentedDeclaration[] {
  return [
    ...blocks
      .filter((block) => !block.isTest)
      .map((block) => ({ kind: "function" as const, name: block.name, line: block.declarationLine, isPublic: block.isPublic })),
    ...interfaces.map((declaration) => ({ kind: "interface" as const, name: declaration.name, line: declaration.line, isPublic: true })),
  ];
}

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

// Accepts durable tracking markers rather than forcing one issue system.
function hasTodoTracking(text: string): boolean {
  return TODO_TRACKING_PATTERNS.some((pattern) => pattern.test(text));
}

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

function suppressionDirective(text: string): string | undefined {
  if (/@ts-(?:ignore|expect-error|nocheck|check)\b/.test(text)) {
    return undefined;
  }
  const match = text.match(/\b(eslint-disable(?:-next-line|-line)?|biome-ignore|oxlint-disable|istanbul ignore|c8 ignore|v8 ignore|prettier-ignore)\b/i);
  return match?.[1];
}

function hasSuppressionRationale(text: string): boolean {
  return /\b(?:because|intentional|false positive|tracked in|M\d{1,3}|ADR-\d{3}|GH-\d+)\b/i.test(text) || /\breason\s*:/i.test(text) || /(?:^|\s)#\d+\b/.test(text) || /https?:\/\//i.test(text) || /\.goat-flow\/tasks\//.test(text);
}

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

function referencedPathExists(file: SourceFile, referencedPath: string): boolean {
  const fromProject = resolve(cwd(), referencedPath);
  const fromFile = resolve(dirnamePath(file.absolutePath), referencedPath);
  return existsSync(fromProject) || existsSync(fromFile);
}

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

// Extracts names from prose without treating every identifier mention as documentation drift.
function referencedDeclarationName(text: string, kind: CommentedDeclaration["kind"]): string | undefined {
  const identifier = "([A-Za-z_$][A-Za-z0-9_$]*)";
  const direct = text.match(new RegExp(["\\b", kind, "\\s+`?", identifier, "`?"].join(""), "i"));
  if (direct?.[1]) {
    return direct[1];
  }
  const leading = text.match(new RegExp(["^`?", identifier, "`?\\s+(?:", kind, "|helper|method|contract|type)\\b"].join(""), "i"));
  return leading?.[1];
}

function pushRestatingSignatureCommentFinding(file: SourceFile, comment: CommentRecord, declaration: CommentedDeclaration, findings: Finding[]): void {
  if (declaration.kind === "function" && declaration.isPublic && comment.kind === "block") {
    return;
  }
  if (!isRestatingSignatureComment(comment.text, declaration.name, declaration.kind)) {
    return;
  }
  findings.push(docFinding({ ruleId: "docs.useless-docblock", message: `Comment for \`${declaration.name}\` only restates the signature.`, file, line: comment.line, symbol: declaration.name }));
}

// Emits at most one finding for each missing context class on a documented function.
function pushFunctionContextFindings(file: SourceFile, block: FunctionBlock, comment: CommentRecord, config: Config, findings: Finding[]): void {
  for (const detail of functionContextDocFindings(block, comment.text, config)) {
    findings.push(contextDocFinding({ file, comment, ...detail }));
  }
}

// Evaluates independent context classes before materialising stable findings.
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

// Requires "why" context only after the function crosses a configured complexity threshold.
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

// Centralises shared metadata so context-doc findings keep identical shape.
function contextDocDetails(symbol: string, ruleId: string, message: string, remediation: string, contextClass: string): ContextDocFindingDetails {
  return {
    symbol,
    ruleId,
    message,
    remediation,
    metadata: { contextClass },
  };
}

// Checks interface comments for public contract cues without duplicating function logic.
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

// Materialises a documentation-context finding using the comment location as the anchor.
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

function hasComplexWhyMarker(text: string): boolean {
  return /\b(?:because|why|intentional|tradeoff|compat|avoid|preserve)\b/i.test(text);
}

function hasSideEffectMarker(text: string): boolean {
  return /\b(?:writes|reads|persists|mutates|starts|spawns|network|filesystem|environment)\b/i.test(text);
}

function hasErrorBehaviorMarker(text: string): boolean {
  return /\b(?:throws|returns diagnostic|reports|exits|swallows|fallback|recover)\b/i.test(text);
}

function hasInvariantMarker(text: string): boolean {
  return /\b(?:invariant|contract|must|stable|deterministic|schema|fingerprint)\b/i.test(text);
}

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

// Treats filesystem, process, HTTP, and server operations as comment-worthy effects.
function hasSideEffectSignal(name: string, body: string): boolean {
  return SIDE_EFFECT_BODY_PATTERNS.some((pattern) => pattern.test(body)) || /^(?:write|recordHistory|startDashboard)\b/.test(name);
}

function hasErrorBehaviorSignal(body: string): boolean {
  return /\bthrow\b|\bcatch\b|\bprocess\.exit\s*\(|\bdiagnosticType\s*:|\b(?:findings|diagnostics)\.push\s*\(/.test(body);
}

// Detects public-contract vocabulary in function names or bodies.
function hasInvariantFunctionSignal(block: FunctionBlock): boolean {
  const signalText = [block.name, block.codeBody].join("\n");
  return /\b(?:fingerprint|schemaVersion|baseline|AnalysisReport|Finding|stable sort|deterministic|dedupe|sort)\b/i.test(signalText);
}

function hasInvariantInterfaceSignal(lines: string[], declaration: CommentedDeclaration): boolean {
  const blockText = declarationBlockText(lines, declaration.line);
  const signalText = `${declaration.name}\n${blockText}`;
  return /\b(?:fingerprint|schemaVersion|baseline|report|Finding|AnalysisReport|Baseline|stable|deterministic)\b/i.test(signalText);
}

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

// Finds hard-coded limits that are likely policy rather than ordinary arithmetic.
function magicThresholdCandidate(rawLine: string, codeLine: string): MagicThresholdCandidate | undefined {
  return namedThresholdCandidate(rawLine) ?? configDefaultThresholdCandidate(rawLine, codeLine);
}

// Names such as "maxLength" usually deserve rationale when set above common sentinels.
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

// Config threshold defaults are scanned only when the unmasked code still calls threshold().
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

function isCommonSafeNumber(value: string): boolean {
  return ["-1", "0", "1", "2"].includes(value);
}

function hasNearbyThresholdRationale(lines: string[], comments: CommentRecord[], line: number): boolean {
  const sameLine = comments.find((comment) => comment.line <= line && comment.endLine >= line);
  if (sameLine && hasThresholdRationaleMarker(sameLine.text)) {
    return true;
  }
  const leading = leadingCommentForLine(lines, comments, line);
  return Boolean(leading && hasThresholdRationaleMarker(leading.text));
}

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

function normalizedCommentWords(text: string): string[] {
  return text
    .replace(/`/g, " ")
    .replace(/[^A-Za-z0-9_$]+/g, " ")
    .trim()
    .split(/\s+/)
    .flatMap(splitIdentifierWords)
    .filter(Boolean);
}

function restatementStopWords(kind: CommentedDeclaration["kind"]): Set<string> {
  return new Set(["a", "an", "the", "this", "that", "function", "method", "helper", "type", "declaration", kind]);
}

function stemCommentWord(word: string): string {
  return word.length > 3 && word.endsWith("s") ? word.slice(0, -1) : word;
}

function sameWords(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((word, index) => word === right[index]);
}

function hasUsefulCommentContext(text: string): boolean {
  return /\b(?:because|why|intentional|tradeoff|compat|avoid|preserve|invariant|contract|side effect|throws|writes|reads|persists|fallback|recover|stable|deterministic|schema|fingerprint)\b/i.test(text);
}

function isHistoricalContextComment(text: string): boolean {
  return /\b(?:previously|legacy|compat|migration|ADR)\b/i.test(text);
}

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

function hasOnlyBlankLines(lines: string[], startLine: number, endLine: number): boolean {
  for (let line = startLine; line < endLine; line += 1) {
    if ((lines[line - 1] ?? "").trim() !== "") {
      return false;
    }
  }
  return true;
}

function commentRecords(source: string): CommentRecord[] {
  const records: CommentRecord[] = [];
  let quote: string | undefined;
  let isEscaped = false;
  let isRegex = false;
  let isRegexEscaped = false;
  let isRegexCharClass = false;
  let previousCode = "";
  let line = 1;

  for (let index = 0; index < source.length; index += 1) {
    const character = source[index] ?? "";
    const next = source[index + 1] ?? "";
    if (character === "\n") {
      line += 1;
      if (quote !== "`") {
        quote = undefined;
      }
      isRegex = false;
      isRegexEscaped = false;
      isRegexCharClass = false;
      continue;
    }
    if (quote) {
      const state = scanQuotedCommentCharacter(character, quote, isEscaped);
      quote = state.quote;
      isEscaped = state.isEscaped;
      continue;
    }
    if (isRegex) {
      const state = scanRegexCommentCharacter(character, isRegexEscaped, isRegexCharClass);
      isRegex = state.isRegex;
      isRegexEscaped = state.isEscaped;
      isRegexCharClass = state.isCharClass;
      continue;
    }
    if (character === "/" && next === "/") {
      const record = lineCommentRecord(source, index, line);
      records.push(record);
      index = record.endIndex - 1;
      continue;
    }
    if (character === "/" && next === "*") {
      const record = blockCommentRecord(source, index, line);
      records.push(record);
      line = record.endLine;
      index = record.endIndex;
      continue;
    }
    if (character === "\"" || character === "'" || character === "`") {
      quote = character;
      isEscaped = false;
      previousCode = character;
      continue;
    }
    if (character === "/" && isCommentRegexStart(previousCode, source.slice(Math.max(0, index - 40), index))) {
      isRegex = true;
      isRegexEscaped = false;
      isRegexCharClass = false;
      previousCode = character;
      continue;
    }
    if (/\S/.test(character)) {
      previousCode = character;
    }
  }
  return records;
}

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

function isCommentRegexStart(previousCode: string, beforeSlash: string): boolean {
  return previousCode === "" || "([{=,:!&|?;".includes(previousCode) || /\breturn$/.test(beforeSlash.trimEnd());
}

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

function normalizedBlockCommentText(text: string): string {
  return text
    .split(/\r?\n/)
    .map((line) => line.replace(/^[ \t]*\*[ \t]?/, "").trim())
    .filter((line) => line !== "")
    .join(" ")
    .trim();
}

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

function analysePublicProperties(file: SourceFile, source: string, codeSource: string, findings: Finding[]): void {
  const publicProperty = /\bpublic\s+[A-Za-z_$][A-Za-z0-9_$]*\s*[=:]/g;
  for (const match of codeSource.matchAll(publicProperty)) {
    findings.push(finding({ ruleId: "modernisation.public-property", message: "Public class property exposes representation; prefer readonly or accessors when invariants matter.", file, line: byteLine(source, match.index ?? 0), severity: "advisory", pillar: "modernisation" }));
  }
}

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

interface DocumentedExportBlock {
  doc: string;
  name: string;
  params: string[];
  paramTags: string[];
  line: number;
  returnType: string;
}

interface DocFindingInput {
  ruleId: string;
  message: string;
  file: SourceFile;
  line: number;
  symbol: string;
  parameter?: string;
}

function analyseDocRules(file: SourceFile, source: string, codeSource: string, findings: Finding[]): void {
  for (const documentedExport of documentedExportBlocks(source, codeSource)) {
    pushStaleParamFindings(file, documentedExport, findings);
    pushMissingParamFindings(file, documentedExport, findings);
    pushMissingReturnFinding(file, documentedExport, findings);
    pushUselessDocblockFinding(file, documentedExport, findings);
  }
}

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

function regexMatchStart(match: RegExpMatchArray): number {
  return match.index ?? 0;
}

function regexGroup(match: RegExpMatchArray, index: number): string {
  return match[index] ?? "";
}

function isDocumentedExportInCode(codeSource: string, exportIndex: number): boolean {
  return exportIndex >= 0 && codeSource[exportIndex] === "e";
}

function pushStaleParamFindings(file: SourceFile, block: DocumentedExportBlock, findings: Finding[]): void {
  for (const tag of block.paramTags) {
    if (!block.params.includes(tag)) {
      findings.push(docFinding({ ruleId: "docs.stale-param-tag", message: `Docblock for \`${block.name}\` has stale @param tag \`${tag}\`.`, file, line: block.line, symbol: block.name, parameter: tag }));
    }
  }
}

function pushMissingParamFindings(file: SourceFile, block: DocumentedExportBlock, findings: Finding[]): void {
  for (const param of block.params) {
    if (!block.paramTags.includes(param)) {
      findings.push(docFinding({ ruleId: "docs.missing-param-tag", message: `Docblock for \`${block.name}\` is missing @param for \`${param}\`.`, file, line: block.line, symbol: block.name, parameter: param }));
    }
  }
}

function pushMissingReturnFinding(file: SourceFile, block: DocumentedExportBlock, findings: Finding[]): void {
  if (!needsReturnTag(block)) {
    return;
  }
  findings.push(docFinding({ ruleId: "docs.missing-return-tag", message: `Docblock for \`${block.name}\` is missing @returns.`, file, line: block.line, symbol: block.name }));
}

function needsReturnTag(block: DocumentedExportBlock): boolean {
  return block.returnType !== "" && !/^void\b/.test(block.returnType) && !/@returns?\b/.test(block.doc);
}

function pushUselessDocblockFinding(file: SourceFile, block: DocumentedExportBlock, findings: Finding[]): void {
  if (isUselessDocblock(block.doc, block.name)) {
    findings.push(docFinding({ ruleId: "docs.useless-docblock", message: `Docblock for \`${block.name}\` only restates the signature.`, file, line: block.line, symbol: block.name }));
  }
}

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

function isBranchLabel(trimmedLine: string): boolean {
  return /^(?:case\b.*:|default\s*:)$/.test(trimmedLine);
}

function isUnreachableStatement(trimmedLine: string, didPreviousTerminate: boolean, branchLabel: boolean): boolean {
  return didPreviousTerminate && /\S/.test(trimmedLine) && !trimmedLine.startsWith(String.fromCharCode(125)) && !branchLabel;
}

function isTerminatingStatement(trimmedLine: string): boolean {
  return /\b(return|throw|process\.exit)\b/.test(trimmedLine) && trimmedLine.endsWith(";");
}

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

function isNamedImportLine(trimmedLine: string): boolean {
  return trimmedLine.startsWith("import ") && trimmedLine.includes(" from ");
}

function hasNamedImportBraces(openBrace: number, closeBrace: number): boolean {
  return openBrace !== -1 && closeBrace !== -1 && closeBrace > openBrace;
}

function unusedImportName(source: string, specifier: string): string | undefined {
  const name = localImportName(specifier);
  if (!name || countMatches(source, new RegExp(`\\b${escapeRegex(name)}\\b`, "g")) > 1) {
    return undefined;
  }
  return name;
}

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

function localImportName(specifier: string): string | undefined {
  const parts = specifier.trim().split(/\s+as\s+/);
  const candidate = parts[1] ?? parts[0] ?? "";
  const match = candidate.trim().match(/^[A-Za-z_$][A-Za-z0-9_$]*/);
  return match?.[0];
}

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

function isEmptyFunctionBody(source: string): boolean {
  const body = functionBodyContent(source)
    .replace(/\/\/.*$/gm, "")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .trim();
  return body === "";
}

function functionBodyContent(source: string): string {
  const start = source.indexOf("{");
  const end = source.lastIndexOf("}");
  if (start === -1 || end <= start) {
    const arrow = source.indexOf("=>");
    return arrow === -1 ? "" : source.slice(arrow + 2).replace(/;?\s*$/, "");
  }
  return source.slice(start + 1, end);
}

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

function redundantVariableReturns(source: string): Array<{ name: string; lineOffset: number }> {
  const results: Array<{ name: string; lineOffset: number }> = [];
  for (const match of source.matchAll(/\b(?:const|let)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*[^;]+;\s*return\s+\1\s*;/g)) {
    results.push({ name: match[1] ?? "", lineOffset: lineOffset(source, match.index ?? 0) });
  }
  return results.filter((result) => result.name !== "");
}

function lineOffset(source: string, index: number): number {
  return source.slice(0, Math.max(0, index)).split("\n").length - 1;
}

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

function hasBooleanPrefix(name: string, prefixes: Set<string>): boolean {
  const regex = booleanPrefixRegex(prefixes);
  return regex !== null && regex.test(name);
}

function booleanPrefixRegex(prefixes: Set<string>): RegExp | null {
  if (BOOLEAN_PREFIX_REGEX_CACHE.has(prefixes)) {
    return BOOLEAN_PREFIX_REGEX_CACHE.get(prefixes) ?? null;
  }
  const regex = prefixes.size === 0 ? null : new RegExp(`^(?:${[...prefixes].map(escapeRegex).join("|")})[A-Z_]`);
  BOOLEAN_PREFIX_REGEX_CACHE.set(prefixes, regex);
  return regex;
}

function hungarianPrefixRegex(prefixes: Set<string>): RegExp | null {
  if (HUNGARIAN_PREFIX_REGEX_CACHE.has(prefixes)) {
    return HUNGARIAN_PREFIX_REGEX_CACHE.get(prefixes) ?? null;
  }
  const regex = prefixes.size === 0 ? null : new RegExp(`\\b(?:const|let|var|public|private|protected)\\s+((?:${[...prefixes].map(escapeRegex).join("|")})[A-Z][A-Za-z0-9_$]*)`, "g");
  HUNGARIAN_PREFIX_REGEX_CACHE.set(prefixes, regex);
  return regex;
}

function fileBaseName(path: string): string {
  return basename(path).replace(/\.[^.]+$/, "");
}

function normalizedIdentifier(value: string): string {
  return value.replace(/[^A-Za-z0-9]/g, "").toLowerCase();
}

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

function docParamTagName(line: string): string | undefined {
  const marker = line.indexOf("@param");
  if (marker === -1) {
    return undefined;
  }
  const rest = stripDocParamType(line.slice(marker + "@param".length).trim());
  return rest.match(/^([A-Za-z_$][A-Za-z0-9_$]*)/)?.[1];
}

function stripDocParamType(rest: string): string {
  if (!rest.startsWith(String.fromCharCode(123))) {
    return rest;
  }
  const end = rest.indexOf(String.fromCharCode(125));
  return end === -1 ? "" : rest.slice(end + 1).trim();
}

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

function splitIdentifierWords(value: string): string[] {
  return value
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .split(/[^A-Za-z0-9]+/)
    .map((word) => word.toLowerCase())
    .filter(Boolean);
}

function hasTrivialAssertion(source: string): boolean {
  return hasLiteralTrivialAssertion(source) || hasRepeatedAssertArgument(source) || hasRepeatedExpectArgument(source);
}

function hasLiteralTrivialAssertion(source: string): boolean {
  return (
    /\bassert\.ok\s*\(\s*true\s*\)/.test(source) ||
    /\bassert\.(?:equal|strictEqual|deepEqual)\s*\(\s*(true|false|null|undefined|\d+|["'][^"']*["'])\s*,\s*\1\s*\)/.test(source)
  );
}

function hasRepeatedAssertArgument(source: string): boolean {
  for (const match of source.matchAll(/\bassert\.(?:equal|strictEqual|deepEqual)\s*\(\s*([^,\n]+?)\s*,\s*([^,\n)]+?)(?:\s*,|\s*\))/g)) {
    if (normalizeAssertionExpression(match[1] ?? "") === normalizeAssertionExpression(match[2] ?? "")) {
      return true;
    }
  }
  return false;
}

function hasRepeatedExpectArgument(source: string): boolean {
  for (const match of source.matchAll(/\bexpect\s*\(\s*([^)]+?)\s*\)\s*\.\s*to(?:Be|Equal|StrictEqual)\s*\(\s*([^)]+?)\s*\)/g)) {
    if (normalizeAssertionExpression(match[1] ?? "") === normalizeAssertionExpression(match[2] ?? "")) {
      return true;
    }
  }
  return false;
}

function normalizeAssertionExpression(expression: string): string {
  return expression.trim().replace(/;$/, "");
}

function hasAssertion(source: string): boolean {
  return /\bassert(?:\.[A-Za-z]+)?\s*\(/.test(source) || /\bexpect(?:\.(?:assertions|hasAssertions))?\s*\(/.test(source);
}

function isSnapshotOnlyTest(source: string): boolean {
  if (!/\.\s*toMatch(?:Inline)?Snapshot\s*\(/.test(source)) {
    return false;
  }
  const withoutSnapshots = source
    .replace(/\bexpect\s*\([\s\S]*?\)\s*\.\s*toMatch(?:Inline)?Snapshot\s*\([^)]*\)\s*;?/g, "")
    .replace(/\bexpect\.(?:assertions|hasAssertions)\s*\([^)]*\)\s*;?/g, "");
  return !hasAssertion(withoutSnapshots);
}

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

function hasExceptionTypeOnlyAssertion(source: string): boolean {
  return /\.toThrow\s*\(\s*(?:Error|[A-Z][A-Za-z0-9_$]*Error)\s*\)/.test(source) || /\bassert\.throws\s*\([^,\n]+,\s*(?:Error|[A-Z][A-Za-z0-9_$]*Error)\s*\)/.test(source);
}

function hasGlobalStateMutation(source: string): boolean {
  return /\bprocess\.env\.[A-Za-z0-9_]+\s*=/.test(source) || /\bglobalThis\.[A-Za-z0-9_$]+\s*=/.test(source) || /\b(?:Date\.now|Math\.random)\s*=/.test(source);
}

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

function isIgnorableSetupLine(trimmedLine: string): boolean {
  return trimmedLine.length === 0 || trimmedLine === "});" || trimmedLine === "}";
}

function isTestInvocationLine(line: string): boolean {
  return /^\s*(?:test|it)\s*\(/.test(line);
}

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

function functionBlockPatterns(): RegExp[] {
  return [
    /^\s*(?:test|it)\s*\(\s*["'`]([^"'`]+)["'`]\s*,\s*(?:async\s*)?\(([^)]*)\)\s*=>/,
    /^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)/,
    /^\s*(?:public|private|protected)?\s*(?:async\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)\s*[:{]/,
    /^\s*(?:const|let)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>/,
  ];
}

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

function functionPatternMatch(pattern: RegExp, patternIndex: number, line: string, rawLine: string): RegExpMatchArray | undefined {
  const candidate = patternIndex === 0 && isTestInvocationLine(line) ? rawLine : line;
  const match = candidate.match(pattern);
  if (!match?.[1] || isControlBlockName(match[1])) {
    return undefined;
  }
  return match;
}

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

function functionEndIndex(scan: FunctionBlockScan, index: number): number {
  return expressionArrowEndIndex(scan.codeLines, index) ?? blockFunctionEndIndex(scan, index);
}

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

function applyFunctionBodyCharacter(state: FunctionBodyScanState, character: string): void {
  if (character === "{") {
    state.depth += 1;
    state.hasSeenOpen = true;
  } else if (character === "}") {
    state.depth -= 1;
  }
}

function isFunctionBodyClosed(state: FunctionBodyScanState): boolean {
  return state.hasSeenOpen && state.depth <= 0;
}

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

function isExpressionArrowLine(line: string, arrowIndex: number): boolean {
  return arrowIndex !== -1 && !line.slice(arrowIndex + 2).includes("{");
}

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

function isControlBlockName(name: string): boolean {
  return ["if", "for", "while", "switch", "catch"].includes(name);
}

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

function isFunctionPrefixLine(trimmedLine: string): boolean {
  return trimmedLine.startsWith("@") || trimmedLine.startsWith("/**") || trimmedLine.startsWith("*") || trimmedLine === "";
}

interface LineFindingArgs {
  ruleId: string;
  message: string;
  file: SourceFile;
  line: number;
  severity: Severity;
  pillar: Pillar;
}

interface BlockFindingArgs {
  ruleId: string;
  message: string;
  file: SourceFile;
  block: FunctionBlock;
  severity: Severity;
  pillar: Pillar;
}

interface BlockFindingWithMetadataArgs extends BlockFindingArgs {
  metadata: Record<string, unknown>;
}

function finding(args: LineFindingArgs): Finding {
  return makeFinding({ ruleId: args.ruleId, message: args.message, filePath: args.file.displayPath, line: args.line, severity: args.severity, pillar: args.pillar, confidence: "high" });
}

function blockFinding(args: BlockFindingArgs): Finding {
  return makeFinding({ ruleId: args.ruleId, message: args.message, filePath: args.file.displayPath, line: args.block.startLine, severity: args.severity, pillar: args.pillar, confidence: "high", symbol: args.block.name });
}

function blockFindingWithMetadata(args: BlockFindingWithMetadataArgs): Finding {
  return makeFinding({ ruleId: args.ruleId, message: args.message, filePath: args.file.displayPath, line: args.block.startLine, severity: args.severity, pillar: args.pillar, confidence: "medium", symbol: args.block.name, metadata: args.metadata });
}

function writeCommandOutput(program: Command, output: string): void {
  if (outputSuppressed(program)) {
    return;
  }
  process.stdout.write(output.endsWith("\n") ? output : `${output}\n`);
}

function outputSuppressed(program: Command): boolean {
  const options = program.opts() as { quiet?: boolean; silent?: boolean };
  return options.quiet === true || options.silent === true;
}

function ansiEnabled(program: Command): boolean {
  const options = program.opts() as { ansi?: boolean };
  if (options.ansi === true) {
    return true;
  }
  if (options.ansi === false) {
    return false;
  }
  return process.stdout.isTTY === true;
}

function buildProgram(): Command {
  const program = new Command();
  configureRootProgram(program);
  registerAnalyseCommand(program);
  registerCompletionCommand(program);
  registerDashboardCommand(program);
  registerListCommand(program);
  registerListRulesCommand(program);
  registerReportCommand(program);
  registerSummaryCommand(program);
  return program;
}

function configureRootProgram(program: Command): void {
  program
    .name("gruff-ts")
    .usage("command [options] [arguments]")
    .helpOption("-h, --help", "Display help for the given command. When no command is given display help for the list command")
    .version(VERSION, "-V, --version", "Display this application version")
    .option("--silent", "Do not output any message")
    .option("-q, --quiet", "Only errors are displayed. All other output is suppressed")
    .option("--ansi", "Force ANSI output")
    .option("--no-ansi", "Disable ANSI output")
    .option("-n, --no-interaction", "Do not ask any interactive question")
    .option("-v, --verbose", "Increase the verbosity of messages: 1 for normal output, 2 for more verbose output and 3 for debug", (_value, previous: number) => previous + 1, 0)
    .addHelpCommand("help [command]", "Display help for a command")
    .showHelpAfterError()
    .configureHelp({
      formatHelp(command, helper) {
        return rootHelpText(program, command, helper);
      },
    })
    .action(() => {
      writeCommandOutput(program, renderConsoleList(ansiEnabled(program)));
    });
}

function rootHelpText(program: Command, command: Command, helper: Help): string {
  if (command === program) {
    return renderConsoleList(ansiEnabled(program));
  }
  const defaultHelp = new Help();
  defaultHelp.showGlobalOptions = true;
  if (helper.helpWidth !== undefined) {
    defaultHelp.helpWidth = helper.helpWidth;
  }
  if (helper.minWidthToWrap !== undefined) {
    defaultHelp.minWidthToWrap = helper.minWidthToWrap;
  }
  return defaultHelp.formatHelp(command, defaultHelp);
}

function registerAnalyseCommand(program: Command): void {
  program
    .command("analyse")
    .description("Run gruff analysis.")
    .argument("[paths...]", "Files or directories to analyse.")
    .option("--config <path>", "Path to a gruff YAML config file.")
    .option("--no-config", "Skip auto-applying the default .gruff-ts.yaml file for this run.")
    .option("--format <format>", "Output format: text, json, html, markdown, github, hotspot, or sarif.", "text")
    .option("--fail-on <severity>", "Finding severity that fails the run: advisory, warning, error, or none.", "error")
    .option("--include-ignored", "Include files under default and Git ignored paths; config ignores still apply.")
    .option("--diff [mode]", "Filter findings to changed files. Use working-tree, staged, unstaged, or a base ref.")
    .option("--history-file <path>", "Append score trend history to this JSON file.")
    .option("--baseline [path]", "Suppress findings that match a gruff baseline JSON file.")
    .option("--generate-baseline [path]", "Write current findings to a gruff baseline JSON file.")
    .option("--no-baseline", "Skip auto-applying the default baseline file for this run.")
    .action((paths: string[], rawOptions: Record<string, unknown>) => {
      const options = normalizeOptions(paths, rawOptions, { allowBaselineFlag: true });
      const report = analyse(options);
      writeCommandOutput(program, renderReport(report, options.format));
      process.exitCode = exitFor(report, options.failOn);
    });
}

function registerCompletionCommand(program: Command): void {
  program
    .command("completion")
    .description("Dump the shell completion script")
    .argument("[shell]", "Shell to generate completion for: bash, zsh, or fish.", "bash")
    .action((shell: string) => {
      writeCommandOutput(program, renderCompletionScript(completionShell(shell)));
    });
}

function registerDashboardCommand(program: Command): void {
  program
    .command("dashboard")
    .description("Serve the local gruff dashboard.")
    .option("--host <host>", "Host to bind.", "127.0.0.1")
    .option("--port <port>", "Port to bind.", "8767")
    .option("--project-root <path>", "Default project root.", ".")
    .action((rawOptions: Record<string, unknown>) => {
      startDashboard(String(rawOptions.host ?? "127.0.0.1"), Number(rawOptions.port ?? 8767), resolve(String(rawOptions.projectRoot ?? ".")), analyse, !outputSuppressed(program));
    });
}

function registerListCommand(program: Command): void {
  program
    .command("list")
    .description("List commands")
    .action(() => {
      writeCommandOutput(program, renderConsoleList(ansiEnabled(program)));
    });
}

function registerListRulesCommand(program: Command): void {
  program
    .command("list-rules")
    .description("List gruff rule metadata.")
    .option("--format <format>", "Output format: text or json.", "text")
    .action((rawOptions: Record<string, unknown>) => {
      const format: RuleListFormat = rawOptions.format === "json" ? "json" : "text";
      writeCommandOutput(program, renderRuleList(format));
    });
}

function registerReportCommand(program: Command): void {
  program
    .command("report")
    .description("Render a gruff report to stdout or a file.")
    .argument("[paths...]", "Files or directories to analyse.")
    .option("--format <format>", "Report format: html or json.", "html")
    .option("--output <path>", "Write report to a file.")
    .option("--config <path>", "Path to a gruff YAML config file.")
    .option("--no-config", "Skip auto-applying the default .gruff-ts.yaml file for this run.")
    .option("--fail-on <severity>", "Finding severity that fails the run.", "none")
    .option("--include-ignored", "Include files under default and Git ignored paths; config ignores still apply.")
    .option("--no-baseline", "Skip auto-applying the default baseline file for this run.")
    .action((paths: string[], rawOptions: Record<string, unknown>) => {
      const format = rawOptions.format === "json" ? "json" : "html";
      const options = normalizeOptions(paths, { ...rawOptions, format }, { allowBaselineFlag: false });
      const report = analyse(options);
      const rendered = renderReport(report, format);
      if (typeof rawOptions.output === "string") {
        writeFileSync(rawOptions.output, rendered);
      } else {
        writeCommandOutput(program, rendered);
      }
      process.exitCode = exitFor(report, options.failOn);
    });
}

function registerSummaryCommand(program: Command): void {
  program
    .command("summary")
    .description(
      "Print a compact digest of a scan: per-pillar finding counts, top rules, and top file offenders. Runs the analyser once and renders only the summary; no per-finding spam.",
    )
    .argument("[paths...]", "Files or directories to analyse.")
    .option("--config <path>", "Path to a gruff YAML config file.")
    .option("--no-config", "Skip auto-applying the default .gruff-ts.yaml file for this run.")
    .option("--fail-on <severity>", "Finding severity that fails the run: advisory, warning, error, or none.", "error")
    .option("--include-ignored", "Include files under default and Git ignored paths; config ignores still apply.")
    .option("--diff [mode]", "Filter findings to changed files. Use working-tree, staged, unstaged, or a base ref.")
    .option("--history-file <path>", "Append score trend history to this JSON file.")
    .option("--baseline [path]", "Suppress findings that match a gruff baseline JSON file.")
    .option("--generate-baseline [path]", "Write current findings to a gruff baseline JSON file.")
    .option("--no-baseline", "Skip auto-applying the default baseline file for this run.")
    .action((paths: string[], rawOptions: Record<string, unknown>) => {
      const options = normalizeOptions(paths, { ...rawOptions, format: "text" }, { allowBaselineFlag: true });
      const report = analyse(options);
      writeCommandOutput(program, renderSummary(report));
      process.exitCode = exitFor(report, options.failOn);
    });
}

function normalizeOptions(paths: string[], rawOptions: Record<string, unknown>, context: NormalizeContext): AnalysisOptions {
  const format = stringChoice(rawOptions.format, ["text", "json", "html", "markdown", "github", "hotspot", "sarif"], "text");
  const failOn = stringChoice(rawOptions.failOn, ["none", "advisory", "warning", "error"], "error");
  const baselineValue = rawOptions.baseline;
  const noBaseline = baselineValue === false || rawOptions.noBaseline === true;
  return {
    paths,
    ...configOption(rawOptions),
    noConfig: rawOptions.config === false || rawOptions.noConfig === true,
    format,
    failOn,
    includeIgnored: rawOptions.includeIgnored === true,
    ...diffOption(rawOptions),
    ...historyFileOption(rawOptions),
    ...baselineOption(baselineValue, context),
    ...generateBaselineOption(rawOptions),
    noBaseline,
  };
}

function configOption(rawOptions: Record<string, unknown>): Partial<Pick<AnalysisOptions, "config">> {
  return typeof rawOptions.config === "string" ? { config: rawOptions.config } : {};
}

function diffOption(rawOptions: Record<string, unknown>): Partial<Pick<AnalysisOptions, "diff">> {
  if (typeof rawOptions.diff === "string") {
    return { diff: rawOptions.diff };
  }
  return rawOptions.diff === true ? { diff: "working-tree" } : {};
}

function historyFileOption(rawOptions: Record<string, unknown>): Partial<Pick<AnalysisOptions, "historyFile">> {
  return typeof rawOptions.historyFile === "string" ? { historyFile: rawOptions.historyFile } : {};
}

function baselineOption(baselineValue: unknown, context: NormalizeContext): Partial<Pick<AnalysisOptions, "baseline">> {
  if (!context.allowBaselineFlag) {
    return {};
  }
  if (typeof baselineValue === "string") {
    return { baseline: baselineValue };
  }
  return baselineValue === true ? { baseline: DEFAULT_BASELINE } : {};
}

function generateBaselineOption(rawOptions: Record<string, unknown>): Partial<Pick<AnalysisOptions, "generateBaseline">> {
  if (typeof rawOptions.generateBaseline === "string") {
    return { generateBaseline: rawOptions.generateBaseline };
  }
  return rawOptions.generateBaseline === true ? { generateBaseline: DEFAULT_BASELINE } : {};
}

function changedFiles(mode: string): Set<string> {
  const args = ["diff", "--name-only"];
  if (mode === "staged") {
    args.push("--cached");
  } else if (mode !== "working-tree" && mode !== "unstaged") {
    args.push(mode);
  }
  return new Set(execFileSync("git", args, { encoding: "utf8" }).split(/\r?\n/).filter(Boolean).map((line) => line.replaceAll("\\", "/")));
}


function isDefaultIgnoredDir(path: string): boolean {
  const first = path.split("/")[0] ?? path;
  return [".git", ".hg", ".svn", ".idea", ".vscode", "build", "cache", "coverage", "dist", "generated", "node_modules", "target", "tmp", "vendor"].includes(first);
}

function isIgnoredDiscoveryPath(display: string, isDirectory: boolean, options: AnalysisOptions, config: Config, gitIgnoreRules: GitIgnoreRule[]): boolean {
  if (isDefaultIgnoredDiscoveryPath(display, isDirectory, options)) {
    return true;
  }
  if (isGitIgnoredDiscoveryPath(display, isDirectory, options, gitIgnoreRules)) {
    return true;
  }
  return config.ignoredPaths.some((pattern) => pathMatches(pattern, display));
}

function isDefaultIgnoredDiscoveryPath(display: string, isDirectory: boolean, options: AnalysisOptions): boolean {
  return !options.includeIgnored && isDirectory && isDefaultIgnoredDir(display);
}

function isGitIgnoredDiscoveryPath(display: string, isDirectory: boolean, options: AnalysisOptions, gitIgnoreRules: GitIgnoreRule[]): boolean {
  return !options.includeIgnored && isGitIgnoredPath(gitIgnoreRules, display, isDirectory);
}

function gitIgnoreRulesForDirectory(projectRoot: string, directory: string): GitIgnoreRule[] {
  if (!isInsideProject(projectRoot, directory)) {
    return [];
  }

  const relativeDirectory = displayPath(projectRoot, directory);
  const segments = relativeDirectory === "." ? [] : relativeDirectory.split("/");
  let current = projectRoot;
  let rules = appendGitIgnoreRules(projectRoot, current, []);
  for (const segment of segments) {
    current = join(current, segment);
    rules = appendGitIgnoreRules(projectRoot, current, rules);
  }
  return rules;
}

function appendGitIgnoreRules(projectRoot: string, directory: string, inheritedRules: GitIgnoreRule[]): GitIgnoreRule[] {
  const ignoreFile = join(directory, ".gitignore");
  if (!existsSync(ignoreFile) || !statSync(ignoreFile).isFile()) {
    return inheritedRules;
  }

  const basePath = displayPath(projectRoot, directory);
  const parsedRules = parseGitIgnoreRules(readFileSync(ignoreFile, "utf8"), basePath === "." ? "" : basePath);
  return parsedRules.length > 0 ? [...inheritedRules, ...parsedRules] : inheritedRules;
}

function parseGitIgnoreRules(source: string, basePath: string): GitIgnoreRule[] {
  const rules: GitIgnoreRule[] = [];
  for (const rawLine of source.replace(/\r\n/g, "\n").split("\n")) {
    const rule = parseGitIgnoreRule(rawLine, basePath);
    if (rule) {
      rules.push(rule);
    }
  }
  return rules;
}

function parseGitIgnoreRule(rawLine: string, basePath: string): GitIgnoreRule | undefined {
  const initial = unescapedGitIgnoreLine(rawLine);
  if (!initial) {
    return undefined;
  }
  const negated = initial.startsWith("!");
  const withoutNegation = negated ? initial.slice(1) : initial;
  if (withoutNegation.length === 0) {
    return undefined;
  }
  const anchored = withoutNegation.startsWith("/");
  const directoryOnly = withoutNegation.endsWith("/");
  const pattern = normalizedGitIgnorePattern(withoutNegation);
  if (pattern.length === 0) {
    return undefined;
  }
  return { basePath, pattern, negated, directoryOnly, anchored, hasSlash: pattern.includes("/") };
}

function unescapedGitIgnoreLine(rawLine: string): string | undefined {
  const line = rawLine.trimEnd();
  if (line.length === 0 || line.startsWith("#")) {
    return undefined;
  }
  return line.startsWith("\\#") || line.startsWith("\\!") ? line.slice(1) : line;
}

function normalizedGitIgnorePattern(line: string): string {
  return line
    .replace(/^\/+/, "")
    .replace(/\/+$/, "")
    .split("/")
    .filter((segment) => segment.length > 0)
    .join("/");
}

function isGitIgnoredPath(rules: GitIgnoreRule[], display: string, isDirectory: boolean): boolean {
  let isIgnored = false;
  for (const rule of rules) {
    if (gitIgnoreRuleMatches(rule, display, isDirectory)) {
      isIgnored = !rule.negated;
    }
  }
  return isIgnored;
}

function gitIgnoreRuleMatches(rule: GitIgnoreRule, display: string, isDirectory: boolean): boolean {
  const relativePath = pathRelativeToBase(rule.basePath, display);
  if (relativePath === undefined || relativePath.length === 0) {
    return false;
  }

  if (rule.directoryOnly) {
    return gitIgnoreDirectoryRuleMatches(rule, relativePath, isDirectory);
  }
  return gitIgnoreFileRuleMatches(rule, relativePath, isDirectory);
}

function gitIgnoreFileRuleMatches(rule: GitIgnoreRule, relativePath: string, isDirectory: boolean): boolean {
  if (isPathScopedGitIgnoreRule(rule)) {
    return gitIgnorePathCandidates(relativePath, isDirectory, true).some((candidate) => gitIgnoreGlobMatches(rule.pattern, candidate));
  }
  return relativePath.split("/").some((segment) => gitIgnoreGlobMatches(rule.pattern, segment));
}

function gitIgnoreDirectoryRuleMatches(rule: GitIgnoreRule, relativePath: string, isDirectory: boolean): boolean {
  if (isPathScopedGitIgnoreRule(rule)) {
    return gitIgnorePathCandidates(relativePath, isDirectory, false).some((candidate) => gitIgnoreGlobMatches(rule.pattern, candidate));
  }
  const segments = relativePath.split("/");
  const directorySegments = isDirectory ? segments : segments.slice(0, -1);
  return directorySegments.some((segment) => gitIgnoreGlobMatches(rule.pattern, segment));
}

function isPathScopedGitIgnoreRule(rule: GitIgnoreRule): boolean {
  return rule.anchored || rule.hasSlash;
}

function gitIgnorePathCandidates(relativePath: string, isDirectory: boolean, includeFilePath: boolean): string[] {
  const segments = relativePath.split("/");
  const limit = isDirectory || includeFilePath ? segments.length : segments.length - 1;
  const candidates: string[] = [];
  for (let index = 1; index <= limit; index += 1) {
    candidates.push(segments.slice(0, index).join("/"));
  }
  return candidates;
}

function gitIgnoreGlobMatches(pattern: string, value: string): boolean {
  return gitIgnoreGlobRegex(pattern).test(value);
}

function gitIgnoreGlobRegex(pattern: string): RegExp {
  let source = "^";
  for (let index = 0; index < pattern.length; index += 1) {
    const fragment = gitIgnoreGlobFragment(pattern, index);
    source += fragment.source;
    index += fragment.skip;
  }
  return new RegExp(`${source}$`);
}

function gitIgnoreGlobFragment(pattern: string, index: number): { source: string; skip: number } {
  const character = pattern[index] ?? "";
  if (character === "*") {
    return gitIgnoreStarFragment(pattern, index);
  }
  if (character === "?") {
    return { source: "[^/]", skip: 0 };
  }
  return { source: escapeRegex(character), skip: 0 };
}

function gitIgnoreStarFragment(pattern: string, index: number): { source: string; skip: number } {
  const next = pattern[index + 1];
  const afterNext = pattern[index + 2];
  if (next !== "*") {
    return { source: "[^/]*", skip: 0 };
  }
  if (afterNext === "/") {
    return { source: "(?:.*/)?", skip: 2 };
  }
  return { source: ".*", skip: 1 };
}

function pathRelativeToBase(basePath: string, display: string): string | undefined {
  if (basePath.length === 0) {
    return display === "." ? "" : display;
  }
  if (display === basePath) {
    return "";
  }
  return display.startsWith(`${basePath}/`) ? display.slice(basePath.length + 1) : undefined;
}

function isInsideProject(projectRoot: string, path: string): boolean {
  const relativePath = relative(projectRoot, path).replaceAll("\\", "/");
  return relativePath === "" || (!relativePath.startsWith("../") && relativePath !== ".." && !isAbsolute(relativePath));
}

function pathMatches(pattern: string, path: string): boolean {
  if (pattern === path) {
    return true;
  }
  if (pattern.endsWith("/**")) {
    const prefix = pattern.slice(0, -3);
    return path === prefix || path.startsWith(`${prefix}/`);
  }
  if (pattern.includes("*")) {
    const regex = new RegExp(`^${escapeRegex(pattern).replaceAll("\\*\\*", ".*").replaceAll("\\*", "[^/]*")}$`);
    return regex.test(path);
  }
  return path.startsWith(pattern.replace(/\/$/, ""));
}

function uniqueFiles(files: SourceFile[]): SourceFile[] {
  const seen = new Set<string>();
  return files.filter((file) => {
    if (seen.has(file.absolutePath)) {
      return false;
    }
    seen.add(file.absolutePath);
    return true;
  });
}

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

function isDocCommentLine(trimmedLine: string): boolean {
  return trimmedLine.startsWith("/**") || trimmedLine.startsWith("*");
}

function isDocCommentSearchBoundary(trimmedLine: string): boolean {
  return trimmedLine !== "" && !trimmedLine.startsWith("@");
}

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

function firstMeaningfulLineIndex(lines: string[], start = 0): number | undefined {
  for (let index = start; index < lines.length; index += 1) {
    if ((lines[index] ?? "").trim() !== "") {
      return index;
    }
  }
  return undefined;
}

function hasLeadingCommentBeforeLine(source: string, line: number): boolean {
  return hasLeadingCommentBeforeLines(source.split(/\r?\n/), line);
}

function hasLeadingCommentBeforeLines(lines: string[], line: number): boolean {
  let index = line - 2;
  while (index >= 0 && (lines[index] ?? "").trim() === "") {
    index -= 1;
  }
  return index >= 0 && commentTextAtLine(lines, index) !== undefined;
}

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

function blockCommentTextEndingAt(lines: string[], endIndex: number): string | undefined {
  for (let index = endIndex; index >= 0; index -= 1) {
    if ((lines[index] ?? "").trim().startsWith("/*")) {
      return blockCommentText(lines, index, endIndex);
    }
  }
  return undefined;
}

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

function blockCommentEndIndex(lines: string[], startIndex: number): number | undefined {
  for (let index = startIndex; index < lines.length; index += 1) {
    if ((lines[index] ?? "").includes("*/")) {
      return index;
    }
  }
  return undefined;
}

function isGenericName(name: string, bannedNames: Set<string>): boolean {
  return bannedNames.has(name.toLowerCase());
}


function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function absolutize(projectRoot: string, path: string): string {
  return isAbsolute(path) ? path : join(projectRoot, path);
}

function displayPath(projectRoot: string, path: string): string {
  const relativePath = relative(projectRoot, path).replaceAll("\\", "/");
  return relativePath === "" ? "." : relativePath;
}

function stringChoice<T extends string>(value: unknown, choices: readonly T[], fallback: T): T {
  return typeof value === "string" && choices.includes(value as T) ? (value as T) : fallback;
}
if (import.meta.url === pathToFileURL(argv[1] ?? "").href) {
  buildProgram().parse(argv);
}

export { absolutize, buildProgram, displayPath, renderReport, ruleDescriptors };
