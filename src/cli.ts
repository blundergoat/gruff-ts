#!/usr/bin/env node
import { Command, Help } from "commander";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { createServer } from "node:http";
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { argv, chdir, cwd, stdout } from "node:process";
import { basename, dirname as dirnamePath, extname, isAbsolute, join, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { isString, loadConfig, objectValue, ruleEnabled, threshold } from "./config.ts";
import { dashboardErrorHtml, dashboardHomeHtml, grade, renderHtml, renderReport, renderSummary } from "./report-renderers.ts";
import { ruleDescriptors } from "./rules.ts";
import { codeLineForMatching, maskNonCode, parseDiagnostics } from "./source-text.ts";
import { byteLine, countMatches, firstLine, todoMarkerSummary } from "./text-scans.ts";
import type { AnalysisOptions, AnalysisReport, Config, Confidence, FailThreshold, Finding, OutputFormat, Pillar, RunDiagnostic, Severity } from "./types.ts";
export type { AnalysisReport, Finding, OutputFormat, Pillar, RuleDescriptor, Severity } from "./types.ts";

const VERSION = "0.1.0";
const DEFAULT_BASELINE = "gruff-baseline.json";
const NPATH_CAP = 1_000_000;
const ANSI_GREEN = "\u001b[32m";
const ANSI_YELLOW = "\u001b[33m";
const ANSI_RESET_FG = "\u001b[39m";

type RuleListFormat = "text" | "json";
type CompletionShell = "bash" | "fish" | "zsh";

const CONSOLE_COMMANDS = [
  { name: "analyse", description: "Run gruff analysis." },
  { name: "completion", description: "Dump the shell completion script" },
  { name: "dashboard", description: "Serve the local gruff dashboard." },
  { name: "help", description: "Display help for a command" },
  { name: "list", description: "List commands" },
  { name: "list-rules", description: "List gruff rule metadata." },
  { name: "report", description: "Render a gruff report to stdout or a file." },
  {
    name: "summary",
    description:
      "Print a compact digest of a scan: per-pillar finding counts, top rules, and top file offenders. Runs the analyser once and renders only the summary; no per-finding spam.",
  },
] as const;
interface SourceFile {
  absolutePath: string;
  displayPath: string;
  isTypeScript: boolean;
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
  typeScriptSources: ProjectSource[];
  sourcePaths: Set<string>;
  importsByFile: Map<string, ImportEdge[]>;
}

interface ImportEdge {
  specifier: string;
  line: number;
  parentSegments: number;
  targetPath?: string;
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

function discoverSources(projectRoot: string, options: AnalysisOptions, config: Config) {
  const files: SourceFile[] = [];
  const missingPaths: string[] = [];
  const ignoredPaths = new Set<string>();
  const inputs = options.paths.length > 0 ? options.paths : ["."];

  for (const input of inputs) {
    const absolute = absolutize(projectRoot, input);
    if (!existsSync(absolute)) {
      missingPaths.push(input);
      continue;
    }
    const stats = statSync(absolute);
    if (stats.isFile()) {
      pushSourceFile(projectRoot, absolute, files);
      continue;
    }
    const gitIgnoreRules = options.includeIgnored ? [] : gitIgnoreRulesForDirectory(projectRoot, absolute);
    walk(projectRoot, absolute, options, config, ignoredPaths, files, gitIgnoreRules);
  }

  files.sort((left, right) => left.displayPath.localeCompare(right.displayPath));
  return { files: uniqueFiles(files), missingPaths, ignoredPaths: [...ignoredPaths].sort() };
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
  const isTypeScript = ["ts", "tsx", "js", "jsx", "mjs", "cjs"].includes(extension);
  const isText =
    ["conf", "config", "env", "ini", "json", "toml", "xml", "yaml", "yml"].includes(extension) ||
    name.startsWith(".env");
  if (isTypeScript || isText) {
    files.push({ absolutePath, displayPath: displayPath(projectRoot, absolutePath), isTypeScript });
  }
}
function analyseSource(file: SourceFile, source: string, config: Config): Finding[] {
  const findings: Finding[] = [];
  analyseTextRules(file, source, config, findings);
  if (file.isTypeScript) {
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
  const typeScriptSources = sources.filter((source) => source.file.isTypeScript);
  const sourcePaths = new Set(typeScriptSources.map((source) => source.file.displayPath));
  const importsByFile = new Map<string, ImportEdge[]>();
  for (const source of typeScriptSources) {
    importsByFile.set(source.file.displayPath, importEdgesForSource(source, sourcePaths));
  }
  return { sources, typeScriptSources, sourcePaths, importsByFile };
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
  const maxParentSegments = threshold(config, "design.deep-relative-import", "maxParentSegments", 2);
  for (const source of index.typeScriptSources) {
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
          severity: "advisory",
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
  const cycles = importCycles(index);
  for (const cycle of cycles) {
    const anchorPath = cycle.files[0] ?? "";
    const anchorSource = index.typeScriptSources.find((source) => source.file.displayPath === anchorPath);
    if (!anchorSource) {
      continue;
    }
    const anchorEdges = index.importsByFile.get(anchorPath) ?? [];
    const line = anchorEdges.find((edge) => edge.targetPath && cycle.files.includes(edge.targetPath))?.line ?? 1;
    const cycleLabel = cycle.files.join(" -> ");
    findings.push(
      makeFinding({
        ruleId: "design.circular-import",
        message: `Import cycle detected among ${cycle.files.join(", ")}.`,
        filePath: anchorSource.file.displayPath,
        line,
        severity: "warning",
        pillar: "design",
        confidence: "medium",
        symbol: cycleLabel,
        remediation: "Extract the shared contract or move one dependency behind an explicit boundary.",
        metadata: { files: cycle.files },
      }),
    );
  }
}

function analyseLargeModuleConcentration(index: ProjectIndex, config: Config, findings: Finding[]): void {
  const minFiles = threshold(config, "design.large-module-concentration", "minFiles", 4);
  const minLines = threshold(config, "design.large-module-concentration", "minLines", 80);
  const maxSharePercent = threshold(config, "design.large-module-concentration", "maxSharePercent", 55);
  const modules = index.typeScriptSources
    .filter((source) => isProductionSourcePath(source.file.displayPath))
    .map((source) => ({ source, lines: source.lines.length }))
    .sort((left, right) => right.lines - left.lines || left.source.file.displayPath.localeCompare(right.source.file.displayPath));
  if (modules.length < minFiles) {
    return;
  }
  const totalLines = modules.reduce((sum, module) => sum + module.lines, 0);
  const largest = modules[0];
  if (!largest || totalLines === 0) {
    return;
  }
  const sharePercent = Math.round((largest.lines / totalLines) * 1000) / 10;
  if (largest.lines < minLines || sharePercent <= maxSharePercent) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "design.large-module-concentration",
      message: `Module \`${largest.source.file.displayPath}\` contains ${sharePercent}% of production source lines.`,
      filePath: largest.source.file.displayPath,
      line: 1,
      severity: "advisory",
      pillar: "design",
      confidence: "medium",
      symbol: fileBaseName(largest.source.file.displayPath),
      remediation: "Split unrelated responsibilities into smaller modules once stable seams are visible.",
      metadata: { lines: largest.lines, totalLines, sharePercent, minFiles, minLines, maxSharePercent },
    }),
  );
}

function importEdgesForSource(source: ProjectSource, sourcePaths: Set<string>): ImportEdge[] {
  const edges: ImportEdge[] = [];
  for (const [index, line] of source.lines.entries()) {
    for (const match of line.matchAll(/\b(?:import|export)\b(?:[^"'`]*?\bfrom\s*)?\s*["']([^"']+)["']/g)) {
      const specifier = match[1] ?? "";
      if (!specifier.startsWith(".")) {
        continue;
      }
      const targetPath = resolveRelativeImport(source.file.displayPath, specifier, sourcePaths);
      edges.push({
        specifier,
        line: index + 1,
        parentSegments: specifier.split("/").filter((segment) => segment === "..").length,
        ...(targetPath ? { targetPath } : {}),
      });
    }
  }
  return edges.sort((left, right) => left.line - right.line || left.specifier.localeCompare(right.specifier));
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

function importCycles(index: ProjectIndex): Array<{ files: string[] }> {
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
  const testPaths = new Set(index.typeScriptSources.filter((source) => isTestPath(source.file.displayPath)).map((source) => source.file.displayPath));
  for (const source of index.typeScriptSources.filter((candidate) => isProductionSourcePath(candidate.file.displayPath))) {
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
  const warn = threshold(config, "size.file-length", "warn", 400);
  const error = threshold(config, "size.file-length", "error", 800);
  if (!isGeneratedLockfile(file.displayPath)) {
    if (lines > error) {
      findings.push(finding("size.file-length", `File has ${lines} lines, above the error threshold of ${error}.`, file, 1, "error", "size"));
    } else if (lines > warn) {
      findings.push(finding("size.file-length", `File has ${lines} lines, above the warning threshold of ${warn}.`, file, 1, "warning", "size"));
    }
  }

  const todoMarkers = todoMarkerSummary(source, file.isTypeScript);
  if (todoMarkers.count >= threshold(config, "docs.todo-density", "markers", 4)) {
    findings.push(finding("docs.todo-density", `File contains ${todoMarkers.count} TODO/FIXME markers.`, file, todoMarkers.firstLine, "advisory", "documentation"));
  }

  analyseSensitiveData(file, source, config, findings);
  analyseProjectConfigRules(file, source, findings);
}

function isGeneratedLockfile(path: string): boolean {
  const name = basename(path);
  return name === "package-lock.json" || name === "npm-shrinkwrap.json" || name === "yarn.lock" || name === "pnpm-lock.yaml" || name === "bun.lockb";
}

function analyseProjectConfigRules(file: SourceFile, source: string, findings: Finding[]): void {
  const name = basename(file.displayPath);
  if (name !== "package.json" && name !== "tsconfig.json") {
    return;
  }
  const configObject = parseJsonObject(source);
  if (!configObject) {
    return;
  }
  if (name === "package.json") {
    analysePackageJson(file, source, configObject, findings);
  } else {
    analyseTsconfigJson(file, source, configObject, findings);
  }
}

function analysePackageJson(file: SourceFile, source: string, pkg: Record<string, unknown>, findings: Finding[]): void {
  const scripts = objectValue(pkg.scripts);
  if (scripts) {
    for (const [scriptName, value] of Object.entries(scripts)) {
      if (!isString(value)) {
        continue;
      }
      const line = jsonKeyLine(source, scriptName);
      if (isRemoteInstallScript(value)) {
        findings.push(
          makeFinding({
            ruleId: "security.remote-install-script",
            message: `Package script \`${scriptName}\` downloads and executes remote shell content.`,
            filePath: file.displayPath,
            line,
            severity: "error",
            pillar: "security",
            confidence: "medium",
            symbol: scriptName,
            remediation: "Vendor the installer, pin an audited package, or remove remote shell execution.",
            metadata: { scriptName },
          }),
        );
      }
      if (isLifecycleScript(scriptName)) {
        findings.push(
          makeFinding({
            ruleId: "security.risky-lifecycle-script",
            message: `Package lifecycle script \`${scriptName}\` runs automatically during install or publish flows.`,
            filePath: file.displayPath,
            line,
            severity: "warning",
            pillar: "security",
            confidence: "medium",
            symbol: scriptName,
            remediation: "Move setup behind an explicit command unless lifecycle execution is required.",
            metadata: { scriptName },
          }),
        );
      }
    }
  }

  for (const section of ["dependencies", "optionalDependencies", "peerDependencies", "devDependencies"]) {
    const dependencies = objectValue(pkg[section]);
    if (!dependencies) {
      continue;
    }
    const runtimeDependency = section !== "devDependencies";
    for (const [packageName, value] of Object.entries(dependencies)) {
      if (!isString(value)) {
        continue;
      }
      const line = jsonKeyLine(source, packageName);
      if (isUrlDependency(value)) {
        findings.push(
          makeFinding({
            ruleId: "security.url-dependency",
            message: `Dependency \`${packageName}\` in \`${section}\` installs from a URL or git spec.`,
            filePath: file.displayPath,
            line,
            severity: "warning",
            pillar: "security",
            confidence: "medium",
            symbol: packageName,
            remediation: "Prefer a registry package version that can be locked and audited.",
            metadata: { packageName, section, runtimeDependency },
          }),
        );
      }
      if (runtimeDependency && isBroadRuntimeVersion(value)) {
        findings.push(
          makeFinding({
            ruleId: "waste.broad-runtime-version",
            message: `Runtime dependency \`${packageName}\` uses overly broad version spec \`${value}\`.`,
            filePath: file.displayPath,
            line,
            severity: "advisory",
            pillar: "waste",
            confidence: "medium",
            symbol: packageName,
            remediation: "Use a bounded semver range and rely on the lockfile for repeatable installs.",
            metadata: { packageName, section, versionSpec: value },
          }),
        );
      }
    }
  }

  analysePackageBins(file, source, pkg, findings);
}

function analysePackageBins(file: SourceFile, source: string, pkg: Record<string, unknown>, findings: Finding[]): void {
  const bins = packageBinEntries(pkg);
  for (const [command, target] of bins) {
    const line = jsonKeyLine(source, command);
    const absolute = isAbsolute(target) ? target : join(dirnamePath(file.absolutePath), target);
    if (!existsSync(absolute)) {
      findings.push(
        makeFinding({
          ruleId: "design.package-bin-missing",
          message: `Package bin \`${command}\` points to missing file \`${target}\`.`,
          filePath: file.displayPath,
          line,
          severity: "warning",
          pillar: "design",
          confidence: "high",
          symbol: command,
          remediation: "Update the bin path or add the executable file.",
          metadata: { command, target },
        }),
      );
      continue;
    }
    const stats = statSync(absolute);
    if (!stats.isFile() || (stats.mode & 0o111) === 0) {
      findings.push(
        makeFinding({
          ruleId: "design.package-bin-not-executable",
          message: `Package bin \`${command}\` points to a file that is not executable.`,
          filePath: file.displayPath,
          line,
          severity: "warning",
          pillar: "design",
          confidence: "high",
          symbol: command,
          remediation: "Make the bin target executable and keep its shebang valid.",
          metadata: { command, target },
        }),
      );
    }
  }
}

function analyseTsconfigJson(file: SourceFile, source: string, data: Record<string, unknown>, findings: Finding[]): void {
  const compilerOptions = objectValue(data.compilerOptions) ?? {};
  const checks: Array<[string, string, string]> = [
    ["strict", "modernisation.tsconfig-strict-disabled", "`strict` is disabled, reducing TypeScript's baseline safety checks."],
    ["noUncheckedIndexedAccess", "modernisation.tsconfig-index-safety-disabled", "`noUncheckedIndexedAccess` is disabled, so indexed reads can silently ignore undefined."],
    ["exactOptionalPropertyTypes", "modernisation.tsconfig-exact-optional-disabled", "`exactOptionalPropertyTypes` is disabled, weakening optional property contracts."],
  ];
  for (const [optionName, ruleId, message] of checks) {
    if (compilerOptions[optionName] === true) {
      continue;
    }
    findings.push(
      makeFinding({
        ruleId,
        message,
        filePath: file.displayPath,
        line: jsonKeyLine(source, optionName),
        severity: "warning",
        pillar: "modernisation",
        confidence: "high",
        symbol: optionName,
        remediation: `Set compilerOptions.${optionName} to true unless a documented migration blocker exists.`,
        metadata: { optionName, currentValue: compilerOptions[optionName] ?? null },
      }),
    );
  }
}

function parseJsonObject(source: string): Record<string, unknown> | undefined {
  try {
    return objectValue(JSON.parse(source));
  } catch {
    return undefined;
  }
}

function jsonKeyLine(source: string, key: string): number {
  const escapedKey = escapeRegex(key);
  return firstLine(source, new RegExp(`"${escapedKey}"\\s*:`));
}

function isRemoteInstallScript(command: string): boolean {
  return /\b(?:curl|wget)\b[^\n|;&]*https?:\/\/[^\n|;&]*(?:\|\s*(?:sh|bash|zsh)\b|\b(?:sh|bash|zsh)\b)/i.test(command);
}

function isLifecycleScript(scriptName: string): boolean {
  return ["preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly"].includes(scriptName);
}

function isUrlDependency(versionSpec: string): boolean {
  return /^(?:https?:\/\/|git(?:\+https?|\+ssh)?:\/\/|ssh:\/\/|github:|gitlab:|bitbucket:)/i.test(versionSpec);
}

function isBroadRuntimeVersion(versionSpec: string): boolean {
  const normalized = versionSpec.trim().toLowerCase();
  return normalized === "*" || normalized === "x" || normalized === "latest" || /^>=\s*\d/.test(normalized) || normalized.includes("||");
}

function packageBinEntries(pkg: Record<string, unknown>): Array<[string, string]> {
  const bin = pkg.bin;
  if (isString(bin)) {
    const name = isString(pkg.name) ? pkg.name : "bin";
    return [[name, bin]];
  }
  const bins = objectValue(bin);
  if (!bins) {
    return [];
  }
  return Object.entries(bins).filter((entry): entry is [string, string] => isString(entry[1]));
}

function analyseSensitiveData(file: SourceFile, source: string, config: Config, findings: Finding[]): void {
  const patterns: Array<[string, RegExp, string]> = [
    ["sensitive-data.aws-access-key", /AKIA[0-9A-Z]{16}/g, "AWS access key pattern detected."],
    ["sensitive-data.private-key", /BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY/g, "Private key block detected."],
    ["sensitive-data.jwt-token", /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, "JWT-looking token detected."],
    ["sensitive-data.database-url-password", /[a-z]+:\/\/[^:\s]+:[^@\s]+@/g, "Database URL appears to include a password."],
    ["sensitive-data.api-key-pattern", /\b(?:sk_live_[A-Za-z0-9_-]{12,}|sk_test_[A-Za-z0-9_-]{12,}|sk-proj-[A-Za-z0-9_-]{16,}|sk-ant-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b/g, "API key pattern detected."],
    ["sensitive-data.pii-pattern", /\b\d{3}-\d{2}-\d{4}\b/g, "PII-like identifier pattern detected."],
  ];

  for (const [ruleId, pattern, message] of patterns) {
    for (const match of source.matchAll(pattern)) {
      const raw = match[0] ?? "";
      pushSensitiveFinding(config, findings, file, ruleId, message, byteLine(source, match.index ?? 0), raw, "high");
    }
  }

  const hardcodedEnvMinLength = threshold(config, "sensitive-data.hardcoded-env-value", "minLength", 16);
  const lines = source.split(/\r?\n/);
  for (const [index, line] of lines.entries()) {
    const envValue = hardcodedEnvValue(line, hardcodedEnvMinLength);
    if (!envValue) {
      continue;
    }
    pushSensitiveFinding(
      config,
      findings,
      file,
      "sensitive-data.hardcoded-env-value",
      `Environment-style value \`${envValue.keyName}\` appears to be hardcoded with secret-like content.`,
      index + 1,
      envValue.value,
      "medium",
      { keyName: envValue.keyName, length: envValue.value.length },
    );
  }

  const minLength = threshold(config, "sensitive-data.high-entropy-string", "minLength", 32);
  for (const match of source.matchAll(/(["'`])([A-Za-z0-9_+=./-]{32,})\1/g)) {
    const raw = match[2] ?? "";
    if (!isHighEntropySecretCandidate(raw, minLength)) {
      continue;
    }
    pushSensitiveFinding(
      config,
      findings,
      file,
      "sensitive-data.high-entropy-string",
      "High-entropy string literal may be an embedded secret.",
      byteLine(source, match.index ?? 0),
      raw,
      "medium",
      { length: raw.length, detector: "high-entropy-string" },
    );
  }
}

function pushSensitiveFinding(
  config: Config,
  findings: Finding[],
  file: SourceFile,
  ruleId: string,
  message: string,
  line: number,
  raw: string,
  confidence: Finding["confidence"],
  metadata: Record<string, unknown> = {},
): void {
  const preview = redact(raw);
  if (config.secretPreviews.has(preview)) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId,
      message: `${message} Redacted preview: ${preview}.`,
      filePath: file.displayPath,
      line,
      severity: "error",
      pillar: "sensitive-data",
      confidence,
      remediation: "Remove the sensitive value and load it from a secure runtime source.",
      metadata: { ...metadata, preview },
    }),
  );
}

function hardcodedEnvValue(line: string, minLength: number): { keyName: string; value: string } | undefined {
  const match = line.match(/^\s*([A-Z][A-Z0-9_]*(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|DATABASE_URL|DSN)[A-Z0-9_]*)\s*[:=]\s*["']?([^"'\s#]+)["']?/i);
  const keyName = match?.[1] ?? "";
  const candidateValue = match?.[2] ?? "";
  if (!keyName || candidateValue.length < minLength) {
    return undefined;
  }
  if (/^(?:x-api-key|token|secret|password|example|sample|placeholder)$/i.test(candidateValue)) {
    return undefined;
  }
  if (!/[A-Za-z]/.test(candidateValue) || !/[0-9]/.test(candidateValue)) {
    return undefined;
  }
  return { keyName, value: candidateValue };
}

function analyseTypeScriptRules(file: SourceFile, source: string, config: Config, findings: Finding[]): void {
  const codeSource = maskNonCode(source);
  const blocks = functionBlocks(source, codeSource);
  analyseBlocks(file, blocks, config, findings);
  analyseLineRules(file, source, codeSource, config, findings);
  analyseDocRules(file, source, codeSource, findings);
  analyseClassRules(file, source, codeSource, findings);
  analyseDeadCode(file, codeSource, findings);
}

function analyseBlocks(file: SourceFile, blocks: FunctionBlock[], config: Config, findings: Finding[]): void {
  for (const block of blocks) {
    const functionWarn = threshold(config, "size.function-length", "warn", 30);
    const functionError = threshold(config, "size.function-length", "error", 60);
    if (block.lineCount > functionError) {
      findings.push(blockFinding("size.function-length", `Function \`${block.name}\` has ${block.lineCount} lines, above the error threshold of ${functionError}.`, file, block, "error", "size"));
    } else if (block.lineCount > functionWarn) {
      findings.push(blockFinding("size.function-length", `Function \`${block.name}\` has ${block.lineCount} lines, above the warning threshold of ${functionWarn}.`, file, block, "warning", "size"));
    }

    const params = block.params.split(",").map((value) => value.trim()).filter(Boolean).length;
    if (params > threshold(config, "size.parameter-count", "warn", 5)) {
      findings.push(blockFinding("size.parameter-count", `Function \`${block.name}\` declares ${params} parameters.`, file, block, "warning", "size"));
    }

    const cyclomatic = countMatches(block.codeBody, /\b(if|else if|switch|case|for|while|catch)\b|\?|&&|\|\|/g) + 1;
    if (cyclomatic > threshold(config, "complexity.cyclomatic", "error", 20)) {
      findings.push(blockFinding("complexity.cyclomatic", `Function \`${block.name}\` has cyclomatic complexity ${cyclomatic}.`, file, block, "error", "complexity"));
    } else if (cyclomatic > threshold(config, "complexity.cyclomatic", "warn", 10)) {
      findings.push(blockFinding("complexity.cyclomatic", `Function \`${block.name}\` has cyclomatic complexity ${cyclomatic}.`, file, block, "warning", "complexity"));
    }

    const nesting = maxNestingDepth(block.codeBody);
    const cognitive = cyclomatic + nesting;
    if (cognitive > threshold(config, "complexity.cognitive", "warn", 15)) {
      findings.push(blockFinding("complexity.cognitive", `Function \`${block.name}\` has cognitive complexity ${cognitive}.`, file, block, "warning", "complexity"));
    }
    const npath = approximateNpath(functionBodyContent(block.codeBody));
    const npathWarn = threshold(config, "complexity.npath", "warn", 20);
    const npathError = threshold(config, "complexity.npath", "error", 80);
    if (npath.value > npathError) {
      findings.push(
        blockFindingWithMetadata(
          "complexity.npath",
          `Function \`${block.name}\` has approximate NPath complexity ${npath.value} (capped at ${NPATH_CAP}).`,
          file,
          block,
          "error",
          "complexity",
          { npath: npath.value, capped: npath.capped, cap: NPATH_CAP },
        ),
      );
    } else if (npath.value > npathWarn) {
      findings.push(
        blockFindingWithMetadata(
          "complexity.npath",
          `Function \`${block.name}\` has approximate NPath complexity ${npath.value} (capped at ${NPATH_CAP}).`,
          file,
          block,
          "warning",
          "complexity",
          { npath: npath.value, capped: npath.capped, cap: NPATH_CAP },
        ),
      );
    }
    if (block.lineCount > 45 && cyclomatic > 10) {
      findings.push(blockFinding("design.god-function", `Function \`${block.name}\` is both long and complex.`, file, block, "warning", "design"));
    }
    if (isGenericName(block.name)) {
      findings.push(blockFinding("naming.generic-function", `Function \`${block.name}\` is too generic to explain intent.`, file, block, "advisory", "naming"));
    }
    if (block.isPublic && !hasDocCommentBefore(block.body)) {
      findings.push(blockFinding("docs.missing-public-doc", `Exported function \`${block.name}\` is missing a doc comment.`, file, block, "advisory", "documentation"));
    }
    if (isEmptyFunctionBody(block.codeBody)) {
      findings.push(blockFinding("waste.empty-function", `Function \`${block.name}\` has no executable body.`, file, block, "advisory", "waste"));
    }
    for (const parameter of parameterNames(block.params)) {
      if (!parameter.name.startsWith("_") && !new RegExp(`\\b${escapeRegex(parameter.name)}\\b`).test(functionBodyContent(block.codeBody))) {
        findings.push(
          makeFinding({
            ruleId: "waste.unused-parameter",
            message: `Parameter \`${parameter.name}\` does not appear to be used.`,
            filePath: file.displayPath,
            line: block.startLine,
            severity: "advisory",
            pillar: "waste",
            confidence: "medium",
            symbol: block.name,
            remediation: "Remove the parameter or prefix it with _ if it is intentionally unused.",
            metadata: { parameter: parameter.name },
          }),
        );
      }
    }
    for (const redundant of redundantVariableReturns(block.codeBody)) {
      findings.push(
        makeFinding({
          ruleId: "waste.redundant-variable",
          message: `Variable \`${redundant.name}\` is returned immediately after assignment.`,
          filePath: file.displayPath,
          line: block.startLine + redundant.lineOffset,
          severity: "advisory",
          pillar: "waste",
          confidence: "medium",
          symbol: redundant.name,
          remediation: "Return the expression directly.",
          metadata: { variable: redundant.name },
        }),
      );
    }
    for (const lineOffset of terminalBareReturnLines(block.codeBody)) {
      findings.push(
        makeFinding({
          ruleId: "waste.useless-return",
          message: `Function \`${block.name}\` ends with a redundant bare return.`,
          filePath: file.displayPath,
          line: block.startLine + lineOffset,
          severity: "advisory",
          pillar: "waste",
          confidence: "medium",
          symbol: block.name,
          remediation: "Remove the final return statement.",
        }),
      );
    }
    if (block.isTest) {
      analyseTestBlock(file, block, config, findings);
    }
  }
}

function analyseTestBlock(file: SourceFile, block: FunctionBlock, config: Config, findings: Finding[]): void {
  const body = block.codeBody;
  if (!hasAssertion(body)) {
    findings.push(blockFinding("test-quality.no-assertions", `Test \`${block.name}\` does not appear to make an assertion.`, file, block, "warning", "test-quality"));
  }
  if (hasTrivialAssertion(body)) {
    findings.push(blockFinding("test-quality.trivial-assertion", `Test \`${block.name}\` contains an assertion that compares a value to itself.`, file, block, "warning", "test-quality"));
  }
  if (isSnapshotOnlyTest(body)) {
    findings.push(blockFinding("test-quality.snapshot-only-test", `Test \`${block.name}\` relies only on snapshot assertions.`, file, block, "advisory", "test-quality"));
  }
  if (isNoThrowOnlyTest(body)) {
    findings.push(blockFinding("test-quality.no-throw-only-test", `Test \`${block.name}\` only verifies that code does not throw.`, file, block, "advisory", "test-quality"));
  }
  for (const assertion of magicNumberAssertions(body)) {
    findings.push(
      blockFindingWithMetadata(
        "test-quality.magic-number-assertion",
        `Test \`${block.name}\` asserts against unexplained numeric literal ${assertion.value}.`,
        file,
        block,
        "advisory",
        "test-quality",
        { value: assertion.value },
      ),
    );
  }
  const unusedMocks = unusedMockVariables(body);
  for (const mock of unusedMocks) {
    findings.push(
      blockFindingWithMetadata(
        "test-quality.unused-mock",
        `Mock \`${mock}\` is created but not used.`,
        file,
        block,
        "advisory",
        "test-quality",
        { mockName: mock },
      ),
    );
  }
  if (isMockOnlyTest(body)) {
    findings.push(blockFinding("test-quality.mock-only-test", `Test \`${block.name}\` only verifies mock interaction.`, file, block, "advisory", "test-quality"));
  }
  if (hasExceptionTypeOnlyAssertion(body)) {
    findings.push(blockFinding("test-quality.exception-type-only", `Test \`${block.name}\` checks only the exception type.`, file, block, "advisory", "test-quality"));
  }
  if (hasGlobalStateMutation(body)) {
    findings.push(blockFinding("test-quality.global-state-mutation", `Test \`${block.name}\` mutates global process or runtime state.`, file, block, "warning", "test-quality"));
  }
  const setupLines = setupLineCount(body);
  const maxSetupLines = threshold(config, "test-quality.setup-bloat", "maxSetupLines", 12);
  if (setupLines > maxSetupLines) {
    findings.push(
      blockFindingWithMetadata(
        "test-quality.setup-bloat",
        `Test \`${block.name}\` has ${setupLines} setup lines before its first assertion.`,
        file,
        block,
        "advisory",
        "test-quality",
        { setupLines, maxSetupLines },
      ),
    );
  }
  const checks: Array<[string, RegExp, string]> = [
    ["test-quality.sleep-in-test", /\b(setTimeout|sleep|waitForTimeout)\s*\(/, "Test sleeps instead of synchronising on behaviour."],
    ["test-quality.loop-in-test", /\b(for|while)\b/, "Test contains loop logic."],
    ["test-quality.conditional-logic", /\b(if|switch)\b/, "Test contains conditional logic."],
    ["test-quality.only-skip", /\.(only|skip)\s*\(/, "Focused or skipped test is committed."],
  ];
  for (const [ruleId, pattern, message] of checks) {
    if (pattern.test(body)) {
      findings.push(blockFinding(ruleId, message, file, block, "advisory", "test-quality"));
    }
  }
}

function analyseLineRules(file: SourceFile, source: string, codeSource: string, config: Config, findings: Finding[]): void {
  analyseUnusedImports(file, codeSource, findings);
  const codeChecks: Array<[string, RegExp, string, Severity, Pillar]> = [
    ["security.eval-call", /\beval\s*\(/, "eval() executes dynamic code.", "error", "security"],
    ["security.new-function", /\bnew\s+Function\s*\(|(?:^|[=(:,])\s*Function\s*\(/, "Function constructor executes dynamic code.", "error", "security"],
    ["security.insecure-random", /\bMath\.random\s*\(/, "Math.random() is not suitable for security-sensitive randomness.", "warning", "security"],
    ["security.inner-html", /\.innerHTML\s*=|\bdangerouslySetInnerHTML\b/, "HTML injection sink can introduce XSS.", "warning", "security"],
    ["security.proto-access", /\.__proto__\b/, "Direct __proto__ access can enable prototype pollution.", "warning", "security"],
    ["security.document-write", /\bdocument\.write\s*\(/, "document.write() can introduce injection risks.", "warning", "security"],
    ["waste.redundant-boolean-cast", /\b(?:if|while)\s*\(\s*(?:!!\s*[A-Za-z_$][A-Za-z0-9_$.]*|Boolean\s*\()/, "Condition contains a redundant boolean cast.", "advisory", "waste"],
  ];
  const literalChecks: Array<[string, RegExp, string, Severity, Pillar]> = [
    ["security.weak-crypto", /\b(?:createHash|createHmac)\s*\(\s*["'](?:md5|sha1)["']|\bcreateCipher\s*\(|\b(?:secureProtocol|minVersion|maxVersion)\s*:\s*["'](?:SSLv2_method|SSLv3_method|TLSv1(?:_method)?|TLSv1\.1)["']/i, "Weak cryptographic primitive is used.", "warning", "security"],
    ["security.disabled-tls-verification", /\b(?:process\.env\.)?NODE_TLS_REJECT_UNAUTHORIZED\b\s*=\s*["']0["']|\brejectUnauthorized\s*:\s*false\b/i, "TLS certificate verification is disabled.", "error", "security"],
    ["security.javascript-url", /["'`]\s*javascript\s*:(?!\s+URL\b)/i, "javascript: URL literal can execute script.", "error", "security"],
    ["security.proto-access", /\[\s*["']__proto__["']\s*\]/, "Direct __proto__ access can enable prototype pollution.", "warning", "security"],
    ["security.sql-concatenation", /\b(?:query|execute|raw)\s*\(\s*(?:`[^`]*(?:SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{|["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)[^"']*["']\s*\+)/i, "SQL text is composed with runtime string interpolation.", "warning", "security"],
    ["modernisation.date-now-candidate", /\bnew\s+Date\s*\(\s*\)\s*\.getTime\s*\(\s*\)|\bNumber\s*\(\s*new\s+Date\s*\(\s*\)\s*\)/, "Current-time expression can use Date.now().", "advisory", "modernisation"],
    ["modernisation.object-spread-candidate", /\bObject\.assign\s*\(\s*\{\s*\}\s*,/, "Object.assign clone can usually use object spread.", "advisory", "modernisation"],
    ["waste.console-log", /\bconsole\.(log|debug)\s*\(/, "console logging is committed in source.", "advisory", "waste"],
    ["waste.any-type", /:\s*any\b|as\s+any\b/, "any weakens TypeScript's type guarantees.", "warning", "waste"],
    ["modernisation.var-declaration", /\bvar\s+[A-Za-z_$]/, "var declaration should usually be let or const.", "advisory", "modernisation"],
  ];
  const variables = /\b(?:const|let|for\s*\(\s*const|for\s*\(\s*let)\s+([A-Za-z_$][A-Za-z0-9_$]*)/g;

  const sourceLines = source.split(/\r?\n/);
  const codeLines = codeSource.split(/\r?\n/);
  sourceLines.forEach((line, index) => {
    const lineNumber = index + 1;
    const codeLine = codeLines[index] ?? codeLineForMatching(line);
    analyseTypeSafetyLine(file, line, codeLine, lineNumber, findings);
    analyseReliabilityLine(file, codeLine, lineNumber, findings);
    if (isCommentedOutCode(line)) {
      findings.push(finding("waste.commented-out-code", "Comment appears to contain disabled source code.", file, lineNumber, "advisory", "waste"));
    }
    const booleanDeclaration = codeLine.match(/\b(?:const|let|var|public|private|protected)\s+([A-Za-z_$][A-Za-z0-9_$]*)\??(?:\s*:\s*boolean|\s*=\s*(?:true|false)\b)/);
    if (booleanDeclaration?.[1] && !hasBooleanPrefix(booleanDeclaration[1])) {
      findings.push(
        makeFinding({
          ruleId: "naming.boolean-prefix",
          message: `Boolean identifier \`${booleanDeclaration[1]}\` should use an intent-revealing prefix.`,
          filePath: file.displayPath,
          line: lineNumber,
          severity: "advisory",
          pillar: "naming",
          confidence: "medium",
          symbol: booleanDeclaration[1],
          remediation: "Use a prefix such as is, has, can, should, or will.",
          metadata: { identifierName: booleanDeclaration[1] },
        }),
      );
    }
    for (const hungarian of codeLine.matchAll(/\b(?:const|let|var|public|private|protected)\s+((?:str|obj|arr|bool|int|num)[A-Z][A-Za-z0-9_$]*)/g)) {
      const name = hungarian[1] ?? "";
      findings.push(
        makeFinding({
          ruleId: "naming.hungarian-notation",
          message: `Identifier \`${name}\` uses type-style Hungarian notation.`,
          filePath: file.displayPath,
          line: lineNumber,
          severity: "advisory",
          pillar: "naming",
          confidence: "medium",
          symbol: name,
          remediation: "Name the domain concept instead of the storage type.",
          metadata: { identifierName: name },
        }),
      );
    }
    for (const optional of codeLine.matchAll(/\b([A-Za-z_$][A-Za-z0-9_$]*)\s*&&\s*\1\.[A-Za-z_$][A-Za-z0-9_$]*/g)) {
      const name = optional[1] ?? "";
      findings.push(
        makeFinding({
          ruleId: "modernisation.optional-chaining-candidate",
          message: `Guarded property access on \`${name}\` can usually use optional chaining.`,
          filePath: file.displayPath,
          line: lineNumber,
          severity: "advisory",
          pillar: "modernisation",
          confidence: "medium",
          symbol: name,
          remediation: "Use optional chaining for the guarded property access.",
        }),
      );
    }
    for (const fallback of codeLine.matchAll(/=\s*([A-Za-z_$][A-Za-z0-9_$.]*)\s*\|\|\s*(["'`]\s*["'`]|\d+|true|false)/g)) {
      const name = fallback[1] ?? "";
      findings.push(
        makeFinding({
          ruleId: "modernisation.nullish-coalescing-candidate",
          message: `Fallback for \`${name}\` can usually use nullish coalescing to preserve falsy values.`,
          filePath: file.displayPath,
          line: lineNumber,
          severity: "advisory",
          pillar: "modernisation",
          confidence: "medium",
          symbol: name,
          remediation: "Use ?? when only null or undefined should trigger the fallback.",
        }),
      );
    }
    const looseOperator = looseEqualityOperator(codeLine);
    if (looseOperator) {
      findings.push(finding("modernisation.loose-equality", `Loose equality operator ${looseOperator} may coerce values.`, file, lineNumber, "advisory", "modernisation"));
    }
    if (stringTimerCandidate(codeLine)) {
      findings.push(finding("security.string-timer", "Timer callback is provided as a string.", file, lineNumber, "warning", "security"));
    }
    if (processExecCandidate(codeLine) && !isFixedLocalProcessHarness(file, line, codeLine)) {
      findings.push(finding("security.process-exec", "Child-process execution is used; validate arguments are not user-controlled.", file, lineNumber, "warning", "security"));
    }
    for (const [ruleId, pattern, message, severity, pillar] of codeChecks) {
      if (pattern.test(codeLine)) {
        findings.push(finding(ruleId, message, file, lineNumber, severity, pillar));
      }
    }
    for (const [ruleId, pattern, message, severity, pillar] of literalChecks) {
      if (rawPatternStartsInCode(line, codeLine, pattern)) {
        findings.push(finding(ruleId, message, file, lineNumber, severity, pillar));
      }
    }

    for (const match of codeLine.matchAll(variables)) {
      const name = match[1] ?? "";
      if (name.length <= 2 && !["i", "j", "k"].includes(name) && !config.acceptedAbbreviations.has(name.toLowerCase())) {
        findings.push(
          makeFinding({
            ruleId: "naming.short-variable",
            message: `Variable \`${name}\` is too short to explain intent.`,
            filePath: file.displayPath,
            line: lineNumber,
            severity: "advisory",
            pillar: "naming",
            confidence: "medium",
            symbol: name,
            remediation: "Use a name that describes the domain role.",
          }),
        );
      }
      const variant = identifierQualityVariant(name);
      if (variant) {
        findings.push(
          makeFinding({
            ruleId: "naming.identifier-quality",
            message: `Identifier \`${name}\` is a ${variant} name that does not explain domain intent.`,
            filePath: file.displayPath,
            line: lineNumber,
            severity: "advisory",
            pillar: "naming",
            confidence: "medium",
            symbol: name,
            remediation: "Use an identifier that names the domain role.",
            metadata: { identifierName: name, variant },
          }),
        );
      }
    }
  });

  analyseUselessCatches(file, codeSource, findings);
  analyseSwallowedCatches(file, codeSource, findings);
  analyseUnreachable(file, codeSource, findings);
}

function rawPatternStartsInCode(rawLine: string, codeLine: string, pattern: RegExp): boolean {
  const flags = pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`;
  const globalPattern = new RegExp(pattern.source, flags);
  for (const match of rawLine.matchAll(globalPattern)) {
    const index = match.index ?? 0;
    if (/\S/.test(codeLine[index] ?? "")) {
      return true;
    }
  }
  return false;
}

function looseEqualityOperator(codeLine: string): string | undefined {
  for (const match of codeLine.matchAll(/[=!]=/g)) {
    const index = match.index ?? 0;
    const operator = match[0] ?? "";
    const before = codeLine[index - 1] ?? "";
    const after = codeLine[index + operator.length] ?? "";
    if (before === "=" || before === "!" || after === "=") {
      continue;
    }
    const left = codeLine.slice(Math.max(0, index - 24), index).trimEnd();
    const right = codeLine.slice(index + operator.length, Math.min(codeLine.length, index + operator.length + 24)).trimStart();
    if (/\bnull$/.test(left) || /^null\b/.test(right)) {
      continue;
    }
    return operator;
  }
  return undefined;
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
  const directive = tsDirectiveWithoutRationale(line);
  if (directive) {
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

  const exportedAny = exportedAnySymbol(codeLine);
  if (exportedAny) {
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
}

function analyseReliabilityLine(file: SourceFile, codeLine: string, lineNumber: number, findings: Finding[]): void {
  if (/\.forEach\s*\(\s*async\b/.test(codeLine)) {
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

  const floating = floatingPromiseCall(codeLine);
  if (floating) {
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

  const thrown = nonErrorThrowExpression(codeLine);
  if (thrown) {
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
  return words.length >= 3;
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
  if (!trimmed || /^(?:await|return|void|throw|yield)\b/.test(trimmed) || /^(?:const|let|var)\s+/.test(trimmed)) {
    return undefined;
  }
  const match = trimmed.match(/^([A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)\s*\(/);
  const callName = match?.[1] ?? "";
  if (!callName) {
    return undefined;
  }
  const localName = callName.split(".").at(-1) ?? callName;
  return callName === "fetch" || /(?:Async|Promise)$/.test(localName) ? callName : undefined;
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
function analyseClassRules(file: SourceFile, source: string, codeSource: string, findings: Finding[]): void {
  for (const match of codeSource.matchAll(/\bexport\s+(class|interface|type|enum|function)\s+([A-Za-z_$][A-Za-z0-9_$]*)/g)) {
    const kind = match[1] ?? "";
    const name = match[2] ?? "";
    const line = byteLine(source, match.index ?? 0);
    if (!hasDocCommentBeforeLine(source, line)) {
      findings.push(
        makeFinding({
          ruleId: "docs.missing-public-doc",
          message: `Exported item \`${name}\` is missing a doc comment.`,
          filePath: file.displayPath,
          line,
          severity: "advisory",
          pillar: "documentation",
          confidence: "medium",
          symbol: name,
          remediation: "Add a /** ... */ comment explaining the exported API.",
        }),
      );
    }
    if (kind === "class" && normalizedIdentifier(name) !== normalizedIdentifier(fileBaseName(file.displayPath))) {
      findings.push(
        makeFinding({
          ruleId: "naming.class-file-mismatch",
          message: `Exported class \`${name}\` does not match file name \`${fileBaseName(file.displayPath)}\`.`,
          filePath: file.displayPath,
          line,
          severity: "advisory",
          pillar: "naming",
          confidence: "medium",
          symbol: name,
          remediation: "Rename the class or file so the primary export is easy to locate.",
          metadata: { className: name, fileName: fileBaseName(file.displayPath) },
        }),
      );
    }
  }

  const publicProperty = /\bpublic\s+[A-Za-z_$][A-Za-z0-9_$]*\s*[=:]/g;
  for (const match of codeSource.matchAll(publicProperty)) {
    findings.push(finding("modernisation.public-property", "Public class property exposes representation; prefer readonly or accessors when invariants matter.", file, byteLine(source, match.index ?? 0), "advisory", "modernisation"));
  }

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

function analyseDocRules(file: SourceFile, source: string, codeSource: string, findings: Finding[]): void {
  const documentedExport = /\/\*\*((?:(?!\*\/)[\s\S])*?)\*\/\s*export\s+function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)\s*(?::\s*([^\x7b\n]+))?/g;
  for (const match of source.matchAll(documentedExport)) {
    const exportIndex = source.indexOf("export", match.index ?? 0);
    if (exportIndex < 0 || codeSource[exportIndex] !== "e") {
      continue;
    }
    const doc = match[1] ?? "";
    const name = match[2] ?? "";
    const params = parameterNames(match[3] ?? "").map((parameter) => parameter.name);
    const paramTags = docParamTags(doc);
    const line = byteLine(source, match.index ?? 0);
    for (const tag of paramTags) {
      if (!params.includes(tag)) {
        findings.push(docFinding("docs.stale-param-tag", `Docblock for \`${name}\` has stale @param tag \`${tag}\`.`, file, line, name, tag));
      }
    }
    for (const param of params) {
      if (!paramTags.includes(param)) {
        findings.push(docFinding("docs.missing-param-tag", `Docblock for \`${name}\` is missing @param for \`${param}\`.`, file, line, name, param));
      }
    }
    const returnType = (match[4] ?? "").trim();
    if (returnType && !/^void\b/.test(returnType) && !/@returns?\b/.test(doc)) {
      findings.push(docFinding("docs.missing-return-tag", `Docblock for \`${name}\` is missing @returns.`, file, line, name));
    }
    if (isUselessDocblock(doc, name)) {
      findings.push(docFinding("docs.useless-docblock", `Docblock for \`${name}\` only restates the signature.`, file, line, name));
    }
  }
}

function docFinding(ruleId: string, message: string, file: SourceFile, line: number, symbol: string, parameter?: string): Finding {
  return makeFinding({
    ruleId,
    message,
    filePath: file.displayPath,
    line,
    severity: "advisory",
    pillar: "documentation",
    confidence: "medium",
    symbol,
    remediation: "Update the JSDoc so it documents the current signature and return value.",
    metadata: { ...(parameter ? { parameter } : {}) },
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
    const branchLabel = /^(?:case\b.*:|default\s*:)$/.test(trimmed);
    if (branchLabel) {
      didPreviousTerminate = false;
    }
    if (didPreviousTerminate && /\S/.test(trimmed) && !trimmed.startsWith(String.fromCharCode(125)) && !branchLabel) {
      findings.push(finding("waste.unreachable-code", "Statement appears after a terminating statement.", file, index + 1, "warning", "waste"));
    }
    didPreviousTerminate = /\b(return|throw|process\.exit)\b/.test(trimmed) && trimmed.endsWith(";");
  });
}

function analyseUnusedImports(file: SourceFile, source: string, findings: Finding[]): void {
  const lines = source.split(/\r?\n/);
  for (const [index, line] of lines.entries()) {
    const trimmed = line.trim();
    if (!trimmed.startsWith("import ") || !trimmed.includes(" from ")) {
      continue;
    }
    const openBrace = trimmed.indexOf(String.fromCharCode(123));
    const closeBrace = trimmed.indexOf(String.fromCharCode(125), openBrace + 1);
    if (openBrace === -1 || closeBrace === -1 || closeBrace <= openBrace) {
      continue;
    }
    for (const specifier of trimmed.slice(openBrace + 1, closeBrace).split(",")) {
      const name = localImportName(specifier);
      if (!name || countMatches(source, new RegExp(`\\b${escapeRegex(name)}\\b`, "g")) > 1) {
        continue;
      }
      findings.push(
        makeFinding({
          ruleId: "waste.unused-import",
          message: `Imported symbol \`${name}\` does not appear to be used.`,
          filePath: file.displayPath,
          line: index + 1,
          severity: "advisory",
          pillar: "waste",
          confidence: "medium",
          symbol: name,
          remediation: "Remove the unused import.",
          metadata: { importName: name },
        }),
      );
    }
  }
}

function localImportName(specifier: string): string | undefined {
  const parts = specifier.trim().split(/\s+as\s+/);
  const candidate = parts[1] ?? parts[0] ?? "";
  const match = candidate.trim().match(/^[A-Za-z_$][A-Za-z0-9_$]*/);
  return match?.[0];
}

function approximateNpath(source: string): { value: number; capped: boolean } {
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

function parameterNames(params: string): Array<{ name: string }> {
  return params
    .split(",")
    .map((parameter) => parameter.trim())
    .filter(Boolean)
    .map((parameter) => parameter.replace(/^(?:public|private|protected|readonly)\s+/, "").replace(/^\.\.\./, "").split(/[?:=]/)[0]?.trim() ?? "")
    .filter((name): name is string => /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(name))
    .map((name) => ({ name }));
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

function identifierQualityVariant(name: string): string | undefined {
  const lower = name.toLowerCase();
  if (["foo", "bar", "baz", "tmp", "temp", "thing", "stuff", "data", "value", "item"].includes(lower)) {
    return "generic";
  }
  if (/^[A-Za-z_$]+[0-9]+$/.test(name)) {
    return "numbered";
  }
  return undefined;
}

function hasBooleanPrefix(name: string): boolean {
  return /^(?:is|has|can|should|does|did|was|will)[A-Z_]/.test(name);
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
    const marker = line.indexOf("@param");
    if (marker === -1) {
      continue;
    }
    let rest = line.slice(marker + "@param".length).trim();
    if (rest.startsWith(String.fromCharCode(123))) {
      const end = rest.indexOf(String.fromCharCode(125));
      rest = end === -1 ? "" : rest.slice(end + 1).trim();
    }
    const match = rest.match(/^([A-Za-z_$][A-Za-z0-9_$]*)/);
    if (match?.[1]) {
      names.push(match[1]);
    }
  }
  return names;
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
  if (/\bassert\.ok\s*\(\s*true\s*\)/.test(source)) {
    return true;
  }
  if (/\bassert\.(?:equal|strictEqual|deepEqual)\s*\(\s*(true|false|null|undefined|\d+|["'][^"']*["'])\s*,\s*\1\s*\)/.test(source)) {
    return true;
  }
  for (const match of source.matchAll(/\bassert\.(?:equal|strictEqual|deepEqual)\s*\(\s*([^,\n]+?)\s*,\s*([^,\n)]+?)(?:\s*,|\s*\))/g)) {
    if (normalizeAssertionExpression(match[1] ?? "") === normalizeAssertionExpression(match[2] ?? "")) {
      return true;
    }
  }
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
    if (!trimmed || trimmed === "});" || trimmed === "}") {
      continue;
    }
    if (hasAssertion(trimmed)) {
      break;
    }
    count += 1;
  }
  return count;
}

function isTestInvocationLine(line: string): boolean {
  return /^\s*(?:test|it)\s*\(/.test(line);
}

function functionBlocks(source: string, codeSource = source): FunctionBlock[] {
  const lines = source.split(/\r?\n/);
  const codeLines = codeSource.split(/\r?\n/);
  const blocks: FunctionBlock[] = [];
  const patterns = [
    /^\s*(?:test|it)\s*\(\s*["'`]([^"'`]+)["'`]\s*,\s*(?:async\s*)?\(([^)]*)\)\s*=>/,
    /^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)/,
    /^\s*(?:public|private|protected)?\s*(?:async\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)\s*[:{]/,
    /^\s*(?:const|let)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>/,
  ];
  codeLines.forEach((line, index) => {
    const rawLine = lines[index] ?? "";
    const match = patterns.map((pattern, patternIndex) => (patternIndex === 0 && isTestInvocationLine(line) ? rawLine.match(pattern) : line.match(pattern))).find(Boolean);
    if (!match?.[1]) {
      return;
    }
    if (isControlBlockName(match[1])) {
      return;
    }
    const start = functionStartIndex(lines, index);
    const expressionArrowEnd = expressionArrowEndIndex(codeLines, index);
    let depth = 0;
    let hasSeenOpen = false;
    let end = expressionArrowEnd ?? index;
    if (expressionArrowEnd === undefined) {
      for (let current = index; current < lines.length; current += 1) {
        for (const character of codeLines[current] ?? "") {
          if (character === "{") {
            depth += 1;
            hasSeenOpen = true;
          } else if (character === "}") {
            depth -= 1;
          }
        }
        end = current;
        if (hasSeenOpen && depth <= 0) {
          break;
        }
      }
    }
    const body = lines.slice(start, end + 1).join("\n");
    const codeBody = codeLines.slice(start, end + 1).join("\n");
    blocks.push({
      name: match[1],
      params: match[2] ?? "",
      startLine: start + 1,
      lineCount: end - start + 1,
      body,
      codeBody,
      isPublic: /\bexport\b|\bpublic\b/.test(codeLines.slice(start, index + 1).join("\n")),
      isTest: isTestInvocationLine(codeLines[index] ?? ""),
    });
  });
  return blocks;
}

function expressionArrowEndIndex(codeLines: string[], index: number): number | undefined {
  const line = codeLines[index] ?? "";
  const arrowIndex = line.indexOf("=>");
  if (arrowIndex === -1 || line.slice(arrowIndex + 2).includes("{")) {
    return undefined;
  }
  for (let current = index; current < codeLines.length; current += 1) {
    const trimmed = (codeLines[current] ?? "").trim();
    if (current === index) {
      const tail = line.slice(arrowIndex + 2).trim();
      if (tail.endsWith(";")) {
        return current;
      }
      continue;
    }
    if (trimmed === "") {
      return current - 1;
    }
    if (trimmed.endsWith(";")) {
      return current;
    }
  }
  return index;
}

function isControlBlockName(name: string): boolean {
  return ["if", "for", "while", "switch", "catch"].includes(name);
}

function functionStartIndex(lines: string[], index: number): number {
  let start = index;
  while (start > 0) {
    const previous = lines[start - 1]?.trim() ?? "";
    if (previous.startsWith("@") || previous.startsWith("/**") || previous.startsWith("*") || previous === "") {
      start -= 1;
      continue;
    }
    break;
  }
  return start;
}

function makeFinding(input: {
  ruleId: string;
  message: string;
  filePath: string;
  line?: number;
  severity: Severity;
  pillar: Pillar;
  confidence: Confidence;
  symbol?: string;
  remediation?: string;
  metadata?: Record<string, unknown>;
}): Finding {
  const fingerprint = createHash("sha256")
    .update([input.ruleId, input.filePath, input.line ?? "", input.symbol ?? ""].join("\0"))
    .digest("hex")
    .slice(0, 16);
  return {
    ruleId: input.ruleId,
    message: input.message,
    filePath: input.filePath,
    ...(input.line ? { line: input.line } : {}),
    severity: input.severity,
    pillar: input.pillar,
    secondaryPillars: [],
    tier: "v0.1",
    confidence: input.confidence,
    ...(input.symbol ? { symbol: input.symbol } : {}),
    ...(input.remediation ? { remediation: input.remediation } : {}),
    metadata: input.metadata ?? {},
    fingerprint,
  };
}

function finding(ruleId: string, message: string, file: SourceFile, line: number, severity: Severity, pillar: Pillar): Finding {
  return makeFinding({ ruleId, message, filePath: file.displayPath, line, severity, pillar, confidence: "high" });
}

function blockFinding(ruleId: string, message: string, file: SourceFile, block: FunctionBlock, severity: Severity, pillar: Pillar): Finding {
  return makeFinding({ ruleId, message, filePath: file.displayPath, line: block.startLine, severity, pillar, confidence: "high", symbol: block.name });
}

function blockFindingWithMetadata(ruleId: string, message: string, file: SourceFile, block: FunctionBlock, severity: Severity, pillar: Pillar, metadata: Record<string, unknown>): Finding {
  return makeFinding({ ruleId, message, filePath: file.displayPath, line: block.startLine, severity, pillar, confidence: "medium", symbol: block.name, metadata });
}

function scoreReport(findings: Finding[]): AnalysisReport["score"] {
  const byPillar = new Map<Pillar, Finding[]>();
  const byFile = new Map<string, Finding[]>();
  for (const finding of findings) {
    byPillar.set(finding.pillar, [...(byPillar.get(finding.pillar) ?? []), finding]);
    byFile.set(finding.filePath, [...(byFile.get(finding.filePath) ?? []), finding]);
  }
  const pillars = [...byPillar.entries()].map(([pillar, pillarFindings]) => {
    const penalty = pillarFindings.reduce((sum, finding) => sum + severityPenalty(finding.severity), 0);
    return { pillar, score: Math.max(0, 100 - penalty), findings: pillarFindings.length };
  });
  const composite = pillars.length === 0 ? 100 : pillars.reduce((sum, pillar) => sum + pillar.score, 0) / pillars.length;
  const topOffenders = [...byFile.entries()]
    .map(([filePath, fileFindings]) => ({
      filePath,
      score: Math.max(0, 100 - fileFindings.reduce((sum, finding) => sum + severityPenalty(finding.severity), 0)),
      findings: fileFindings.length,
    }))
    .sort((left, right) => left.score - right.score)
    .slice(0, 10);
  return { composite, grade: grade(composite), pillars, topOffenders };
}

function summarize(findings: Finding[]) {
  return {
    advisory: findings.filter((finding) => finding.severity === "advisory").length,
    warning: findings.filter((finding) => finding.severity === "warning").length,
    error: findings.filter((finding) => finding.severity === "error").length,
    total: findings.length,
  };
}

function exitFor(report: AnalysisReport, failOn: FailThreshold): number {
  if (report.diagnostics.length > 0) {
    return 2;
  }
  return report.findings.some((finding) => thresholdTriggered(failOn, finding.severity)) ? 1 : 0;
}

function thresholdTriggered(thresholdValue: FailThreshold, severity: Severity): boolean {
  if (thresholdValue === "none") {
    return false;
  }
  if (thresholdValue === "advisory") {
    return true;
  }
  if (thresholdValue === "warning") {
    return severity === "warning" || severity === "error";
  }
  return severity === "error";
}

function startDashboard(host: string, port: number, projectRoot: string, outputEnabled = true): void {
  const server = createServer((request, response) => {
    const url = new URL(request.url ?? "/", `http://${host}:${port}`);
    if (url.pathname === "/health") {
      response.writeHead(200, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
      response.end("ok");
      return;
    }
    if (url.pathname === "/scan") {
      const root = url.searchParams.get("projectRoot") ?? projectRoot;
      const scanPath = url.searchParams.get("path") ?? ".";
      const previous = cwd();
      try {
        chdir(root);
        const report = analyse({
          paths: [scanPath],
          noConfig: false,
          format: "html",
          failOn: "none",
          includeIgnored: false,
          noBaseline: false,
        });
        response.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
        response.end(renderHtml(report, { projectRoot: root, scanPath }));
      } catch (error) {
        response.writeHead(500, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
        response.end(dashboardErrorHtml(String(error), root, scanPath));
      } finally {
        chdir(previous);
      }
      return;
    }
    if (url.pathname !== "/") {
      response.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
      response.end("not found");
      return;
    }
    const root = url.searchParams.get("projectRoot") ?? projectRoot;
    const scanPath = url.searchParams.get("path") ?? ".";
    response.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
    response.end(dashboardHomeHtml(root, scanPath));
  });
  server.listen(port, host, () => {
    if (outputEnabled) {
      stdout.write(`gruff-ts dashboard listening at http://${host}:${port}\n`);
    }
  });
}

function renderRuleList(format: RuleListFormat): string {
  const descriptors = ruleDescriptors();
  if (format === "json") {
    return `${JSON.stringify({ tool: { name: "gruff-ts", version: VERSION }, rules: descriptors }, null, 2)}\n`;
  }
  const lines = [`gruff-ts ${VERSION} rules (${descriptors.length})`, ""];
  for (const descriptor of descriptors) {
    const thresholds = descriptor.thresholdKeys && descriptor.thresholdKeys.length > 0 ? ` | thresholds: ${descriptor.thresholdKeys.join(",")}` : "";
    lines.push(`${descriptor.ruleId} | ${descriptor.pillar} | ${descriptor.severity} | ${descriptor.confidence} | ${descriptor.description}${thresholds}`);
  }
  return `${lines.join("\n")}\n`;
}

function renderConsoleList(useAnsi = false): string {
  const listCommand = ansiWrap("list", ANSI_GREEN, useAnsi);
  return [
    `gruff-ts ${ansiWrap(VERSION, ANSI_GREEN, useAnsi)}`,
    "",
    ansiWrap("Usage:", ANSI_YELLOW, useAnsi),
    "  command [options] [arguments]",
    "",
    ansiWrap("Options:", ANSI_YELLOW, useAnsi),
    formatConsoleRow("-h, --help", `Display help for the given command. When no command is given display help for the ${listCommand} command`, 22, useAnsi),
    formatConsoleRow("    --silent", "Do not output any message", 22, useAnsi),
    formatConsoleRow("-q, --quiet", "Only errors are displayed. All other output is suppressed", 22, useAnsi),
    formatConsoleRow("-V, --version", "Display this application version", 22, useAnsi),
    formatConsoleRow("    --ansi|--no-ansi", "Force (or disable --no-ansi) ANSI output", 22, useAnsi),
    formatConsoleRow("-n, --no-interaction", "Do not ask any interactive question", 22, useAnsi),
    formatConsoleRow("-v|vv|vvv, --verbose", "Increase the verbosity of messages: 1 for normal output, 2 for more verbose output and 3 for debug", 22, useAnsi),
    "",
    ansiWrap("Available commands:", ANSI_YELLOW, useAnsi),
    ...CONSOLE_COMMANDS.map((command) => formatConsoleRow(command.name, command.description, 12, useAnsi)),
  ].join("\n") + "\n";
}

function formatConsoleRow(label: string, description: string, width: number, useAnsi: boolean): string {
  const paddedLabel = ansiWrap(label, ANSI_GREEN, useAnsi);
  const padding = " ".repeat(Math.max(1, width - label.length));
  const rowDescription = description;
  return `  ${paddedLabel}${padding}${rowDescription}`;
}

function ansiWrap(value: string, color: string, useAnsi: boolean): string {
  if (!useAnsi) {
    return value;
  }
  const ansiColor = color;
  return `${ansiColor}${value}${ANSI_RESET_FG}`;
}

function renderCompletionScript(shell: CompletionShell): string {
  const commands = CONSOLE_COMMANDS.filter((command) => command.name !== "help").map((command) => command.name).join(" ");
  const options = "-h --help --silent -q --quiet -V --version --ansi --no-ansi -n --no-interaction -v -vv -vvv --verbose";
  if (shell === "fish") {
    return [
      "complete -c gruff-ts -f",
      ...commands.split(" ").map((command) => `complete -c gruff-ts -n '__fish_use_subcommand' -a '${command}'`),
      ...options.split(" ").map((option) => `complete -c gruff-ts -a '${option}'`),
      "",
    ].join("\n");
  }
  if (shell === "zsh") {
    return [
      "#compdef gruff-ts",
      "_gruff_ts() {",
      "  local -a commands",
      `  commands=(${commands})`,
      "  _arguments '1:command:->commands' '*::arg:->args'",
      "  case $state in",
      "    commands) _describe 'command' commands ;;",
      "    args) _values 'option' " + options.split(" ").map((option) => `'${option}'`).join(" ") + " ;;",
      "  esac",
      "}",
      "_gruff_ts \"$@\"",
      "",
    ].join("\n");
  }
  return [
    "_gruff_ts_completion() {",
    "  local current previous commands options",
    "  COMPREPLY=()",
    "  current=\"${COMP_WORDS[COMP_CWORD]}\"",
    "  previous=\"${COMP_WORDS[COMP_CWORD-1]}\"",
    `  commands=\"${commands}\"`,
    `  options=\"${options}\"`,
    "  if [ \"$COMP_CWORD\" -eq 1 ]; then",
    "    COMPREPLY=( $(compgen -W \"$commands $options\" -- \"$current\") )",
    "  else",
    "    case \"$previous\" in",
    "      --format) COMPREPLY=( $(compgen -W \"text json html markdown github hotspot sarif\" -- \"$current\") ) ;;",
    "      --fail-on) COMPREPLY=( $(compgen -W \"none advisory warning error\" -- \"$current\") ) ;;",
    "      *) COMPREPLY=( $(compgen -W \"$options\" -- \"$current\") ) ;;",
    "    esac",
    "  fi",
    "}",
    "complete -F _gruff_ts_completion gruff-ts",
    "",
  ].join("\n");
}

function completionShell(value: unknown): CompletionShell {
  return value === "fish" || value === "zsh" ? value : "bash";
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
      },
    })
    .action(() => {
      writeCommandOutput(program, renderConsoleList(ansiEnabled(program)));
    });

  program
    .command("analyse")
    .description("Run gruff analysis.")
    .argument("[paths...]", "Files or directories to analyse.")
    .option("--config <path>", "Path to a gruff JSON/YAML config file.")
    .option("--no-config", "Skip auto-applying the default .gruff.json/.gruff.yaml/.gruff.yml file for this run.")
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

  program
    .command("completion")
    .description("Dump the shell completion script")
    .argument("[shell]", "Shell to generate completion for: bash, zsh, or fish.", "bash")
    .action((shell: string) => {
      writeCommandOutput(program, renderCompletionScript(completionShell(shell)));
    });

  program
    .command("dashboard")
    .description("Serve the local gruff dashboard.")
    .option("--host <host>", "Host to bind.", "127.0.0.1")
    .option("--port <port>", "Port to bind.", "8767")
    .option("--project-root <path>", "Default project root.", ".")
    .action((rawOptions: Record<string, unknown>) => {
      startDashboard(String(rawOptions.host ?? "127.0.0.1"), Number(rawOptions.port ?? 8767), resolve(String(rawOptions.projectRoot ?? ".")), !outputSuppressed(program));
    });

  program
    .command("list")
    .description("List commands")
    .action(() => {
      writeCommandOutput(program, renderConsoleList(ansiEnabled(program)));
    });

  program
    .command("list-rules")
    .description("List gruff rule metadata.")
    .option("--format <format>", "Output format: text or json.", "text")
    .action((rawOptions: Record<string, unknown>) => {
      const format: RuleListFormat = rawOptions.format === "json" ? "json" : "text";
      writeCommandOutput(program, renderRuleList(format));
    });

  program
    .command("report")
    .description("Render a gruff report to stdout or a file.")
    .argument("[paths...]", "Files or directories to analyse.")
    .option("--format <format>", "Report format: html or json.", "html")
    .option("--output <path>", "Write report to a file.")
    .option("--config <path>", "Path to a gruff JSON/YAML config file.")
    .option("--no-config", "Skip auto-applying the default .gruff.json/.gruff.yaml/.gruff.yml file for this run.")
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

  program
    .command("summary")
    .description(
      "Print a compact digest of a scan: per-pillar finding counts, top rules, and top file offenders. Runs the analyser once and renders only the summary; no per-finding spam.",
    )
    .argument("[paths...]", "Files or directories to analyse.")
    .option("--config <path>", "Path to a gruff JSON/YAML config file.")
    .option("--no-config", "Skip auto-applying the default .gruff.json/.gruff.yaml/.gruff.yml file for this run.")
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

  return program;
}

function normalizeOptions(paths: string[], rawOptions: Record<string, unknown>, context: NormalizeContext): AnalysisOptions {
  const format = stringChoice(rawOptions.format, ["text", "json", "html", "markdown", "github", "hotspot", "sarif"], "text");
  const failOn = stringChoice(rawOptions.failOn, ["none", "advisory", "warning", "error"], "error");
  const baselineValue = rawOptions.baseline;
  const noBaseline = baselineValue === false || rawOptions.noBaseline === true;
  return {
    paths,
    ...(typeof rawOptions.config === "string" ? { config: rawOptions.config } : {}),
    noConfig: rawOptions.config === false || rawOptions.noConfig === true,
    format,
    failOn,
    includeIgnored: rawOptions.includeIgnored === true,
    ...(typeof rawOptions.diff === "string" ? { diff: rawOptions.diff } : rawOptions.diff === true ? { diff: "working-tree" } : {}),
    ...(typeof rawOptions.historyFile === "string" ? { historyFile: rawOptions.historyFile } : {}),
    ...(context.allowBaselineFlag && typeof baselineValue === "string" ? { baseline: baselineValue } : context.allowBaselineFlag && baselineValue === true ? { baseline: DEFAULT_BASELINE } : {}),
    ...(typeof rawOptions.generateBaseline === "string"
      ? { generateBaseline: rawOptions.generateBaseline }
      : rawOptions.generateBaseline === true
        ? { generateBaseline: DEFAULT_BASELINE }
        : {}),
    noBaseline,
  };
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

function writeBaseline(path: string, findings: Finding[]): void {
  writeFileSync(
    path,
    JSON.stringify(
      {
        schemaVersion: "gruff.baseline.v1",
        generatedAt: new Date().toISOString(),
        entries: findings.map((finding) => ({
          fingerprint: finding.fingerprint,
          ruleId: finding.ruleId,
          filePath: finding.filePath,
          line: finding.line,
          symbol: finding.symbol,
          message: finding.message,
        })),
      },
      null,
      2,
    ),
  );
}

function applyBaseline(path: string, findings: Finding[]): Finding[] {
  const baselineFile = JSON.parse(readFileSync(path, "utf8")) as { schemaVersion?: string; entries?: Array<{ fingerprint: string; ruleId: string; filePath: string }> };
  if (baselineFile.schemaVersion !== "gruff.baseline.v1") {
    throw new Error(`unsupported baseline schema in ${path}`);
  }
  const keys = new Set((baselineFile.entries ?? []).map((entry) => [entry.fingerprint, entry.ruleId, entry.filePath].join("\0")));
  return findings.filter((finding) => !keys.has([finding.fingerprint, finding.ruleId, finding.filePath].join("\0")));
}

function recordHistory(projectRoot: string, historyFile: string, findings: Finding[], diagnostics: RunDiagnostic[]): void {
  const path = absolutize(projectRoot, historyFile);
  try {
    const entries = existsSync(path) ? (JSON.parse(readFileSync(path, "utf8")) as unknown[]) : [];
    entries.push({ recordedAt: new Date().toISOString(), findings: findings.length, score: scoreReport(findings).composite });
    writeFileSync(path, JSON.stringify(entries.slice(-100), null, 2));
  } catch (error) {
    diagnostics.push({ diagnosticType: "history-error", message: `Unable to write history file: ${String(error)}`, filePath: displayPath(projectRoot, path) });
  }
}
function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((finding) => {
    const key = finding.ruleId === "docs.missing-public-doc" && finding.symbol ? [finding.ruleId, finding.filePath, finding.symbol].join("\0") : finding.fingerprint;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function isDefaultIgnoredDir(path: string): boolean {
  const first = path.split("/")[0] ?? path;
  return [".git", ".hg", ".svn", ".idea", ".vscode", "build", "cache", "coverage", "dist", "generated", "node_modules", "target", "tmp", "vendor"].includes(first);
}

function isIgnoredDiscoveryPath(display: string, isDirectory: boolean, options: AnalysisOptions, config: Config, gitIgnoreRules: GitIgnoreRule[]): boolean {
  if (!options.includeIgnored && isDirectory && isDefaultIgnoredDir(display)) {
    return true;
  }
  if (!options.includeIgnored && isGitIgnoredPath(gitIgnoreRules, display, isDirectory)) {
    return true;
  }
  return config.ignoredPaths.some((pattern) => pathMatches(pattern, display));
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
    let line = rawLine.trimEnd();
    if (line.length === 0 || line.startsWith("#")) {
      continue;
    }
    if (line.startsWith("\\#") || line.startsWith("\\!")) {
      line = line.slice(1);
    }

    const negated = line.startsWith("!");
    if (negated) {
      line = line.slice(1);
    }
    if (line.length === 0) {
      continue;
    }

    const anchored = line.startsWith("/");
    line = line.replace(/^\/+/, "");
    const directoryOnly = line.endsWith("/");
    line = line.replace(/\/+$/, "");
    if (line.length === 0) {
      continue;
    }

    const pattern = line
      .split("/")
      .filter((segment) => segment.length > 0)
      .join("/");
    rules.push({ basePath, pattern, negated, directoryOnly, anchored, hasSlash: pattern.includes("/") });
  }
  return rules;
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
  if (rule.anchored || rule.hasSlash) {
    return gitIgnorePathCandidates(relativePath, isDirectory, true).some((candidate) => gitIgnoreGlobMatches(rule.pattern, candidate));
  }
  return relativePath.split("/").some((segment) => gitIgnoreGlobMatches(rule.pattern, segment));
}

function gitIgnoreDirectoryRuleMatches(rule: GitIgnoreRule, relativePath: string, isDirectory: boolean): boolean {
  if (rule.anchored || rule.hasSlash) {
    return gitIgnorePathCandidates(relativePath, isDirectory, false).some((candidate) => gitIgnoreGlobMatches(rule.pattern, candidate));
  }
  const segments = relativePath.split("/");
  const directorySegments = isDirectory ? segments : segments.slice(0, -1);
  return directorySegments.some((segment) => gitIgnoreGlobMatches(rule.pattern, segment));
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
    const character = pattern[index];
    if (character === "*") {
      const next = pattern[index + 1];
      const afterNext = pattern[index + 2];
      if (next === "*") {
        if (afterNext === "/") {
          source += "(?:.*/)?";
          index += 2;
        } else {
          source += ".*";
          index += 1;
        }
      } else {
        source += "[^/]*";
      }
      continue;
    }
    if (character === "?") {
      source += "[^/]";
      continue;
    }
    source += escapeRegex(character ?? "");
  }
  return new RegExp(`${source}$`);
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

function hasDocCommentBefore(block: string): boolean {
  return block
    .split(/\r?\n/)
    .filter((line) => !/\b(function|class|interface|type|enum)\b/.test(line))
    .some((line) => line.trimStart().startsWith("/**") || line.trimStart().startsWith("*"));
}

function hasDocCommentBeforeLine(source: string, line: number): boolean {
  const lines = source.split(/\r?\n/);
  let index = line - 2;
  while (index >= 0) {
    const current = lines[index]?.trim() ?? "";
    if (current.startsWith("/**") || current.startsWith("*")) {
      return true;
    }
    if (current !== "" && !current.startsWith("@")) {
      return false;
    }
    index -= 1;
  }
  return false;
}

function isGenericName(name: string): boolean {
  return ["process", "handle", "doit", "run", "execute", "manage"].includes(name.toLowerCase());
}

function isHighEntropySecretCandidate(value: string, minLength: number): boolean {
  if (value.length < minLength || /^[0-9a-f]+$/i.test(value) || /^sha(?:256|384|512)-[A-Za-z0-9+/=]+$/.test(value)) {
    return false;
  }
  if (!/[a-z]/.test(value) || !/[A-Z]/.test(value) || !/[0-9]/.test(value)) {
    return false;
  }
  if (new Set(value).size < Math.min(12, Math.ceil(value.length / 3))) {
    return false;
  }
  return shannonEntropy(value) >= 4;
}

function shannonEntropy(value: string): number {
  const counts = new Map<string, number>();
  for (const character of value) {
    counts.set(character, (counts.get(character) ?? 0) + 1);
  }
  return [...counts.values()].reduce((sum, count) => {
    const probability = count / value.length;
    return sum - probability * Math.log2(probability);
  }, 0);
}
function redact(value: string): string {
  if (value.length <= 8) {
    return `${"*".repeat(value.length)} (redacted, ${value.length} chars)`;
  }
  return `${value.slice(0, 4)}...${value.slice(-4)} (redacted, ${value.length} chars)`;
}

function severityPenalty(severity: Severity): number {
  return severity === "error" ? 8 : severity === "warning" ? 4 : 1.5;
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

export { buildProgram, renderReport, ruleDescriptors };
