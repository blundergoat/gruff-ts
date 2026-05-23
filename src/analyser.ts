// Analyser pipeline: walks discovered sources, runs every rule pass (size, complexity, dead-code,
// waste, naming, documentation, modernisation, security, sensitive-data, test-quality, design),
// aggregates findings into the `gruff.analysis.v1` schema, and exposes `analyse` to the CLI shell.
import { existsSync, readFileSync } from "node:fs";
import { cwd } from "node:process";
import { basename, join } from "node:path";
import { applyBaseline, dedupeFindings, DEFAULT_BASELINE, recordHistory, writeBaseline } from "./baseline.ts";
import { loadConfig, optionNumber, ruleEnabled, ruleSeverity, threshold } from "./config.ts";
import { VERSION } from "./constants.ts";
import { absolutize, discoverSources, displayPath, type SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import { changedFiles, finding } from "./findings-helpers.ts";
import { commentRecords } from "./comment-scanner.ts";
import { analyseArchitectureRules, analyseTestAdequacyRules, buildProjectIndex, exportedSurface, isProductionSourcePath, isTestPath, type ProjectSource } from "./project-rules.ts";
import { analyseBlockRules, type BlockRuleContext, blockRuleContext, type FunctionBlock, functionBlocks, parameterNames } from "./blocks.ts";
import { analyseClassRules, analyseAcronymCase, analyseInconsistentCasing, analyseInterfaceFields, collectDeclaredIdentifiers } from "./class-rules.ts";
import { analyseDeadCode, analyseUnreachable, analyseUnusedImports } from "./dead-code-rules.ts";
import { analyseCommentQualityRules } from "./comment-rules.ts";
import { analyseDocRules, analyseFileOverviewDoc, analyseInterfaceDocs } from "./doc-rules.ts";
import { analyseLineRules } from "./line-rules.ts";
import { pushAbbreviationAt, pushBooleanPrefixAt, pushIdentifierQualityAt, pushNegativeBooleanAt, pushShortVariableAt } from "./naming-pushers.ts";
import { analyseTestBlock } from "./test-block-rules.ts";
import { analyseGithubActionsRules } from "./github-actions-rules.ts";
import { analyseProjectConfigRules } from "./project-config-rules.ts";
import { scoreReport, summarize } from "./scoring.ts";
import { analyseSensitiveData } from "./sensitive-data-rules.ts";
import { maskNonCode, maskTemplateLiteralBodies, parseDiagnostics } from "./source-text.ts";
import { todoMarkerSummary } from "./text-scans.ts";
import type { AnalysisOptions, AnalysisReport, Config, Finding, RunDiagnostic } from "./types.ts";

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
 * Per-file read + scan loop. Reports read failures as diagnostics because CLI users need partial
 * results from the rest of the tree, but the stable discovered-file order still feeds project-index
 * snapshots before the final canonical sort. Changing that contract can churn graph-rule anchors.
 */
function scanDiscoveredSources(files: SourceFile[], config: Config, diagnostics: RunDiagnostic[]): SourceScanResult {
  const findings: Finding[] = [];
  const projectSources: ProjectSource[] = [];
  for (const file of files) {
    try {
      const source = readFileSync(file.absolutePath, "utf8");
      if (shouldRetainProjectSource(file, source)) {
        projectSources.push(projectSource(file, source));
      }
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
  const surface = isProductionSourcePath(file.displayPath) ? exportedSurface(source) : undefined;
  return { file, lines, templateMaskedLines, ...(surface ? { exportedSurface: surface } : {}) };
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

/*
 * Three-way baseline dispatcher. `--generate-baseline` wins (writes a new file, returns findings
 * unchanged); `--no-baseline` skips entirely; otherwise look for an explicit or default baseline.
 * The stable identity tuple (fingerprint, ruleId, filePath) drives suppression matching.
 */
function applyBaselineOptions(projectRoot: string, options: AnalysisOptions, findings: Finding[]): BaselineApplication {
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

/*
 * Per-file text-pillar rules run before script-only rules because config, workflow, CSS, and
 * secret surfaces are not TypeScript. The order is a stable baseline contract: reshuffling these
 * checks changes same-line finding order for machine reports.
 */
function analyseTextRules(file: SourceFile, source: string, config: Config, findings: Finding[]): void {
  const lines = lineCount(source);
  if (isCssPath(file.displayPath)) {
    const stylesheetThreshold = threshold(config, "size.stylesheet-length", 1500);
    if (lines > stylesheetThreshold) {
      findings.push(finding({ ruleId: "size.stylesheet-length", message: `Stylesheet has ${lines} lines, above the threshold of ${stylesheetThreshold}.`, file, line: 1, severity: ruleSeverity(config, "size.stylesheet-length", "warning"), pillar: "size" }));
    }
  } else if (!isGeneratedLockfile(file.displayPath)) {
    const fileLengthThreshold = threshold(config, "size.file-length", 750);
    if (lines > fileLengthThreshold) {
      findings.push(finding({ ruleId: "size.file-length", message: `File has ${lines} lines, above the threshold of ${fileLengthThreshold}.`, file, line: 1, severity: ruleSeverity(config, "size.file-length", "warning"), pillar: "size" }));
    }
  }

  /*
   * Opt-in by default per M38 (.goat-flow/tasks/0.1/M38-css-metrics-and-todo-density-calibration.md):
   * raw marker density produced too many false positives in other gruff projects; prefer the
   * context-aware docs.todo-without-tracking rule when task-marker scanning matters.
   */
  if (config.rules.get("docs.todo-density")?.enabled === true) {
    const todoMarkers = todoMarkerSummary(source, file.isScript);
    if (todoMarkers.count >= threshold(config, "docs.todo-density", 4)) {
      findings.push(finding({ ruleId: "docs.todo-density", message: `File contains ${todoMarkers.count} TODO/FIXME markers.`, file, line: todoMarkers.firstLine, severity: ruleSeverity(config, "docs.todo-density", "advisory"), pillar: "documentation" }));
    }
  }

  analyseSensitiveData(file, source, config, findings);
  analyseGithubActionsRules(file, source, findings);
  analyseProjectConfigRules(file, source, findings);
}

// CSS paths use a dedicated size rule (`size.stylesheet-length`) so stylesheets can have a
// different threshold and message from generic source files.
function isCssPath(displayPath: string): boolean {
  return displayPath.toLowerCase().endsWith(".css");
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
  const codeSource = maskNonCode(source);
  const blocks = functionBlocks(source, codeSource);
  const comments = commentRecords(source);
  analyseFileOverviewDoc(file, source, findings);
  analyseBlocks(file, blocks, config, findings);
  analyseUnusedImports(file, codeSource, source, findings);
  analyseLineRules(file, source, codeSource, config, findings);
  analyseUnreachable(file, codeSource, findings);
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


// One pass over the file's parsed callables. The naming and test-block fanouts are dispatched
// separately so blocks.ts can stay independent of the naming-pusher and test-block-rule modules;
// the per-rule emission order from `analyseBlockRules` is the stable fingerprint contract every
// Finding depends on for deterministic baseline matching.
function analyseBlocks(file: SourceFile, blocks: FunctionBlock[], config: Config, findings: Finding[]): void {
  for (const block of blocks) {
    const context = blockRuleContext(file, block, config, findings);
    analyseBlockRules(context);
    pushParameterNamingFindings(context);
    if (block.isTest) {
      analyseTestBlock(file, block, config, findings);
    }
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
