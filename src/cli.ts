#!/usr/bin/env node
// Analyser core: walks discovered sources, runs every rule pass (size, complexity, dead-code,
// waste, naming, documentation, modernisation, security, sensitive-data, test-quality, design),
// aggregates findings into the `gruff.analysis.v1` schema, and exposes `analyse` to the CLI.
import { existsSync, readFileSync } from "node:fs";
import { argv, cwd } from "node:process";
import { basename, join } from "node:path";
import { pathToFileURL } from "node:url";
import { applyBaseline, dedupeFindings, DEFAULT_BASELINE, recordHistory, writeBaseline } from "./baseline.ts";
import { buildProgram as buildCliProgram } from "./cli-program.ts";
import { loadConfig, optionNumber, ruleEnabled, ruleSeverity, threshold } from "./config.ts";
import { VERSION } from "./constants.ts";
import { absolutize, discoverSources, displayPath, type SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import { changedFiles, escapeRegex, fileBaseName, finding, isCommentedOutCode, normalizedIdentifier } from "./findings-helpers.ts";
import { type CommentRecord, commentRecords } from "./comment-scanner.ts";
import { analyseArchitectureRules, analyseTestAdequacyRules, buildProjectIndex, isTestPath, type ProjectSource } from "./project-rules.ts";
import { analyseBlockRules, type BlockRuleContext, blockFinding, blockFindingWithMetadata, blockRuleContext, type FunctionBlock, functionBlocks, hasAssertion, parameterNames, setupLineCount } from "./blocks.ts";
import { analyseCommentQualityRules, analyseDocRules, analyseFileOverviewDoc, analyseInterfaceDocs, type ExportedDeclaration, exportedDeclarations, hasSuppressionRationale, pushMissingPublicDocFinding } from "./comment-rules.ts";
import { analyseProjectConfigRules } from "./project-config-rules.ts";
import { renderReport } from "./report-renderers.ts";
import { scoreReport, summarize } from "./scoring.ts";
import { ruleDescriptors } from "./rules.ts";
import { analyseSensitiveData } from "./sensitive-data-rules.ts";
import { codeLineForMatching, maskNonCode, parseDiagnostics } from "./source-text.ts";
import { byteLine, countMatches, todoMarkerSummary } from "./text-scans.ts";
import type { AnalysisOptions, AnalysisReport, Config, Finding, OutputFormat, Pillar, RunDiagnostic, Severity } from "./types.ts";
export type { AnalysisReport, Finding, OutputFormat, Pillar, RuleDescriptor, Severity } from "./types.ts";


// Provisional rule output gathered during a test-block walk. Built before the surrounding context
// (file, line) is known, then promoted into a real Finding by the caller.
interface TestBlockCheck {
  ruleId: string;
  message: string;
  severity: Severity;
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

// Returns the directive name only when the suffix following a TypeScript suppression directive
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
function hasDirectiveRationale(directiveSuffix: string): boolean {
  const cleaned = directiveSuffix.replace(/^[-:\s]+/, "").trim();
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
function isUnreachableStatement(trimmedLine: string, didPreviousTerminate: boolean, isBranchLabel: boolean): boolean {
  return didPreviousTerminate && /\S/.test(trimmedLine) && !trimmedLine.startsWith(String.fromCharCode(125)) && !isBranchLabel;
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
  const escaped = [...prefixes].map(escapeRegex);
  const regex = prefixes.size === 0 ? null : new RegExp(`^(?:${escaped.join("|")})[A-Z_]`);
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




const buildProgram = (): ReturnType<typeof buildCliProgram> => buildCliProgram(analyse);

if (import.meta.url === pathToFileURL(argv[1] ?? "").href) {
  buildProgram().parse(argv);
}

export { absolutize, buildProgram, displayPath, renderReport, ruleDescriptors };
