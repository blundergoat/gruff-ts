// Cross-file architecture rules (deep imports, cycles, large-module concentration) and the
// path-classification helpers (isTestPath, isFixtureLikePath, etc.) every rule pass shares. Pulls the
// project-index types and the rules that consume them out of cli.ts so the orchestrator stays lean.
import { dirname as dirnamePath, extname, join } from "node:path";
import { isString } from "./config-parse.ts";
import { optionNumber, ruleEnabled, ruleSeverity, threshold } from "./config.ts";
import { type SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import { fileBaseName } from "./findings-helpers.ts";
import type { Config, Finding, Severity } from "./types.ts";

// Read-once snapshot of a discovered file. Lines are cached because cross-file project rules
// scan each source repeatedly - splitting once amortises the cost across rule passes.
// `templateMaskedLines` mirrors `lines` but blanks out `` ` `` template-literal body characters
// (single/double-quoted strings stay intact), so syntax-pattern rules can skip fixture
// template-literal content without losing real `import ... from "..."` detection.
export interface ProjectSource {
  file: SourceFile;
  lines: string[];
  templateMaskedLines: string[];
  // Code lines only, so a module's share of production source does not grow with its documentation.
  codeLineCount: number;
}

// Project-wide aggregate built once per scan and reused by every architecture rule (cycle detection,
// large-module concentration, deep-relative-import). `scriptSources` is a pre-filtered view of
// `sources` so per-rule code paths don't repeat the script-file check.
export interface ProjectIndex {
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
  isTypeOnly: boolean;
  targetPath?: string;
}

// Raw import/export statement span extracted before edge parsing. `line` anchors every edge found
// inside the statement, even when the specifier appears several physical lines later.
interface ImportStatement {
  source: string;
  line: number;
}

// Sorted SCC member list plus one deterministic closed cycle path for reviewer context.
interface ImportCycle {
  files: string[];
  representativeCycle: string[];
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

// Optional switches for architecture analysis. The circular-import gate lets a caller build root
// graph context elsewhere without emitting duplicate SCC findings from the scoped index.
interface ArchitectureRuleOptions {
  shouldSkipCircularImports?: boolean;
}

// Builds and returns a ProjectIndex from projectSources, copying and sorting sources by display path without reordering the input array.
// The index includes script sources, their path set and import edges so cross-file rules share a deterministic view.
export function buildProjectIndex(projectSources: ProjectSource[]): ProjectIndex {
  const sources = [...projectSources].sort((left, right) => left.file.displayPath.localeCompare(right.file.displayPath));
  const scriptSources = sources.filter((source) => source.file.isScript);
  const sourcePaths = new Set(scriptSources.map((source) => source.file.displayPath));
  const importsByFile = new Map<string, ImportEdge[]>();
  for (const source of scriptSources) {
    importsByFile.set(source.file.displayPath, importEdgesForSource(source, sourcePaths));
  }
  return { sources, scriptSources, sourcePaths, importsByFile };
}

// Runs enabled deep-import, cycle and large-module checks in that stable order.
// The index supplies sources and import edges. Config supplies rule settings. The options can suppress the otherwise enabled cycle check.
// Returns nothing. Appends any reported findings to the supplied list.
export function analyseArchitectureRules(index: ProjectIndex, config: Config, findings: Finding[], options: ArchitectureRuleOptions = {}): void {
  if (ruleEnabled(config, DEEP_RELATIVE_IMPORT_RULE_ID)) {
    analyseDeepRelativeImports(index, config, findings);
  }
  if (!options.shouldSkipCircularImports && ruleEnabled(config, CIRCULAR_IMPORT_RULE_ID)) {
    analyseCircularImportRule(index, findings);
  }
  if (ruleEnabled(config, LARGE_MODULE_CONCENTRATION_RULE_ID)) {
    analyseLargeModuleConcentration(index, config, findings);
  }
}

const DEEP_RELATIVE_IMPORT_RULE_ID = "design.deep-relative-import";
export const CIRCULAR_IMPORT_RULE_ID = "design.circular-import";
const LARGE_MODULE_CONCENTRATION_RULE_ID = "design.large-module-concentration";

/**
 * Reports relative imports above the configured parent-hop limit.
 * Uses parsed import edges because they supply both the hop count and the source line for a stable finding location.
 *
 * @param index - supplies importing scripts and their parsed import edges
 * @param config - supplies the parent-hop limit and finding severity
 * @param findings - destination for one finding per import above the limit
 * @returns Nothing. Appends findings to the supplied list, leaving it unchanged if no import qualifies.
 */
function analyseDeepRelativeImports(index: ProjectIndex, config: Config, findings: Finding[]): void {
  const maxParentSegments = threshold(config, "design.deep-relative-import", 2);
  const severity = ruleSeverity(config, DEEP_RELATIVE_IMPORT_RULE_ID, "advisory");
  for (const source of index.scriptSources) {
    const edges = index.importsByFile.get(source.file.displayPath) ?? [];
    for (const edge of edges) {
      if (edge.parentSegments <= maxParentSegments) {
        continue;
      }
      findings.push(
        makeFinding({
          ruleId: DEEP_RELATIVE_IMPORT_RULE_ID,
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

// Appends one finding to findings for each cyclic runtime-import component in index that has an available anchor source.
// importCycles supplies deterministic component order. Components without an anchor are skipped.
// Returns no value after appending the qualifying findings.
export function analyseCircularImportRule(index: ProjectIndex, findings: Finding[]): void {
  for (const cycle of importCycles(index)) {
    const finding = circularImportFinding(index, cycle);
    if (finding) {
      findings.push(finding);
    }
  }
}

/*
 * Anchors the finding at the first file in the cycle so the stable fingerprint and reported line
 * match across reruns. Returns undefined when no indexed script source matches that anchor.
 */
function circularImportFinding(index: ProjectIndex, cycle: ImportCycle): Finding | undefined {
  const anchorPath = cycle.files[0] ?? "";
  const anchorSource = index.scriptSources.find((source) => source.file.displayPath === anchorPath);
  if (!anchorSource) {
    return undefined;
  }
  return makeFinding({
    ruleId: CIRCULAR_IMPORT_RULE_ID,
    message: `Import cycle detected among ${cycle.files.join(", ")}.`,
    filePath: anchorSource.file.displayPath,
    line: circularImportLine(index, anchorPath, cycle),
    severity: "warning",
    pillar: "design",
    confidence: "medium",
    symbol: cycle.files.join(" -> "),
    remediation: "Extract the shared contract or move one dependency behind an explicit boundary.",
    metadata: { files: cycle.files, representativeCycle: cycle.representativeCycle },
  });
}

// Returns the first non-type-only import line in index for anchorPath whose resolved target belongs to cycle.
// Returns line 1 when no qualifying edge exists, keeping the finding's source anchor defined.
function circularImportLine(index: ProjectIndex, anchorPath: string, cycle: ImportCycle): number {
  const anchorEdges = index.importsByFile.get(anchorPath) ?? [];
  return anchorEdges.find((edge) => !edge.isTypeOnly && edge.targetPath && cycle.files.includes(edge.targetPath))?.line ?? 1;
}

/**
 * Checks whether the largest production source file exceeds the configured share after the project and file size minimums are met.
 * Emits at most one stable finding so the report points to the most concentrated module.
 *
 * @param index - project index supplying source files and their line counts
 * @param config - supplies the concentration thresholds and finding severity
 * @param findings - destination for the finding if the largest file qualifies
 * @returns Nothing. Appends a finding only when the project and largest file meet the rule's conditions.
 */
function analyseLargeModuleConcentration(index: ProjectIndex, config: Config, findings: Finding[]): void {
  const candidate = largeModuleCandidate(index, largeModuleThresholds(config));
  if (!candidate) {
    return;
  }
  findings.push(largeModuleConcentrationFinding(candidate, ruleSeverity(config, "design.large-module-concentration", "advisory")));
}

// Reads the rule limits from config: a minimum production-file count, a line minimum for the largest file, and a project-share cap.
// Returns these thresholds for candidate selection. Both minima must be met and the share cap exceeded.
// Missing settings default to 4 production files, 80 lines for the largest file and a 55 percent share cap.
function largeModuleThresholds(config: Config): LargeModuleThresholds {
  return {
    minFiles: optionNumber(config, "design.large-module-concentration", "minFiles", 4),
    minLines: optionNumber(config, "design.large-module-concentration", "minLines", 80),
    maxSharePercent: threshold(config, "design.large-module-concentration", 55),
  };
}

// Returns the largest production file in index with its line count, project total, share, and thresholds when it qualifies.
// Returns undefined for too few production files, no production lines, or a largest file failing the size or dominance limits.
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

// Checks largest's production line count and sharePercent against thresholds; returns true only when both limits qualify.
// The line minimum is inclusive and the share cap must be exceeded, so tiny dominant modules remain ineligible.
function exceedsLargeModuleThresholds(largest: ModuleLineCount, sharePercent: number, thresholds: LargeModuleThresholds): boolean {
  return largest.lines >= thresholds.minLines && sharePercent > thresholds.maxSharePercent;
}

// Returns line counts for indexed production sources, excluding tests, fixtures, declarations and generated paths.
// Sorts by descending line count then path so the rule has a deterministic largest source. An empty list leaves no candidate.
function productionModuleLineCounts(index: ProjectIndex): ModuleLineCount[] {
  return index.scriptSources
    .filter((source) => isProductionSourcePath(source.file.displayPath))
    .map((source) => ({ source, lines: source.codeLineCount }))
    .sort((left, right) => right.lines - left.lines || left.source.file.displayPath.localeCompare(right.source.file.displayPath));
}

// Returns a stable design finding for candidate's share of production lines at the supplied severity.
// Includes measured counts and all configured thresholds so reviewers can explain the result without rerunning with the same config.
function largeModuleConcentrationFinding(candidate: LargeModuleCandidate, severity: Severity): Finding {
  return makeFinding({
    ruleId: LARGE_MODULE_CONCENTRATION_RULE_ID,
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

// Extracts relative import edges from source's template-masked lines, resolving targets only against sourcePaths.
// Returns edges ordered by line and specifier for deterministic traversal. No matching relative import or re-export yields an empty list.
// Unresolved relative imports keep their edges without targetPath so parent-hop checks can still use them.
function importEdgesForSource(source: ProjectSource, sourcePaths: Set<string>): ImportEdge[] {
  const edges: ImportEdge[] = [];
  for (const statement of importStatements(source.templateMaskedLines)) {
    edges.push(...importEdgesForStatement(source.file.displayPath, statement, sourcePaths));
  }
  return edges.sort((left, right) => left.line - right.line || left.specifier.localeCompare(right.specifier));
}

// Reassembles import/export spans from template-masked lines, returning their source text and starting lines for graph extraction.
// Lines before a declaration are skipped; trailing text that fails the completion check is omitted.
function importStatements(lines: string[]): ImportStatement[] {
  const statements: ImportStatement[] = [];
  let current = "";
  let startLine = 1;
  for (const [index, line] of lines.entries()) {
    const trimmed = line.trim();
    if (!current && !/^(?:import|export)\b/.test(trimmed)) {
      continue;
    }
    if (!current) {
      startLine = index + 1;
    }
    current = `${current}\n${line}`;
    if (isImportStatementComplete(current)) {
      statements.push({ source: current, line: startLine });
      current = "";
    }
  }
  if (isImportStatementComplete(current)) {
    statements.push({ source: current, line: startLine });
  }
  return statements;
}

// A statement is complete once it reaches a quoted module specifier, either bare side-effect
// imports (`import "x"`) or `from "x"` forms.
function isImportStatementComplete(statement: string): boolean {
  return /\b(?:from\s*)?["'][^"']+["']/.test(statement);
}

// Extracts edges from relative imports and re-exports in statement, anchoring each edge at the statement's starting line.
// importerPath is the resolution base and sourcePaths supplies candidate files. Unresolved relative edges have no targetPath.
// Returns an empty list when no relative specifier matches. Omits non-relative specifiers.
function importEdgesForStatement(importerPath: string, statement: ImportStatement, sourcePaths: Set<string>): ImportEdge[] {
  const edges: ImportEdge[] = [];
  for (const match of statement.source.matchAll(/\b(?:import|export)\b(?:[\s\S]*?\bfrom\s*)?\s*["']([^"']+)["']/g)) {
    const edge = importEdgeForSpecifier(importerPath, match[1] ?? "", statement.line, sourcePaths, isTypeOnlyImportStatement(match[0] ?? ""));
    if (edge) {
      edges.push(edge);
    }
  }
  return edges;
}

// Builds an import-rule edge using importerPath as the resolution base and sourcePaths as the discovered-file candidates.
// specifier supplies the module text and parent hops; line and isTypeOnly retain its source anchor and classification.
// Returns undefined for non-relative specifiers; unresolved relative imports return an edge without targetPath.
function importEdgeForSpecifier(importerPath: string, specifier: string, line: number, sourcePaths: Set<string>, isTypeOnly: boolean): ImportEdge | undefined {
  if (!specifier.startsWith(".")) {
    return undefined;
  }
  const targetPath = resolveRelativeImport(importerPath, specifier, sourcePaths);
  return {
    specifier,
    line,
    parentSegments: specifier.split("/").filter((segment) => segment === "..").length,
    isTypeOnly,
    ...(targetPath ? { targetPath } : {}),
  };
}

// Returns whether importStatement contains an import type or export type prefix, marking that edge as type-only for cycle checks.
// Inline type specifiers are not recognized by this check.
function isTypeOnlyImportStatement(importStatement: string): boolean {
  return /\b(?:import|export)\s+type\b/.test(importStatement);
}

// Returns the first indexed match for a specifier resolved from the importing file's directory, or undefined if none match.
// The source-path set defines the available targets. A stable candidate order keeps cycle output reproducible.
function resolveRelativeImport(importerPath: string, specifier: string, sourcePaths: Set<string>): string | undefined {
  const basePath = normalizeDisplayPath(join(dirnamePath(importerPath), specifier));
  for (const candidate of importPathCandidates(basePath)) {
    if (sourcePaths.has(candidate)) {
      return candidate;
    }
  }
  return undefined;
}

// Returns resolution candidates for basePath: an explicit extension tries the original path and script-extension substitutions.
// An extensionless path tries script files and directory indexes; duplicates are removed before path normalization.
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

// Returns deterministic cycle records from index's import graph for one finding per multi-file component.
// Records contain sorted members and a representative closed path; no qualifying components returns an empty list.
function importCycles(index: ProjectIndex): ImportCycle[] {
  return stronglyConnectedImportComponents(index)
    .map((files) => ({ files, representativeCycle: representativeCycle(index, files) }))
    .sort((left, right) => left.files.join("\0").localeCompare(right.files.join("\0")));
}

// Mutable state for Tarjan's algorithm. Keeping it in one object makes the recursive visitor's
// signature small enough to audit.
interface StronglyConnectedState {
  nextIndex: number;
  indices: Map<string, number>;
  lowLinks: Map<string, number>;
  stack: string[];
  onStack: Set<string>;
  components: string[][];
}

// Returns sorted multi-file strongly connected components from index's graph, excluding edges marked type-only, for stable findings.
// Singleton components, including self-imports, are omitted; no qualifying component yields an empty list.
function stronglyConnectedImportComponents(index: ProjectIndex): string[][] {
  const state: StronglyConnectedState = {
    nextIndex: 0,
    indices: new Map(),
    lowLinks: new Map(),
    stack: [],
    onStack: new Set(),
    components: [],
  };
  for (const path of [...index.importsByFile.keys()].sort()) {
    if (!state.indices.has(path)) {
      visitStronglyConnectedImportComponent(index, path, state);
    }
  }
  return state.components
    .map((component) => [...component].sort())
    .filter((component) => component.length > 1)
    .sort((left, right) => left.join("\0").localeCompare(right.join("\0")));
}

// Traverses index's import graph from path, mutating state to track Tarjan discovery order, low-links, and the active stack.
// Returns no value. Non-root vertices stay on the stack so that the component root can pop and record them together in state.components.
function visitStronglyConnectedImportComponent(index: ProjectIndex, path: string, state: StronglyConnectedState): void {
  state.indices.set(path, state.nextIndex);
  state.lowLinks.set(path, state.nextIndex);
  state.nextIndex += 1;
  state.stack.push(path);
  state.onStack.add(path);

  for (const target of circularImportTargets(index, path)) {
    if (!state.indices.has(target)) {
      visitStronglyConnectedImportComponent(index, target, state);
      state.lowLinks.set(path, Math.min(lowLinkFor(state, path), lowLinkFor(state, target)));
      continue;
    }
    if (state.onStack.has(target)) {
      state.lowLinks.set(path, Math.min(lowLinkFor(state, path), indexFor(state, target)));
    }
  }

  if (lowLinkFor(state, path) !== indexFor(state, path)) {
    return;
  }
  const component: string[] = [];
  while (state.stack.length > 0) {
    const member = state.stack.pop();
    if (!member) {
      break;
    }
    state.onStack.delete(member);
    component.push(member);
    if (member === path) {
      break;
    }
  }
  state.components.push(component);
}

// Returns path's discovery index from state for Tarjan comparisons; absent entries return zero.
function indexFor(state: StronglyConnectedState, path: string): number {
  return state.indices.get(path) ?? 0;
}

// Returns path's low-link value from traversal state for Tarjan comparisons, or zero when no value is recorded.
function lowLinkFor(state: StronglyConnectedState, path: string): number {
  return state.lowLinks.get(path) ?? 0;
}

// Returns sorted, unique value-import targets for the importing file's path in the project index under the stable runtime-cycle contract.
// If the file has no resolved value imports, the empty list leaves it with no outgoing cycle edges.
function circularImportTargets(index: ProjectIndex, path: string): string[] {
  return [...new Set((index.importsByFile.get(path) ?? []).filter((edge) => !edge.isTypeOnly).map((edge) => edge.targetPath).filter(isString))].sort();
}

// Uses index's import graph to choose a closed path through files, starting with the first member, for a grouped cycle finding.
// Returns an empty list for empty files; if no closing path is found, returns the supplied files array unchanged.
function representativeCycle(index: ProjectIndex, files: string[]): string[] {
  const anchor = files[0];
  if (!anchor) {
    return [];
  }
  const members = new Set(files);
  for (const target of circularImportTargets(index, anchor).filter((candidate) => members.has(candidate))) {
    const returnPath = pathBetweenComponentMembers(index, target, anchor, members);
    if (returnPath) {
      return [anchor, ...returnPath];
    }
  }
  return files;
}

// Queue item for finding a representative path through one SCC.
interface ComponentPathSearch {
  current: string;
  path: string[];
}

// Finds a shortest directed import path from start to end in index, following only targets present in members.
// Returns the path including both endpoints when an edge reaches end, or undefined when none does, for a representative cycle.
function pathBetweenComponentMembers(index: ProjectIndex, start: string, end: string, members: Set<string>): string[] | undefined {
  const queue: ComponentPathSearch[] = [{ current: start, path: [start] }];
  const visited = new Set([start]);
  for (let queueIndex = 0; queueIndex < queue.length; queueIndex += 1) {
    const searchState = queue[queueIndex];
    if (!searchState) {
      continue;
    }
    for (const target of circularImportTargets(index, searchState.current).filter((candidate) => members.has(candidate))) {
      if (target === end) {
        return [...searchState.path, target];
      }
      if (visited.has(target)) {
        continue;
      }
      visited.add(target);
      queue.push({ current: target, path: [...searchState.path, target] });
    }
  }
  return undefined;
}

// Returns whether path qualifies for production-only rules by excluding test, declaration, and fixture-like paths.
// Any slash-delimited generated component also excludes the path. This classification governs every production-only rule.
export function isProductionSourcePath(path: string): boolean {
  return !isTestPath(path) && !isDeclarationPath(path) && !isFixtureLikePath(path) && !path.split("/").includes("generated");
}

// Returns true for a path under __tests__, test, tests or spec, or for a filename with .test or .spec before a JS or TS extension.
// The production-source filter uses this classification, so adding a convention here changes which files count as production.
export function isTestPath(path: string): boolean {
  return /(?:^|\/)(?:__tests__|tests?|spec)\//.test(path) || /\.(?:test|spec)\.[cm]?[tj]sx?$/.test(path);
}

// Returns whether path has a .d.ts, .d.cts, or .d.mts suffix, identifying declaration files for rule filtering.
export function isDeclarationPath(path: string): boolean {
  return /\.d\.[cm]?ts$/.test(path);
}

// Returns true for a slash-separated path under __fixtures__, fixture, fixtures or testdata.
// The production-source filter excludes these paths, and docs.fixture-purpose-missing can check them.
export function isFixtureLikePath(path: string): boolean {
  return /(?:^|\/)(?:__fixtures__|fixtures?|testdata)\//.test(path);
}

// Converts platform-native paths to the POSIX-style report shape used in every Finding. Must be
// idempotent - repeated normalisation must produce the same string.
function normalizeDisplayPath(path: string): string {
  return path.replaceAll("\\", "/").replace(/^\.\//, "");
}
