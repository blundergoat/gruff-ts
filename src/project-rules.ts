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

// Read-once snapshot of a discovered file for cross-file architecture rules. Stores only extracted
// import/export statements and substantive code-line count so multi-thousand-file repositories do
// not retain full line arrays in memory across the whole scan.
export interface ProjectSource {
  file: SourceFile;
  importStatements: ImportStatement[];
  // Code lines only, so a module's share of production source does not grow with its documentation.
  codeLineCount: number;
}

// Project-wide aggregate built once per scan and reused by every architecture rule (cycle detection and
// large-module concentration). `scriptSources` is a pre-filtered view of
// `sources` so per-rule code paths don't repeat the script-file check.
export interface ProjectIndex {
  sources: ProjectSource[];
  scriptSources: ProjectSource[];
  sourcePaths: Set<string>;
  importsByFile: Map<string, ImportEdge[]>;
}

// One import statement in the graph. `targetPath` is set only when the specifier resolves to a file
// gruff has actually discovered.
interface ImportEdge {
  specifier: string;
  line: number;
  isTypeOnly: boolean;
  targetPath?: string;
}

// Raw import/export statement span extracted before edge parsing. `line` anchors every edge found
// inside the statement, even when the specifier appears several physical lines later.
export interface ImportStatement {
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

/**
 * Copies and sorts discovered sources by display path without reordering the input array so cross-file rules share a deterministic view.
 *
 * @param projectSources - discovered source snapshots to sort and index
 * @returns Project index containing sorted sources, script sources, their path set, and resolved import edges.
 */
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

/**
 * Runs enabled circular-import and large-module concentration checks in that stable order.
 *
 * @param index - project index supplying sources and import edges
 * @param config - rule configuration supplying enabled flags, thresholds, and severities
 * @param findings - destination array for emitted findings
 * @param options - optional switches that can suppress the circular-import check when already enabled
 * @returns Nothing. Appends any reported findings to `findings`.
 */
export function analyseArchitectureRules(index: ProjectIndex, config: Config, findings: Finding[], options: ArchitectureRuleOptions = {}): void {
  if (!options.shouldSkipCircularImports && ruleEnabled(config, CIRCULAR_IMPORT_RULE_ID)) {
    analyseCircularImportRule(index, findings);
  }
  if (ruleEnabled(config, LARGE_MODULE_CONCENTRATION_RULE_ID)) {
    analyseLargeModuleConcentration(index, config, findings);
  }
}

export const CIRCULAR_IMPORT_RULE_ID = "design.circular-import";
const LARGE_MODULE_CONCENTRATION_RULE_ID = "design.large-module-concentration";

/**
 * Records one finding for each cyclic runtime-import component in deterministic `importCycles` order, skipping components without an anchor.
 *
 * @param index - project index supplying script sources and import edges
 * @param findings - destination array for qualifying circular-import findings
 * @returns Nothing. Appends one finding to `findings` for each anchored component.
 */
export function analyseCircularImportRule(index: ProjectIndex, findings: Finding[]): void {
  for (const cycle of importCycles(index)) {
    const finding = circularImportFinding(index, cycle);
    if (finding) {
      findings.push(finding);
    }
  }
}

/**
 * Builds a circular-import finding anchored at the first file in the cycle so the stable fingerprint and reported line match across reruns.
 *
 * @param index - project index used to resolve the anchor script source and import line
 * @param cycle - strongly connected import component with sorted files and representative cycle path
 * @returns Finding anchored at the first cycle file, or undefined when no indexed script source matches that anchor.
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

/**
 * Locates the first non-type-only import line in the anchor file targeting another member of the cycle, keeping the anchor defined.
 *
 * @param index - project index mapping files to extracted import edges
 * @param anchorPath - display path of the anchor file whose edges are searched
 * @param cycle - cycle record listing member file paths
 * @returns Line number of the first matching runtime import edge, or 1 when no qualifying edge exists.
 */
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

/**
 * Reads the large-module concentration limits from config so candidate selection requires both minima to be met and the share cap exceeded.
 * Missing settings default to 4 production files, 80 lines for the largest file, and a 55 percent share cap.
 *
 * @param config - rule configuration providing optional `minFiles`, `minLines`, and share threshold overrides
 * @returns Resolved thresholds for production file count, largest file line count, and share percentage cap.
 */
function largeModuleThresholds(config: Config): LargeModuleThresholds {
  return {
    minFiles: optionNumber(config, "design.large-module-concentration", "minFiles", 4),
    minLines: optionNumber(config, "design.large-module-concentration", "minLines", 80),
    maxSharePercent: threshold(config, "design.large-module-concentration", 55),
  };
}

/**
 * Selects the largest production module when the project meets the file-count minimum and the module exceeds the size and dominance limits.
 *
 * @param index - project index supplying script sources and production line counts
 * @param thresholds - resolved file-count, line-count, and share-percentage limits
 * @returns Largest production module with total lines, share percentage, and thresholds, or undefined when ineligible.
 */
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

/**
 * Evaluates whether the largest module meets the inclusive line minimum and exceeds the share cap so tiny dominant modules remain ineligible.
 *
 * @param largest - candidate module entry containing its production line count
 * @param sharePercent - candidate module's rounded percentage of total production lines
 * @param thresholds - resolved line minimum and maximum share percentage limits
 * @returns True only when `largest.lines` meets `minLines` and `sharePercent` exceeds `maxSharePercent`.
 */
function exceedsLargeModuleThresholds(largest: ModuleLineCount, sharePercent: number, thresholds: LargeModuleThresholds): boolean {
  return largest.lines >= thresholds.minLines && sharePercent > thresholds.maxSharePercent;
}

/**
 * Collects production script line counts, excluding tests, fixtures, declarations, and generated paths, for deterministic largest-source selection.
 *
 * @param index - project index supplying script sources and cached code line counts
 * @returns Module line-count entries sorted by descending line count then ascending display path.
 */
function productionModuleLineCounts(index: ProjectIndex): ModuleLineCount[] {
  return index.scriptSources
    .filter((source) => isProductionSourcePath(source.file.displayPath))
    .map((source) => ({ source, lines: source.codeLineCount }))
    .sort((left, right) => right.lines - left.lines || left.source.file.displayPath.localeCompare(right.source.file.displayPath));
}

/**
 * Builds a stable design finding with measured counts and all configured thresholds so reviewers can explain the result without rerunning.
 *
 * @param candidate - qualifying largest production module and its share metrics
 * @param severity - configured severity level for the emitted finding
 * @returns Design finding anchored at line 1 of the concentrated module.
 */
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

/**
 * Extracts relative import edges from pre-extracted import statements for deterministic traversal, keeping unresolved edges so parent-hop checks can use them.
 *
 * @param source - project source snapshot providing display path and pre-extracted import statements
 * @param sourcePaths - set of discovered script display paths used to resolve relative targets
 * @returns Relative import edges ordered by starting line then specifier, resolving targets only within `sourcePaths`.
 */
function importEdgesForSource(source: ProjectSource, sourcePaths: Set<string>): ImportEdge[] {
  const edges: ImportEdge[] = [];
  for (const statement of source.importStatements) {
    edges.push(...importEdgesForStatement(source.file.displayPath, statement, sourcePaths));
  }
  return edges.sort((left, right) => left.line - right.line || left.specifier.localeCompare(right.specifier));
}

/**
 * Reassembles multi-line import/export spans from template-masked lines for graph extraction, skipping non-declaration lines and incomplete tails.
 *
 * @param lines - template-masked lines of a source file in line order
 * @returns Complete import/export statement spans paired with their 1-based starting line numbers.
 */
export function extractImportStatements(lines: string[]): ImportStatement[] {
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

/**
 * Checks whether an accumulated import/export span has reached a quoted module specifier, covering bare side-effect imports and `from` clauses.
 *
 * @param statement - accumulated source text for a candidate import or export statement
 * @returns True once `statement` contains a quoted specifier, otherwise false.
 */
function isImportStatementComplete(statement: string): boolean {
  return /\b(?:from\s*)?["'][^"']+["']/.test(statement);
}

/**
 * Extracts relative import and re-export edges anchored at the statement's starting line, omitting non-relative specifiers.
 *
 * @param importerPath - display path of the importing file used as the resolution base
 * @param statement - complete import/export statement text and starting line
 * @param sourcePaths - set of discovered script display paths used as target candidates
 * @returns Relative import edges found in `statement`, leaving `targetPath` unset when unresolved.
 */
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

/**
 * Builds an import-rule edge for a relative specifier while retaining its source line anchor and type-only classification.
 *
 * @param importerPath - display path of the importing file used as the resolution base
 * @param specifier - module specifier text, including any relative parent hops
 * @param line - 1-based starting line of the enclosing import or export statement
 * @param sourcePaths - discovered script display paths eligible as resolution targets
 * @param isTypeOnly - whether the statement uses an `import type` or `export type` prefix
 * @returns Edge object (without `targetPath` when unresolved), or undefined for non-relative specifiers.
 */
function importEdgeForSpecifier(importerPath: string, specifier: string, line: number, sourcePaths: Set<string>, isTypeOnly: boolean): ImportEdge | undefined {
  if (!specifier.startsWith(".")) {
    return undefined;
  }
  const targetPath = resolveRelativeImport(importerPath, specifier, sourcePaths);
  return {
    specifier,
    line,
    isTypeOnly,
    ...(targetPath ? { targetPath } : {}),
  };
}

/**
 * Detects an `import type` or `export type` prefix so cycle checks can exclude type-only edges; inline type specifiers are not matched.
 *
 * @param importStatement - matched import or export clause text up to its module specifier
 * @returns True when `importStatement` starts a type-only import or export, otherwise false.
 */
function isTypeOnlyImportStatement(importStatement: string): boolean {
  return /\b(?:import|export)\s+type\b/.test(importStatement);
}

/**
 * Resolves a relative specifier from the importing file's directory in a stable candidate order so cycle output stays reproducible.
 *
 * @param importerPath - display path of the importing file providing the base directory
 * @param specifier - relative module specifier to resolve
 * @param sourcePaths - set of discovered script paths defining available targets
 * @returns First candidate path present in `sourcePaths`, or undefined if none match.
 */
function resolveRelativeImport(importerPath: string, specifier: string, sourcePaths: Set<string>): string | undefined {
  const basePath = normalizeDisplayPath(join(dirnamePath(importerPath), specifier));
  for (const candidate of importPathCandidates(basePath)) {
    if (sourcePaths.has(candidate)) {
      return candidate;
    }
  }
  return undefined;
}

/**
 * Expands `basePath` into deduplicated resolution candidates: explicit extensions try the original path and script substitutions,
 * while extensionless paths try script extensions and directory index files before normalization.
 *
 * @param basePath - joined and normalized relative target path before extension resolution
 * @returns Ordered list of normalized candidate display paths without duplicates.
 */
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

/**
 * Derives deterministic cycle records from the import graph so circular-import reporting emits one finding per multi-file component.
 *
 * @param index - project index supplying script sources and resolved import edges
 * @returns Sorted cycle records with sorted member files and a representative closed path, or an empty list when none qualify.
 */
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

/**
 * Computes sorted multi-file strongly connected components from the import graph, excluding type-only edges and singletons, for stable findings.
 *
 * @param index - project index supplying files and resolved import edges
 * @returns Sorted arrays of member file paths for components with two or more files, or an empty list when none exist.
 */
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

/**
 * Runs Tarjan's DFS from `path`, mutating `state` to track discovery order and low-links while keeping non-root vertices on the stack until popped.
 *
 * @param index - project index supplying outgoing runtime import targets
 * @param path - display path of the current vertex being visited
 * @param state - mutable Tarjan traversal state recording indices, low-links, active stack, and completed components
 * @returns Nothing. Mutates `state` in place and pushes completed strongly connected components onto `state.components`.
 */
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

/**
 * Reads `path`'s Tarjan discovery index from traversal state, defaulting absent entries to zero.
 *
 * @param state - mutable Tarjan traversal state holding discovery indices
 * @param path - display path of the vertex to look up
 * @returns Discovery index recorded for `path`, or 0 when absent.
 */
function indexFor(state: StronglyConnectedState, path: string): number {
  return state.indices.get(path) ?? 0;
}

/**
 * Reads `path`'s Tarjan low-link value from traversal state for component-root comparisons.
 *
 * @param state - mutable Tarjan traversal state holding low-link values
 * @param path - display path of the vertex to look up
 * @returns Low-link value recorded for `path`, or 0 when no value is recorded.
 */
function lowLinkFor(state: StronglyConnectedState, path: string): number {
  return state.lowLinks.get(path) ?? 0;
}

/**
 * Collects sorted, unique resolved value-import targets for a file under the stable runtime-cycle contract.
 *
 * @param index - project index mapping file paths to extracted import edges
 * @param path - display path of the importing file
 * @returns Sorted unique target paths for non-type-only resolved imports, or an empty list when none exist.
 */
function circularImportTargets(index: ProjectIndex, path: string): string[] {
  return [...new Set((index.importsByFile.get(path) ?? []).filter((edge) => !edge.isTypeOnly).map((edge) => edge.targetPath).filter(isString))].sort();
}

/**
 * Chooses a closed path through the component starting from the first member for a grouped cycle finding.
 *
 * @param index - project index supplying runtime import edges
 * @param files - sorted member paths belonging to the strongly connected component
 * @returns Closed path starting and ending at `files[0]`, an empty list if `files` is empty, or `files` unchanged if no closing path is found.
 */
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

/**
 * Finds a shortest directed runtime-import path between two component members while restricting traversal to `members` for a representative cycle.
 *
 * @param index - project index supplying runtime import targets
 * @param start - starting member path for the breadth-first search
 * @param end - target member path to reach
 * @param members - set of component file paths allowed during traversal
 * @returns Path including both `start` and `end`, or undefined when no directed path reaches `end`.
 */
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

/**
 * Determines whether a path qualifies for production-only rules by excluding tests, declarations, fixtures, and slash-delimited `generated` segments.
 *
 * @param path - normalized display path to classify
 * @returns True when `path` counts as production source code, otherwise false.
 */
export function isProductionSourcePath(path: string): boolean {
  return !isTestPath(path) && !isDeclarationPath(path) && !isFixtureLikePath(path) && !path.split("/").includes("generated");
}

/**
 * Classifies test paths because the production-source filter relies on this check to decide which files count as production code.
 *
 * @param path - normalized display path to inspect
 * @returns True for paths under `__tests__`, `test`, `tests`, or `spec`, or filenames with `.test` or `.spec` before a JS/TS extension.
 */
export function isTestPath(path: string): boolean {
  return /(?:^|\/)(?:__tests__|tests?|spec)\//.test(path) || /\.(?:test|spec)\.[cm]?[tj]sx?$/.test(path);
}

/**
 * Identifies TypeScript declaration files so rule filters can exclude them from production source metrics.
 *
 * @param path - display path to inspect
 * @returns True when `path` ends with `.d.ts`, `.d.cts`, or `.d.mts`.
 */
export function isDeclarationPath(path: string): boolean {
  return /\.d\.[cm]?ts$/.test(path);
}

/**
 * Identifies fixture-like directories because the production-source filter excludes them and `docs.fixture-purpose-missing` checks them.
 *
 * @param path - normalized display path to inspect
 * @returns True for slash-separated paths under `__fixtures__`, `fixture`, `fixtures`, or `testdata`.
 */
export function isFixtureLikePath(path: string): boolean {
  return /(?:^|\/)(?:__fixtures__|fixtures?|testdata)\//.test(path);
}

/**
 * Converts platform-native paths to the POSIX-style report shape used in every `Finding`; must be idempotent across repeated calls.
 *
 * @param path - raw file or relative path string to normalize
 * @returns Forward-slash path with any leading `./` prefix stripped.
 */
function normalizeDisplayPath(path: string): string {
  return path.replaceAll("\\", "/").replace(/^\.\//, "");
}
