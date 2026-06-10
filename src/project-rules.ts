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

// Sorts sources by display path so every cross-file rule sees the same order regardless of which
// filesystem yielded what entries first - the stable input ordering is what keeps reports deterministic.
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

// Three architecture rules, evaluated in their stable contract order: deep imports, cycles, then
// large-module concentration. Reordering shuffles the deterministic fingerprint output.
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

/*
 * Reports imports that climb more than `maxParentSegments` `../` hops, anchored at the edge line
 * in the importing file. The double loop exists intentionally because `..` and `../foo` look
 * identical to a regex pass, so the parsed edge metadata is the only stable way to count depth
 * without false positives.
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

/*
 * Reports one finding per strongly connected component in the runtime import graph. The component
 * list comes back already deterministic from `importCycles`, so fingerprints are reproducible.
 */
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
 * match across reruns. Returns undefined when the anchor file dropped out of the index.
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

// Finds the first import edge in the anchor file that points into another cycle member. Line 1
// fallback keeps finding metadata stable when no edge could be located on the parsed source.
function circularImportLine(index: ProjectIndex, anchorPath: string, cycle: ImportCycle): number {
  const anchorEdges = index.importsByFile.get(anchorPath) ?? [];
  return anchorEdges.find((edge) => !edge.isTypeOnly && edge.targetPath && cycle.files.includes(edge.targetPath))?.line ?? 1;
}

/*
 * Reports the largest directory if it crosses the configured share-of-project threshold. Single
 * stable finding (the worst case) rather than one per directory - keeps the rule a noise-tolerant signal.
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
// line count so the caller can take the head without re-scanning - keeps the rule deterministic and stable.
function productionModuleLineCounts(index: ProjectIndex): ModuleLineCount[] {
  return index.scriptSources
    .filter((source) => isProductionSourcePath(source.file.displayPath))
    .map((source) => ({ source, lines: source.lines.length }))
    .sort((left, right) => right.lines - left.lines || left.source.file.displayPath.localeCompare(right.source.file.displayPath));
}

// Single makeFinding site for the rule. All threshold values are surfaced in metadata so reviewers
// can see why the rule fired without re-running with the same config - keeps reports stable for audits.
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

// Per-file regex pass over the cached source lines. The resulting edges are sorted by (line,
// specifier) so the import graph and cycle detection both see the same stable, deterministic order.
function importEdgesForSource(source: ProjectSource, sourcePaths: Set<string>): ImportEdge[] {
  const edges: ImportEdge[] = [];
  for (const statement of importStatements(source.templateMaskedLines)) {
    edges.push(...importEdgesForStatement(source.file.displayPath, statement, sourcePaths));
  }
  return edges.sort((left, right) => left.line - right.line || left.specifier.localeCompare(right.specifier));
}

// Reassembles multiline import/export declarations from template-masked lines. This keeps
// `import { a,\n b } from "x"` visible to the graph without parsing fixture template bodies.
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

// One statement may contain multiple imports (e.g., `import a;export b from 'x'`); the regex
// captures every `from "specifier"` form. Non-relative specifiers are dropped because the rule
// only cares about intra-project edges.
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

// Builds an edge with `parentSegments` (counted from `..` hops) and an optional `targetPath` that
// points to a file gruff has actually discovered. Used by both the cycle detector and the deep-import rule.
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

// Type-only imports disappear at runtime, so they should not participate in circular-import cycles.
function isTypeOnlyImportStatement(importStatement: string): boolean {
  return /\b(?:import|export)\s+type\b/.test(importStatement);
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

// Tarjan SCC pass over the import graph. Components, members, and outgoing edges are sorted so
// one runtime import region yields one deterministic finding regardless of discovery order.
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

// Finds strongly connected import components with Tarjan's algorithm, then normalizes component
// order so one runtime cycle produces stable report anchors and fingerprints.
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

// Visits one graph node and updates Tarjan indices, low-links, and the active stack in lockstep.
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

// Reads a Tarjan discovery index; missing entries fall back to zero only for malformed graph edges.
function indexFor(state: StronglyConnectedState, path: string): number {
  return state.indices.get(path) ?? 0;
}

// Reads a Tarjan low-link value; the fallback keeps partially indexed edges bounded.
function lowLinkFor(state: StronglyConnectedState, path: string): number {
  return state.lowLinks.get(path) ?? 0;
}

// Stable runtime-cycle contract: returns sorted value imports only; type-only edges never count.
function circularImportTargets(index: ProjectIndex, path: string): string[] {
  return [...new Set((index.importsByFile.get(path) ?? []).filter((edge) => !edge.isTypeOnly).map((edge) => edge.targetPath).filter(isString))].sort();
}

// Chooses one concrete closed path inside the SCC so the finding still shows a reviewable edge
// chain even though the primary output unit is the whole component.
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

// Breadth-first path search inside one SCC so the grouped finding can display a concrete cycle.
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

// Production = not a test, not a `.d.ts`, not a fixture, not under `generated/`. Conservative on
// purpose - adding a path category here changes the rule surface of every production-only rule.
export function isProductionSourcePath(path: string): boolean {
  return !isTestPath(path) && !isDeclarationPath(path) && !isFixtureLikePath(path) && !path.split("/").includes("generated");
}

// `__tests__/` and `tests/` directories, plus `.test.ts` / `.spec.ts` filename suffix. The same
// patterns drive the production-source filter, so adding a layout here widens every test-aware rule.
export function isTestPath(path: string): boolean {
  return /(?:^|\/)(?:__tests__|tests?|spec)\//.test(path) || /\.(?:test|spec)\.[cm]?[tj]sx?$/.test(path);
}

// `.d.ts` family. Declaration files don't carry runtime behaviour, so most rules skip them.
export function isDeclarationPath(path: string): boolean {
  return /\.d\.[cm]?ts$/.test(path);
}

// Conventional fixture directories. Only `docs.fixture-purpose-missing` opts in to fixture paths;
// every other rule should treat them as test infrastructure.
export function isFixtureLikePath(path: string): boolean {
  return /(?:^|\/)(?:__fixtures__|fixtures?|testdata)\//.test(path);
}

// Converts platform-native paths to the POSIX-style report shape used in every Finding. Must be
// idempotent - repeated normalisation must produce the same string.
function normalizeDisplayPath(path: string): string {
  return path.replaceAll("\\", "/").replace(/^\.\//, "");
}
