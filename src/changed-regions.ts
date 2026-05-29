// Diff-aware changed-region filtering for analyse runs. The public JSON finding shape stays intact:
// this module only decides which already-produced findings are attributable to the requested change.
import { execFileSync } from "node:child_process";
import { functionBlocks } from "./blocks.ts";
import type { SourceFile } from "./discovery.ts";
import { maskNonCode } from "./source-text.ts";
import type { AnalysisOptions, ChangedScopeMode, Finding } from "./types.ts";

export interface ChangedRange {
  start: number;
  end: number;
}

export interface ChangedRegionScope {
  mode: ChangedScopeMode;
  rangesByFile: Map<string, ChangedRange[]>;
  wholeFiles: Set<string>;
  explicitRanges?: ChangedRange[];
}

interface SourceSnapshot {
  file: SourceFile;
  source: string;
}

interface DeclarationRegion {
  name: string;
  start: number;
  end: number;
}

interface DiffParseState {
  currentFile: string | undefined;
  isNewFile: boolean;
}

export function changedRegionScope(options: AnalysisOptions): ChangedRegionScope | undefined {
  if (options.changedRanges) {
    return { mode: options.changedScope, rangesByFile: new Map(), wholeFiles: new Set(), explicitRanges: parseChangedRanges(options.changedRanges) };
  }
  if (options.diffPatch !== undefined) {
    return parseUnifiedDiff(options.diffPatch, options.changedScope);
  }
  if (options.since) {
    return gitDiffScope(options.since, options.changedScope);
  }
  if (options.diff) {
    return options.diff === "-" ? parseUnifiedDiff("", options.changedScope) : gitDiffScope(options.diff, options.changedScope);
  }
  return undefined;
}

export function filterChangedSources(files: SourceFile[], scope: ChangedRegionScope | undefined): SourceFile[] {
  if (!scope || scope.explicitRanges) {
    return files;
  }
  return files.filter((file) => scope.wholeFiles.has(file.displayPath) || scope.rangesByFile.has(file.displayPath));
}

export function filterChangedFindings(
  findings: Finding[],
  scope: ChangedRegionScope | undefined,
  sources: Map<string, SourceSnapshot>,
): { findings: Finding[]; suppressedCount?: number } {
  if (!scope) {
    return { findings };
  }
  const declarationsByFile = new Map<string, DeclarationRegion[]>();
  const kept: Finding[] = [];
  let suppressedCount = 0;
  for (const finding of findings) {
    if (isFindingInChangedScope(finding, scope, sources, declarationsByFile)) {
      kept.push(finding);
    } else {
      suppressedCount += 1;
    }
  }
  return { findings: kept, suppressedCount };
}

function isFindingInChangedScope(
  finding: Finding,
  scope: ChangedRegionScope,
  sources: Map<string, SourceSnapshot>,
  declarationsByFile: Map<string, DeclarationRegion[]>,
): boolean {
  if (scope.wholeFiles.has(finding.filePath)) {
    return true;
  }
  const changedRanges = rangesForFindingFile(scope, finding.filePath);
  if (changedRanges.length === 0) {
    return false;
  }
  const findingRange = { start: finding.line ?? 1, end: finding.endLine ?? finding.line ?? 1 };
  if (overlapsAny(findingRange, changedRanges)) {
    return true;
  }
  if (scope.mode === "hunk") {
    return false;
  }
  const declaration = enclosingDeclaration(finding, sources, declarationsByFile);
  return declaration !== undefined && overlapsAny(declaration, changedRanges);
}

function rangesForFindingFile(scope: ChangedRegionScope, filePath: string): ChangedRange[] {
  return scope.explicitRanges ?? scope.rangesByFile.get(filePath) ?? [];
}

function enclosingDeclaration(
  finding: Finding,
  sources: Map<string, SourceSnapshot>,
  declarationsByFile: Map<string, DeclarationRegion[]>,
): DeclarationRegion | undefined {
  const source = sources.get(finding.filePath);
  if (!source?.file.isScript) {
    return undefined;
  }
  let declarations = declarationsByFile.get(finding.filePath);
  if (!declarations) {
    declarations = declarationRegions(source.source);
    declarationsByFile.set(finding.filePath, declarations);
  }
  const line = finding.line ?? 1;
  const named = finding.symbol
    ? declarations.filter((region) => region.name === finding.symbol && line >= region.start && line <= region.end)
    : [];
  const candidates = named.length > 0 ? named : declarations.filter((region) => line >= region.start && line <= region.end);
  return candidates.sort((left, right) => (left.end - left.start) - (right.end - right.start))[0];
}

function declarationRegions(source: string): DeclarationRegion[] {
  const codeSource = maskNonCode(source);
  return [
    ...functionBlocks(source, codeSource).map((block) => ({
      name: block.name,
      start: block.startLine,
      end: block.startLine + block.lineCount - 1,
    })),
    ...classLikeRegions(codeSource),
  ];
}

function classLikeRegions(codeSource: string): DeclarationRegion[] {
  const lines = codeSource.split(/\r?\n/);
  const regions: DeclarationRegion[] = [];
  lines.forEach((line, index) => {
    const match = line.match(/^\s*(?:export\s+)?(?:abstract\s+)?(?:class|interface)\s+([A-Za-z_$][A-Za-z0-9_$]*)\b/);
    if (!match?.[1]) {
      return;
    }
    regions.push({ name: match[1], start: index + 1, end: bracedRegionEnd(lines, index) });
  });
  return regions;
}

function bracedRegionEnd(lines: string[], startIndex: number): number {
  let depth = 0;
  let hasSeenOpen = false;
  for (let index = startIndex; index < lines.length; index += 1) {
    for (const character of lines[index] ?? "") {
      if (character === "{") {
        depth += 1;
        hasSeenOpen = true;
      } else if (character === "}") {
        depth -= 1;
      }
    }
    if (hasSeenOpen && depth <= 0) {
      return index + 1;
    }
  }
  return startIndex + 1;
}

function overlapsAny(range: ChangedRange, changedRanges: ChangedRange[]): boolean {
  return changedRanges.some((changedRange) => rangesOverlap(range, changedRange));
}

function rangesOverlap(left: ChangedRange, right: ChangedRange): boolean {
  return left.start <= right.end && right.start <= left.end;
}

function parseChangedRanges(rawRanges: string): ChangedRange[] {
  const ranges = rawRanges
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean)
    .map(parseChangedRange);
  if (ranges.length === 0) {
    throw new Error("--changed-ranges must include at least one range such as 3-3 or 8-10");
  }
  return mergeRanges(ranges);
}

function parseChangedRange(rawRange: string): ChangedRange {
  const match = rawRange.match(/^(\d+)(?:-(\d+))?$/);
  if (!match?.[1]) {
    throw new Error(`invalid --changed-ranges entry: ${rawRange}`);
  }
  const start = Number(match[1]);
  const end = Number(match[2] ?? match[1]);
  if (start < 1 || end < start) {
    throw new Error(`invalid --changed-ranges entry: ${rawRange}`);
  }
  return { start, end };
}

function gitDiffScope(mode: string, changedScope: ChangedScopeMode): ChangedRegionScope {
  if (mode === "staged") {
    return parseUnifiedDiff(gitOutput(["diff", "--cached", "--unified=0", "--no-color", "--no-ext-diff"]), changedScope);
  }
  if (mode === "unstaged") {
    return parseUnifiedDiff(gitOutput(["diff", "--unified=0", "--no-color", "--no-ext-diff"]), changedScope);
  }
  if (mode === "working-tree") {
    return mergeScopes(
      [
        parseUnifiedDiff(gitOutput(["diff", "--cached", "--unified=0", "--no-color", "--no-ext-diff"]), changedScope),
        parseUnifiedDiff(gitOutput(["diff", "--unified=0", "--no-color", "--no-ext-diff"]), changedScope),
        untrackedFileScope(changedScope),
      ],
      changedScope,
    );
  }
  return mergeScopes([parseUnifiedDiff(gitOutput(["diff", "--unified=0", "--no-color", "--no-ext-diff", mode]), changedScope), untrackedFileScope(changedScope)], changedScope);
}

function parseUnifiedDiff(diffText: string, changedScope: ChangedScopeMode): ChangedRegionScope {
  const scope: ChangedRegionScope = { mode: changedScope, rangesByFile: new Map(), wholeFiles: new Set() };
  const state: DiffParseState = { currentFile: undefined, isNewFile: false };
  for (const line of diffText.split(/\r?\n/)) {
    applyDiffLine(scope, state, line);
  }
  return scope;
}

function applyDiffLine(scope: ChangedRegionScope, state: DiffParseState, line: string): void {
  if (line.startsWith("diff --git ")) {
    state.currentFile = undefined;
    state.isNewFile = false;
    return;
  }
  if (line.startsWith("new file mode ") || line === "--- /dev/null") {
    state.isNewFile = true;
    return;
  }
  if (line.startsWith("+++ ")) {
    const path = diffPath(line.slice(4));
    state.currentFile = path === "/dev/null" ? undefined : path;
    if (state.currentFile && state.isNewFile) {
      scope.wholeFiles.add(state.currentFile);
    }
    return;
  }
  const hunk = line.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/);
  if (!hunk?.[1] || !state.currentFile || scope.wholeFiles.has(state.currentFile)) {
    return;
  }
  const start = Math.max(1, Number(hunk[1]));
  const length = hunk[2] === undefined ? 1 : Number(hunk[2]);
  const end = length === 0 ? start : start + length - 1;
  addRange(scope.rangesByFile, state.currentFile, { start, end });
}

function diffPath(rawPath: string): string {
  const trimmed = rawPath.trim();
  if (trimmed === "/dev/null") {
    return trimmed;
  }
  return trimmed.replace(/^"?(?:a|b)\//, "").replace(/"$/, "").replaceAll("\\", "/");
}

function untrackedFileScope(changedScope: ChangedScopeMode): ChangedRegionScope {
  return {
    mode: changedScope,
    rangesByFile: new Map(),
    wholeFiles: new Set(gitOutput(["ls-files", "--others", "--exclude-standard"]).split(/\r?\n/).filter(Boolean).map((path) => path.replaceAll("\\", "/"))),
  };
}

function mergeScopes(scopes: ChangedRegionScope[], changedScope: ChangedScopeMode): ChangedRegionScope {
  const merged: ChangedRegionScope = { mode: changedScope, rangesByFile: new Map(), wholeFiles: new Set() };
  for (const scope of scopes) {
    for (const file of scope.wholeFiles) {
      merged.wholeFiles.add(file);
      merged.rangesByFile.delete(file);
    }
    for (const [file, ranges] of scope.rangesByFile) {
      if (merged.wholeFiles.has(file)) {
        continue;
      }
      for (const range of ranges) {
        addRange(merged.rangesByFile, file, range);
      }
    }
  }
  return merged;
}

function addRange(rangesByFile: Map<string, ChangedRange[]>, filePath: string, range: ChangedRange): void {
  rangesByFile.set(filePath, mergeRanges([...(rangesByFile.get(filePath) ?? []), range]));
}

function mergeRanges(ranges: ChangedRange[]): ChangedRange[] {
  const sorted = [...ranges].sort((left, right) => left.start - right.start || left.end - right.end);
  const merged: ChangedRange[] = [];
  for (const range of sorted) {
    const previous = merged[merged.length - 1];
    if (!previous || range.start > previous.end + 1) {
      merged.push({ ...range });
      continue;
    }
    previous.end = Math.max(previous.end, range.end);
  }
  return merged;
}

function gitOutput(args: string[]): string {
  return execFileSync("git", args, { encoding: "utf8" });
}
