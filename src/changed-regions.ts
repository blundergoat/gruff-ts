// Diff-aware changed-region filtering for analyse runs. The public JSON finding shape stays intact:
// this module only decides which already-produced findings are attributable to the requested change.
import { execFileSync } from "node:child_process";
import { functionBlocks } from "./blocks.ts";
import type { SourceFile } from "./discovery.ts";
import type { ParsedScript } from "./parsed-script.ts";
import { maskNonCode } from "./source-text.ts";
import type { AnalysisOptions, ChangedScopeMode, Finding, RunDiagnostic } from "./types.ts";

/**
 * Raised when the requested changed region cannot be read, so the caller reports which input was wrong.
 *
 * The hook publishes it as a fatal diagnostic naming `changed-region`, which is what tells an agent the run never
 * happened rather than that the file was clean. `analyse` reports it under the same type.
 */
export class ChangedRegionError extends Error {}

// The diagnostic type both the hook and `analyse` give a ChangedRegionError.
export const CHANGED_REGION_DIAGNOSTIC_TYPE = "changed-region";

// Inclusive line range from a changed hunk or explicit `--changed-ranges` input.
export interface ChangedRange {
  start: number;
  end: number;
}

// Complete changed-region filter state used after the full report is generated.
export interface ChangedRegionScope {
  mode: ChangedScopeMode;
  rangesByFile: Map<string, ChangedRange[]>;
  wholeFiles: Set<string>;
  // Every file that appears in the diff, including deletion-only files that contribute no target-side
  // ranges. `file` scope keeps all findings in any changed file, so it consults this set, not ranges.
  changedFiles: Set<string>;
  explicitRanges?: ChangedRange[];
}

// Source text paired with discovery metadata so findings can be expanded to symbols.
interface SourceSnapshot {
  file: SourceFile;
  source: string;
  parsed?: ParsedScript;
}

// Named source span used to keep symbol-scope findings when their declaration overlaps a hunk.
interface DeclarationRegion {
  name: string;
  start: number;
  end: number;
}

// Mutable state for the current file while walking a unified diff line by line.
interface DiffParseState {
  currentFile: string | undefined;
  isNewFile: boolean;
  targetLine: number | undefined;
}

const FILE_WIDE_RULE_IDS = new Set(["design.large-module-concentration", "docs.missing-file-overview", "size.file-length"]);

// Project-relationship rules anchor one canonical file but relate every member in `metadata.files`,
// so changed-region attribution must consult the member list, not only the anchor `filePath`.
const PROJECT_RELATIONSHIP_RULE_IDS = new Set(["design.circular-import"]);

// Returns a scope in options.changedScope mode, giving explicit ranges priority because they name the exact lines to check.
// Supplied patch text wins over since and diff. An empty patch selects no files. With no selector, returns undefined for an unscoped scan.
// Otherwise reads Git changes using since before diff and propagates command failures.
// @throws {ChangedRegionError} - the range list is empty or malformed, or the selected diff requires stdin patch text that was not supplied.
export function changedRegionScope(options: AnalysisOptions): ChangedRegionScope | undefined {
  if (options.changedRanges !== undefined) {
    return { mode: options.changedScope, rangesByFile: new Map(), wholeFiles: new Set(), changedFiles: new Set(), explicitRanges: parseChangedRanges(options.changedRanges) };
  }
  if (options.diffPatch !== undefined) {
    return parseUnifiedDiff(options.diffPatch, options.changedScope);
  }
  if (options.since) {
    return gitDiffScope(options.since, options.changedScope);
  }
  if (options.diff) {
    if (options.diff === "-") {
      throw new ChangedRegionError("--diff - requires diffPatch input; the CLI reads stdin before analysis.");
    }
    return gitDiffScope(options.diff, options.changedScope);
  }
  return undefined;
}

// Diagnostic types that describe one analysed file's content or readability. Only these are
// file-scoped under diff filtering; operational diagnostics (missing paths, history errors) always
// stay, because they describe the request rather than an unchanged context file.
const FILE_CONTENT_DIAGNOSTIC_TYPES = new Set(["bounded-deep-scan", "parse-error", "read-error"]);

/*
 * Returns the input diagnostics unchanged for an unscoped run or a scope with explicit ranges.
 * Diff scopes keep file-content diagnostics from changed target files, including errors outside the changed lines.
 * Operational diagnostics and diagnostics without a file path always remain.
 */
export function filterScopedDiagnostics(diagnostics: RunDiagnostic[], scope: ChangedRegionScope | undefined): RunDiagnostic[] {
  if (!scope || scope.explicitRanges !== undefined) {
    return diagnostics;
  }
  return diagnostics.filter((diagnostic) => {
    // Operational diagnostics (missing-path, history-error) describe the request, not file content.
    if (!diagnostic.filePath || !FILE_CONTENT_DIAGNOSTIC_TYPES.has(diagnostic.diagnosticType)) {
      return true;
    }
    return scope.changedFiles.has(diagnostic.filePath) || scope.wholeFiles.has(diagnostic.filePath);
  });
}

// Filters findings against scope, using sources to resolve declarations for symbol scope.
// With a scope, returns the kept findings and suppressedCount. The invariant is that kept plus suppressed equals the input total.
// Without a scope, returns the original findings array in the result and leaves suppressedCount absent.
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

// Returns whether scope keeps the finding by relationship member, whole file, hunk overlap or enclosing declaration under the gate contract.
// Uses sources to look up scripts and fills declarationsByFile on cache misses to avoid rebuilding spans during symbol widening.
// Hunk checks use line 1 for an absent start and the start for an absent end. Empty ranges disable hunk and symbol matches.
function isFindingInChangedScope(
  finding: Finding,
  scope: ChangedRegionScope,
  sources: Map<string, SourceSnapshot>,
  declarationsByFile: Map<string, DeclarationRegion[]>,
): boolean {
  if (PROJECT_RELATIONSHIP_RULE_IDS.has(finding.ruleId)) {
    return projectRelationshipTouchesChange(finding, scope);
  }
  if (scope.wholeFiles.has(finding.filePath)) {
    return true;
  }
  // File scope runs before line checks so deletion-only edits still count. Explicit ranges make every selected file eligible.
  if (scope.mode === "file") {
    return scope.explicitRanges !== undefined || scope.changedFiles.has(finding.filePath);
  }
  const changedRanges = rangesForFindingFile(scope, finding.filePath);
  if (changedRanges.length === 0) {
    return false;
  }
  const findingRange = { start: finding.line ?? 1, end: finding.endLine ?? finding.line ?? 1 };
  if (overlapsAny(findingRange, changedRanges)) {
    return true;
  }
  return symbolScopeWidensFinding(finding, scope, sources, declarationsByFile, changedRanges);
}

// Returns true when symbol scope keeps a finding because its enclosing declaration overlaps the file's changedRanges.
// Uses sources for script lookup and fills declarationsByFile on cache misses while resolving the declaration.
// The invariant is that file-wide findings and findings without a resolvable declaration never widen.
function symbolScopeWidensFinding(
  finding: Finding,
  scope: ChangedRegionScope,
  sources: Map<string, SourceSnapshot>,
  declarationsByFile: Map<string, DeclarationRegion[]>,
  changedRanges: ChangedRange[],
): boolean {
  if (scope.mode !== "symbol" || isFileWideFinding(finding)) {
    return false;
  }
  const declaration = enclosingDeclaration(finding, sources, declarationsByFile);
  return declaration !== undefined && overlapsAny(declaration, changedRanges);
}

// Returns true when a FILE_WIDE_RULE_IDS finding has an explicit line 1 anchor. The symbol-scope invariant then prevents widening.
// An absent line leaves the finding eligible for ordinary symbol-scope checks.
function isFileWideFinding(finding: Finding): boolean {
  return FILE_WIDE_RULE_IDS.has(finding.ruleId) && finding.line === 1;
}

/**
 * Applies the project-relationship scope contract using the files that participate in the change.
 *
 * @param finding - relationship to check. Uses its path if no member array exists. An empty member array matches neither file set.
 * @param scope - selection whose whole-file and changed-file sets identify participating members
 * @returns True for explicit ranges because they apply to every selected file, or if a member is in either file set. Otherwise false.
 */
function projectRelationshipTouchesChange(finding: Finding, scope: ChangedRegionScope): boolean {
  if (scope.explicitRanges !== undefined) {
    return true;
  }
  const files = Array.isArray(finding.metadata.files) ? finding.metadata.files : [finding.filePath];
  return files.some((file) => typeof file === "string" && (scope.wholeFiles.has(file) || scope.changedFiles.has(file)));
}

// Scope contract: explicit ranges take precedence because they apply to every selected file.
// Otherwise returns the hunk ranges for filePath. An empty list leaves range-based finding checks with no target span to match.
function rangesForFindingFile(scope: ChangedRegionScope, filePath: string): ChangedRange[] {
  return scope.explicitRanges ?? scope.rangesByFile.get(filePath) ?? [];
}

// Returns the narrowest declaration around the finding's line, preferring matching symbols for a stable choice. An absent line means line 1.
// Uses sources to look up the script and fills declarationsByFile on a cache miss to avoid rebuilding declaration spans.
// Returns undefined when no script or enclosing declaration is available, leaving symbol scope without a span to widen through.
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
    declarations = declarationRegions(source.source, source.parsed);
    declarationsByFile.set(finding.filePath, declarations);
  }
  const line = finding.line ?? 1;
  const named = finding.symbol
    ? declarations.filter((region) => region.name === finding.symbol && line >= region.start && line <= region.end)
    : [];
  const candidates = named.length > 0 ? named : declarations.filter((region) => line >= region.start && line <= region.end);
  return candidates.sort((left, right) => (left.end - left.start) - (right.end - right.start))[0];
}

// Returns the function, class and interface spans in source for symbol scoping.
// The optional shared parse supplies syntax for function spans. Without it, those spans come from the text-based block scan.
function declarationRegions(source: string, parsed?: ParsedScript): DeclarationRegion[] {
  const codeSource = maskNonCode(source);
  return [
    ...functionBlocks(source, codeSource, parsed).map((block) => ({
      name: block.name,
      start: block.startLine,
      end: block.startLine + block.lineCount - 1,
    })),
    ...classLikeRegions(codeSource),
  ];
}

// Returns named class and interface line spans from masked source text, covering declarations outside the function-block scan.
function classLikeRegions(codeSource: string): DeclarationRegion[] {
  const lines = codeSource.split(/\r?\n/);
  const regions: DeclarationRegion[] = [];
  lines.forEach((line, index) => {
    const match = line.match(/^\s*(?:export\s+)?(?:default\s+)?(?:abstract\s+)?(?:class|interface)\s+([A-Za-z_$][A-Za-z0-9_$]*)\b/);
    if (!match?.[1]) {
      return;
    }
    regions.push({ name: match[1], start: index + 1, end: bracedRegionEnd(lines, index) });
  });
  return regions;
}

// Estimates a class or interface's one-based closing line by counting braces in lines from the zero-based declaration index, startIndex.
// If no closing brace balances the declaration, returns its starting line.
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

// Checks whether a finding or declaration span intersects any changed hunk.
function overlapsAny(range: ChangedRange, changedRanges: ChangedRange[]): boolean {
  return changedRanges.some((changedRange) => rangesOverlap(range, changedRange));
}

// Inclusive range overlap test for one-based source line numbers.
function rangesOverlap(left: ChangedRange, right: ChangedRange): boolean {
  return left.start <= right.end && right.start <= left.end;
}

// Returns sorted, merged ranges from the comma-separated CLI text, skipping blank entries.
// @throws {ChangedRegionError} - no ranges remain or a nonblank entry is outside the valid N or N-M syntax or bounds.
function parseChangedRanges(rawRanges: string): ChangedRange[] {
  const ranges = rawRanges
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean)
    .map(parseChangedRange);
  if (ranges.length === 0) {
    throw new ChangedRegionError("--changed-ranges must include at least one range such as 3-3 or 8-10");
  }
  return mergeRanges(ranges);
}

// Returns inclusive line bounds for one --changed-ranges entry. A single number supplies both bounds.
// @throws {ChangedRegionError} - when the entry is not N or N-M digits, starts below 1, or ends before it starts.
function parseChangedRange(rawRange: string): ChangedRange {
  const match = rawRange.match(/^(\d+)(?:-(\d+))?$/);
  if (!match?.[1]) {
    throw new ChangedRegionError(`invalid --changed-ranges entry: ${rawRange}`);
  }
  const start = Number(match[1]);
  const end = Number(match[2] ?? match[1]);
  if (start < 1 || end < start) {
    throw new ChangedRegionError(`invalid --changed-ranges entry: ${rawRange}`);
  }
  return { start, end };
}

/*
 * Returns a scope using changedScope for finding attribution. The mode selects staged, unstaged, working-tree or Git-ref changes.
 * Reads Git changes with paths relative to the scan directory so nested scans can match findings.
 * Working-tree mode combines staged, unstaged and non-ignored untracked changes. Failed Git commands propagate their errors.
 */
function gitDiffScope(mode: string, changedScope: ChangedScopeMode): ChangedRegionScope {
  if (mode === "staged") {
    return parseUnifiedDiff(gitOutput(["diff", "--cached", "--unified=0", "--no-color", "--no-ext-diff", "--relative"]), changedScope);
  }
  if (mode === "unstaged") {
    return parseUnifiedDiff(gitOutput(["diff", "--unified=0", "--no-color", "--no-ext-diff", "--relative"]), changedScope);
  }
  if (mode === "working-tree") {
    return mergeScopes(
      [
        parseUnifiedDiff(gitOutput(["diff", "--cached", "--unified=0", "--no-color", "--no-ext-diff", "--relative"]), changedScope),
        parseUnifiedDiff(gitOutput(["diff", "--unified=0", "--no-color", "--no-ext-diff", "--relative"]), changedScope),
        untrackedFileScope(changedScope),
      ],
      changedScope,
    );
  }
  return parseUnifiedDiff(gitOutput(["diff", "--unified=0", "--no-color", "--no-ext-diff", "--relative", "--end-of-options", mode]), changedScope);
}

// Returns changed target files and addition ranges from the diffText patch, carrying changedScope forward for later filtering.
// A new file with a target header gets whole-file coverage. A surviving file with only deletions can be changed without any target ranges.
// An empty patch returns a scope with no changed files.
function parseUnifiedDiff(diffText: string, changedScope: ChangedScopeMode): ChangedRegionScope {
  const scope: ChangedRegionScope = { mode: changedScope, rangesByFile: new Map(), wholeFiles: new Set(), changedFiles: new Set() };
  const state: DiffParseState = { currentFile: undefined, isNewFile: false, targetLine: undefined };
  for (const line of diffText.split(/\r?\n/)) {
    applyDiffLine(scope, state, line);
  }
  return scope;
}

// Reads one unified-diff line, updating state for the current target file and hunk.
// Returns nothing. Records changed files and additions in scope, clearing state at each file header to avoid carrying over the previous file.
function applyDiffLine(scope: ChangedRegionScope, state: DiffParseState, line: string): void {
  if (line.startsWith("diff --git ")) {
    state.currentFile = undefined;
    state.isNewFile = false;
    state.targetLine = undefined;
    return;
  }
  if (line.startsWith("new file mode ") || line === "--- /dev/null") {
    state.isNewFile = true;
    return;
  }
  if (applyTargetFileLine(scope, state, line)) {
    return;
  }
  if (applyHunkHeader(scope, state, line)) {
    return;
  }
  applyHunkBodyLine(scope, state, line);
}

// Returns true if line is a target-file header. Sets state's current file and clears its hunk cursor.
// A deleted target leaves no current file. Other targets enter scope's changed-file set, with whole-file coverage for new files.
function applyTargetFileLine(scope: ChangedRegionScope, state: DiffParseState, line: string): boolean {
  if (line.startsWith("+++ ")) {
    const path = diffPath(line.slice(4));
    state.currentFile = path === "/dev/null" ? undefined : path;
    state.targetLine = undefined;
    if (state.currentFile) {
      scope.changedFiles.add(state.currentFile);
      if (state.isNewFile) {
        scope.wholeFiles.add(state.currentFile);
      }
    }
    return true;
  }
  return false;
}

// Returns true if line is a hunk header and updates state's target cursor for the hunk.
// A missing target file, whole-file coverage in scope or a zero-length target hunk clears the cursor and skips line tracking.
function applyHunkHeader(scope: ChangedRegionScope, state: DiffParseState, line: string): boolean {
  const hunk = line.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/);
  if (!hunk) {
    return false;
  }
  if (!hunk[1] || !state.currentFile || scope.wholeFiles.has(state.currentFile)) {
    state.targetLine = undefined;
    return true;
  }
  const start = Math.max(1, Number(hunk[1]));
  const length = hunk[2] === undefined ? 1 : Number(hunk[2]);
  state.targetLine = length === 0 ? undefined : start;
  return true;
}

// Reads one hunk body line using state's current file and target cursor. Additions update scope's ranges and advance the cursor.
// Context lines only advance the cursor. Skip the line when no target file or cursor is active or the whole file is already covered.
// Returns nothing. Line tracking is skipped for whole-file coverage because the scope already includes every line.
function applyHunkBodyLine(scope: ChangedRegionScope, state: DiffParseState, line: string): void {
  if (!state.currentFile || state.targetLine === undefined || scope.wholeFiles.has(state.currentFile)) {
    return;
  }
  if (line.startsWith("+")) {
    addRange(scope.rangesByFile, state.currentFile, { start: state.targetLine, end: state.targetLine });
    state.targetLine += 1;
    return;
  }
  if (line.startsWith(" ")) {
    state.targetLine += 1;
  }
}

// Returns the normalized target-header path for finding lookup, preserving /dev/null as the marker for a deleted target.
function diffPath(rawPath: string): string {
  const trimmed = rawPath.trim();
  if (trimmed === "/dev/null") {
    return trimmed;
  }
  return trimmed.replace(/^"?(?:a|b)\//, "").replace(/"$/, "").replaceAll("\\", "/");
}

// Spawns Git to list untracked paths after applying its ignore rules. They get whole-file coverage because they have no hunks.
// Returns a scope in changedScope mode. An empty listing selects no paths, and Git command failures propagate.
function untrackedFileScope(changedScope: ChangedScopeMode): ChangedRegionScope {
  const untracked = new Set(gitOutput(["ls-files", "--others", "--exclude-standard"]).split(/\r?\n/).filter(Boolean).map((path) => path.replaceAll("\\", "/")));
  return { mode: changedScope, rangesByFile: new Map(), wholeFiles: untracked, changedFiles: new Set(untracked) };
}

// Returns a new scope in changedScope mode by combining the staged, unstaged and untracked input scopes.
// Whole-file coverage takes precedence over hunk ranges for the same file.
function mergeScopes(scopes: ChangedRegionScope[], changedScope: ChangedScopeMode): ChangedRegionScope {
  const merged: ChangedRegionScope = { mode: changedScope, rangesByFile: new Map(), wholeFiles: new Set(), changedFiles: new Set() };
  for (const scope of scopes) {
    for (const file of scope.changedFiles) {
      merged.changedFiles.add(file);
    }
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

// Returns nothing. Adds range to the rangesByFile entry for filePath, creating it if absent and merging overlaps or adjacent ranges.
function addRange(rangesByFile: Map<string, ChangedRange[]>, filePath: string, range: ChangedRange): void {
  rangesByFile.set(filePath, mergeRanges([...(rangesByFile.get(filePath) ?? []), range]));
}

// Returns a new sorted list of line ranges, merging overlaps and adjacency so downstream checks stay deterministic.
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

// Spawns git with the caller's argument array and returns UTF-8 stdout, which can be empty when git has no changes to report.
// Git execution errors propagate to the scope loader.
function gitOutput(args: string[]): string {
  return execFileSync("git", args, { encoding: "utf8" });
}
