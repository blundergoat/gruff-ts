// Selects the findings that belong to a user's Git changes, patch, or explicit line ranges.
//
// Use `analyse --diff staged` to review the next commit, or `--changed-ranges` for specific lines.
// A full scan supplies context for findings that span functions, files, or imports.
import { execFileSync } from "node:child_process";
import { cwd } from "node:process";
import { functionBlocks } from "./blocks.ts";
import type { SourceFile } from "./discovery.ts";
import type { ParsedScript } from "./parsed-script.ts";
import { maskNonCode } from "./source-text.ts";
import type { AnalysisOptions, ChangedScopeMode, Finding, RunDiagnostic } from "./types.ts";

/**
 * Signals that Gruff could not read the lines the user asked to review.
 *
 * For example, a mistyped revision makes `analyse --since` fail with a `changed-region` diagnostic.
 * Hooks can show the same diagnostic when an edit could not be reviewed.
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

/**
 * Resolves the changed lines requested for `analyse` or a hook.
 * Explicit ranges take priority, then supplied patch text, then `--since` or `--diff`.
 *
 * @param options - Analysis options carrying changed-range, patch, `--since`, `--diff`, and scope selectors.
 * @param projectRoot - Working directory used when running Git comparisons; defaults to the current working directory.
 * @returns Scope describing the requested changes, or undefined when the user asks for a full scan.
 * @throws {ChangedRegionError} When a range, patch input, or Git comparison cannot be read.
 */
export function changedRegionScope(options: AnalysisOptions, projectRoot = cwd()): ChangedRegionScope | undefined {
  // Editor integrations can specify the exact line ranges the user edited.
  if (options.changedRanges !== undefined) {
    return { mode: options.changedScope, rangesByFile: new Map(), wholeFiles: new Set(), changedFiles: new Set(), explicitRanges: parseChangedRanges(options.changedRanges) };
  }
  // An empty supplied patch means nothing changed and still takes priority over Git selectors.
  if (options.diffPatch !== undefined) {
    return parseUnifiedDiff(options.diffPatch, options.changedScope);
  }
  // A commit range lets a user see findings introduced since a known revision; `--since` always names a Git ref, never a diff mode keyword.
  if (options.since) {
    return gitDiffScope(options.since, options.changedScope, projectRoot, false);
  }
  // A named diff compares the requested part of the checkout, unless `--diff-base` explicitly named a Git ref.
  if (options.diff) {
    // A lone dash expects patch text from stdin, supplied by the CLI before the scan.
    if (options.diff === "-") {
      throw new ChangedRegionError("--diff - requires diffPatch input; the CLI reads stdin before analysis.");
    }
    return gitDiffScope(options.diff, options.changedScope, projectRoot, options.isDiffExplicitRef !== true);
  }
  return undefined;
}

// Diagnostic types that describe one analysed file's content or readability. Only these are
// file-scoped under diff filtering; operational diagnostics (missing paths, history errors) always
// stay, because they describe the request rather than an unchanged context file.
const FILE_CONTENT_DIAGNOSTIC_TYPES = new Set(["bounded-deep-scan", "parse-error", "read-error"]);

/**
 * Filters run diagnostics to changed target files when a diff scope is active.
 * Operational diagnostics and diagnostics without a file path always remain.
 *
 * @param diagnostics - Run diagnostics emitted during analysis.
 * @param scope - Active changed-region scope, or undefined for an unscoped run.
 * @returns Input diagnostics unchanged for unscoped or explicit-range runs, or diff-filtered diagnostics keeping changed-file content errors.
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

/**
 * Filters findings against the active changed-region scope, using sources to resolve declarations for symbol scope.
 * The invariant is that kept plus suppressed equals the input total when a scope is provided.
 *
 * @param findings - Candidate findings from the full analysis pass.
 * @param scope - Active changed-region scope, or undefined when no filtering is requested.
 * @param sources - Snapshot lookup by file path used to resolve enclosing declarations in symbol scope.
 * @returns Kept findings with suppressedCount when scoped, or the original findings with suppressedCount absent when unscoped.
 */
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

/**
 * Determines whether scope keeps a finding by relationship member, whole file, hunk overlap, or enclosing declaration under the gate contract.
 * Hunk checks use line 1 for an absent start and the start for an absent end; empty ranges disable hunk and symbol matches.
 *
 * @param finding - Finding to evaluate against the active scope.
 * @param scope - Active changed-region selection rules and file ranges.
 * @param sources - Snapshot lookup used to read script sources on declaration cache misses.
 * @param declarationsByFile - Mutates this per-file declaration cache on misses to avoid rebuilding spans during symbol widening.
 * @returns True when the finding belongs in the changed scope under the gate contract; otherwise false.
 */
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

/**
 * Checks whether symbol scope widens to keep a finding because its enclosing declaration overlaps changedRanges.
 * The invariant is that file-wide findings and findings without a resolvable declaration never widen.
 *
 * @param finding - Finding outside direct hunk ranges to test for declaration-level widening.
 * @param scope - Active changed-region scope whose mode must be `symbol` for widening to apply.
 * @param sources - Snapshot lookup used to load scripts when resolving declarations.
 * @param declarationsByFile - Mutates this per-file declaration cache on misses while resolving the enclosing declaration.
 * @param changedRanges - Changed line ranges for the finding's file.
 * @returns True when symbol scope keeps the finding because its enclosing declaration overlaps changedRanges; otherwise false.
 */
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

/**
 * Checks whether a finding is a file-wide rule anchored at explicit line 1 so the symbol-scope invariant prevents widening.
 * An absent line leaves the finding eligible for ordinary symbol-scope checks.
 *
 * @param finding - Finding whose rule ID and line anchor are checked.
 * @returns True when a `FILE_WIDE_RULE_IDS` finding has an explicit line 1 anchor; otherwise false.
 */
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

/**
 * Resolves the changed line ranges applicable to a finding's file under the scope contract.
 * Explicit ranges take precedence because they apply to every selected file; an empty list leaves range checks with no target span.
 *
 * @param scope - Active changed-region scope holding explicit ranges and per-file hunk ranges.
 * @param filePath - Path of the finding's file to look up when explicit ranges are absent.
 * @returns Explicit ranges if configured, otherwise the hunk ranges for filePath or an empty list.
 */
function rangesForFindingFile(scope: ChangedRegionScope, filePath: string): ChangedRange[] {
  return scope.explicitRanges ?? scope.rangesByFile.get(filePath) ?? [];
}

/**
 * Finds the narrowest declaration around the finding's line, preferring matching symbols for a stable choice.
 * An absent line means line 1; fills declarationsByFile on a cache miss to avoid rebuilding declaration spans.
 *
 * @param finding - Finding whose file, symbol name, and line anchor locate the enclosing declaration.
 * @param sources - Snapshot lookup used to verify script status and retrieve source text on cache misses.
 * @param declarationsByFile - Mutates this per-file declaration cache on misses.
 * @returns Narrowest enclosing declaration region, or undefined when no script or enclosing declaration is available.
 */
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

/**
 * Collects function, class, and interface spans in source for symbol scoping.
 * Without the optional shared parse, function spans come from the text-based block scan instead of syntax nodes.
 *
 * @param source - Full file text to scan for function, class, and interface declarations.
 * @param parsed - Optional shared parse supplying syntax for function spans when available.
 * @returns Combined declaration regions across functions, classes, and interfaces.
 */
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

/**
 * Extracts named class and interface line spans from masked source text, covering declarations outside the function-block scan.
 *
 * @param codeSource - Source text with comments and non-code literals masked out.
 * @returns Named declaration regions for matched class and interface declarations.
 */
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

/**
 * Estimates a class or interface's one-based closing line by counting braces from the zero-based declaration startIndex.
 * If no closing brace balances the declaration, returns its one-based starting line.
 *
 * @param lines - Masked source lines split at line breaks.
 * @param startIndex - Zero-based line index where the class or interface declaration starts.
 * @returns One-based closing line number, or the starting line when braces never balance.
 */
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

/**
 * Checks whether a finding or declaration span intersects any changed hunk.
 *
 * @param range - Inclusive one-based line span to test.
 * @param changedRanges - Changed line ranges for the target file.
 * @returns True when range overlaps at least one entry in changedRanges; otherwise false.
 */
function overlapsAny(range: ChangedRange, changedRanges: ChangedRange[]): boolean {
  return changedRanges.some((changedRange) => rangesOverlap(range, changedRange));
}

/**
 * Performs an inclusive range overlap test for one-based source line numbers.
 *
 * @param left - First inclusive line range.
 * @param right - Second inclusive line range.
 * @returns True when left and right share at least one line; otherwise false.
 */
function rangesOverlap(left: ChangedRange, right: ChangedRange): boolean {
  return left.start <= right.end && right.start <= left.end;
}

/**
 * Parses sorted, merged line ranges from comma-separated CLI text, skipping blank entries.
 *
 * @param rawRanges - Comma-separated `--changed-ranges` input text.
 * @returns Sorted, merged inclusive line ranges.
 * @throws {ChangedRegionError} When no ranges remain or a nonblank entry is outside the valid N or N-M syntax or bounds.
 */
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

/**
 * Parses inclusive line bounds for one `--changed-ranges` entry, using a single number for both bounds.
 *
 * @param rawRange - Trimmed single range token in N or N-M form.
 * @returns Inclusive start and end line numbers for the entry.
 * @throws {ChangedRegionError} When the entry is not N or N-M digits, starts below 1, or ends before it starts.
 */
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

/**
 * Builds a changed-region scope from Git diff output, reading paths relative to the scan directory so nested scans match findings.
 * Working-tree mode combines staged, unstaged, and non-ignored untracked changes for a review of all local edits.
 *
 * @param mode - Diff selector: `staged`, `unstaged`, `working-tree` (when `allowDiffModes` is true), or a Git revision expression.
 * @param changedScope - Attribution mode carried onto the resulting scope for downstream filtering.
 * @param projectRoot - Directory passed to Git so reported paths remain relative to the scan root.
 * @param allowDiffModes - true lets `staged`, `unstaged` and `working-tree` pick a mode; false (`--since`, `--diff-base`) reads them as Git refs
 * @returns Scope populated with changed files, whole files, and per-file hunk ranges.
 */
function gitDiffScope(mode: string, changedScope: ChangedScopeMode, projectRoot: string, allowDiffModes = true): ChangedRegionScope {
  /**
   * Runs `git diff` with paths relative to the selected project so a scan launched from a parent directory sees the right edits.
   *
   * @param extra - Additional Git diff flags or revision arguments appended to the base command.
   * @returns Parsed changed-region scope from the resulting unified diff output.
   */
  const readDiff = (extra: string[]) => parseUnifiedDiff(
    gitOutput(["-c", "core.quotepath=false", "diff", "--unified=0", "--no-color", "--no-ext-diff", "--relative", ...extra], projectRoot),
    changedScope,
  );
  // Mode keywords apply only to --diff; --since and --diff-base treat the value as a Git ref, even a branch named staged.
  if (allowDiffModes) {
    // Staged mode reviews the contents selected for the next commit. Without HEAD every staged file is new, so whole-file coverage needs no renumbering.
    if (mode === "staged") {
      const staged = readDiff(["--cached"]);
      return hasGitHead(projectRoot) ? stagedInWorkingTreeLines(staged, readDiff(["HEAD", "--"]), readDiff([])) : staged;
    }
    // Unstaged mode reviews changes made since the last staging operation.
    if (mode === "unstaged") {
      return readDiff([]);
    }
    // A working-tree review uses `git diff HEAD` when HEAD exists so staged and unstaged edits share exact working-tree line numbers.
    if (mode === "working-tree") {
      const trackedScopes = hasGitHead(projectRoot)
        ? [readDiff(["HEAD", "--"])]
        : [readDiff(["--cached"]), readDiff([])];
      return mergeScopes(
        [...trackedScopes, untrackedFileScope(changedScope, projectRoot)],
        changedScope,
      );
    }
  }
  // Trailing `--` forces Git to interpret `mode` strictly as a revision expression rather than a path when the ref is missing.
  return readDiff(["--end-of-options", mode, "--"]);
}

/**
 * Renumbers staged ranges in working-tree lines, because the scan reads the working tree while `git diff --cached` numbers the index.
 * For example, two unstaged lines inserted above a staged line 20 move it to line 22, which an index range would miss.
 * A staged line counts when it is new since HEAD and the unstaged edit did not add it; one an unstaged edit rewrote drops out.
 *
 * @param staged - `git diff --cached` scope, which decides the changed files and whole files a staged review covers
 * @param sinceHead - `git diff HEAD` scope: lines new since HEAD, numbered in the working tree
 * @param unstaged - `git diff` scope: lines the unstaged edit added, numbered in the working tree
 * @returns The staged scope with each file's hunk ranges replaced by working-tree ranges; files without surviving lines get no ranges.
 */
function stagedInWorkingTreeLines(staged: ChangedRegionScope, sinceHead: ChangedRegionScope, unstaged: ChangedRegionScope): ChangedRegionScope {
  const rangesByFile = new Map<string, ChangedRange[]>();
  for (const file of staged.rangesByFile.keys()) {
    // A staged rename that unstaged edits pushed past Git's rename threshold reads as a new file since HEAD, so every line is new.
    const newSinceHead = sinceHead.wholeFiles.has(file) ? [{ start: 1, end: Number.MAX_SAFE_INTEGER }] : sinceHead.rangesByFile.get(file) ?? [];
    const ranges = subtractRanges(newSinceHead, unstaged.rangesByFile.get(file) ?? []);
    // A staged hunk whose lines an unstaged edit replaced leaves nothing staged in the working tree to review.
    if (ranges.length > 0) {
      rangesByFile.set(file, ranges);
    }
  }
  return { ...staged, rangesByFile };
}

/**
 * Removes every line covered by `removed` from `ranges`, splitting a range when a removed block falls inside it.
 *
 * @param ranges - sorted, merged inclusive ranges to keep lines from
 * @param removed - sorted, merged inclusive ranges whose lines are taken out
 * @returns Sorted inclusive ranges holding the lines of `ranges` outside `removed`; empty when every line is removed.
 */
function subtractRanges(ranges: ChangedRange[], removed: ChangedRange[]): ChangedRange[] {
  const kept: ChangedRange[] = [];
  for (const range of ranges) {
    let start = range.start;
    for (const cut of removed) {
      // A removed block entirely before the remaining span, or after the range, leaves it whole.
      if (cut.end < start || cut.start > range.end) {
        continue;
      }
      if (cut.start > start) {
        kept.push({ start, end: cut.start - 1 });
      }
      start = cut.end + 1;
    }
    if (start <= range.end) {
      kept.push({ start, end: range.end });
    }
  }
  return kept;
}

/**
 * Spawns `git rev-parse` to check whether `HEAD` exists so `working-tree` can diff against `HEAD` instead of merging index coordinates.
 *
 * @param projectRoot - Directory passed to Git when verifying `HEAD`.
 * @returns True when `HEAD` resolves to a commit; false in a freshly initialized repository with an unborn `HEAD` or outside a repo.
 */
function hasGitHead(projectRoot: string): boolean {
  try {
    execFileSync("git", ["rev-parse", "--verify", "--quiet", "HEAD"], { cwd: projectRoot, stdio: ["ignore", "ignore", "ignore"] });
    return true;
  } catch {
    // For example, a brand-new repository after `git init` has staged files but no initial commit yet, so `HEAD` does not exist.
    return false;
  }
}

/**
 * Parses changed target files and addition ranges from unified diff text, carrying changedScope forward for later filtering.
 * A new file with a target header gets whole-file coverage; a surviving file with only deletions can be changed without target ranges.
 *
 * @param diffText - Unified diff text to walk line by line; an empty patch yields a scope with no changed files.
 * @param changedScope - Scope attribution mode assigned to the returned scope.
 * @returns Scope containing changed files, whole-file additions, and per-file target addition ranges.
 */
function parseUnifiedDiff(diffText: string, changedScope: ChangedScopeMode): ChangedRegionScope {
  const scope: ChangedRegionScope = { mode: changedScope, rangesByFile: new Map(), wholeFiles: new Set(), changedFiles: new Set() };
  const state: DiffParseState = { currentFile: undefined, isNewFile: false, targetLine: undefined };
  for (const line of diffText.split(/\r?\n/)) {
    applyDiffLine(scope, state, line);
  }
  return scope;
}

/**
 * Reads one unified-diff line and updates state for the current target file and hunk.
 * Mutates scope and state, clearing state at each file header to avoid carrying over the previous file.
 *
 * @param scope - Mutates changedFiles, wholeFiles, and rangesByFile as target headers and additions are encountered.
 * @param state - Mutates per-file parser state across headers and hunk lines.
 * @param line - Single line from the unified diff stream.
 * @returns Nothing. Records changed files and additions in scope and updates state in place.
 */
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

/**
 * Applies a unified-diff target-file header (`+++ `) by updating state's current file and clearing its hunk cursor.
 * A deleted target leaves no current file; surviving targets enter changedFiles, with whole-file coverage for new files.
 *
 * @param scope - Mutates changedFiles and wholeFiles when a surviving or new target file header is matched.
 * @param state - Mutates currentFile and resets targetLine when the line is a target-file header.
 * @param line - Candidate unified-diff line to inspect.
 * @returns True if line is a target-file header; otherwise false.
 */
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

/**
 * Applies a unified-diff hunk header (`@@ ... @@`) and updates state's target line cursor for the hunk.
 * A missing target file, whole-file coverage in scope, or a zero-length target hunk clears the cursor and skips line tracking.
 *
 * @param scope - Active diff scope checked for whole-file coverage on the current file.
 * @param state - Mutates targetLine to the hunk's starting line or clears it when tracking should be skipped.
 * @param line - Candidate unified-diff line to inspect.
 * @returns True if line is a hunk header; otherwise false.
 */
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

/**
 * Reads one hunk body line using state's current file and target cursor, recording additions and advancing the cursor on context lines.
 * Line tracking is skipped when no target file or cursor is active, or for whole-file coverage because the scope already includes every line.
 *
 * @param scope - Mutates rangesByFile on added lines unless whole-file coverage already applies.
 * @param state - Mutates targetLine as added or context lines advance through the hunk.
 * @param line - Hunk body line prefixed with `+`, space, or `-`.
 * @returns Nothing. Updates scope ranges and state's targetLine cursor in place.
 */
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

/**
 * Normalizes a unified-diff target-header path for finding lookup while preserving `/dev/null` as the deleted-target marker.
 *
 * @param rawPath - Raw path suffix extracted after the `+++ ` header prefix.
 * @returns Normalized forward-slash path relative to the diff root, or `/dev/null` for deleted targets.
 */
function diffPath(rawPath: string): string {
  const trimmed = rawPath.trim();
  if (trimmed === "/dev/null") {
    return trimmed;
  }
  return trimmed.replace(/^"?(?:a|b)\//, "").replace(/"$/, "").replaceAll("\\", "/");
}

/**
 * Collects new, non-ignored files for a working-tree review because Git has no hunks yet for these files.
 * Reads NUL-separated paths from `git ls-files` to keep filenames with spaces or newlines intact.
 *
 * @param changedScope - Attribution mode assigned to the resulting scope.
 * @param projectRoot - Directory passed to Git when listing untracked files.
 * @returns Scope marking all untracked non-ignored files as whole-file changes, or empty sets if none exist.
 */
function untrackedFileScope(changedScope: ChangedScopeMode, projectRoot: string): ChangedRegionScope {
  const untracked = new Set(gitOutput(["ls-files", "-z", "--others", "--exclude-standard"], projectRoot).split("\0").filter(Boolean));
  return { mode: changedScope, rangesByFile: new Map(), wholeFiles: untracked, changedFiles: new Set(untracked) };
}

/**
 * Combines staged, unstaged, and untracked input scopes into a single scope under changedScope mode.
 * Whole-file coverage takes precedence over hunk ranges for the same file.
 *
 * @param scopes - Input scopes whose changed files, whole files, and hunk ranges are merged.
 * @param changedScope - Attribution mode assigned to the combined scope.
 * @returns New merged scope combining all input changes.
 */
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

/**
 * Adds a changed line range to the entry for filePath, creating it if absent and merging overlaps or adjacent ranges.
 *
 * @param rangesByFile - Mutates the per-file range list for filePath in place.
 * @param filePath - Target file path whose changed ranges are being updated.
 * @param range - Inclusive line range to insert and merge.
 * @returns Nothing. Mutates rangesByFile in place with the sorted, merged ranges for filePath.
 */
function addRange(rangesByFile: Map<string, ChangedRange[]>, filePath: string, range: ChangedRange): void {
  rangesByFile.set(filePath, mergeRanges([...(rangesByFile.get(filePath) ?? []), range]));
}

/**
 * Builds a sorted list of line ranges, merging overlaps and adjacency so downstream checks stay deterministic.
 *
 * @param ranges - Unsorted or potentially overlapping inclusive line ranges.
 * @returns New sorted, non-overlapping, non-adjacent inclusive line ranges.
 */
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

/**
 * Spawns git with the caller's argument array and returns UTF-8 stdout, which can be empty when git has no changes to report.
 *
 * @param args - Git CLI flags and arguments passed directly to the executable.
 * @param projectRoot - Working directory used for the Git subprocess.
 * @returns UTF-8 standard output produced by Git.
 * @throws {ChangedRegionError} If Git cannot read the changes from projectRoot.
 */
function gitOutput(args: string[], projectRoot: string): string {
  try {
    return execFileSync("git", args, { cwd: projectRoot, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (error) {
    // For example, `--since main` can fail in a shallow checkout where that branch is missing.
    // When Git supplies no detail, the user still sees that the change selection failed.
    const detail = error instanceof Error && "stderr" in error && typeof error.stderr === "string"
      ? error.stderr.split(/\r?\n/u)[0]
      : undefined;
    throw new ChangedRegionError(`Unable to read the requested Git changes${detail ? `: ${detail}` : "."}`);
  }
}
