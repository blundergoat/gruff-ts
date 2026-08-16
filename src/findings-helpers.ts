// Shared low-level finding factories and string utilities used across every rule pass. Kept as
// a leaf module (no rule-specific imports) so block/line/comment/project rule modules can depend
// on it without forming a cycle.
import { execFileSync } from "node:child_process";
import { basename } from "node:path";
import { ruleSeverity } from "./config.ts";
import type { SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import type { Config, Finding, Pillar, Severity } from "./types.ts";

// Splits only at top-level commas, then strips parameter-property modifiers and `...rest`.
// Destructured parameters remain intentionally invisible to per-parameter rules.
export function parameterNames(params: string): Array<{ name: string; raw: string }> {
  return splitTopLevelParameters(params)
    .map((parameter) => parameter.trim())
    .filter(Boolean)
    .map((raw) => {
      const stripped = raw.replace(/^(?:(?:public|private|protected|readonly|override)\s+)*/, "").replace(/^\.\.\./, "");
      const name = stripped.match(/^([A-Za-z_$][A-Za-z0-9_$]*)\s*(?=[?:=]|$)/)?.[1] ?? "";
      return { name, raw: stripped };
    })
    .filter((parameter) => /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(parameter.name));
}

// Nesting and quote context for the parameter splitter. Kept as one mutable record so the
// per-character helpers stay small enough to read at a glance.
interface ParameterSplitState {
  parenthesisDepth: number;
  bracketDepth: number;
  braceDepth: number;
  angleDepth: number;
  quote: string;
  isEscaped: boolean;
}

// Parameter defaults and type expressions can contain their own commas. A small delimiter scanner
// keeps those nested commas attached, because adding another TypeScript parse to this hot path
// would cost more than the character walk saves.
function splitTopLevelParameters(params: string): string[] {
  const parameters: string[] = [];
  const state: ParameterSplitState = { parenthesisDepth: 0, bracketDepth: 0, braceDepth: 0, angleDepth: 0, quote: "", isEscaped: false };
  let start = 0;
  for (let index = 0; index < params.length; index += 1) {
    const character = params[index] ?? "";
    if (advanceParameterQuoteState(state, character)) {
      continue;
    }
    if (character === "," && isTopLevelParameterPosition(state)) {
      parameters.push(params.slice(start, index));
      start = index + 1;
      continue;
    }
    advanceParameterDepths(state, params, index, start);
  }
  parameters.push(params.slice(start));
  return parameters;
}

// Consumes quote-context characters: inside a string nothing is structural, and a quote character
// opens string context. Returns false for ordinary characters so the caller keeps scanning.
function advanceParameterQuoteState(state: ParameterSplitState, character: string): boolean {
  if (state.quote !== "") {
    if (state.isEscaped) {
      state.isEscaped = false;
    } else if (character === "\\") {
      state.isEscaped = true;
    } else if (character === state.quote) {
      state.quote = "";
    }
    return true;
  }
  if (character === '"' || character === "'" || character === "`") {
    state.quote = character;
    return true;
  }
  return false;
}

// Tracks nesting for parentheses, brackets, braces, and guarded type-argument angles so commas
// inside them stay attached to their parameter.
function advanceParameterDepths(state: ParameterSplitState, params: string, index: number, start: number): void {
  const character = params[index] ?? "";
  if (character === "(") state.parenthesisDepth += 1;
  else if (character === ")") state.parenthesisDepth = Math.max(0, state.parenthesisDepth - 1);
  else if (character === "[") state.bracketDepth += 1;
  else if (character === "]") state.bracketDepth = Math.max(0, state.bracketDepth - 1);
  else if (character === "{") state.braceDepth += 1;
  else if (character === "}") state.braceDepth = Math.max(0, state.braceDepth - 1);
  else if (character === "<" && opensTypeArgumentList(params, index, start)) state.angleDepth += 1;
  else if (character === ">" && state.angleDepth > 0 && params[index - 1] !== "=") state.angleDepth -= 1;
}

// A comma splits parameters only outside every nesting kind.
function isTopLevelParameterPosition(state: ParameterSplitState): boolean {
  return state.parenthesisDepth === 0 && state.bracketDepth === 0 && state.braceDepth === 0 && state.angleDepth === 0;
}

// Treat `<...>` as type arguments in annotations, or in generic call/arrow defaults whose closing
// token is followed by `(`. Requiring that call boundary keeps comparison chains from swallowing
// a later parameter while preserving commas inside `factory<T, U>(...)` and `<T, U>(...) => ...`.
function opensTypeArgumentList(params: string, index: number, parameterStart: number): boolean {
  const prefix = params.slice(parameterStart, index);
  const previousCharacter = params[index - 1] ?? "";
  const isTypeContext = prefix.includes(":") && !prefix.includes("=");
  const followsTokenWithoutWhitespace = previousCharacter !== "" && !/\s/.test(previousCharacter);
  const startsGenericArrowDefault = /=\s*$/.test(prefix);
  if (!isTypeContext && !followsTokenWithoutWhitespace && !startsGenericArrowDefault) {
    return false;
  }
  let depth = 1;
  for (let cursor = index + 1; cursor < params.length; cursor += 1) {
    const character = params[cursor] ?? "";
    if (character === "<") depth += 1;
    else if (character === ">" && params[cursor - 1] !== "=") {
      depth -= 1;
      if (depth === 0) {
        const isFollowedByCallParameters = /^\s*\(/.test(params.slice(cursor + 1));
        return isTypeContext || isFollowedByCallParameters;
      }
    }
  }
  return false;
}

/*
 * Central severity-override pass: config `rules.<id>.severity` wins over the scanner's created
 * severity for every rule family in one place, so a user's policy applies even to scanners that
 * hardcode their descriptor literal; without an override the created severity stands.
 * Invariant: the fingerprint hashes (ruleId, filePath, line, symbol), so overrides never churn identity.
 */
export function applyConfiguredSeverity(config: Config, finding: Finding): Finding {
  const severity = ruleSeverity(config, finding.ruleId, finding.severity);
  return severity === finding.severity ? finding : { ...finding, severity };
}

// Input bundle for `finding()` - the lowest-cost finding factory. Captures everything the caller
// must supply for a line-anchored Finding; shared defaults (confidence "high", empty metadata)
// are added inside the builder so callers don't repeat them at every rule site.
export interface LineFindingArgs {
  ruleId: string;
  message: string;
  file: SourceFile;
  line: number;
  severity: Severity;
  pillar: Pillar;
}

// Cheapest finding factory: line-anchored, no symbol, confidence "high". Produces the
// (ruleId, filePath, line) tuple that every per-line emission relies on - this tuple is the
// stable fingerprint that drives baseline matching and report determinism.
export function finding(args: LineFindingArgs): Finding {
  return makeFinding({ ruleId: args.ruleId, message: args.message, filePath: args.file.displayPath, line: args.line, severity: args.severity, pillar: args.pillar, confidence: "high" });
}

// Diff-aware discovery: uses `execFileSync` (not `execSync`) so the `mode` value is passed as
// an argv entry and a malicious value cannot inject shell metacharacters. Custom-mode values pass
// through `--end-of-options` so a leading `-` cannot be reinterpreted as a `git diff` flag
// (e.g., `--output=…`). Normalises path separators to `/` for clean display-path joins.
export function changedFiles(mode: string): Set<string> {
  if (mode === "staged") {
    return gitPathSet(["diff", "--name-only", "--cached"]);
  }
  if (mode === "unstaged") {
    return gitPathSet(["diff", "--name-only"]);
  }
  if (mode === "working-tree") {
    return new Set([...gitPathSet(["diff", "--name-only"]), ...gitPathSet(["diff", "--name-only", "--cached"]), ...gitPathSet(["ls-files", "--others", "--exclude-standard"])]);
  }
  return gitPathSet(["diff", "--name-only", "--end-of-options", mode]);
}

// Spawns `git` through execFileSync with one fixed argv vector and returns the normalized path set
// used by diff filtering; spawns no shell because callers choose argv arrays, never shell strings.
function gitPathSet(args: string[]): Set<string> {
  return new Set(execFileSync("git", args, { encoding: "utf8" }).split(/\r?\n/).filter(Boolean).map((line) => line.replaceAll("\\", "/")));
}

// Strips directory and trailing extension. Used by `naming.class-file-mismatch` so the exported
// symbol name and the file stem normalise to the same shape - both sides must agree on this
// canonical form for the deterministic comparison to be meaningful.
export function fileBaseName(path: string): string {
  return basename(path).replace(/\.[^.]+$/, "");
}

// Lowercase-and-strip-separators canonical form. Treats `FooBar`, `foo_bar`, and `foo-bar` as
// the same key so naming rules can compare across case styles without baking the convention in.
export function normalizedIdentifier(identifier: string): string {
  return identifier.replace(/[^A-Za-z0-9]/g, "").toLowerCase();
}

// Inserts a space at every camelCase boundary, then splits on any non-alphanumeric run. Acronym
// runs (`HTTPServer`) stay intact because the inserted boundary is `lower → Upper`, not
// `Upper → Upper` - callers comparing word lists rely on this to keep tokens aligned.
export function splitIdentifierWords(identifier: string): string[] {
  return identifier
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .split(/[^A-Za-z0-9]+/)
    .map((word) => word.toLowerCase())
    .filter(Boolean);
}

// Counts newlines before the offset to get a 0-based line number. `Math.max(0, …)` guards against
// negative input - callers occasionally pass `match.index` which is typed as optional.
export function lineOffset(source: string, index: number): number {
  return source.slice(0, Math.max(0, index)).split("\n").length - 1;
}

// Detector for `waste.commented-out-code`: require a parseable disabled-code shape rather than a
// bare keyword so prose such as "import cycle" or section headings don't look executable.
export function isCommentedOutCode(line: string): boolean {
  const trimmed = line.trim();
  if (!trimmed.startsWith("//")) {
    return false;
  }
  const uncommented = trimmed.replace(/^\/\/+\s?/, "");
  if (isCommentSeparatorOrAnchor(uncommented)) {
    return false;
  }
  return isDisabledDeclaration(uncommented) || isDisabledControlFlow(uncommented) || isDisabledCall(uncommented);
}

// Skips prose examples, labels, search anchors, and section dividers that often begin with code words.
function isCommentSeparatorOrAnchor(uncommented: string): boolean {
  const text = uncommented.trim();
  return (
    text === "" ||
    /^[-=*_#]{3,}$/.test(text) ||
    /^[A-Za-z_$][A-Za-z0-9_$]*\s*:\s*['"`[{]/.test(text) ||
    /\b(?:search|grep|anchor|example|for example|e\.g\.)\s*:/.test(text) ||
    /^(?!(?:if|for|while|switch)\b)[A-Za-z_$][A-Za-z0-9_$]*\s+\([^;{}]*[A-Za-z][^;{}]*\)$/.test(text) ||
    /^[A-Z][A-Za-z0-9_$]*(?:\s|\s*\([^)]*\)$)/.test(text)
  );
}

// Declarations must carry their syntactic partner (`=`, `{`, `from`, etc.) to count as disabled code.
function isDisabledDeclaration(uncommented: string): boolean {
  return (
    /^(?:const|let|var)\s+[A-Za-z_$][A-Za-z0-9_$]*\s*=/.test(uncommented) ||
    /^(?:async\s+)?function\s+[A-Za-z_$][A-Za-z0-9_$]*\s*\(/.test(uncommented) ||
    /^class\s+[A-Za-z_$][A-Za-z0-9_$]*(?:\s+extends\s+[A-Za-z_$][A-Za-z0-9_$]*)?\s*\{?/.test(uncommented) ||
    /^interface\s+[A-Za-z_$][A-Za-z0-9_$]*\s*\{?/.test(uncommented) ||
    /^type\s+[A-Za-z_$][A-Za-z0-9_$]*\s*=/.test(uncommented) ||
    /^enum\s+[A-Za-z_$][A-Za-z0-9_$]*\s*\{?/.test(uncommented) ||
    /^import\s+(?:["'][^"']+["']|.+\s+from\s+["'][^"']+["'])/.test(uncommented) ||
    /^export\s+(?:\{|\*|(?:default\s+)?(?:const|let|var|function|class|interface|type|enum)\b)/.test(uncommented)
  );
}

// Control-flow comments need real syntax such as parentheses or an expression after `return`/`throw`.
function isDisabledControlFlow(uncommented: string): boolean {
  return /^(?:if|for|while|switch)\s*\(/.test(uncommented) || /^(?:return|throw|await)\s+\S/.test(uncommented);
}

// Keep single-line disabled calls; heading/prose guards above filter labels such as `Rules (...)`.
function isDisabledCall(uncommented: string): boolean {
  return /^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)?\s*\([^)]*\);?$/.test(uncommented);
}

// Lowercase membership test against the configured banned-names set. Drives the
// `naming.identifier-quality` predicate so the rule stays a single Set lookup per identifier.
export function isGenericName(name: string, bannedNames: Set<string>): boolean {
  return bannedNames.has(name.toLowerCase());
}

// Escapes the standard regex metacharacters so user-supplied strings (rule IDs, identifiers,
// paths) can be embedded in dynamic patterns without altering their meaning. Hot path -
// used by every rule that builds a per-source RegExp.
export function escapeRegex(source: string): string {
  return source.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/*
 * Per-rule severity tally for the `summary` Top-N rules block. Walks the findings once and returns
 * a deterministic Map keyed by ruleId carrying total / error / warning / advisory counts. Lets the
 * renderer surface "412 (0 err / 0 warn / 412 adv)" rows without re-scanning findings per row. The
 * count shape mirrors the `summary` schema invariant - total must equal err + warn + adv.
 */
export function countRuleSeverities(findings: Finding[]): Map<string, { total: number; error: number; warning: number; advisory: number }> {
  const counts = new Map<string, { total: number; error: number; warning: number; advisory: number }>();
  for (const finding of findings) {
    const entry = counts.get(finding.ruleId) ?? { total: 0, error: 0, warning: 0, advisory: 0 };
    entry.total += 1;
    entry[finding.severity] += 1;
    counts.set(finding.ruleId, entry);
  }
  return counts;
}
