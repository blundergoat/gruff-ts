// Shared low-level finding factories and string utilities used across every rule pass. Kept as
// a leaf module (no rule-specific imports) so block/line/comment/project rule modules can depend
// on it without forming a cycle.
import { execFileSync } from "node:child_process";
import { basename } from "node:path";
import { ruleSeverity } from "./config.ts";
import type { SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import type { Config, Finding, Pillar, Severity } from "./types.ts";

// Returns named entries from parameter-list text params for per-parameter rules; destructured or unrecognized entries are omitted.
// Each entry has name, raw text without supported modifiers or rest dots, and isParameterProperty set when a modifier was removed.
// Empty input returns no entries.
export function parameterNames(params: string): Array<{ name: string; raw: string; isParameterProperty: boolean }> {
  return splitTopLevelParameters(params)
    .map((parameter) => parameter.trim())
    .filter(Boolean)
    .map((raw) => {
      const modifiers = raw.match(/^(?:(?:public|private|protected|readonly|override)\s+)*/)?.[0] ?? "";
      const stripped = raw.slice(modifiers.length).replace(/^\.\.\./, "");
      const name = stripped.match(/^([A-Za-z_$][A-Za-z0-9_$]*)\s*(?=[?:=]|$)/)?.[1] ?? "";
      return { name, raw: stripped, isParameterProperty: modifiers !== "" };
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

// Splits parameter-list text params into original substrings at top-level commas, keeping quoted and nested commas within each parameter.
// Preserves whitespace and empty segments; empty input returns one empty string for parameterNames to filter out.
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

// Updates state in place for character, tracking quote boundaries and backslash escapes so string contents are not treated as structure.
// Returns true when character belongs to quoted text or opens a quote; false lets the caller inspect it as a delimiter.
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

// Updates state in place for the character at index in params so nested commas do not split parameters.
// Uses start as the current parameter's starting offset when recognizing type arguments; returns no value.
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

// Returns whether index in params looks like a type-argument opener so its commas stay within the parameter.
// parameterStart bounds the prefix. A colon without an equals sign marks type context. Otherwise, the close must be followed by optional space and (.
// Rejects unrecognized prefixes and unmatched brackets to avoid treating comparison operators as type delimiters.
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

/**
 * Applies rules.<id>.severity while preserving the finding's stable fingerprint.
 *
 * @param config - effective configuration supplying any override for this finding's rule
 * @param finding - scanner result to check. Lower-band notices keep their assigned severity.
 * @returns - the original finding if its severity stands, or a copy carrying the configured severity
 */
export function applyConfiguredSeverity(config: Config, finding: Finding): Finding {
  // A lower-band size or complexity finding is advisory whatever severity the user configured (FAMILY-CONTRACT.md
  // section 12, search `Size and complexity findings in two bands`).
  if (finding.metadata.limitBand === "lower") {
    return finding;
  }
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
  // The rule's advice; omitted, the finding carries none and consumers fall back to the catalogue.
  remediation?: string | undefined;
}

// Builds a high-confidence, symbol-free finding from args for a per-line report entry.
// Uses args.file.displayPath and args.line for location; an empty remediation is omitted.
// Returns a finding whose fingerprint hashes ruleId, filePath, line and an empty symbol slot.
export function finding(args: LineFindingArgs): Finding {
  return makeFinding({
    ruleId: args.ruleId, message: args.message, filePath: args.file.displayPath, line: args.line, severity: args.severity, pillar: args.pillar,
    confidence: "high", ...(args.remediation ? { remediation: args.remediation } : {}),
  });
}

// Returns slash-normalized Git paths for mode: staged, unstaged, working-tree, or a revision compared with the working tree.
// Working-tree mode includes staged, unstaged and non-ignored untracked paths. An empty set means Git reported no matching paths.
// Spawns Git without a shell and places revision arguments after --end-of-options. Command failures propagate to the caller.
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

// Spawns Git through execFileSync without a shell, using args as the subcommand and its arguments.
// Returns a set of Git output paths with backslashes converted to slashes. No paths give an empty set. Git failures propagate.
function gitPathSet(args: string[]): Set<string> {
  return new Set(execFileSync("git", args, { encoding: "utf8" }).split(/\r?\n/).filter(Boolean).map((line) => line.replaceAll("\\", "/")));
}

// Strips directory and trailing extension. Used by naming.class-file-mismatch so the exported
// symbol name and the file stem normalise to the same shape - both sides must agree on this
// canonical form for the deterministic comparison to be meaningful.
export function fileBaseName(path: string): string {
  return basename(path).replace(/\.[^.]+$/, "");
}

// Returns a lowercase ASCII alphanumeric key from identifier so naming rules can compare across case styles.
// Treats FooBar, foo_bar and foo-bar as the same key. An identifier with no ASCII letters or digits produces an empty key.
export function normalizedIdentifier(identifier: string): string {
  return identifier.replace(/[^A-Za-z0-9]/g, "").toLowerCase();
}

// Returns lowercase ASCII word tokens from identifier for naming comparisons.
// Splits where an ASCII lowercase letter or digit precedes an uppercase letter, and at runs outside ASCII letters and digits.
// Uppercase runs stay together, so HTTPServer yields httpserver; input with no ASCII letters or digits returns an empty array.
export function splitIdentifierWords(identifier: string): string[] {
  return identifier
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .split(/[^A-Za-z0-9]+/)
    .map((word) => word.toLowerCase())
    .filter(Boolean);
}

// Returns the zero-based line at the string offset index in source.
// Negative offsets select the first line so they cannot index from the end. Offsets beyond the end select the final line.
export function lineOffset(source: string, index: number): number {
  return source.slice(0, Math.max(0, index)).split("\n").length - 1;
}

// Escapes the standard regex metacharacters so user-supplied strings (rule IDs, identifiers,
// paths) can be embedded in dynamic patterns without altering their meaning.
export function escapeRegex(source: string): string {
  return source.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Accumulates rule counts so that summary rows can be rendered without scanning the findings again.
 * Each total must equal the sum of errors, warnings and advisories.
 *
 * @param findings - report results to group by rule and count by severity
 * @returns a map of totals and severity counts keyed by rule ID, or an empty map when there are no findings
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
