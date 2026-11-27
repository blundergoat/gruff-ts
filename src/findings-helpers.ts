// Shared low-level finding factories and string utilities used across every rule pass. Kept as
// a leaf module (no rule-specific imports) so block/line/comment/project rule modules can depend
// on it without forming a cycle.
import { execFileSync } from "node:child_process";
import { basename } from "node:path";
import { ruleSeverity } from "./config.ts";
import type { SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import type { Config, Finding, Pillar, Severity } from "./types.ts";

/**
 * Extracts named entries from parameter-list text for per-parameter rules, omitting destructured or unrecognized entries.
 * Each entry has name, raw text without supported modifiers or rest dots, and isParameterProperty set when a modifier was removed.
 *
 * @param params - raw parameter-list text inside a signature's parentheses
 * @returns matching parameter entries with stripped raw text and parameter-property flags, or an empty array on empty input
 */
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

/**
 * Splits parameter-list text into original substrings at top-level commas, keeping quoted and nested commas within each parameter.
 * Preserves whitespace and empty segments so `parameterNames` can filter them out.
 *
 * @param params - raw parameter-list text to split at top-level commas
 * @returns original parameter substrings, or a single empty string on empty input
 */
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

/**
 * Updates quote and escape tracking in place so string contents are not treated as parameter structure.
 *
 * @param state - mutable splitter state whose `quote` and `isEscaped` fields are updated
 * @param character - current character being scanned from the parameter list
 * @returns true when `character` belongs to quoted text or opens a quote, or false when the caller should inspect it as a delimiter
 */
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

/**
 * Updates nesting depths in place for the character at `index` so nested commas do not split parameters.
 * Uses `start` as the current parameter's starting offset when recognizing type arguments.
 *
 * @param state - mutable splitter state whose parenthesis, bracket, brace, and angle depths are updated
 * @param params - full parameter-list text being scanned
 * @param index - zero-based character offset in `params` to inspect
 * @param start - zero-based starting offset of the current parameter segment in `params`
 * @returns Nothing. Mutates `state` nesting depths in place.
 */
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

/**
 * Checks whether the splitter sits outside every nesting kind, because a comma splits parameters only at top level.
 *
 * @param state - current splitter nesting depths to inspect
 * @returns true only when parenthesis, bracket, brace, and angle depths are all zero
 */
function isTopLevelParameterPosition(state: ParameterSplitState): boolean {
  return state.parenthesisDepth === 0 && state.bracketDepth === 0 && state.braceDepth === 0 && state.angleDepth === 0;
}

/**
 * Determines whether the `<` at `index` opens a type-argument list so its commas stay within the parameter.
 * A colon without `=` marks type context; otherwise the matching `>` must precede optional space and `(`.
 * Rejects unrecognized prefixes and unmatched brackets to avoid treating comparison operators as type delimiters.
 *
 * @param params - full parameter-list text being scanned
 * @param index - zero-based offset of the `<` character in `params`
 * @param parameterStart - zero-based starting offset of the current parameter segment bounding the prefix
 * @returns true when the prefix and matching `>` indicate a type-argument list, or false otherwise
 */
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
 * Lower-band notices and unbuilt build-output bin advisories keep their assigned severity so starter configs do not promote them.
 *
 * @param config - effective configuration supplying any override for this finding's rule
 * @param finding - scanner result to check. Lower-band and unbuilt-output advisories keep their assigned severity.
 * @returns - the original finding if its severity stands, or a copy carrying the configured severity
 */
export function applyConfiguredSeverity(config: Config, finding: Finding): Finding {
  // A lower-band size or complexity finding is advisory whatever severity the user configured (FAMILY-CONTRACT.md
  // section 12, search `Size and complexity findings in two bands`). Unbuilt dist/build/lib bin targets keep advisory
  // severity for the same reason: starter configs pin `design.package-bin-missing` to `warning`.
  if (finding.metadata.limitBand === "lower" || finding.metadata.unbuiltOutput === true) {
    return finding;
  }
  const severity = ruleSeverity(config, finding.ruleId, finding.severity);
  return severity === finding.severity ? finding : { ...finding, severity };
}

// Input bundle for `finding()`, defining the stable contract for line-anchored findings.
//
// Defaults (`confidence: "high"`, empty `metadata`) are filled inside `finding()`, and analysis then stamps each rule's catalogue confidence.
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

/**
 * Builds a high-confidence, symbol-free finding for a per-line report entry.
 * Uses `args.file.displayPath` and `args.line` for location and omits empty remediation text.
 *
 * @param args - rule, message, file, line, severity, pillar, and optional remediation fields
 * @returns finding whose fingerprint hashes ruleId, filePath, line, and an empty symbol slot
 */
export function finding(args: LineFindingArgs): Finding {
  return makeFinding({
    ruleId: args.ruleId, message: args.message, filePath: args.file.displayPath, line: args.line, severity: args.severity, pillar: args.pillar,
    confidence: "high", ...(args.remediation ? { remediation: args.remediation } : {}),
  });
}

/**
 * Collects slash-normalized Git paths for `staged`, `unstaged`, `working-tree`, or a revision compared with the working tree.
 * Spawns Git without a shell and places revision arguments after `--end-of-options`; command failures propagate to the caller.
 *
 * @param mode - diff selection mode (`staged`, `unstaged`, `working-tree`, or a Git revision)
 * @returns set of matching slash-normalized paths (including non-ignored untracked paths in working-tree mode), or an empty set when none match
 */
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

/**
 * Spawns Git through `execFileSync` without a shell and normalizes output paths; Git failures propagate to the caller.
 *
 * @param args - Git subcommand and option arguments passed directly without shell interpolation
 * @returns set of non-empty output paths with backslashes converted to slashes, or an empty set when Git emits no paths
 */
function gitPathSet(args: string[]): Set<string> {
  return new Set(execFileSync("git", args, { encoding: "utf8" }).split(/\r?\n/).filter(Boolean).map((line) => line.replaceAll("\\", "/")));
}

/**
 * Strips directory segments and any trailing extension so `naming.class-file-mismatch` can normalize file stems.
 * Both sides must agree on this canonical form for the deterministic comparison to be meaningful.
 *
 * @param path - source file path whose base stem is extracted
 * @returns file name without parent directories or its final dot extension
 */
export function fileBaseName(path: string): string {
  return basename(path).replace(/\.[^.]+$/, "");
}

/**
 * Normalizes an identifier to a lowercase ASCII alphanumeric key so naming rules can compare across case styles.
 * Treats `FooBar`, `foo_bar`, and `foo-bar` as the same key.
 *
 * @param identifier - source identifier to strip and lowercase
 * @returns lowercase ASCII alphanumeric key, or an empty string when `identifier` contains no ASCII letters or digits
 */
export function normalizedIdentifier(identifier: string): string {
  return identifier.replace(/[^A-Za-z0-9]/g, "").toLowerCase();
}

/**
 * Splits an identifier into lowercase ASCII word tokens for naming comparisons.
 * Splits where an ASCII lowercase letter or digit precedes an uppercase letter and at non-alphanumeric runs, keeping uppercase runs together.
 *
 * @param identifier - source identifier to tokenize into lowercase words
 * @returns lowercase word tokens (for example `HTTPServer` yields `["httpserver"]`), or an empty array when no ASCII letters or digits exist
 */
export function splitIdentifierWords(identifier: string): string[] {
  return identifier
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .split(/[^A-Za-z0-9]+/)
    .map((word) => word.toLowerCase())
    .filter(Boolean);
}

/**
 * Computes the zero-based line number at a character offset in source text.
 * Negative offsets select the first line so they cannot index from the end, and offsets beyond the end select the final line.
 *
 * @param source - full text in which lines are counted by newline characters
 * @param index - zero-based character offset clamped at zero
 * @returns zero-based line number containing the clamped offset
 */
export function lineOffset(source: string, index: number): number {
  return source.slice(0, Math.max(0, index)).split("\n").length - 1;
}

/**
 * Escapes standard regex metacharacters so user-supplied strings (rule IDs, identifiers, paths) can be embedded in dynamic patterns literally.
 *
 * @param source - raw string to escape for safe inclusion in a `RegExp` pattern
 * @returns string with regex metacharacters backslash-escaped
 */
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
