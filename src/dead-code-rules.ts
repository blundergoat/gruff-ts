// Dead-code rules: unused private methods, unreachable statements after terminators, unused
// named imports. Invoked from the analyseTypeScriptRules orchestrator alongside the line-rules
// pass; they share the same `codeSource` mask and emit findings on a stable per-file order.
import { type SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import { escapeRegex, finding } from "./findings-helpers.ts";
import { namedImportBindings, type ParsedScript } from "./parsed-script.ts";
import { byteLine, countMatches } from "./text-scans.ts";
import type { Finding } from "./types.ts";

/**
 * Scans for likely unused private methods. The declaration counts as one call-shaped match.
 * Another call-shaped match or a matching this.name or this?.name reference suppresses the finding because even a bare reference may be used.
 * The advisory contract allows for real uses that the scan can miss.
 *
 * @param file - supplies the display path for each finding
 * @param source - masked source used to count call-shaped matches and references
 * @param findings - accumulator that receives the low-confidence advisories
 * @returns Nothing. Appends an advisory finding for each private method that appears unused.
 */
export function analyseDeadCode(file: SourceFile, source: string, findings: Finding[]): void {
  for (const match of source.matchAll(/\bprivate\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/g)) {
    const name = match[1] ?? "";
    const escaped = escapeRegex(name);
    if (countMatches(source, new RegExp(`${escaped}\\s*\\(`, "g")) <= 1 && countMatches(source, new RegExp(`\\bthis\\??\\.${escaped}\\b`, "g")) === 0) {
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

/**
 * Scans masked source line by line for statements after terminating statements and appends unreachable-code findings.
 * Case and default labels reset prior termination so a previous branch's terminator cannot make the new branch appear unreachable.
 * Uses stable finding anchors so baselines and report snapshots can match results across runs.
 *
 * @param file - provides the file path metadata for emitted findings
 * @param source - comment- and literal-masked script text scanned line by line
 * @param findings - accumulator that receives emitted unreachable-code findings
 * @returns Nothing. Appends `waste.unreachable-code` findings to `findings`.
 */
export function analyseUnreachable(file: SourceFile, source: string, findings: Finding[]): void {
  let state: UnreachableScanState = { didPreviousTerminate: false, conditionalParenDepth: 0, isConsequentPending: false };
  source.split(/\r?\n/).forEach((line, index) => {
    const trimmed = line.trim();
    const branchLabel = isBranchLabel(trimmed);
    const didPriorTerminate = branchLabel ? false : state.didPreviousTerminate;
    if (isUnreachableStatement(trimmed, didPriorTerminate, branchLabel)) {
      findings.push(finding({ ruleId: "waste.unreachable-code", message: "Statement appears after a terminating statement.", file, line: index + 1, severity: "warning", pillar: "maintainability" }));
    }
    state = advanceUnreachableState(trimmed, { ...state, didPreviousTerminate: didPriorTerminate });
  });
}

// Working state for the unreachable walker. Tracking these three fields together keeps the
// state-machine transitions explicit and lets the per-line update return a fresh value rather
// than mutating shared scope.
interface UnreachableScanState {
  didPreviousTerminate: boolean;
  conditionalParenDepth: number;
  isConsequentPending: boolean;
}

/**
 * Computes the next unreachable-code walker state after processing one trimmed masked line.
 * Carries predicate depth and a pending-consequent flag so terminators inside those conditional contexts are not treated as unconditional.
 *
 * @param trimmed - current trimmed masked source line being evaluated
 * @param state - prior walker state carrying termination and conditional-branch context
 * @returns Updated walker state for the subsequent line.
 */
function advanceUnreachableState(trimmed: string, state: UnreachableScanState): UnreachableScanState {
  const isInConditionalBranch = state.conditionalParenDepth > 0 || state.isConsequentPending;
  const didPreviousTerminate = isTerminatingStatement(trimmed) && !isInConditionalBranch;
  if (isBracelessConditionalOpener(trimmed)) {
    const balance = parenBalance(trimmed);
    const conditionalParenDepth = balance > 0 ? balance : 0;
    return { didPreviousTerminate, conditionalParenDepth, isConsequentPending: conditionalParenDepth === 0 };
  }
  if (state.conditionalParenDepth > 0) {
    const conditionalParenDepth = Math.max(0, state.conditionalParenDepth + parenBalance(trimmed));
    return { didPreviousTerminate, conditionalParenDepth, isConsequentPending: conditionalParenDepth === 0 };
  }
  return { didPreviousTerminate, conditionalParenDepth: 0, isConsequentPending: false };
}

/**
 * Computes the net parenthesis balance (opens minus closes) for one line of masked code.
 * String-literal parens are already blanked upstream by the masker, so the count is reliable for predicate-depth tracking.
 *
 * @param text - masked code fragment whose parentheses are counted
 * @returns Net count of opening minus closing parentheses in `text`.
 */
function parenBalance(text: string): number {
  return countChar(text, "(") - countChar(text, ")");
}

/**
 * Counts occurrences of a single character without allocating a match array.
 * Used to balance parens across the lines of a multi-line conditional predicate in `analyseUnreachable`.
 *
 * @param text - input text scanned character by character
 * @param character - target character to count within `text`
 * @returns Total number of positions where `text` matches `character`.
 */
function countChar(text: string, character: string): number {
  let count = 0;
  for (const char of text) {
    if (char === character) {
      count += 1;
    }
  }
  return count;
}

/**
 * Detects single-line conditional or loop openers that begin a one-statement body without a brace.
 * The next line is the conditional body, so any terminator there is conditional rather than unconditional.
 *
 * @param trimmed - trimmed masked source line to inspect
 * @returns True when `trimmed` opens a braceless conditional or loop header; false otherwise.
 */
function isBracelessConditionalOpener(trimmed: string): boolean {
  if (trimmed.endsWith("{") || trimmed.endsWith("}")) {
    return false;
  }
  return /^(?:if|else\s+if|for|while)\s*\(/.test(trimmed) || /^else\b/.test(trimmed) || /^do\b/.test(trimmed);
}

/**
 * Checks whether a trimmed line is a `case` or `default` label followed only by an optional opening brace.
 * The walker resets its terminator flag there because a switch can enter that case directly.
 *
 * @param trimmedLine - trimmed masked source line under inspection
 * @returns True when `trimmedLine` matches a switch `case` or `default` branch label; false otherwise.
 */
function isBranchLabel(trimmedLine: string): boolean {
  return /^(?:case\b.*|default\s*):\s*\{?$/.test(trimmedLine);
}

/**
 * Determines whether a line should be flagged as unreachable after a terminating statement.
 * Three conditions must hold: prior termination, non-whitespace content, and not a `}` closer or branch label,
 * because a closing brace looks like a statement to a naive walker.
 *
 * @param trimmedLine - trimmed masked source line being evaluated
 * @param didPreviousTerminate - whether the preceding control path ended unconditionally
 * @param isBranchLabel - whether the current line starts a switch `case` or `default` branch
 * @returns True when all three unreachability conditions hold; false otherwise.
 */
function isUnreachableStatement(trimmedLine: string, didPreviousTerminate: boolean, isBranchLabel: boolean): boolean {
  return didPreviousTerminate && /\S/.test(trimmedLine) && !trimmedLine.startsWith(String.fromCharCode(125)) && !isBranchLabel;
}

/**
 * Checks whether a trimmed line is a complete `return`, `throw`, or `process.exit(...)` terminator ending in `;`.
 * The trailing `;` requirement filters out multi-line expressions like `return foo()` so continuations are not falsely flagged.
 *
 * @param trimmedLine - trimmed masked source line to check
 * @returns True when `trimmedLine` begins with a terminator keyword and ends with `;`; false otherwise.
 */
function isTerminatingStatement(trimmedLine: string): boolean {
  return /^(?:return|throw|process\.exit)\b/.test(trimmedLine) && trimmedLine.endsWith(";");
}

/**
 * Reports `waste.unused-import` for named specifiers unused elsewhere, preferring the shared AST (`parsed`) over masked text scanning.
 * Checks both masked code and raw template-literal `${...}` interpolations so interpolated identifiers still count as used.
 * Never throws; writes to `findings` under the public per-file rule contract so finding order and message shape remain stable.
 *
 * @param file - provides the file path metadata for emitted findings
 * @param source - masked code used for fallback import scanning and identifier reference counts
 * @param rawSource - unmasked source inspected for template-literal `${...}` interpolations
 * @param findings - accumulator that receives `waste.unused-import` findings
 * @param parsed - optional shared TypeScript AST that resolves inline `type` modifiers, aliases, and multiline lists
 * @returns Nothing. Writes `waste.unused-import` findings to `findings` in stable order.
 */
export function analyseUnusedImports(file: SourceFile, source: string, rawSource: string, findings: Finding[], parsed?: ParsedScript): void {
  if (parsed) {
    for (const binding of namedImportBindings(parsed)) {
      if (isUnusedImportBinding(source, rawSource, binding.name)) {
        findings.push(unusedImportFinding(file, binding.name, binding.line));
      }
    }
    return;
  }
  for (const statement of namedImportStatements(source)) {
    for (const specifier of namedImportSpecifiers(statement.source)) {
      const name = localImportName(specifier);
      if (!name || !isUnusedImportBinding(source, rawSource, name)) {
        continue;
      }
      findings.push(unusedImportFinding(file, name, statement.line));
    }
  }
}

// One complete named-import declaration, including multiline `{ ... }` bodies, plus the anchor
// line where the `import` keyword began. Keeping the original source preserves alias parsing.
interface NamedImportStatement {
  source: string;
  line: number;
}

/**
 * Extracts named-import declarations and their starting line numbers from masked source text.
 * Matches `import { ... } from "..."` and `import type { ... } from "..."` statements, including multiline lists.
 *
 * @param source - comment- and literal-masked script text to scan for named imports
 * @returns Matched statement fragments with 1-based starting line numbers, or an empty array if none match.
 */
function namedImportStatements(source: string): NamedImportStatement[] {
  return [...source.matchAll(/\bimport\s+(?:type\s+)?\{[\s\S]*?\}\s+from\s*["'][^"']+["']/g)].map((match) => ({ source: match[0] ?? "", line: byteLine(source, match.index ?? 0) }));
}

/**
 * Splits the brace-enclosed list of a masked named-import statement into comma-separated specifier fragments.
 * Braces with no specifiers yield one fragment, preserving whitespace; masking keeps string commas from splitting specifiers.
 *
 * @param source - masked import statement text containing the named specifier list
 * @returns Raw comma-separated specifier fragments, or an empty array when no complete brace pair is found.
 */
function namedImportSpecifiers(source: string): string[] {
  const trimmed = source.trim();
  const openBrace = trimmed.indexOf(String.fromCharCode(123));
  const closeBrace = trimmed.indexOf(String.fromCharCode(125), openBrace + 1);
  if (!hasNamedImportBraces(openBrace, closeBrace)) {
    return [];
  }
  return trimmed.slice(openBrace + 1, closeBrace).split(",");
}

/**
 * Validates `indexOf` brace positions before slicing a named-import specifier list.
 *
 * @param openBrace - zero-based index of `{`, or `-1` when absent
 * @param closeBrace - zero-based index of `}` after `openBrace`, or `-1` when absent
 * @returns True when both braces exist and `closeBrace` follows `openBrace`; false otherwise.
 */
function hasNamedImportBraces(openBrace: number, closeBrace: number): boolean {
  return openBrace !== -1 && closeBrace !== -1 && closeBrace > openBrace;
}

/**
 * Checks whether a local import binding appears only at its declaration site across masked code and raw template interpolations.
 * Uses JavaScript identifier boundaries (`[A-Za-z0-9_$]`) rather than `\b` so `$`-bearing bindings such as Bun's `$`, `$state`,
 * and RxJS `events$` are recognised without letting `${...}` template interpolations count as uses of `$`.
 *
 * @param source - comment- and literal-masked script source for identifier reference counts
 * @param rawSource - unmasked script source inspected for `${...}` template interpolations
 * @param bindingName - local identifier bound by one named import specifier
 * @returns True when no usage outside the import declaration is found; false when at least one reference exists.
 */
function isUnusedImportBinding(source: string, rawSource: string, bindingName: string): boolean {
  const escaped = escapeRegex(bindingName);
  const trailingGuard = bindingName.endsWith("$") ? "(?![A-Za-z0-9_$]|\\{)" : "(?![A-Za-z0-9_$])";
  const boundaryPattern = `(?<![A-Za-z0-9_$])${escaped}${trailingGuard}`;
  if (countMatches(source, new RegExp(boundaryPattern, "g")) > 1) {
    return false;
  }
  if (new RegExp(`\\$\\{[^}]*${boundaryPattern}[^}]*\\}`).test(rawSource)) {
    return false;
  }
  return true;
}

/**
 * Builds a `waste.unused-import` advisory finding for an unused local import binding.
 * Places `name` in the message, `symbol`, and `metadata.importName` for grouping; its fingerprint uses rule ID, file path, line, and symbol.
 *
 * @param file - source file providing `displayPath` for the finding location and fingerprint
 * @param name - unused local identifier bound by the import specifier
 * @param line - 1-based line number of the import declaration or binding
 * @returns Structured `Finding` object with rule ID `waste.unused-import`.
 */
function unusedImportFinding(file: SourceFile, name: string, line: number): Finding {
  return makeFinding({
    ruleId: "waste.unused-import",
    message: `Imported symbol \`${name}\` does not appear to be used.`,
    filePath: file.displayPath,
    line,
    severity: "advisory",
    pillar: "maintainability",
    confidence: "medium",
    symbol: name,
    remediation: "Remove the unused import.",
    metadata: { importName: name },
  });
}

/**
 * Resolves the local identifier bound by one named-import specifier fragment.
 * Returns the right-hand side of `as` when aliased, or the specifier without any leading inline `type` modifier; used only by the fallback path.
 *
 * @param specifier - raw specifier fragment extracted from inside import braces
 * @returns Local identifier string, or `undefined` when no valid identifier is present.
 */
function localImportName(specifier: string): string | undefined {
  const stripped = specifier.trim().replace(/^type\s+/, "");
  const parts = stripped.split(/\s+as\s+/);
  const candidate = parts[1] ?? parts[0] ?? "";
  const match = candidate.trim().match(/^[A-Za-z_$][A-Za-z0-9_$]*/);
  return match?.[0];
}
