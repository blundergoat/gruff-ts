// Dead-code rules: unused private methods, unreachable statements after terminators, unused
// named imports. Invoked from the analyseTypeScriptRules orchestrator alongside the line-rules
// pass; they share the same `codeSource` mask and emit findings on a stable per-file order.
import { type SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import { escapeRegex, finding } from "./findings-helpers.ts";
import { byteLine, countMatches } from "./text-scans.ts";
import type { Finding } from "./types.ts";

// Deliberately single-file and low confidence because private methods can still be reached by
// tests, decorators, framework hooks, or string-based reflection; reports stable advisory findings because removal still needs human confirmation.
export function analyseDeadCode(file: SourceFile, source: string, findings: Finding[]): void {
  for (const match of source.matchAll(/\bprivate\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/g)) {
    const name = match[1] ?? "";
    const escaped = escapeRegex(name);
    if (countMatches(source, new RegExp(`${escaped}\\s*\\(`, "g")) <= 1) {
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

/*
 * Line-by-line walker that resets the terminator flag at every `case:` / `default:` because
 * dead-code detection must respect control-flow boundaries. Each line is walked once in source
 * order; the per-line state-machine update is extracted into `advanceUnreachableState` to keep
 * this loop's branching low. Reports `waste.unreachable-code` with stable, deterministic
 * fingerprint anchors so baselines and report snapshots round-trip without churn.
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

/*
 * Computes the next walker state from the current line. The conditional-context check (inside the
 * predicate parens, or on the consequent line) drives whether a terminator on this line counts as
 * unconditional. Branching is intentional here because the multi-line predicate has three discrete
 * cases: opener line, inside-predicate continuation, and "no longer in a predicate." Splitting
 * them inline would invariably reintroduce the npath the wrapper was trying to avoid.
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

// Net paren balance for one line of masked code (opens minus closes). String-literal parens are
// already blanked upstream by the masker, so the count is reliable for predicate-depth tracking.
function parenBalance(text: string): number {
  return countChar(text, "(") - countChar(text, ")");
}

// Counts a single character's occurrences without allocating a match array. Used to balance parens
// across the lines of a multi-line conditional predicate in `analyseUnreachable`.
function countChar(text: string, character: string): number {
  let count = 0;
  for (const char of text) {
    if (char === character) {
      count += 1;
    }
  }
  return count;
}

// Detects single-line conditional/loop openers that begin a one-statement body (no `{`). The next
// line is the conditional body, so any terminator there is conditional rather than unconditional.
function isBracelessConditionalOpener(trimmed: string): boolean {
  if (trimmed.endsWith("{") || trimmed.endsWith("}")) {
    return false;
  }
  return /^(?:if|else\s+if|for|while)\s*\(/.test(trimmed) || /^else\b/.test(trimmed) || /^do\b/.test(trimmed);
}

// `case X:` / `default:` open a new control path, so the unreachable walker must reset its
// terminator flag here - otherwise the first statement in a fallthrough case looks dead.
function isBranchLabel(trimmedLine: string): boolean {
  return /^(?:case\b.*:|default\s*:)$/.test(trimmedLine);
}

// Three conditions must hold to flag a line: the prior statement terminated, this line has real
// content, and it's not a `}` closer or a branch label. The `}` exclusion matters because the
// closing brace of the terminating block looks like a statement to a naive walker.
function isUnreachableStatement(trimmedLine: string, didPreviousTerminate: boolean, isBranchLabel: boolean): boolean {
  return didPreviousTerminate && /\S/.test(trimmedLine) && !trimmedLine.startsWith(String.fromCharCode(125)) && !isBranchLabel;
}

// `return`, `throw`, and `process.exit(...)` exit the current control path. The trailing `;`
// requirement filters out expressions like `return foo()` split across lines - without it the
// walker would falsely flag the continuation as unreachable.
function isTerminatingStatement(trimmedLine: string): boolean {
  return /^(?:return|throw|process\.exit)\b/.test(trimmedLine) && trimmedLine.endsWith(";");
}

/*
 * Reports `waste.unused-import` for every named specifier whose local name appears nowhere else
 * in the file. Default imports and namespace imports are out of scope because the regex anchors
 * on `{ … }`; walking lines in source order keeps the reports stable and deterministic. Receives
 * both the masked code and the raw source so identifiers referenced inside template-literal
 * `${...}` interpolations (which the mask would otherwise blank out) still count as used. Never
 * throws - every regex is anchored and the input shape is validated upstream by the analyser; the
 * helper writes to `findings` and returns void. Part of the public per-file rule contract that
 * baselines depend on, so finding ordering and message shape are intentionally stable across releases.
 */
export function analyseUnusedImports(file: SourceFile, source: string, rawSource: string, findings: Finding[]): void {
  for (const statement of namedImportStatements(source)) {
    for (const specifier of namedImportSpecifiers(statement.source)) {
      const name = unusedImportName(source, rawSource, specifier);
      if (!name) {
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

// Finds only named import declarations and spans across newlines until the matching `from` source.
// The non-greedy body keeps adjacent imports from merging into one statement.
function namedImportStatements(source: string): NamedImportStatement[] {
  return [...source.matchAll(/\bimport\s+(?:type\s+)?\{[\s\S]*?\}\s+from\s*["'][^"']+["']/g)].map((match) => ({ source: match[0] ?? "", line: byteLine(source, match.index ?? 0) }));
}

// Slices the `{ a, b as c }` body out of a named-import statement and splits on commas. No AST: a
// regex-light approach is sufficient because `analyseUnusedImports` runs after the comment mask,
// so commas inside string defaults never reach this function.
function namedImportSpecifiers(source: string): string[] {
  const trimmed = source.trim();
  const openBrace = trimmed.indexOf(String.fromCharCode(123));
  const closeBrace = trimmed.indexOf(String.fromCharCode(125), openBrace + 1);
  if (!hasNamedImportBraces(openBrace, closeBrace)) {
    return [];
  }
  return trimmed.slice(openBrace + 1, closeBrace).split(",");
}

// Both braces present and well-ordered. Indexes come from raw `indexOf` calls, so this guards
// against the malformed slice that would otherwise feed an empty or reversed specifier list.
function hasNamedImportBraces(openBrace: number, closeBrace: number): boolean {
  return openBrace !== -1 && closeBrace !== -1 && closeBrace > openBrace;
}

// The local binding (after `as`, if present) must appear in the source exactly once - the
// declaration itself. More than one match in the masked code, OR a `${...name...}` template-literal
// interpolation in the raw source, counts as a real reference. Returning undefined suppresses the finding.
function unusedImportName(source: string, rawSource: string, specifier: string): string | undefined {
  const name = localImportName(specifier);
  if (!name) {
    return undefined;
  }
  const escaped = escapeRegex(name);
  if (countMatches(source, new RegExp(`\\b${escaped}\\b`, "g")) > 1) {
    return undefined;
  }
  if (new RegExp(`\\$\\{[^}]*\\b${escaped}\\b[^}]*\\}`).test(rawSource)) {
    return undefined;
  }
  return name;
}

// Single makeFinding factory for `waste.unused-import`. The local binding name lands in both the
// message and `metadata.importName` so downstream tooling can group by symbol while the stable
// fingerprint identity remains (ruleId, filePath, line).
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

// Returns the right-hand side of `as` when present, otherwise the specifier itself. The trailing
// identifier regex protects against type-only specifiers that include extra tokens.
function localImportName(specifier: string): string | undefined {
  const parts = specifier.trim().split(/\s+as\s+/);
  const candidate = parts[1] ?? parts[0] ?? "";
  const match = candidate.trim().match(/^[A-Za-z_$][A-Za-z0-9_$]*/);
  return match?.[0];
}
