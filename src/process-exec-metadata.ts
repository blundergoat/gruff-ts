// Metadata classifiers for `security.process-exec` findings. They turn a process call's
// first argument and shell option into review hints without changing whether the rule fires.
import { escapeRegex } from "./findings-helpers.ts";

/** Closed command-source vocabulary used by process-exec grading and finding metadata. */
export type ProcessExecArgumentSource = "literal" | "process-exec-path" | "local-const" | "local-builder" | "parameter" | "member" | "template" | "unknown";

/** Typed process-exec classifier result used to grade and serialize finding metadata. */
export type ProcessExecMetadata = {
  callName: string;
  argumentSource: ProcessExecArgumentSource;
  isShellEnabled: boolean;
};

// Stable scanner state for the first-argument boundary walk.
interface ArgumentScanState {
  depth: number;
  quote: string | undefined;
}

// Stable result of consuming one character in the first-argument scanner.
interface ArgumentScanStep {
  state: ArgumentScanState;
  skip: number;
  isBoundary: boolean;
}

/**
 * Builds non-suppressing metadata for a child-process finding.
 *
 * @param callName Matched process API name, for example `spawn` or `execSync`.
 * @param rawSource Original source text used for literal and local-const classification.
 * @param callStart Byte offset where the process call starts in the file.
 * @param rawSegment Original source segment from call start through closing paren.
 * @param codeSegment Masked source segment used to read the shell option safely.
 * @returns Stable metadata describing command-source shape and shell mode.
 */
export function processExecMetadata(callName: string, rawSource: string, callStart: number, rawSegment: string, codeSegment: string): ProcessExecMetadata {
  const firstArgument = firstProcessCallArgument(rawSegment);
  return {
    callName,
    argumentSource: processExecArgumentSource(rawSource, callStart, firstArgument),
    isShellEnabled: processExecShellEnabled(callName, codeSegment),
  };
}

// Extracts the first top-level call argument so commas inside arrays, objects, calls, or strings
// do not misclassify `spawn("node", ["script,arg"])` as a dynamic command.
function firstProcessCallArgument(rawSegment: string): string {
  const argsText = rawSegment.slice(rawSegment.indexOf("(") + 1, rawSegment.lastIndexOf(")"));
  return firstTopLevelArgument(argsText).trim();
}

// Walks one argument list with quote and nesting state. The invariant is deliberately narrow:
// find only the first top-level comma, because command-source classification does not need parsing.
function firstTopLevelArgument(argsText: string): string {
  let state: ArgumentScanState = { depth: 0, quote: undefined };
  for (let index = 0; index < argsText.length; index += 1) {
    const step = argumentScanStep(argsText, index, state);
    if (step.isBoundary) {
      return argsText.slice(0, index);
    }
    state = step.state;
    index += step.skip;
  }
  return argsText;
}

// Advances one character in the argument scan while keeping string escapes and nesting separate.
function argumentScanStep(argsText: string, index: number, state: ArgumentScanState): ArgumentScanStep {
  const character = argsText[index] ?? "";
  if (state.quote) {
    return quotedArgumentScanStep(argsText, index, state, character);
  }
  if (isQuoteDelimiter(character)) {
    return scanStep({ depth: state.depth, quote: character });
  }
  if (isOpeningDelimiter(character)) {
    return scanStep({ depth: state.depth + 1, quote: undefined });
  }
  if (isClosingDelimiter(character)) {
    return scanStep({ depth: Math.max(0, state.depth - 1), quote: undefined });
  }
  return scanStep(state, character === "," && state.depth === 0);
}

// Handles one quoted character; escaped characters skip the next byte so an escaped quote stays inside.
function quotedArgumentScanStep(argsText: string, index: number, state: ArgumentScanState, character: string): ArgumentScanStep {
  if (character === "\\" && index + 1 < argsText.length) {
    return scanStep(state, false, 1);
  }
  if (character === state.quote) {
    return scanStep({ depth: state.depth, quote: undefined });
  }
  return scanStep(state);
}

// Builds the scan step object with explicit defaults so the main loop stays branch-light.
function scanStep(state: ArgumentScanState, isBoundary = false, skip = 0): ArgumentScanStep {
  return { state, isBoundary, skip };
}

// Quote delimiters are all significant because shell-command strings commonly use any of them.
function isQuoteDelimiter(character: string): boolean {
  return character === "\"" || character === "'" || character === "`";
}

// Nested call/array/object delimiters suppress comma boundaries until they close.
function isOpeningDelimiter(character: string): boolean {
  return character === "(" || character === "[" || character === "{";
}

// Closing delimiters unwind nesting but never below zero, which keeps malformed snippets bounded.
function isClosingDelimiter(character: string): boolean {
  return character === ")" || character === "]" || character === "}";
}

// Classifies the command operand for reviewer triage. This is advisory metadata only: every emitted
// process-exec finding still requires human review of the surrounding command construction.
function processExecArgumentSource(rawSource: string, callStart: number, firstArgument: string): ProcessExecArgumentSource {
  if (firstArgument === "process.execPath") {
    return "process-exec-path";
  }
  if (/^`/.test(firstArgument)) {
    return /\$\{/.test(firstArgument) ? "template" : "literal";
  }
  if (/^["'][^"']*["']$/.test(firstArgument)) {
    return "literal";
  }
  if (/^[A-Za-z_$][A-Za-z0-9_$]*\s*\(/.test(firstArgument)) {
    return "local-builder";
  }
  const identifier = firstArgument.match(/^[A-Za-z_$][A-Za-z0-9_$]*$/)?.[0];
  if (identifier) {
    return hasConstLiteralCommandDeclaration(rawSource, callStart, identifier) ? "local-const" : "parameter";
  }
  if (/^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+/.test(firstArgument)) {
    return "member";
  }
  return "unknown";
}

// Looks backward from the call for a same-scope `const command = "fixed"` shape so reviewers can
// distinguish fixed command vectors from parameter-driven command names. The initializer must be
// wholly one quoted literal: `"echo " + input` also contains a quoted fragment, and grading that as
// fixed would drop a shell-enabled, input-derived command from warning to advisory.
function hasConstLiteralCommandDeclaration(rawSource: string, callStart: number, identifier: string): boolean {
  const declaration = rawSource.slice(0, callStart).match(new RegExp(`\\bconst\\s+${escapeRegex(identifier)}\\s*=\\s*([^;]+);\\s*$`, "s"));
  const initializer = (declaration?.[1] ?? "").trim();
  return /^(?:"[^"\\]*"|'[^'\\]*')$/.test(initializer);
}

// Reports default shell semantics: exec/execSync imply a shell unless an explicit option says false,
// while spawn/execFile variants default to shell-disabled unless explicitly enabled.
function processExecShellEnabled(callName: string, codeSegment: string): boolean {
  if (/\bshell\s*:\s*true\b/.test(codeSegment)) {
    return true;
  }
  if (/\bshell\s*:\s*false\b/.test(codeSegment)) {
    return false;
  }
  return callName === "exec" || callName === "execSync";
}
