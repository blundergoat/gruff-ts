/**
 * Provides lightweight source text scanners that separate executable TypeScript
 * from comments, strings, and regex bodies before rule matching runs.
 */
import { parseScript } from "./parsed-script.ts";
import type { RunDiagnostic } from "./types.ts";

// Just enough of `SourceFile` to keep `parseDiagnostics` decoupled from the full project type:
// `isScript` gates whether parser diagnostics run; `displayPath` is the report-path anchor.
interface DiagnosticSourceFile {
  displayPath: string;
  isScript: boolean;
}

/**
 * Syntax-only TypeScript parser diagnostics for script files; non-script inputs stay unparsed.
 * Uses the shared parser so callers that only need diagnostics get the same summary as the analyser.
 *
 * @param file - Source metadata used to skip non-script inputs and report paths.
 * @param source - Raw file text to parse for syntax diagnostics.
 * @returns One summarized parse-error diagnostic when the script fails to parse; empty for non-script inputs and clean parses.
 */
function parseDiagnostics(file: DiagnosticSourceFile, source: string): RunDiagnostic[] {
  return parseScript(file, source)?.diagnostics ?? [];
}

// Running totals for `{}`, `()`, and `[]`. A negative count means a closer appeared with no opener
// and is reported as a `parse-error` at that line; a non-zero final value is reported at EOF.
interface DelimiterCounts {
  braces: number;
  parentheses: number;
  brackets: number;
}

// Lexer state for the delimiter scanner. `previousCode` is the last non-whitespace executable
// character - required because `/` may start a regex or a division depending on what came before.
// `templateInterpolationStack` records the brace count at each `${` so a matching `}` can re-enter
// template literal mode; without it, nested-template-literal files like `\`\${x.map(n => \`\${n}\`)}\``
// flip out of quote mode early and start counting code-level braces inside the string body.
interface DelimiterScanState {
  quote: string | undefined;
  isEscaped: boolean;
  isInBlockComment: boolean;
  isInRegex: boolean;
  isInRegexCharClass: boolean;
  isRegexEscaped: boolean;
  previousCode: string;
  templateInterpolationStack: number[];
}

// Bundles state + counts so per-character handlers can mutate both without threading two arguments.
interface DelimiterScanContext {
  scan: DelimiterScanState;
  counts: DelimiterCounts;
}

// Per-character scanner result. `skip` consumes the next N characters (e.g. the `/` of `*/`);
// `shouldStopLine` bails out of the rest of the line when a `//` line comment starts.
interface ScanStep {
  skip: number;
  shouldStopLine: boolean;
}

// Returns fresh delimiter-scan state for a new file, with no active literal or comment and no prior code character.
// An empty previousCode lets a slash at the start of code open a regex; later code updates that context.
function defaultDelimiterScanState(): DelimiterScanState {
  return {
    quote: undefined,
    isEscaped: false,
    isInBlockComment: false,
    isInRegex: false,
    isInRegexCharClass: false,
    isRegexEscaped: false,
    previousCode: "",
    templateInterpolationStack: [],
  };
}

// Returns nothing and updates the supplied delimiter totals and scanner state for one source line.
// Stops at a line comment because the rest of the line is comment text.
// Block comments, string text and regex bodies leave counts unchanged. Template interpolations resume counting.
function scanDelimiterLine(line: string, ctx: DelimiterScanContext): void {
  for (let offset = 0; offset < line.length; offset += 1) {
    const step = scanDelimiterCharacter(line, offset, ctx);
    offset += step.skip;
    if (step.shouldStopLine) {
      break;
    }
  }
}

// Scan line at offset according to the lexical mode stored in ctx, updating its counts and scan state.
// Return a step telling the line walker whether to continue, skip a character, or stop at a line comment.
function scanDelimiterCharacter(line: string, offset: number, ctx: DelimiterScanContext): ScanStep {
  const character = line[offset] ?? "";
  const next = line[offset + 1] ?? "";
  if (ctx.scan.isInBlockComment) {
    return scanBlockCommentDelimiter(character, next, ctx.scan);
  }
  if (ctx.scan.quote) {
    return scanQuotedDelimiter(character, next, ctx);
  }
  if (ctx.scan.isInRegex) {
    scanRegexDelimiter(character, ctx.scan);
    return continueScan();
  }
  return scanCodeDelimiter(line, offset, character, next, ctx);
}

// Inside `/* ... */`. Returns `skip: 1` to swallow the `/` of the closing `*/`, then the next
// step resumes in code mode. Block-comment contents do not affect delimiter counts.
// Read character and lookahead next, update scan's lexical mode, and return a continuing step when no closer is found.
function scanBlockCommentDelimiter(character: string, next: string, scan: DelimiterScanState): ScanStep {
  if (character === "*" && next === "/") {
    scan.isInBlockComment = false;
    return skipNextCharacter();
  }
  return continueScan();
}

// Scan character and lookahead next inside a quoted literal, updating the quote, escape, and delimiter state in ctx.
// Escapes protect the next character; template interpolation saves brace depth and resumes code until its closing brace.
// Return a continuing step, skipping the opening brace after a template interpolation marker.
function scanQuotedDelimiter(character: string, next: string, ctx: DelimiterScanContext): ScanStep {
  const scan = ctx.scan;
  if (scan.isEscaped) {
    scan.isEscaped = false;
    return continueScan();
  }
  if (character === "\\") {
    scan.isEscaped = true;
    return continueScan();
  }
  if (scan.quote === "`" && character === "$" && next === "{") {
    scan.templateInterpolationStack.push(ctx.counts.braces);
    scan.quote = undefined;
    ctx.counts.braces += 1;
    scan.previousCode = "{";
    return skipNextCharacter();
  }
  if (character === scan.quote) {
    scan.quote = undefined;
  }
  return continueScan();
}

// Returns nothing. Updates scan from character, tracking escapes and classes. Closing the regex sets previousCode to an operand marker.
// Inside `/regex/`. `[...]` character classes can legally contain `/`, so the closing slash
// is only honoured when `isInRegexCharClass` is false; otherwise `/[/]/` would terminate early.
function scanRegexDelimiter(character: string, scan: DelimiterScanState): void {
  if (scan.isRegexEscaped) {
    scan.isRegexEscaped = false;
  } else if (character === "\\") {
    scan.isRegexEscaped = true;
  } else if (character === "[") {
    scan.isInRegexCharClass = true;
  } else if (character === "]") {
    scan.isInRegexCharClass = false;
  } else if (character === "/" && !scan.isInRegexCharClass) {
    scan.isInRegex = false;
    scan.previousCode = "x";
  }
}

// Classify character and lookahead next in executable code, using line and offset for the regex-opening heuristic.
// Update delimiter counts and lexical state in ctx; return the matched token's scan step or the ordinary-code step.
function scanCodeDelimiter(line: string, offset: number, character: string, next: string, ctx: DelimiterScanContext): ScanStep {
  return (
    scanLineCommentStart(character, next) ??
    scanBlockCommentStart(character, next, ctx.scan) ??
    scanQuoteStart(character, ctx.scan) ??
    scanRegexStart(line, offset, character, ctx.scan) ??
    scanPlainCodeDelimiter(character, ctx)
  );
}

// `//` ends the line for delimiter purposes - anything to the right is comment text.
// Read character and lookahead next; return a stopping step for the opener or undefined to try another token kind.
function scanLineCommentStart(character: string, next: string): ScanStep | undefined {
  if (character === "/" && next === "/") {
    return stopLineScan();
  }
  return undefined;
}

// `/*` flips the scanner into block-comment mode; `skip: 1` swallows the `*` so it isn't re-evaluated.
// Inspect character and lookahead next, update scan on an opener, and return a skip step or undefined for another token handler.
function scanBlockCommentStart(character: string, next: string, scan: DelimiterScanState): ScanStep | undefined {
  if (character === "/" && next === "*") {
    scan.isInBlockComment = true;
    return skipNextCharacter();
  }
  return undefined;
}

// Treat character as a possible quote opener and store a recognised quote in the caller's scan state.
// Return a continuing step for a quote, or undefined so the caller can try another token kind.
function scanQuoteStart(character: string, scan: DelimiterScanState): ScanStep | undefined {
  if (isQuote(character)) {
    scan.quote = character;
    return continueScan();
  }
  return undefined;
}

// Use character, the prefix of line before offset, and scan.previousCode to distinguish a regex opener from division.
// On an opener, update the caller's scan flags and return a continuing step; otherwise return undefined for the next token handler.
function scanRegexStart(line: string, offset: number, character: string, scan: DelimiterScanState): ScanStep | undefined {
  if (character === "/" && isRegexLiteralStart(scan.previousCode, line.slice(0, offset))) {
    scan.isInRegex = true;
    scan.isInRegexCharClass = false;
    scan.isRegexEscaped = false;
    return continueScan();
  }
  return undefined;
}

// Count character in ctx.counts and update ctx.scan so later slashes can be classified as regex or division.
// Ignore whitespace when remembering code; a closing interpolation brace restores template-literal mode at its saved depth.
// Return a continuing scan step after updating the caller's state.
function scanPlainCodeDelimiter(character: string, ctx: DelimiterScanContext): ScanStep {
  countDelimiter(character, ctx.counts);
  if (character === "}" && ctx.scan.templateInterpolationStack.length > 0 && ctx.counts.braces === (ctx.scan.templateInterpolationStack[ctx.scan.templateInterpolationStack.length - 1] ?? -1)) {
    ctx.scan.templateInterpolationStack.pop();
    ctx.scan.quote = "`";
    ctx.scan.previousCode = "`";
    return continueScan();
  }
  if (character.trim() !== "") {
    ctx.scan.previousCode = character;
  }
  return continueScan();
}

// Returns nothing and updates the supplied delimiter totals for the current character.
// Openers add to their own total and closers subtract. Other characters are ignored so that callers can pass each character unconditionally.
function countDelimiter(character: string, counts: DelimiterCounts): void {
  if (character === "{") {
    counts.braces += 1;
  } else if (character === "}") {
    counts.braces -= 1;
  } else if (character === "(") {
    counts.parentheses += 1;
  } else if (character === ")") {
    counts.parentheses -= 1;
  } else if (character === "[") {
    counts.brackets += 1;
  } else if (character === "]") {
    counts.brackets -= 1;
  }
}

// Returns whether counts contains a negative brace, parenthesis, or bracket balance, indicating a closer without an opener.
function hasNegativeDelimiterCount(counts: DelimiterCounts): boolean {
  return counts.braces < 0 || counts.parentheses < 0 || counts.brackets < 0;
}

// Returns whether counts has any nonzero brace, parenthesis, or bracket balance, indicating unmatched delimiters.
function hasUnbalancedDelimiterCount(counts: DelimiterCounts): boolean {
  return counts.braces !== 0 || counts.parentheses !== 0 || counts.brackets !== 0;
}

/**
 * Builds a parse-error diagnostic for a caller to include in scan results.
 *
 * @param file - source metadata whose displayPath identifies the failed file
 * @param line - source line to attach to the error
 * @param message - explanation copied into the diagnostic
 * @returns a parse-error record containing the supplied message, display path, and line
 */
function parseErrorDiagnostic(file: DiagnosticSourceFile, line: number, message: string): RunDiagnostic {
  return {
    diagnosticType: "parse-error",
    message,
    filePath: file.displayPath,
    line,
  };
}

// Returns whether a slash looks like a regex opener. previousCode holds a code character, a synthetic operand marker, or an empty start marker.
// beforeSlash supplies preceding text. An empty marker, selected punctuation, or the word return after trimming trailing whitespace permits a regex.
// This conservative heuristic limits the risk of masking real code as a regex body and losing its delimiters.
function isRegexLiteralStart(previousCode: string, beforeSlash: string): boolean {
  return previousCode === "" || "([{=,:!&|?;".includes(previousCode) || /\breturn$/.test(beforeSlash.trimEnd());
}

// Returns source with recognized comment and literal bodies masked, preserving UTF-16 code-unit offsets and newline positions.
// Regex-driven rules use the unchanged positions to report source locations without matching text inside those bodies.
function maskNonCode(source: string): string {
  let result = "";
  const state = defaultMaskState();
  for (let index = 0; index < source.length; index += 1) {
    const step = maskNonCodeCharacter(source, index, state);
    result += step.text;
    index += step.skip;
  }
  return result;
}

// Masks template-literal bodies in source with spaces and returns the result, preserving offsets and line-feed characters.
// Single- and double-quoted bodies remain visible so syntax-pattern rules can read real import specifiers.
// Import-edge rules use this to ignore fixture text inside backticks. Import calls inside interpolations can also be masked.
function maskTemplateLiteralBodies(source: string): string {
  let result = "";
  const state = templateMaskState();
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index] ?? "";
    const next = source[index + 1] ?? "";
    const step = templateMaskCharacter(character, next, state);
    result += step.text;
    index += step.skip;
  }
  return result;
}

// Mutable lexer state for `maskTemplateLiteralBodies`. Smaller than `MaskState` because the
// helper only needs to know which quote/comment context the current character sits inside.
interface TemplateMaskState {
  quote: '"' | "'" | "`" | undefined;
  isEscaped: boolean;
  isLineComment: boolean;
  isBlockComment: boolean;
}

// Fresh default state for a single-file template-mask pass.
function templateMaskState(): TemplateMaskState {
  return { quote: undefined, isEscaped: false, isLineComment: false, isBlockComment: false };
}

// Transform character with lookahead next for template-body masking, updating the caller's state.
// Preserve delimiters, newlines, single/double-quoted strings, and comments while masking template body text.
// Return output text and the extra-character skip count; regex literals receive no dedicated handling.
function templateMaskCharacter(character: string, next: string, state: TemplateMaskState): MaskStep {
  if (character === "\n") return templateMaskNewline(state);
  if (state.isLineComment) return { text: character, skip: 0 };
  if (state.isBlockComment) return templateMaskBlockComment(character, next, state);
  if (state.quote) return templateMaskQuotedCharacter(character, state);
  return templateMaskCodeCharacter(character, next, state);
}

// Newlines clear line-comment state and any non-template quote; template literals survive across lines.
// Mutate state in place and return a newline with no extra-character skip.
function templateMaskNewline(state: TemplateMaskState): MaskStep {
  state.isLineComment = false;
  if (state.quote !== "`") {
    state.quote = undefined;
  }
  return { text: "\n", skip: 0 };
}

// Use character and lookahead next to preserve block-comment text, clearing state.isBlockComment on its closer.
// Return preserved text and an extra-character skip of one for the closer, or zero otherwise.
function templateMaskBlockComment(character: string, next: string, state: TemplateMaskState): MaskStep {
  if (character === "*" && next === "/") {
    state.isBlockComment = false;
    return { text: "*/", skip: 1 };
  }
  return { text: character, skip: 0 };
}

// Inside any quoted string: bodies of `` ` `` get masked, single/double-quote bodies pass through.
// Use character and the active quote in state, updating escape and quote flags in place.
// Return the transformed character with no extra skip; preserve an unescaped closing quote and leave quote mode.
function templateMaskQuotedCharacter(character: string, state: TemplateMaskState): MaskStep {
  const masked = state.quote === "`";
  if (state.isEscaped) {
    state.isEscaped = false;
    return { text: masked ? " " : character, skip: 0 };
  }
  if (character === "\\") {
    state.isEscaped = true;
    return { text: masked ? " " : character, skip: 0 };
  }
  if (character === state.quote) {
    state.quote = undefined;
    return { text: character, skip: 0 };
  }
  return { text: masked ? " " : character, skip: 0 };
}

// In code: detect comment openers and the three quote types, otherwise pass through.
// Read character and lookahead next, update state on an opener, and return preserved text plus the extra-character skip count.
function templateMaskCodeCharacter(character: string, next: string, state: TemplateMaskState): MaskStep {
  if (character === "/" && next === "/") {
    state.isLineComment = true;
    return { text: "//", skip: 1 };
  }
  if (character === "/" && next === "*") {
    state.isBlockComment = true;
    return { text: "/*", skip: 1 };
  }
  if (character === '"' || character === "'" || character === "`") {
    state.quote = character;
    return { text: character, skip: 0 };
  }
  return { text: character, skip: 0 };
}

// Mutable lexer state for the masking pass. Mirrors `DelimiterScanState` because both passes solve
// the same code-vs-literal problem, but `maskNonCode` runs over the whole file rather than line-by-line.
interface MaskState {
  quote: string | undefined;
  isEscaped: boolean;
  isLineComment: boolean;
  isBlockComment: boolean;
  isRegex: boolean;
  isRegexCharClass: boolean;
  isRegexEscaped: boolean;
  previousCode: string;
  // One entry per open `${`, innermost last, counting the braces still open inside that interpolation. A scalar
  // depth cannot tell a nested template's own `}` from the enclosing interpolation's, so it resumed code where the
  // inner template body continued and masked the rest of the file.
  templateInterpolationDepths: number[];
}

// `text` is what gets written for this character (space for masked, original for code, "  " for
// two-char openers like `//`); `skip` advances past a paired character so it isn't re-scanned.
interface MaskStep {
  text: string;
  skip: number;
}

// All flags start cleared so the first scanner step treats source as code.
function defaultMaskState(): MaskState {
  return {
    quote: undefined,
    isEscaped: false,
    isLineComment: false,
    isBlockComment: false,
    isRegex: false,
    isRegexCharClass: false,
    isRegexEscaped: false,
    previousCode: "",
    templateInterpolationDepths: [],
  };
}

// Returns output text and an extra-character skip for source[index], updating state as comments and literals open or close.
// source is the complete input and index selects the current character; state carries the masking context between calls.
// Newlines end line comments and ordinary quote or regex state, while template literals and block comments remain active.
function maskNonCodeCharacter(source: string, index: number, state: MaskState): MaskStep {
  const character = source[index] ?? "";
  const next = source[index + 1] ?? "";
  if (character === "\n") {
    return maskNewline(state);
  }
  if (state.isLineComment) {
    return maskSingleCharacter();
  }
  if (state.isBlockComment) {
    return maskBlockComment(character, next, state);
  }
  if (state.quote) {
    return maskQuotedCharacter(character, next, state);
  }
  if (state.isRegex) {
    return maskRegexCharacter(character, state);
  }
  return maskCodeCharacter(source, index, character, next, state);
}

// Updates the supplied mask state at a newline by clearing line-comment, single-quote, double-quote, and regex modes.
// Keeps template-literal and block-comment modes because both can span lines.
// Returns a step containing the original newline to preserve source offsets.
function maskNewline(state: MaskState): MaskStep {
  state.isLineComment = false;
  if (state.quote !== "`") {
    state.quote = undefined;
  }
  state.isRegex = false;
  state.isRegexCharClass = false;
  state.isRegexEscaped = false;
  return { text: "\n", skip: 0 };
}

// Replaces block-comment text with spaces; the closing `*/` becomes "  " so the two output
// characters line up with the two consumed characters; character and next are the current source pair.
// Returns text plus an extra-character skip, clearing state.isBlockComment when the closing pair is consumed.
function maskBlockComment(character: string, next: string, state: MaskState): MaskStep {
  if (character === "*" && next === "/") {
    state.isBlockComment = false;
    return { text: "  ", skip: 1 };
  }
  return maskSingleCharacter();
}

// Returns masking text and an extra-character skip for character inside a literal; next is the following source character.
// Mutates state to track escapes and the closing quote; body text becomes spaces while the closing quote remains visible.
// In a template, an interpolation opener remains visible, pushes its brace depth, and clears the quote so expression code is scanned.
function maskQuotedCharacter(character: string, next: string, state: MaskState): MaskStep {
  if (state.isEscaped) {
    state.isEscaped = false;
    return maskSingleCharacter();
  }
  if (character === "\\") {
    state.isEscaped = true;
    return maskSingleCharacter();
  }
  if (state.quote === "`" && character === "$" && next === "{") {
    state.quote = undefined;
    state.templateInterpolationDepths.push(1);
    state.previousCode = "{";
    return { text: "${", skip: 1 };
  }
  if (character === state.quote) {
    state.previousCode = character;
    state.quote = undefined;
    return { text: character, skip: 0 };
  }
  return maskSingleCharacter();
}

// Inside `/.../`: mask body characters and pass through the closing `/`. `[ ... ]` character classes
// suspend the closing-slash check so `/[/]/` does not terminate at the inner slash.
// Returns text for character with skip 0 and updates state for escapes, character classes, and the closing slash.
function maskRegexCharacter(character: string, state: MaskState): MaskStep {
  if (state.isRegexEscaped) {
    state.isRegexEscaped = false;
    return maskSingleCharacter();
  }
  if (character === "\\") {
    state.isRegexEscaped = true;
    return maskSingleCharacter();
  }
  if (character === "[") {
    state.isRegexCharClass = true;
    return maskSingleCharacter();
  }
  if (character === "]") {
    state.isRegexCharClass = false;
    return maskSingleCharacter();
  }
  if (character === "/" && !state.isRegexCharClass) {
    state.isRegex = false;
    state.previousCode = character;
    return { text: character, skip: 0 };
  }
  return maskSingleCharacter();
}

// Returns output text and an extra-character skip for source[index]; character and next are the current and following source characters.
// Mutates state for template braces, comment or literal starts, or the last code character, preserving positions for rule matching.
// Checks comment openers before regex starts so a comment opener cannot enter regex mode; unmatched text passes through.
function maskCodeCharacter(source: string, index: number, character: string, next: string, state: MaskState): MaskStep {
  return (
    maskTemplateInterpolationBrace(character, state) ??
    maskLineCommentStart(character, next, state) ??
    maskBlockCommentStart(character, next, state) ??
    maskRegexStart(source, index, character, state) ??
    maskQuoteStart(character, state) ??
    maskPlainCodeCharacter(character, state)
  );
}

// Returns character with skip 0 for a brace in the active template interpolation, updating state and only its innermost brace depth.
// character is the current code character; state tracks open interpolations. Closing its final brace resumes template-body masking.
// Returns undefined outside an interpolation or for other characters so the caller can try the next detector.
function maskTemplateInterpolationBrace(character: string, state: MaskState): MaskStep | undefined {
  const openBraceDepths = state.templateInterpolationDepths;
  const innermost = openBraceDepths.length - 1;
  if (innermost < 0) {
    return undefined;
  }
  if (character === "{") {
    openBraceDepths[innermost] = (openBraceDepths[innermost] ?? 0) + 1;
    state.previousCode = character;
    return { text: character, skip: 0 };
  }
  if (character === "}") {
    openBraceDepths[innermost] = (openBraceDepths[innermost] ?? 0) - 1;
    state.previousCode = character;
    if (openBraceDepths[innermost] === 0) {
      openBraceDepths.pop();
      state.quote = "`";
    }
    return { text: character, skip: 0 };
  }
  return undefined;
}

// Detects a line-comment opener from character and next, the current and following source characters.
// On a match, sets state.isLineComment and returns two spaces with skip 1; otherwise returns undefined for the next detector.
function maskLineCommentStart(character: string, next: string, state: MaskState): MaskStep | undefined {
  if (character === "/" && next === "/") {
    state.isLineComment = true;
    return { text: "  ", skip: 1 };
  }
  return undefined;
}

// Detects a block-comment opener from character and next, the current and following source characters.
// On a match, sets state.isBlockComment and returns two spaces with skip 1; otherwise returns undefined for the next detector.
function maskBlockCommentStart(character: string, next: string, state: MaskState): MaskStep | undefined {
  if (character === "/" && next === "*") {
    state.isBlockComment = true;
    return { text: "  ", skip: 1 };
  }
  return undefined;
}

// Returns character with skip 0 on a recognized regex opener, updating state.isRegex and state.previousCode.
// source supplies up to 80 characters before index as context; character is the current source character and state holds the prior code.
// Returns undefined for other characters or contexts so the caller can try the next detector.
function maskRegexStart(source: string, index: number, character: string, state: MaskState): MaskStep | undefined {
  if (character === "/" && isRegexLiteralStart(state.previousCode, source.slice(Math.max(0, index - 80), index))) {
    state.isRegex = true;
    state.previousCode = character;
    return { text: character, skip: 0 };
  }
  return undefined;
}

// Returns character with skip 0 when it is a string or template delimiter, updating state.quote and state.previousCode.
// character is the current source character; state carries the masking context. A non-quote returns undefined for the plain-code fallback.
// Later calls mask literal text while keeping quote boundaries and template interpolation code visible.
function maskQuoteStart(character: string, state: MaskState): MaskStep | undefined {
  if (isQuote(character)) {
    state.quote = character;
    state.previousCode = character;
    return { text: character, skip: 0 };
  }
  return undefined;
}

// Code characters survive into the masked output; only non-whitespace updates `previousCode` because
// the regex-start heuristic must look at the last real token, not at the space before it.
function maskPlainCodeCharacter(character: string, state: MaskState): MaskStep {
  if (isNonWhitespaceCharacter(character)) {
    state.previousCode = character;
  }
  return { text: character, skip: 0 };
}

// Returns one space with skip 0, masking one UTF-16 code unit while preserving source offsets.
function maskSingleCharacter(): MaskStep {
  return { text: " ", skip: 0 };
}

// Returns a source line with string bodies and line comments removed, leaving quote delimiters for matching.
// The line-local scanner has no block-comment state.
// Use maskNonCode when rules need to preserve scanner state across lines.
function codeLineForMatching(line: string): string {
  let result = "";
  const state: CodeLineState = { quote: undefined, isEscaped: false };
  for (let index = 0; index < line.length; index += 1) {
    const step = codeLineCharacter(line, index, state);
    result += step.text;
    if (step.shouldStopLine) {
      break;
    }
  }
  return result;
}

// Smaller lexer state: just enough to detect when we're inside a quoted string and skip its body.
interface CodeLineState {
  quote: string | undefined;
  isEscaped: boolean;
}

// One step yields the kept text (empty when masked, original when code) plus a `shouldStopLine` flag set
// once a line comment opens.
interface CodeLineStep {
  text: string;
  shouldStopLine: boolean;
}

// Returns the output text and stop flag for line[index]; line is raw input and index selects the character.
// Mutates state to track string delimiters and escapes, emitting quotes but dropping string bodies.
// A line-comment opener outside a string returns empty text and stops the line; other steps keep scanning.
function codeLineCharacter(line: string, index: number, state: CodeLineState): CodeLineStep {
  const character = line[index] ?? "";
  const next = line[index + 1] ?? "";
  if (!state.quote && character === "/" && next === "/") {
    return { text: "", shouldStopLine: true };
  }
  if (state.quote) {
    return quotedCodeLineCharacter(character, state);
  }
  if (isQuote(character)) {
    state.quote = character;
    return { text: character, shouldStopLine: false };
  }
  return { text: character, shouldStopLine: false };
}

// Suppresses literal contents while keeping the closing quote visible so the caller can see the literal boundary.
// Returns the unescaped closing quote or empty text for any other character. The stop flag is always false inside the quote.
// Updates state to track escapes and clears the stored quote when the literal closes.
function quotedCodeLineCharacter(character: string, state: CodeLineState): CodeLineStep {
  if (state.isEscaped) {
    state.isEscaped = false;
    return { text: "", shouldStopLine: false };
  }
  if (character === "\\") {
    state.isEscaped = true;
    return { text: "", shouldStopLine: false };
  }
  if (character === state.quote) {
    state.quote = undefined;
    return { text: character, shouldStopLine: false };
  }
  return { text: "", shouldStopLine: false };
}

// Default step: caller advances by one, line continues. Centralised so callers stay symmetrical.
function continueScan(): ScanStep {
  return { skip: 0, shouldStopLine: false };
}

// Returns a step that skips the second character of a two-character token and continues scanning the line.
function skipNextCharacter(): ScanStep {
  return { skip: 1, shouldStopLine: false };
}

// Returns a step that ends the current scan at a line comment so the remaining text contributes no delimiters.
function stopLineScan(): ScanStep {
  return { skip: 0, shouldStopLine: true };
}

// Returns whether character can delimit a single-quoted string, double-quoted string, or template literal.
function isQuote(character: string): boolean {
  return character === "\"" || character === "'" || character === "`";
}

// Used by `maskPlainCodeCharacter` to decide whether a character should overwrite `previousCode`.
// Whitespace must not, otherwise the regex-vs-division heuristic would be fed the wrong token.
function isNonWhitespaceCharacter(character: string): boolean {
  return character !== "" && character !== " " && character !== "\t" && character !== "\r" && character !== "\n";
}

export { codeLineForMatching, maskNonCode, maskTemplateLiteralBodies, parseDiagnostics };
