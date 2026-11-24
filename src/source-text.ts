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

// Lexer state for the delimiter and masking scanner across quotes, comments, regex literals, and nested templates.
//
// - `previousCode` tracks the last non-whitespace code character so `/` disambiguates regex literals from division;
// - `templateInterpolationStack` records the brace depth at each `${` so matching `}` re-enters template text cleanly.
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

/**
 * Builds fresh delimiter-scan state for a new file with no active literal or comment and no prior code character.
 * An empty `previousCode` lets a slash at the start of code open a regex; later code updates that context.
 *
 * @returns Initialized `DelimiterScanState` with cleared literal, comment, and escape flags.
 */
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

/**
 * Updates the supplied delimiter totals and scanner state across one source line.
 * Stops at a line comment because the rest of the line is comment text; block comments, string text, and regex
 * bodies leave counts unchanged while template interpolations resume counting.
 *
 * @param line - Source line text to scan from left to right.
 * @param ctx - Mutable delimiter counts and lexer state updated in place for `line`.
 * @returns Nothing. Mutates `ctx.counts` and `ctx.scan` for each scanned character until EOL or a line comment.
 */
function scanDelimiterLine(line: string, ctx: DelimiterScanContext): void {
  for (let offset = 0; offset < line.length; offset += 1) {
    const step = scanDelimiterCharacter(line, offset, ctx);
    offset += step.skip;
    if (step.shouldStopLine) {
      break;
    }
  }
}

/**
 * Scans `line` at `offset` according to the lexical mode stored in `ctx`, mutating its counts and scan state.
 *
 * @param line - Source line text containing the character to inspect.
 * @param offset - Zero-based index of the current character within `line`.
 * @param ctx - Mutable delimiter counts and lexer state carried across characters.
 * @returns Step telling the line walker whether to continue, skip a character, or stop at a line comment.
 */
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

/**
 * Scans inside a block comment, leaving delimiter counts unchanged until the closing delimiter.
 * Mutates `scan.isInBlockComment` to false on the closer so the next step resumes in code mode.
 *
 * @param character - Current character inside the block comment.
 * @param next - Lookahead character immediately following `character`.
 * @param scan - Mutable lexer state updated when the closing delimiter is matched.
 * @returns Step with `skip: 1` to swallow the trailing `/` on a closer, or a continuing step otherwise.
 */
function scanBlockCommentDelimiter(character: string, next: string, scan: DelimiterScanState): ScanStep {
  if (character === "*" && next === "/") {
    scan.isInBlockComment = false;
    return skipNextCharacter();
  }
  return continueScan();
}

/**
 * Scans inside a quoted literal, mutating quote, escape, and template-interpolation state in `ctx`.
 * Escapes protect the next character; template interpolation saves brace depth and resumes code until its closing brace.
 *
 * @param character - Current character inside the quoted literal.
 * @param next - Lookahead character immediately following `character`.
 * @param ctx - Mutable delimiter counts and lexer state updated on escapes, quotes, or `${`.
 * @returns Continuing step, or a skip step after `${` so the opening brace is not re-counted.
 */
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

/**
 * Scans inside a regex literal, mutating `scan` for escapes, character classes, and the closing slash.
 * Closing slash is only honoured when `isInRegexCharClass` is false because `[...]` can contain `/`.
 *
 * @param character - Current character inside the regex literal body.
 * @param scan - Mutable lexer state updated for escapes, `[` / `]` class boundaries, and regex exit.
 * @returns Nothing. Mutates `scan` in place and sets `scan.previousCode` to `"x"` when the regex closes.
 */
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

/**
 * Classifies `character` and lookahead `next` in executable code, using `line` and `offset` for regex detection.
 * Mutates delimiter counts and lexical state in `ctx` according to the matched token handler.
 *
 * @param line - Source line text providing preceding context for the regex-opening heuristic.
 * @param offset - Zero-based index of `character` in `line`.
 * @param character - Current character in executable code.
 * @param next - Lookahead character immediately following `character`.
 * @param ctx - Mutable delimiter counts and lexer state updated by the matching token handler.
 * @returns Matched token's scan step, or the ordinary-code step when no opener matches.
 */
function scanCodeDelimiter(line: string, offset: number, character: string, next: string, ctx: DelimiterScanContext): ScanStep {
  return (
    scanLineCommentStart(character, next) ??
    scanBlockCommentStart(character, next, ctx.scan) ??
    scanQuoteStart(character, ctx.scan) ??
    scanRegexStart(line, offset, character, ctx.scan) ??
    scanPlainCodeDelimiter(character, ctx)
  );
}

/**
 * Detects a `//` line-comment opener that ends delimiter scanning for the remainder of the line.
 *
 * @param character - Current character in executable code.
 * @param next - Lookahead character immediately following `character`.
 * @returns Stopping step when `//` is matched, or `undefined` to try another token kind.
 */
function scanLineCommentStart(character: string, next: string): ScanStep | undefined {
  if (character === "/" && next === "/") {
    return stopLineScan();
  }
  return undefined;
}

/**
 * Detects a block-comment opener (`/*`) and mutates `scan.isInBlockComment` so following text is skipped.
 * Uses `skip: 1` to swallow the `*` so it is not re-evaluated as part of a closer.
 *
 * @param character - Current character in executable code.
 * @param next - Lookahead character immediately following `character`.
 * @param scan - Mutable lexer state updated when a block comment opens.
 * @returns Skip step when a block comment opens, or `undefined` to try another token handler.
 */
function scanBlockCommentStart(character: string, next: string, scan: DelimiterScanState): ScanStep | undefined {
  if (character === "/" && next === "*") {
    scan.isInBlockComment = true;
    return skipNextCharacter();
  }
  return undefined;
}

/**
 * Recognises a string or template quote opener and stores it in `scan.quote`.
 *
 * @param character - Current character in executable code.
 * @param scan - Mutable lexer state updated with the active quote delimiter on match.
 * @returns Continuing step when `character` is a quote, or `undefined` to try another token kind.
 */
function scanQuoteStart(character: string, scan: DelimiterScanState): ScanStep | undefined {
  if (isQuote(character)) {
    scan.quote = character;
    return continueScan();
  }
  return undefined;
}

/**
 * Distinguishes a regex literal opener from division using `scan.previousCode` and the line prefix before `offset`.
 * Mutates `scan` regex flags when `/` opens a regex literal.
 *
 * @param line - Source line text containing the candidate slash.
 * @param offset - Zero-based index of `character` in `line`.
 * @param character - Current character in executable code.
 * @param scan - Mutable lexer state supplying `previousCode` and receiving updated regex flags.
 * @returns Continuing step on a regex opener, or `undefined` for the next token handler.
 */
function scanRegexStart(line: string, offset: number, character: string, scan: DelimiterScanState): ScanStep | undefined {
  if (character === "/" && isRegexLiteralStart(scan.previousCode, line.slice(0, offset))) {
    scan.isInRegex = true;
    scan.isInRegexCharClass = false;
    scan.isRegexEscaped = false;
    return continueScan();
  }
  return undefined;
}

/**
 * Counts `character` in `ctx.counts` and updates `ctx.scan` so later slashes classify as regex or division.
 * Ignores whitespace when recording `previousCode`; a closing interpolation brace restores template-literal mode.
 *
 * @param character - Current ordinary character in executable code.
 * @param ctx - Mutable delimiter counts and lexer state updated in place.
 * @returns Continuing scan step after updating counts and interpolation/code state.
 */
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

/**
 * Updates the supplied delimiter totals for `character` by incrementing on openers and decrementing on closers.
 * Other characters are ignored so callers can pass every code character unconditionally.
 *
 * @param character - Character tested against `{`, `}`, `(`, `)`, `[`, and `]`.
 * @param counts - Mutable delimiter totals updated in place.
 * @returns Nothing. Mutates `counts` when `character` is a tracked delimiter.
 */
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

/**
 * Checks whether `counts` has any negative brace, parenthesis, or bracket balance from a closer without an opener.
 *
 * @param counts - Running delimiter totals to inspect.
 * @returns True if any delimiter balance is below zero; otherwise false.
 */
function hasNegativeDelimiterCount(counts: DelimiterCounts): boolean {
  return counts.braces < 0 || counts.parentheses < 0 || counts.brackets < 0;
}

/**
 * Checks whether `counts` has any nonzero brace, parenthesis, or bracket balance indicating unmatched delimiters.
 *
 * @param counts - Final delimiter totals at end of file.
 * @returns True if any delimiter count is nonzero; otherwise false.
 */
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

/**
 * Determines whether a slash looks like a regex opener using a conservative heuristic to avoid masking real code.
 * Empty `previousCode`, selected punctuation, or trailing `return` before the slash permits a regex.
 *
 * @param previousCode - Last non-whitespace code character, synthetic operand marker, or empty start marker.
 * @param beforeSlash - Preceding line slice before the candidate `/` character.
 * @returns True when the slash context permits a regex literal opener; otherwise false.
 */
function isRegexLiteralStart(previousCode: string, beforeSlash: string): boolean {
  return previousCode === "" || "([{=,:!&|?;".includes(previousCode) || /\breturn$/.test(beforeSlash.trimEnd());
}

/**
 * Masks recognized comment and literal bodies in `source` while preserving UTF-16 code-unit offsets and newlines.
 * Regex-driven rules use the unchanged positions to report source locations without matching text inside those bodies.
 *
 * @param source - Raw source file text to mask.
 * @returns Copy of `source` with comment, string, template, and regex bodies replaced by spaces.
 */
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

/**
 * Masks template-literal bodies in `source` with spaces while preserving offsets and line-feed characters.
 * Single- and double-quoted bodies remain visible so syntax-pattern rules can read real import specifiers.
 *
 * @param source - Raw source file text to mask.
 * @returns Copy of `source` with backtick template contents replaced by spaces.
 */
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

/**
 * Creates fresh default state for a single-file template-mask pass.
 *
 * @returns Initialized `TemplateMaskState` with no active quote or comment context.
 */
function templateMaskState(): TemplateMaskState {
  return { quote: undefined, isEscaped: false, isLineComment: false, isBlockComment: false };
}

/**
 * Transforms `character` with lookahead `next` for template-body masking, mutating `state` in place.
 * Preserves delimiters, newlines, single/double-quoted strings, and comments while masking template body text.
 *
 * @param character - Current character from the source text.
 * @param next - Lookahead character immediately following `character`.
 * @param state - Mutable quote and comment context carried across characters.
 * @returns Output text and extra-character skip count; regex literals receive no dedicated handling.
 */
function templateMaskCharacter(character: string, next: string, state: TemplateMaskState): MaskStep {
  if (character === "\n") return templateMaskNewline(state);
  if (state.isLineComment) return { text: character, skip: 0 };
  if (state.isBlockComment) return templateMaskBlockComment(character, next, state);
  if (state.quote) return templateMaskQuotedCharacter(character, state);
  return templateMaskCodeCharacter(character, next, state);
}

/**
 * Clears line-comment state and any non-template quote at a newline while preserving template-literal mode.
 *
 * @param state - Mutable template-mask state updated in place at the line boundary.
 * @returns Step emitting `"\n"` with no extra-character skip.
 */
function templateMaskNewline(state: TemplateMaskState): MaskStep {
  state.isLineComment = false;
  if (state.quote !== "`") {
    state.quote = undefined;
  }
  return { text: "\n", skip: 0 };
}

/**
 * Preserves block-comment text and clears `state.isBlockComment` when the closing delimiter is reached.
 *
 * @param character - Current character inside the block comment.
 * @param next - Lookahead character immediately following `character`.
 * @param state - Mutable template-mask state updated on a block-comment closer.
 * @returns Preserved text with `skip: 1` on the closing pair, or `skip: 0` otherwise.
 */
function templateMaskBlockComment(character: string, next: string, state: TemplateMaskState): MaskStep {
  if (character === "*" && next === "/") {
    state.isBlockComment = false;
    return { text: "*/", skip: 1 };
  }
  return { text: character, skip: 0 };
}

/**
 * Processes a character inside a quoted literal, masking backtick bodies while passing single/double quotes through.
 * Preserves an unescaped closing quote and mutates escape and quote flags in `state`.
 *
 * @param character - Current character inside the active literal.
 * @param state - Mutable template-mask state tracking escapes and the active quote delimiter.
 * @returns Transformed character step with `skip: 0`.
 */
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

/**
 * Detects comment openers and the three quote types in code, passing ordinary characters through unchanged.
 * Mutates `state` when a comment or quote opener is matched.
 *
 * @param character - Current character in code context.
 * @param next - Lookahead character immediately following `character`.
 * @param state - Mutable template-mask state updated on comment or quote entry.
 * @returns Preserved text and extra-character skip count (`1` for comment openers, `0` otherwise).
 */
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

/**
 * Builds fresh `MaskState` with all flags cleared so the first scanner step treats source as code.
 *
 * @returns Initialized `MaskState` with empty prior code and no active literal or comment flags.
 */
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

/**
 * Masks or preserves `source[index]` according to `state`, mutating `state` as comments and literals open or close.
 * Newlines end line comments and single-line quote or regex state while template literals and block comments remain active.
 *
 * @param source - Complete source text being masked.
 * @param index - Zero-based UTF-16 offset of the current character in `source`.
 * @param state - Mutable masking context carried across characters.
 * @returns Output text and extra-character skip count for the current character or opener/closer pair.
 */
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

/**
 * Updates `state` at a newline by clearing line-comment, single-quote, double-quote, and regex modes.
 * Keeps template-literal and block-comment modes because both can span lines, preserving source offsets.
 *
 * @param state - Mutable mask state updated in place at the newline.
 * @returns Step emitting `"\n"` with `skip: 0`.
 */
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

/**
 * Replaces block-comment text with spaces, turning the closing delimiter into two spaces to preserve character alignment.
 * Clears `state.isBlockComment` when the closing pair is consumed.
 *
 * @param character - Current character inside the block comment.
 * @param next - Lookahead character immediately following `character`.
 * @param state - Mutable mask state updated when the block comment closes.
 * @returns Two spaces with `skip: 1` on a closer, or a single masked space step otherwise.
 */
function maskBlockComment(character: string, next: string, state: MaskState): MaskStep {
  if (character === "*" && next === "/") {
    state.isBlockComment = false;
    return { text: "  ", skip: 1 };
  }
  return maskSingleCharacter();
}

/**
 * Masks characters inside a quoted literal while keeping the closing quote and template `${` openers visible.
 * Mutates `state` for escapes, closing quotes, and pushing brace depth when a template interpolation opens.
 *
 * @param character - Current character inside the quoted literal.
 * @param next - Lookahead character immediately following `character`.
 * @param state - Mutable mask state tracking escape, quote, and template interpolation stack state.
 * @returns Masking step with spaces for literal body text, `"${"` on interpolation, or the closing quote.
 */
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

/**
 * Masks regex literal body characters and passes through the closing `/`, tracking escapes and `[...]` classes.
 * Character classes suspend the closing-slash check so `/[/]/` does not terminate at the inner slash.
 *
 * @param character - Current character inside the regex literal.
 * @param state - Mutable mask state updated for escapes, class boundaries, and regex exit.
 * @returns Space-mask step for body characters, or the closing `/` with `skip: 0`.
 */
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

/**
 * Dispatches code-context masking for `source[index]`, mutating `state` on openers, braces, or code tokens.
 * Checks comment openers before regex starts so a comment opener cannot enter regex mode, preserving offsets.
 *
 * @param source - Complete source text used to inspect context before a candidate regex slash.
 * @param index - Zero-based offset of `character` in `source`.
 * @param character - Current character in code context.
 * @param next - Lookahead character immediately following `character`.
 * @param state - Mutable mask state updated by the matching detector or plain-code fallback.
 * @returns Output text and extra-character skip count from the first matching detector.
 */
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

/**
 * Tracks `{` and `}` inside the active template interpolation, mutating only its innermost brace depth.
 * Closing the final brace pops the interpolation entry and resumes template-body masking.
 *
 * @param character - Current character in code context.
 * @param state - Mutable mask state carrying `templateInterpolationDepths` and `previousCode`.
 * @returns Step preserving the brace with `skip: 0`, or `undefined` outside interpolations or for other characters.
 */
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

/**
 * Detects a `//` line-comment opener and mutates `state.isLineComment` so the rest of the line is masked.
 *
 * @param character - Current character in code context.
 * @param next - Lookahead character immediately following `character`.
 * @param state - Mutable mask state updated when a line comment starts.
 * @returns Two spaces with `skip: 1` on match, or `undefined` for the next detector.
 */
function maskLineCommentStart(character: string, next: string, state: MaskState): MaskStep | undefined {
  if (character === "/" && next === "/") {
    state.isLineComment = true;
    return { text: "  ", skip: 1 };
  }
  return undefined;
}

/**
 * Detects a block-comment opener (`/*`) and mutates `state.isBlockComment` so comment text is masked.
 *
 * @param character - Current character in code context.
 * @param next - Lookahead character immediately following `character`.
 * @param state - Mutable mask state updated when a block comment starts.
 * @returns Two spaces with `skip: 1` on match, or `undefined` for the next detector.
 */
function maskBlockCommentStart(character: string, next: string, state: MaskState): MaskStep | undefined {
  if (character === "/" && next === "*") {
    state.isBlockComment = true;
    return { text: "  ", skip: 1 };
  }
  return undefined;
}

/**
 * Detects a regex literal opener using up to 80 characters before `index` and mutates `state.isRegex`.
 *
 * @param source - Complete source text supplying preceding context for the regex-start heuristic.
 * @param index - Zero-based offset of `character` in `source`.
 * @param character - Current character in code context.
 * @param state - Mutable mask state supplying `previousCode` and updated on regex entry.
 * @returns Step preserving `/` with `skip: 0` on match, or `undefined` for the next detector.
 */
function maskRegexStart(source: string, index: number, character: string, state: MaskState): MaskStep | undefined {
  if (character === "/" && isRegexLiteralStart(state.previousCode, source.slice(Math.max(0, index - 80), index))) {
    state.isRegex = true;
    state.previousCode = character;
    return { text: character, skip: 0 };
  }
  return undefined;
}

/**
 * Detects a string or template quote opener and mutates `state.quote` and `state.previousCode`.
 * Later calls mask literal text while keeping quote boundaries and template interpolation code visible.
 *
 * @param character - Current character in code context.
 * @param state - Mutable mask state updated with the active quote delimiter.
 * @returns Step preserving the quote with `skip: 0` on match, or `undefined` for the plain-code fallback.
 */
function maskQuoteStart(character: string, state: MaskState): MaskStep | undefined {
  if (isQuote(character)) {
    state.quote = character;
    state.previousCode = character;
    return { text: character, skip: 0 };
  }
  return undefined;
}

/**
 * Passes an ordinary code character through into masked output, updating `state.previousCode` only for non-whitespace.
 * Only non-whitespace updates `previousCode` because the regex-start heuristic must see the last real token.
 *
 * @param character - Current ordinary character in code context.
 * @param state - Mutable mask state whose `previousCode` is updated for non-whitespace characters.
 * @returns Step preserving `character` with `skip: 0`.
 */
function maskPlainCodeCharacter(character: string, state: MaskState): MaskStep {
  if (isNonWhitespaceCharacter(character)) {
    state.previousCode = character;
  }
  return { text: character, skip: 0 };
}

/**
 * Builds a single-space mask step to obscure one UTF-16 code unit while preserving source offsets.
 *
 * @returns `MaskStep` emitting `" "` with `skip: 0`.
 */
function maskSingleCharacter(): MaskStep {
  return { text: " ", skip: 0 };
}

/**
 * Strips string bodies and line comments from a single line while leaving quote delimiters for matching.
 * This line-local scanner has no block-comment state; use `maskNonCode` to preserve state across lines.
 *
 * @param line - Single source line to strip for local pattern matching.
 * @returns Line text with quoted contents and trailing line comments removed.
 */
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

/**
 * Evaluates `line[index]` for line-local matching, mutating `state` to track string delimiters and escapes.
 * A line-comment opener outside a string emits empty text and stops the line; other characters continue scanning.
 *
 * @param line - Raw source line being scanned.
 * @param index - Zero-based offset of the current character in `line`.
 * @param state - Mutable quote and escape state carried along the line.
 * @returns Output text (keeping quotes and code, dropping string bodies) and `shouldStopLine` flag.
 */
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

/**
 * Suppresses quoted literal contents while keeping the unescaped closing quote visible as the literal boundary.
 * Mutates `state` to track escapes and clears `state.quote` when the literal closes.
 *
 * @param character - Current character inside the quoted literal.
 * @param state - Mutable quote and escape state updated in place.
 * @returns Closing quote or empty text, always with `shouldStopLine: false`.
 */
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

/**
 * Default scan step advancing by one character while keeping the line scan active.
 *
 * @returns `ScanStep` with `skip: 0` and `shouldStopLine: false`.
 */
function continueScan(): ScanStep {
  return { skip: 0, shouldStopLine: false };
}

/**
 * Builds a scan step that skips the second character of a two-character token and keeps scanning.
 *
 * @returns `ScanStep` with `skip: 1` and `shouldStopLine: false`.
 */
function skipNextCharacter(): ScanStep {
  return { skip: 1, shouldStopLine: false };
}

/**
 * Builds a scan step that ends the current line scan at a line comment so remaining text contributes no delimiters.
 *
 * @returns `ScanStep` with `skip: 0` and `shouldStopLine: true`.
 */
function stopLineScan(): ScanStep {
  return { skip: 0, shouldStopLine: true };
}

/**
 * Checks whether `character` can delimit a single-quoted string, double-quoted string, or template literal.
 *
 * @param character - Single character to check against `"`, `'`, and `` ` ``.
 * @returns True when `character` is one of the three JS/TS quote delimiters; otherwise false.
 */
function isQuote(character: string): boolean {
  return character === "\"" || character === "'" || character === "`";
}

/**
 * Checks whether `character` is non-empty and not horizontal or vertical ASCII whitespace.
 * Used by `maskPlainCodeCharacter` so whitespace must not overwrite `previousCode` for the regex heuristic.
 *
 * @param character - Character inspected before updating `previousCode`.
 * @returns True if `character` is non-empty and not space, tab, CR, or LF; otherwise false.
 */
function isNonWhitespaceCharacter(character: string): boolean {
  return character !== "" && character !== " " && character !== "\t" && character !== "\r" && character !== "\n";
}

export { codeLineForMatching, maskNonCode, maskTemplateLiteralBodies, parseDiagnostics };
