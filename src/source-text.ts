/**
 * Provides lightweight source text scanners that separate executable TypeScript
 * from comments, strings, and regex bodies before rule matching runs.
 */
import type { RunDiagnostic } from "./types.ts";

// Just enough of `SourceFile` to keep `parseDiagnostics` decoupled from the full project type:
// `isScript` gates whether to run the delimiter check; `displayPath` is the report-path anchor.
interface DiagnosticSourceFile {
  displayPath: string;
  isScript: boolean;
}

/**
 * Checks TypeScript or JavaScript source for obviously unbalanced delimiters.
 *
 * @param file - Source metadata used to skip non-script inputs and report paths.
 * @param source - Raw file text to scan for delimiter balance.
 */
function parseDiagnostics(file: DiagnosticSourceFile, source: string): RunDiagnostic[] {
  if (!file.isScript) {
    return [];
  }
  const ctx: DelimiterScanContext = {
    scan: defaultDelimiterScanState(),
    counts: { braces: 0, parentheses: 0, brackets: 0 },
  };
  const lines = source.split(/\r?\n/);
  for (const [index, line] of lines.entries()) {
    scanDelimiterLine(line, ctx);
    if (hasNegativeDelimiterCount(ctx.counts)) {
      return [parseErrorDiagnostic(file, index + 1)];
    }
  }
  if (hasUnbalancedDelimiterCount(ctx.counts)) {
    return [parseErrorDiagnostic(file, lines.length)];
  }
  return [];
}

// Running totals for `{}`, `()`, and `[]`. A negative count means a closer appeared with no opener
// and is reported as a `parse-error` at that line; a non-zero final value is reported at EOF.
interface DelimiterCounts {
  braces: number;
  parentheses: number;
  brackets: number;
}

// Lexer state for the delimiter scanner. `previousCode` is the last non-whitespace executable
// character — required because `/` may start a regex or a division depending on what came before.
interface DelimiterScanState {
  quote: string | undefined;
  escaped: boolean;
  blockComment: boolean;
  regex: boolean;
  regexCharClass: boolean;
  regexEscaped: boolean;
  previousCode: string;
}

// Bundles state + counts so per-character handlers can mutate both without threading two arguments.
interface DelimiterScanContext {
  scan: DelimiterScanState;
  counts: DelimiterCounts;
}

// Per-character scanner result. `skip` consumes the next N characters (e.g. the `/` of `*/`);
// `stopLine` bails out of the rest of the line when a `//` line comment starts.
interface ScanStep {
  skip: number;
  stopLine: boolean;
}

// All flags begin false / quote unset. `previousCode` starts empty so the first `/` in a file
// is treated as a regex opener (matches the JS grammar at program start).
function defaultDelimiterScanState(): DelimiterScanState {
  return {
    quote: undefined,
    escaped: false,
    blockComment: false,
    regex: false,
    regexCharClass: false,
    regexEscaped: false,
    previousCode: "",
  };
}

// Walks one line, mutating `ctx.counts` and `ctx.scan` in place. The `stopLine` step is the only
// way out before line end; comment, string, and regex bodies merely advance offset without counting.
function scanDelimiterLine(line: string, ctx: DelimiterScanContext): void {
  for (let offset = 0; offset < line.length; offset += 1) {
    const step = scanDelimiterCharacter(line, offset, ctx);
    offset += step.skip;
    if (step.stopLine) {
      break;
    }
  }
}

// State-machine dispatch: block-comment, string, regex, or code. Order matters — once inside a
// block comment, characters must not be re-interpreted as a quote or regex opener.
function scanDelimiterCharacter(line: string, offset: number, ctx: DelimiterScanContext): ScanStep {
  const character = line[offset] ?? "";
  const next = line[offset + 1] ?? "";
  if (ctx.scan.blockComment) {
    return scanBlockCommentDelimiter(character, next, ctx.scan);
  }
  if (ctx.scan.quote) {
    scanQuotedDelimiter(character, ctx.scan);
    return continueScan();
  }
  if (ctx.scan.regex) {
    scanRegexDelimiter(character, ctx.scan);
    return continueScan();
  }
  return scanCodeDelimiter(line, offset, character, next, ctx);
}

// Inside `/* ... */`. Returns `skip: 1` to swallow the `/` of the closing `*/`, then the next
// step resumes in code mode. Block-comment contents do not affect delimiter counts.
function scanBlockCommentDelimiter(character: string, next: string, scan: DelimiterScanState): ScanStep {
  if (character === "*" && next === "/") {
    scan.blockComment = false;
    return skipNextCharacter();
  }
  return continueScan();
}

// Inside a string or template literal. `\` arms `escaped` so the next character (including a
// closing quote) is treated as literal text. Necessary to handle `"\\\""` and similar correctly.
function scanQuotedDelimiter(character: string, scan: DelimiterScanState): void {
  if (scan.escaped) {
    scan.escaped = false;
  } else if (character === "\\") {
    scan.escaped = true;
  } else if (character === scan.quote) {
    scan.quote = undefined;
  }
}

// Inside `/regex/`. `[...]` character classes can legally contain `/`, so the closing slash
// is only honoured when `regexCharClass` is false; otherwise `/[/]/` would terminate early.
function scanRegexDelimiter(character: string, scan: DelimiterScanState): void {
  if (scan.regexEscaped) {
    scan.regexEscaped = false;
  } else if (character === "\\") {
    scan.regexEscaped = true;
  } else if (character === "[") {
    scan.regexCharClass = true;
  } else if (character === "]") {
    scan.regexCharClass = false;
  } else if (character === "/" && !scan.regexCharClass) {
    scan.regex = false;
    scan.previousCode = "x";
  }
}

// In executable code. The chain order (line comment → block comment → quote → regex → plain) is
// deliberate: line comments must win over block-comment openers because `/* /* */` is one comment.
function scanCodeDelimiter(line: string, offset: number, character: string, next: string, ctx: DelimiterScanContext): ScanStep {
  return (
    scanLineCommentStart(character, next) ??
    scanBlockCommentStart(character, next, ctx.scan) ??
    scanQuoteStart(character, ctx.scan) ??
    scanRegexStart(line, offset, character, ctx.scan) ??
    scanPlainCodeDelimiter(character, ctx)
  );
}

// `//` ends the line for delimiter purposes — anything to the right is comment text.
function scanLineCommentStart(character: string, next: string): ScanStep | undefined {
  if (character === "/" && next === "/") {
    return stopLineScan();
  }
  return undefined;
}

// `/*` flips the scanner into block-comment mode; `skip: 1` swallows the `*` so it isn't re-evaluated.
function scanBlockCommentStart(character: string, next: string, scan: DelimiterScanState): ScanStep | undefined {
  if (character === "/" && next === "*") {
    scan.blockComment = true;
    return skipNextCharacter();
  }
  return undefined;
}

// Records which quote character opened the literal so the scanner closes on the same kind.
function scanQuoteStart(character: string, scan: DelimiterScanState): ScanStep | undefined {
  if (isQuote(character)) {
    scan.quote = character;
    return continueScan();
  }
  return undefined;
}

// `/` is ambiguous in JS — it can start a regex or be division. `isRegexLiteralStart` decides based
// on the previous non-whitespace token; getting this wrong would let division `a / b / c` enter
// regex mode and absorb everything to the next slash.
function scanRegexStart(line: string, offset: number, character: string, scan: DelimiterScanState): ScanStep | undefined {
  if (character === "/" && isRegexLiteralStart(scan.previousCode, line.slice(0, offset))) {
    scan.regex = true;
    scan.regexCharClass = false;
    scan.regexEscaped = false;
    return continueScan();
  }
  return undefined;
}

// Updates the delimiter tallies and remembers this character as `previousCode` so the next `/`
// can decide regex-vs-division. Whitespace is not recorded; it would corrupt the regex heuristic.
function scanPlainCodeDelimiter(character: string, ctx: DelimiterScanContext): ScanStep {
  countDelimiter(character, ctx.counts);
  if (character.trim() !== "") {
    ctx.scan.previousCode = character;
  }
  return continueScan();
}

// Increment on opener, decrement on closer. Other characters are no-ops so the function can be
// called unconditionally per character without a guard in the caller.
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

// Negative on any of the three means a closer ran ahead of its opener — caller reports immediately
// at the current line because the original mismatch is local, not at EOF.
function hasNegativeDelimiterCount(counts: DelimiterCounts): boolean {
  return counts.braces < 0 || counts.parentheses < 0 || counts.brackets < 0;
}

// Non-zero after the whole file means an opener was never closed. Caller reports at EOF.
function hasUnbalancedDelimiterCount(counts: DelimiterCounts): boolean {
  return counts.braces !== 0 || counts.parentheses !== 0 || counts.brackets !== 0;
}

/*
 * Emits a `parse-error` diagnostic. The CLI exit contract forces a non-zero exit (see `exitFor`)
 * whenever diagnostics fire — this builder reports failures so a broken file in the scan tree
 * cannot hide silently rather than throw the error or recover quietly.
 */
function parseErrorDiagnostic(file: DiagnosticSourceFile, line: number): RunDiagnostic {
  return {
    diagnosticType: "parse-error",
    message: "Unbalanced TypeScript delimiters detected.",
    filePath: file.displayPath,
    line,
  };
}

// Heuristic for the regex-vs-division ambiguity: `/` is a regex opener after operators, control
// punctuation, or `return`; otherwise it's division. False positives would expand a regex across
// real code and break delimiter balance, so this list is intentionally conservative.
function isRegexLiteralStart(previousCode: string, beforeSlash: string): boolean {
  return previousCode === "" || "([{=,:!&|?;".includes(previousCode) || /\breturn$/.test(beforeSlash.trimEnd());
}

// Returns `source` with comments, strings, and regex bodies replaced by spaces. Line and column
// offsets are preserved so callers can map matches back to the original — this is the standard
// pre-filter for any rule that must run regex against "code shape only".
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
  };
}

// Newlines short-circuit first — single-line `//` comments must clear at line end, and ordinary
// quotes do too, but template literals (` ` `) survive across lines.
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
    return maskQuotedCharacter(character, state);
  }
  if (state.isRegex) {
    return maskRegexCharacter(character, state);
  }
  return maskCodeCharacter(source, index, character, next, state);
}

// At a newline: drop line-comment / single-quote / regex state, but preserve template-literal state
// because backtick strings legitimately span multiple lines. Emits `\n` verbatim to keep offsets aligned.
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
// characters line up with the two consumed characters.
function maskBlockComment(character: string, next: string, state: MaskState): MaskStep {
  if (character === "*" && next === "/") {
    state.isBlockComment = false;
    return { text: "  ", skip: 1 };
  }
  return maskSingleCharacter();
}

// Inside a string: mask body characters but emit the closing quote unchanged so downstream rules
// can still see the quote boundary. `\` arms `isEscaped` to keep the next character literal.
function maskQuotedCharacter(character: string, state: MaskState): MaskStep {
  if (state.isEscaped) {
    state.isEscaped = false;
    return maskSingleCharacter();
  }
  if (character === "\\") {
    state.isEscaped = true;
    return maskSingleCharacter();
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

// Dispatch order in code mode matters: detect comment openers before regex, since `/*` would
// otherwise be misread as a regex start; detect regex before quote because no quote begins with `/`.
function maskCodeCharacter(source: string, index: number, character: string, next: string, state: MaskState): MaskStep {
  return (
    maskLineCommentStart(character, next, state) ??
    maskBlockCommentStart(character, next, state) ??
    maskRegexStart(source, index, character, state) ??
    maskQuoteStart(character, state) ??
    maskPlainCodeCharacter(character, state)
  );
}

// Detects `//` and arms line-comment mode; the actual masking happens on subsequent characters
// via the `state.isLineComment` branch in `maskNonCodeCharacter`.
function maskLineCommentStart(character: string, next: string, state: MaskState): MaskStep | undefined {
  if (character === "/" && next === "/") {
    state.isLineComment = true;
    return { text: "  ", skip: 1 };
  }
  return undefined;
}

// Detects `/*` and masks the two opener characters. State flips so subsequent chars route to `maskBlockComment`.
function maskBlockCommentStart(character: string, next: string, state: MaskState): MaskStep | undefined {
  if (character === "/" && next === "*") {
    state.isBlockComment = true;
    return { text: "  ", skip: 1 };
  }
  return undefined;
}

// Same regex-vs-division heuristic as `parseDiagnostics`, but with up to 80 prior characters of
// context (rather than just one) to recognise the `return /pattern/` case across multi-token expressions.
function maskRegexStart(source: string, index: number, character: string, state: MaskState): MaskStep | undefined {
  if (character === "/" && isRegexLiteralStart(state.previousCode, source.slice(Math.max(0, index - 80), index))) {
    state.isRegex = true;
    state.previousCode = character;
    return { text: character, skip: 0 };
  }
  return undefined;
}

// Opening quote is emitted unchanged so downstream rules can detect string boundaries; subsequent
// body characters get masked by `maskQuotedCharacter`.
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

// One space per masked byte. Preserves overall length so byte offsets in masked text map 1:1 to source.
function maskSingleCharacter(): MaskStep {
  return { text: " ", skip: 0 };
}

// Cheaper, line-local mask used when rules don't need full lexer state — strips line-comments and
// string bodies but does not track block comments. Use `maskNonCode` instead when state must
// survive across lines.
function codeLineForMatching(line: string): string {
  let result = "";
  const state: CodeLineState = { quote: undefined, isEscaped: false };
  for (let index = 0; index < line.length; index += 1) {
    const step = codeLineCharacter(line, index, state);
    result += step.text;
    if (step.stopLine) {
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

// One step yields the kept text (empty when masked, original when code) plus a `stopLine` flag set
// once a line comment opens.
interface CodeLineStep {
  text: string;
  stopLine: boolean;
}

// Quotes are emitted (so callers can see the literal boundary) but their bodies are dropped, while
// any `//` outside a string truncates the rest of the line.
function codeLineCharacter(line: string, index: number, state: CodeLineState): CodeLineStep {
  const character = line[index] ?? "";
  const next = line[index + 1] ?? "";
  if (!state.quote && character === "/" && next === "/") {
    return { text: "", stopLine: true };
  }
  if (state.quote) {
    return quotedCodeLineCharacter(character, state);
  }
  if (isQuote(character)) {
    state.quote = character;
    return { text: character, stopLine: false };
  }
  return { text: character, stopLine: false };
}

// Body characters of a string are dropped so `"// not a comment"` doesn't truncate the line, but
// the closing quote is emitted so the caller still sees a balanced literal.
function quotedCodeLineCharacter(character: string, state: CodeLineState): CodeLineStep {
  if (state.isEscaped) {
    state.isEscaped = false;
    return { text: "", stopLine: false };
  }
  if (character === "\\") {
    state.isEscaped = true;
    return { text: "", stopLine: false };
  }
  if (character === state.quote) {
    state.quote = undefined;
    return { text: character, stopLine: false };
  }
  return { text: "", stopLine: false };
}

// Default step: caller advances by one, line continues. Centralised so callers stay symmetrical.
function continueScan(): ScanStep {
  return { skip: 0, stopLine: false };
}

// Skip one extra character — used to swallow the second half of a two-character token like `*/`.
function skipNextCharacter(): ScanStep {
  return { skip: 1, stopLine: false };
}

// End-of-line short circuit returned when a `//` line comment starts.
function stopLineScan(): ScanStep {
  return { skip: 0, stopLine: true };
}

// String, template literal, and char-class quotes recognised by every lexer in this module.
function isQuote(character: string): boolean {
  return character === "\"" || character === "'" || character === "`";
}

// Used by `maskPlainCodeCharacter` to decide whether a character should overwrite `previousCode`.
// Whitespace must not, otherwise the regex-vs-division heuristic would be fed the wrong token.
function isNonWhitespaceCharacter(character: string): boolean {
  return character !== "" && character !== " " && character !== "\t" && character !== "\r" && character !== "\n";
}

export { codeLineForMatching, maskNonCode, parseDiagnostics };
