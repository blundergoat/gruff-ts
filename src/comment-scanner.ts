// Source-text comment lexer. Walks a file once and emits one CommentRecord per `//` or `/* */`
// block. Kept as a leaf module (no gruff imports) so block, line, and comment-rule modules can
// depend on it without forming a cycle.

// One comment block extracted by `commentRecords`. `endLine` differs from `line` for block
// comments; documentation rules need both to compute the gap between comment and declaration.
export interface CommentRecord {
  kind: "line" | "block";
  text: string;
  line: number;
  endLine: number;
  startIndex: number;
  endIndex: number;
}

/** Tracks comment lexer state so string and regex contents are not treated as comments. */
interface CommentScanState {
  quote: string | undefined;
  isEscaped: boolean;
  isRegex: boolean;
  isRegexEscaped: boolean;
  isRegexCharClass: boolean;
  previousCode: string;
  line: number;
}

type CommentScanHandler = (source: string, index: number, state: CommentScanState, records: CommentRecord[]) => number | undefined;

// Source-text comment lexer. Produces the stable list of CommentRecords every documentation rule
// consumes. Walks the file once via the prioritised handler chain (`COMMENT_SCAN_HANDLERS`).
export function commentRecords(source: string): CommentRecord[] {
  const records: CommentRecord[] = [];
  const state = initialCommentScanState();

  for (let index = 0; index < source.length; index += 1) {
    index = advanceCommentRecordScan(source, index, state, records);
  }
  return records;
}

/** Ordered comment lexer steps keep comment detection deterministic and branch-light. */
const COMMENT_SCAN_HANDLERS: CommentScanHandler[] = [
  scanCommentLineBreak,
  scanQuotedCommentStep,
  scanRegexCommentStep,
  scanCommentRecordStep,
  scanQuoteStartStep,
  scanRegexStartStep,
];

/** Runs the first lexer step that can consume the current source character. */
function advanceCommentRecordScan(source: string, index: number, state: CommentScanState, records: CommentRecord[]): number {
  for (const handler of COMMENT_SCAN_HANDLERS) {
    const nextIndex = handler(source, index, state, records);
    if (typeof nextIndex === "number") {
      return nextIndex;
    }
  }
  updateCommentScanPreviousCode(state, source[index] ?? "");
  return index;
}

/** Creates a fresh comment lexer state for a single source file scan. */
function initialCommentScanState(): CommentScanState {
  return {
    quote: undefined,
    isEscaped: false,
    isRegex: false,
    isRegexEscaped: false,
    isRegexCharClass: false,
    previousCode: "",
    line: 1,
  };
}

/** Consumes newlines and resets quote/regex state that cannot cross lines. */
function scanCommentLineBreak(source: string, index: number, state: CommentScanState): number | undefined {
  if ((source[index] ?? "") !== "\n") {
    return undefined;
  }
  advanceCommentScanLine(state);
  return index;
}

/** Advances the lexer after a newline has been consumed. */
function advanceCommentScanLine(state: CommentScanState): void {
  state.line += 1;
  if (state.quote !== "`") {
    state.quote = undefined;
  }
  state.isRegex = false;
  state.isRegexEscaped = false;
  state.isRegexCharClass = false;
}

/** Keeps quoted text from being reported as a real source comment. */
function scanQuotedCommentStep(source: string, index: number, state: CommentScanState): number | undefined {
  return scanActiveQuotedCommentState(state, source[index] ?? "") ? index : undefined;
}

/** Updates quote escape/close state when the lexer is inside a string. */
function scanActiveQuotedCommentState(state: CommentScanState, character: string): boolean {
  if (!state.quote) {
    return false;
  }
  const nextState = scanQuotedCommentCharacter(character, state.quote, state.isEscaped);
  state.quote = nextState.quote;
  state.isEscaped = nextState.isEscaped;
  return true;
}

/** Keeps regex literal bodies from being reported as real source comments. */
function scanRegexCommentStep(source: string, index: number, state: CommentScanState): number | undefined {
  return scanActiveRegexCommentState(state, source[index] ?? "") ? index : undefined;
}

/** Updates regex escape, character-class, and close state. */
function scanActiveRegexCommentState(state: CommentScanState, character: string): boolean {
  if (!state.isRegex) {
    return false;
  }
  const nextState = scanRegexCommentCharacter(character, state.isRegexEscaped, state.isRegexCharClass);
  state.isRegex = nextState.isRegex;
  state.isRegexEscaped = nextState.isEscaped;
  state.isRegexCharClass = nextState.isCharClass;
  return true;
}

/** Records a line or block comment and returns the consumed source index. */
function scanCommentRecordStep(source: string, index: number, state: CommentScanState, records: CommentRecord[]): number | undefined {
  const record = commentRecordAt(source, index, state.line);
  if (!record) {
    return undefined;
  }
  records.push(record);
  state.line = record.endLine;
  return record.kind === "line" ? record.endIndex - 1 : record.endIndex;
}

/** Detects whether the current slash pair begins a source comment. */
function commentRecordAt(source: string, index: number, line: number): CommentRecord | undefined {
  const character = source[index] ?? "";
  const next = source[index + 1] ?? "";
  if (character === "/" && next === "/") {
    return lineCommentRecord(source, index, line);
  }
  if (character === "/" && next === "*") {
    return blockCommentRecord(source, index, line);
  }
  return undefined;
}

/** Opens string/template quote state when the current character starts a literal. */
function scanQuoteStartStep(source: string, index: number, state: CommentScanState): number | undefined {
  return openCommentScanQuote(state, source[index] ?? "") ? index : undefined;
}

/** Mutates quote state after a quote-start character is found. */
function openCommentScanQuote(state: CommentScanState, character: string): boolean {
  if (character !== "\"" && character !== "'" && character !== "`") {
    return false;
  }
  state.quote = character;
  state.isEscaped = false;
  state.previousCode = character;
  return true;
}

/** Opens regex state for slash tokens that follow expression-start syntax. */
function scanRegexStartStep(source: string, index: number, state: CommentScanState): number | undefined {
  return openCommentScanRegex(state, source, index, source[index] ?? "") ? index : undefined;
}

/** Mutates regex state after a regex literal start is found. */
function openCommentScanRegex(state: CommentScanState, source: string, index: number, character: string): boolean {
  if (character !== "/" || !isCommentRegexStart(state.previousCode, source.slice(Math.max(0, index - 40), index))) {
    return false;
  }
  state.isRegex = true;
  state.isRegexEscaped = false;
  state.isRegexCharClass = false;
  state.previousCode = character;
  return true;
}

/** Remembers the last non-whitespace code token for regex/comment disambiguation. */
function updateCommentScanPreviousCode(state: CommentScanState, character: string): void {
  if (/\S/.test(character)) {
    state.previousCode = character;
  }
}

// Pure function returning the next quote state. Pure because callers thread the state explicitly,
// which keeps the comment-lexer testable in isolation from the surrounding mutation.
function scanQuotedCommentCharacter(character: string, quote: string, isEscaped: boolean): { quote: string | undefined; isEscaped: boolean } {
  if (isEscaped) {
    return { quote, isEscaped: false };
  }
  if (character === "\\") {
    return { quote, isEscaped: true };
  }
  if (character === quote) {
    return { quote: undefined, isEscaped: false };
  }
  return { quote, isEscaped: false };
}

// Pure step that yields the next regex state. Same isolation pattern as `scanQuotedCommentCharacter`.
function scanRegexCommentCharacter(character: string, isEscaped: boolean, isCharClass: boolean): { isRegex: boolean; isEscaped: boolean; isCharClass: boolean } {
  if (isEscaped) {
    return { isRegex: true, isEscaped: false, isCharClass };
  }
  if (character === "\\") {
    return { isRegex: true, isEscaped: true, isCharClass };
  }
  if (character === "[") {
    return { isRegex: true, isEscaped: false, isCharClass: true };
  }
  if (character === "]") {
    return { isRegex: true, isEscaped: false, isCharClass: false };
  }
  if (character === "/" && !isCharClass) {
    return { isRegex: false, isEscaped: false, isCharClass: false };
  }
  return { isRegex: true, isEscaped: false, isCharClass };
}

// Same regex-vs-division heuristic as `source-text.ts:isRegexLiteralStart`. Duplicated here so the
// comment lexer stays a leaf with no cross-module dependency on the masking pass.
function isCommentRegexStart(previousCode: string, beforeSlash: string): boolean {
  return previousCode === "" || "([{=,:!&|?;".includes(previousCode) || /\breturn$/.test(beforeSlash.trimEnd());
}

// Line-comment record. `line === endLine` because line comments cannot span newlines. Text is
// captured trimmed so leading/trailing whitespace doesn't enter rule comparisons.
function lineCommentRecord(source: string, startIndex: number, line: number): CommentRecord {
  const newline = source.indexOf("\n", startIndex + 2);
  const endIndex = newline === -1 ? source.length : newline;
  return {
    kind: "line",
    text: source.slice(startIndex + 2, endIndex).trim(),
    line,
    endLine: line,
    startIndex,
    endIndex,
  };
}

// Block-comment record. `endLine > line` is normal for multi-line blocks. `text` is normalised
// (leading-asterisk decoration stripped) so JSDoc-style and plain-block comments compare equally.
function blockCommentRecord(source: string, startIndex: number, line: number): CommentRecord {
  let endIndex = source.length - 1;
  let endLine = line;
  for (let index = startIndex + 2; index < source.length; index += 1) {
    if (source[index] === "\n") {
      endLine += 1;
    }
    if (source[index] === "*" && source[index + 1] === "/") {
      endIndex = index + 1;
      break;
    }
  }
  return {
    kind: "block",
    text: normalizedBlockCommentText(source.slice(startIndex + 2, Math.max(startIndex + 2, endIndex - 1))),
    line,
    endLine,
    startIndex,
    endIndex,
  };
}

// Strips the `* ` JSDoc-style line decoration so `/** foo */`, `/* foo */`, and `// foo` all
// produce the same `text` payload for rule comparison.
function normalizedBlockCommentText(text: string): string {
  return text
    .split(/\r?\n/)
    .map((line) => line.replace(/^[ \t]*\*[ \t]?/, "").trim())
    .filter((line) => line !== "")
    .join(" ")
    .trim();
}

// String-input wrapper around `hasLeadingCommentBeforeLines`. Keeps call sites that already hold
// a split line array from re-splitting on every lookup.
export function hasLeadingCommentBeforeLine(source: string, line: number): boolean {
  return hasLeadingCommentBeforeLines(source.split(/\r?\n/), line);
}

// Skips blank padding above the declaration and asks whether the immediately preceding non-blank
// line is any comment shape (`//`, `/*`, or `*/`). Underlies the missing-comment rules across
// functions, interfaces, and exported declarations.
export function hasLeadingCommentBeforeLines(lines: string[], line: number): boolean {
  let index = line - 2;
  while (index >= 0 && (lines[index] ?? "").trim() === "") {
    index -= 1;
  }
  return index >= 0 && commentTextAtLine(lines, index) !== undefined;
}

// Three comment shapes resolved here: `//` line comments, `/* … */` opener lines, and lines that
// only contain the `*/` closer (call delegates upward to find the opener). Returns undefined for
// non-comment lines and for empty comments, so callers can use truthiness as the "has text" gate.
export function commentTextAtLine(lines: string[], index: number): string | undefined {
  const trimmedLine = (lines[index] ?? "").trim();
  if (trimmedLine.startsWith("//")) {
    const text = trimmedLine.slice(2).trim();
    return text === "" ? undefined : text;
  }
  if (trimmedLine.startsWith("/*")) {
    return blockCommentText(lines, index);
  }
  if (trimmedLine.endsWith("*/")) {
    return blockCommentTextEndingAt(lines, index);
  }
  return undefined;
}

// Walks upward from a `*/` closer to its matching `/*` opener, then delegates to
// `blockCommentText` to extract the joined body. Used when a declaration's leading comment is a
// block comment whose closer sits on the line above the declaration.
function blockCommentTextEndingAt(lines: string[], endIndex: number): string | undefined {
  for (let index = endIndex; index >= 0; index -= 1) {
    if ((lines[index] ?? "").trim().startsWith("/*")) {
      return blockCommentText(lines, index, endIndex);
    }
  }
  return undefined;
}

// Joins a block comment's lines into one normalised text run: strips `/*` / `*/` / leading `*`,
// drops `@tag` lines, and collapses whitespace. The `knownEndIndex` parameter lets
// `blockCommentTextEndingAt` skip the scan when the closer line is already known.
function blockCommentText(lines: string[], startIndex: number, knownEndIndex?: number): string | undefined {
  const endIndex = knownEndIndex ?? blockCommentEndIndex(lines, startIndex);
  if (endIndex === undefined) {
    return undefined;
  }
  const text = lines
    .slice(startIndex, endIndex + 1)
    .map((line) => line.replace(/^\s*\/\*\*?/, "").replace(/\*\/\s*$/, "").replace(/^\s*\*\s?/, "").trim())
    .filter((line) => line !== "" && !line.startsWith("@"))
    .join(" ")
    .trim();
  return text === "" ? undefined : text;
}

// Forward scan for the next line containing `*/`. Returns undefined for unterminated comments,
// which the caller treats as "no useful text" rather than throwing - partial-scan robustness.
function blockCommentEndIndex(lines: string[], startIndex: number): number | undefined {
  for (let index = startIndex; index < lines.length; index += 1) {
    if ((lines[index] ?? "").includes("*/")) {
      return index;
    }
  }
  return undefined;
}
