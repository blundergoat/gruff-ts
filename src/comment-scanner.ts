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

// Scans a file's source text and returns comment records in source order for checks that inspect comment text and locations.
// The result is empty when the lexer recognises no source comments.
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

/**
 * Runs the first lexer step that can consume the current source character.
 *
 * @param source - the whole file text being scanned
 * @param index - position of the current character in `source`
 * @param state - lexer state, updated by whichever step runs; an unconsumed non-whitespace character becomes `previousCode`
 * @param records - comment records found so far; the comment step appends to it
 * @returns index of the last consumed character, after which `commentRecords` resumes; `index` when no step consumed the character
 */
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

/**
 * Creates a fresh comment lexer state for a single source file scan.
 *
 * @returns state at line 1 with no open string, template or regex and no previous code character
 */
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

/**
 * Consumes newlines and resets quote/regex state that cannot cross lines.
 *
 * @param source - the whole file text being scanned
 * @param index - position of the current character
 * @param state - lexer state; on a newline its line count advances, a non-template quote closes and regex state clears
 * @returns `index` when the character is a newline, or undefined to pass it to the next step
 */
function scanCommentLineBreak(source: string, index: number, state: CommentScanState): number | undefined {
  if ((source[index] ?? "") !== "\n") {
    return undefined;
  }
  advanceCommentScanLine(state);
  return index;
}

/**
 * Advances the lexer after a newline has been consumed.
 *
 * @param state - lexer state to update: the line count goes up by one, any quote except a template backtick closes, and the regex flags clear
 * @returns Nothing. Updates the lexer state in place for the next line.
 */
function advanceCommentScanLine(state: CommentScanState): void {
  state.line += 1;
  if (state.quote !== "`") {
    state.quote = undefined;
  }
  state.isRegex = false;
  state.isRegexEscaped = false;
  state.isRegexCharClass = false;
}

/**
 * Keeps quoted text from being reported as a real source comment.
 *
 * @param source - the whole file text being scanned
 * @param index - position of the current character
 * @param state - lexer state; inside a string or template, the character updates its quote and escape flags
 * @returns `index` when the lexer is inside a string or template, so the character is neither code nor a comment; otherwise undefined
 */
function scanQuotedCommentStep(source: string, index: number, state: CommentScanState): number | undefined {
  return scanActiveQuotedCommentState(state, source[index] ?? "") ? index : undefined;
}

/**
 * Updates quote escape/close state when the lexer is inside a string.
 *
 * @param state - lexer state whose quote and escape flags change: a backslash escapes the next character, an unescaped closing quote ends the string
 * @param character - the current source character
 * @returns true when a quote was open, so the character belongs to the string; false when none was open
 */
function scanActiveQuotedCommentState(state: CommentScanState, character: string): boolean {
  if (!state.quote) {
    return false;
  }
  const nextState = scanQuotedCommentCharacter(character, state.quote, state.isEscaped);
  state.quote = nextState.quote;
  state.isEscaped = nextState.isEscaped;
  return true;
}

/**
 * Keeps regex literal bodies from being reported as real source comments.
 *
 * @param source - the whole file text being scanned
 * @param index - position of the current character
 * @param state - lexer state; inside a regex literal, the character updates its escape, character-class and close flags
 * @returns `index` when the lexer is inside a regex literal, otherwise undefined
 */
function scanRegexCommentStep(source: string, index: number, state: CommentScanState): number | undefined {
  return scanActiveRegexCommentState(state, source[index] ?? "") ? index : undefined;
}

/**
 * Updates regex escape, character-class, and close state.
 *
 * @param state - lexer state whose regex flags change: an unescaped `/` outside a character class ends the literal
 * @param character - the current source character
 * @returns true when a regex literal was open, so the character belongs to it; false when none was open
 */
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

/**
 * Records a line or block comment and returns the consumed source index.
 *
 * @param source - the whole file text being scanned
 * @param index - position of the current character, a possible `//` or `/*` start
 * @param state - lexer state; its line moves to the comment's last line
 * @param records - comment records found so far; a comment starting here is appended
 * @returns index of the comment's last character, or undefined when none starts here; a line comment stops before its newline for the line count
 */
function scanCommentRecordStep(source: string, index: number, state: CommentScanState, records: CommentRecord[]): number | undefined {
  const record = commentRecordAt(source, index, state.line);
  if (!record) {
    return undefined;
  }
  records.push(record);
  state.line = record.endLine;
  return record.kind === "line" ? record.endIndex - 1 : record.endIndex;
}

/**
 * Detects whether the current slash pair begins a source comment.
 *
 * @param source - the whole file text being scanned
 * @param index - position of the possible `//` or `/*` start
 * @param line - one-based line number of `index`, stored as the record's first line
 * @returns a line or block comment record starting at `index`, or undefined when the two characters there are neither `//` nor `/*`
 */
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

/**
 * Opens string/template quote state when the current character starts a literal.
 *
 * @param source - the whole file text being scanned
 * @param index - position of the current character
 * @param state - lexer state that records an opener as both the open quote and previous code character and clears the escape flag
 * @returns the current index when a quote opens, otherwise undefined with lexer state unchanged
 */
function scanQuoteStartStep(source: string, index: number, state: CommentScanState): number | undefined {
  return openCommentScanQuote(state, source[index] ?? "") ? index : undefined;
}

/**
 * Mutates quote state after a quote-start character is found.
 *
 * @param state - lexer state; a quote character becomes its open quote and `previousCode`, with the escape flag cleared
 * @param character - the current source character
 * @returns true when the character opened a string or template; false for any other character, leaving the state unchanged
 */
function openCommentScanQuote(state: CommentScanState, character: string): boolean {
  if (character !== "\"" && character !== "'" && character !== "`") {
    return false;
  }
  state.quote = character;
  state.isEscaped = false;
  state.previousCode = character;
  return true;
}

/**
 * Opens regex state for a slash that the lexer treats as the start of a literal, including when it has seen no code yet.
 *
 * @param source - file text supplying the current character and up to 40 preceding characters to check for return
 * @param index - position of the current character
 * @param state - lexer state to update on a match. Opens the regex, clears its escape and class flags and records the slash as previous code
 * @returns index on a regex start, or undefined with lexer state unchanged when the character does not open a regex
 */
function scanRegexStartStep(source: string, index: number, state: CommentScanState): number | undefined {
  return openCommentScanRegex(state, source, index, source[index] ?? "") ? index : undefined;
}

/**
 * Mutates regex state after a regex literal start is found.
 *
 * @param state - lexer state; a regex start sets the regex flag, clears its escape and character-class flags and makes `/` the previous code
 * @param source - the whole file text; up to 40 characters before `index` are checked for a preceding `return`
 * @param index - position of the current character
 * @param character - the current source character
 * @returns true when the character is a `/` that `isCommentRegexStart` accepts as a regex start; false otherwise, leaving the state unchanged
 */
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

/**
 * Remembers the last non-whitespace code character for regex/comment disambiguation.
 *
 * @param state - lexer state whose previousCode becomes character unless it is whitespace
 * @param character - the source character no other lexer step consumed
 * @returns Nothing. Records the character in the supplied lexer state when it contains non-whitespace.
 */
function updateCommentScanPreviousCode(state: CommentScanState, character: string): void {
  if (/\S/.test(character)) {
    state.previousCode = character;
  }
}

// Computes the next quote and escape flags for one character inside a string or template.
// The quote is the opening delimiter, and the incoming escape flag says whether the current character is escaped.
// An unescaped matching delimiter yields an undefined quote, so the caller resumes scanning outside the literal.
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

// Computes the next regex state from the current character, whether it is escaped, and whether it is in a character class.
// Returns the open, escape, and character-class flags. An unescaped slash outside a class closes the regex.
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

// Returns whether to open a regex literal using the last code character and the available source text before the slash.
// With no previous code character, the lexer treats the slash as a regex start.
// This mirrors the masking pass and keeps the comment lexer independent of it.
function isCommentRegexStart(previousCode: string, beforeSlash: string): boolean {
  return previousCode === "" || "([{=,:!&|?;".includes(previousCode) || /\breturn$/.test(beforeSlash.trimEnd());
}

// Builds a record for the line comment at the opener offset in the source, using the supplied one-based line number for both line bounds.
// Trims the body for rule comparisons. The exclusive end offset is the newline's index or the source length if there is no newline.
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

// Builds a record for the block comment at the opener offset in the source, using the supplied one-based line number.
// The text drops leading asterisks so the same prose compares equally in JSDoc and plain blocks.
// The end index points to the closer's last character, or the final source character when no closer is found.
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

// Returns comparison text from a delimiter-free block comment body by removing leading asterisks and joining nonblank lines.
// A body containing only decoration and whitespace yields an empty string.
function normalizedBlockCommentText(text: string): string {
  return text
    .split(/\r?\n/)
    .map((line) => line.replace(/^[ \t]*\*[ \t]?/, "").trim())
    .filter((line) => line !== "")
    .join(" ")
    .trim();
}

// Reads consecutive line comments as one maintainer comment while keeping the final record's source position.
// Pass comments in source order so context on earlier lines of the header still counts.
// A block comment or a final record absent from the supplied list is returned unchanged.
export function combinedContextLineComment(comments: CommentRecord[], finalComment: CommentRecord): CommentRecord {
  if (finalComment.kind !== "line") {
    return finalComment;
  }
  const finalIndex = comments.indexOf(finalComment);
  if (finalIndex < 0) {
    return finalComment;
  }
  let firstIndex = finalIndex;
  while (firstIndex > 0) {
    const previous = comments[firstIndex - 1];
    const current = comments[firstIndex];
    if (!previous || !current || previous.kind !== "line" || previous.endLine + 1 !== current.line) {
      break;
    }
    firstIndex -= 1;
  }
  const text = comments
    .slice(firstIndex, finalIndex + 1)
    .map((comment) => comment.text)
    .join(" ");
  return { ...finalComment, text };
}

// Splits the file text and returns whether there is usable leading comment text above the one-based declaration line.
export function hasLeadingCommentBeforeLine(source: string, line: number): boolean {
  return hasLeadingCommentBeforeLines(source.split(/\r?\n/), line);
}

// Checks the source lines above a one-based declaration line, skipping blank padding.
// Returns true if the preceding nonblank line yields comment text and false if there is no usable text.
export function hasLeadingCommentBeforeLines(lines: string[], line: number): boolean {
  let index = line - 2;
  while (index >= 0 && (lines[index] ?? "").trim() === "") {
    index -= 1;
  }
  return index >= 0 && commentTextAtLine(lines, index) !== undefined;
}

// Checks the source lines above the one-based function declaration line for text that counts as its own documentation.
// Skips blank lines and returns false if there is no comment text or the comment is a section divider or file overview.
export function hasFunctionLeadingCommentBeforeLines(lines: string[], line: number): boolean {
  let endIndex = line - 2;
  while (endIndex >= 0 && (lines[endIndex] ?? "").trim() === "") {
    endIndex -= 1;
  }
  if (endIndex < 0 || commentTextAtLine(lines, endIndex) === undefined) {
    return false;
  }
  return !isOverviewOrDividerCommentAt(lines, commentStartIndex(lines, endIndex), endIndex, line - 1);
}

// The opener line of the comment that ends on `endIndex`: the line itself for `//` and one-line
// `/* */` comments, else the nearest `/*` above a `*/` closer.
function commentStartIndex(lines: string[], endIndex: number): number {
  for (let index = endIndex; index >= 0; index -= 1) {
    const trimmedLine = (lines[index] ?? "").trim();
    if (trimmedLine.startsWith("//") || trimmedLine.startsWith("/*")) {
      return index;
    }
  }
  return endIndex;
}

// Returns true for a section divider or a file-opening comment with a file-level tag or a blank gap before the declaration.
// Supply the source file's lines from the beginning so earlier code can rule out a file overview.
// startIndex and endIndex are the zero-based inclusive comment bounds. declarationIndex marks the declaration and bounds the gap.
export function isOverviewOrDividerCommentAt(lines: string[], startIndex: number, endIndex: number, declarationIndex: number): boolean {
  const commentText = lines.slice(startIndex, endIndex + 1).join("\n");
  return isDividerComment(commentText) || (isFileOverviewComment(commentText, lines.slice(endIndex + 1, declarationIndex)) && isFileOpeningLine(lines, startIndex));
}

// A one-line comment whose text opens with a run of three or more `-`, `=`, `*`, `_`, `#`, `~`, `+`
// or `/`, such as `// ---- helpers` or `/* ==== */`, divides sections; it does not describe the
// function below it.
export function isDividerComment(commentText: string): boolean {
  if (commentText.includes("\n")) {
    return false;
  }
  const text = commentText.trim().replace(/^\/\/|^\/\*\*?/, "").replace(/\*\/$/, "").trim();
  return /^[-=*_#~+/]{3,}/.test(text);
}

// Returns true when the comment text has a file-level tag or the lines before the next declaration contain a blank separator.
// The caller checks whether the comment is at the file opening before treating it as an overview.
export function isFileOverviewComment(commentText: string, gapLines: string[]): boolean {
  return gapLines.some((gapLine) => gapLine.trim() === "") || /@(?:file|fileoverview|overview|packageDocumentation|module|license)\b/.test(commentText);
}

// True when only a shebang, blank lines and other comments come before line `startIndex`, so a
// comment that starts there opens the file. Stops at the first code line.
function isFileOpeningLine(lines: string[], startIndex: number): boolean {
  let isInBlockComment = false;
  for (let index = 0; index < startIndex; index += 1) {
    const trimmedLine = (lines[index] ?? "").trim();
    if (isInBlockComment || trimmedLine.startsWith("/*")) {
      isInBlockComment = !trimmedLine.endsWith("*/");
      continue;
    }
    if (trimmedLine !== "" && !trimmedLine.startsWith("//") && !(index === 0 && trimmedLine.startsWith("#!"))) {
      return false;
    }
  }
  return true;
}

// Returns text at the given source line index from a leading line comment or block opener, or a block closer at the end of the trimmed line.
// Block extraction drops tag lines. Returns undefined if no text remains, if an opener has no closer or if the line has no comment to extract.
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

// Extracts text from the source lines beginning at the block opener index, removing delimiters, leading asterisks, and tag lines.
// The remaining lines are trimmed and joined with spaces. A supplied closer index skips the search for the end of the block.
// Returns undefined if the search finds no closer or no text remains for the documentation checks.
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

// Returns the first source line index containing a block closer, starting at the opener's zero-based line index.
// Returns undefined if no closer is found, so the caller has no comment text to inspect.
function blockCommentEndIndex(lines: string[], startIndex: number): number | undefined {
  for (let index = startIndex; index < lines.length; index += 1) {
    if ((lines[index] ?? "").includes("*/")) {
      return index;
    }
  }
  return undefined;
}
