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

/**
 * Scans a file's source text and collects comment records in source order for checks that inspect comment text and locations.
 *
 * @param source - the whole file text to scan for line and block comments
 * @returns comment records in source order, or an empty array when the lexer recognises no source comments
 */
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

/**
 * Computes the next quote and escape flags for one character inside a string or template.
 *
 * @param character - current source character inside the quoted literal
 * @param quote - opening delimiter of the active string or template literal
 * @param isEscaped - whether the current character is escaped by a preceding backslash
 * @returns updated quote and escape flags; an unescaped matching delimiter yields an undefined quote so scanning resumes outside the literal
 */
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

/**
 * Computes the next regex state from one character inside a regex literal.
 *
 * @param character - current source character inside the regex literal
 * @param isEscaped - whether the current character is escaped by a preceding backslash
 * @param isCharClass - whether the scanner is currently inside a `[...]` character class
 * @returns updated open, escape, and character-class flags; an unescaped slash outside a class closes the regex
 */
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

/**
 * Determines whether a slash opens a regex literal, mirroring the masking pass to keep the comment lexer independent.
 *
 * @param previousCode - last non-whitespace code character before the slash, or empty when none was seen yet
 * @param beforeSlash - available source slice immediately preceding the slash, checked for a trailing `return` keyword
 * @returns true when `previousCode` is empty or a regex-preceding token, or `beforeSlash` ends with `return`; false otherwise
 */
function isCommentRegexStart(previousCode: string, beforeSlash: string): boolean {
  return previousCode === "" || "([{=,:!&|?;".includes(previousCode) || /\breturn$/.test(beforeSlash.trimEnd());
}

/**
 * Builds a record for a line comment at its opener offset and trims its body for rule comparisons.
 *
 * @param source - whole file text being scanned
 * @param startIndex - zero-based offset of the `//` opener in `source`
 * @param line - one-based line number used for both `line` and `endLine`
 * @returns line comment record whose exclusive `endIndex` is the newline index, or `source.length` when no newline follows
 */
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

/**
 * Builds a record for a block comment, dropping leading asterisks so prose compares equally in JSDoc and plain blocks.
 *
 * @param source - whole file text being scanned
 * @param startIndex - zero-based offset of the block comment opener in `source`
 * @param line - one-based line number of the opener
 * @returns block comment record whose `endIndex` points to the closer's last character, or the final source character when unclosed
 */
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

/**
 * Extracts comparison text from a delimiter-free block comment body by removing leading asterisks and joining nonblank lines.
 *
 * @param text - block comment body with opening and closing delimiters already removed
 * @returns normalized space-joined prose, or an empty string when the body contains only decoration and whitespace
 */
function normalizedBlockCommentText(text: string): string {
  return text
    .split(/\r?\n/)
    .map((line) => line.replace(/^[ \t]*\*[ \t]?/, "").trim())
    .filter((line) => line !== "")
    .join(" ")
    .trim();
}

/**
 * Reads consecutive line comments as one maintainer comment while keeping the final record's source position.
 *
 * @param comments - comment records in source order so context on earlier lines of the header still counts
 * @param finalComment - trailing comment record whose contiguous preceding line comments should be merged
 * @returns merged comment record anchored at `finalComment`, or `finalComment` unchanged if it is a block comment or absent from `comments`
 */
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

/**
 * Splits file text into lines and checks whether usable leading comment text precedes a declaration line.
 *
 * @param source - whole file text to split on line breaks
 * @param line - one-based line number of the declaration
 * @returns true when a nonblank comment with usable text precedes `line`, otherwise false
 */
export function hasLeadingCommentBeforeLine(source: string, line: number): boolean {
  return hasLeadingCommentBeforeLines(source.split(/\r?\n/), line);
}

/**
 * Checks source lines above a declaration line, skipping blank padding, for a usable leading comment.
 *
 * @param lines - source file split into zero-based lines
 * @param line - one-based line number of the declaration
 * @returns true if the nearest preceding nonblank line yields comment text, and false if there is no usable text
 */
export function hasLeadingCommentBeforeLines(lines: string[], line: number): boolean {
  let index = line - 2;
  while (index >= 0 && (lines[index] ?? "").trim() === "") {
    index -= 1;
  }
  return index >= 0 && commentTextAtLine(lines, index) !== undefined;
}

/**
 * Checks source lines above a function declaration for leading text that counts as its own documentation.
 *
 * @param lines - source file split into zero-based lines
 * @param line - one-based line number of the function declaration
 * @returns false when blank-skipped preceding text is missing or is a section divider or file overview, otherwise true
 */
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

/**
 * Finds the opener line of the comment ending on `endIndex` (the first contiguous `//` line for line comments, else the nearest `/*` above).
 *
 * @param lines - source file split into zero-based lines
 * @param endIndex - zero-based line index where the comment ends
 * @returns zero-based line index of the comment opener, or `endIndex` if no opener line is found above
 */
function commentStartIndex(lines: string[], endIndex: number): number {
  // Walk upward across contiguous `//` lines so tags like `@fileoverview` on line 1 of a multi-line header stay included.
  if ((lines[endIndex] ?? "").trim().startsWith("//")) {
    let start = endIndex;
    while (start > 0 && (lines[start - 1] ?? "").trim().startsWith("//")) {
      start -= 1;
    }
    return start;
  }
  for (let index = endIndex; index >= 0; index -= 1) {
    const trimmedLine = (lines[index] ?? "").trim();
    if (trimmedLine.startsWith("/*")) {
      return index;
    }
  }
  return endIndex;
}

/**
 * Checks whether a comment is a section divider or a file-opening overview rather than declaration documentation.
 *
 * @param lines - source file lines from the beginning so earlier code can rule out a file overview
 * @param startIndex - zero-based inclusive start line index of the comment
 * @param endIndex - zero-based inclusive end line index of the comment
 * @param declarationIndex - zero-based line index of the following declaration, bounding the gap lines
 * @returns true for a section divider or a file-opening comment with a file-level tag or a blank gap before the declaration
 */
export function isOverviewOrDividerCommentAt(lines: string[], startIndex: number, endIndex: number, declarationIndex: number): boolean {
  const commentText = lines.slice(startIndex, endIndex + 1).join("\n");
  return isDividerComment(commentText) || (isFileOverviewComment(commentText, lines.slice(endIndex + 1, declarationIndex)) && isFileOpeningLine(lines, startIndex));
}

/**
 * Detects one-line section-divider comments (such as `// ---- helpers` or a `====` block comment) that do not describe the function below.
 *
 * @param commentText - raw comment text across one or more source lines
 * @returns true when `commentText` is a single line opening with three or more `-`, `=`, `*`, `_`, `#`, `~`, `+`, or `/` characters
 */
export function isDividerComment(commentText: string): boolean {
  if (commentText.includes("\n")) {
    return false;
  }
  const text = commentText.trim().replace(/^\/\/|^\/\*\*?/, "").replace(/\*\/$/, "").trim();
  return /^[-=*_#~+/]{3,}/.test(text);
}

/**
 * Determines whether a comment looks like a file overview (the caller separately checks that it sits at the file opening).
 *
 * @param commentText - raw comment text checked for file-level JSDoc tags
 * @param gapLines - source lines between the end of the comment and the next declaration
 * @returns true when `commentText` has a file-level tag or `gapLines` contains a blank separator line
 */
export function isFileOverviewComment(commentText: string, gapLines: string[]): boolean {
  return gapLines.some((gapLine) => gapLine.trim() === "") || /@(?:file|fileoverview|overview|packageDocumentation|module|license)\b/.test(commentText);
}

/**
 * Checks whether a comment at `startIndex` opens the file, stopping as soon as any preceding code token appears.
 * Handles inline block comments followed by code on the same line (such as `/* policy *\/ export const seed = 1;`).
 *
 * @param lines - source file split into zero-based lines
 * @param startIndex - zero-based start line index of the comment being tested
 * @returns True when only a shebang, blank lines, and earlier comments precede `startIndex`; false if code appears first.
 */
function isFileOpeningLine(lines: string[], startIndex: number): boolean {
  let isInBlockComment = false;
  for (let index = 0; index < startIndex; index += 1) {
    let rest = (lines[index] ?? "").trim();
    if (index === 0 && !isInBlockComment && rest.startsWith("#!")) {
      continue;
    }
    // Consume any sequence of block comments and trailing line comments on this line; any leftover token is code.
    while (rest !== "") {
      if (isInBlockComment) {
        const closeIndex = rest.indexOf("*/");
        if (closeIndex === -1) {
          rest = "";
          break;
        }
        isInBlockComment = false;
        rest = rest.slice(closeIndex + 2).trim();
        continue;
      }
      if (rest.startsWith("//")) {
        rest = "";
        break;
      }
      if (rest.startsWith("/*")) {
        isInBlockComment = true;
        rest = rest.slice(2);
        continue;
      }
      return false;
    }
  }
  return !isInBlockComment;
}

/**
 * Extracts comment prose at a source line from a line comment, block opener, or trailing block closer, dropping block tag lines.
 *
 * @param lines - source file split into zero-based lines
 * @param index - zero-based line index to inspect
 * @returns extracted comment text, or undefined when no text remains, an opener lacks a closer, or the line has no comment
 */
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

/**
 * Walks upward from a block closer to its matching opener and extracts the joined body for a leading declaration comment.
 *
 * @param lines - source file split into zero-based lines
 * @param endIndex - zero-based line index ending with the block comment closer
 * @returns extracted block comment text from `blockCommentText`, or undefined if no matching opener line is found
 */
function blockCommentTextEndingAt(lines: string[], endIndex: number): string | undefined {
  for (let index = endIndex; index >= 0; index -= 1) {
    if ((lines[index] ?? "").trim().startsWith("/*")) {
      return blockCommentText(lines, index, endIndex);
    }
  }
  return undefined;
}

/**
 * Extracts space-joined prose from a block comment starting at `startIndex`, stripping delimiters, leading asterisks, and tag lines.
 *
 * @param lines - source file split into zero-based lines
 * @param startIndex - zero-based line index of the block opener
 * @param knownEndIndex - optional zero-based closer line index that skips searching for the end of the block
 * @returns trimmed, space-joined comment text, or undefined when no closer is found or no prose remains
 */
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

/**
 * Finds the first source line index containing a block closer at or after the block opener.
 *
 * @param lines - source file split into zero-based lines
 * @param startIndex - zero-based line index of the block comment opener
 * @returns zero-based line index of the closing line, or undefined when no closer is found
 */
function blockCommentEndIndex(lines: string[], startIndex: number): number | undefined {
  for (let index = startIndex; index < lines.length; index += 1) {
    if ((lines[index] ?? "").includes("*/")) {
      return index;
    }
  }
  return undefined;
}
