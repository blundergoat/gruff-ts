import type { RunDiagnostic } from "./types.ts";

interface DiagnosticSourceFile {
  displayPath: string;
  isTypeScript: boolean;
}

function parseDiagnostics(file: DiagnosticSourceFile, source: string): RunDiagnostic[] {
  if (!file.isTypeScript) {
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

interface DelimiterCounts {
  braces: number;
  parentheses: number;
  brackets: number;
}

interface DelimiterScanState {
  quote: string | undefined;
  escaped: boolean;
  blockComment: boolean;
  regex: boolean;
  regexCharClass: boolean;
  regexEscaped: boolean;
  previousCode: string;
}

interface DelimiterScanContext {
  scan: DelimiterScanState;
  counts: DelimiterCounts;
}

interface ScanStep {
  skip: number;
  stopLine: boolean;
}

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

function scanDelimiterLine(line: string, ctx: DelimiterScanContext): void {
  for (let offset = 0; offset < line.length; offset += 1) {
    const step = scanDelimiterCharacter(line, offset, ctx);
    offset += step.skip;
    if (step.stopLine) {
      break;
    }
  }
}

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

function scanBlockCommentDelimiter(character: string, next: string, scan: DelimiterScanState): ScanStep {
  if (character === "*" && next === "/") {
    scan.blockComment = false;
    return skipNextCharacter();
  }
  return continueScan();
}

function scanQuotedDelimiter(character: string, scan: DelimiterScanState): void {
  if (scan.escaped) {
    scan.escaped = false;
  } else if (character === "\\") {
    scan.escaped = true;
  } else if (character === scan.quote) {
    scan.quote = undefined;
  }
}

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

function scanCodeDelimiter(line: string, offset: number, character: string, next: string, ctx: DelimiterScanContext): ScanStep {
  if (character === "/" && next === "/") {
    return stopLineScan();
  }
  if (character === "/" && next === "*") {
    ctx.scan.blockComment = true;
    return skipNextCharacter();
  }
  if (isQuote(character)) {
    ctx.scan.quote = character;
    return continueScan();
  }
  if (character === "/" && isRegexLiteralStart(ctx.scan.previousCode, line.slice(0, offset))) {
    ctx.scan.regex = true;
    ctx.scan.regexCharClass = false;
    ctx.scan.regexEscaped = false;
    return continueScan();
  }
  countDelimiter(character, ctx.counts);
  if (character.trim() !== "") {
    ctx.scan.previousCode = character;
  }
  return continueScan();
}

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

function hasNegativeDelimiterCount(counts: DelimiterCounts): boolean {
  return counts.braces < 0 || counts.parentheses < 0 || counts.brackets < 0;
}

function hasUnbalancedDelimiterCount(counts: DelimiterCounts): boolean {
  return counts.braces !== 0 || counts.parentheses !== 0 || counts.brackets !== 0;
}

function parseErrorDiagnostic(file: DiagnosticSourceFile, line: number): RunDiagnostic {
  return {
    diagnosticType: "parse-error",
    message: "Unbalanced TypeScript delimiters detected.",
    filePath: file.displayPath,
    line,
  };
}

function isRegexLiteralStart(previousCode: string, beforeSlash: string): boolean {
  return previousCode === "" || "([{=,:!&|?;".includes(previousCode) || /\breturn$/.test(beforeSlash.trimEnd());
}

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

interface MaskStep {
  text: string;
  skip: number;
}

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

function maskBlockComment(character: string, next: string, state: MaskState): MaskStep {
  if (character === "*" && next === "/") {
    state.isBlockComment = false;
    return { text: "  ", skip: 1 };
  }
  return maskSingleCharacter();
}

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

function maskCodeCharacter(source: string, index: number, character: string, next: string, state: MaskState): MaskStep {
  if (character === "/" && next === "/") {
    state.isLineComment = true;
    return { text: "  ", skip: 1 };
  }
  if (character === "/" && next === "*") {
    state.isBlockComment = true;
    return { text: "  ", skip: 1 };
  }
  if (character === "/" && isRegexLiteralStart(state.previousCode, source.slice(Math.max(0, index - 80), index))) {
    state.isRegex = true;
    state.previousCode = character;
    return { text: character, skip: 0 };
  }
  if (isQuote(character)) {
    state.quote = character;
    state.previousCode = character;
    return { text: character, skip: 0 };
  }
  if (/\S/.test(character)) {
    state.previousCode = character;
  }
  return { text: character, skip: 0 };
}

function maskSingleCharacter(): MaskStep {
  return { text: " ", skip: 0 };
}

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

interface CodeLineState {
  quote: string | undefined;
  isEscaped: boolean;
}

interface CodeLineStep {
  text: string;
  stopLine: boolean;
}

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

function continueScan(): ScanStep {
  return { skip: 0, stopLine: false };
}

function skipNextCharacter(): ScanStep {
  return { skip: 1, stopLine: false };
}

function stopLineScan(): ScanStep {
  return { skip: 0, stopLine: true };
}

function isQuote(character: string): boolean {
  return character === "\"" || character === "'" || character === "`";
}

export { codeLineForMatching, maskNonCode, parseDiagnostics };
