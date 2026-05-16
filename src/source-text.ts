import type { RunDiagnostic } from "./types.ts";

interface DiagnosticSourceFile {
  displayPath: string;
  isTypeScript: boolean;
}

function parseDiagnostics(file: DiagnosticSourceFile, source: string): RunDiagnostic[] {
  if (!file.isTypeScript) {
    return [];
  }
  let braces = 0;
  let parentheses = 0;
  let brackets = 0;
  const scan: DelimiterScanState = {
    quote: undefined,
    escaped: false,
    blockComment: false,
    regex: false,
    regexCharClass: false,
    regexEscaped: false,
    previousCode: "",
  };
  const lines = source.split(/\r?\n/);
  for (const [index, line] of lines.entries()) {
    for (let offset = 0; offset < line.length; offset += 1) {
      const character = line[offset] ?? "";
      const next = line[offset + 1] ?? "";
      if (scan.blockComment) {
        if (character === "*" && next === "/") {
          scan.blockComment = false;
          offset += 1;
        }
        continue;
      }
      if (scan.quote) {
        if (scan.escaped) {
          scan.escaped = false;
          continue;
        }
        if (character === "\\") {
          scan.escaped = true;
          continue;
        }
        if (character === scan.quote) {
          scan.quote = undefined;
        }
        continue;
      }
      if (scan.regex) {
        if (scan.regexEscaped) {
          scan.regexEscaped = false;
          continue;
        }
        if (character === "\\") {
          scan.regexEscaped = true;
          continue;
        }
        if (character === "[") {
          scan.regexCharClass = true;
          continue;
        }
        if (character === "]") {
          scan.regexCharClass = false;
          continue;
        }
        if (character === "/" && !scan.regexCharClass) {
          scan.regex = false;
          scan.previousCode = "x";
        }
        continue;
      }
      if (character === "/" && next === "/") {
        break;
      }
      if (character === "/" && next === "*") {
        scan.blockComment = true;
        offset += 1;
        continue;
      }
      if (character === "\"" || character === "'" || character === "`") {
        scan.quote = character;
        continue;
      }
      if (character === "/" && isRegexLiteralStart(scan.previousCode, line.slice(0, offset))) {
        scan.regex = true;
        scan.regexCharClass = false;
        scan.regexEscaped = false;
        continue;
      }
      if (character === "{") {
        braces += 1;
      } else if (character === "}") {
        braces -= 1;
      } else if (character === "(") {
        parentheses += 1;
      } else if (character === ")") {
        parentheses -= 1;
      } else if (character === "[") {
        brackets += 1;
      } else if (character === "]") {
        brackets -= 1;
      }
      if (character.trim() !== "") {
        scan.previousCode = character;
      }
    }
    if (braces < 0 || parentheses < 0 || brackets < 0) {
      return [
        {
          diagnosticType: "parse-error",
          message: "Unbalanced TypeScript delimiters detected.",
          filePath: file.displayPath,
          line: index + 1,
        },
      ];
    }
  }
  if (braces !== 0 || parentheses !== 0 || brackets !== 0) {
    return [
      {
        diagnosticType: "parse-error",
        message: "Unbalanced TypeScript delimiters detected.",
        filePath: file.displayPath,
        line: lines.length,
      },
    ];
  }
  return [];
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

function isRegexLiteralStart(previousCode: string, beforeSlash: string): boolean {
  return previousCode === "" || "([{=,:!&|?;".includes(previousCode) || /\breturn$/.test(beforeSlash.trimEnd());
}

function maskNonCode(source: string): string {
  let result = "";
  let quote: string | undefined;
  let isEscaped = false;
  let isLineComment = false;
  let isBlockComment = false;
  let isRegex = false;
  let isRegexCharClass = false;
  let isRegexEscaped = false;
  let previousCode = "";

  for (let index = 0; index < source.length; index += 1) {
    const character = source[index] ?? "";
    const next = source[index + 1] ?? "";
    if (character === "\n") {
      result += character;
      isLineComment = false;
      if (quote !== "`") {
        quote = undefined;
      }
      isRegex = false;
      isRegexCharClass = false;
      isRegexEscaped = false;
      continue;
    }
    if (isLineComment) {
      result += " ";
      continue;
    }
    if (isBlockComment) {
      if (character === "*" && next === "/") {
        result += "  ";
        index += 1;
        isBlockComment = false;
      } else {
        result += " ";
      }
      continue;
    }
    if (quote) {
      if (isEscaped) {
        result += " ";
        isEscaped = false;
        continue;
      }
      if (character === "\\") {
        result += " ";
        isEscaped = true;
        continue;
      }
      if (character === quote) {
        result += character;
        previousCode = character;
        quote = undefined;
        continue;
      }
      result += " ";
      continue;
    }
    if (isRegex) {
      if (isRegexEscaped) {
        result += " ";
        isRegexEscaped = false;
        continue;
      }
      if (character === "\\") {
        result += " ";
        isRegexEscaped = true;
        continue;
      }
      if (character === "[") {
        result += " ";
        isRegexCharClass = true;
        continue;
      }
      if (character === "]") {
        result += " ";
        isRegexCharClass = false;
        continue;
      }
      if (character === "/" && !isRegexCharClass) {
        result += character;
        isRegex = false;
        previousCode = character;
        continue;
      }
      result += " ";
      continue;
    }
    if (character === "/" && next === "/") {
      result += "  ";
      index += 1;
      isLineComment = true;
      continue;
    }
    if (character === "/" && next === "*") {
      result += "  ";
      index += 1;
      isBlockComment = true;
      continue;
    }
    if (character === "/" && isRegexLiteralStart(previousCode, source.slice(Math.max(0, index - 80), index))) {
      result += character;
      isRegex = true;
      previousCode = character;
      continue;
    }
    if (character === "\"" || character === "'" || character === "`") {
      result += character;
      quote = character;
      previousCode = character;
      continue;
    }
    result += character;
    if (/\S/.test(character)) {
      previousCode = character;
    }
  }
  return result;
}

function codeLineForMatching(line: string): string {
  let result = "";
  let quote: string | undefined;
  let isEscaped = false;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index] ?? "";
    const next = line[index + 1] ?? "";
    if (!quote && character === "/" && next === "/") {
      break;
    }
    if (quote) {
      if (isEscaped) {
        isEscaped = false;
        continue;
      }
      if (character === "\\") {
        isEscaped = true;
        continue;
      }
      if (character === quote) {
        result += character;
        quote = undefined;
      }
      continue;
    }
    if (character === "\"" || character === "'" || character === "`") {
      quote = character;
      result += character;
      continue;
    }
    result += character;
  }
  return result;
}

export { codeLineForMatching, maskNonCode, parseDiagnostics };
