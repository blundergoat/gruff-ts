// Empty-match guard (`lastIndex += 1`) prevents zero-width patterns like /(?=)/g from looping forever.
// Caller's RegExp is never mutated — `globalRegExp` clones it when the global flag is missing.
function countMatches(source: string, pattern: RegExp): number {
  const globalPattern = globalRegExp(pattern);
  let count = 0;
  let match: RegExpExecArray | null;
  globalPattern.lastIndex = 0;
  while ((match = globalPattern["exec"](source)) !== null) {
    count += 1;
    if (match[0] === "") {
      globalPattern.lastIndex += 1;
    }
  }
  return count;
}

// Clones into a new `g`-flagged RegExp when needed. Mutating the caller's pattern (via `lastIndex`)
// would silently break any further use on the calling side — rule descriptors share patterns at module scope.
function globalRegExp(pattern: RegExp): RegExp {
  if (pattern.flags.includes("g")) {
    return pattern;
  }
  return new RegExp(pattern.source, `${pattern.flags}g`);
}

// One-based line number of the first matching line, defaulting to 1 when no match exists so
// findings always have a valid anchor. Used by rules that need a stable file-level location.
function firstLine(source: string, pattern: RegExp): number {
  return source.split(/\r?\n/).findIndex((line) => pattern.test(line)) + 1 || 1;
}

// Mutable lexer state threaded through the task-marker scanner. `quote === "\`"` survives across
// newlines because template literals can span lines; ordinary quotes reset at end of line.
interface TodoMarkerScanState {
  isInBlockComment: boolean;
  quote: string | undefined;
  isEscaped: boolean;
}

// One scanner step yields the comment bytes for this position, how many extra characters to skip
// (e.g., to consume `*/`), and whether the rest of the line is comment text (no need to keep scanning).
interface CommentScanStep {
  comment: string;
  skip: number;
  isDone: boolean;
}

// Task-marker counter consumed by the density rule. Skipping strings is mandatory — markers inside
// string literals must not inflate the count, or every fixture string containing a task keyword
// would trip. `isScript` flips `#` line-comment recognition for shell-like config files.
function todoMarkerSummary(source: string, isScript: boolean): { count: number; firstLine: number } {
  if (!source.includes("TODO") && !source.includes("FIXME")) {
    return { count: 0, firstLine: 1 };
  }
  let count = 0;
  let firstLine = 0;
  const state: TodoMarkerScanState = { isInBlockComment: false, quote: undefined, isEscaped: false };

  source.split(/\r?\n/).forEach((line, index) => {
    const markerCount = countMatches(commentTextForLine(line, state, isScript), /\b(?:TODO|FIXME)\b/g);
    if (markerCount === 0) {
      return;
    }
    count += markerCount;
    if (firstLine === 0) {
      firstLine = index + 1;
    }
  });

  return { count, firstLine: firstLine || 1 };
}

// Returns only the comment portions of `line` — strings, regex literals, and code are dropped.
// Mutates `state` so block comments and template literals can carry across line boundaries.
function commentTextForLine(line: string, state: TodoMarkerScanState, isScript: boolean): string {
  let comment = "";
  for (let index = 0; index < line.length; index += 1) {
    const step = commentScanStep(line, index, state, isScript);
    comment += step.comment;
    index += step.skip;
    if (step.isDone) {
      break;
    }
  }
  if (state.quote !== "`") {
    state.quote = undefined;
    state.isEscaped = false;
  }
  return comment;
}

// Three-state dispatcher: in a block comment, in a quoted string, or in executable code. Each
// branch must be exhaustive — falling through would let a task keyword inside a string get counted.
function commentScanStep(line: string, index: number, state: TodoMarkerScanState, isScript: boolean): CommentScanStep {
  const character = line[index] ?? "";
  const next = line[index + 1] ?? "";
  if (state.isInBlockComment) {
    return blockCommentScanStep(character, next, state);
  }
  if (state.quote) {
    return quotedScanStep(character, state);
  }
  return openCodeCommentScanStep(line, index, state, isScript);
}

// Priority order: quote → block opener → line comment. Quotes must come first because `/* ... */`
// inside a string is just text, and `// foo` inside a string would otherwise prematurely end scanning.
function openCodeCommentScanStep(line: string, index: number, state: TodoMarkerScanState, isScript: boolean): CommentScanStep {
  const character = line[index] ?? "";
  const next = line[index + 1] ?? "";
  const quoteStep = quoteStartScanStep(character, state);
  if (quoteStep) {
    return quoteStep;
  }
  const blockStep = blockStartScanStep(character, next, state);
  if (blockStep) {
    return blockStep;
  }
  return lineCommentScanStep(line, index, character, next, isScript);
}

// Detects opening quote of a string or template literal and mutates `state.quote` so subsequent
// characters are routed through `quotedScanStep` rather than the code branch.
function quoteStartScanStep(character: string, state: TodoMarkerScanState): CommentScanStep | undefined {
  if (character === "\"" || character === "'" || character === "`") {
    state.quote = character;
    return emptyCommentScanStep();
  }
  return undefined;
}

// Detects `/*` opener. Returns `skip: 1` so the caller advances past `*` and does not re-enter on
// the next character as if `*` were code.
function blockStartScanStep(character: string, next: string, state: TodoMarkerScanState): CommentScanStep | undefined {
  if (character === "/" && next === "*") {
    state.isInBlockComment = true;
    return { comment: "", skip: 1, isDone: false };
  }
  return undefined;
}

// Slices the comment payload after `//` (or `#` in config files) and signals `isDone: true` so the
// caller stops walking the line — everything to the right is comment text.
function lineCommentScanStep(line: string, index: number, character: string, next: string, isScript: boolean): CommentScanStep {
  if (character === "/" && next === "/") {
    return { comment: line.slice(index + 2), skip: line.length, isDone: true };
  }
  if (!isScript && character === "#") {
    return { comment: line.slice(index + 1), skip: line.length, isDone: true };
  }
  return emptyCommentScanStep();
}

// Inside a block comment until `*/` is seen. Each character is treated as comment text so task
// markers inside the block contribute to the count.
function blockCommentScanStep(character: string, next: string, state: TodoMarkerScanState): CommentScanStep {
  if (character === "*" && next === "/") {
    state.isInBlockComment = false;
    return { comment: "", skip: 1, isDone: false };
  }
  return { comment: character, skip: 0, isDone: false };
}

// Consumes the body of a string/template literal. `\` toggles `isEscaped` so the next character
// is not interpreted as the closing quote — necessary for sequences like `"\""` and `"\\\""`.
function quotedScanStep(character: string, state: TodoMarkerScanState): CommentScanStep {
  if (state.isEscaped) {
    state.isEscaped = false;
  } else if (character === "\\") {
    state.isEscaped = true;
  } else if (character === state.quote) {
    state.quote = undefined;
  }
  return emptyCommentScanStep();
}

// No-op step used by branches that consumed a character but produced no comment text — keeps the
// caller loop branchless at the cost of one allocation per non-comment character.
function emptyCommentScanStep(): CommentScanStep {
  return { comment: "", skip: 0, isDone: false };
}

// One-based line number containing byte offset `index`. Used to anchor findings extracted from
// regex match indices; off-by-one would shift every reported line in the resulting reports.
function byteLine(source: string, index: number): number {
  const end = Math.max(0, index);
  let line = 1;
  for (let offset = 0; offset < end; offset += 1) {
    if (source.charCodeAt(offset) === 10) {
      line += 1;
    }
  }
  return line;
}

export { byteLine, countMatches, firstLine, todoMarkerSummary };
