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

function globalRegExp(pattern: RegExp): RegExp {
  if (pattern.flags.includes("g")) {
    return pattern;
  }
  return new RegExp(pattern.source, `${pattern.flags}g`);
}

function firstLine(source: string, pattern: RegExp): number {
  return source.split(/\r?\n/).findIndex((line) => pattern.test(line)) + 1 || 1;
}

interface TodoMarkerScanState {
  blockComment: boolean;
  quote: string | undefined;
  escaped: boolean;
}

interface CommentScanStep {
  comment: string;
  skip: number;
  done: boolean;
}

function todoMarkerSummary(source: string, isScript: boolean): { count: number; firstLine: number } {
  let count = 0;
  let firstLine = 0;
  const state: TodoMarkerScanState = { blockComment: false, quote: undefined, escaped: false };

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

function commentTextForLine(line: string, state: TodoMarkerScanState, isScript: boolean): string {
  let comment = "";
  for (let index = 0; index < line.length; index += 1) {
    const step = commentScanStep(line, index, state, isScript);
    comment += step.comment;
    index += step.skip;
    if (step.done) {
      break;
    }
  }
  if (state.quote !== "`") {
    state.quote = undefined;
    state.escaped = false;
  }
  return comment;
}

function commentScanStep(line: string, index: number, state: TodoMarkerScanState, isScript: boolean): CommentScanStep {
  const character = line[index] ?? "";
  const next = line[index + 1] ?? "";
  if (state.blockComment) {
    return blockCommentScanStep(character, next, state);
  }
  if (state.quote) {
    return quotedScanStep(character, state);
  }
  return openCodeCommentScanStep(line, index, state, isScript);
}

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

function quoteStartScanStep(character: string, state: TodoMarkerScanState): CommentScanStep | undefined {
  if (character === "\"" || character === "'" || character === "`") {
    state.quote = character;
    return emptyCommentScanStep();
  }
  return undefined;
}

function blockStartScanStep(character: string, next: string, state: TodoMarkerScanState): CommentScanStep | undefined {
  if (character === "/" && next === "*") {
    state.blockComment = true;
    return { comment: "", skip: 1, done: false };
  }
  return undefined;
}

function lineCommentScanStep(line: string, index: number, character: string, next: string, isScript: boolean): CommentScanStep {
  if (character === "/" && next === "/") {
    return { comment: line.slice(index + 2), skip: line.length, done: true };
  }
  if (!isScript && character === "#") {
    return { comment: line.slice(index + 1), skip: line.length, done: true };
  }
  return emptyCommentScanStep();
}

function blockCommentScanStep(character: string, next: string, state: TodoMarkerScanState): CommentScanStep {
  if (character === "*" && next === "/") {
    state.blockComment = false;
    return { comment: "", skip: 1, done: false };
  }
  return { comment: character, skip: 0, done: false };
}

function quotedScanStep(character: string, state: TodoMarkerScanState): CommentScanStep {
  if (state.escaped) {
    state.escaped = false;
  } else if (character === "\\") {
    state.escaped = true;
  } else if (character === state.quote) {
    state.quote = undefined;
  }
  return emptyCommentScanStep();
}

function emptyCommentScanStep(): CommentScanStep {
  return { comment: "", skip: 0, done: false };
}

function byteLine(source: string, index: number): number {
  return source.slice(0, Math.max(0, index)).split("\n").length;
}

export { byteLine, countMatches, firstLine, todoMarkerSummary };
