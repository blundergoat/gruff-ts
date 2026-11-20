// Returns the number of pattern matches in source for occurrence-based rules, or zero when none match. The caller's pattern is unchanged.
// Empty matches count toward the total. The scan advances its index by one code unit to avoid retrying a zero-width match.
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

// Returns a new global copy of pattern, preserving its other flags so scans cannot mutate the caller's RegExp.
function globalRegExp(pattern: RegExp): RegExp {
  return new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`);
}

// Returns the one-based first source line accepted by pattern.test, or 1 when none pass, to anchor file-level findings.
// Uses pattern's current state; global or sticky patterns may change lastIndex and affect which line is accepted.
function firstLine(source: string, pattern: RegExp): number {
  return source.split(/\r?\n/).findIndex((line) => pattern.test(line)) + 1 || 1;
}

// Returns the one-based line at UTF-16 index in source for regex-derived finding locations; negative indices use the start of source.
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

// One-based column of byte offset `index` on its line. Lets two matches on one line report
// distinct positions so neither occurrence is lost when their line-keyed identities collide.
function byteColumn(source: string, index: number): number {
  const end = Math.max(0, index);
  return end - source.lastIndexOf("\n", end - 1);
}

// Returns the closing-parenthesis index paired with the opening at openParen in masked source, or undefined if none is found.
// Callers mask strings and comments so parentheses inside them do not affect the nesting count.
function matchingCloseParen(source: string, openParen: number): number | undefined {
  let depth = 0;
  for (let index = openParen; index < source.length; index += 1) {
    const character = source[index];
    if (character === "(") {
      depth += 1;
    } else if (character === ")") {
      depth -= 1;
      if (depth === 0) {
        return index;
      }
    }
  }
  return undefined;
}

export { byteColumn, byteLine, countMatches, firstLine, matchingCloseParen };
