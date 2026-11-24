/**
 * Counts pattern matches in `source` for occurrence-based rules without mutating `pattern`.
 * Empty matches count toward the total; the scan advances by one code unit to avoid retrying a zero-width match.
 *
 * @param source - Text to scan for matches.
 * @param pattern - Regular expression matched via a fresh global copy so caller state is unchanged.
 * @returns Number of matches found in `source`, or zero when none match.
 */
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

/**
 * Clones `pattern` with the global flag enabled while preserving its other flags so scans cannot mutate the caller's RegExp.
 *
 * @param pattern - Source regular expression whose pattern text and existing flags are copied.
 * @returns New global RegExp instance with the same source and flags as `pattern`.
 */
function globalRegExp(pattern: RegExp): RegExp {
  return new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`);
}

/**
 * Finds the first line accepted by `pattern.test` to anchor file-level findings.
 * Uses `pattern`'s current state; global or sticky patterns may change `lastIndex` and affect which line is accepted.
 *
 * @param source - Multi-line text split on LF or CRLF line endings.
 * @param pattern - Regular expression tested line by line using its current `lastIndex` state.
 * @returns One-based line number of the first matching line, or 1 when no line passes.
 */
function firstLine(source: string, pattern: RegExp): number {
  return source.split(/\r?\n/).findIndex((line) => pattern.test(line)) + 1 || 1;
}

/**
 * Computes the one-based line number at a UTF-16 index for regex-derived finding locations.
 *
 * @param source - Text whose newline characters before `index` are counted.
 * @param index - Zero-based UTF-16 code unit offset; negative indices use the start of `source`.
 * @returns One-based line number at `index`.
 */
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

/**
 * Computes the one-based column of UTF-16 offset `index` on its line.
 * Lets two matches on one line report distinct positions so neither occurrence is lost when their line-keyed identities collide.
 *
 * @param source - Text containing the line to measure against.
 * @param index - Zero-based UTF-16 offset; negative indices are clamped to the start of `source`.
 * @returns One-based column offset from the start of the line containing `index`.
 */
function byteColumn(source: string, index: number): number {
  const end = Math.max(0, index);
  return end - source.lastIndexOf("\n", end - 1);
}

/**
 * Finds the closing parenthesis paired with the opening parenthesis at `openParen` in masked source.
 * Callers mask strings and comments so parentheses inside them do not affect the nesting count.
 *
 * @param source - Masked source text scanned forward from `openParen`.
 * @param openParen - Zero-based index of the opening parenthesis in `source`.
 * @returns Zero-based index of the matching closing parenthesis, or undefined if none is found.
 */
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
