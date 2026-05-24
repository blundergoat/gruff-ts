// Empty-match guard (`lastIndex += 1`) prevents zero-width patterns like /(?=)/g from looping forever.
// Caller's RegExp is never mutated - `globalRegExp` clones it when the global flag is missing.
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
// would silently break any further use on the calling side - rule descriptors share patterns at module scope.
function globalRegExp(pattern: RegExp): RegExp {
  return new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`);
}

// One-based line number of the first matching line, defaulting to 1 when no match exists so
// findings always have a valid anchor. Used by rules that need a stable file-level location.
function firstLine(source: string, pattern: RegExp): number {
  return source.split(/\r?\n/).findIndex((line) => pattern.test(line)) + 1 || 1;
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

export { byteLine, countMatches, firstLine };
