// Bounded event proof for existing secret sinks; this is not a general YAML parser.
type GuardTruth = boolean | undefined;

// Own mapping key or sequence entry, with an inclusive source range and direct children.
interface GuardNode {
  key: string;
  result: string;
  indent: number;
  start: number;
  end: number;
  isItem: boolean;
  children: GuardNode[];
}

type GuardOperand =
  | { kind: "event" }
  | { kind: "literal"; result: string }
  | { kind: "truth"; result: GuardTruth };

// Returns source line numbers in workflow YAML source covered by job or step guards proved false for every event in events.
// Empty events, missing jobs, or structure rejected by the ownership scan return an empty set, leaving warnings in place.
// Only a proved guard contributes a range. A proved job also covers steps whose own guards are unproven.
export function unreachableWorkflowSecretLines(source: string, events: readonly string[]): Set<number> {
  const root = guardOwnership(source);
  const unreachable = new Set<number>();
  const jobs = root?.children.find((node) => node.key === "jobs" && !node.isItem && node.result === "");
  if (!jobs || events.length === 0) return unreachable;
  for (const job of jobs.children) {
    if (job.isItem || job.result !== "") continue;
    if (guardRejectsEvents(job, events)) markGuardLines(job, unreachable);
    markUnreachableSteps(job, events, unreachable);
  }
  return unreachable;
}

// Returns nothing and adds each qualifying step's own source-line range from job to unreachable.
// A step qualifies when its guard rejects every event in events. With empty events, an if entry alone qualifies the step without evaluation.
// Missing steps add nothing.
function markUnreachableSteps(job: GuardNode, events: readonly string[], unreachable: Set<number>): void {
  const steps = job.children.find((node) => node.key === "steps" && node.result === "");
  for (const step of steps?.children ?? []) {
    if (step.isItem && guardRejectsEvents(step, events)) markGuardLines(step, unreachable);
  }
}

// Returns whether node's direct-child if condition is provably false for every event in events.
// A missing condition or any unknown result returns false; an existing condition with no events returns true.
// Nested inputs and shell text cannot guard the node.
function guardRejectsEvents(node: GuardNode, events: readonly string[]): boolean {
  const condition = node.children.find((child) => child.key === "if" && !child.isItem)?.result;
  return condition !== undefined && events.every((event) => eventGuardTruth(condition, event) === false);
}

// Returns nothing and adds node's inclusive source-line range to lines, including references before its guard.
function markGuardLines(node: GuardNode, lines: Set<number>): void {
  for (let line = node.start; line <= node.end; line++) lines.add(line);
}

// Returns raw YAML text without trailing whitespace or an unquoted comment, preserving hashes inside quoted spans.
// Blank or comment-only input returns an empty string; an unterminated quoted span returns undefined, abandoning guard proof.
function guardYamlText(raw: string): string | undefined {
  for (let index = 0; index < raw.length; index++) {
    const char = raw[index];
    if (char === "'" || char === '"') {
      const quoted = raw.slice(index).match(/^(?:'(?:[^']|'')*'|"(?:[^"\\]|\\.)*")/)?.[0];
      if (!quoted) return undefined;
      index += quoted.length - 1;
      continue;
    }
    if (char === "#" && (index === 0 || /\s/.test(raw[index - 1] ?? ""))) return raw.slice(0, index).trimEnd();
  }
  return raw.trimEnd();
}

// Builds an ownership tree from workflow YAML source so late job and step guards also cover earlier references.
// Returns the root, or undefined when the scan detects unsupported or ambiguous structure, so callers retain warnings.
function guardOwnership(source: string): GuardNode | undefined {
  const lines = source.split(/\r?\n/);
  const root: GuardNode = { key: "", result: "", indent: -1, start: 1, end: lines.length, isItem: false, children: [] };
  const stack = [root];
  let scalarIndent = -1;
  for (const [index, raw] of lines.entries()) {
    if (!raw.trim() || raw.trimStart().startsWith("#")) continue;
    const indent = raw.match(/^ */)?.[0].length ?? 0;
    if (scalarIndent >= 0 && indent > scalarIndent) continue;
    scalarIndent = -1;
    if (/^ *\t/.test(raw)) return undefined;
    const text = guardYamlText(raw)?.trim();
    if (text === undefined) return undefined;
    const prefix = text.match(/^-(?: +|$)/)?.[0];
    const parent = guardParent(stack, indent, index, prefix, lines.length);
    if (!parent) return undefined;
    const node = guardEntry(parent, text, prefix, indent, index, lines.length);
    if (!node) return undefined;
    if (node !== parent) stack.push(node);
    if (/^[|>](?:[+-]?\d*|\d*[+-]?)$/.test(node.result)) scalarIndent = node.indent;
  }
  return root;
}

// Pops entries from stack at or deeper than indent, updating their end lines from zero-based index; total is the source line count.
// Without a prefix, returns the mapping parent. A dash adds the returned item to the parent's children and pushes it onto stack.
// Returns undefined for a missing or scalar-valued parent or mixed child kinds to avoid guessing line ownership.
function guardParent(stack: GuardNode[], indent: number, index: number, prefix: string | undefined, total: number): GuardNode | undefined {
  while (stack.length > 1 && (stack.at(-1)?.indent ?? -1) >= indent) {
    const closed = stack.pop();
    if (closed) closed.end = index;
  }
  const parent = stack.at(-1);
  if (!parent || parent.result !== "") return undefined;
  if (prefix === undefined) return parent.children.some((child) => child.isItem) ? undefined : parent;
  if (parent.children.some((child) => !child.isItem)) return undefined;
  const stepItem: GuardNode = { key: "", result: "", indent, start: index + 1, end: total, isItem: true, children: [] };
  parent.children.push(stepItem);
  stack.push(stepItem);
  return stepItem;
}

// Parses text under parent; indent is its source depth, index its zero-based line, total the line count, and prefix an optional sequence marker.
// Adds and returns a child node, or stores a non-key sequence value in parent.result and returns parent.
// Returns undefined for anchor or alias patterns even in quotes, merge or duplicate keys, or unsupported mapping entries to avoid false proof.
function guardEntry(parent: GuardNode, text: string, prefix: string | undefined, indent: number, index: number, total: number): GuardNode | undefined {
  if (/(?:^|\s)[&*][A-Za-z0-9_-]+/.test(text)) return undefined;
  const entry = text.slice(prefix?.length ?? 0).match(/^(?:([A-Za-z0-9_.-]+)|'([^']+)'|"([^"\\]+)"|(<<)):\s*(.*)$/);
  if (!entry) {
    if (prefix === undefined) return undefined;
    parent.result = text.slice(prefix.length);
    return parent;
  }
  const key = entry[1] ?? entry[2] ?? entry[3] ?? entry[4] ?? "";
  const result = entry[5] ?? "";
  if (key === "<<") return undefined;
  if (parent.children.some((child) => child.key === key)) return undefined;
  const node: GuardNode = { key, result, indent: indent + (prefix?.length ?? 0), start: index + 1, end: total, isItem: false, children: [] };
  parent.children.push(node);
  return node;
}

// Returns guard tokens after decoding supported YAML quoting and an enclosing expression wrapper from yamlValue.
// Malformed quoting or wrappers, unsupported syntax, or too many tokens return undefined; empty input returns an empty array.
// An absent token result cannot justify suppressing a warning, so malformed double-quoted values need no separate JSON parse log.
function guardTokens(yamlValue: string): string[] | undefined {
  let expression = yamlValue.trim();
  if (expression.startsWith('"')) {
    try {
      const decoded: unknown = JSON.parse(expression);
      if (typeof decoded !== "string") return undefined;
      expression = decoded;
    } catch { return undefined; }
  } else if (expression.startsWith("'")) {
    if (!/^'(?:[^']|'')*'$/.test(expression)) return undefined;
    expression = expression.slice(1, -1).replaceAll("''", "'");
  }
  expression = expression.trim();
  if (expression.startsWith("$" + "{{")) {
    if (!expression.endsWith("}}")) return undefined;
    expression = expression.slice(3, -2).trim();
  }
  return tokenizeGuard(expression);
}

// Splits expression into supported guard tokens, omitting whitespace, to bound the work of recursive parsing.
// Returns the tokens, an empty array for whitespace-only input, or undefined for unsupported syntax or more than 128 tokens.
function tokenizeGuard(expression: string): string[] | undefined {
  const tokens: string[] = [];
  while (expression) {
    const match = expression.match(/^(?:\s+|'(?:[^']|'')*'|[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*|==|!=|&&|\|\||[!()])/);
    if (!match) return undefined;
    if (match[0].trim()) tokens.push(match[0]);
    expression = expression.slice(match[0].length);
    if (tokens.length > 128) return undefined;
  }
  return tokens;
}

// Evaluates the workflow if value in yamlValue for the GitHub event named by event.
// Returns true or false when proved, or undefined for empty input, invalid syntax or an undecided guard.
// Complete parsing is required because false AND a malformed expression must retain the warning.
function eventGuardTruth(yamlValue: string, event: string): GuardTruth {
  const tokens = guardTokens(yamlValue) ?? [];
  if (tokens.length === 0) return undefined;
  let position = 0;
  let isValid = true;
  // Returns the boolean result carried by operand, or undefined for unknown truth, an event marker or a string literal.
  const truth = (operand: GuardOperand): GuardTruth => operand.kind === "truth" ? operand.result : undefined;
  // Consumes the next operand from tokens, advancing position and marking isValid false for invalid syntax.
  // Returns an event marker, decoded string literal, or three-valued truth operand; undefined truth means no proof.
  // Negation binds before equality, and parentheses parse a complete nested expression.
  function unary(): GuardOperand {
    const token = tokens[position++];
    if (token === "!") {
      const result = truth(unary());
      return { kind: "truth", result: result === undefined ? undefined : !result };
    }
    if (token === "(") {
      const result = disjunction();
      if (tokens[position++] !== ")") isValid = false;
      return { kind: "truth", result };
    }
    if (token?.startsWith("'")) return { kind: "literal", result: token.slice(1, -1).replaceAll("''", "'") };
    if (token === "github.event_name") return { kind: "event" };
    if (!token || !/^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$/.test(token)) isValid = false;
    return { kind: "truth", result: undefined };
  }
  // Consumes one comparison from tokens, advancing position and propagating syntax failures to isValid.
  // Returns a case-insensitive equality or inequality result for an event and string literal. A lone operand keeps its known truth.
  // Returns undefined for a lone operand without known truth or an unsupported pair, leaving the comparison undecided.
  function comparison(): GuardTruth {
    const left = unary();
    const operator = tokens[position];
    if (operator !== "==" && operator !== "!=") return truth(left);
    position++;
    const right = unary();
    const literal = left.kind === "event" && right.kind === "literal" ? right
      : right.kind === "event" && left.kind === "literal" ? left : undefined;
    if (!literal) return undefined;
    const equal = event.toLowerCase() === literal.result.toLowerCase();
    return operator === "==" ? equal : !equal;
  }
  // Consumes an AND expression from tokens, advancing position and propagating invalid operands to isValid.
  // Returns false if any term is false, true if all are true, otherwise undefined; every term is parsed to detect malformed syntax.
  function conjunction(): GuardTruth {
    let result = comparison();
    while (tokens[position] === "&&") {
      position++;
      const right = comparison();
      result = result === false || right === false ? false : result === true && right === true ? true : undefined;
    }
    return result;
  }
  // Consumes an OR expression from tokens, advancing position and propagating invalid operands to isValid.
  // Returns true if any term is true, false if all are false, otherwise undefined; every term is parsed to detect malformed syntax.
  function disjunction(): GuardTruth {
    let result = conjunction();
    while (tokens[position] === "||") {
      position++;
      const right = conjunction();
      result = result === true || right === true ? true : result === false && right === false ? false : undefined;
    }
    return result;
  }
  const result = disjunction();
  return isValid && position === tokens.length ? result : undefined;
}
