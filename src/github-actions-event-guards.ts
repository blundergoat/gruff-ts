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

// Returns source lines covered by an own job/step guard false for every covered PR event.
// Any structural ambiguity disables proof for the whole workflow, preserving existing warnings.
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

// Each step is checked separately because its guard cannot cover job env or sibling steps.
function markUnreachableSteps(job: GuardNode, events: readonly string[], unreachable: Set<number>): void {
  const steps = job.children.find((node) => node.key === "steps" && node.result === "");
  for (const step of steps?.children ?? []) {
    if (step.isItem && guardRejectsEvents(step, events)) markGuardLines(step, unreachable);
  }
}

// Guard lookup is direct-child only: with.if and shell text cannot control a step.
function guardRejectsEvents(node: GuardNode, events: readonly string[]): boolean {
  const condition = node.children.find((child) => child.key === "if" && !child.isItem)?.result;
  return condition !== undefined && events.every((event) => eventGuardTruth(condition, event) === false);
}

// Inclusive source ranges include references before an own late if.
function markGuardLines(node: GuardNode, lines: Set<number>): void {
  for (let line = node.start; line <= node.end; line++) lines.add(line);
}

// Quote spans keep comments outside YAML strings because expression literals can contain hashes.
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

// Complete the ownership tree before proof because a late guard belongs to preceding references.
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

// Closing siblings first prevents a previous step's guard from covering the next sequence entry.
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

// Duplicate keys and YAML aliases destroy proof; unsupported entries return undefined conservatively.
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

// YAML quoting and wrappers cover the whole scalar; the fallback on JSON parse errors is unknown proof.
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

// A fixed token budget bounds recursive nesting and rejects trailing unsupported syntax.
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

// Complete parsing is required because false AND a malformed expression must retain the warning.
function eventGuardTruth(yamlValue: string, event: string): GuardTruth {
  const tokens = guardTokens(yamlValue) ?? [];
  if (tokens.length === 0) return undefined;
  let position = 0;
  let isValid = true;
  // Non-boolean operands are unknown until an exact event comparison establishes a result.
  const truth = (operand: GuardOperand): GuardTruth => operand.kind === "truth" ? operand.result : undefined;
  // Negation binds before equality; parentheses evaluate their own complete expression.
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
  // Only an event and a string literal establish equality; other comparisons remain unknown.
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
  // False dominates unknown in AND, so all terms are still parsed before proof.
  function conjunction(): GuardTruth {
    let result = comparison();
    while (tokens[position] === "&&") {
      position++;
      const right = comparison();
      result = result === false || right === false ? false : result === true && right === true ? true : undefined;
    }
    return result;
  }
  // Unknown prevents false proof in OR; reachable branches retain the warning.
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
