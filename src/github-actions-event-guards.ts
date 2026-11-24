// Bounded event-guard evaluator for GitHub Actions `if:` conditions on jobs and steps.
//
// Proves when a `secrets.*` reference cannot execute under a `pull_request_target` trigger so guarded steps stay quiet.
// Intentionally scoped to workflow event guards rather than general YAML or expression evaluation.
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

/**
 * Computes source line numbers in workflow YAML covered by job or step guards proved false for every event.
 * Empty events, missing jobs, or structure rejected by the ownership scan yield an empty set, leaving warnings in place.
 * Only a proved guard contributes a range, and a proved job also covers steps whose own guards are unproven.
 *
 * @param source - Workflow YAML file text to scan for job and step guards.
 * @param events - Trigger event names to test against each guard condition.
 * @returns Source line numbers inside proved unreachable job or step ranges.
 */
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

/**
 * Marks each qualifying step's own source-line range from `job` in `unreachable`.
 * A step qualifies when its guard rejects every event, or when it has an `if` entry with empty events; missing steps add nothing.
 *
 * @param job - Job ownership node whose `steps` child sequence is inspected.
 * @param events - Trigger event names tested against each step guard.
 * @param unreachable - Collected unreachable lines updated in place with qualifying step source ranges.
 * @returns Nothing. Adds each qualifying step's inclusive source-line range to `unreachable`.
 */
function markUnreachableSteps(job: GuardNode, events: readonly string[], unreachable: Set<number>): void {
  const steps = job.children.find((node) => node.key === "steps" && node.result === "");
  for (const step of steps?.children ?? []) {
    if (step.isItem && guardRejectsEvents(step, events)) markGuardLines(step, unreachable);
  }
}

/**
 * Checks whether `node`'s direct-child `if` condition is provably false for every event.
 * A missing condition or any unknown result fails the check; an existing condition with no events passes.
 * Nested inputs and shell text cannot guard `node`.
 *
 * @param node - Job or step ownership node whose direct `if` child is evaluated.
 * @param events - Trigger event names required to evaluate to false.
 * @returns True only when a direct `if` condition exists and evaluates to false for every event.
 */
function guardRejectsEvents(node: GuardNode, events: readonly string[]): boolean {
  const condition = node.children.find((child) => child.key === "if" && !child.isItem)?.result;
  return condition !== undefined && events.every((event) => eventGuardTruth(condition, event) === false);
}

/**
 * Records `node`'s inclusive source-line range in `lines`, including references before its guard.
 *
 * @param node - Ownership node supplying the inclusive start and end line numbers.
 * @param lines - Target collection updated in place with each covered line number.
 * @returns Nothing. Adds every line from `node.start` through `node.end` to `lines`.
 */
function markGuardLines(node: GuardNode, lines: Set<number>): void {
  for (let line = node.start; line <= node.end; line++) lines.add(line);
}

/**
 * Strips trailing whitespace and any unquoted YAML comment from `raw`, preserving hashes inside quoted spans.
 * Blank or comment-only input yields an empty result; an unterminated quoted span abandons guard proof.
 *
 * @param raw - Single raw line of workflow YAML text.
 * @returns Trimmed text without unquoted comments, or undefined when a quoted span is unterminated.
 */
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

/**
 * Builds an ownership tree from workflow YAML `source` so late job and step guards also cover earlier references.
 * Aborts on tabs before content, malformed quotes, or ambiguous structure so callers retain warnings.
 *
 * @param source - Complete workflow YAML document text.
 * @returns Root ownership node, or undefined when the scan detects unsupported or ambiguous structure.
 */
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

/**
 * Pops entries from `stack` at or deeper than `indent`, closing their end lines from `index`, and resolves the active parent.
 * Without `prefix`, returns the mapping parent; a dash adds a new sequence item to its parent's children and pushes it onto `stack`.
 * Rejects a missing or scalar-valued parent or mixed child kinds to avoid guessing line ownership.
 *
 * @param stack - Open ownership ancestor stack mutated by closing deeper nodes and pushing new sequence items.
 * @param indent - Leading space count of the current YAML line.
 * @param index - Zero-based line index of the current YAML line.
 * @param prefix - Optional sequence dash marker preceding the entry on the line.
 * @param total - Total line count of the YAML document used as the initial end line.
 * @returns Active parent or newly pushed sequence item, or undefined on invalid parent or mixed child kinds.
 */
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

/**
 * Parses `text` under `parent`, adding a mapping child node or storing a non-key sequence value in `parent.result`.
 * Rejects anchor or alias patterns even in quotes, merge or duplicate keys, or unsupported entries to avoid false proof.
 *
 * @param parent - Enclosing mapping or sequence-item node receiving the parsed entry.
 * @param text - Trimmed line text with unquoted comments removed.
 * @param prefix - Optional sequence dash marker stripped before matching a mapping key.
 * @param indent - Leading space count of the line before any sequence prefix.
 * @param index - Zero-based line index of the current YAML line.
 * @param total - Total line count of the YAML document used as the child's initial end line.
 * @returns Newly created child node, `parent` for a plain sequence scalar, or undefined on unsupported syntax.
 */
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

/**
 * Decodes supported YAML quoting and an enclosing `${{ ... }}` wrapper from `yamlValue`, then tokenizes the expression.
 * An absent token result cannot justify suppressing a warning, so malformed double-quoted values need no separate JSON parse log.
 *
 * @param yamlValue - Raw YAML scalar text from a job or step `if` field.
 * @returns Guard tokens, an empty list for empty input, or undefined on malformed quoting, wrappers, or unsupported syntax.
 */
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

/**
 * Splits `expression` into supported guard tokens while omitting whitespace to bound the work of recursive parsing.
 *
 * @param expression - Unwrapped expression body to scan sequentially.
 * @returns Guard tokens, an empty list for whitespace-only input, or undefined on unsupported syntax or over 128 tokens.
 */
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

/**
 * Evaluates the workflow `if` value in `yamlValue` for the GitHub event named by `event`.
 * Complete parsing is required because false AND a malformed expression must retain the warning.
 *
 * @param yamlValue - Raw YAML `if` expression value to tokenize and parse.
 * @param event - GitHub Actions event name compared against `github.event_name`.
 * @returns True or false when proved for `event`, or undefined for empty input, invalid syntax, or an undecided guard.
 */
function eventGuardTruth(yamlValue: string, event: string): GuardTruth {
  const tokens = guardTokens(yamlValue) ?? [];
  if (tokens.length === 0) return undefined;
  let position = 0;
  let isValid = true;
  /**
   * Extracts the proved boolean truth carried by `operand`, discarding non-boolean operands.
   *
   * @param operand - Parsed guard operand (event marker, literal, or truth value).
   * @returns Proved boolean result from `operand`, or undefined for unknown truth, an event marker, or a literal.
   */
  const truth = (operand: GuardOperand): GuardTruth => operand.kind === "truth" ? operand.result : undefined;
  /**
   * Consumes the next operand from `tokens`, advancing `position` and marking `isValid` false on invalid syntax.
   * Negation binds before equality, and parentheses parse a complete nested expression.
   *
   * @returns Event marker, decoded literal, or three-valued truth operand where undefined truth means no proof.
   */
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
  /**
   * Consumes one comparison from `tokens`, advancing `position` and propagating syntax failures to `isValid`.
   * A lone operand keeps its known truth; unsupported pairs leave the comparison undecided.
   *
   * @returns Case-insensitive equality or inequality result for an event and literal, lone operand truth, or undefined.
   */
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
  /**
   * Consumes an AND expression from `tokens`, advancing `position` and propagating invalid operands to `isValid`.
   * Every term is parsed to detect malformed syntax even when an earlier term is already false.
   *
   * @returns False if any term is false, true if all terms are true, or undefined otherwise.
   */
  function conjunction(): GuardTruth {
    let result = comparison();
    while (tokens[position] === "&&") {
      position++;
      const right = comparison();
      result = result === false || right === false ? false : result === true && right === true ? true : undefined;
    }
    return result;
  }
  /**
   * Consumes an OR expression from `tokens`, advancing `position` and propagating invalid operands to `isValid`.
   * Every term is parsed to detect malformed syntax even when an earlier term is already true.
   *
   * @returns True if any term is true, false if all terms are false, or undefined otherwise.
   */
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
