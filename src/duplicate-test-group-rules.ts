// Finds complete, file-local duplicate test groups without changing legacy callable discovery.
// Matching follows FAMILY-CONTRACT section 16; candidates stay advisory and default-on.
import { createRequire } from "node:module";
import type { Node, Expression, CallExpression, ArrowFunction, FunctionExpression, SourceFile as SyntaxFile } from "typescript";
import type { SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import type { ParsedScript } from "./parsed-script.ts";
import type { Finding } from "./types.ts";

const require = createRequire(import.meta.url);
const syntax = require("typescript") as typeof import("typescript");
const MINIMUM_GROUP_SIZE = 3;
// Section 16's TypeScript member minimum: a one- or two-statement test is one named case whose table form reads no better.
const MINIMUM_STATEMENTS = 3;
const TEST_NAMES = new Set(["test", "it"]);
const SUITE_NAMES = new Set(["describe", "context", "suite"]);
const TEST_MODIFIERS = new Set(["skip", "only", "todo", "concurrent", "fails", "failing", "serial", "sequential", "skipIf", "runIf"]);
const TABLE_MODIFIERS = new Set(["each", "for"]);
const TABLE_ITERATORS = new Set(["forEach", "map", "flatMap"]);

// Supported runner root and ordered modifier evidence; a table target never joins a group.
interface CallTarget {
  name: string;
  modifiers: string[];
  isTable: boolean;
}

// Every member carries its native title and complete location for group review.
interface TestMember {
  name: string;
  qualifiedName: string;
  line: number;
  column: number;
  endLine: number;
}

type TestCallback = ArrowFunction | FunctionExpression;

/**
 * Appends one finding for every qualifying group, retaining every member in source order.
 * Contract: the first member owns the native identity and every member remains visible.
 * @param file - discovered file identity for native findings
 * @param parsed - shared syntax tree; malformed files provide no reliable groups
 * @param findings - destination for complete native findings
 */
export function analyseDuplicateTestGroups(file: SourceFile, parsed: ParsedScript, findings: Finding[]): void {
  if (parsed.diagnostics.length > 0) {
    return;
  }
  const groups = new Map<string, TestMember[]>();
  // Visits each syntax node once; node supplies possible registrations without another parse.
  const visit = (node: Node): void => {
    if (syntax.isCallExpression(node)) {
      collectTestMember(node, parsed.sourceFile, groups);
    }
    node.forEachChild(visit);
  };
  parsed.sourceFile.forEachChild(visit);
  for (const members of groups.values()) {
    const first = members[0];
    if (!first || members.length < MINIMUM_GROUP_SIZE) {
      continue;
    }
    findings.push(makeFinding({
      ruleId: "test-quality.duplicate-test-body",
      message: `${members.length} tests share a body: ${members.map((member) => `${member.qualifiedName} (${member.line}:${member.column})`).join(", ")}. Consider the test runner's table form with a descriptive label per row.`,
      filePath: file.displayPath,
      line: first.line,
      column: first.column,
      endLine: first.endLine,
      symbol: first.name,
      severity: "advisory",
      pillar: "test-quality",
      confidence: "low",
      remediation: "Review the cases as a consolidation candidate; use the test runner's table form with a descriptive label per row when it keeps each case clear.",
      metadata: { groupSize: members.length, members },
    }));
  }
}

/**
 * Adds a supported registration to its exact container, attributes and normalized-body group.
 * @param call - possible test registration
 * @param sourceFile - shared tree used for decoded titles and positions
 * @param groups - ordered group membership collected during the traversal
 */
function collectTestMember(call: CallExpression, sourceFile: SyntaxFile, groups: Map<string, TestMember[]>): void {
  const target = callTarget(call.expression);
  const title = call.arguments[0];
  if (!target || !TEST_NAMES.has(target.name) || target.isTable || !title || !syntax.isStringLiteralLike(title)) {
    return;
  }
  const callbacks = call.arguments.filter(isTestCallback);
  const callback = callbacks[0];
  if (callbacks.length !== 1 || !callback || call.arguments.length > 3 || !syntax.isBlock(callback.body)) {
    return;
  }
  if (callback.body.statements.filter((statement) => !syntax.isEmptyStatement(statement)).length < MINIMUM_STATEMENTS) {
    return;
  }
  const container = enclosingContainer(call, sourceFile);
  if (!container) {
    return;
  }
  const options = call.arguments.slice(1).filter((argument) => argument !== callback);
  const attributes = [target.modifiers, options.map((option) => syntaxIdentity(option, false)), callback.kind,
    syntax.isFunctionExpression(callback) && callback.asteriskToken !== undefined,
    callback.modifiers?.map((modifier) => modifier.kind) ?? [], callback.parameters.map((parameter) => syntaxIdentity(parameter, false))];
  const key = JSON.stringify([container.positions, attributes, syntaxIdentity(callback.body, true)]);
  const start = sourceFile.getLineAndCharacterOfPosition(call.getStart(sourceFile));
  const member: TestMember = {
    name: title.text,
    qualifiedName: [...container.names, title.text].join(" > "),
    line: start.line + 1,
    column: start.character + 1,
    endLine: sourceFile.getLineAndCharacterOfPosition(call.getEnd()).line + 1,
  };
  const members = groups.get(key) ?? [];
  members.push(member);
  groups.set(key, members);
}

/**
 * Recognizes literal test/suite roots and preserves the order and arguments of modifiers.
 * The walk must retain both property and call steps because either can change a runner modifier.
 * @param expression - callee, including modifier calls such as skipIf(condition)
 * @returns supported root and modifiers, or undefined for a custom registration form
 */
function callTarget(expression: Expression): CallTarget | undefined {
  if (syntax.isIdentifier(expression)) {
    return TEST_NAMES.has(expression.text) || SUITE_NAMES.has(expression.text)
      ? { name: expression.text, modifiers: [], isTable: false } : undefined;
  }
  if (syntax.isPropertyAccessExpression(expression)) {
    const target = callTarget(expression.expression);
    const modifier = expression.name.text;
    if (!target || (!TEST_MODIFIERS.has(modifier) && !TABLE_MODIFIERS.has(modifier))) {
      return undefined;
    }
    return { ...target, modifiers: [...target.modifiers, modifier], isTable: target.isTable || TABLE_MODIFIERS.has(modifier) };
  }
  if (syntax.isCallExpression(expression) || syntax.isTaggedTemplateExpression(expression)) {
    const target = callTarget(syntax.isCallExpression(expression) ? expression.expression : expression.tag);
    if (!target) {
      return undefined;
    }
    const argumentsIdentity = syntax.isCallExpression(expression)
      ? expression.arguments.map((argument) => syntaxIdentity(argument, false))
      : syntaxIdentity(expression.template, false);
    return { ...target, modifiers: [...target.modifiers, JSON.stringify(argumentsIdentity)] };
  }
  return undefined;
}

/**
 * Separates lexical declarations and rejects registrations already inside table iteration.
 * Declaration positions must stay distinct because same-named sibling suites are separate containers.
 * @param call - test registration whose ancestor declarations define its container
 * @param sourceFile - shared source for enclosing declaration names
 * @returns declaration positions and readable names, or undefined for a table form
 */
function enclosingContainer(call: CallExpression, sourceFile: SyntaxFile): { positions: number[]; names: string[] } | undefined {
  const positions: number[] = [];
  const names: string[] = [];
  for (let node = call.parent; node && !syntax.isSourceFile(node); node = node.parent) {
    if (syntax.isIterationStatement(node, false)) {
      return undefined;
    }
    if (syntax.isCallExpression(node)) {
      const target = callTarget(node.expression);
      if (target?.isTable || (syntax.isPropertyAccessExpression(node.expression) && TABLE_ITERATORS.has(node.expression.name.text))) {
        return undefined;
      }
    }
    if (syntax.isFunctionLike(node) || syntax.isClassLike(node) || syntax.isModuleDeclaration(node)) {
      positions.unshift(node.getStart(sourceFile));
      const parentCall = isTestCallback(node) && syntax.isCallExpression(node.parent) ? node.parent : undefined;
      const title = parentCall?.arguments[0];
      const name = title && syntax.isStringLiteralLike(title) ? title.text : node.name?.getText(sourceFile);
      names.unshift(name ?? `<anonymous@${sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1}>`);
    }
  }
  return { positions, names };
}

/**
 * Checks the two callback forms that supported runners register directly.
 * @param node - candidate callback argument or enclosing declaration
 * @returns whether the node has a function or arrow callback body
 */
function isTestCallback(node: Node): node is TestCallback {
  return syntax.isArrowFunction(node) || syntax.isFunctionExpression(node);
}

/**
 * Compares syntax, retaining keys, indices and decoded whitespace-bearing text exactly.
 * The token walk must retain operators, declaration keywords and empty for-loop clauses that
 * forEachChild omits, while allowing optional statement semicolons and trailing commas.
 * @param node - syntax subtree to compare
 * @param normalize - whether eligible literal values may become same-kind placeholders
 * @param exact - whether the subtree sits inside a declaration or decorator that keeps its documentation
 * @returns deterministic syntax identity, with no local-name renaming
 */
function syntaxIdentity(node: Node, normalize: boolean, exact = false): unknown {
  // Section 16 compares a declaration in the body exactly, because a case table cannot carry it, and keeps
  // decorator arguments; a const binding is a named value and normalizes like any other statement.
  const inExact = exact || isExactDeclaration(node);
  const literal = literalIdentity(node, normalize && !inExact);
  if (literal !== undefined) {
    return literal;
  }
  const children: unknown[] = inExact ? [leadingDocumentation(node)] : [];
  const syntaxChildren = node.getChildren();
  for (const [index, child] of syntaxChildren.entries()) {
    if (!isComparisonChild(node, child, index, syntaxChildren.length)) {
      continue;
    }
    const isKey = "name" in node && node.name === child;
    const isIndex = syntax.isElementAccessExpression(node) && node.argumentExpression === child;
    children.push(syntaxIdentity(child, normalize && !inExact && !isKey && !isIndex, inExact));
  }
  return [node.kind, children];
}

/**
 * Recognizes the declarations section 16 compares exactly, and decorators wherever they appear.
 * @param node - syntax node inside a compared test body
 * @returns whether its literals and documentation must stay exact
 */
function isExactDeclaration(node: Node): boolean {
  return syntax.isFunctionDeclaration(node) || syntax.isClassDeclaration(node) || syntax.isInterfaceDeclaration(node)
    || syntax.isTypeAliasDeclaration(node) || syntax.isEnumDeclaration(node) || syntax.isModuleDeclaration(node)
    || syntax.isDecorator(node);
}

/**
 * Reads the JSDoc blocks before a node inside an exact declaration; the parser leaves them unattached in function bodies.
 * @param node - declaration or one of its descendants
 * @returns the raw documentation comments, in source order
 */
function leadingDocumentation(node: Node): string[] {
  const text = node.getSourceFile().text;
  // Trailing ranges hold comments on the previous token's line; leading ranges start after the next line break.
  const ranges = [...syntax.getTrailingCommentRanges(text, node.pos) ?? [], ...syntax.getLeadingCommentRanges(text, node.pos) ?? []];
  return ranges.map((range) => text.slice(range.pos, range.end))
    .filter((comment) => comment.startsWith("/**"));
}

/**
 * Keeps grammar separators that distinguish roles, without treating optional punctuation as a difference.
 * For-loop semicolons must remain because they identify initializer, condition and increment clauses.
 * @param owner - syntax node whose immediate children are compared
 * @param child - candidate token or nested syntax node
 * @param index - child's position in the owner's token sequence
 * @param count - number of immediate children, used to recognize a trailing comma
 * @returns whether this child contributes to the comparison
 */
function isComparisonChild(owner: Node, child: Node, index: number, count: number): boolean {
  if (syntax.isEmptyStatement(child) && syntax.isBlock(child.parent)) {
    return false;
  }
  if (child.kind >= syntax.SyntaxKind.FirstJSDocNode && child.kind <= syntax.SyntaxKind.LastJSDocNode) {
    return false;
  }
  if (child.kind === syntax.SyntaxKind.SemicolonToken) {
    return syntax.isForStatement(owner);
  }
  return !(child.kind === syntax.SyntaxKind.CommaToken && owner.kind === syntax.SyntaxKind.SyntaxList && index === count - 1);
}

/**
 * Gives literal leaves their language kind and keeps decoded whitespace text exact.
 * Normalization cannot erase meaningful strings or cross literal kinds, so each leaf keeps its kind.
 * @param node - possible literal or identifier leaf
 * @param normalize - false within any key, index or option argument
 * @returns leaf identity, or undefined when child structure must be compared
 */
function literalIdentity(node: Node, normalize: boolean): unknown {
  switch (node.kind) {
    case syntax.SyntaxKind.JsxText:
    case syntax.SyntaxKind.JsxTextAllWhiteSpaces:
      return [node.kind, (node as import("typescript").JsxText).text];
    case syntax.SyntaxKind.StringLiteral:
    case syntax.SyntaxKind.NoSubstitutionTemplateLiteral:
    case syntax.SyntaxKind.TemplateHead:
    case syntax.SyntaxKind.TemplateMiddle:
    case syntax.SyntaxKind.TemplateTail: {
      const text = (node as import("typescript").LiteralLikeNode).text;
      const kind = syntax.isStringLiteralLike(node) ? "text" : node.kind;
      return [kind, normalize && !/[\t-\r ]/.test(text) ? "<literal>" : text];
    }
    case syntax.SyntaxKind.NumericLiteral:
    case syntax.SyntaxKind.BigIntLiteral:
    case syntax.SyntaxKind.RegularExpressionLiteral:
      return [node.kind, normalize ? "<literal>" : (node as import("typescript").LiteralLikeNode).text];
    case syntax.SyntaxKind.TrueKeyword:
    case syntax.SyntaxKind.FalseKeyword:
      return ["boolean", normalize ? "<literal>" : node.kind];
    case syntax.SyntaxKind.Identifier:
    case syntax.SyntaxKind.PrivateIdentifier:
      return [node.kind, (node as import("typescript").Identifier).text];
    default:
      return undefined;
  }
}
