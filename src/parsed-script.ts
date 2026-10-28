// Shared syntax-only parse boundary (ADR-012): each analysed script is parsed exactly once per
// analysis run, and that one result feeds parse diagnostics, security-flow analysis, and AST
// function discovery. Separate parse paths would triple parser cost and drift apart; this module
// owns the parser, the script-kind mapping, and the AST callable enumeration consumed by the
// block rules (and, downstream, complexity metrics and naming ownership).
import { createRequire } from "node:module";
import { commentRecords, isDividerComment, isFileOverviewComment } from "./comment-scanner.ts";
import type { RunDiagnostic } from "./types.ts";

// Loaded via createRequire because typescript ships as CommonJS; usage stays bounded to syntax
// walking - no type checker, program, language service, or emit (ADR-012).
const require = createRequire(import.meta.url);
const typescriptSyntax = require("typescript") as typeof import("typescript");

type TsSourceFile = import("typescript").SourceFile;
type TsNode = import("typescript").Node;
type TsDiagnostic = import("typescript").DiagnosticWithLocation;

// Minimal file identity the parser needs: the display path picks the grammar and labels
// diagnostics; the script flag keeps config/text inputs from ever paying parser cost.
export interface ParsedScriptInput {
  displayPath: string;
  isScript: boolean;
}

// One parse result shared by every downstream consumer within a single analysis run.
export interface ParsedScript {
  sourceFile: TsSourceFile;
  diagnostics: RunDiagnostic[];
}

/*
 * One cached projection of the shared syntax tree. Every block rule reads this same result, so no
 * rule walks or parses the user's file twice.
 */
interface ParsedSyntaxIndex {
  callablePoints: CallableMatchPoint[];
  // Callables only the size and complexity rules measure; every other block rule reads `callablePoints` alone.
  measuredOnlyPoints: CallableMatchPoint[];
}

const parsedSyntaxIndexes = new WeakMap<ParsedScript, ParsedSyntaxIndex>();

// `createSourceFile` recovers from syntax errors and records them on an internal field; this
// narrow extension types that field without widening the public TypeScript surface.
interface ParsedSourceFileWithDiagnostics extends TsSourceFile {
  parseDiagnostics: TsDiagnostic[];
}

// Test-visible parse counter backing the one-parse-per-script assertion; never drives behavior.
let parseCount = 0;

// Returns how many times the shared parser has run in this process; tests subtract before/after
// snapshots to assert one parse per analysed script.
export function parsedScriptParseCount(): number {
  return parseCount;
}

/**
 * Parses one script into the shared boundary result. Non-script inputs return undefined so a
 * config or text file never parses; diagnostics always cover the whole file (never range-filtered).
 *
 * @param file - display path plus the script flag from discovery; a false script flag skips parsing
 * @param source - decoded file text; empty script text produces a source file with no diagnostics
 * @returns shared parse result; undefined means the input was a config or text file
 */
export function parseScript(file: ParsedScriptInput, source: string): ParsedScript | undefined {
  // Config and text inputs do not enter the script parser, so callers receive no parse result.
  if (!file.isScript) {
    return undefined;
  }
  parseCount += 1;
  const parsedSourceFile = typescriptSyntax.createSourceFile(file.displayPath, source, typescriptSyntax.ScriptTarget.Latest, true, scriptKindFor(file.displayPath)) as ParsedSourceFileWithDiagnostics;
  const firstParseError = parsedSourceFile.parseDiagnostics[0];
  return {
    sourceFile: parsedSourceFile,
    // One report entry per malformed file keeps diagnostics proportional to affected files.
    diagnostics: firstParseError
      ? [summarizeParseErrors(file, parsedSourceFile, firstParseError, parsedSourceFile.parseDiagnostics.length)]
      : [],
  };
}

/**
 * Blanks every decorator in `text` with spaces, keeping newlines and offsets, so a line that holds only decorators reads
 * as blank.
 *
 * @param text - the parsed source text, or a same-length masking of it such as the source with its comments blanked
 * @param parsed - the shared parse of that source
 * @returns `text` with each decorator's characters replaced by spaces
 */
export function maskDecorators(text: string, parsed: ParsedScript): string {
  const characters = text.split("");
  // Walks every node once; decorators can sit on classes, members and parameters at any depth.
  const visit = (node: TsNode): void => {
    // A decorator's span runs from its `@` to the end of its expression, arguments included.
    if (node.kind === typescriptSyntax.SyntaxKind.Decorator) {
      blankRange(characters, node.getStart(parsed.sourceFile), node.end);
    }
    node.forEachChild(visit);
  };
  parsed.sourceFile.forEachChild(visit);
  return characters.join("");
}

/**
 * Flags each line that carries code, for the function-block, for-of body and module line counts (FAMILY-CONTRACT section 12,
 * search `Code lines in every line count`). A line is not code when it is blank or holds only comments or decorators; the
 * text of string and template literals still counts as code.
 *
 * @param source - decoded file text
 * @param parsed - the shared parse of `source`; without it decorators are not recognised and count as code
 * @returns one flag per line of `source`, 0-based, true where the line carries code
 */
export function codeLineFlags(source: string, parsed?: ParsedScript): boolean[] {
  const characters = source.split("");
  for (const comment of commentRecords(source)) {
    blankRange(characters, comment.startIndex, comment.kind === "block" ? Math.min(source.length, comment.endIndex + 1) : comment.endIndex);
  }
  const withoutComments = characters.join("");
  const code = parsed ? maskDecorators(withoutComments, parsed) : withoutComments;
  return code.split(/\r?\n/).map((line) => line.trim() !== "");
}

// Replaces one half-open character range with spaces, keeping line breaks so line numbers do not move.
function blankRange(characters: string[], start: number, end: number): void {
  for (let index = start; index < end && index < characters.length; index += 1) {
    if (characters[index] !== "\n" && characters[index] !== "\r") {
      characters[index] = " ";
    }
  }
}

// Maps extensions onto the matching TypeScript parser mode so TSX/JSX syntax parses as syntax.
// The single copy: source-text and security-flow used to carry one each.
export function scriptKindFor(path: string): import("typescript").ScriptKind {
  if (path.endsWith(".tsx")) {
    return typescriptSyntax.ScriptKind.TSX;
  }
  if (path.endsWith(".jsx")) {
    return typescriptSyntax.ScriptKind.JSX;
  }
  if (path.endsWith(".js") || path.endsWith(".mjs") || path.endsWith(".cjs")) {
    return typescriptSyntax.ScriptKind.JS;
  }
  return typescriptSyntax.ScriptKind.TS;
}

/**
 * Builds the single parse-error entry reported for a source file.
 * Multiple parser errors retain their count and first location so one malformed file cannot flood the report.
 *
 * @param file - discovered source metadata used for the reported path
 * @param sourceFile - parser output used to translate the first error offset into a source line
 * @param firstParseError - first parser error; a missing offset falls back to line 1
 * @param parseErrorCount - total errors in this file; callers provide at least one
 * @returns one diagnostic for the file; reports parser errors without throwing
 */
function summarizeParseErrors(file: ParsedScriptInput, sourceFile: TsSourceFile, firstParseError: TsDiagnostic, parseErrorCount: number): RunDiagnostic {
  // TypeScript can omit an offset for malformed input; line 1 remains a usable report anchor.
  const firstErrorLine = firstParseError.start === undefined
    ? 1
    : sourceFile.getLineAndCharacterOfPosition(firstParseError.start).line + 1;
  const firstErrorMessage = typescriptSyntax.flattenDiagnosticMessageText(firstParseError.messageText, " ");
  // A single error keeps the established wording; larger sets expose their count without repeated entries.
  const parseErrorMessage = parseErrorCount === 1
    ? `TypeScript syntax error: ${firstErrorMessage}`
    : `TypeScript syntax errors: ${parseErrorCount} diagnostics in this file; first: ${firstErrorMessage}`;
  return {
    diagnosticType: "parse-error",
    message: parseErrorMessage,
    filePath: file.displayPath,
    line: firstErrorLine,
  };
}

/*
 * One discovered callable declaration point: the zero-based line index where the legacy regex
 * scanner would have matched, the reported block name, raw parameter text, actual AST parameter
 * count, and the callable node used by later syntax metrics. The block parser turns points into
 * FunctionBlocks with the exact same start/end/body slicing it always used, so the retained
 * fingerprint invariant cannot move.
 */
export interface CallableMatchPoint {
  lineIndex: number;
  // Zero-based first line of the declaration itself, modifiers included but leading documentation
  // excluded. Equals `lineIndex` for every single-line declaration; it moves earlier only when a
  // declaration splits its modifiers onto their own line, where the line above the name is
  // `export async function` rather than the docblock a reader can plainly see.
  declarationLineIndex: number;
  // Zero-based line of the callable's final token. The block parser prefers this over its legacy
  // brace walk: a `{}` inside a multi-line parameter default would otherwise close the walk early
  // and slice an empty body.
  endLineIndex: number;
  name: string;
  params: string;
  parameterCount: number;
  isTestCallable: boolean;
  // Syntax-backed visibility keeps split-line modifiers and file-level re-exports scoped to the
  // declaration that owns them without moving the legacy name-line finding anchor.
  isDirectlyExported: boolean;
  isExplicitlyPublic: boolean;
  isModuleScoped: boolean;
  // False for signature-only declarations: interface and type-literal methods, overload
  // signatures, and abstract or ambient members. The block rules use this instead of guessing
  // from text, because a multi-line signature reads like an implementation on its first line.
  hasBody: boolean;
  // True only for a declaration carrying the `override` modifier: its base class chose the name.
  isOverride: boolean;
  // Shared-parse node whose parameters and body belong to this stable analysed block.
  callableNode: TsNode;
}

/**
 * Enumerates callable declarations from the shared syntax tree: function declarations (including
 * generic and multi-line signatures the regex missed), class/object methods and constructors,
 * interface/type-literal method signatures, const/let arrow and function initializers (including
 * parenless single-argument arrows), and test/it callbacks. At most one point per source line is
 * returned (source order wins) - the legacy scanner's one-block-per-line invariant.
 *
 * @param parsed Shared parse result for the script.
 * @returns Match points sorted by line, ready for the block parser.
 */
export function callableMatchPoints(parsed: ParsedScript): CallableMatchPoint[] {
  return parsedSyntaxIndex(parsed).callablePoints;
}

/**
 * Enumerates the callable forms only the size and complexity rules measure (FAMILY-CONTRACT.md section 12, search
 * `four more function forms`): an object-literal `key: function` method, a function assigned to a member, a `var`
 * function expression and an immediately invoked function. Each takes a function expression or an arrow function.
 * Which callables the documentation rules see is unchanged.
 *
 * @param parsed Shared parse result for the script.
 * @returns Points in source order; empty when the script uses none of these forms.
 */
export function measuredOnlyCallablePoints(parsed: ParsedScript): CallableMatchPoint[] {
  return parsedSyntaxIndex(parsed).measuredOnlyPoints;
}

// Builds one deterministic syntax index per parsed script so every block rule shares one walk.
// Stable contract: repeated consumers receive the same ordered rows.
function parsedSyntaxIndex(parsed: ParsedScript): ParsedSyntaxIndex {
  const cachedIndex = parsedSyntaxIndexes.get(parsed);
  // Multiple rule consumers reach the same file, so a completed projection is reused verbatim.
  if (cachedIndex) {
    return cachedIndex;
  }
  const callablePointsByLine = new Map<number, CallableMatchPoint>();
  const measuredOnlyPoints: CallableMatchPoint[] = [];
  // One depth-first walk visits the user's syntax tree.
  const visitSyntaxNode = (node: TsNode): void => {
    recordCallablePoint(callablePointsByLine, matchPointFor(parsed.sourceFile, node));
    const measuredOnlyPoint = measuredOnlyPointFor(parsed.sourceFile, node);
    // Most nodes are not one of the measure-only forms.
    if (measuredOnlyPoint) {
      measuredOnlyPoints.push(measuredOnlyPoint);
    }
    node.forEachChild(visitSyntaxNode);
  };
  parsed.sourceFile.forEachChild(visitSyntaxNode);
  const syntaxIndex: ParsedSyntaxIndex = {
    callablePoints: [...callablePointsByLine.values()].sort((left, right) => left.lineIndex - right.lineIndex),
    measuredOnlyPoints,
  };
  parsedSyntaxIndexes.set(parsed, syntaxIndex);
  return syntaxIndex;
}

// Applies the established one-block-per-line policy while the shared syntax index is built.
function recordCallablePoint(callablePointsByLine: Map<number, CallableMatchPoint>, callablePoint: CallableMatchPoint | undefined): void {
  // Most syntax nodes are not callable declarations, so they add no report block.
  if (!callablePoint) {
    return;
  }
  const existingPoint = callablePointsByLine.get(callablePoint.lineIndex);
  // Test callbacks outrank same-line declarations; otherwise the first source declaration wins.
  if (!existingPoint || (callablePoint.isTestCallable && !existingPoint.isTestCallable)) {
    callablePointsByLine.set(callablePoint.lineIndex, callablePoint);
  }
}

// Classifies one AST node into a callable match point, or undefined for non-callable nodes.
// Accessors and anonymous/default-export-anonymous functions stay excluded: the legacy scanner
// never discovered them, and naming policy for those shapes is deferred to a separate decision.
function matchPointFor(sourceFile: TsSourceFile, node: TsNode): CallableMatchPoint | undefined {
  if (typescriptSyntax.isFunctionDeclaration(node) && node.name) {
    return declarationPoint(sourceFile, node.name.getStart(sourceFile), node, node.name.text, node.parameters);
  }
  if ((typescriptSyntax.isMethodDeclaration(node) || typescriptSyntax.isMethodSignature(node)) && typescriptSyntax.isIdentifier(node.name)) {
    return declarationPoint(sourceFile, node.name.getStart(sourceFile), node, node.name.text, node.parameters);
  }
  if (typescriptSyntax.isConstructorDeclaration(node)) {
    // Constructors carry no name node; the parameter-list position sits on the declaration line.
    return declarationPoint(sourceFile, node.parameters.pos, node, "constructor", node.parameters);
  }
  if (typescriptSyntax.isVariableDeclaration(node)) {
    return variableInitializerPoint(sourceFile, node);
  }
  if (typescriptSyntax.isCallExpression(node)) {
    return testCallbackPoint(sourceFile, node);
  }
  return undefined;
}

// Finds the point for one of the four measure-only forms; a node is at most one of them.
function measuredOnlyPointFor(sourceFile: TsSourceFile, node: TsNode): CallableMatchPoint | undefined {
  return varFunctionPoint(sourceFile, node) ?? keyFunctionPoint(sourceFile, node) ?? memberFunctionPoint(sourceFile, node) ?? invokedFunctionPoint(sourceFile, node);
}

// `var render = function () {}`, named after the variable.
function varFunctionPoint(sourceFile: TsSourceFile, node: TsNode): CallableMatchPoint | undefined {
  if (!typescriptSyntax.isVariableDeclaration(node) || !typescriptSyntax.isIdentifier(node.name) || !isFunctionValue(node.initializer) || !isVarList(node.parent)) {
    return undefined;
  }
  return declarationPoint(sourceFile, node.name.getStart(sourceFile), node.initializer, node.name.text, node.initializer.parameters);
}

// `{ paint: function () {} }`, named after the key, qualified by the object's variable or assignment target when it has one.
function keyFunctionPoint(sourceFile: TsSourceFile, node: TsNode): CallableMatchPoint | undefined {
  if (!typescriptSyntax.isPropertyAssignment(node) || !isFunctionValue(node.initializer) || typescriptSyntax.isComputedPropertyName(node.name)) {
    return undefined;
  }
  const objectName = objectLiteralName(sourceFile, node.parent);
  const name = objectName ? `${objectName}.${node.name.text}` : node.name.text;
  return declarationPoint(sourceFile, node.name.getStart(sourceFile), node.initializer, name, node.initializer.parameters);
}

// `Calendar.render = function () {}`, named after the member it is assigned to.
function memberFunctionPoint(sourceFile: TsSourceFile, node: TsNode): CallableMatchPoint | undefined {
  if (!typescriptSyntax.isBinaryExpression(node) || node.operatorToken.kind !== typescriptSyntax.SyntaxKind.EqualsToken || !isMember(node.left) || !isFunctionValue(node.right)) {
    return undefined;
  }
  return declarationPoint(sourceFile, node.left.getStart(sourceFile), node.right, compactText(sourceFile, node.left), node.right.parameters);
}

// `(function () {})()`, named after the function when it has a name and `<iife>` otherwise.
function invokedFunctionPoint(sourceFile: TsSourceFile, node: TsNode): CallableMatchPoint | undefined {
  const callee = typescriptSyntax.isCallExpression(node) ? withoutParentheses(node.expression) : undefined;
  if (!isFunctionValue(callee)) {
    return undefined;
  }
  const name = typescriptSyntax.isFunctionExpression(callee) && callee.name ? callee.name.text : "<iife>";
  return declarationPoint(sourceFile, callee.getStart(sourceFile), callee, name, callee.parameters);
}

// A function expression or arrow function is the value each measure-only form binds or invokes.
function isFunctionValue(node: TsNode | undefined): node is import("typescript").FunctionExpression | import("typescript").ArrowFunction {
  return node !== undefined && (typescriptSyntax.isFunctionExpression(node) || typescriptSyntax.isArrowFunction(node));
}

// `const` and `let` initializers are already ordinary blocks (search `variableInitializerPoint`); only `var` is added.
function isVarList(node: TsNode): boolean {
  return typescriptSyntax.isVariableDeclarationList(node) && (node.flags & typescriptSyntax.NodeFlags.BlockScoped) === 0;
}

// A property or element access is the member a function can be assigned to.
function isMember(node: TsNode): boolean {
  return typescriptSyntax.isPropertyAccessExpression(node) || typescriptSyntax.isElementAccessExpression(node);
}

// The name an object literal is bound to, when it is a variable's initializer or the right side of an assignment.
function objectLiteralName(sourceFile: TsSourceFile, objectLiteral: TsNode): string | undefined {
  const owner = objectLiteral.parent;
  if (typescriptSyntax.isVariableDeclaration(owner) && typescriptSyntax.isIdentifier(owner.name)) {
    return owner.name.text;
  }
  if (typescriptSyntax.isBinaryExpression(owner) && owner.operatorToken.kind === typescriptSyntax.SyntaxKind.EqualsToken && owner.right === objectLiteral) {
    return compactText(sourceFile, owner.left);
  }
  return undefined;
}

// Source text with its whitespace removed, so a member written across lines names its function on one.
function compactText(sourceFile: TsSourceFile, node: TsNode): string {
  return node.getText(sourceFile).replace(/\s+/g, "");
}

// Looks through the parentheses an immediately invoked function is usually wrapped in.
function withoutParentheses(node: TsNode): TsNode {
  let inner = node;
  while (typescriptSyntax.isParenthesizedExpression(inner)) {
    inner = inner.expression;
  }
  return inner;
}

// Builds the point for a named declaration: the anchor line is the name's line, matching where
// the legacy line-oriented patterns fired; the end line is the declaration's final token.
function declarationPoint(sourceFile: TsSourceFile, position: number, callableNode: TsNode, name: string, parameters: readonly TsNode[]): CallableMatchPoint {
  const visibilityNode = callableVisibilityNode(callableNode);
  const isDirectlyExported = hasNodeModifier(visibilityNode, typescriptSyntax.SyntaxKind.ExportKeyword);
  const lineIndex = sourceFile.getLineAndCharacterOfPosition(position).line;
  // `getStart` skips leading documentation, so this lands on the first modifier or keyword. Clamped
  // to `lineIndex` so the declaration anchor can only ever move earlier than the reported name line.
  const declarationStartLine = sourceFile.getLineAndCharacterOfPosition(visibilityNode.getStart(sourceFile)).line;
  return {
    lineIndex,
    declarationLineIndex: Math.min(declarationStartLine, lineIndex),
    endLineIndex: sourceFile.getLineAndCharacterOfPosition(callableNode.getEnd()).line,
    name,
    params: parametersText(sourceFile, parameters),
    parameterCount: parameters.length,
    isTestCallable: false,
    isDirectlyExported,
    isExplicitlyPublic: isDirectlyExported || hasNodeModifier(visibilityNode, typescriptSyntax.SyntaxKind.PublicKeyword),
    isModuleScoped: visibilityNode.parent === sourceFile,
    hasBody: callableNodeHasBody(callableNode),
    isOverride: hasNodeModifier(visibilityNode, typescriptSyntax.SyntaxKind.OverrideKeyword),
    callableNode,
  };
}

// Variable-backed callables inherit export modifiers and module scope from their statement;
// declaration-shaped callables already carry both facts on their own node.
function callableVisibilityNode(callableNode: TsNode): TsNode {
  const declaration = callableNode.parent;
  if (!typescriptSyntax.isVariableDeclaration(declaration)) {
    return callableNode;
  }
  const declarationList = declaration.parent;
  if (!typescriptSyntax.isVariableDeclarationList(declarationList)) {
    return callableNode;
  }
  const statement = declarationList.parent;
  return typescriptSyntax.isVariableStatement(statement) ? statement : callableNode;
}

// Reads a modifier only when the syntax node can own modifiers.
function hasNodeModifier(node: TsNode, modifierKind: import("typescript").SyntaxKind): boolean {
  const modifiers = typescriptSyntax.canHaveModifiers(node) ? typescriptSyntax.getModifiers(node) : undefined;
  return modifiers?.some((modifier) => modifier.kind === modifierKind) === true;
}

// Arrow functions and function expressions always carry a body, so only declaration-shaped nodes
// can answer false here: a method signature has no `body` property at all, and an overload or
// abstract member leaves it undefined.
function callableNodeHasBody(callableNode: TsNode): boolean {
  return (callableNode as { body?: unknown }).body !== undefined;
}

// const/let initializer arrows and function expressions become blocks named after the variable;
// `var` stays excluded because the legacy pattern never matched it.
function variableInitializerPoint(sourceFile: TsSourceFile, node: import("typescript").VariableDeclaration): CallableMatchPoint | undefined {
  if (!typescriptSyntax.isIdentifier(node.name) || !node.initializer) {
    return undefined;
  }
  if (!typescriptSyntax.isArrowFunction(node.initializer) && !typescriptSyntax.isFunctionExpression(node.initializer)) {
    return undefined;
  }
  const declarationList = node.parent;
  if (!typescriptSyntax.isVariableDeclarationList(declarationList) || (declarationList.flags & typescriptSyntax.NodeFlags.Const) === 0 && (declarationList.flags & typescriptSyntax.NodeFlags.Let) === 0) {
    return undefined;
  }
  return declarationPoint(sourceFile, node.name.getStart(sourceFile), node.initializer, node.name.text, node.initializer.parameters);
}

// `test("name", () => …)` / `it("name", …)` callbacks become blocks named by the test title,
// anchored at the call line - the legacy scanner's highest-priority pattern.
function testCallbackPoint(sourceFile: TsSourceFile, node: import("typescript").CallExpression): CallableMatchPoint | undefined {
  if (!typescriptSyntax.isIdentifier(node.expression) || (node.expression.text !== "test" && node.expression.text !== "it")) {
    return undefined;
  }
  const [title, callback] = node.arguments;
  if (!title || !typescriptSyntax.isStringLiteralLike(title) || !callback) {
    return undefined;
  }
  if (!typescriptSyntax.isArrowFunction(callback) && !typescriptSyntax.isFunctionExpression(callback)) {
    return undefined;
  }
  const lineIndex = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line;
  return {
    lineIndex,
    // A test callback is anchored at its call expression, which is already the declaration line.
    declarationLineIndex: lineIndex,
    endLineIndex: sourceFile.getLineAndCharacterOfPosition(node.getEnd()).line,
    name: title.text,
    params: parametersText(sourceFile, callback.parameters),
    parameterCount: callback.parameters.length,
    isTestCallable: true,
    isDirectlyExported: false,
    isExplicitlyPublic: false,
    isModuleScoped: false,
    hasBody: true,
    isOverride: false,
    callableNode: callback,
  };
}

// Joins each AST parameter span without the inter-parameter trivia where an end-of-line comment
// could otherwise swallow the following name after newlines are flattened.
function parametersText(sourceFile: TsSourceFile, parameters: readonly TsNode[]): string {
  return parameters
    .map((parameter) => sourceFile.text.slice(parameter.getStart(sourceFile), parameter.getEnd()))
    .join(", ")
    .replace(/\r?\n/g, " ");
}

/*
 * One documented callable as the docblock rules consume it (exported function declarations by default;
 * exported constants, default and later exports, methods, and private or nested callables only under
 * the tag rules' `everyCallable` switches): the JSDoc text
 * between its markers, the declared name, identifier parameter names (destructured parameters stay
 * intentionally invisible, matching the legacy text splitter), the docblock's one-based start line
 * (the docblock rules' stable finding anchor), the declared return type text ("" when absent), and
 * whether the body itself returns a value, which only `docs.missing-return-tag`'s `everyCallable`
 * switch reads.
 */
export interface DocumentedExportFunction {
  docText: string;
  name: string;
  parameterNames: string[];
  line: number;
  returnTypeText: string;
  hasBodyReturnValue: boolean;
}

/**
 * Enumerates every exported function declaration that carries a leading JSDoc block. Anchoring to
 * the syntax tree means prose containing the word `export` inside a comment can no longer suppress
 * detection, and `export async function` plus generic and multi-line signatures are covered.
 *
 * @param parsed Shared parse result for the script.
 * @returns Documented exported functions in source order; empty when the file has none.
 */
export function documentedExportFunctions(parsed: ParsedScript): DocumentedExportFunction[] {
  return collectDocumented(parsed, documentedExportFunction);
}

/**
 * Enumerates every exported `const` bound to an arrow function or function expression whose
 * statement carries a leading JSDoc block, for the tag rules' `everyCallable` switches. The JSDoc
 * attaches to the variable statement, so the parameters and return type come from the initializer.
 *
 * @param parsed Shared parse result for the script.
 * @returns Documented exported callable constants in source order; empty when the file has none.
 */
export function documentedExportConstants(parsed: ParsedScript): DocumentedExportFunction[] {
  return collectDocumented(parsed, documentedExportConstant);
}

// Full-depth walk so namespaced exports keep their docblock coverage too. `project` decides which
// nodes count and returns undefined for the rest, so results stay in source order.
function collectDocumented(parsed: ParsedScript, project: (sourceFile: TsSourceFile, node: TsNode) => DocumentedExportFunction | undefined): DocumentedExportFunction[] {
  const results: DocumentedExportFunction[] = [];
  // Records each projected node, then recurses so nested namespaces are reached too.
  const visit = (node: TsNode): void => {
    const documented = project(parsed.sourceFile, node);
    if (documented) {
      results.push(documented);
    }
    node.forEachChild(visit);
  };
  parsed.sourceFile.forEachChild(visit);
  return results;
}

// Projects one function declaration into the documented-export shape, or undefined when it is not
// an exported named function with a JSDoc block. `export default function` never matched the
// legacy pattern, so the default pass still excludes it; the tag rules' `everyCallable` switches
// cover it through `documentedDefaultAndLaterExports`.
function documentedExportFunction(sourceFile: TsSourceFile, node: TsNode): DocumentedExportFunction | undefined {
  if (!typescriptSyntax.isFunctionDeclaration(node) || !node.name) {
    return undefined;
  }
  const flags = typescriptSyntax.getCombinedModifierFlags(node);
  if ((flags & typescriptSyntax.ModifierFlags.Export) === 0 || (flags & typescriptSyntax.ModifierFlags.Default) !== 0) {
    return undefined;
  }
  return documentedCallable(sourceFile, node, node.name.text, node);
}

// Projects one exported `const name = (...) => ...` or `const name = function (...) {...}`
// statement, or undefined for any other node. The JSDoc is read from the statement because that
// is where the parser attaches it.
function documentedExportConstant(sourceFile: TsSourceFile, node: TsNode): DocumentedExportFunction | undefined {
  const declaration = soleConstDeclaration(node);
  return declaration && hasExportFlag(declaration) ? documentedConstantCallable(sourceFile, node, declaration) : undefined;
}

// Projects the one binding of a `const` statement when it is an identifier bound to an arrow
// function or function expression, or undefined otherwise. The JSDoc comes from the statement.
function documentedConstantCallable(sourceFile: TsSourceFile, statement: TsNode, declaration: import("typescript").VariableDeclaration): DocumentedExportFunction | undefined {
  const initializer = declaration.initializer;
  if (!initializer || !typescriptSyntax.isIdentifier(declaration.name)) {
    return undefined;
  }
  if (!typescriptSyntax.isArrowFunction(initializer) && !typescriptSyntax.isFunctionExpression(initializer)) {
    return undefined;
  }
  return documentedCallable(sourceFile, statement, declaration.name.text, initializer);
}

// Returns the declaration of a `const` statement that declares exactly one binding.
// A statement such as `const a = ..., b = ...` is skipped because one docblock above it cannot be
// said to document both callables.
function soleConstDeclaration(node: TsNode): import("typescript").VariableDeclaration | undefined {
  if (!typescriptSyntax.isVariableStatement(node) || (node.declarationList.flags & typescriptSyntax.NodeFlags.Const) === 0) {
    return undefined;
  }
  const [declaration, ...others] = node.declarationList.declarations;
  return declaration && others.length === 0 ? declaration : undefined;
}

// Whether a declaration carries its own `export` modifier, directly or through its statement.
function hasExportFlag(declaration: import("typescript").Declaration): boolean {
  return (typescriptSyntax.getCombinedModifierFlags(declaration) & typescriptSyntax.ModifierFlags.Export) !== 0;
}

/**
 * Enumerates the documented callables that reach the module surface through a default export or a
 * later export statement, for the tag rules' `everyCallable` switches: an `export default function`
 * (an anonymous one is named `default`, the name importers see), an `export default` arrow function
 * (also named `default`), and a top-level function declaration or single-binding `const` callable
 * without its own `export` modifier that a later `export { name }` or `export default name`
 * statement names. Callables named by a later statement keep their declared local name.
 *
 * @param parsed Shared parse result for the script.
 * @returns Documented default and later-exported callables in source order; empty when the file has none.
 */
export function documentedDefaultAndLaterExports(parsed: ParsedScript): DocumentedExportFunction[] {
  const laterExportedNames = laterExportedLocalNames(parsed.sourceFile);
  const results: DocumentedExportFunction[] = [];
  // Default exports and export lists are module-level syntax, so only top-level statements count.
  for (const statement of parsed.sourceFile.statements) {
    const documented = documentedDefaultExport(parsed.sourceFile, statement) ?? documentedLaterExport(parsed.sourceFile, statement, laterExportedNames);
    if (documented) {
      results.push(documented);
    }
  }
  return results;
}

// Projects an `export default function` declaration or an `export default` arrow function, or
// undefined for any other statement. A parenthesised default expression is not unwrapped.
function documentedDefaultExport(sourceFile: TsSourceFile, statement: TsNode): DocumentedExportFunction | undefined {
  if (typescriptSyntax.isFunctionDeclaration(statement)) {
    const isDefault = (typescriptSyntax.getCombinedModifierFlags(statement) & typescriptSyntax.ModifierFlags.Default) !== 0;
    return isDefault ? documentedCallable(sourceFile, statement, statement.name?.text ?? "default", statement) : undefined;
  }
  if (!typescriptSyntax.isExportAssignment(statement) || statement.isExportEquals || !typescriptSyntax.isArrowFunction(statement.expression)) {
    return undefined;
  }
  return documentedCallable(sourceFile, statement, "default", statement.expression);
}

// Projects a top-level function declaration or single-binding `const` callable that lacks its own
// `export` modifier but is named by a later export statement, or undefined for anything else.
// Declarations with the modifier already reach the default pass or the exported-constant list.
function documentedLaterExport(sourceFile: TsSourceFile, statement: TsNode, laterExportedNames: ReadonlySet<string>): DocumentedExportFunction | undefined {
  if (typescriptSyntax.isFunctionDeclaration(statement)) {
    const name = statement.name?.text;
    return name !== undefined && laterExportedNames.has(name) && !hasExportFlag(statement) ? documentedCallable(sourceFile, statement, name, statement) : undefined;
  }
  const declaration = soleConstDeclaration(statement);
  if (!declaration || hasExportFlag(declaration) || !typescriptSyntax.isIdentifier(declaration.name) || !laterExportedNames.has(declaration.name.text)) {
    return undefined;
  }
  return documentedConstantCallable(sourceFile, statement, declaration);
}

// Local names that an `export default name` or `export { name }` / `export { name as alias }`
// statement exposes. Export statements may sit anywhere at the top level, so all are read first.
function laterExportedLocalNames(sourceFile: TsSourceFile): Set<string> {
  const names = new Set<string>();
  // Collects the local name from every default-name export and every local export list.
  for (const statement of sourceFile.statements) {
    if (typescriptSyntax.isExportAssignment(statement) && typescriptSyntax.isIdentifier(statement.expression)) {
      names.add(statement.expression.text);
    }
    for (const name of localExportListNames(statement)) {
      names.add(name);
    }
  }
  return names;
}

// The local names in one `export { ... }` statement; empty for any other statement, a re-export
// from another module, or a type-only export, none of which name a local value.
function localExportListNames(statement: TsNode): string[] {
  if (!typescriptSyntax.isExportDeclaration(statement) || statement.moduleSpecifier || statement.isTypeOnly || !statement.exportClause || !typescriptSyntax.isNamedExports(statement.exportClause)) {
    return [];
  }
  return statement.exportClause.elements.filter((element) => !element.isTypeOnly).map((element) => (element.propertyName ?? element.name).text);
}

/**
 * Enumerates the documented private and nested callables for the tag rules' `everyCallable`
 * switches: every function declaration and single-binding `const` arrow or function-expression
 * callable, at any depth, that has no `export` modifier of its own and is not a top-level callable
 * named by a later export statement. Exported forms reach the default pass,
 * `documentedExportConstants` or `documentedDefaultAndLaterExports`, so none is reported twice.
 *
 * @param parsed Shared parse result for the script.
 * @returns Documented private and nested callables in source order; empty when the file has none.
 */
export function documentedPrivateCallables(parsed: ParsedScript): DocumentedExportFunction[] {
  const laterExportedNames = laterExportedLocalNames(parsed.sourceFile);
  return collectDocumented(parsed, (sourceFile, node) => documentedPrivateCallable(sourceFile, node, laterExportedNames));
}

// Projects a function declaration or single-binding `const` callable without its own `export`
// modifier, or undefined for anything else. A top-level one named by a later export statement is
// left to `documentedLaterExport`; a nested one of that name is a different binding, so it counts.
function documentedPrivateCallable(sourceFile: TsSourceFile, node: TsNode, laterExportedNames: ReadonlySet<string>): DocumentedExportFunction | undefined {
  // Only a top-level binding can be the one a later export statement names.
  const isLaterExported = (name: string): boolean => node.parent === sourceFile && laterExportedNames.has(name);
  if (typescriptSyntax.isFunctionDeclaration(node)) {
    const name = node.name?.text;
    return name !== undefined && !hasExportFlag(node) && !isLaterExported(name) ? documentedCallable(sourceFile, node, name, node) : undefined;
  }
  const declaration = soleConstDeclaration(node);
  if (!declaration || hasExportFlag(declaration) || !typescriptSyntax.isIdentifier(declaration.name) || isLaterExported(declaration.name.text)) {
    return undefined;
  }
  return documentedConstantCallable(sourceFile, node, declaration);
}

/**
 * Enumerates every class and object-literal method that carries a leading JSDoc block, for the tag
 * rules' `everyCallable` switches. Static and private methods count too; constructors, accessors
 * and arrow-valued properties are not method declarations and stay out. Each method is named bare
 * (`join`, `pickFirst`), as the size and missing-doc rules name it; same-named methods of two owners
 * in one file stay apart through the finding identity's declaration ordinal.
 *
 * @param parsed Shared parse result for the script.
 * @returns Documented methods in source order; empty when the file has none.
 */
export function documentedMethods(parsed: ParsedScript): DocumentedExportFunction[] {
  return collectDocumented(parsed, documentedMethod);
}

/**
 * Reports whether a callable is a public method of an exported class: a method declaration with
 * no `private` or `protected` modifier and no `#private` name, declared in a class that carries
 * the `export` modifier. The tag rules' `everyCallable` switches report such an undocumented
 * method at the exported severity (operator decision D8).
 *
 * @param callableNode Shared-parse node of one analysed callable.
 * @returns True when the callable belongs to an exported class's public surface.
 */
export function isPublicExportedClassMethod(callableNode: TsNode): boolean {
  if (!typescriptSyntax.isMethodDeclaration(callableNode) || typescriptSyntax.isPrivateIdentifier(callableNode.name)) {
    return false;
  }
  if (hasNodeModifier(callableNode, typescriptSyntax.SyntaxKind.PrivateKeyword) || hasNodeModifier(callableNode, typescriptSyntax.SyntaxKind.ProtectedKeyword)) {
    return false;
  }
  return typescriptSyntax.isClassDeclaration(callableNode.parent) && hasNodeModifier(callableNode.parent, typescriptSyntax.SyntaxKind.ExportKeyword);
}

// Projects one method declaration with an identifier or `#private` name, or undefined for any
// other node. Computed and literal method names have no plain name to report, so they stay out.
function documentedMethod(sourceFile: TsSourceFile, node: TsNode): DocumentedExportFunction | undefined {
  if (!typescriptSyntax.isMethodDeclaration(node) || (!typescriptSyntax.isIdentifier(node.name) && !typescriptSyntax.isPrivateIdentifier(node.name))) {
    return undefined;
  }
  // A method is named bare, as gruff-ts's size and missing-doc rules name it; two same-named methods in one file
  // stay apart through the finding identity's declaration ordinal.
  return documentedCallable(sourceFile, node, node.name.text, node);
}

// Shared projection: the JSDoc comes from `docHost` (the declaration itself, or the statement that
// holds a callable constant) while the parameters and return type come from `callable`.
function documentedCallable(sourceFile: TsSourceFile, docHost: TsNode, name: string, callable: import("typescript").SignatureDeclarationBase): DocumentedExportFunction | undefined {
  const jsDocs = (docHost as { jsDoc?: readonly import("typescript").JSDoc[] }).jsDoc;
  const jsDoc = jsDocs?.[jsDocs.length - 1];
  if (!jsDoc || isOverviewOrDividerJsDoc(sourceFile, docHost, jsDoc)) {
    return undefined;
  }
  return {
    docText: sourceFile.text.slice(jsDoc.getStart(sourceFile) + 3, jsDoc.getEnd() - 2),
    name,
    parameterNames: callable.parameters
      .map((parameter) => (typescriptSyntax.isIdentifier(parameter.name) ? parameter.name.text : undefined))
      .filter((parameterName): parameterName is string => parameterName !== undefined),
    line: sourceFile.getLineAndCharacterOfPosition(jsDoc.getStart(sourceFile)).line + 1,
    returnTypeText: callable.type ? callable.type.getText(sourceFile).replace(/\s+/g, " ").trim() : "",
    hasBodyReturnValue: isBodyReturningValue(callable),
  };
}

// A divider, or the file's overview that TypeScript attaches to the first statement, is not this
// callable's docblock (M13-T18). Only the first statement can carry the file's opening comment.
function isOverviewOrDividerJsDoc(sourceFile: TsSourceFile, docHost: TsNode, jsDoc: import("typescript").JSDoc): boolean {
  const commentText = sourceFile.text.slice(jsDoc.getStart(sourceFile), jsDoc.getEnd());
  if (isDividerComment(commentText)) {
    return true;
  }
  const gapLines = sourceFile.text.slice(jsDoc.getEnd(), docHost.getStart(sourceFile)).split(/\r?\n/).slice(1, -1);
  return sourceFile.statements[0] === docHost && isFileOverviewComment(commentText, gapLines);
}

/*
 * Return-value inference for `docs.missing-return-tag`'s `everyCallable` switch, read from the
 * syntax alone. A concise arrow body returns its expression; a block body returns a value when one
 * of its own `return` statements carries one. A bare `return;`, `return undefined;` and
 * `return void x;` hand back nothing. Returns inside nested functions and classes belong to those
 * callables and are skipped. Bodiless signatures (overloads, `declare`, abstract methods) return false.
 */
function isBodyReturningValue(callable: import("typescript").SignatureDeclarationBase): boolean {
  const body = (callable as { body?: TsNode }).body;
  if (!body) {
    return false;
  }
  return typescriptSyntax.isBlock(body) ? hasOwnValueReturn(body) : isValueExpression(body);
}

// Whether a callable hands back a value, for the missing-doc message (M13-T29, operator decision D3).
// A declared type wins: `void`, `undefined`, `never`, an `asserts` predicate and a promise of `void`
// or `undefined` return nothing. Without a declared type, `isBodyReturningValue` reads the body.
export function isCallableReturningValue(callableNode: TsNode): boolean {
  if (!typescriptSyntax.isFunctionLike(callableNode)) {
    return false;
  }
  if (callableNode.type === undefined) {
    return isBodyReturningValue(callableNode);
  }
  const returnType = callableNode.type.getText().replace(/\s+/g, " ").trim();
  return !/^(?:void|undefined|never|asserts\b.*|Promise< ?(?:void|undefined) ?>)$/.test(returnType);
}

// Depth-first search for a value-carrying `return` of the enclosing callable. It stops at function
// and class boundaries, so a callback's or nested method's return does not count.
function hasOwnValueReturn(node: TsNode): boolean {
  if (typescriptSyntax.isReturnStatement(node)) {
    return node.expression !== undefined && isValueExpression(node.expression);
  }
  if (typescriptSyntax.isFunctionLike(node) || typescriptSyntax.isClassLike(node)) {
    return false;
  }
  return node.forEachChild((child) => (hasOwnValueReturn(child) ? true : undefined)) ?? false;
}

// `undefined` and a `void` expression evaluate to nothing, so returning one is the same as a bare `return;`.
function isValueExpression(expression: TsNode): boolean {
  return !typescriptSyntax.isVoidExpression(expression) && !(typescriptSyntax.isIdentifier(expression) && expression.text === "undefined");
}
