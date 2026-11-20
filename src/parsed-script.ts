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
 * Each script input increments the process-wide parse count exposed by parsedScriptParseCount.
 *
 * @param file - display path plus the script flag from discovery; a false script flag skips parsing
 * @param source - decoded file text; empty script text produces a source file with no diagnostics
 * @returns - shared parse result. No diagnostics means a clean parse. Undefined means the script flag was false.
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
 * Masks decorators with spaces while preserving line breaks and offsets, so decorator-only lines read as blank.
 *
 * @param text - the parsed source text, or a same-length masking of it such as the source with its comments blanked
 * @param parsed - the shared parse of that source
 * @returns Text with decorator characters replaced by spaces except for CR and LF.
 */
export function maskDecorators(text: string, parsed: ParsedScript): string {
  const characters = text.split("");
  // Returns nothing. Visits node and its descendants and blanks decorator spans in the shared buffer to preserve source offsets.
  const visit = (node: TsNode): void => {
    // A decorator's span runs from its at sign to the end of its expression, arguments included.
    if (node.kind === typescriptSyntax.SyntaxKind.Decorator) {
      blankRange(characters, node.getStart(parsed.sourceFile), node.end);
    }
    node.forEachChild(visit);
  };
  parsed.sourceFile.forEachChild(visit);
  return characters.join("");
}

/**
 * Flags lines for the function-block, for-of body and module counts in FAMILY-CONTRACT section 12.
 * Blank lines and comment-only lines do not count. With a parse, decorator-only lines do not count either.
 * Nonblank string and template text outside those masked spans counts as code.
 *
 * @param source - decoded file text whose comment ranges and line boundaries determine the flags
 * @param parsed - the shared parse of source; without it decorators are not recognised and count as code
 * @returns - one flag per LF- or CRLF-delimited line in source order. Empty source returns one false flag.
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

// Returns nothing and replaces characters in place with spaces from start up to but excluding end, bounded by the array length.
// Preserves CR and LF so line numbers stay fixed for LF- and CRLF-delimited text.
function blankRange(characters: string[], start: number, end: number): void {
  for (let index = start; index < end && index < characters.length; index += 1) {
    if (characters[index] !== "\n" && characters[index] !== "\r") {
      characters[index] = " ";
    }
  }
}

// Returns the TypeScript parser mode selected by path's case-sensitive extension so JSX and TSX are parsed correctly.
// Recognises .tsx, .jsx, .js, .mjs and .cjs; all other paths use TS mode.
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
 * Returns cached callable points, building the shared syntax index on first access. Ties go to the first point recorded on the line.
 * Covers named functions, identifier-named methods and signatures, constructors, and identifier-bound const or let function values.
 * Bare test and it calls need a literal title and a function callback. These callbacks take priority over other points on the same line.
 *
 * @param parsed - script parse whose syntax tree is indexed
 * @returns - cached points sorted by zero-based source line; empty when no supported callable is found
 */
export function callableMatchPoints(parsed: ParsedScript): CallableMatchPoint[] {
  return parsedSyntaxIndex(parsed).callablePoints;
}

/**
 * List the four callable forms reserved for size and complexity checks in FAMILY-CONTRACT.md section 12.
 * Covers function or arrow expressions in non-computed properties, member assignments, identifier-bound var initializers and immediate calls.
 * Uses the shared syntax index and caches it on first access for this parse.
 *
 * @param parsed - script parse whose syntax index supplies the callable locations
 * @returns the cached match points in source order, empty when the script uses none of those forms
 */
export function measuredOnlyCallablePoints(parsed: ParsedScript): CallableMatchPoint[] {
  return parsedSyntaxIndex(parsed).measuredOnlyPoints;
}

// Returns the index for parsed's syntax tree so that block rules share one walk.
// Caches the index by parse identity and reuses it on later calls.
// The stable index holds ordinary callable points sorted by line and measure-only points in traversal order.
function parsedSyntaxIndex(parsed: ParsedScript): ParsedSyntaxIndex {
  const cachedIndex = parsedSyntaxIndexes.get(parsed);
  // Multiple rule consumers reach the same file, so a completed projection is reused verbatim.
  if (cachedIndex) {
    return cachedIndex;
  }
  const callablePointsByLine = new Map<number, CallableMatchPoint>();
  const measuredOnlyPoints: CallableMatchPoint[] = [];
  // Returns nothing. Visits node and its descendants to populate the shared callable map and list of measure-only points.
  const visitSyntaxNode = (node: TsNode): void => {
    recordCallablePoint(callablePointsByLine, matchPointFor(parsed.sourceFile, node));
    const measuredOnlyPoint = measuredOnlyPointFor(parsed.sourceFile, node);
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

// Returns nothing. Updates callablePointsByLine with callablePoint under the one-block-per-line policy. Undefined leaves the map unchanged.
function recordCallablePoint(callablePointsByLine: Map<number, CallableMatchPoint>, callablePoint: CallableMatchPoint | undefined): void {
  // Most syntax nodes are not callable declarations, so they add no report block.
  if (!callablePoint) {
    return;
  }
  const existingPoint = callablePointsByLine.get(callablePoint.lineIndex);
  // A test callback replaces a non-test point on the same line. Otherwise the first recorded point stays.
  if (!existingPoint || (callablePoint.isTestCallable && !existingPoint.isTestCallable)) {
    callablePointsByLine.set(callablePoint.lineIndex, callablePoint);
  }
}

// Returns a match point for node when it is a named function, identifier-named method or signature, or constructor.
// Also covers identifier-bound const or let function values and bare test or it calls with a literal title and a function callback.
// Uses sourceFile for positions and parameter text. Unsupported shapes, including accessors and anonymous declarations, return undefined.
function matchPointFor(sourceFile: TsSourceFile, node: TsNode): CallableMatchPoint | undefined {
  if (typescriptSyntax.isFunctionDeclaration(node) && node.name) {
    return declarationPoint(sourceFile, node.name.getStart(sourceFile), node, node.name.text, node.parameters);
  }
  if ((typescriptSyntax.isMethodDeclaration(node) || typescriptSyntax.isMethodSignature(node)) && typescriptSyntax.isIdentifier(node.name)) {
    return declarationPoint(sourceFile, node.name.getStart(sourceFile), node, node.name.text, node.parameters);
  }
  if (typescriptSyntax.isConstructorDeclaration(node)) {
    // Constructors have no name node, so the match point uses the parameter-list position as its anchor.
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

// Projects node into a size/complexity-only match point for a var binding, object key, member assignment or immediate invocation.
// Uses sourceFile for positions and parameter text; returns undefined when no supported function-value form matches.
function measuredOnlyPointFor(sourceFile: TsSourceFile, node: TsNode): CallableMatchPoint | undefined {
  return varFunctionPoint(sourceFile, node) ?? keyFunctionPoint(sourceFile, node) ?? memberFunctionPoint(sourceFile, node) ?? invokedFunctionPoint(sourceFile, node);
}

// Returns a match point for node when it is an identifier-named var binding initialized with a function expression or arrow.
// Uses sourceFile for positions and parameter text and names the point after the variable; returns undefined for other shapes.
function varFunctionPoint(sourceFile: TsSourceFile, node: TsNode): CallableMatchPoint | undefined {
  if (!typescriptSyntax.isVariableDeclaration(node) || !typescriptSyntax.isIdentifier(node.name) || !isFunctionValue(node.initializer) || !isVarList(node.parent)) {
    return undefined;
  }
  return declarationPoint(sourceFile, node.name.getStart(sourceFile), node.initializer, node.name.text, node.initializer.parameters);
}

// Projects node into a match point for a non-computed object property whose value is a function expression or arrow.
// Uses sourceFile for positions and parameter text; prefixes the key with the object's variable or assignment target when known.
// Keeps the bare key without an owner name and returns undefined when node does not match.
function keyFunctionPoint(sourceFile: TsSourceFile, node: TsNode): CallableMatchPoint | undefined {
  if (!typescriptSyntax.isPropertyAssignment(node) || !isFunctionValue(node.initializer) || typescriptSyntax.isComputedPropertyName(node.name)) {
    return undefined;
  }
  const objectName = objectLiteralName(sourceFile, node.parent);
  const name = objectName ? `${objectName}.${node.name.text}` : node.name.text;
  return declarationPoint(sourceFile, node.name.getStart(sourceFile), node.initializer, name, node.initializer.parameters);
}

// Returns a match point when node assigns a function expression or arrow to a property or element access.
// Uses sourceFile for source positions, parameter text and the target name; returns undefined for other node shapes.
function memberFunctionPoint(sourceFile: TsSourceFile, node: TsNode): CallableMatchPoint | undefined {
  if (!typescriptSyntax.isBinaryExpression(node) || node.operatorToken.kind !== typescriptSyntax.SyntaxKind.EqualsToken || !isMember(node.left) || !isFunctionValue(node.right)) {
    return undefined;
  }
  return declarationPoint(sourceFile, node.left.getStart(sourceFile), node.right, compactText(sourceFile, node.left), node.right.parameters);
}

// Returns a match point when node directly invokes a function expression or arrow; sourceFile supplies positions and parameter text.
// Uses the function expression's name or <iife> when unnamed; returns undefined for all other nodes.
function invokedFunctionPoint(sourceFile: TsSourceFile, node: TsNode): CallableMatchPoint | undefined {
  const callee = typescriptSyntax.isCallExpression(node) ? withoutParentheses(node.expression) : undefined;
  if (!isFunctionValue(callee)) {
    return undefined;
  }
  const name = typescriptSyntax.isFunctionExpression(callee) && callee.name ? callee.name.text : "<iife>";
  return declarationPoint(sourceFile, callee.getStart(sourceFile), callee, name, callee.parameters);
}

// Returns true and narrows node for a function expression or arrow function; undefined and all other node kinds return false.
function isFunctionValue(node: TsNode | undefined): node is import("typescript").FunctionExpression | import("typescript").ArrowFunction {
  return node !== undefined && (typescriptSyntax.isFunctionExpression(node) || typescriptSyntax.isArrowFunction(node));
}

// Returns whether node is a var declaration list; const and let lists are excluded because variableInitializerPoint already handles them.
function isVarList(node: TsNode): boolean {
  return typescriptSyntax.isVariableDeclarationList(node) && (node.flags & typescriptSyntax.NodeFlags.BlockScoped) === 0;
}

// Returns whether node is a property or element access, the member targets accepted for function assignments.
function isMember(node: TsNode): boolean {
  return typescriptSyntax.isPropertyAccessExpression(node) || typescriptSyntax.isElementAccessExpression(node);
}

// Returns the binding name for objectLiteral, or reads its assignment target from sourceFile and removes all whitespace for the label.
// Returns undefined unless the object directly initializes an identifier binding or is the right-hand side of a simple equals assignment.
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

// Returns node's text from sourceFile with all whitespace removed, keeping multiline member names on one line.
function compactText(sourceFile: TsSourceFile, node: TsNode): string {
  return node.getText(sourceFile).replace(/\s+/g, "");
}

// Returns node with all outer parentheses removed, exposing an immediate call's callee; returns node itself when it is not parenthesized.
function withoutParentheses(node: TsNode): TsNode {
  let inner = node;
  while (typescriptSyntax.isParenthesizedExpression(inner)) {
    inner = inner.expression;
  }
  return inner;
}

// Builds a callable match point for callableNode in sourceFile, using position to choose the reported line.
// name is the reported label and parameters supply displayed parameter text and count.
// The point records name and declaration lines, the final-token line, visibility and body flags; all line indexes are zero-based.
function declarationPoint(sourceFile: TsSourceFile, position: number, callableNode: TsNode, name: string, parameters: readonly TsNode[]): CallableMatchPoint {
  const visibilityNode = callableVisibilityNode(callableNode);
  const isDirectlyExported = hasNodeModifier(visibilityNode, typescriptSyntax.SyntaxKind.ExportKeyword);
  const lineIndex = sourceFile.getLineAndCharacterOfPosition(position).line;
  // getStart skips leading documentation, so this finds the start of the declaration syntax.
  // Clamp the declaration anchor because a callable expression can start on a later line than its reported label.
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

// Returns the enclosing variable statement for a variable-backed callableNode so visibility checks see its export and module scope.
// Returns callableNode itself for declaration-shaped callables or when the expected variable-statement ancestry is absent.
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

// Returns whether node carries modifierKind; nodes that cannot own modifiers or lack the requested modifier return false.
function hasNodeModifier(node: TsNode, modifierKind: import("typescript").SyntaxKind): boolean {
  const modifiers = typescriptSyntax.canHaveModifiers(node) ? typescriptSyntax.getModifiers(node) : undefined;
  return modifiers?.some((modifier) => modifier.kind === modifierKind) === true;
}

// Arrow functions and function expressions always carry a body, so only declaration-shaped nodes
// can answer false here: a method signature has no body property at all, and an overload or
// abstract member leaves it undefined.
function callableNodeHasBody(callableNode: TsNode): boolean {
  return (callableNode as { body?: unknown }).body !== undefined;
}

// Returns a variable-named match point for node when it is a const or let declaration with a function expression or arrow initializer.
// Uses sourceFile for positions and parameter text; var declarations, destructured bindings and other initializers return undefined.
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

// Returns a match point for a bare test or it call in node with a literal string or substitution-free template title and a function or arrow.
// Uses sourceFile for positions and parameter text, and the title as the name; returns undefined when this shape does not match.
// Anchors the point at the call line so recordCallablePoint gives it priority over other declarations on that line.
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
    // Keep the declaration anchor at the call start when the callback begins on a later line.
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

// Returns sourceFile text for parameters joined by comma-space with newlines flattened; an empty list returns an empty string.
// Omits inter-parameter trivia so a line comment between parameters cannot swallow the next name after flattening.
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
 * Lists named, non-default exported function declarations with callable JSDoc in the shared syntax tree.
 * Recognises async, generic and multiline declarations without treating comment text as declarations.
 *
 * @param parsed - shared syntax tree searched for qualifying function declarations
 * @returns Documented exported functions in source order; empty when the file has none.
 */
export function documentedExportFunctions(parsed: ParsedScript): DocumentedExportFunction[] {
  return collectDocumented(parsed, documentedExportFunction);
}

/**
 * Lists exported statements with the parser's const flag and one identifier bound to an arrow or function expression for everyCallable tag checks.
 * The statement supplies its final callable JSDoc. The initializer supplies the parameters and return type.
 *
 * @param parsed - shared syntax tree searched for documented exported callable constants
 * @returns Documented exported callable constants in source order; empty when the file has none.
 */
export function documentedExportConstants(parsed: ParsedScript): DocumentedExportFunction[] {
  return collectDocumented(parsed, documentedExportConstant);
}

// Walks the parsed syntax tree at every depth so that namespaced exports keep their docblock coverage.
// The projection receives the source file and each node. It returns a record to include or undefined to skip that node.
// Returns the collected records in source order, or an empty array when the projection accepts no nodes.
function collectDocumented(parsed: ParsedScript, project: (sourceFile: TsSourceFile, node: TsNode) => DocumentedExportFunction | undefined): DocumentedExportFunction[] {
  const results: DocumentedExportFunction[] = [];
  // Returns nothing. Adds the record for node, if present, to the shared results and visits children so that nested namespace exports are covered.
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

// Projects node into a documentation record for a named, non-default exported function with callable JSDoc.
// Uses sourceFile for documentation text and locations; returns undefined when node fails these conditions.
// With both tag switches off, default exports stay excluded; everyCallable covers them through documentedDefaultAndLaterExports.
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

// Returns a documentation record for an exported node with the const flag and one identifier bound to an arrow or function expression.
// Uses sourceFile for the statement's JSDoc text and positions. Returns undefined for other shapes or missing or unusable callable JSDoc.
function documentedExportConstant(sourceFile: TsSourceFile, node: TsNode): DocumentedExportFunction | undefined {
  const declaration = soleConstDeclaration(node);
  return declaration && hasExportFlag(declaration) ? documentedConstantCallable(sourceFile, node, declaration) : undefined;
}

// Returns a documentation row for declaration's identifier-bound arrow or function initializer, using statement as the JSDoc host.
// sourceFile supplies text and positions. Missing callable shape or usable JSDoc returns undefined; callers supply the sole const binding.
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

// Returns the sole variable declaration when node is a const statement; returns undefined for other nodes or multiple declarations.
// A shared docblock cannot distinguish several declarations; callers check the returned declaration's binding shape.
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
 * Returns documented default function declarations, bare default arrows and qualifying top-level local callables named by separate exports.
 * Anonymous default functions and default arrows are named default; separately exported bindings keep their local names.
 * Separate exports match named functions or single const-flagged callable bindings. An export modifier rules out this match.
 *
 * @param parsed - script tree whose module-level statements and exports are inspected
 * @returns - documentation rows in source order; empty when no eligible callable has usable JSDoc
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

// Returns a record for statement when it is a default function declaration or bare default arrow. sourceFile supplies JSDoc text and positions.
// Returns undefined for other shapes, parenthesised expressions, or missing or unusable JSDoc.
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

// Projects top-level statement into a documentation record for a function or single-binding const callable named in laterExportedNames.
// Uses sourceFile for text and locations; returns undefined for other shapes, own export modifiers, or missing callable JSDoc.
// Declarations with export modifiers are handled by the exported-callable passes.
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

// Returns local names exposed by sourceFile's top-level default exports, export-equals assignments, and value export lists.
// Reads exports before matching declarations so statement order does not hide a binding; returns an empty set when none qualify.
function laterExportedLocalNames(sourceFile: TsSourceFile): Set<string> {
  const names = new Set<string>();
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

// Returns original local names from an export { ... } statement, using the binding name for each alias.
// Other statement forms and re-exports return an empty list. Type-only lists and specifiers contribute no names.
function localExportListNames(statement: TsNode): string[] {
  if (!typescriptSyntax.isExportDeclaration(statement) || statement.moduleSpecifier || statement.isTypeOnly || !statement.exportClause || !typescriptSyntax.isNamedExports(statement.exportClause)) {
    return [];
  }
  return statement.exportClause.elements.filter((element) => !element.isTypeOnly).map((element) => (element.propertyName ?? element.name).text);
}

/**
 * Lists private and nested functions and single-binding const arrow or function-expression callables with JSDoc for everyCallable checks.
 * Excludes direct exports and top-level names from local value export lists or bare-identifier export assignments.
 * Exported forms belong to the exported-callable passes so each declaration is documented once.
 *
 * @param parsed - shared syntax tree searched for eligible declarations
 * @returns Documented private and nested callables in source order; empty when the file has none.
 */
export function documentedPrivateCallables(parsed: ParsedScript): DocumentedExportFunction[] {
  const laterExportedNames = laterExportedLocalNames(parsed.sourceFile);
  return collectDocumented(parsed, (sourceFile, node) => documentedPrivateCallable(sourceFile, node, laterExportedNames));
}

// Returns a documentation record for node when it is a private function declaration or single-binding const callable with usable JSDoc.
// sourceFile supplies text and identifies top-level nodes. laterExportedNames lists top-level bindings handled by documentedLaterExport.
// Returns undefined for ineligible nodes or missing usable JSDoc. A nested binding can reuse a top-level export's name.
function documentedPrivateCallable(sourceFile: TsSourceFile, node: TsNode, laterExportedNames: ReadonlySet<string>): DocumentedExportFunction | undefined {
  // Returns true when name matches a separate export of this top-level binding. Nested names are independent bindings for private checks.
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
 * Lists class and object-literal methods with identifier or private-identifier names and callable JSDoc for everyCallable tag checks.
 * Includes static and private methods; excludes constructors, accessors, arrow-valued properties, and computed or literal names.
 * Bare method names use the declaration ordinal to distinguish same-named methods in one file.
 *
 * @param parsed - shared syntax tree searched for qualifying methods
 * @returns Documented methods in source order; empty when the file has none.
 */
export function documentedMethods(parsed: ParsedScript): DocumentedExportFunction[] {
  return collectDocumented(parsed, documentedMethod);
}

/**
 * Recognizes methods on class declarations with their own export modifier, excluding private, protected and private-identifier methods.
 * The missing-function-documentation check uses this classification to apply exported severity when either everyCallable tag switch is enabled.
 *
 * @param callableNode - shared-parse node inspected for public exported-method status
 * @returns True when the method qualifies for exported severity under these syntax checks.
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

// Projects node into a documentation record for an identifier-named or private-identifier method with callable JSDoc.
// Uses sourceFile for text and locations; returns undefined for other nodes, computed or literal names, or missing callable JSDoc.
function documentedMethod(sourceFile: TsSourceFile, node: TsNode): DocumentedExportFunction | undefined {
  if (!typescriptSyntax.isMethodDeclaration(node) || (!typescriptSyntax.isIdentifier(node.name) && !typescriptSyntax.isPrivateIdentifier(node.name))) {
    return undefined;
  }
  // Use the unqualified name so identifier-named methods match the names used by the size and missing-doc rules.
  // The finding fingerprint uses the JSDoc line to distinguish same-named methods documented on different lines.
  return documentedCallable(sourceFile, node, node.name.text, node);
}

// Returns a documentation row named name using sourceFile positions, docHost's final JSDoc, and callable's parameters and return facts.
// Returns undefined when docHost has no JSDoc or its final block is an overview or divider rather than callable documentation.
// Only identifier parameter names are included; an absent return annotation produces an empty returnTypeText.
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

// Returns whether jsDoc is a divider or the file overview attached to its first statement, so it is excluded as callable documentation.
// Uses sourceFile for comment text and intervening lines, and docHost as the declaration carrying jsDoc.
function isOverviewOrDividerJsDoc(sourceFile: TsSourceFile, docHost: TsNode, jsDoc: import("typescript").JSDoc): boolean {
  const commentText = sourceFile.text.slice(jsDoc.getStart(sourceFile), jsDoc.getEnd());
  if (isDividerComment(commentText)) {
    return true;
  }
  const gapLines = sourceFile.text.slice(jsDoc.getEnd(), docHost.getStart(sourceFile)).split(/\r?\n/).slice(1, -1);
  return sourceFile.statements[0] === docHost && isFileOverviewComment(commentText, gapLines);
}

/**
 * Checks a callable body for everyCallable return-tag inference. Concise arrows use their expression and blocks skip nested functions and classes.
 * Bare returns, the undefined identifier and void expressions do not count as returned values.
 *
 * @param callable - signature whose own body supplies the return evidence
 * @returns true for a syntactic value return and false for a bodiless signature or a body without a value return
 */
function isBodyReturningValue(callable: import("typescript").SignatureDeclarationBase): boolean {
  const body = (callable as { body?: TsNode }).body;
  if (!body) {
    return false;
  }
  return typescriptSyntax.isBlock(body) ? hasOwnValueReturn(body) : isValueExpression(body);
}

// Returns whether callableNode is function-like and its declared type or body indicates a value for the missing-doc message.
// Non-callables return false; explicit void, undefined, never, asserts predicates, and Promise<void> or Promise<undefined> count as no value.
// Without a declared return type, the result comes from the callable's own body.
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

// Searches the subtree rooted at node for a value-carrying return and reports whether one exists.
// Start at the callable body; function and class boundaries stop the search so nested callables do not contribute.
function hasOwnValueReturn(node: TsNode): boolean {
  if (typescriptSyntax.isReturnStatement(node)) {
    return node.expression !== undefined && isValueExpression(node.expression);
  }
  if (typescriptSyntax.isFunctionLike(node) || typescriptSyntax.isClassLike(node)) {
    return false;
  }
  return node.forEachChild((child) => (hasOwnValueReturn(child) ? true : undefined)) ?? false;
}

// Returns whether expression counts as a value for return-tag inference; an undefined identifier or void expression returns false.
function isValueExpression(expression: TsNode): boolean {
  return !typescriptSyntax.isVoidExpression(expression) && !(typescriptSyntax.isIdentifier(expression) && expression.text === "undefined");
}
