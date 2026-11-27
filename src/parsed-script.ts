// Shared syntax-only parse boundary (ADR-012): parses each analysed script at most once per run.
//
// Feeds parse diagnostics, security-flow analysis, docblock rules, and AST callable discovery from one syntax tree:
// - prevents triple parser overhead and drift between rule modules;
// - owns script-kind mapping, decorator masking, and callable enumeration consumed by block, complexity, and naming rules.
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

/**
 * Reads how many times the shared parser has run in this process; tests subtract before/after
 * snapshots to assert one parse per analysed script.
 *
 * @returns Total number of scripts parsed by `parseScript` in this process.
 */
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
  /**
   * Visits a syntax node and its descendants, blanking decorator spans in the shared buffer to preserve source offsets.
   *
   * @param node - syntax node inspected for a decorator and traversed recursively
   * @returns Nothing. Replaces decorator characters in the shared buffer with spaces while keeping line breaks.
   */
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

/**
 * Replaces non-newline characters in place with spaces across a half-open range.
 * Preserves CR and LF so line numbers stay fixed for LF- and CRLF-delimited text.
 *
 * @param characters - mutable character array modified in place
 * @param start - zero-based starting index, inclusive, where blanking begins
 * @param end - zero-based ending index, exclusive, bounded by the array length
 * @returns Nothing. Mutates `characters` in place with spaces from `start` up to `end`, leaving `\n` and `\r` intact.
 */
function blankRange(characters: string[], start: number, end: number): void {
  for (let index = start; index < end && index < characters.length; index += 1) {
    if (characters[index] !== "\n" && characters[index] !== "\r") {
      characters[index] = " ";
    }
  }
}

/**
 * Selects the TypeScript parser mode from `path`'s case-sensitive extension so JSX and TSX are parsed correctly.
 * Recognises `.tsx`, `.jsx`, `.js`, `.mjs`, and `.cjs`; all other paths use TS mode.
 *
 * @param path - file path whose trailing extension selects the grammar mode
 * @returns TypeScript `ScriptKind` (`TSX`, `JSX`, `JS`, or `TS`) matching the extension.
 */
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
 * One discovered callable match point projected from the shared syntax tree for block rules.
 *
 * Invariant: preserves the exact line anchor and slicing rules the block parser expects so existing finding fingerprints never move.
 */
export interface CallableMatchPoint {
  lineIndex: number;
  // Zero-based first line of the declaration (modifiers included, docs excluded) so split headers keep doc lookup intact.
  declarationLineIndex: number;
  // Zero-based line of the callable's final token, preferred over brace walking so `{}` in defaults cannot truncate bodies.
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

/**
 * Builds or retrieves the cached syntax index for `parsed` so that block rules share one walk.
 * Caches the index by parse identity and reuses it on later calls.
 *
 * @param parsed - shared script parse whose syntax tree is indexed
 * @returns The stable index holding ordinary callable points sorted by line and measured-only points in traversal order.
 */
function parsedSyntaxIndex(parsed: ParsedScript): ParsedSyntaxIndex {
  const cachedIndex = parsedSyntaxIndexes.get(parsed);
  // Multiple rule consumers reach the same file, so a completed projection is reused verbatim.
  if (cachedIndex) {
    return cachedIndex;
  }
  const callablePointsByLine = new Map<number, CallableMatchPoint>();
  const measuredOnlyPoints: CallableMatchPoint[] = [];
  /**
   * Visits a syntax node and its descendants to populate the shared callable map and list of measured-only points.
   *
   * @param node - AST node inspected for callable match points and traversed recursively
   * @returns Nothing. Records any matching declaration and measured-only points in the enclosing collections.
   */
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

/**
 * Updates `callablePointsByLine` with `callablePoint` under the one-block-per-line policy.
 *
 * @param callablePointsByLine - map keyed by zero-based `lineIndex` holding the winning point per line
 * @param callablePoint - candidate callable point, or undefined when the visited node is not a callable declaration
 * @returns Nothing. Inserts `callablePoint` or replaces a non-test point with a test callback; undefined leaves the map unchanged.
 */
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

/**
 * Builds a match point for named functions, identifier-named methods or signatures, constructors,
 * identifier-bound const/let function values, and bare test or it calls with a literal title and callback.
 *
 * @param sourceFile - parsed TypeScript source file used for positions and parameter text
 * @param node - AST node inspected for a supported callable form
 * @returns Match point for supported declarations, or undefined for unsupported shapes including accessors and anonymous declarations.
 */
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

/**
 * Projects `node` into a size/complexity-only match point for a var binding, object key, member assignment, or immediate invocation.
 *
 * @param sourceFile - parsed TypeScript source file used for positions and parameter text
 * @param node - AST node inspected against the four measured-only function-value forms
 * @returns Match point for the first matching form, or undefined when no supported function-value form matches.
 */
function measuredOnlyPointFor(sourceFile: TsSourceFile, node: TsNode): CallableMatchPoint | undefined {
  return varFunctionPoint(sourceFile, node) ?? keyFunctionPoint(sourceFile, node) ?? memberFunctionPoint(sourceFile, node) ?? invokedFunctionPoint(sourceFile, node);
}

/**
 * Extracts a match point for an identifier-named `var` binding initialized with a function expression or arrow, naming it after the variable.
 *
 * @param sourceFile - parsed TypeScript source file used for positions and parameter text
 * @param node - AST node checked for a `var` declaration with a function or arrow initializer
 * @returns Callable match point anchored at the variable identifier, or undefined for other shapes.
 */
function varFunctionPoint(sourceFile: TsSourceFile, node: TsNode): CallableMatchPoint | undefined {
  if (!typescriptSyntax.isVariableDeclaration(node) || !typescriptSyntax.isIdentifier(node.name) || !isVarList(node.parent)) {
    return undefined;
  }
  const initializer = node.initializer ? withoutParentheses(node.initializer) : undefined;
  if (!isFunctionValue(initializer)) {
    return undefined;
  }
  return declarationPoint(sourceFile, node.name.getStart(sourceFile), initializer, node.name.text, initializer.parameters);
}

/**
 * Projects a non-computed object property assigned a function expression or arrow into a match point.
 * Prefixes the key with the object's variable or assignment target when known, keeping the bare key without an owner name.
 *
 * @param sourceFile - parsed TypeScript source file used for positions and parameter text
 * @param node - AST node checked for a non-computed property assignment with a function-value initializer
 * @returns Callable match point for the property function, or undefined when `node` does not match.
 */
function keyFunctionPoint(sourceFile: TsSourceFile, node: TsNode): CallableMatchPoint | undefined {
  if (!typescriptSyntax.isPropertyAssignment(node) || typescriptSyntax.isComputedPropertyName(node.name)) {
    return undefined;
  }
  const initializer = withoutParentheses(node.initializer);
  if (!isFunctionValue(initializer)) {
    return undefined;
  }
  const objectName = objectLiteralName(sourceFile, node.parent);
  const name = objectName ? `${objectName}.${node.name.text}` : node.name.text;
  return declarationPoint(sourceFile, node.name.getStart(sourceFile), initializer, name, initializer.parameters);
}

/**
 * Extracts a match point when `node` assigns a function expression or arrow to a property or element access.
 *
 * @param sourceFile - parsed TypeScript source file used for positions, parameter text, and compact target naming
 * @param node - AST node checked for a simple `=` assignment onto a member access expression
 * @returns Callable match point named after the target expression, or undefined for other node shapes.
 */
function memberFunctionPoint(sourceFile: TsSourceFile, node: TsNode): CallableMatchPoint | undefined {
  if (!typescriptSyntax.isBinaryExpression(node) || node.operatorToken.kind !== typescriptSyntax.SyntaxKind.EqualsToken || !isMember(node.left)) {
    return undefined;
  }
  const right = withoutParentheses(node.right);
  if (!isFunctionValue(right)) {
    return undefined;
  }
  return declarationPoint(sourceFile, node.left.getStart(sourceFile), right, compactText(sourceFile, node.left), right.parameters);
}

/**
 * Extracts a match point when `node` directly invokes a function expression or arrow, using the function's name or `<iife>` when unnamed.
 *
 * @param sourceFile - parsed TypeScript source file used for positions and parameter text
 * @param node - AST node checked for a call expression whose unparenthesized callee is a function or arrow
 * @returns Callable match point for the invoked function, or undefined for all other nodes.
 */
function invokedFunctionPoint(sourceFile: TsSourceFile, node: TsNode): CallableMatchPoint | undefined {
  const callee = typescriptSyntax.isCallExpression(node) ? withoutParentheses(node.expression) : undefined;
  if (!isFunctionValue(callee)) {
    return undefined;
  }
  const name = typescriptSyntax.isFunctionExpression(callee) && callee.name ? callee.name.text : "<iife>";
  return declarationPoint(sourceFile, callee.getStart(sourceFile), callee, name, callee.parameters);
}

/**
 * Type guard checking whether `node` is a function expression or arrow function.
 *
 * @param node - AST node or undefined to inspect
 * @returns True and narrows `node` for a function expression or arrow function; undefined and all other node kinds return false.
 */
function isFunctionValue(node: TsNode | undefined): node is import("typescript").FunctionExpression | import("typescript").ArrowFunction {
  return node !== undefined && (typescriptSyntax.isFunctionExpression(node) || typescriptSyntax.isArrowFunction(node));
}

/**
 * Checks whether `node` is a `var` declaration list; `const` and `let` lists are excluded because `variableInitializerPoint` already handles them.
 *
 * @param node - AST node tested for a non-block-scoped variable declaration list
 * @returns True when `node` is a `VariableDeclarationList` without `BlockScoped` flags; otherwise false.
 */
function isVarList(node: TsNode): boolean {
  return typescriptSyntax.isVariableDeclarationList(node) && (node.flags & typescriptSyntax.NodeFlags.BlockScoped) === 0;
}

/**
 * Checks whether `node` is a property or element access, the member targets accepted for function assignments.
 *
 * @param node - AST node tested as an assignment target
 * @returns True when `node` is a `PropertyAccessExpression` or `ElementAccessExpression`; otherwise false.
 */
function isMember(node: TsNode): boolean {
  return typescriptSyntax.isPropertyAccessExpression(node) || typescriptSyntax.isElementAccessExpression(node);
}

/**
 * Derives an owner label for `objectLiteral` from its enclosing identifier binding or simple `=` assignment target.
 *
 * @param sourceFile - parsed TypeScript source file used to read and compact the assignment target text
 * @param objectLiteral - object literal node whose parent binding or assignment is inspected
 * @returns Identifier name or whitespace-free target label, or undefined when `objectLiteral` has no qualifying owner.
 */
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

/**
 * Reads `node`'s text from `sourceFile` with all whitespace removed, keeping multiline member names on one line.
 *
 * @param sourceFile - parsed TypeScript source file supplying source text
 * @param node - AST node whose text is compacted
 * @returns Source text of `node` with all whitespace stripped.
 */
function compactText(sourceFile: TsSourceFile, node: TsNode): string {
  return node.getText(sourceFile).replace(/\s+/g, "");
}

/**
 * Unwraps all outer parenthesized expressions from `node`, exposing an immediate call's callee.
 *
 * @param node - AST node to unwrap
 * @returns Inner non-parenthesized node, or `node` itself when it is not parenthesized.
 */
function withoutParentheses(node: TsNode): TsNode {
  let inner = node;
  while (typescriptSyntax.isParenthesizedExpression(inner)) {
    inner = inner.expression;
  }
  return inner;
}

/**
 * Builds a callable match point with zero-based name, declaration, and end line indexes plus visibility and body flags.
 *
 * @param sourceFile - parsed TypeScript source file used for line lookups and parameter text
 * @param position - zero-based character offset anchoring the reported name line
 * @param callableNode - AST node whose enclosing visibility, final-token line, and body presence are recorded
 * @param name - reported block label for the callable
 * @param parameters - parameter nodes supplying displayed parameter text and count
 * @returns Populated `CallableMatchPoint` with clamped declaration start line and zero-based line indexes.
 */
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

/**
 * Resolves the enclosing variable statement for a variable-backed `callableNode` so visibility checks see its export and module scope.
 *
 * @param callableNode - callable AST node whose parent chain is inspected
 * @returns Enclosing `VariableStatement` for variable-backed callables, or `callableNode` itself for declarations or missing ancestry.
 */
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

/**
 * Checks whether `node` carries a modifier matching `modifierKind`.
 *
 * @param node - AST node whose modifiers are inspected when supported
 * @param modifierKind - TypeScript `SyntaxKind` modifier flag to match
 * @returns True when `node` can hold modifiers and includes `modifierKind`; otherwise false.
 */
function hasNodeModifier(node: TsNode, modifierKind: import("typescript").SyntaxKind): boolean {
  const modifiers = typescriptSyntax.canHaveModifiers(node) ? typescriptSyntax.getModifiers(node) : undefined;
  return modifiers?.some((modifier) => modifier.kind === modifierKind) === true;
}

/**
 * Checks whether `callableNode` has an implementation body. Arrow functions and function expressions always carry a body,
 * whereas method signatures, overloads, and abstract members lack one or leave it undefined.
 *
 * @param callableNode - callable AST node checked for a defined `body` property
 * @returns True when `callableNode` has a defined body; false for signatures, overloads, and abstract members.
 */
function callableNodeHasBody(callableNode: TsNode): boolean {
  return (callableNode as { body?: unknown }).body !== undefined;
}

/**
 * Extracts a variable-named match point for a `const` or `let` declaration initialized with a function expression or arrow.
 *
 * @param sourceFile - parsed TypeScript source file used for positions and parameter text
 * @param node - variable declaration checked for an identifier binding, block-scoped list, and callable initializer
 * @returns Match point named after the variable, or undefined for `var` declarations, destructured bindings, and other initializers.
 */
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

/**
 * Extracts a match point for a bare `test` or `it` call with a literal string or substitution-free template title and a function or arrow callback.
 * Anchors the point at the call line so `recordCallablePoint` gives it priority over other declarations on that line.
 *
 * @param sourceFile - parsed TypeScript source file used for positions and parameter text
 * @param node - call expression inspected for a `test`/`it` identifier, literal title, and callback argument
 * @returns Test-callable match point named after the title, or undefined when the call shape does not match.
 */
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

/**
 * Formats parameter slices from `sourceFile` joined by comma-space with newlines flattened.
 * Omits inter-parameter trivia so a line comment between parameters cannot swallow the next name after flattening.
 *
 * @param sourceFile - parsed TypeScript source file supplying raw parameter spans
 * @param parameters - AST parameter nodes whose trimmed spans are formatted
 * @returns Comma-space joined parameter text with newlines replaced by spaces, or an empty string when `parameters` is empty.
 */
function parametersText(sourceFile: TsSourceFile, parameters: readonly TsNode[]): string {
  return parameters
    .map((parameter) => sourceFile.text.slice(parameter.getStart(sourceFile), parameter.getEnd()))
    .join(", ")
    .replace(/\r?\n/g, " ");
}

/**
 * One named import binding extracted from the shared syntax tree for unused-import checks.
 * Preserves the import declaration's one-based start line so finding fingerprints stay stable.
 */
export interface NamedImportBinding {
  /** Local identifier bound by the specifier (the alias when `as` is used, otherwise the imported name). */
  name: string;
  /** One-based line where the enclosing `import` statement starts. */
  line: number;
}

/**
 * Lists every named import binding in the shared syntax tree, including inline `type` specifiers and aliases.
 * Skips default-only, namespace, and side-effect imports because they bind no `{ ... }` specifier list.
 *
 * @param parsed - shared syntax tree whose top-level statements are inspected for named imports
 * @returns Named import bindings in source order; empty when the script has no named import specifiers.
 */
export function namedImportBindings(parsed: ParsedScript): NamedImportBinding[] {
  const bindings: NamedImportBinding[] = [];
  for (const statement of parsed.sourceFile.statements) {
    if (!typescriptSyntax.isImportDeclaration(statement)) {
      continue;
    }
    const namedBindings = statement.importClause?.namedBindings;
    if (!namedBindings || !typescriptSyntax.isNamedImports(namedBindings)) {
      continue;
    }
    const line = parsed.sourceFile.getLineAndCharacterOfPosition(statement.getStart(parsed.sourceFile)).line + 1;
    for (const element of namedBindings.elements) {
      bindings.push({ name: element.name.text, line });
    }
  }
  return bindings;
}

/**
 * Metadata for one destructured parameter slot so `docs.stale-param-tag` can validate JSDoc object and dotted property tags.
 */
export interface DestructuredParameterSlot {
  /** Top-level object keys explicitly named in the destructuring pattern; empty for array or rest-only patterns. */
  keys: string[];
  /** True when a rest element, computed property, or array pattern prevents enumerating all valid sub-keys statically. */
  hasOpenKeys: boolean;
}

/*
 * One documented callable projected for docblock tag rules (`docs.missing-param-tag`, `docs.missing-return-tag`, `docs.stale-param-tag`).
 *
 * Covers exported declarations plus constants, methods, and private callables when `everyCallable` is enabled:
 * - `docText` holds JSDoc interior text (empty when `hasJsDoc` is false for `//` or `/* *\/` comments);
 * - `parameterNames` lists identifier parameters while `destructuredParameters` tracks object/array binding patterns separately;
 * - `line` anchors findings on the comment's one-based start line for stable fingerprints.
 */
export interface DocumentedExportFunction {
  docText: string;
  hasJsDoc: boolean;
  name: string;
  parameterNames: string[];
  destructuredParameters: DestructuredParameterSlot[];
  line: number;
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

/**
 * Walks the parsed syntax tree at every depth so that namespaced exports keep their docblock coverage.
 *
 * @param parsed - shared script parse whose syntax tree is traversed in source order
 * @param project - callback receiving `(sourceFile, node)` and returning a documentation record to include or undefined to skip
 * @returns Collected documentation records in source order, or an empty array when `project` accepts no nodes.
 */
function collectDocumented(parsed: ParsedScript, project: (sourceFile: TsSourceFile, node: TsNode) => DocumentedExportFunction | undefined): DocumentedExportFunction[] {
  const results: DocumentedExportFunction[] = [];
  /**
   * Projects `node` and recurses into its children so that nested namespace exports are covered.
   *
   * @param node - AST node evaluated with `project` and traversed recursively
   * @returns Nothing. Appends any non-undefined documentation record to `results` in traversal order.
   */
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

/**
 * Projects `node` into a documentation record for a named, non-default exported function declaration with a leading comment.
 * Default exports stay excluded here; `everyCallable` covers them through `documentedDefaultAndLaterExports`.
 *
 * @param sourceFile - parsed TypeScript source file used for documentation text and locations
 * @param node - AST node checked for a named non-default exported function declaration
 * @returns Documentation record for the exported function, or undefined when `node` fails these conditions.
 */
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

/**
 * Extracts a documentation record for an exported `const` statement with one identifier bound to an arrow or function expression.
 *
 * @param sourceFile - parsed TypeScript source file used for the statement's comment text and positions
 * @param node - AST node inspected as a single-binding exported `const` statement
 * @returns Documentation record for the constant callable, or undefined for other shapes or missing usable comments.
 */
function documentedExportConstant(sourceFile: TsSourceFile, node: TsNode): DocumentedExportFunction | undefined {
  const declaration = soleConstDeclaration(node);
  return declaration && hasExportFlag(declaration) ? documentedConstantCallable(sourceFile, node, declaration) : undefined;
}

/**
 * Builds a documentation row for `declaration`'s identifier-bound arrow or function initializer, using `statement` as the comment host.
 * Callers supply the sole `const` binding for the statement.
 *
 * @param sourceFile - parsed TypeScript source file supplying comment text and positions
 * @param statement - enclosing variable statement hosting the leading comment
 * @param declaration - sole variable declaration whose identifier name and callable initializer are inspected
 * @returns Documentation record for the initializer callable, or undefined for missing callable shape or unusable comments.
 */
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

/**
 * Extracts the single variable declaration from a `const` statement; a shared docblock cannot distinguish several declarations.
 *
 * @param node - AST node inspected for a `VariableStatement` with the `Const` flag and exactly one declarator
 * @returns Sole `VariableDeclaration`, or undefined for non-`const` nodes or multi-declarator statements.
 */
function soleConstDeclaration(node: TsNode): import("typescript").VariableDeclaration | undefined {
  if (!typescriptSyntax.isVariableStatement(node) || (node.declarationList.flags & typescriptSyntax.NodeFlags.Const) === 0) {
    return undefined;
  }
  const [declaration, ...others] = node.declarationList.declarations;
  return declaration && others.length === 0 ? declaration : undefined;
}

/**
 * Checks whether `declaration` carries its own `export` modifier, directly or through its statement.
 *
 * @param declaration - TypeScript declaration node whose combined modifier flags are checked
 * @returns True when `ModifierFlags.Export` is set on `declaration`; otherwise false.
 */
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

/**
 * Extracts a documentation record when `statement` is a default function declaration or bare default arrow export.
 *
 * @param sourceFile - parsed TypeScript source file supplying comment text and positions
 * @param statement - top-level statement inspected for a default function or non-parenthesised arrow export assignment
 * @returns Documentation record named after the function or `"default"`, or undefined for other shapes or missing usable comments.
 */
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

/**
 * Projects a top-level `statement` into a documentation record for a function or single-binding `const` callable named in `laterExportedNames`.
 * Declarations with their own `export` modifiers are excluded because the exported-callable passes handle them.
 *
 * @param sourceFile - parsed TypeScript source file supplying text and locations
 * @param statement - top-level statement checked for a non-exported function or single-binding `const` declaration
 * @param laterExportedNames - local binding names exported later by default, export-equals, or `export { ... }` statements
 * @returns Documentation record for the separately exported callable, or undefined when ineligible or missing a usable comment.
 */
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

/**
 * Collects local names exposed by `sourceFile`'s top-level identifier default exports, export-equals assignments, and value export lists.
 * Reads exports before matching declarations so statement order does not hide a binding.
 *
 * @param sourceFile - parsed TypeScript source file whose top-level statements are scanned
 * @returns Set of locally bound names exported via separate export statements; empty when none qualify.
 */
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

/**
 * Extracts original local names from a value `export { ... }` statement, using the local binding name for each alias.
 * Type-only lists, type-only specifiers, re-exports, and other statement forms contribute no names.
 *
 * @param statement - AST statement inspected for a local named export declaration
 * @returns Array of local value binding names from `statement`, or an empty array when none apply.
 */
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

/**
 * Extracts a documentation record for a private function declaration or single-binding `const` callable with a usable leading comment.
 * A nested binding can reuse a top-level export's name while remaining private.
 *
 * @param sourceFile - parsed TypeScript source file supplying text and identifying top-level parents
 * @param node - AST node inspected as a non-exported function or single-binding `const` callable
 * @param laterExportedNames - top-level binding names already handled by `documentedLaterExport`
 * @returns Documentation record for the private or nested callable, or undefined for ineligible nodes or missing usable comments.
 */
function documentedPrivateCallable(sourceFile: TsSourceFile, node: TsNode, laterExportedNames: ReadonlySet<string>): DocumentedExportFunction | undefined {
  /**
   * Checks whether `name` refers to a top-level binding handled by a separate export; nested names are independent bindings for private checks.
   *
   * @param name - declared identifier name to test against top-level separate exports
   * @returns True when `node` is top-level in `sourceFile` and `name` is in `laterExportedNames`; otherwise false.
   */
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

/**
 * Projects `node` into a documentation record for an identifier-named or private-identifier method with a usable leading comment.
 *
 * @param sourceFile - parsed TypeScript source file used for comment text and locations
 * @param node - AST node checked for a `MethodDeclaration` with an identifier or private-identifier name
 * @returns Documentation record for the method, or undefined for other nodes, computed or literal names, or missing usable comments.
 */
function documentedMethod(sourceFile: TsSourceFile, node: TsNode): DocumentedExportFunction | undefined {
  if (!typescriptSyntax.isMethodDeclaration(node) || (!typescriptSyntax.isIdentifier(node.name) && !typescriptSyntax.isPrivateIdentifier(node.name))) {
    return undefined;
  }
  // Use the unqualified name so identifier-named methods match the names used by the size and missing-doc rules.
  // The finding fingerprint uses the JSDoc line to distinguish same-named methods documented on different lines.
  return documentedCallable(sourceFile, node, node.name.text, node);
}

/**
 * Builds a documentation row from `docHost`'s leading comment and `callable`'s signature.
 * Prefers a usable `/** ... *\/` JSDoc block (`hasJsDoc: true`), falling back to leading `//` or `/* *\/` comments (`hasJsDoc: false`)
 * so tag rules can enforce JSDoc contracts instead of letting slash or block comments bypass them.
 *
 * @param sourceFile - parsed TypeScript source file supplying comment text and line numbers
 * @param docHost - AST declaration or statement hosting the leading comment
 * @param name - callable display name recorded in the returned row
 * @param callable - signature node supplying identifier and destructured parameters
 * @returns Documentation record for `docHost`, or undefined when it has no leading comment or only a file overview or section divider.
 */
function documentedCallable(sourceFile: TsSourceFile, docHost: TsNode, name: string, callable: import("typescript").SignatureDeclarationBase): DocumentedExportFunction | undefined {
  const jsDocs = (docHost as { jsDoc?: readonly import("typescript").JSDoc[] }).jsDoc;
  const jsDoc = jsDocs?.[jsDocs.length - 1];
  if (jsDoc && !isOverviewOrDividerJsDoc(sourceFile, docHost, jsDoc)) {
    return buildDocumentedCallableRecord(sourceFile, name, callable, sourceFile.text.slice(jsDoc.getStart(sourceFile) + 3, jsDoc.getEnd() - 2), true, jsDoc.getStart(sourceFile));
  }
  const nonJsDocStart = leadingNonJsDocCommentStart(sourceFile, docHost);
  if (nonJsDocStart === undefined) {
    return undefined;
  }
  return buildDocumentedCallableRecord(sourceFile, name, callable, "", false, nonJsDocStart);
}

/**
 * Builds one `DocumentedExportFunction` record from an already-resolved leading comment anchor and callable signature.
 *
 * @param sourceFile - parsed TypeScript source file supplying text and line numbers
 * @param name - callable display name used in finding messages and fingerprints
 * @param callable - signature node supplying declared and destructured parameters
 * @param docText - JSDoc body text between markers, or empty string for non-JSDoc comments
 * @param hasJsDoc - true when the comment is a `/** ... *\/` JSDoc block; false for `//` or `/* *\/` comments
 * @param commentStartPos - zero-based character offset where the leading comment begins
 * @returns Populated `DocumentedExportFunction` record ready for doc-rule evaluation.
 */
function buildDocumentedCallableRecord(
  sourceFile: TsSourceFile,
  name: string,
  callable: import("typescript").SignatureDeclarationBase,
  docText: string,
  hasJsDoc: boolean,
  commentStartPos: number,
): DocumentedExportFunction {
  return {
    docText,
    hasJsDoc,
    name,
    parameterNames: callable.parameters
      .map((parameter) => (typescriptSyntax.isIdentifier(parameter.name) ? parameter.name.text : undefined))
      .filter((parameterName): parameterName is string => parameterName !== undefined),
    destructuredParameters: callable.parameters
      .map((parameter) => destructuredParameterSlot(parameter.name))
      .filter((slot): slot is DestructuredParameterSlot => slot !== undefined),
    line: sourceFile.getLineAndCharacterOfPosition(commentStartPos).line + 1,
  };
}

/**
 * Finds the start offset of a leading `//` or `/* *\/` comment attached to `docHost` when no usable JSDoc block is present.
 * Ignores file overviews, section dividers, empty comments, and rejected `/** *\/` blocks so missing-doc rules own those declarations.
 *
 * @param sourceFile - parsed TypeScript source file supplying text and statement order
 * @param docHost - declaration or statement carrying the leading trivia
 * @returns Zero-based character offset where the non-JSDoc comment block starts, or undefined if none qualifies.
 */
function leadingNonJsDocCommentStart(sourceFile: TsSourceFile, docHost: TsNode): number | undefined {
  const ranges = typescriptSyntax.getLeadingCommentRanges(sourceFile.text, docHost.getFullStart());
  if (!ranges || ranges.length === 0) {
    return undefined;
  }
  const lastRange = ranges[ranges.length - 1];
  if (!lastRange) {
    return undefined;
  }
  const lastText = sourceFile.text.slice(lastRange.pos, lastRange.end);
  if (lastText.startsWith("/**") || isDividerComment(lastText)) {
    return undefined;
  }
  const blockStartPos = contiguousCommentBlockStart(sourceFile.text, ranges, ranges.length - 1);
  const rawComment = sourceFile.text.slice(blockStartPos, lastRange.end);
  if (rawComment.replace(/\/\/|\/\*|\*\/|\*/g, "").trim() === "" || isDividerComment(rawComment)) {
    return undefined;
  }
  const gapLines = sourceFile.text.slice(lastRange.end, docHost.getStart(sourceFile)).split(/\r?\n/).slice(1, -1);
  if (sourceFile.statements[0] === docHost && isFileOverviewComment(rawComment, gapLines)) {
    return undefined;
  }
  return blockStartPos;
}

/**
 * Walks backward through contiguous `//` line comments ending at `lastIndex` so multi-line slash blocks anchor on their first line.
 *
 * @param text - full script text
 * @param ranges - leading comment trivia ranges returned by TypeScript
 * @param lastIndex - index of the final leading comment range before the declaration
 * @returns Zero-based start offset of the contiguous comment block.
 */
function contiguousCommentBlockStart(text: string, ranges: readonly import("typescript").CommentRange[], lastIndex: number): number {
  const lastRange = ranges[lastIndex];
  if (!lastRange || lastRange.kind !== typescriptSyntax.SyntaxKind.SingleLineCommentTrivia) {
    return lastRange?.pos ?? 0;
  }
  let startIndex = lastIndex;
  while (startIndex > 0) {
    const previous = ranges[startIndex - 1];
    const current = ranges[startIndex];
    if (!previous || !current || previous.kind !== typescriptSyntax.SyntaxKind.SingleLineCommentTrivia) {
      break;
    }
    const between = text.slice(previous.end, current.pos);
    if (/\r?\n\s*\r?\n/.test(between)) {
      break;
    }
    startIndex -= 1;
  }
  return ranges[startIndex]?.pos ?? lastRange.pos;
}

/**
 * Extracts destructured parameter metadata for one object or array binding pattern so stale-tag checks accept standard JSDoc object tags.
 *
 * @param parameterName - binding name node from one callable parameter declaration
 * @returns Destructured slot metadata for object or array patterns, or undefined for ordinary identifier parameters.
 */
function destructuredParameterSlot(parameterName: import("typescript").BindingName): DestructuredParameterSlot | undefined {
  if (typescriptSyntax.isIdentifier(parameterName)) {
    return undefined;
  }
  if (typescriptSyntax.isArrayBindingPattern(parameterName)) {
    return { keys: [], hasOpenKeys: true };
  }
  const keys: string[] = [];
  let hasOpenKeys = false;
  for (const element of parameterName.elements) {
    if (element.dotDotDotToken) {
      hasOpenKeys = true;
      continue;
    }
    const keyName = destructuredElementKey(element);
    if (keyName === undefined) {
      hasOpenKeys = true;
    } else {
      keys.push(keyName);
    }
  }
  return { keys, hasOpenKeys };
}

/**
 * Reads the static property key bound by one object destructuring element.
 *
 * @param element - object binding element whose property name or shorthand identifier is inspected
 * @returns The static key string when known syntactically, or undefined for computed property keys.
 */
function destructuredElementKey(element: import("typescript").BindingElement): string | undefined {
  if (element.propertyName) {
    if (typescriptSyntax.isIdentifier(element.propertyName) || typescriptSyntax.isStringLiteral(element.propertyName) || typescriptSyntax.isNumericLiteral(element.propertyName)) {
      return element.propertyName.text;
    }
    return undefined;
  }
  return typescriptSyntax.isIdentifier(element.name) ? element.name.text : undefined;
}

/**
 * Checks whether `jsDoc` is a section divider or a file overview attached to the first statement, excluding it as callable documentation.
 *
 * @param sourceFile - parsed TypeScript source file used for comment text, intervening lines, and first-statement identity
 * @param docHost - declaration or statement carrying `jsDoc`
 * @param jsDoc - TypeScript JSDoc node attached to `docHost`
 * @returns True when `jsDoc` is a divider comment or the file's leading overview block; otherwise false.
 */
function isOverviewOrDividerJsDoc(sourceFile: TsSourceFile, docHost: TsNode, jsDoc: import("typescript").JSDoc): boolean {
  const commentText = sourceFile.text.slice(jsDoc.getStart(sourceFile), jsDoc.getEnd());
  if (isDividerComment(commentText)) {
    return true;
  }
  const gapLines = sourceFile.text.slice(jsDoc.getEnd(), docHost.getStart(sourceFile)).split(/\r?\n/).slice(1, -1);
  return sourceFile.statements[0] === docHost && isFileOverviewComment(commentText, gapLines);
}

/**
 * Reports whether `callableNode` requires a return description in missing-doc hints.
 * Every function-like declaration other than constructors and `set` accessors requires an explicit `@returns` contract, including `void`.
 *
 * @param callableNode - AST node inspected by the missing-function-documentation message builder
 * @returns True for functions, methods, arrows, and getters; false for non-callables, constructors, and setters.
 */
export function isCallableReturningValue(callableNode: TsNode): boolean {
  return (
    typescriptSyntax.isFunctionLike(callableNode) &&
    !typescriptSyntax.isConstructorDeclaration(callableNode) &&
    !typescriptSyntax.isSetAccessorDeclaration(callableNode)
  );
}
