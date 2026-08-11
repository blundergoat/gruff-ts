// Shared syntax-only parse boundary (ADR-012): each analysed script is parsed exactly once per
// analysis run, and that one result feeds parse diagnostics, security-flow analysis, and AST
// function discovery. Separate parse paths would triple parser cost and drift apart; this module
// owns the parser, the script-kind mapping, and the AST callable enumeration consumed by the
// block rules (and, downstream, complexity metrics and naming ownership).
import { createRequire } from "node:module";
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
 * Stable owner categories attached to naming inventory rows. CLI users see these categories only
 * inside finding metadata, where they explain whether a casing comparison came from the module,
 * one callable, one interface, or one type-literal contract.
 */
export type IdentifierOwnerKind = "module" | "function" | "interface" | "type-literal";

/*
 * Deterministic syntax owner projected into naming diagnostics. The id contains source ranges or
 * lexical names, never paths or TypeScript object identities; ownerName is absent when the module
 * itself is the user-visible comparison boundary.
 */
export interface IdentifierOwner {
  ownerId: string;
  ownerKind: IdentifierOwnerKind;
  ownerName?: string;
}

/*
 * One syntax-backed declaration row for the shared naming inventory. The row retains the existing
 * name and line presented to users, while owner fields let a later rule compare only declarations
 * that belong to the same reviewable surface.
 */
export interface OwnedDeclarationPoint extends IdentifierOwner {
  name: string;
  line: number;
}

/*
 * The two non-parameter inventories collected during the shared callable walk. Keeping variable
 * declarations and contract fields separate preserves the existing acronym input order when the
 * analyser inserts callable parameters between them.
 */
export interface DeclarationOwnershipPoints {
  variableDeclarations: OwnedDeclarationPoint[];
  contractFields: OwnedDeclarationPoint[];
}

/*
 * One cached projection of the shared syntax tree. Function discovery and naming ownership read
 * this same result, so enabling both rule families does not walk or parse the user's file twice.
 */
interface ParsedSyntaxIndex {
  callablePoints: CallableMatchPoint[];
  declarationOwnership: DeclarationOwnershipPoints;
}

const MODULE_IDENTIFIER_OWNER: IdentifierOwner = { ownerId: "module", ownerKind: "module" };
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
export interface CallableMatchPoint extends IdentifierOwner {
  lineIndex: number;
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
 * Returns variable and contract-field owners from the same syntax walk used for callable blocks.
 * @param parsed Shared parse for the user's script; it is always present for a deep script scan.
 * @returns Ordered rows; empty arrays mean the source declares no currently inventoried names.
 */
export function declarationOwnershipPoints(parsed: ParsedScript): DeclarationOwnershipPoints {
  return parsedSyntaxIndex(parsed).declarationOwnership;
}

// Builds one deterministic syntax index per parsed script so block and naming rules share a walk.
// Stable contract: repeated consumers receive the same ordered rows and owner ids.
function parsedSyntaxIndex(parsed: ParsedScript): ParsedSyntaxIndex {
  const cachedIndex = parsedSyntaxIndexes.get(parsed);
  // Multiple rule consumers reach the same file, so a completed projection is reused verbatim.
  if (cachedIndex) {
    return cachedIndex;
  }
  const callablePointsByLine = new Map<number, CallableMatchPoint>();
  const variableDeclarations: OwnedDeclarationPoint[] = [];
  const contractFields: OwnedDeclarationPoint[] = [];
  const sourceLines = parsed.sourceFile.text.split(/\r?\n/);
  // Carries the nearest callable owner for local declarations and the lexical type scope for
  // declaration merging while one depth-first walk visits the user's syntax tree.
  const visitSyntaxNode = (node: TsNode, declarationOwner: IdentifierOwner, contractScopeId: string): void => {
    recordCallablePoint(callablePointsByLine, matchPointFor(parsed.sourceFile, node));
    recordVariableDeclaration(parsed.sourceFile, node, declarationOwner, variableDeclarations);
    recordContractFields(parsed.sourceFile, sourceLines, node, contractScopeId, contractFields);
    const callableOwner = functionLikeOwner(parsed.sourceFile, node);
    const childDeclarationOwner = callableOwner ?? declarationOwner;
    const childContractScopeId = nestedContractScopeId(parsed.sourceFile, node, callableOwner, contractScopeId);
    // Nested declarations inherit the nearest user-visible callable and lexical contract boundary.
    node.forEachChild((child) => visitSyntaxNode(child, childDeclarationOwner, childContractScopeId));
  };
  // Top-level declarations begin in the module owner shown to CLI and report consumers.
  parsed.sourceFile.forEachChild((node) => visitSyntaxNode(node, MODULE_IDENTIFIER_OWNER, MODULE_IDENTIFIER_OWNER.ownerId));
  const syntaxIndex: ParsedSyntaxIndex = {
    callablePoints: [...callablePointsByLine.values()].sort((left, right) => left.lineIndex - right.lineIndex),
    declarationOwnership: { variableDeclarations, contractFields },
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

const CONTRACT_FIELD_LINE = /^[ \t]*(?:readonly\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\??\s*:/;

/*
 * Inputs for projecting one named contract into naming inventory rows. Bundling the syntax owner,
 * source view, and result sink keeps the traversal call readable when a CLI scan reaches an
 * interface or type-literal declaration.
 */
interface ContractFieldCollection {
  sourceFile: TsSourceFile;
  sourceLines: string[];
  members: import("typescript").NodeArray<import("typescript").TypeElement>;
  ownerName: string;
  ownerKind: "interface" | "type-literal";
  contractScopeId: string;
  declarationPosition: number;
  contractFields: OwnedDeclarationPoint[];
}

// Records the first simple binding from each declaration list, matching the inventory users saw
// before ownership was added. A comma-separated second binding remains outside this rule's scope.
function recordVariableDeclaration(sourceFile: TsSourceFile, node: TsNode, owner: IdentifierOwner, variableDeclarations: OwnedDeclarationPoint[]): void {
  // Other syntax nodes cannot introduce the const/let/var rows this naming inventory covers.
  if (!typescriptSyntax.isVariableDeclarationList(node)) {
    return;
  }
  const firstDeclaration = node.declarations[0];
  // Destructuring or an empty recovered declaration stays outside the existing simple-name rule.
  if (!firstDeclaration || !typescriptSyntax.isIdentifier(firstDeclaration.name)) {
    return;
  }
  variableDeclarations.push({
    name: firstDeclaration.name.text,
    line: sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1,
    ...owner,
  });
}

// Adds direct interface or named type-literal fields to the report inventory. Member methods,
// computed keys, mapped types, and same-line bodies remain outside the established rule surface.
function recordContractFields(sourceFile: TsSourceFile, sourceLines: string[], node: TsNode, contractScopeId: string, contractFields: OwnedDeclarationPoint[]): void {
  // Interface declaration blocks with the same name and lexical scope intentionally share an owner.
  if (typescriptSyntax.isInterfaceDeclaration(node)) {
    recordNamedContractFields({ sourceFile, sourceLines, members: node.members, ownerName: node.name.text, ownerKind: "interface", contractScopeId, declarationPosition: node.name.getStart(sourceFile), contractFields });
    return;
  }
  // Only a named alias whose direct value is an object type matches the existing type-literal scan.
  if (typescriptSyntax.isTypeAliasDeclaration(node) && typescriptSyntax.isTypeLiteralNode(node.type)) {
    recordNamedContractFields({ sourceFile, sourceLines, members: node.type.members, ownerName: node.name.text, ownerKind: "type-literal", contractScopeId, declarationPosition: node.name.getStart(sourceFile), contractFields });
  }
}

// Projects direct property signatures for one contract owner while retaining the old line filter.
function recordNamedContractFields(args: ContractFieldCollection): void {
  const declarationLineIndex = args.sourceFile.getLineAndCharacterOfPosition(args.declarationPosition).line;
  const owner = contractIdentifierOwner(args.ownerKind, args.contractScopeId, args.ownerName);
  // Each direct member is evaluated once in source order, which keeps report ordering stable.
  for (const member of args.members) {
    // Methods, indexes, and computed property names are not simple field declarations for users.
    if (!typescriptSyntax.isPropertySignature(member) || !typescriptSyntax.isIdentifier(member.name)) {
      continue;
    }
    const lineIndex = args.sourceFile.getLineAndCharacterOfPosition(member.name.getStart(args.sourceFile)).line;
    // The legacy line walker begins after the header, so a one-line contract remains un-inventoried.
    if (lineIndex <= declarationLineIndex) {
      continue;
    }
    const sourceName = args.sourceLines[lineIndex]?.match(CONTRACT_FIELD_LINE)?.[1];
    // Multi-line or non-leading property syntax stays outside the current user-visible coverage.
    if (sourceName !== member.name.text) {
      continue;
    }
    args.contractFields.push({ name: member.name.text, line: lineIndex + 1, ...owner });
  }
}

// Builds the merged contract identity shown in finding metadata. Names are syntactic identifiers,
// while the lexical prefix separates equally named contracts in unrelated user scopes.
function contractIdentifierOwner(ownerKind: "interface" | "type-literal", contractScopeId: string, ownerName: string): IdentifierOwner {
  return {
    ownerId: `${ownerKind}:${contractScopeId}:${ownerName}`,
    ownerKind,
    ownerName,
  };
}

// Returns a stable callable owner for descendants, or no replacement when this node is ordinary
// syntax. An absent owner means local declarations keep the nearest callable or module boundary.
function functionLikeOwner(sourceFile: TsSourceFile, node: TsNode): IdentifierOwner | undefined {
  // Only function-like syntax starts a new local naming boundary for the user's declarations.
  if (!typescriptSyntax.isFunctionLike(node)) {
    return undefined;
  }
  return callableIdentifierOwner(sourceFile, node);
}

// Creates a range-derived callable identity without exposing TypeScript node objects or file paths.
function callableIdentifierOwner(sourceFile: TsSourceFile, callableNode: TsNode): IdentifierOwner {
  const ownerName = functionLikeOwnerName(callableNode);
  // Anonymous callbacks retain their range identity while omitting a misleading display name.
  return {
    ownerId: `function:${callableNode.getStart(sourceFile)}:${callableNode.getEnd()}`,
    ownerKind: "function",
    ...(ownerName === undefined ? {} : { ownerName }),
  };
}

// Chooses the first human label a CLI user recognizes across declaration, binding, and test shapes.
function functionLikeOwnerName(node: TsNode): string | undefined {
  // The precedence matches existing block labels; no recognized shape means an anonymous owner.
  return declaredFunctionLikeOwnerName(node) ?? boundFunctionLikeOwnerName(node) ?? testFunctionLikeOwnerName(node);
}

// Reads names written directly on functions and methods, including the constructor label.
function declaredFunctionLikeOwnerName(node: TsNode): string | undefined {
  const namedNode = node as TsNode & { name?: TsNode };
  // Named functions, methods, accessors, and signatures already carry their user-facing label.
  if (namedNode.name && typescriptSyntax.isIdentifier(namedNode.name)) {
    return namedNode.name.text;
  }
  // Constructors have no name node but are recognizable as one callable in class diagnostics.
  if (typescriptSyntax.isConstructorDeclaration(node)) {
    return "constructor";
  }
  return undefined;
}

// Reads the variable or property label that presents an otherwise anonymous callable to users.
function boundFunctionLikeOwnerName(node: TsNode): string | undefined {
  const parent = node.parent;
  // Variable-bound arrows and function expressions are presented under their declared variable.
  if (typescriptSyntax.isVariableDeclaration(parent) && typescriptSyntax.isIdentifier(parent.name)) {
    return parent.name.text;
  }
  // Object and class property callbacks can use the property label without a discovered block row.
  if ((typescriptSyntax.isPropertyAssignment(parent) || typescriptSyntax.isPropertyDeclaration(parent)) && typescriptSyntax.isIdentifier(parent.name)) {
    return parent.name.text;
  }
  return undefined;
}

// Reads a literal test title, matching the test block symbol a CLI user already sees.
function testFunctionLikeOwnerName(node: TsNode): string | undefined {
  const parent = node.parent;
  // Ordinary callback arguments have no stable test label and remain anonymous owner metadata.
  if (!typescriptSyntax.isCallExpression(parent) || parent.arguments[1] !== node || !typescriptSyntax.isIdentifier(parent.expression) || (parent.expression.text !== "test" && parent.expression.text !== "it")) {
    return undefined;
  }
  const title = parent.arguments[0];
  // Dynamic test titles have no stable human label, so only literal titles are included.
  if (!title || !typescriptSyntax.isStringLiteralLike(title)) {
    return undefined;
  }
  return title.text;
}

// Advances the lexical scope used only for merging named contracts. Ordinary function body blocks
// stay under their callable, while nested blocks and namespaces separate same-name declarations.
function nestedContractScopeId(sourceFile: TsSourceFile, node: TsNode, callableOwner: IdentifierOwner | undefined, currentScopeId: string): string {
  // A function-like boundary is the lexical contract scope users see around local type declarations.
  if (callableOwner) {
    return callableOwner.ownerId;
  }
  // Namespace bodies can contain same-name interfaces that must not merge with module contracts.
  if (typescriptSyntax.isModuleBlock(node)) {
    return `module-block:${node.getStart(sourceFile)}:${node.getEnd()}`;
  }
  // A nested statement block is a distinct type-declaration scope; the function body itself is not.
  if (typescriptSyntax.isBlock(node) && !typescriptSyntax.isFunctionLike(node.parent)) {
    return `block:${node.getStart(sourceFile)}:${node.getEnd()}`;
  }
  return currentScopeId;
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

// Builds the point for a named declaration: the anchor line is the name's line, matching where
// the legacy line-oriented patterns fired; the end line is the declaration's final token.
function declarationPoint(sourceFile: TsSourceFile, position: number, callableNode: TsNode, name: string, parameters: readonly TsNode[]): CallableMatchPoint {
  const visibilityNode = callableVisibilityNode(callableNode);
  const isDirectlyExported = hasNodeModifier(visibilityNode, typescriptSyntax.SyntaxKind.ExportKeyword);
  return {
    ...callableIdentifierOwner(sourceFile, callableNode),
    lineIndex: sourceFile.getLineAndCharacterOfPosition(position).line,
    endLineIndex: sourceFile.getLineAndCharacterOfPosition(callableNode.getEnd()).line,
    name,
    params: parametersText(sourceFile, parameters),
    parameterCount: parameters.length,
    isTestCallable: false,
    isDirectlyExported,
    isExplicitlyPublic: isDirectlyExported || hasNodeModifier(visibilityNode, typescriptSyntax.SyntaxKind.PublicKeyword),
    isModuleScoped: visibilityNode.parent === sourceFile,
    hasBody: callableNodeHasBody(callableNode),
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
  return {
    ...callableIdentifierOwner(sourceFile, callback),
    lineIndex: sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line,
    endLineIndex: sourceFile.getLineAndCharacterOfPosition(node.getEnd()).line,
    name: title.text,
    params: parametersText(sourceFile, callback.parameters),
    parameterCount: callback.parameters.length,
    isTestCallable: true,
    isDirectlyExported: false,
    isExplicitlyPublic: false,
    isModuleScoped: false,
    hasBody: true,
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
 * One exported, documented function declaration as the docblock rules consume it: the JSDoc text
 * between its markers, the declared name, identifier parameter names (destructured parameters stay
 * intentionally invisible, matching the legacy text splitter), the docblock's one-based start line
 * (the docblock rules' stable finding anchor), and the declared return type text ("" when absent).
 */
export interface DocumentedExportFunction {
  docText: string;
  name: string;
  parameterNames: string[];
  line: number;
  returnTypeText: string;
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
  const results: DocumentedExportFunction[] = [];
  // Full-depth walk so namespaced exported functions keep their docblock coverage too.
  const visit = (node: TsNode): void => {
    const documented = documentedExportFunction(parsed.sourceFile, node);
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
// legacy pattern, so it stays excluded until a deliberate policy change covers it.
function documentedExportFunction(sourceFile: TsSourceFile, node: TsNode): DocumentedExportFunction | undefined {
  if (!typescriptSyntax.isFunctionDeclaration(node) || !node.name) {
    return undefined;
  }
  const flags = typescriptSyntax.getCombinedModifierFlags(node);
  if ((flags & typescriptSyntax.ModifierFlags.Export) === 0 || (flags & typescriptSyntax.ModifierFlags.Default) !== 0) {
    return undefined;
  }
  const jsDocs = (node as { jsDoc?: readonly import("typescript").JSDoc[] }).jsDoc;
  const jsDoc = jsDocs?.[jsDocs.length - 1];
  if (!jsDoc) {
    return undefined;
  }
  return {
    docText: sourceFile.text.slice(jsDoc.getStart(sourceFile) + 3, jsDoc.getEnd() - 2),
    name: node.name.text,
    parameterNames: node.parameters
      .map((parameter) => (typescriptSyntax.isIdentifier(parameter.name) ? parameter.name.text : undefined))
      .filter((name): name is string => name !== undefined),
    line: sourceFile.getLineAndCharacterOfPosition(jsDoc.getStart(sourceFile)).line + 1,
    returnTypeText: node.type ? node.type.getText(sourceFile).replace(/\s+/g, " ").trim() : "",
  };
}
