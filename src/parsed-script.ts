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
 * @param file Display path plus the script flag from discovery.
 * @param source Raw file text to parse.
 * @returns The shared parse result, or undefined when the input is not a script.
 */
export function parseScript(file: ParsedScriptInput, source: string): ParsedScript | undefined {
  if (!file.isScript) {
    return undefined;
  }
  parseCount += 1;
  const parsed = typescriptSyntax.createSourceFile(file.displayPath, source, typescriptSyntax.ScriptTarget.Latest, true, scriptKindFor(file.displayPath)) as ParsedSourceFileWithDiagnostics;
  return { sourceFile: parsed, diagnostics: parsed.parseDiagnostics.map((diagnostic) => parseErrorDiagnostic(file, parsed, diagnostic)) };
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

// Projects one recovered parser diagnostic into the run-diagnostic contract (type, message, path,
// line). Line 1 is the stable fallback when the parser omits a start offset on malformed files.
function parseErrorDiagnostic(file: ParsedScriptInput, sourceFile: TsSourceFile, diagnostic: TsDiagnostic): RunDiagnostic {
  const line = diagnostic.start === undefined ? 1 : sourceFile.getLineAndCharacterOfPosition(diagnostic.start).line + 1;
  return {
    diagnosticType: "parse-error",
    message: `TypeScript syntax error: ${typescriptSyntax.flattenDiagnosticMessageText(diagnostic.messageText, " ")}`,
    filePath: file.displayPath,
    line,
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
  // Zero-based line of the callable's final token. The block parser prefers this over its legacy
  // brace walk: a `{}` inside a multi-line parameter default would otherwise close the walk early
  // and slice an empty body.
  endLineIndex: number;
  name: string;
  params: string;
  parameterCount: number;
  isTestCallable: boolean;
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
  const points = new Map<number, CallableMatchPoint>();
  // Applies the one-block-per-line policy while collecting points from the walk below.
  const record = (point: CallableMatchPoint | undefined): void => {
    if (!point) {
      return;
    }
    const existing = points.get(point.lineIndex);
    // Test/it callbacks outrank same-line declarations (the legacy pattern order); otherwise the
    // first declaration on a line keeps the slot so one line yields one block, as before.
    if (!existing || (point.isTestCallable && !existing.isTestCallable)) {
      points.set(point.lineIndex, point);
    }
  };
  // Full-depth walk: nested named callables are their own blocks, exactly as the regex found them.
  const visit = (node: TsNode): void => {
    record(matchPointFor(parsed.sourceFile, node));
    node.forEachChild(visit);
  };
  parsed.sourceFile.forEachChild(visit);
  return [...points.values()].sort((left, right) => left.lineIndex - right.lineIndex);
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
  return {
    lineIndex: sourceFile.getLineAndCharacterOfPosition(position).line,
    endLineIndex: sourceFile.getLineAndCharacterOfPosition(callableNode.getEnd()).line,
    name,
    params: parametersText(sourceFile, parameters),
    parameterCount: parameters.length,
    isTestCallable: false,
    callableNode,
  };
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
    lineIndex: sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line,
    endLineIndex: sourceFile.getLineAndCharacterOfPosition(node.getEnd()).line,
    name: title.text,
    params: parametersText(sourceFile, callback.parameters),
    parameterCount: callback.parameters.length,
    isTestCallable: true,
    callableNode: callback,
  };
}

// Raw text between the parameter list's start and end, exactly what the legacy patterns captured
// between the parens; empty when the callable declares no parameters.
function parametersText(sourceFile: TsSourceFile, parameters: readonly TsNode[]): string {
  const first = parameters[0];
  const last = parameters[parameters.length - 1];
  if (!first || !last) {
    return "";
  }
  return sourceFile.text.slice(first.getStart(sourceFile), last.getEnd()).replace(/\r?\n/g, " ");
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
