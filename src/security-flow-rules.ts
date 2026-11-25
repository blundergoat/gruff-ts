// Finds candidate security issues in TypeScript and JavaScript during analysis.
//
// Uses written source and local assignments to connect inputs with calls worth reviewing.
// A finding points the developer to the code to inspect, with no need to run the scanned project.
import type { SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import { parseScript } from "./parsed-script.ts";
import type { Finding } from "./types.ts";
import { createRequire } from "node:module";

// Syntax-only TypeScript/JavaScript parser (ADR-012): ts.createSourceFile only -
// no type checker, program, language service, or emit. Loaded via createRequire
// because typescript ships as CommonJS; usage stays bounded to syntax walking.
const require = createRequire(import.meta.url);
const typescriptSyntax = require("typescript") as typeof import("typescript");

type TsSourceFile = import("typescript").SourceFile;
type TsNode = import("typescript").Node;
type TsCallLikeExpression = import("typescript").CallExpression | import("typescript").NewExpression;
type TsNamedImportBindings = import("typescript").NamedImportBindings;

/**
 * Parse source text for a discovered file through the shared syntax-only parser; script parsing increments the shared parse count.
 * Parser exceptions stay silent because full scans retain their separate same-line pass.
 *
 * @param file - discovered file passed to the shared script parser
 * @param source - source text to parse into a syntax tree
 * @returns An AST even with syntax diagnostics, or null to skip AST flow for non-script input or parser exceptions.
 */
function getSourceFile(file: SourceFile, source: string): TsSourceFile | null {
  try {
    return parseScript(file, source)?.sourceFile ?? null;
  } catch {
    return null;
  }
}

/**
 * Walk the subtree rooted at a node depth-first, calling the visitor before its children.
 *
 * @param node - root AST node of the subtree to traverse
 * @param visit - callback invoked for each visited node; returning false skips that node's children
 * @returns Nothing. The visitor performs the work at each visited node.
 */
function walk(node: TsNode, visit: (node: TsNode) => boolean | void): void {
  if (visit(node) === false) {
    return;
  }
  typescriptSyntax.forEachChild(node, (child) => {
    walk(child, visit);
  });
}

/**
 * Compute a node's zero-based start line so callers can convert it to a one-based finding line.
 *
 * @param parsedSource - parsed syntax tree that owns the node's character offsets
 * @param node - AST node whose start position is mapped to a line index
 * @returns Zero-based start line of node within parsedSource.
 */
function lineIndexOf(parsedSource: TsSourceFile, node: TsNode): number {
  return parsedSource.getLineAndCharacterOfPosition(node.getStart(parsedSource)).line;
}

// External input token that can be visibly matched on one source line.
interface SourceToken {
  kind: string;
  pattern: RegExp;
}

// Each imported reader records function scopes whose hoisted locals hide its import.
type FileReadBindings = ReadonlyMap<string, ReadonlySet<TsNode>>;

// One source-to-sink heuristic: a risky call pattern plus the remediation attached to its finding.
interface SecurityFlowRule {
  ruleId: string;
  message: string;
  sinkKind: string;
  remediation: string;
  callPattern: RegExp;
}

const SOURCE_TOKENS: readonly SourceToken[] = [
  { kind: "request", pattern: /\b(?:req|request|ctx)\.(?:query|params|body|headers|cookies)\b/ },
  { kind: "cli-argument", pattern: /\bprocess\.argv(?:\s*\[|\b)/ },
  { kind: "environment", pattern: /\bprocess\.env\.[A-Za-z_$][A-Za-z0-9_$]*/ },
  { kind: "browser-location", pattern: /\blocation\.search\b|\bURLSearchParams\s*\(\s*location\.search\b/ },
];

// The receivers the request source token reads. A nested function declaring one as its own parameter is a handler
// whose request is its own argument, so `textOutsideRequestHandlers` blanks its reads of that name.
const REQUEST_RECEIVER_NAMES: ReadonlySet<string> = new Set(["req", "request", "ctx"]);

const SECURITY_FLOW_RULES: readonly SecurityFlowRule[] = [
  {
    ruleId: "security.path-traversal-candidate",
    message: "External input reaches a filesystem path sink.",
    sinkKind: "filesystem-path",
    remediation: "Validate the path against an allowlist, resolve it under a safe root, and reject traversal.",
    callPattern: /\b(?:fs\.)?(?:readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|createReadStream|createWriteStream|stat|statSync|readdir|readdirSync|unlink|unlinkSync|rm|rmSync|mkdir|mkdirSync)\s*\(/g,
  },
  {
    ruleId: "security.ssrf-candidate",
    message: "External input reaches a network request sink.",
    sinkKind: "network-request",
    remediation: "Validate destinations against an allowlist and block internal or metadata-service hosts.",
    callPattern: /\b(?:fetch|axios\.(?:get|post|put|patch|delete|request)|(?:http|https)\.(?:request|get))\s*\(/g,
  },
  {
    ruleId: "security.open-redirect-candidate",
    message: "External input reaches a redirect or browser navigation sink.",
    sinkKind: "redirect",
    remediation: "Redirect only to relative paths or destinations from an allowlist.",
    callPattern: /\b(?:(?:res|reply|response)\.redirect|(?:location|window\.location)\.(?:assign|replace))\s*\(|\b(?:location|window\.location)\.href\s*=/g,
  },
  {
    ruleId: "security.dynamic-regexp",
    message: "External input is used to build a regular expression.",
    sinkKind: "regular-expression",
    remediation: "Use a fixed pattern, escape user input, or enforce strict length and character limits.",
    callPattern: /\b(?:new\s+RegExp|RegExp)\s*\(/g,
  },
];

/**
 * Scan one source line for same-line external-input-to-sink matches. Same-line matching is intentional: reports stable candidate findings without
 * implying full taint analysis, and resets shared sink matchers only when a recognized source token is found.
 *
 * @param file - discovered file whose display path anchors emitted findings
 * @param codeLine - single source line checked for the first catalogue source pattern and matching sink calls
 * @param lineNumber - one-based line number assigned to appended findings
 * @param findings - accumulator that receives matching candidate findings
 * @returns Nothing. Appends to findings at lineNumber in file for matching sinks, leaving matchers and findings untouched if no source matches.
 */
export function analyseSecurityFlowLine(file: SourceFile, codeLine: string, lineNumber: number, findings: Finding[]): void {
  const source = sourceToken(codeLine);
  if (!source) {
    return;
  }
  for (const rule of SECURITY_FLOW_RULES) {
    if (sourceAppearsInSink(codeLine, source.pattern, rule.callPattern)) {
      findings.push(securityFlowFinding(file, lineNumber, rule, source.kind));
    }
  }
}

/**
 * Match a source line against SOURCE_TOKENS in catalogue order for deterministic metadata.
 *
 * @param codeLine - single source line checked for recognized external-input tokens
 * @returns The first matching SOURCE_TOKENS entry, or undefined when the line contains no recognized external-input token.
 */
function sourceToken(codeLine: string): SourceToken | undefined {
  return SOURCE_TOKENS.find((source) => source.pattern.test(codeLine));
}

/**
 * Check whether a bounded sink call segment contains external-input evidence.
 * Resets callPattern.lastIndex to zero; testing a global or sticky sourcePattern can also advance or reset its lastIndex.
 *
 * @param codeLine - single source line searched for sink calls
 * @param sourcePattern - external-input pattern tested against each bounded call segment
 * @param callPattern - sink matcher that must have the global flag to enumerate call sites
 * @returns True if sourcePattern matches a bounded call segment selected by callPattern, or false when no segment contains source evidence.
 */
function sourceAppearsInSink(codeLine: string, sourcePattern: RegExp, callPattern: RegExp): boolean {
  callPattern.lastIndex = 0;
  for (const call of codeLine.matchAll(callPattern)) {
    const callStart = call.index ?? 0;
    if (sourcePattern.test(singleLineCallSegment(codeLine, callStart))) {
      return true;
    }
  }
  return false;
}

/**
 * Extract a bounded source slice from a sink call start for same-line sink matching.
 * Stops at the first closing parenthesis or 240 characters.
 *
 * @param codeLine - single source line containing the candidate sink call
 * @param callStart - zero-based start offset of the call match within codeLine
 * @returns Bounded slice from callStart up to the first closing parenthesis, or up to 240 characters if none occurs.
 */
function singleLineCallSegment(codeLine: string, callStart: number): string {
  // Cap the text inspected per candidate call; this is a bounded heuristic, not balanced-parenthesis parsing.
  const maxSegmentLength = 240;
  const segment = codeLine.slice(callStart, callStart + maxSegmentLength);
  const close = segment.indexOf(")");
  return close === -1 ? segment : segment.slice(0, close + 1);
}

/**
 * Build a warning finding with a stable finding contract: medium confidence and metadata containing sourceKind and the rule's sink kind.
 *
 * @param file - discovered file whose display path locates the finding
 * @param line - one-based line number of the candidate sink
 * @param rule - rule definition supplying the finding's id, message, remediation, and sink kind
 * @param sourceKind - external-input category recorded in finding metadata
 * @returns A medium-confidence security warning at the supplied file and line.
 */
function securityFlowFinding(file: SourceFile, line: number, rule: SecurityFlowRule, sourceKind: string): Finding {
  return makeFinding({
    ruleId: rule.ruleId,
    message: rule.message,
    filePath: file.displayPath,
    line,
    severity: "warning",
    pillar: "security",
    confidence: "medium",
    remediation: rule.remediation,
    metadata: { sourceKind, sinkKind: rule.sinkKind },
  });
}

// --- Bounded intra-function AST flow (ADR-012) -------------------------
//
// Augments the same-line checks above by tracking local variables assigned from external input to sinks across lines within one function.
// Same-line flows remain owned by the line pass so existing fingerprints never move; this pass adds cross-line flows and AST-only sinks.

// One tainted local: the 0-based line of the originating external source, the
// source kind for metadata, and how many alias hops removed it is (cap below).
interface TaintRecord {
  line: number;
  kind: string;
  depth: number;
}

// Deserialization needs content provenance while the other sinks still inspect path influence.
interface FlowInputs {
  tainted: Map<string, TaintRecord>;
  contentTainted: Map<string, TaintRecord>;
  fileReadCallees: FileReadBindings;
}

// Bundles the syntax context each sink matcher needs so all text extraction remains anchored
// to the parsed source file instead of raw substrings.
interface AstSinkInput {
  callee: string;
  call: TsCallLikeExpression;
  sourceFile: TsSourceFile;
  unsafeXmlParsers: ReadonlySet<string>;
  isFrameworkRedirectCallee: boolean;
}

// Describes one AST sink candidate. Some AST-only rules report same-line direct-source
// evidence because no legacy line scanner owns those rule ids.
interface AstFlowSink {
  ruleId: string;
  sinkKind: string;
  shouldReportSameLine?: boolean;
  isSink: (input: AstSinkInput) => boolean;
}

// AST sink matchers for the flow-upgraded rules. `callee` is the source text of
// the call/new expression's callee (e.g. "fs.readFile", "RegExp",
// "axios.get"); the patterns mirror the same-line callPattern sinks above.
const AST_FLOW_SINKS: readonly AstFlowSink[] = [
  {
    ruleId: "security.path-traversal-candidate",
    sinkKind: "filesystem-path",
    isSink: ({ callee }) =>
      /(?:^|\.)(?:readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|createReadStream|createWriteStream|stat|statSync|readdir|readdirSync|unlink|unlinkSync|rm|rmSync|mkdir|mkdirSync)$/.test(
        callee,
      ),
  },
  {
    ruleId: "security.ssrf-candidate",
    sinkKind: "network-request",
    isSink: ({ callee }) =>
      /(?:^|\.)fetch$/.test(callee) ||
      /^axios\.(?:get|post|put|patch|delete|request)$/.test(callee) ||
      /^https?\.(?:request|get)$/.test(callee),
  },
  {
    ruleId: "security.open-redirect-candidate",
    sinkKind: "redirect",
    isSink: ({ callee, isFrameworkRedirectCallee }) =>
      /^(?:res|reply|response)\.redirect$/.test(callee) ||
      /^(?:location|window\.location)\.(?:assign|replace)$/.test(callee) ||
      isFrameworkRedirectCallee,
  },
  {
    ruleId: "security.dynamic-regexp",
    sinkKind: "regular-expression",
    isSink: ({ callee }) => /^RegExp$/.test(callee),
  },
  {
    ruleId: "security.unsafe-deserialization",
    sinkKind: "deserialization",
    shouldReportSameLine: true,
    isSink: ({ callee, call, sourceFile }) => isUnsafeDeserializationSink(callee, call, sourceFile),
  },
  {
    ruleId: "security.xxe-candidate",
    sinkKind: "xml-entity-expansion",
    shouldReportSameLine: true,
    isSink: ({ callee, call, unsafeXmlParsers }) => isXxeSink(callee, call, unsafeXmlParsers),
  },
];

const MAX_ALIAS_DEPTH = 2;
const MAX_SCOPE_NODES = 4000;

/**
 * Collect runtime filesystem-reader names imported from fs, node:fs, and their promises modules (promises support readFile only).
 * Only these imports establish the filename/content boundary; unrelated helpers retain ordinary taint.
 *
 * @param parsedSource - parsed syntax tree whose top-level imports are inspected
 * @returns Set of imported reader callees including default/namespace member paths and named local aliases, or an empty set if none qualify.
 */
function importedFileReadCallees(parsedSource: TsSourceFile): ReadonlySet<string> {
  const callees = new Set<string>();
  for (const statement of parsedSource.statements) {
    if (!typescriptSyntax.isImportDeclaration(statement) || !typescriptSyntax.isStringLiteral(statement.moduleSpecifier)) continue;
    const moduleName = statement.moduleSpecifier.text;
    if (!/^(?:node:)?fs(?:\/promises)?$/.test(moduleName)) continue;
    const clause = statement.importClause;
    if (!clause || clause.isTypeOnly) continue;
    const methods = moduleName.endsWith("/promises") ? ["readFile"] : ["readFile", "readFileSync"];
    for (const name of fileReadBindingNames(clause, methods)) callees.add(name);
  }
  return callees;
}

/**
 * Extract callable reader names exposed by a non-type-only import clause for the requested methods.
 * Skips named type-only imports; the caller must exclude whole type-only import clauses.
 *
 * @param clause - import clause whose default, namespace, and named bindings are inspected
 * @param methods - filesystem reader method names allowed for the imported module
 * @returns Default/namespace member paths and matching named local aliases, or an empty array if none match.
 */
function fileReadBindingNames(clause: import("typescript").ImportClause, methods: readonly string[]): string[] {
  const names: string[] = [];
  if (clause.name) for (const method of methods) names.push(`${clause.name.text}.${method}`);
  const bindings = clause.namedBindings;
  if (!bindings) return names;
  if (typescriptSyntax.isNamespaceImport(bindings)) {
    for (const method of methods) names.push(`${bindings.name.text}.${method}`);
  } else {
    for (const binding of bindings.elements) {
      if (!binding.isTypeOnly && methods.includes(binding.propertyName?.text ?? binding.name.text)) names.push(binding.name.text);
    }
  }
  return names;
}

/**
 * Normalizes a simple identifier or dotted property chain (such as `fs . readFileSync`) into compact `a.b` text without whitespace or comments.
 *
 * @param expr - AST expression inspected as an identifier or chain of property accesses
 * @returns Compact dotted name when `expr` is an identifier or property-access chain, or undefined for other expression shapes.
 */
function dottedIdentifierPath(expr: TsNode): string | undefined {
  if (typescriptSyntax.isParenthesizedExpression(expr)) {
    return dottedIdentifierPath(expr.expression);
  }
  if (typescriptSyntax.isIdentifier(expr)) {
    return expr.text;
  }
  if (typescriptSyntax.isPropertyAccessExpression(expr)) {
    const receiver = dottedIdentifierPath(expr.expression);
    return receiver === undefined ? undefined : `${receiver}.${expr.name.text}`;
  }
  return undefined;
}

/**
 * Check whether an AST node is an unshadowed call to an imported filesystem reader.
 * Returning false leaves the expression eligible for content taint.
 *
 * @param node - AST node tested as a call expression
 * @param parsedSource - parsed syntax tree used to extract the callee text
 * @param bindings - imported-reader names and their hoisted shadowing scopes
 * @returns True if node is a call whose normalized callee belongs to bindings with no visible reader shadowing; otherwise false.
 */
function isImportedFileRead(node: TsNode, parsedSource: TsSourceFile, bindings: FileReadBindings): boolean {
  if (!typescriptSyntax.isCallExpression(node)) return false;
  const callee = dottedIdentifierPath(node.expression) ?? node.expression.getText(parsedSource);
  return bindings.has(callee) && !isFileReadBindingShadowed(node, callee, bindings);
}

/**
 * Build reader exemptions from imports in parsedSource and drop exemptions for unshadowed assignments to tracked reader members
 * so that replacement methods remain eligible for content taint.
 *
 * A module too large to walk drops every exemption, so file reads stay reported.
 * A function or static block too large to walk loses the exemptions inside it; a reader assigned there loses its exemption everywhere.
 *
 * @param parsedSource - parsed syntax tree providing imports and assignment target text
 * @param scopes - function, module, and static-block scope roots scanned for hoisted shadowing and member writes
 * @returns Map of reader names to shadowing scopes, or an empty map when no readers exist or the module root exceeds the node budget.
 */
function fileReadBindingsForScopes(parsedSource: TsSourceFile, scopes: readonly TsNode[]): FileReadBindings {
  const bindings = new Map([...importedFileReadCallees(parsedSource)].map((callee) => [callee, new Set<TsNode>()]));
  if (bindings.size === 0) return bindings;
  const writes: TsNode[] = [];
  const exhaustedScopes: TsNode[] = [];
  for (const scope of scopes) {
    // A scope too large to walk fully cannot prove that a file reader was left untouched.
    if (!indexFileReadScope(scope, bindings, writes)) {
      // Module-level exhaustion can hide top-level hoisting or reassignment that affects every scope, so fail closed globally.
      if (scope === parsedSource) {
        return new Map();
      }
      exhaustedScopes.push(scope);
    }
  }
  for (const write of writes) {
    const callee = writtenFileReadCallee(write, parsedSource);
    if (callee && bindings.has(callee) && !isFileReadBindingShadowed(write, callee, bindings)) bindings.delete(callee);
  }
  // Scope-local exhaustion fails closed for that scope and drops any member reader whose text matches an assignment in the exhausted body.
  for (const exhaustedScope of exhaustedScopes) {
    dropExhaustedScopeWrittenCallees(exhaustedScope.getText(parsedSource), bindings);
    // Treat the oversized scope as shadowing every reader, so reads inside it lose the exemption and can still be reported.
    for (const shadowedScopes of bindings.values()) {
      shadowedScopes.add(exhaustedScope);
    }
  }
  return bindings;
}

/**
 * Drops tracked member-reader bindings globally when an exhausted scope's source text appears to assign to that member.
 * Mutates `bindings` in place so an unwalked tail beyond `MAX_SCOPE_NODES` cannot monkey-patch a reader while leaving sibling exemptions active.
 *
 * @param scopeText - source text of a function or static-block scope that exceeded `MAX_SCOPE_NODES`
 * @param bindings - mutable reader-binding map whose member entries are removed on assignment matches
 * @returns Nothing. Deletes matching member callees from `bindings` in place.
 */
function dropExhaustedScopeWrittenCallees(scopeText: string, bindings: Map<string, Set<TsNode>>): void {
  // Check each tracked reader, such as `fs.readFileSync`, for an assignment in the oversized scope.
  for (const callee of [...bindings.keys()]) {
    const dotIndex = callee.indexOf(".");
    // A bare imported name cannot be replaced through a member write, so only `module.method` readers are checked.
    if (dotIndex === -1) {
      continue;
    }
    const rootPattern = escapeRegExpLiteral(callee.slice(0, dotIndex));
    const methodPattern = escapeRegExpLiteral(callee.slice(dotIndex + 1));
    const memberWritePattern = new RegExp(
      `(?<![\\w$])${rootPattern}\\s*(?:\\.\\s*${methodPattern}(?![\\w$])|\\[\\s*["']${methodPattern}["']\\s*\\])\\s*(?:\\?\\?|&&|\\|\\||\\*\\*|<<|>>>?|[+\\-*/%&|^])?=(?!=)`,
    );
    // Text such as `fs.readFileSync = fake` in the unwalked scope may replace the reader, so its exemption is dropped everywhere.
    if (memberWritePattern.test(scopeText)) {
      bindings.delete(callee);
    }
  }
}

/**
 * Escapes regular-expression metacharacters in an identifier segment before interpolating it into a pattern.
 * Identifiers may start with `$`, so callers bound matches with `(?<![\w$])` rather than `\b`.
 *
 * @param literalText - raw identifier text such as `fs` or `$fs`
 * @returns Escaped string safe for literal matching inside `RegExp`.
 */
function escapeRegExpLiteral(literalText: string): string {
  return literalText.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Scan a scope for hoisted reader shadowing and assignment targets while skipping nested functions and static blocks.
 * Mutates both bindings and writes in place.
 *
 * @param scope - root AST node of the scope to scan up to MAX_SCOPE_NODES
 * @param bindings - mutable map from reader names to shadowing scopes updated with hoisted var declarations
 * @param writes - mutable list receiving assignment left-hand targets for replacement checks
 * @returns True when the scan completes within the node budget, or false on exhaustion leaving partial records to discard.
 */
function indexFileReadScope(scope: TsNode, bindings: Map<string, Set<TsNode>>, writes: TsNode[]): boolean {
  let budget = MAX_SCOPE_NODES;
  walk(scope, (node) => {
    if (budget-- <= 0) return false;
    if ((isFunctionLike(node) || typescriptSyntax.isClassStaticBlockDeclaration(node)) && node !== scope) return false;
    recordHoistedFileReadBindings(node, scope, bindings);
    if (typescriptSyntax.isBinaryExpression(node) && node.operatorToken.kind >= typescriptSyntax.SyntaxKind.FirstAssignment && node.operatorToken.kind <= typescriptSyntax.SyntaxKind.LastAssignment) {
      writes.push(node.left);
    }
    return;
  });
  return budget >= 0;
}

/**
 * Record hoisted var declarations that shadow an imported reader root name in the enclosing scope.
 * Block-scoped let/const declarations and non-declaration nodes leave bindings unchanged.
 *
 * @param node - AST node inspected as a non-block-scoped variable declaration list
 * @param scope - enclosing scope boundary recorded when a reader root name matches
 * @param bindings - mutable reader-to-scope sets updated in place for matching reader root names
 * @returns Nothing. Adds scope to matching entries in bindings when a var declaration binds a reader root name.
 */
function recordHoistedFileReadBindings(node: TsNode, scope: TsNode, bindings: Map<string, Set<TsNode>>): void {
  if (!typescriptSyntax.isVariableDeclarationList(node) || (node.flags & typescriptSyntax.NodeFlags.BlockScoped)) return;
  for (const [callee, shadowedScopes] of bindings) {
    if (variableDeclarationListBindsName(node, callee.split(".", 1)[0] ?? "")) shadowedScopes.add(scope);
  }
}

/**
 * Normalize an assignment target to a reader call spelling, unwrapping parentheses and string-literal element access.
 *
 * @param node - assignment left-hand AST node to normalize
 * @param parsedSource - parsed syntax tree used to read expression text
 * @returns Dotted property text for property or string-literal element access, or undefined for other target shapes.
 */
function writtenFileReadCallee(node: TsNode, parsedSource: TsSourceFile): string | undefined {
  if (typescriptSyntax.isParenthesizedExpression(node)) return writtenFileReadCallee(node.expression, parsedSource);
  // Normalize property access so `fs . readFileSync = ...` invalidates the `fs.readFileSync` reader binding reliably.
  if (typescriptSyntax.isPropertyAccessExpression(node)) return dottedIdentifierPath(node) ?? node.getText(parsedSource);
  if (typescriptSyntax.isElementAccessExpression(node) && typescriptSyntax.isStringLiteral(node.argumentExpression)) {
    const receiver = dottedIdentifierPath(node.expression) ?? node.expression.getText(parsedSource);
    return `${receiver}.${node.argumentExpression.text}`;
  }
  return undefined;
}

/**
 * Check whether an imported reader call is hidden by a lexical binding, a hoisted shadowing scope, or a named class expression.
 * These extra guards apply only to reader exemptions; redirect matching uses the common lexical checks.
 *
 * @param node - AST call or write site where the imported reader appears
 * @param callee - imported reader call spelling whose root identifier is checked
 * @param bindings - hoisted shadowing scopes per reader name; a missing entry adds no hoisted evidence
 * @returns True if callee is shadowed at node by lexical bindings, recorded scopes, or a named class expression; otherwise false.
 */
function isFileReadBindingShadowed(node: TsNode, callee: string, bindings: FileReadBindings): boolean {
  if (isImportedCalleeShadowed(node, callee)) return true;
  const shadowedScopes = bindings.get(callee);
  const rootName = callee.split(".", 1)[0];
  for (let ancestor = node.parent; ancestor; ancestor = ancestor.parent) {
    if (shadowedScopes?.has(ancestor)) return true;
    if (typescriptSyntax.isClassExpression(ancestor) && ancestor.name?.text === rootName) return true;
  }
  return false;
}

/**
 * Collect local redirect call names imported from supported framework packages, ignoring unrelated and type-only bindings.
 *
 * @param parsedSource - parsed syntax tree whose top-level imports are inspected
 * @returns Set of local redirect aliases from named imports and member paths from namespace imports, or an empty set if none match.
 */
function importedFrameworkRedirectCallees(parsedSource: TsSourceFile): ReadonlySet<string> {
  const callees = new Set<string>();
  for (const statement of parsedSource.statements) {
    if (!typescriptSyntax.isImportDeclaration(statement) || !typescriptSyntax.isStringLiteral(statement.moduleSpecifier)) {
      continue;
    }
    if (!isFrameworkRedirectModule(statement.moduleSpecifier.text)) {
      continue;
    }
    const importClause = statement.importClause;
    if (!importClause || importClause.isTypeOnly || !importClause.namedBindings) {
      continue;
    }
    collectRedirectAliases(importClause.namedBindings, callees);
  }
  return callees;
}

/**
 * Check whether a module specifier belongs to the supported framework redirect allowlist to exclude unrelated redirect helpers.
 * Recognizes next/navigation, React Router's core and DOM packages, and supported Remix runtime packages.
 *
 * @param moduleName - import-source module specifier text
 * @returns True if moduleName matches the framework redirect allowlist; otherwise false.
 */
function isFrameworkRedirectModule(moduleName: string): boolean {
  return moduleName === "next/navigation" ||
    /^react-router(?:-dom)?$/.test(moduleName) ||
    /^@remix-run\/(?:node|cloudflare|deno|server-runtime)$/.test(moduleName);
}

/**
 * Record the local alias each binding style gives the framework redirect export, skipping named specifiers marked type-only.
 *
 * @param namedBindings - namespace or named import bindings from a framework redirect import
 * @param callees - mutable set receiving the namespace member path or renamed local redirect names
 * @returns Nothing. Adds redirect aliases from namedBindings to callees in place.
 */
function collectRedirectAliases(namedBindings: TsNamedImportBindings, callees: Set<string>): void {
  if (typescriptSyntax.isNamespaceImport(namedBindings)) {
    callees.add(`${namedBindings.name.text}.redirect`);
    return;
  }
  for (const element of namedBindings.elements) {
    const importedName = element.propertyName?.text ?? element.name.text;
    if (!element.isTypeOnly && importedName === "redirect") {
      callees.add(element.name.text);
    }
  }
}

/**
 * Collect syntax-only source-to-sink findings. A local script parse increments the shared parse count.
 * An unavailable parse or failed traversal leaves findings unchanged; full scans retain the separate same-line pass.
 * Invariant: this pass never uses TypeScript type-checking, emit, or schema changes.
 *
 * @param file - discovered script file whose display path anchors emitted fingerprints
 * @param source - full source text to parse with syntax-only TypeScript APIs
 * @param findings - accumulator that receives additional AST flow findings
 * @param sharedSourceFile - the run's shared parse result. Null or undefined triggers a local parse.
 * @returns Nothing. Appends AST flow findings after a successful traversal.
 */
export function analyseSecurityFlow(file: SourceFile, source: string, findings: Finding[], sharedSourceFile?: TsSourceFile | null): void {
  // Reuse the run's AST when available to avoid parsing and counting the script twice.
  const parsedSource = sharedSourceFile ?? getSourceFile(file, source);
  if (!parsedSource) {
    return;
  }
  // Recovery-tree text or position access can throw, so publish the local buffer only after traversal succeeds.
  // This optional pass reports security evidence; recovery failures add no reliable evidence, so they stay silent.
  // Discarding the buffer avoids partial results, while full scans retain separate same-line candidates.
  const flowFindings: Finding[] = [];
  try {
    const frameworkRedirectCallees = importedFrameworkRedirectCallees(parsedSource);
    const scopes: TsNode[] = [parsedSource];
    const staticBlocks: TsNode[] = [];
    walk(parsedSource, (node) => {
      if (isFunctionLike(node)) {
        scopes.push(node);
      } else if (typescriptSyntax.isClassStaticBlockDeclaration(node)) {
        staticBlocks.push(node);
      }
    });
    const fileReadCallees = fileReadBindingsForScopes(parsedSource, [...scopes, ...staticBlocks]);
    for (const scope of scopes) {
      analyseFlowScope(parsedSource, scope, frameworkRedirectCallees, fileReadCallees, file, flowFindings);
    }
  } catch {
    return;
  }
  for (const flow of flowFindings) {
    findings.push(flow);
  }
}

/**
 * Walk one function or the module top level and record bounded local taint evidence.
 * Invariant: each scope starts with fresh taint maps and its walk skips nested functions, so nested-function sinks never see outer tainted locals.
 * When the node budget runs out, the rest of the scope contributes no findings.
 *
 * @param parsedSource - syntax tree that owns positions and text extraction
 * @param scopeOwner - top-level source file or function-like node to scan
 * @param frameworkRedirectCallees - local names of framework redirect functions this file imports; an unshadowed call to one is a redirect sink
 * @param fileReadCallees - imported file readers and the scopes shadowing each; an unshadowed read keeps a tainted filename out of content taint
 * @param file - discovered file used for stable finding locations
 * @param findings - accumulator that receives sink findings for this scope
 * @returns - Nothing. Appends the scope's sink findings to the supplied accumulator.
 */
function analyseFlowScope(
  parsedSource: TsSourceFile,
  scopeOwner: TsNode,
  frameworkRedirectCallees: ReadonlySet<string>,
  fileReadCallees: FileReadBindings,
  file: SourceFile,
  findings: Finding[],
): void {
  const tainted = new Map<string, TaintRecord>();
  const contentTainted = new Map<string, TaintRecord>();
  const inputs = { tainted, contentTainted, fileReadCallees };
  const unsafeXmlParsers = new Set<string>();
  let budget = MAX_SCOPE_NODES;
  walk(scopeOwner, (node) => {
    if (budget <= 0) {
      return false;
    }
    budget -= 1;
    if (isFunctionLike(node) && node !== scopeOwner) {
      return false;
    }
    recordUnsafeXmlParser(parsedSource, node, unsafeXmlParsers);
    recordTaint(parsedSource, node, tainted);
    recordTaint(parsedSource, node, contentTainted, fileReadCallees);
    reportSink(parsedSource, node, inputs, unsafeXmlParsers, frameworkRedirectCallees, file, findings);
    return;
  });
}

/**
 * Update local provenance for variable declarations or identifier assignments, clearing an assignment's entry when its new value has no source.
 * Function initializers add no record; without fileReads, alias lookup uses bare identifiers instead of compound expressions.
 *
 * @param parsedSource - parsed syntax tree used for expression text and line positions
 * @param node - AST node inspected as a variable declaration or simple identifier assignment
 * @param tainted - mutable map of local variable names to source provenance records
 * @param fileReads - optional reader bindings that mask proven reader calls and enable depth-bounded compound alias lookup
 * @returns Nothing. Updates tainted in place for declarations and identifier assignments.
 */
function recordTaint(parsedSource: TsSourceFile, node: TsNode, tainted: Map<string, TaintRecord>, fileReads?: FileReadBindings): void {
  if (typescriptSyntax.isVariableDeclaration(node)) {
    recordVariableTaint(parsedSource, node, tainted, fileReads);
    return;
  }
  if (typescriptSyntax.isBinaryExpression(node) && node.operatorToken.kind === typescriptSyntax.SyntaxKind.EqualsToken && typescriptSyntax.isIdentifier(node.left)) {
    const nextRecord = taintRecordFromExpression(parsedSource, node.right, tainted, fileReads);
    if (nextRecord) {
      tainted.set(node.left.text, nextRecord);
    } else {
      tainted.delete(node.left.text);
    }
  }
}

/**
 * Record source provenance from a variable declaration's initializer for each bound identifier, including nested destructuring.
 * Missing initializers or untainted values leave existing entries unchanged; destructured names share one record regardless of keys or defaults.
 *
 * @param parsedSource - parsed syntax tree used to inspect the initializer and compute source lines
 * @param node - variable declaration whose initializer and binding pattern are analysed
 * @param tainted - mutable map of local provenance updated in place
 * @param fileReads - optional reader bindings that mask proven reader calls and enable compound alias lookup
 * @returns Nothing. Writes provenance entries into tainted for each identifier bound by node.
 */
function recordVariableTaint(parsedSource: TsSourceFile, node: import("typescript").VariableDeclaration, tainted: Map<string, TaintRecord>, fileReads?: FileReadBindings): void {
  if (!node.initializer) {
    return;
  }
  const record = taintRecordFromExpression(parsedSource, node.initializer, tainted, fileReads);
  if (!record) {
    return;
  }
  if (typescriptSyntax.isIdentifier(node.name)) {
    tainted.set(node.name.text, record);
    return;
  }
  taintBindingNames(node.name, record, tainted);
}

/**
 * Derive provenance for an expression from direct sources or bounded aliases, incrementing depth on successful alias propagation.
 *
 * @param parsedSource - parsed syntax tree used to classify direct sources and extract text
 * @param expression - initializer or right-hand expression evaluated for provenance
 * @param tainted - existing local provenance records consulted for identifier or compound aliases
 * @param fileReads - optional reader bindings that mask reader calls and enable compound-value alias searches
 * @returns Direct record at depth 1, incremented alias record below MAX_ALIAS_DEPTH, or undefined when ineligible including function values.
 */
function taintRecordFromExpression(parsedSource: TsSourceFile, expression: TsNode, tainted: Map<string, TaintRecord>, fileReads?: FileReadBindings): TaintRecord | undefined {
  if (isFunctionLike(expression)) {
    return undefined;
  }
  const kind = sourceKindOf(parsedSource, expression, fileReads);
  if (kind !== undefined) {
    return { line: lineIndexOf(parsedSource, expression), kind, depth: 1 };
  }
  const upstream = typescriptSyntax.isIdentifier(expression)
    ? tainted.get(expression.text)
    : fileReads ? taintedExpression(expression, parsedSource, tainted, fileReads, MAX_ALIAS_DEPTH - 1) : undefined;
  if (upstream?.depth !== undefined && upstream.depth < MAX_ALIAS_DEPTH) {
    return { line: upstream.line, kind: upstream.kind, depth: upstream.depth + 1 };
  }
  return undefined;
}

/**
 * Propagate shared source provenance across every identifier in a binding pattern, including nested object and array destructuring.
 * Array holes are ignored and tainted is mutated in place.
 *
 * @param name - identifier or destructuring binding pattern receiving provenance
 * @param record - shared source provenance record assigned to each bound identifier
 * @param tainted - mutable local provenance map updated in place
 * @returns Nothing. Writes record into tainted for every identifier bound by name.
 */
function taintBindingNames(name: import("typescript").BindingName, record: TaintRecord, tainted: Map<string, TaintRecord>): void {
  if (typescriptSyntax.isIdentifier(name)) {
    tainted.set(name.text, record);
    return;
  }
  for (const element of name.elements) {
    if (typescriptSyntax.isOmittedExpression(element)) {
      continue;
    }
    taintBindingNames(element.name, record, tainted);
  }
}

/**
 * Record local variables initialized with XMLParser (processEntities: true) or DOMParser (resolveEntity) constructor options.
 *
 * @param parsedSource - parsed syntax tree used to inspect constructor text
 * @param node - AST node tested as an identifier-bound variable declaration
 * @param unsafeXmlParsers - mutable set receiving flagged local parser variable names for later XXE sink checks
 * @returns Nothing. Adds matching local parser names to unsafeXmlParsers in place.
 */
function recordUnsafeXmlParser(parsedSource: TsSourceFile, node: TsNode, unsafeXmlParsers: Set<string>): void {
  if (!typescriptSyntax.isVariableDeclaration(node) || !typescriptSyntax.isIdentifier(node.name) || !node.initializer) {
    return;
  }
  if (isUnsafeXmlParserConstruction(parsedSource, node.initializer)) {
    unsafeXmlParsers.add(node.name.text);
  }
}

/**
 * Check redirect assignments and sink calls for request-derived input.
 * Same-line invariant: legacy scanners own these cases except for opted-in sink rules and unshadowed imported framework redirects.
 *
 * @param parsedSource - parsed file used to read expressions and locate them in source
 * @param node - source node checked for an assignment or call
 * @param inputs - tracked request flows and file readers used to distinguish path influence from content influence
 * @param unsafeXmlParsers - parser names that qualify for the XML sink rule
 * @param frameworkRedirectCallees - imported redirect names to recognize where their bindings are visible
 * @param file - source file used to locate the emitted findings
 * @param findings - caller's accumulator for qualifying findings
 * @returns Nothing. Appends any matching findings to the accumulator.
 */
function reportSink(
  parsedSource: TsSourceFile,
  node: TsNode,
  inputs: FlowInputs,
  unsafeXmlParsers: ReadonlySet<string>,
  frameworkRedirectCallees: ReadonlySet<string>,
  file: SourceFile,
  findings: Finding[],
): void {
  reportRedirectAssignmentSink(parsedSource, node, inputs.tainted, file, findings);
  const call = callLikeExpression(node);
  if (!call) {
    return;
  }
  const callee = call.expression.getText(parsedSource);
  const isFrameworkRedirectCallee = frameworkRedirectCallees.has(callee) && !isImportedCalleeShadowed(call, callee);
  const sink = AST_FLOW_SINKS.find((candidate) => candidate.isSink({ callee, call, sourceFile: parsedSource, unsafeXmlParsers, isFrameworkRedirectCallee }));
  if (!sink) {
    return;
  }
  // A request-controlled filename proves path influence, not control of the bytes read.
  const contentOnly = sink.ruleId === "security.unsafe-deserialization";
  const hit = taintedInput(call, parsedSource, contentOnly ? inputs.contentTainted : inputs.tainted, contentOnly ? inputs.fileReadCallees : undefined);
  if (!hit) {
    return;
  }
  const sinkLine = lineIndexOf(parsedSource, call);
  const reportsSameLine = sink.shouldReportSameLine === true || isFrameworkRedirectCallee;
  if (sinkLine === hit.line && !reportsSameLine) {
    return;
  }
  const sinkForm = sink.ruleId === "security.unsafe-deserialization" ? unsafeDeserializationSinkForm(callee) : undefined;
  findings.push(flowFinding(file, sinkLine, sink.ruleId, sink.sinkKind, hit.kind, hit.depth, sinkForm));
}

type DeserializationSinkForm = "eval" | "function-constructor" | "unserialize" | "yaml-load" | "vm";

/**
 * Classifies an unsafe-deserialization callee into a closed token so duplicate-eval merging never suppresses a co-located `vm` or `yaml` sink.
 *
 * @param callee - normalized sink callee text matched by `isUnsafeDeserializationSink`
 * @returns Closed sink mechanism token (`"eval"`, `"function-constructor"`, `"unserialize"`, `"yaml-load"`, or `"vm"`).
 */
function unsafeDeserializationSinkForm(callee: string): DeserializationSinkForm {
  if (/^eval$/.test(callee)) {
    return "eval";
  }
  if (/^Function$/.test(callee)) {
    return "function-constructor";
  }
  if (/(?:^|\.)unserialize$/.test(callee)) {
    return "unserialize";
  }
  if (/^(?:yaml|YAML|jsYaml|jsyaml)\.load$/.test(callee)) {
    return "yaml-load";
  }
  return "vm";
}

/**
 * Check whether an imported callee's root name is rebound around a call by a parameter, local declaration, loop binding, or catch binding.
 * Scans ancestors below the source file.
 *
 * @param call - AST call use site from which enclosing scopes are walked upward
 * @param callee - source spelling of the callee whose root identifier is checked
 * @returns True if callee's root name is shadowed by an enclosing binding, or false if unshadowed or root is empty.
 */
function isImportedCalleeShadowed(call: TsNode, callee: string): boolean {
  const rootName = callee.split(".", 1)[0];
  if (!rootName) {
    return false;
  }
  for (let ancestor = call.parent; ancestor && !typescriptSyntax.isSourceFile(ancestor); ancestor = ancestor.parent) {
    if (functionLikeBindsName(ancestor, rootName) || lexicalStatementsBindName(ancestor, rootName) || loopOrCatchBindsName(ancestor, rootName)) {
      return true;
    }
  }
  return false;
}

/**
 * Check whether a function-like node binds an identifier through a parameter or its own declaration/expression name.
 * Methods and accessors contribute only parameter bindings because their property names do not hide imported functions.
 *
 * @param node - AST node inspected as a function-like scope boundary
 * @param name - identifier name checked for local binding
 * @returns True if node binds name via parameter or function declaration/expression name; false for non-function nodes or no match.
 */
function functionLikeBindsName(node: TsNode, name: string): boolean {
  if (!isFunctionLike(node)) {
    return false;
  }
  const functionNode = node as TsNode & {
    name?: import("typescript").PropertyName;
    parameters: readonly import("typescript").ParameterDeclaration[];
  };
  const bindsOwnName = typescriptSyntax.isFunctionDeclaration(node) || typescriptSyntax.isFunctionExpression(node);
  if (bindsOwnName && functionNode.name && typescriptSyntax.isIdentifier(functionNode.name) && functionNode.name.text === name) {
    return true;
  }
  return functionNode.parameters.some((parameter) => bindingNameContains(parameter.name, name));
}

/**
 * Check whether a lexical block or switch clause binds a name via direct runtime statements, including its temporal-dead-zone prefix.
 *
 * @param node - AST block, module block, case clause, or default clause to inspect
 * @param name - identifier name checked against direct value declarations
 * @returns True if node is a block or switch clause whose direct statements bind name; otherwise false.
 */
function lexicalStatementsBindName(node: TsNode, name: string): boolean {
  if (typescriptSyntax.isBlock(node) || typescriptSyntax.isModuleBlock(node) || typescriptSyntax.isCaseClause(node) || typescriptSyntax.isDefaultClause(node)) {
    return node.statements.some((statement) => statementBindsName(statement, name));
  }
  return false;
}

/**
 * Check whether a loop or catch clause binds an identifier in its catch variable or variable-declaration initializer.
 *
 * @param node - AST node inspected as a catch clause or for/for-in/for-of loop
 * @param name - identifier name checked against the clause's local bindings
 * @returns True if node binds name; missing catch variables, non-declaration loop initializers, and other node kinds return false.
 */
function loopOrCatchBindsName(node: TsNode, name: string): boolean {
  if (typescriptSyntax.isCatchClause(node)) {
    return node.variableDeclaration ? bindingNameContains(node.variableDeclaration.name, name) : false;
  }
  if (typescriptSyntax.isForStatement(node)) {
    return node.initializer && typescriptSyntax.isVariableDeclarationList(node.initializer)
      ? variableDeclarationListBindsName(node.initializer, name)
      : false;
  }
  if (typescriptSyntax.isForInStatement(node) || typescriptSyntax.isForOfStatement(node)) {
    return typescriptSyntax.isVariableDeclarationList(node.initializer)
      ? variableDeclarationListBindsName(node.initializer, name)
      : false;
  }
  return false;
}

/**
 * Check whether a statement introduces a runtime value binding for name; only runtime declarations count
 * because type-only declarations do not shadow an imported value.
 *
 * @param statement - AST statement checked for variable, function, class, enum, import-equals, or identifier namespace declarations
 * @param name - identifier name tested against the statement's runtime bindings
 * @returns True if statement declares a runtime binding matching name; otherwise false.
 */
function statementBindsName(statement: import("typescript").Statement, name: string): boolean {
  if (typescriptSyntax.isVariableStatement(statement)) {
    return variableDeclarationListBindsName(statement.declarationList, name);
  }
  if (typescriptSyntax.isFunctionDeclaration(statement) || typescriptSyntax.isClassDeclaration(statement) || typescriptSyntax.isEnumDeclaration(statement)) {
    return statement.name?.text === name;
  }
  if (typescriptSyntax.isImportEqualsDeclaration(statement)) {
    return statement.name.text === name;
  }
  if (typescriptSyntax.isModuleDeclaration(statement) && typescriptSyntax.isIdentifier(statement.name)) {
    return statement.name.text === name;
  }
  return false;
}

/**
 * Check whether any declaration in a variable declaration list binds an identifier, including nested destructuring, for import-shadow checks.
 *
 * @param list - variable declaration list whose declarators are inspected
 * @param name - identifier name checked across all declarator binding patterns
 * @returns True if any declaration in list binds name; otherwise false.
 */
function variableDeclarationListBindsName(list: import("typescript").VariableDeclarationList, name: string): boolean {
  return list.declarations.some((declaration) => bindingNameContains(declaration.name, name));
}

/**
 * Check whether a binding pattern declares a local identifier, including nested object and array destructuring.
 * Property keys and omitted array elements are ignored.
 *
 * @param bindingName - identifier or destructuring pattern inspected recursively
 * @param name - target identifier name to match against bound locals
 * @returns True if bindingName declares name; an empty binding pattern or non-matching pattern returns false.
 */
function bindingNameContains(bindingName: import("typescript").BindingName, name: string): boolean {
  if (typescriptSyntax.isIdentifier(bindingName)) {
    return bindingName.text === name;
  }
  return bindingName.elements.some((element) =>
    !typescriptSyntax.isOmittedExpression(element) && bindingNameContains(element.name, name),
  );
}

/**
 * Check for a location.href or window.location.href assignment receiving a direct source or tracked tainted value.
 * Same-line invariant: skips same-line hits because the legacy scanner looks for direct source tokens in the sink segment.
 *
 * @param parsedSource - parsed syntax tree used to inspect assignment text and sink line
 * @param node - AST node tested as an equals assignment to location.href or window.location.href
 * @param tainted - local provenance map consulted for right-hand side taint
 * @param file - discovered file whose display path locates emitted findings
 * @param findings - accumulator receiving cross-line open-redirect candidate findings
 * @returns Nothing. Appends a finding to findings when a cross-line assignment match qualifies.
 */
function reportRedirectAssignmentSink(parsedSource: TsSourceFile, node: TsNode, tainted: Map<string, TaintRecord>, file: SourceFile, findings: Finding[]): void {
  if (!typescriptSyntax.isBinaryExpression(node) || node.operatorToken.kind !== typescriptSyntax.SyntaxKind.EqualsToken) {
    return;
  }
  const left = node.left.getText(parsedSource);
  if (!/^(?:location|window\.location)\.href$/.test(left)) {
    return;
  }
  const hit = taintedExpression(node.right, parsedSource, tainted);
  if (!hit) {
    return;
  }
  const sinkLine = lineIndexOf(parsedSource, node);
  if (sinkLine === hit.line) {
    return;
  }
  findings.push(flowFinding(file, sinkLine, "security.open-redirect-candidate", "redirect", hit.kind, hit.depth));
}

/**
 * Narrow an AST node to a call or constructor expression because both forms can be dynamic-regexp sinks handled through one interface.
 *
 * @param node - AST node checked for CallExpression or NewExpression syntax
 * @returns node unchanged when it is a call or constructor expression, or undefined when it is neither.
 */
function callLikeExpression(node: TsNode): TsCallLikeExpression | undefined {
  return typescriptSyntax.isCallExpression(node) || typescriptSyntax.isNewExpression(node) ? node : undefined;
}

/**
 * Search call arguments in order for the first tainted expression record; prunes functions and sanitizer calls, though direct-source checks
 * can still see pruned function or sanitizer text in an ancestor.
 *
 * @param call - call or constructor expression whose arguments are searched in order
 * @param parsedSource - parsed syntax tree used for source-text extraction and line mapping
 * @param tainted - local provenance map consulted for tainted identifier references
 * @param fileReads - optional reader bindings that mask proven reader calls and exclude property-key aliases
 * @returns First source record found across arguments, or undefined for absent arguments or no match.
 */
function taintedInput(call: TsCallLikeExpression, parsedSource: TsSourceFile, tainted: Map<string, TaintRecord>, fileReads?: FileReadBindings): TaintRecord | undefined {
  for (const argument of call.arguments ?? []) {
    const found = taintedExpression(argument, parsedSource, tainted, fileReads);
    if (found) {
      return found;
    }
  }
  return undefined;
}

/**
 * Search an expression for direct sources or tainted aliases while pruning functions and sanitizer calls (direct-source checks can still see
 * their text because they scan ancestor text). With fileReads, skips proven reader calls and excludes property-key aliases.
 *
 * @param expression - root expression node walked for taint evidence
 * @param parsedSource - parsed syntax tree used for text extraction and line lookup
 * @param tainted - local provenance map consulted for tracked identifiers
 * @param fileReads - optional reader bindings enabling content-only filtering of proven reads and property keys
 * @param maxAliasDepth - depth limit applied to alias records only (defaults to MAX_ALIAS_DEPTH)
 * @returns First eligible taint record found, or undefined if none qualifies.
 */
function taintedExpression(expression: TsNode, parsedSource: TsSourceFile, tainted: Map<string, TaintRecord>, fileReads?: FileReadBindings, maxAliasDepth = MAX_ALIAS_DEPTH): TaintRecord | undefined {
  let found: TaintRecord | undefined;
  if (isFunctionLike(expression)) {
    return undefined;
  }
  walk(expression, (node) => {
    if (found) {
      return false;
    }
    if (node !== expression && isFunctionLike(node)) {
      return false;
    }
    if (fileReads && isImportedFileRead(node, parsedSource, fileReads)) return false;
    if (isSafeWrapperExpression(parsedSource, node)) {
      return false;
    }
    const record = taintedIdentifierRecord(node, tainted, maxAliasDepth, fileReads !== undefined);
    if (record) {
      found = record;
      return false;
    }
    const kind = sourceKindOf(parsedSource, node, fileReads);
    if (kind !== undefined) {
      found = { line: lineIndexOf(parsedSource, node), kind, depth: 0 };
      return false;
    }
    return;
  });
  return found;
}

/**
 * Look up an identifier in tainted only when its alias depth does not exceed maxAliasDepth.
 *
 * @param node - AST node tested as a local identifier reference
 * @param tainted - local provenance map indexed by identifier name
 * @param maxAliasDepth - maximum alias depth permitted for returned records
 * @param contentOnly - when true, excludes property-access names and property-assignment keys so key spelling cannot stand in for a local value
 * @returns Matching source record within the depth limit, or undefined for non-identifiers, excluded keys, unknown locals, or deeper records.
 */
function taintedIdentifierRecord(node: TsNode, tainted: Map<string, TaintRecord>, maxAliasDepth: number, contentOnly: boolean): TaintRecord | undefined {
  if (!typescriptSyntax.isIdentifier(node)) return undefined;
  const propertyKey = isPropertyAccessName(node) || (typescriptSyntax.isPropertyAssignment(node.parent) && node.parent.name === node);
  if (contentOnly && propertyKey) return undefined;
  const record = tainted.get(node.text);
  return record && record.depth <= maxAliasDepth ? record : undefined;
}

/**
 * Check whether a call's spelling identifies a supported deserialization or dynamic-code sink.
 *
 * @param callee - source text of the call or constructor callee
 * @param call - call expression supplying arguments for YAML schema checks
 * @param parsedSource - parsed syntax tree used to read argument text
 * @returns True for supported deserialization or dynamic-code sinks; safe-schema YAML loads and other names return false.
 */
function isUnsafeDeserializationSink(callee: string, call: TsCallLikeExpression, parsedSource: TsSourceFile): boolean {
  return (
    /^eval$/.test(callee) ||
    /^Function$/.test(callee) ||
    /(?:^|\.)unserialize$/.test(callee) ||
    isUnsafeYamlLoad(callee, call, parsedSource) ||
    /^vm\.(?:runInNewContext|runInThisContext|runInContext)$/.test(callee) ||
    /^(?:vm\.)?Script$/.test(callee)
  );
}

/**
 * Check whether a call is a recognized YAML load lacking safe-schema option text; missing options make a recognized load unsafe.
 *
 * @param callee - source text of the call target matched against recognized YAML loaders
 * @param call - call expression whose second argument is checked for safe-schema options
 * @param parsedSource - parsed syntax tree used to inspect option text
 * @returns True if callee is a recognized YAML load without safe-schema options; other callees return false.
 */
function isUnsafeYamlLoad(callee: string, call: TsCallLikeExpression, parsedSource: TsSourceFile): boolean {
  if (!/^(?:yaml|YAML|jsYaml|jsyaml)\.load$/.test(callee)) {
    return false;
  }
  return !hasSafeYamlSchema(call, parsedSource);
}

/**
 * Check whether a YAML load's second argument text contains schema: followed by FAILSAFE_SCHEMA, JSON_SCHEMA, or CORE_SCHEMA.
 * Accepts an optional qualifier and can also match nested, quoted, or commented text.
 *
 * @param call - call expression whose second argument supplies YAML options
 * @param parsedSource - parsed syntax tree used to read the options argument text
 * @returns True when safe-schema text is found; missing options return false so the YAML load receives no safe-schema exemption.
 */
function hasSafeYamlSchema(call: TsCallLikeExpression, parsedSource: TsSourceFile): boolean {
  const options = call.arguments?.[1];
  return options !== undefined && /\bschema\s*:\s*(?:[A-Za-z_$][A-Za-z0-9_$]*\.)?(?:FAILSAFE_SCHEMA|JSON_SCHEMA|CORE_SCHEMA)\b/.test(options.getText(parsedSource));
}

/**
 * Check callee text and call options for XXE sink syntax, including locals initialized by flagged parser constructions.
 *
 * @param callee - source text of the call target checked for parser methods or inline construction
 * @param call - call expression whose arguments are checked for unsafe libxml options
 * @param unsafeXmlParsers - local parser variable names recorded as constructed with entity expansion enabled
 * @returns True for flagged libxml options, recorded parser methods, or inline unsafe parser constructions; otherwise false.
 */
function isXxeSink(callee: string, call: TsCallLikeExpression, unsafeXmlParsers: ReadonlySet<string>): boolean {
  const parserMethod = callee.match(/^([A-Za-z_$][A-Za-z0-9_$]*)\.(?:parse|parseFromString)$/);
  return (
    (isLibxmlEntityExpandingCall(callee) && hasUnsafeXmlParserOption(call)) ||
    (parserMethod !== null && unsafeXmlParsers.has(parserMethod[1] ?? "")) ||
    isInlineUnsafeXmlParserCall(callee)
  );
}

/**
 * Check whether a callee names parseXml or parseXmlString, optionally qualified by libxmljs, for subsequent unsafe-option checks.
 * A name match alone does not establish entity expansion because the caller checks the call's options.
 *
 * @param callee - source text of the call expression target
 * @returns True if callee matches parseXml or parseXmlString (optionally prefixed with libxmljs); otherwise false.
 */
function isLibxmlEntityExpandingCall(callee: string): boolean {
  return /^(?:libxmljs\.)?(?:parseXml|parseXmlString)$/.test(callee);
}

/**
 * Perform textual option checks on call arguments for unsafe XML entity-expansion flags.
 *
 * @param call - call expression whose arguments are inspected as source text
 * @returns True if any argument contains noent, dtdload, or processEntities set to true, or a resolveEntity property; missing arguments return false.
 */
function hasUnsafeXmlParserOption(call: TsCallLikeExpression): boolean {
  return (call.arguments ?? []).some((argument) => /\b(?:noent|dtdload|processEntities)\s*:\s*true\b|\bresolveEntity\s*:/.test(argument.getText()));
}

/**
 * Check whether callee text matches an inline XMLParser or DOMParser call with entity-expansion option syntax.
 *
 * @param callee - source text of the call target
 * @returns True for inline new XMLParser(...).parse with processEntities: true or new DOMParser(...).parseFromString with resolveEntity; else false.
 */
function isInlineUnsafeXmlParserCall(callee: string): boolean {
  return (
    /\bnew\s+XMLParser\s*\([^)]*\bprocessEntities\s*:\s*true[^)]*\)\.parse$/.test(callee) ||
    /\bnew\s+DOMParser\s*\([^)]*\bresolveEntity\s*:[^)]*\)\.parseFromString$/.test(callee)
  );
}

/**
 * Check whether an expression constructs XMLParser (with processEntities: true) or DOMParser (with resolveEntity).
 *
 * @param parsedSource - parsed syntax tree used to inspect constructor callee and argument text
 * @param expr - AST expression tested as a NewExpression parser construction
 * @returns True for recognized XMLParser or DOMParser constructions containing unsafe-option syntax; other expressions return false.
 */
function isUnsafeXmlParserConstruction(parsedSource: TsSourceFile, expr: TsNode): boolean {
  if (!typescriptSyntax.isNewExpression(expr)) {
    return false;
  }
  const callee = expr.expression.getText(parsedSource);
  const text = expr.getText(parsedSource);
  return (
    (/^(?:XMLParser|fastXmlParser\.XMLParser)$/.test(callee) && /\bprocessEntities\s*:\s*true\b/.test(text)) ||
    (/^(?:DOMParser|xmldom\.DOMParser)$/.test(callee) && /\bresolveEntity\s*:/.test(text))
  );
}

/**
 * Identify the first recognized external-input source in an expression so a flow finding can report where an unchecked value came from.
 *
 * @param parsedSource - parsed syntax tree used to inspect wrapper calls and blank nested handler parameters
 * @param expr - AST expression evaluated for external-input tokens
 * @param fileReads - optional reader bindings whose calls are masked so file contents remain distinct from file paths
 * @returns First matching source kind string, or undefined for no input evidence such as plain text or a recognized escaping call.
 */
function sourceKindOf(parsedSource: TsSourceFile, expr: TsNode, fileReads?: FileReadBindings): string | undefined {
  // A recognized escaping helper is evidence that the developer prepared the value for this check.
  if (isSafeWrapperExpression(parsedSource, expr)) {
    return undefined;
  }
  // A literal in code or a template with no substitutions supplies text rather than a request value.
  if (isSourceTextLiteral(expr)) {
    return undefined;
  }
  let text = textOutsideRequestHandlers(parsedSource, expr);
  // Without recognized file reads, there are no read paths to mask from input classification.
  if (fileReads?.size) {
    const start = expr.getStart(parsedSource);
    walk(expr, (node) => {
      // Keep other calls visible. A file read's path is separate from the file contents the developer uses.
      if (!isImportedFileRead(node, parsedSource, fileReads)) return;
      const from = node.getStart(parsedSource) - start;
      const endOffset = node.getEnd() - start;
      text = text.slice(0, from) + " ".repeat(endOffset - from) + text.slice(endOffset);
      return false;
    });
  }
  // Use the first recognized input kind to describe the starting point in the finding.
  for (const token of SOURCE_TOKENS) {
    // When the remaining source matches this check, show its input kind in the report.
    if (token.pattern.test(text)) {
      return token.kind;
    }
  }
  return undefined;
}

/**
 * Blank local request parameters inside nested non-contributing handlers while retaining source offsets and evidence from value-producing callbacks.
 *
 * @param parsedSource - parsed syntax tree used to locate expression and parameter offsets
 * @param expr - AST expression whose text is filtered for nested handler request bindings
 * @returns Expression text with non-contributing nested handler request parameters replaced by spaces.
 */
function textOutsideRequestHandlers(parsedSource: TsSourceFile, expr: TsNode): string {
  const expressionStart = expr.getStart(parsedSource);
  let text = expr.getText(parsedSource);
  walk(expr, (node) => {
    // Keep expressions and value-producing callbacks in view when they can supply input to the current finding.
    if (node === expr || !isFunctionLike(node) || contributesCallbackValue(node)) {
      return;
    }
    const declaredNames = declaredRequestParameterNames(node);
    // A nested handler with no recognized request parameter has no local request names to hide.
    if (declaredNames.size === 0) {
      return;
    }
    walk(node, (inner) => {
      // Mask the handler's parameter references. A property named req, such as this.req, is a different binding.
      if (typescriptSyntax.isIdentifier(inner) && declaredNames.has(inner.text) && !isPropertyAccessName(inner)) {
        const blankStart = inner.getStart(parsedSource) - expressionStart;
        const blankEnd = inner.getEnd() - expressionStart;
        text = text.slice(0, blankStart) + " ".repeat(blankEnd - blankStart) + text.slice(blankEnd);
      }
    });
    return;
  });
  return text;
}

/**
 * Collect direct identifier parameter names matching req, request, or ctx for the scanner's name-based filter.
 *
 * @param node - function-like AST node whose direct parameter list is inspected
 * @returns Set of matching parameter names; an empty set means the scanner skips blanking for this function.
 */
function declaredRequestParameterNames(node: TsNode): Set<string> {
  const { parameters } = node as import("typescript").SignatureDeclaration;
  return new Set(parameters.flatMap((parameter) => (typescriptSyntax.isIdentifier(parameter.name) && REQUEST_RECEIVER_NAMES.has(parameter.name.text) ? [parameter.name.text] : [])));
}

/**
 * Check whether a function-like node is immediately invoked or passed to a known value-producing collection/promise method.
 *
 * @param node - function-like AST node whose parent call context is inspected
 * @returns True when the callback can contribute its return value to the enclosing expression; otherwise false.
 */
function contributesCallbackValue(node: TsNode): boolean {
  // Extra parentheses around a function do not change whether its value is used.
  while (typescriptSyntax.isParenthesizedExpression(node.parent)) {
    node = node.parent;
  }
  const parent = node.parent;
  // Developers can invoke a function through call or apply. Reading one of those properties alone supplies no result.
  if (typescriptSyntax.isPropertyAccessExpression(parent) && parent.expression === node) {
    return (parent.name.text === "call" || parent.name.text === "apply")
      && typescriptSyntax.isCallExpression(parent.parent) && parent.parent.expression === parent;
  }
  // A function merely stored as a value does not contribute its body to the current finding.
  if (!typescriptSyntax.isCallExpression(parent)) {
    return false;
  }
  // An immediately invoked function can pass its return value into the expression being checked.
  if (parent.expression === node) {
    return true;
  }
  // Known collection and promise methods use a callback result, such as a value returned from then.
  return parent.arguments[0] === node && typescriptSyntax.isPropertyAccessExpression(parent.expression)
    && /^(?:map|flatMap|reduce|reduceRight|then|catch)$/u.test(parent.expression.name.text);
}

/**
 * Check whether a node is the property name of a dotted property access (such as this.req), where it reads no local binding.
 *
 * @param identifier - AST node compared against its parent PropertyAccessExpression name
 * @returns True when identifier names the property in a dotted access; otherwise false.
 */
function isPropertyAccessName(identifier: TsNode): boolean {
  return typescriptSyntax.isPropertyAccessExpression(identifier.parent) && identifier.parent.name === identifier;
}

/**
 * Check whether an expression is plain literal text rather than an interpolated template or dynamic expression.
 *
 * @param expr - AST expression tested as a string literal or substitution-free template literal
 * @returns True for string literals and substitution-free template literals; other expressions including interpolating templates return false.
 */
function isSourceTextLiteral(expr: TsNode): boolean {
  return typescriptSyntax.isStringLiteral(expr) || typescriptSyntax.isNoSubstitutionTemplateLiteral(expr);
}

/**
 * Check whether an expression calls a recognized regexp-escaping helper so callers can treat it as sanitizer evidence and skip its argument subtree.
 *
 * @param parsedSource - parsed syntax tree used to extract the call target text
 * @param expr - AST node tested as a CallExpression
 * @returns True when expr calls a recognized regexp-escaping helper; non-calls and other names return false.
 */
function isSafeWrapperExpression(parsedSource: TsSourceFile, expr: TsNode): boolean {
  if (!typescriptSyntax.isCallExpression(expr)) {
    return false;
  }
  const callee = expr.expression.getText(parsedSource);
  return /^(?:escapeRegExp|escapeStringRegexp|regexpEscape|RegExp\.escape)$/.test(callee);
}

/**
 * Check whether an AST node is a function-like boundary that receives separate taint analysis.
 *
 * @param node - AST node tested against function, arrow, method, constructor, and accessor kinds
 * @returns True for functions, arrows, methods, constructors, and accessors; other nodes return false.
 */
function isFunctionLike(node: TsNode): boolean {
  return (
    typescriptSyntax.isFunctionDeclaration(node) ||
    typescriptSyntax.isFunctionExpression(node) ||
    typescriptSyntax.isArrowFunction(node) ||
    typescriptSyntax.isMethodDeclaration(node) ||
    typescriptSyntax.isConstructorDeclaration(node) ||
    typescriptSyntax.isGetAccessorDeclaration(node) ||
    typescriptSyntax.isSetAccessorDeclaration(node)
  );
}

/**
 * Build an AST-flow finding with the same stable location and metadata contract as line rules.
 * Invariant: fingerprints continue to derive only from rule id, file path, line, and symbol.
 *
 * @param file - discovered file that owns the finding path
 * @param lineIndex - zero-based sink line from the parsed source file
 * @param ruleId - security rule id to emit
 * @param sinkKind - sink category for machine-readable metadata
 * @param sourceKind - external input category for machine-readable metadata
 * @param flowDepth - bounded alias distance between source and sink
 * @param sinkForm - closed sink mechanism token attached for `security.unsafe-deserialization`; omit for other rules
 * @returns A medium-confidence security warning on the one-based sink line, with the rule's own message and remediation or generic cross-line text.
 */
function flowFinding(
  file: SourceFile,
  lineIndex: number,
  ruleId: string,
  sinkKind: string,
  sourceKind: string,
  flowDepth: number,
  sinkForm?: DeserializationSinkForm,
): Finding {
  const base = securityRuleDetails(ruleId);
  return makeFinding({
    ruleId,
    message: base ? base.message : "External input reaches a risky sink across lines.",
    filePath: file.displayPath,
    line: lineIndex + 1,
    severity: "warning",
    pillar: "security",
    confidence: "medium",
    remediation: base ? base.remediation : "Validate external input before it reaches the sink.",
    metadata: { sourceKind, sinkKind, flowDepth, ...(sinkForm === undefined ? {} : { sinkForm }) },
  });
}

/**
 * Look up message and remediation text for both same-line rule ids and AST-only security candidates.
 *
 * @param ruleId - security rule identifier emitted by a same-line or AST flow sink
 * @returns Message and remediation pair for known rules, or undefined if ruleId is unrecognized.
 */
function securityRuleDetails(ruleId: string): Pick<SecurityFlowRule, "message" | "remediation"> | undefined {
  return (
    SECURITY_FLOW_RULES.find((rule) => rule.ruleId === ruleId) ??
    ({
      "security.unsafe-deserialization": {
        message: "External input reaches an unsafe deserialization or dynamic code-loading sink.",
        remediation: "Use a schema-bound parser or validate and decode data without executing code.",
      },
      "security.xxe-candidate": {
        message: "External XML input reaches an XML parser configured to expand entities.",
        remediation: "Disable external entity expansion and use hardened XML parser options.",
      },
    } as const)[ruleId]
  );
}
