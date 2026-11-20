// Conservative security candidates from same-line source tokens and bounded local AST flow.
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

// Parse source text for discovered file through the shared syntax-only parser; script parsing increments the shared parse count.
// Return an AST even with syntax diagnostics, or null for non-script input or parser exceptions.
// Null skips AST flow. Parser exceptions stay silent because full scans retain their separate same-line pass.
function getSourceFile(file: SourceFile, source: string): TsSourceFile | null {
  try {
    return parseScript(file, source)?.sourceFile ?? null;
  } catch {
    return null;
  }
}

// Walk the subtree rooted at node depth-first, calling visit before its children. A false result skips that node's children.
// Returns nothing. The visitor performs the work at each visited node.
function walk(node: TsNode, visit: (node: TsNode) => boolean | void): void {
  if (visit(node) === false) {
    return;
  }
  typescriptSyntax.forEachChild(node, (child) => {
    walk(child, visit);
  });
}

// Return node's zero-based start line within parsedSource so callers can convert it to a one-based finding line.
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

// Same-line matching is intentional: reports stable candidate findings without implying full taint analysis.
// Returns nothing. Appends to findings at lineNumber in file for sinks using the first catalogue source pattern found in codeLine.
// Resets shared sink matchers before checking a recognized source. With no source token, the sink matchers and findings are untouched.
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

// Return the first SOURCE_TOKENS entry whose pattern matches codeLine, using catalogue order for deterministic metadata.
// Return undefined when the line contains no recognized external-input token.
function sourceToken(codeLine: string): SourceToken | undefined {
  return SOURCE_TOKENS.find((source) => source.pattern.test(codeLine));
}

// Return whether sourcePattern matches a bounded call segment selected by global callPattern in codeLine.
// Reset callPattern.lastIndex to zero; testing a global or sticky sourcePattern can also advance or reset its lastIndex.
// Return false when no selected segment contains source evidence; callPattern must have the global flag.
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

// Return a bounded source slice from callStart in codeLine for same-line sink matching.
// Stop at the first closing parenthesis or 240 characters; if no closing parenthesis occurs, return the available bounded text.
function singleLineCallSegment(codeLine: string, callStart: number): string {
  // Cap the text inspected per candidate call; this is a bounded heuristic, not balanced-parenthesis parsing.
  const maxSegmentLength = 240;
  const segment = codeLine.slice(callStart, callStart + maxSegmentLength);
  const close = segment.indexOf(")");
  return close === -1 ? segment : segment.slice(0, close + 1);
}

// Returns a warning at the supplied file and line, using the rule for its identity, message, and remediation.
// Stable finding contract: confidence is medium, and metadata contains the supplied source kind and the rule's sink kind.
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
// Augments the same-line checks above: detects an external-input value assigned
// to a local variable and later passed (across lines, within one function) to a
// known sink. The same-line pass above is untouched, so its findings and
// fingerprints are unchanged; this pass only adds genuinely cross-line cases and
// skips any flow whose source and sink share a line.

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

// Return runtime filesystem-reader names imported by parsedSource, including default/namespace member paths and named local aliases.
// Recognize fs and node:fs, including their promises modules; promises support readFile only. Return an empty set if none qualify.
// Only these imports establish the filename/content boundary; unrelated helpers retain ordinary taint.
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

// Return callable names exposed by import clause for the reader names in methods.
// Include default and namespace member paths and matching named aliases; skip named type-only imports and return an empty array if none match.
// The caller must exclude whole type-only import clauses.
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

// Return whether node is a call whose callee text in parsedSource belongs to bindings and has no visible reader shadowing.
// bindings supplies imported-reader names and hoisted shadowing scopes; false leaves the expression eligible for content taint.
function isImportedFileRead(node: TsNode, parsedSource: TsSourceFile, bindings: FileReadBindings): boolean {
  if (!typescriptSyntax.isCallExpression(node)) return false;
  const callee = node.expression.getText(parsedSource);
  return bindings.has(callee) && !isFileReadBindingShadowed(node, callee, bindings);
}

// Build reader exemptions from imports in parsedSource and the scope boundaries supplied in scopes.
// Return a map of reader names to shadowing scopes; no readers or any scope exceeding the node budget produces an empty map.
// Drop exemptions for unshadowed assignments that match a tracked reader member so that replacement methods remain eligible for content taint.
function fileReadBindingsForScopes(parsedSource: TsSourceFile, scopes: readonly TsNode[]): FileReadBindings {
  const bindings = new Map([...importedFileReadCallees(parsedSource)].map((callee) => [callee, new Set<TsNode>()]));
  if (bindings.size === 0) return bindings;
  const writes: TsNode[] = [];
  for (const scope of scopes) {
    if (!indexFileReadScope(scope, bindings, writes)) return new Map();
  }
  for (const write of writes) {
    const callee = writtenFileReadCallee(write, parsedSource);
    if (callee && bindings.has(callee) && !isFileReadBindingShadowed(write, callee, bindings)) bindings.delete(callee);
  }
  return bindings;
}

// Scan scope for hoisted reader shadowing in bindings and append assignment targets to writes; skip nested functions and static blocks.
// bindings maps reader names to shadowing scopes, and writes collects targets for replacement checks; both arguments are mutated.
// Return false on node-budget exhaustion, leaving partial records for the caller to discard; otherwise return true.
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

// Returns nothing. For var declaration-list node, record its enclosing scope as shadowing in bindings for each matching reader root name.
// bindings holds mutable reader-to-scope sets; scope is the indexing boundary, and let/const or non-declaration nodes leave it unchanged.
function recordHoistedFileReadBindings(node: TsNode, scope: TsNode, bindings: Map<string, Set<TsNode>>): void {
  if (!typescriptSyntax.isVariableDeclarationList(node) || (node.flags & typescriptSyntax.NodeFlags.BlockScoped)) return;
  for (const [callee, shadowedScopes] of bindings) {
    if (variableDeclarationListBindsName(node, callee.split(".", 1)[0] ?? "")) shadowedScopes.add(scope);
  }
}

// Normalize assignment target node from parsedSource to a reader call spelling, unwrapping parentheses and string-literal element access.
// Return dotted property text, or undefined for other target shapes that cannot supply a reader-method spelling.
function writtenFileReadCallee(node: TsNode, parsedSource: TsSourceFile): string | undefined {
  if (typescriptSyntax.isParenthesizedExpression(node)) return writtenFileReadCallee(node.expression, parsedSource);
  if (typescriptSyntax.isPropertyAccessExpression(node)) return node.getText(parsedSource);
  if (typescriptSyntax.isElementAccessExpression(node) && typescriptSyntax.isStringLiteral(node.argumentExpression)) {
    return `${node.expression.getText(parsedSource)}.${node.argumentExpression.text}`;
  }
  return undefined;
}

// Return whether node's use of callee is hidden by a lexical binding, a scope recorded in bindings, or a named class expression.
// callee is the imported reader's call spelling; bindings supplies hoisted shadowing scopes. A missing entry adds no hoisted evidence.
// These extra guards apply to reader exemptions; redirect matching uses the common lexical checks.
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

// Return local redirect call names imported by parsedSource from supported frameworks; an empty set means no matching runtime import.
// Named imports contribute local aliases and namespace imports contribute their redirect member; unrelated and type-only bindings are ignored.
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

// Return whether import-source text moduleName belongs to the supported framework redirect allowlist.
// Recognize next/navigation, React Router's core and DOM packages, and the listed Remix runtime packages to exclude unrelated redirect helpers.
function isFrameworkRedirectModule(moduleName: string): boolean {
  return moduleName === "next/navigation" ||
    /^react-router(?:-dom)?$/.test(moduleName) ||
    /^@remix-run\/(?:node|cloudflare|deno|server-runtime)$/.test(moduleName);
}

// Records the local alias each binding style gives the framework redirect export: the member
// path for a namespace import, the (possibly renamed) local name for named imports.
// Returns nothing and adds redirect aliases from namedBindings to callees in place, skipping named specifiers marked type-only.
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

// Returns nothing. Updates tainted for declarations or identifier assignments in node, using parsedSource for text and line positions.
// tainted holds local provenance. Clear an assignment's entry when its new value has no source. Function initializers add no record.
// fileReads masks proven reader calls and enables depth-bounded compound alias lookup. Without it, alias lookup uses bare identifiers.
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

// Returns nothing. Records provenance from node's initializer in parsedSource for each identifier bound by the declaration.
// tainted is updated in place, including nested destructuring; missing initializers or untainted values leave existing entries unchanged.
// fileReads masks proven reader calls and enables compound aliases. Destructured names share one record regardless of keys or defaults.
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

// Derive provenance for expression in parsedSource from direct sources or bounded aliases already held in tainted.
// fileReads optionally masks reader calls and enables compound-value alias searches; successful alias propagation increments its depth.
// Return a direct record at depth 1 or an incremented alias record; return undefined when neither is eligible, including function values.
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

// Returns nothing. Writes record into tainted for every identifier bound by name, including nested object and array destructuring.
// name is the binding pattern and record is its shared source provenance; array holes are ignored and tainted is mutated in place.
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

// Inspect declaration node in parsedSource for XMLParser with processEntities: true or DOMParser with resolveEntity in the constructor text.
// Returns nothing. Adds matching local names to unsafeXmlParsers in place for later XXE sink checks.
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
  findings.push(flowFinding(file, sinkLine, sink.ruleId, sink.sinkKind, hit.kind, hit.depth));
}

// Return whether callee's root name is rebound around call by a parameter, local value declaration, loop binding or catch binding.
// call is the use site and callee is its source spelling; scan ancestors below the source file, returning false for an empty root.
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

// Return whether function-like node binds identifier name through a parameter or its own function declaration or expression name.
// Methods and accessors contribute only parameter bindings: their property names do not hide imported functions.
// Non-function nodes return false.
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

// Block-level value declarations shadow an import across the whole lexical block, including its
// temporal-dead-zone prefix. Case clauses carry their own direct statement list.
function lexicalStatementsBindName(node: TsNode, name: string): boolean {
  if (typescriptSyntax.isBlock(node) || typescriptSyntax.isModuleBlock(node) || typescriptSyntax.isCaseClause(node) || typescriptSyntax.isDefaultClause(node)) {
    return node.statements.some((statement) => statementBindsName(statement, name));
  }
  return false;
}

// Return whether loop or catch node binds identifier name in its catch variable or variable-declaration initializer.
// Missing catch variables, non-declaration loop initializers and other node kinds return false.
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

// Only runtime declarations count: type-only declarations do not shadow an imported value.
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

// Return whether any declaration in list binds identifier name, including nested destructuring, for import-shadow checks.
function variableDeclarationListBindsName(list: import("typescript").VariableDeclarationList, name: string): boolean {
  return list.declarations.some((declaration) => bindingNameContains(declaration.name, name));
}

// Return whether bindingName declares the local identifier name, including nested object and array destructuring.
// Property keys and omitted array elements are ignored; an empty binding pattern returns false.
function bindingNameContains(bindingName: import("typescript").BindingName, name: string): boolean {
  if (typescriptSyntax.isIdentifier(bindingName)) {
    return bindingName.text === name;
  }
  return bindingName.elements.some((element) =>
    !typescriptSyntax.isOmittedExpression(element) && bindingNameContains(element.name, name),
  );
}

// Check node in parsedSource for a location.href or window.location.href assignment with a direct source or a tracked value from tainted.
// Same-line invariant: skip these hits here. The legacy scanner looks for direct source tokens in the sink segment.
// Returns nothing. Appends a finding for the source file to the supplied findings list when a cross-line match qualifies.
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

// Return node unchanged when it is a call or constructor expression, or undefined when it is neither.
// Both forms can be dynamic-regexp sinks, so the syntax-only pass handles them through the same interface.
function callLikeExpression(node: TsNode): TsCallLikeExpression | undefined {
  return typescriptSyntax.isCallExpression(node) || typescriptSyntax.isNewExpression(node) ? node : undefined;
}

// Search call's arguments in order using parsedSource and local provenance in tainted; return the first source record found.
// The walk prunes functions and sanitizer calls. Supplying fileReads also masks proven reader calls and excludes property-key aliases.
// Return undefined for absent arguments or no match. Direct-source checks can still see pruned function or sanitizer text in an ancestor.
function taintedInput(call: TsCallLikeExpression, parsedSource: TsSourceFile, tainted: Map<string, TaintRecord>, fileReads?: FileReadBindings): TaintRecord | undefined {
  for (const argument of call.arguments ?? []) {
    const found = taintedExpression(argument, parsedSource, tainted, fileReads);
    if (found) {
      return found;
    }
  }
  return undefined;
}

// Search expression in parsedSource for direct sources or records in tainted. maxAliasDepth limits alias records only.
// The walk prunes functions and sanitizer calls. Direct-source checks can still see their text because they scan ancestor text.
// With fileReads, skip proven reader calls and exclude property-key aliases. Return the first eligible record, or undefined if none qualifies.
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

// Look up identifier node in tainted and return its source record only when its depth does not exceed maxAliasDepth.
// contentOnly excludes property-access names and identifier keys on property assignments so that key spelling cannot stand in for a local value.
// Return undefined for non-identifiers, excluded keys, unknown locals or records beyond the depth limit.
function taintedIdentifierRecord(node: TsNode, tainted: Map<string, TaintRecord>, maxAliasDepth: number, contentOnly: boolean): TaintRecord | undefined {
  if (!typescriptSyntax.isIdentifier(node)) return undefined;
  const propertyKey = isPropertyAccessName(node) || (typescriptSyntax.isPropertyAssignment(node.parent) && node.parent.name === node);
  if (contentOnly && propertyKey) return undefined;
  const record = tainted.get(node.text);
  return record && record.depth <= maxAliasDepth ? record : undefined;
}

// Return whether callee's source spelling identifies a supported deserialization or dynamic-code sink for call.
// call supplies arguments and parsedSource supplies their text for YAML schema checks; safe-schema YAML loads and other names return false.
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

// Return whether callee names a recognized YAML load call whose second argument in call lacks safe-schema text.
// parsedSource supplies the option text; other callees return false, and missing options make a recognized load unsafe.
function isUnsafeYamlLoad(callee: string, call: TsCallLikeExpression, parsedSource: TsSourceFile): boolean {
  if (!/^(?:yaml|YAML|jsYaml|jsyaml)\.load$/.test(callee)) {
    return false;
  }
  return !hasSafeYamlSchema(call, parsedSource);
}

// Return whether call's second argument text in parsedSource contains schema: followed by FAILSAFE_SCHEMA, JSON_SCHEMA or CORE_SCHEMA.
// The text match accepts an optional qualifier and can also match nested, quoted, or commented text.
// Missing options return false, so the YAML load receives no safe-schema exemption.
function hasSafeYamlSchema(call: TsCallLikeExpression, parsedSource: TsSourceFile): boolean {
  const options = call.arguments?.[1];
  return options !== undefined && /\bschema\s*:\s*(?:[A-Za-z_$][A-Za-z0-9_$]*\.)?(?:FAILSAFE_SCHEMA|JSON_SCHEMA|CORE_SCHEMA)\b/.test(options.getText(parsedSource));
}

// Check callee text and call options for XXE sink syntax, using unsafeXmlParsers for locals initialized by flagged parser constructions.
// Return true for flagged libxml options, recorded parser methods or inline unsafe parser constructions; otherwise return false.
function isXxeSink(callee: string, call: TsCallLikeExpression, unsafeXmlParsers: ReadonlySet<string>): boolean {
  const parserMethod = callee.match(/^([A-Za-z_$][A-Za-z0-9_$]*)\.(?:parse|parseFromString)$/);
  return (
    (isLibxmlEntityExpandingCall(callee) && hasUnsafeXmlParserOption(call)) ||
    (parserMethod !== null && unsafeXmlParsers.has(parserMethod[1] ?? "")) ||
    isInlineUnsafeXmlParserCall(callee)
  );
}

// Return whether callee names parseXml or parseXmlString, optionally qualified by libxmljs, for subsequent unsafe-option checks.
// A name match alone does not establish entity expansion; the caller checks the call's options.
function isLibxmlEntityExpandingCall(callee: string): boolean {
  return /^(?:libxmljs\.)?(?:parseXml|parseXmlString)$/.test(callee);
}

// Return whether any argument of call contains noent, dtdload or processEntities set to true, or a resolveEntity property.
// Missing arguments return false; these are textual option checks.
function hasUnsafeXmlParserOption(call: TsCallLikeExpression): boolean {
  return (call.arguments ?? []).some((argument) => /\b(?:noent|dtdload|processEntities)\s*:\s*true\b|\bresolveEntity\s*:/.test(argument.getText()));
}

// Return whether callee text matches an inline parser call with entity-expansion option syntax.
// Matches new XMLParser(...).parse with processEntities text starting with true, or new DOMParser(...).parseFromString with resolveEntity.
function isInlineUnsafeXmlParserCall(callee: string): boolean {
  return (
    /\bnew\s+XMLParser\s*\([^)]*\bprocessEntities\s*:\s*true[^)]*\)\.parse$/.test(callee) ||
    /\bnew\s+DOMParser\s*\([^)]*\bresolveEntity\s*:[^)]*\)\.parseFromString$/.test(callee)
  );
}

// Return whether expr is a recognized XML parser construction whose text in parsedSource contains unsafe-option syntax.
// XMLParser forms require processEntities: true; DOMParser forms require a resolveEntity property. Other expressions return false.
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

// Return the first SOURCE_TOKENS kind in expr's text in parsedSource, or undefined for no unmasked match or a recognized sanitizer call.
// String literals and substitution-free templates return undefined. With fileReads, mask proven reads so path taint cannot imply content taint.
// Mask request-like parameter names from nested functions unless immediately invoked. Property access names stay visible.
function sourceKindOf(parsedSource: TsSourceFile, expr: TsNode, fileReads?: FileReadBindings): string | undefined {
  if (isSafeWrapperExpression(parsedSource, expr)) {
    return undefined;
  }
  if (isSourceTextLiteral(expr)) {
    return undefined;
  }
  let text = textOutsideRequestHandlers(parsedSource, expr);
  if (fileReads?.size) {
    const start = expr.getStart(parsedSource);
    walk(expr, (node) => {
      if (!isImportedFileRead(node, parsedSource, fileReads)) return;
      const from = node.getStart(parsedSource) - start;
      const endOffset = node.getEnd() - start;
      text = text.slice(0, from) + " ".repeat(endOffset - from) + text.slice(endOffset);
      return false;
    });
  }
  for (const token of SOURCE_TOKENS) {
    if (token.pattern.test(text)) {
      return token.kind;
    }
  }
  return undefined;
}

// Returns the text of expr from its owning parsedSource, masking nested handler request names to preserve offsets.
// The mask matches identifiers named by req, request or ctx parameters and leaves property names after a dot visible.
// A function called in place, as in (() => req.query.path)(), starts no handler mask because its result contributes to the value.
function textOutsideRequestHandlers(parsedSource: TsSourceFile, expr: TsNode): string {
  const expressionStart = expr.getStart(parsedSource);
  let text = expr.getText(parsedSource);
  walk(expr, (node) => {
    if (node === expr || !isFunctionLike(node) || isImmediatelyInvoked(node)) {
      return;
    }
    const declaredNames = declaredRequestParameterNames(node);
    if (declaredNames.size === 0) {
      return;
    }
    walk(node, (inner) => {
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

// Returns the function-like node's direct identifier parameters named req, request or ctx for the scanner's name-based filter.
// An empty set means the scanner skips blanking for this function.
function declaredRequestParameterNames(node: TsNode): Set<string> {
  const { parameters } = node as import("typescript").SignatureDeclaration;
  return new Set(parameters.flatMap((parameter) => (typescriptSyntax.isIdentifier(parameter.name) && REQUEST_RECEIVER_NAMES.has(parameter.name.text) ? [parameter.name.text] : [])));
}

// True when a function is called where it is written, through any parentheses, as in ((req) => req.query.path)(req).
function isImmediatelyInvoked(node: TsNode): boolean {
  let callee = node;
  while (typescriptSyntax.isParenthesizedExpression(callee.parent)) {
    callee = callee.parent;
  }
  return typescriptSyntax.isCallExpression(callee.parent) && callee.parent.expression === callee;
}

// Returns true when the identifier names a property in a dotted access such as this.req, where req reads no local binding.
function isPropertyAccessName(identifier: TsNode): boolean {
  return typescriptSyntax.isPropertyAccessExpression(identifier.parent) && identifier.parent.name === identifier;
}

// Return whether expr is a string literal or substitution-free template literal, which source classification treats as literal text.
// Other expressions return false, including templates that interpolate values.
function isSourceTextLiteral(expr: TsNode): boolean {
  return typescriptSyntax.isStringLiteral(expr) || typescriptSyntax.isNoSubstitutionTemplateLiteral(expr);
}

// Return whether expr is a call to a recognized regexp-escaping helper, using parsedSource to read its callee.
// Callers treat a match as sanitizer evidence and skip its argument subtree; non-calls and other names return false.
function isSafeWrapperExpression(parsedSource: TsSourceFile, expr: TsNode): boolean {
  if (!typescriptSyntax.isCallExpression(expr)) {
    return false;
  }
  const callee = expr.expression.getText(parsedSource);
  return /^(?:escapeRegExp|escapeStringRegexp|regexpEscape|RegExp\.escape)$/.test(callee);
}

// Return whether node is a function-like AST boundary that receives separate taint analysis.
// Recognize functions, arrows, methods, constructors and accessors; other nodes return false.
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
 * @returns a medium-confidence security warning on the one-based sink line, with the rule's own message and remediation or generic cross-line text
 */
function flowFinding(file: SourceFile, lineIndex: number, ruleId: string, sinkKind: string, sourceKind: string, flowDepth: number): Finding {
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
    metadata: { sourceKind, sinkKind, flowDepth },
  });
}

// Supplies messages/remediation for both same-line rule ids and AST-only security candidates.
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
