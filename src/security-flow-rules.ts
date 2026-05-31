// Conservative source-to-sink security candidates. These are deliberately same-line checks: they
// report only when an external-input token is visibly inside a known risky sink expression.
import type { SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import type { Finding } from "./types.ts";
import { createRequire } from "node:module";

// Syntax-only TypeScript/JavaScript parser (ADR-012): ts.createSourceFile only -
// no type checker, program, language service, or emit. Loaded via createRequire
// because typescript ships as CommonJS; usage stays bounded to syntax walking.
const require = createRequire(import.meta.url);
const ts = require("typescript") as typeof import("typescript");

type TsSourceFile = import("typescript").SourceFile;
type TsNode = import("typescript").Node;
type TsCallLikeExpression = import("typescript").CallExpression | import("typescript").NewExpression;

// Parse a discovered script to a syntax-only AST; null on non-parseable input so
// callers fall back to the same-line scan. analyseSecurityFlow is the only caller
// and runs once per file, so there is no cache to go stale.
function getSourceFile(file: SourceFile, source: string): TsSourceFile | null {
  try {
    return ts.createSourceFile(file.displayPath, source, ts.ScriptTarget.Latest, true, scriptKindFor(file.displayPath));
  } catch {
    return null;
  }
}

function scriptKindFor(path: string) {
  if (path.endsWith(".tsx")) return ts.ScriptKind.TSX;
  if (path.endsWith(".jsx")) return ts.ScriptKind.JSX;
  if (path.endsWith(".js") || path.endsWith(".mjs") || path.endsWith(".cjs")) {
    return ts.ScriptKind.JS;
  }
  return ts.ScriptKind.TS;
}

// Depth-first walk; return false from visit to skip a node's children.
function walk(node: TsNode, visit: (node: TsNode) => boolean | void): void {
  if (visit(node) === false) {
    return;
  }
  ts.forEachChild(node, (child) => {
    walk(child, visit);
  });
}

// Zero-based start line of a node, for aligning with 1-based finding lines.
function lineIndexOf(parsedSource: TsSourceFile, node: TsNode): number {
  return parsedSource.getLineAndCharacterOfPosition(node.getStart(parsedSource)).line;
}

// External input token that can be visibly matched on one source line.
interface SourceToken {
  kind: string;
  pattern: RegExp;
}

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
    callPattern: /\b(?:(?:res|reply|response)\.redirect|redirect|(?:location|window\.location)\.(?:assign|replace))\s*\(|\b(?:location|window\.location)\.href\s*=/g,
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

// Returns the first visible external-input token so emitted metadata stays deterministic.
function sourceToken(codeLine: string): SourceToken | undefined {
  return SOURCE_TOKENS.find((source) => source.pattern.test(codeLine));
}

// Confirms the external-input token appears inside the same bounded sink call segment.
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

// Keeps matching on one visible call because multiline dataflow is deliberately out of scope.
function singleLineCallSegment(codeLine: string, callStart: number): string {
  // maxSegmentLength limit: 240 chars covers normal calls while avoiding later same-line matches.
  const maxSegmentLength = 240;
  const segment = codeLine.slice(callStart, callStart + maxSegmentLength);
  const close = segment.indexOf(")");
  return close === -1 ? segment : segment.slice(0, close + 1);
}

// Stable finding contract for source-to-sink rules: medium confidence plus source/sink metadata only.
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

// Bundles the syntax context each sink matcher needs so all text extraction remains anchored
// to the parsed source file instead of raw substrings.
interface AstSinkInput {
  callee: string;
  call: TsCallLikeExpression;
  sourceFile: TsSourceFile;
  unsafeXmlParsers: ReadonlySet<string>;
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
    isSink: ({ callee }) =>
      /^(?:res|reply|response)\.redirect$/.test(callee) ||
      /^redirect$/.test(callee) ||
      /^(?:location|window\.location)\.(?:assign|replace)$/.test(callee),
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
 * Per-file AST pass. Parses the file once (syntax-only) and reports cross-line
 * source-to-sink flows for the existing security-flow rule ids. Does nothing
 * when the file cannot be parsed, so the same-line scan remains the fallback.
 * Invariant: this pass never uses TypeScript type-checking, emit, or schema changes.
 *
 * @param file - discovered script file whose display path anchors emitted fingerprints
 * @param source - full source text to parse with syntax-only TypeScript APIs
 * @param findings - accumulator that receives additional AST flow findings
 */
export function analyseSecurityFlow(file: SourceFile, source: string, findings: Finding[]): void {
  const parsedSource = getSourceFile(file, source);
  if (!parsedSource) {
    return;
  }
  // Collect into a local buffer so an error-recovery tree (where node.getText or
  // node.getStart can throw) degrades to "no AST findings" without leaking a
  // partial result. The same-line scan remains the fallback for such files.
  const flowFindings: Finding[] = [];
  try {
    const scopes: TsNode[] = [parsedSource];
    walk(parsedSource, (node) => {
      if (isFunctionLike(node)) {
        scopes.push(node);
      }
    });
    for (const scope of scopes) {
      analyseFlowScope(parsedSource, scope, file, flowFindings);
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
 * Invariant: nested functions are pruned so captured variables never imply inter-procedural flow.
 *
 * @param parsedSource - syntax tree that owns positions and text extraction
 * @param scopeOwner - top-level source file or function-like node to scan
 * @param file - discovered file used for stable finding locations
 * @param findings - accumulator that receives sink findings for this scope
 */
function analyseFlowScope(parsedSource: TsSourceFile, scopeOwner: TsNode, file: SourceFile, findings: Finding[]): void {
  const tainted = new Map<string, TaintRecord>();
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
    reportSink(parsedSource, node, tainted, unsafeXmlParsers, file, findings);
    return;
  });
}

// Marks a local tainted when it is initialised directly from an external source,
// or one hop from another tainted local (`const alias = tainted`), bounded by
// MAX_ALIAS_DEPTH. Function-valued initialisers are skipped so a source token
// inside a callback body never taints the function variable itself.
function recordTaint(parsedSource: TsSourceFile, node: TsNode, tainted: Map<string, TaintRecord>): void {
  if (ts.isVariableDeclaration(node)) {
    recordVariableTaint(parsedSource, node, tainted);
    return;
  }
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(node.left)) {
    const nextRecord = taintRecordFromExpression(parsedSource, node.right, tainted);
    if (nextRecord) {
      tainted.set(node.left.text, nextRecord);
    } else {
      tainted.delete(node.left.text);
    }
  }
}

// Records taint introduced by declarations, including simple object/array destructuring from
// external-input expressions. Non-identifier binding details are intentionally skipped.
function recordVariableTaint(parsedSource: TsSourceFile, node: import("typescript").VariableDeclaration, tainted: Map<string, TaintRecord>): void {
  if (!node.initializer) {
    return;
  }
  const record = taintRecordFromExpression(parsedSource, node.initializer, tainted);
  if (!record) {
    return;
  }
  if (ts.isIdentifier(node.name)) {
    tainted.set(node.name.text, record);
    return;
  }
  taintBindingNames(node.name, record, tainted);
}

// Derives the bounded taint record for one expression and keeps alias depth deterministic.
function taintRecordFromExpression(parsedSource: TsSourceFile, expression: TsNode, tainted: Map<string, TaintRecord>): TaintRecord | undefined {
  if (isFunctionLike(expression)) {
    return undefined;
  }
  const kind = sourceKindOf(parsedSource, expression);
  if (kind !== undefined) {
    return { line: lineIndexOf(parsedSource, expression), kind, depth: 1 };
  }
  if (!ts.isIdentifier(expression)) {
    return undefined;
  }
  const upstream = tainted.get(expression.text);
  if (upstream?.depth !== undefined && upstream.depth < MAX_ALIAS_DEPTH) {
    return { line: upstream.line, kind: upstream.kind, depth: upstream.depth + 1 };
  }
  return undefined;
}

// Applies one proven source record to each simple identifier in a destructuring pattern.
function taintBindingNames(name: import("typescript").BindingName, record: TaintRecord, tainted: Map<string, TaintRecord>): void {
  if (ts.isIdentifier(name)) {
    tainted.set(name.text, record);
    return;
  }
  for (const element of name.elements) {
    if (ts.isOmittedExpression(element)) {
      continue;
    }
    taintBindingNames(element.name, record, tainted);
  }
}

// Records locals that hold an XML parser configured to expand entities. Later `parser.parse(xml)`
// calls are XXE sinks only for these explicitly unsafe parser instances.
function recordUnsafeXmlParser(parsedSource: TsSourceFile, node: TsNode, unsafeXmlParsers: Set<string>): void {
  if (!ts.isVariableDeclaration(node) || !ts.isIdentifier(node.name) || !node.initializer) {
    return;
  }
  if (isUnsafeXmlParserConstruction(parsedSource, node.initializer)) {
    unsafeXmlParsers.add(node.name.text);
  }
}

// Emits a finding when a sink call consumes a tainted local. Because legacy same-line
// scanners own existing rule ids, same-line AST reports are limited to AST-only rules.
function reportSink(
  parsedSource: TsSourceFile,
  node: TsNode,
  tainted: Map<string, TaintRecord>,
  unsafeXmlParsers: ReadonlySet<string>,
  file: SourceFile,
  findings: Finding[],
): void {
  const call = callLikeExpression(node);
  if (!call) {
    return;
  }
  const callee = call.expression.getText(parsedSource);
  const sink = AST_FLOW_SINKS.find((candidate) => candidate.isSink({ callee, call, sourceFile: parsedSource, unsafeXmlParsers }));
  if (!sink) {
    return;
  }
  const hit = taintedInput(call, parsedSource, tainted);
  if (!hit) {
    return;
  }
  const sinkLine = lineIndexOf(parsedSource, call);
  if (sinkLine === hit.line && sink.shouldReportSameLine !== true) {
    return;
  }
  findings.push(flowFinding(file, sinkLine, sink.ruleId, sink.sinkKind, hit.kind, hit.depth));
}

// Normalises calls and constructors because `RegExp(value)` and `new RegExp(value)`
// are equivalent dynamic-regexp sinks for this syntax-only pass.
function callLikeExpression(node: TsNode): TsCallLikeExpression | undefined {
  return ts.isCallExpression(node) || ts.isNewExpression(node) ? node : undefined;
}

// Finds the first tainted identifier or direct external-input expression in sink arguments.
// Because sanitizer wrappers deliberately consume user input, their subtrees are pruned.
function taintedInput(call: TsCallLikeExpression, parsedSource: TsSourceFile, tainted: Map<string, TaintRecord>): TaintRecord | undefined {
  let found: TaintRecord | undefined;
  for (const argument of call.arguments ?? []) {
    walk(argument, (node) => {
      if (found) {
        return false;
      }
      if (isSafeWrapperExpression(parsedSource, node)) {
        return false;
      }
      if (ts.isIdentifier(node)) {
        const record = tainted.get(node.text);
        if (record) {
          found = record;
          return false;
        }
      }
      const kind = sourceKindOf(parsedSource, node);
      if (kind !== undefined) {
        found = { line: lineIndexOf(parsedSource, node), kind, depth: 0 };
        return false;
      }
      return;
    });
    if (found) {
      return found;
    }
  }
  return undefined;
}

// Unsafe-deserialization sinks execute or inflate attacker-controlled serialized/code content.
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

// js-yaml load is treated as unsafe unless the caller pins a safe schema in the options object.
function isUnsafeYamlLoad(callee: string, call: TsCallLikeExpression, parsedSource: TsSourceFile): boolean {
  if (!/^(?:yaml|YAML|jsYaml|jsyaml)\.load$/.test(callee)) {
    return false;
  }
  return !hasSafeYamlSchema(call, parsedSource);
}

// Safe YAML schema evidence must be local to the load options so the finding is deterministic.
function hasSafeYamlSchema(call: TsCallLikeExpression, parsedSource: TsSourceFile): boolean {
  const options = call.arguments?.[1];
  return options !== undefined && /\bschema\s*:\s*(?:[A-Za-z_$][A-Za-z0-9_$]*\.)?(?:FAILSAFE_SCHEMA|JSON_SCHEMA|CORE_SCHEMA)\b/.test(options.getText(parsedSource));
}

// XXE sinks are XML parser calls whose local syntax explicitly enables entity expansion.
function isXxeSink(callee: string, call: TsCallLikeExpression, unsafeXmlParsers: ReadonlySet<string>): boolean {
  const parserMethod = callee.match(/^([A-Za-z_$][A-Za-z0-9_$]*)\.(?:parse|parseFromString)$/);
  return (
    (isLibxmlEntityExpandingCall(callee) && hasUnsafeXmlParserOption(call)) ||
    (parserMethod !== null && unsafeXmlParsers.has(parserMethod[1] ?? "")) ||
    isInlineUnsafeXmlParserCall(callee)
  );
}

// libxmljs-style APIs expose entity expansion through call options such as `noent: true`.
function isLibxmlEntityExpandingCall(callee: string): boolean {
  return /^(?:libxmljs\.)?(?:parseXml|parseXmlString)$/.test(callee);
}

// Looks for parser options that opt into entity expansion or external DTD loading.
function hasUnsafeXmlParserOption(call: TsCallLikeExpression): boolean {
  return (call.arguments ?? []).some((argument) => /\b(?:noent|dtdload|processEntities)\s*:\s*true\b|\bresolveEntity\s*:/.test(argument.getText()));
}

// Inline `new XMLParser(...).parse(...)` and `new DOMParser(...).parseFromString(...)` keep options
// in the callee expression, so the callee text carries the entity-expansion evidence.
function isInlineUnsafeXmlParserCall(callee: string): boolean {
  return (
    /\bnew\s+XMLParser\s*\([^)]*\bprocessEntities\s*:\s*true[^)]*\)\.parse$/.test(callee) ||
    /\bnew\s+DOMParser\s*\([^)]*\bresolveEntity\s*:[^)]*\)\.parseFromString$/.test(callee)
  );
}

// Parser constructors are considered unsafe only when entity expansion is visibly enabled nearby.
function isUnsafeXmlParserConstruction(parsedSource: TsSourceFile, expr: TsNode): boolean {
  if (!ts.isNewExpression(expr)) {
    return false;
  }
  const callee = expr.expression.getText(parsedSource);
  const text = expr.getText(parsedSource);
  return (
    (/^(?:XMLParser|fastXmlParser\.XMLParser)$/.test(callee) && /\bprocessEntities\s*:\s*true\b/.test(text)) ||
    (/^(?:DOMParser|xmldom\.DOMParser)$/.test(callee) && /\bresolveEntity\s*:/.test(text))
  );
}

// Classifies an initialiser expression as an external-input source. Mirrors the
// same-line SOURCE_TOKENS patterns, applied to the expression's source text.
function sourceKindOf(parsedSource: TsSourceFile, expr: TsNode): string | undefined {
  if (isSafeWrapperExpression(parsedSource, expr)) {
    return undefined;
  }
  const text = expr.getText(parsedSource);
  for (const token of SOURCE_TOKENS) {
    if (token.pattern.test(text)) {
      return token.kind;
    }
  }
  return undefined;
}

// Regex escaping helpers are sanitizer evidence for dynamic-regexp flow; walking their arguments
// would otherwise re-taint an already-escaped pattern value.
function isSafeWrapperExpression(parsedSource: TsSourceFile, expr: TsNode): boolean {
  if (!ts.isCallExpression(expr)) {
    return false;
  }
  const callee = expr.expression.getText(parsedSource);
  return /^(?:escapeRegExp|escapeStringRegexp|regexpEscape|RegExp\.escape)$/.test(callee);
}

// Identifies scope boundaries that must not inherit taint from enclosing functions.
function isFunctionLike(node: TsNode): boolean {
  return (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node) ||
    ts.isConstructorDeclaration(node) ||
    ts.isGetAccessorDeclaration(node) ||
    ts.isSetAccessorDeclaration(node)
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
