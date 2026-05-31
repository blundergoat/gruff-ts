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
function lineIndexOf(sf: TsSourceFile, node: TsNode): number {
  return sf.getLineAndCharacterOfPosition(node.getStart(sf)).line;
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

// AST sink matchers for the two flow rules upgraded in this slice. `callee` is
// the source text of the call's callee expression (e.g. "fs.readFile",
// "axios.get"); the patterns mirror the same-line callPattern sinks above.
const AST_FLOW_SINKS: ReadonlyArray<{ ruleId: string; sinkKind: string; isSink: (callee: string) => boolean }> = [
  {
    ruleId: "security.path-traversal-candidate",
    sinkKind: "filesystem-path",
    isSink: (callee) =>
      /(?:^|\.)(?:readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|createReadStream|createWriteStream|stat|statSync|readdir|readdirSync|unlink|unlinkSync|rm|rmSync|mkdir|mkdirSync)$/.test(
        callee,
      ),
  },
  {
    ruleId: "security.ssrf-candidate",
    sinkKind: "network-request",
    isSink: (callee) =>
      /(?:^|\.)fetch$/.test(callee) ||
      /^axios\.(?:get|post|put|patch|delete|request)$/.test(callee) ||
      /^https?\.(?:request|get)$/.test(callee),
  },
];

const MAX_ALIAS_DEPTH = 2;
const MAX_SCOPE_NODES = 4000;

/**
 * Per-file AST pass. Parses the file once (syntax-only) and reports cross-line
 * source-to-sink flows for the existing security-flow rule ids. Does nothing
 * when the file cannot be parsed, so the same-line scan remains the fallback.
 */
export function analyseSecurityFlow(file: SourceFile, source: string, findings: Finding[]): void {
  const sf = getSourceFile(file, source);
  if (!sf) {
    return;
  }
  // Collect into a local buffer so an error-recovery tree (where node.getText or
  // node.getStart can throw) degrades to "no AST findings" without leaking a
  // partial result. The same-line scan remains the fallback for such files.
  const flowFindings: Finding[] = [];
  try {
    const scopes: TsNode[] = [sf];
    walk(sf, (node) => {
      if (isFunctionLike(node)) {
        scopes.push(node);
      }
    });
    for (const scope of scopes) {
      analyseFlowScope(sf, scope, file, flowFindings);
    }
  } catch {
    return;
  }
  for (const flow of flowFindings) {
    findings.push(flow);
  }
}

// Walks one function (or the module top level), pruning nested functions so taint
// stays intra-procedural. Records tainted locals in source order, then flags
// sinks that consume them on a later line.
function analyseFlowScope(sf: TsSourceFile, scopeOwner: TsNode, file: SourceFile, findings: Finding[]): void {
  const tainted = new Map<string, TaintRecord>();
  let budget = MAX_SCOPE_NODES;
  walk(scopeOwner, (node) => {
    if (budget <= 0) {
      return false;
    }
    budget -= 1;
    if (isFunctionLike(node) && node !== scopeOwner) {
      return false;
    }
    recordTaint(sf, node, tainted);
    reportSink(sf, node, tainted, file, findings);
    return;
  });
}

// Marks a local tainted when it is initialised directly from an external source,
// or one hop from another tainted local (`const alias = tainted`), bounded by
// MAX_ALIAS_DEPTH. Function-valued initialisers are skipped so a source token
// inside a callback body never taints the function variable itself.
function recordTaint(sf: TsSourceFile, node: TsNode, tainted: Map<string, TaintRecord>): void {
  if (!ts.isVariableDeclaration(node) || !ts.isIdentifier(node.name) || !node.initializer) {
    return;
  }
  const initializer = node.initializer;
  if (isFunctionLike(initializer)) {
    return;
  }
  const kind = sourceKindOf(sf, initializer);
  if (kind !== undefined) {
    tainted.set(node.name.text, { line: lineIndexOf(sf, node), kind, depth: 1 });
    return;
  }
  if (ts.isIdentifier(initializer)) {
    const upstream = tainted.get(initializer.text);
    if (upstream && upstream.depth < MAX_ALIAS_DEPTH) {
      tainted.set(node.name.text, { line: upstream.line, kind: upstream.kind, depth: upstream.depth + 1 });
    }
  }
}

// Emits a finding when a sink call consumes a tainted local on a different line
// than its source. Same-line flows are left to analyseSecurityFlowLine.
function reportSink(sf: TsSourceFile, node: TsNode, tainted: Map<string, TaintRecord>, file: SourceFile, findings: Finding[]): void {
  if (!ts.isCallExpression(node)) {
    return;
  }
  const callee = node.expression.getText(sf);
  const sink = AST_FLOW_SINKS.find((candidate) => candidate.isSink(callee));
  if (!sink) {
    return;
  }
  const hit = taintedArgument(node, tainted);
  if (!hit) {
    return;
  }
  const sinkLine = lineIndexOf(sf, node);
  if (sinkLine === hit.line) {
    return;
  }
  findings.push(flowFinding(file, sinkLine, sink.ruleId, sink.sinkKind, hit.kind, hit.depth));
}

// First tainted identifier appearing anywhere in the call's arguments.
function taintedArgument(call: import("typescript").CallExpression, tainted: Map<string, TaintRecord>): TaintRecord | undefined {
  let found: TaintRecord | undefined;
  for (const argument of call.arguments) {
    walk(argument, (node) => {
      if (found) {
        return false;
      }
      if (ts.isIdentifier(node)) {
        const record = tainted.get(node.text);
        if (record) {
          found = record;
          return false;
        }
      }
      return;
    });
    if (found) {
      return found;
    }
  }
  return undefined;
}

// Classifies an initialiser expression as an external-input source. Mirrors the
// same-line SOURCE_TOKENS patterns, applied to the expression's source text.
function sourceKindOf(sf: TsSourceFile, expr: TsNode): string | undefined {
  const text = expr.getText(sf);
  for (const token of SOURCE_TOKENS) {
    if (token.pattern.test(text)) {
      return token.kind;
    }
  }
  return undefined;
}

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

// Cross-line flow finding. Reuses the same-line rule's message and remediation so
// both detection paths read identically; metadata adds the bounded flowDepth.
function flowFinding(file: SourceFile, lineIndex: number, ruleId: string, sinkKind: string, sourceKind: string, flowDepth: number): Finding {
  const base = SECURITY_FLOW_RULES.find((rule) => rule.ruleId === ruleId);
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
