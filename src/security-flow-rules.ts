// Conservative source-to-sink security candidates. These are deliberately same-line checks: they
// report only when an external-input token is visibly inside a known risky sink expression.
import type { SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import type { Finding } from "./types.ts";

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
