// Coverage for security-flow-rules: the same-line module surface plus the
// bounded intra-function AST flow pass. Broader same-line behavioural
// cases also live in security-and-config.test.ts.
import assert from "node:assert/strict";
import test from "node:test";
import { analyseSecurityFlow, analyseSecurityFlowLine } from "./security-flow-rules.ts";
import type { SourceFile } from "./discovery.ts";
import type { Finding } from "./types.ts";

const fileStub = { displayPath: "sample.ts", absolutePath: "/sample.ts", isScript: true } as SourceFile;

function run(source: string): Finding[] {
  const findings: Finding[] = [];
  analyseSecurityFlow(fileStub, source, findings);
  return findings;
}

test("security-flow-rules module loads its public surface", () => {
  assert.equal(typeof analyseSecurityFlowLine, "function");
  assert.equal(typeof analyseSecurityFlow, "function");
});

test("flags external input reaching a filesystem sink across lines", () => {
  const findings = run(
    "function handler(req) {\n  const target = req.query.path;\n  const data = fs.readFile(target);\n  return data;\n}\n",
  );
  assert.ok(findings.some((finding) => finding.ruleId === "security.path-traversal-candidate"));
});

test("flags external input reaching a network sink across lines", () => {
  const findings = run(
    "async function proxy(req) {\n  const url = req.query.url;\n  return fetch(url);\n}\n",
  );
  assert.ok(findings.some((finding) => finding.ruleId === "security.ssrf-candidate"));
});

test("follows a single alias hop", () => {
  const findings = run(
    "function handler(req) {\n  const raw = req.params.id;\n  const id = raw;\n  return fs.readFileSync(id);\n}\n",
  );
  assert.ok(findings.some((finding) => finding.ruleId === "security.path-traversal-candidate"));
});

test("emits bounded flow metadata and never the raw value", () => {
  const findings = run(
    "function handler(req) {\n  const target = req.query.path;\n  return fs.readFile(target);\n}\n",
  );
  const finding = findings.find((entry) => entry.ruleId === "security.path-traversal-candidate");
  assert.ok(finding);
  assert.equal(finding.metadata.sourceKind, "request");
  assert.equal(finding.metadata.sinkKind, "filesystem-path");
  assert.equal(typeof finding.metadata.flowDepth, "number");
  assert.ok(!JSON.stringify(finding).includes("req.query.path"));
});

test("does not flag a literal path routed through a variable", () => {
  const findings = run(
    'function handler() {\n  const target = "./config.json";\n  return fs.readFile(target);\n}\n',
  );
  assert.equal(findings.length, 0);
});

test("leaves same-line flows to the line scanner", () => {
  const findings = run("function handler(req) {\n  return fs.readFile(req.query.path);\n}\n");
  assert.equal(findings.length, 0);
});

test("does not flag a tainted value that never reaches a sink", () => {
  const findings = run(
    "function handler(req) {\n  const target = req.query.path;\n  console.log(target);\n  return target;\n}\n",
  );
  assert.equal(findings.length, 0);
});

test("keeps taint intra-procedural across nested functions", () => {
  const findings = run(
    "function outer(req) {\n  const target = req.query.path;\n  return function inner() {\n    return fs.readFile(target);\n  };\n}\n",
  );
  assert.equal(findings.length, 0);
});

test("returns an array and does not throw on unparseable input", () => {
  const findings = run("function ( { this is not valid <<< ts");
  assert.ok(Array.isArray(findings));
});
