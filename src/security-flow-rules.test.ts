// Coverage for security-flow-rules: the same-line module surface plus the
// bounded intra-function AST flow pass. Broader same-line behavioural
// cases also live in security-and-config.test.ts.
import assert from "node:assert/strict";
import test from "node:test";
import { analyseSecurityFlow, analyseSecurityFlowLine } from "./security-flow-rules.ts";
import type { SourceFile } from "./discovery.ts";
import type { Finding } from "./types.ts";

const fileStub = { displayPath: "sample.ts", absolutePath: "/sample.ts", isScript: true } as SourceFile;
const expectedUnsafeDeserializationFindings = 4;
const unsafeDeserializationSource = [
  "function inflate(req) {",
  "  const serialized = req.body.serialized;",
  "  const yamlText = req.body.yaml;",
  "  const code = req.body.code;",
  "  nodeSerialize.unserialize(serialized);",
  "  yaml.load(yamlText);",
  "  vm.runInNewContext(code);",
  "  new Function(code);",
  "}",
  "",
].join("\n");

// Analyse one in-memory source fixture through only the AST flow pass.
// Invariant: these unit tests bypass same-line scanning so flow findings stay isolated.
function analyseSecurityFixture(source: string): Finding[] {
  const findings: Finding[] = [];
  analyseSecurityFlow(fileStub, source, findings);
  return findings;
}

test("security-flow-rules module loads its public surface", () => {
  assert.equal(typeof analyseSecurityFlowLine, "function");
  assert.equal(typeof analyseSecurityFlow, "function");
});

test("flags external input reaching a filesystem sink across lines", () => {
  const findings = analyseSecurityFixture(
    "function handler(req) {\n  const target = req.query.path;\n  const data = fs.readFile(target);\n  return data;\n}\n",
  );
  assert.ok(findings.some((finding) => finding.ruleId === "security.path-traversal-candidate"));
});

test("flags external input reaching a network sink across lines", () => {
  const findings = analyseSecurityFixture(
    "async function proxy(req) {\n  const url = req.query.url;\n  return fetch(url);\n}\n",
  );
  assert.ok(findings.some((finding) => finding.ruleId === "security.ssrf-candidate"));
});

test("flags external input reaching an open redirect sink across lines", () => {
  const findings = analyseSecurityFixture(
    "function login(req, res) {\n  const next = req.query.next;\n  res.redirect(next);\n}\n",
  );
  assert.ok(findings.some((finding) => finding.ruleId === "security.open-redirect-candidate"));
});

test("flags external input reaching a dynamic regular expression sink across lines", () => {
  const findings = analyseSecurityFixture(
    "function filter(req) {\n  const pattern = req.query.pattern;\n  return new RegExp(pattern);\n}\n",
  );
  assert.ok(findings.some((finding) => finding.ruleId === "security.dynamic-regexp"));
});

test("flags RegExp called without new when external input flows across lines", () => {
  const findings = analyseSecurityFixture(
    "function filter() {\n  const pattern = process.argv[2];\n  return RegExp(pattern);\n}\n",
  );
  assert.ok(findings.some((finding) => finding.ruleId === "security.dynamic-regexp"));
});

test("flags external input reaching unsafe deserialization and dynamic code-loading sinks", () => {
  const findings = analyseSecurityFixture(unsafeDeserializationSource);
  const unsafeFindings = findings.filter((finding) => finding.ruleId === "security.unsafe-deserialization");
  assert.equal(unsafeFindings.length, expectedUnsafeDeserializationFindings);
  assert.ok(!JSON.stringify(unsafeFindings).includes("req.body"));
});

test("keeps safe yaml schema and escaped regexp flows quiet", () => {
  const findings = analyseSecurityFixture(
    [
      "function parse(req) {",
      "  const yamlText = req.body.yaml;",
      "  const pattern = escapeRegExp(req.query.pattern);",
      "  yaml.load(yamlText, { schema: yaml.JSON_SCHEMA });",
      "  return new RegExp(pattern);",
      "}",
      "",
    ].join("\n"),
  );
  assert.equal(findings.length, 0);
});

test("flags external XML reaching entity-expanding XML parsers", () => {
  const findings = analyseSecurityFixture(
    [
      "function parse(req) {",
      "  const xmlText = req.body.xml;",
      "  libxmljs.parseXml(xmlText, { noent: true });",
      "  const parser = new XMLParser({ processEntities: true });",
      "  parser.parse(xmlText);",
      "}",
      "",
    ].join("\n"),
  );
  const xxeFindings = findings.filter((finding) => finding.ruleId === "security.xxe-candidate");
  assert.equal(xxeFindings.length, 2);
  assert.ok(!JSON.stringify(xxeFindings).includes("req.body.xml"));
});

test("keeps XML parsers without entity expansion quiet", () => {
  const findings = analyseSecurityFixture(
    [
      "function parse(req) {",
      "  const xmlText = req.body.xml;",
      "  libxmljs.parseXml(xmlText, { noent: false });",
      "  const parser = new XMLParser({ processEntities: false });",
      "  parser.parse(xmlText);",
      "}",
      "",
    ].join("\n"),
  );
  assert.equal(findings.length, 0);
});

test("follows a single alias hop", () => {
  const findings = analyseSecurityFixture(
    "function handler(req) {\n  const raw = req.params.id;\n  const id = raw;\n  return fs.readFileSync(id);\n}\n",
  );
  assert.ok(findings.some((finding) => finding.ruleId === "security.path-traversal-candidate"));
});

test("follows assignments and simple destructuring but clears reassigned locals", () => {
  const assignmentFindings = analyseSecurityFixture(
    "function handler(req) {\n  let target;\n  target = req.query.path;\n  return fs.readFile(target);\n}\n",
  );
  assert.ok(assignmentFindings.some((finding) => finding.ruleId === "security.path-traversal-candidate"));

  const destructuringFindings = analyseSecurityFixture(
    "function handler(req) {\n  const { path } = req.query;\n  return fs.readFile(path);\n}\n",
  );
  assert.ok(destructuringFindings.some((finding) => finding.ruleId === "security.path-traversal-candidate"));

  const clearedFindings = analyseSecurityFixture(
    "function handler(req) {\n  let target = req.query.path;\n  target = './config.json';\n  return fs.readFile(target);\n}\n",
  );
  assert.equal(clearedFindings.length, 0);
});

test("emits bounded flow metadata and never the raw value", () => {
  const findings = analyseSecurityFixture(
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
  const findings = analyseSecurityFixture(
    'function handler() {\n  const target = "./config.json";\n  return fs.readFile(target);\n}\n',
  );
  assert.equal(findings.length, 0);
});

test("leaves same-line flows to the line scanner", () => {
  const findings = analyseSecurityFixture("function handler(req) {\n  return fs.readFile(req.query.path);\n}\n");
  assert.equal(findings.length, 0);
});

test("leaves same-line constructor flows to the line scanner", () => {
  const findings = analyseSecurityFixture("function handler(req) {\n  return new RegExp(req.query.pattern);\n}\n");
  assert.equal(findings.length, 0);
});

test("does not flag a tainted value that never reaches a sink", () => {
  const findings = analyseSecurityFixture(
    "function handler(req) {\n  const target = req.query.path;\n  console.log(target);\n  return target;\n}\n",
  );
  assert.equal(findings.length, 0);
});

test("keeps taint intra-procedural across nested functions", () => {
  const findings = analyseSecurityFixture(
    "function outer(req) {\n  const target = req.query.path;\n  return function inner() {\n    return fs.readFile(target);\n  };\n}\n",
  );
  assert.equal(findings.length, 0);
});

test("returns an array and does not throw on unparseable input", () => {
  const findings = analyseSecurityFixture("function ( { this is not valid <<< ts");
  assert.ok(Array.isArray(findings));
});
