// Focused false-positive regressions for sensitive-data token classification and private-method
// reference counting. Split from the broad false-positive suite to keep each test file scannable.
import assert from "node:assert/strict";
import test from "node:test";
import { analyseFixture, analyseProject, HIGH_ENTROPY_FIXTURE_VALUE } from "./test-fixtures.ts";

const HIGH_ENTROPY_SECRET_LINE = 4;
const JWT_FIXTURE_LINE = 1;
const MODEL_SECRET_LINE = 3;

test("FP-#46 sensitive-data.high-entropy-string exempts word-segment identifiers, not tokens", () => {
  // Purpose: the three audit shapes (dotted namespace, dotted module path, underscored constant)
  // decompose into dictionary-like word segments and must stay quiet, while the paired real
  // secret value on the last line keeps the detector's coverage proof alive.
  const report = analyseFixture(`const a = "Com.Example2.Services.Authentication.TokenProvider";
const b = "App.Module9.Feature.Sub.Component.Factory.Helper";
const c = "WC_Admin_Reports_Orders_Stats_Data_Store_V2";
const secret = "${HIGH_ENTROPY_FIXTURE_VALUE}";
void a; void b; void c; void secret;
`);
  const findings = report.findings.filter((entry) => entry.ruleId === "sensitive-data.high-entropy-string");
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.line, HIGH_ENTROPY_SECRET_LINE);
});

test("FP-#46b JWT-vs-dotted-identifier distinction: the JWT keeps flagging high-entropy", () => {
  // Purpose: a JWT is dot-separated like a namespace identifier, so the word-segment exemption
  // must reject it via the token guard. Both the high-entropy and jwt-token findings stay.
  const jwt = ["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjMifQ", "signature"].join(".");
  const report = analyseFixture(`const webToken = "${jwt}";
const namespacePath = "Com.Example2.Services.Authentication.TokenProvider";
void webToken; void namespacePath;
`);
  const entropyFindings = report.findings.filter((entry) => entry.ruleId === "sensitive-data.high-entropy-string");
  assert.equal(entropyFindings.length, 1);
  assert.equal(entropyFindings[0]?.line, JWT_FIXTURE_LINE);
  assert.equal(report.findings.some((entry) => entry.ruleId === "sensitive-data.jwt-token" && entry.line === JWT_FIXTURE_LINE), true);
});

test("FP-#47 sensitive-data.high-entropy-string exempts alphabet strings and catalog slugs", () => {
  // Purpose: PlantUML/base64 translation alphabets (sequential code-point runs) and mixed-case
  // model-catalog identifiers from the adoption scan stay quiet; a same-alphabet real token
  // without separators keeps flagging as the paired true positive.
  const alphabetTable = ["ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz", "0123456789+/"].join("");
  const digitFirstTable = ["0123456789", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz-_"].join("");
  const report = analyseProject({
    "render.ts": `const table = "${alphabetTable}";
const urlTable = "${digitFirstTable}";
const secret = "${HIGH_ENTROPY_FIXTURE_VALUE}";
void table; void urlTable; void secret;
`,
    "models-api.json": JSON.stringify({
      models: ["deepseek-ai/DeepSeek-R1-Distill-Qwen-32B", "Qwen/Qwen2.5-Coder-32B-Instruct-AWQ"],
    }),
  });
  const findings = report.findings.filter((entry) => entry.ruleId === "sensitive-data.high-entropy-string");
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.filePath, "render.ts");
  assert.equal(findings[0]?.line, MODEL_SECRET_LINE);
});

test("FP-#48 dead-code.unused-private-method counts method references as usage", () => {
  // Purpose: the audit shape - a private method passed as a bare method reference
  // (`items.map(this.double)`) - is real usage and stays quiet, while the genuinely
  // unused sibling in the same class keeps the rule's coverage proof alive.
  const report = analyseFixture(`export class Doubler {
  run(items: number[]): number[] {
    return items.map(this.double);
  }
  private double(n: number): number {
    return n * 2;
  }
  private tripleUnused(n: number): number {
    return n * 3;
  }
}
`);
  const findings = report.findings.filter((entry) => entry.ruleId === "dead-code.unused-private-method");
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.symbol, "tripleUnused");
});

test("FP-#48b dead-code.unused-private-method ignores mentions inside comments and strings", () => {
  // Purpose: the rule counts usage against masked code, so a name appearing only in a comment
  // and a string literal is not usage evidence in either the call count or the reference count.
  const report = analyseFixture(`export class Worker {
  run(): void {
    // halver is documented here but never invoked anywhere
    console.log("halver(2) appears only inside this string");
  }
  private halver(n: number): number {
    return n / 2;
  }
}
`);
  const findings = report.findings.filter((entry) => entry.ruleId === "dead-code.unused-private-method");
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.symbol, "halver");
});

test("FP-#48c dead-code.unused-private-method keeps direct calls quiet", () => {
  // Purpose: existing-behaviour lock-in - a same-file `this.double(n)` call already suppressed
  // the finding before reference counting landed and must keep doing so.
  const report = analyseFixture(`export class Caller {
  run(items: number[]): number[] {
    return items.map((n) => this.double(n));
  }
  private double(n: number): number {
    return n * 2;
  }
}
`);
  assert.equal(report.findings.some((entry) => entry.ruleId === "dead-code.unused-private-method"), false);
});
