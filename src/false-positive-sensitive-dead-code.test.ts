// Focused false-positive regressions for private-method reference counting. Split from the broad
// false-positive suite to keep each test file scannable.
import assert from "node:assert/strict";
import test from "node:test";
import { analyseFixture } from "./test-fixtures.ts";

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

test("FP-#48d dead-code.unused-private-method ignores unrelated receivers sharing the name", () => {
  // Purpose: reference-count usage evidence requires a `this` receiver, so a property access on an
  // unrelated object (`settings.refresh`) must not mask the genuinely unused private `refresh`.
  const report = analyseFixture(`export class Cache {
  run(settings: { refresh: boolean }): boolean {
    return settings.refresh;
  }
  private refresh(): number {
    return 1;
  }
}
`);
  const findings = report.findings.filter((entry) => entry.ruleId === "dead-code.unused-private-method");
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.symbol, "refresh");
});
