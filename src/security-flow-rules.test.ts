// Smoke coverage for security-flow-rules; behavioural coverage lives in security-and-config.test.ts.
import assert from "node:assert/strict";
import test from "node:test";
import * as securityFlowRules from "./security-flow-rules.ts";

test("security-flow-rules module loads its public surface", () => {
  assert.equal(typeof securityFlowRules.analyseSecurityFlowLine, "function");
});
