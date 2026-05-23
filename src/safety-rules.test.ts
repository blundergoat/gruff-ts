// Smoke coverage for safety-rules; behavioural coverage lives in security-and-config.test.ts.
import assert from "node:assert/strict";
import test from "node:test";
import * as safetyRules from "./safety-rules.ts";

test("safety-rules module loads its public surface", () => {
  assert.equal(typeof safetyRules.analyseTypeSafetyLine, "function");
});
