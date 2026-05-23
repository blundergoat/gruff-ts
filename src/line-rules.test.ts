// Smoke coverage for line-rules; behavioural coverage lives in cli.test.ts.
import assert from "node:assert/strict";
import test from "node:test";
import * as lineRules from "./line-rules.ts";

test("line-rules module loads its public surface", () => {
  assert.equal(typeof lineRules.analyseLineRules, "function");
});
