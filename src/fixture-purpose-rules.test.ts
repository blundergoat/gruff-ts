// Smoke coverage for fixture-purpose-rules; behavioural coverage lives in docs-comment-rules.test.ts.
import assert from "node:assert/strict";
import test from "node:test";
import * as fixturePurposeRules from "./fixture-purpose-rules.ts";

test("fixture-purpose-rules module loads its public surface", () => {
  assert.equal(typeof fixturePurposeRules.pushFixturePurposeFindings, "function");
});
