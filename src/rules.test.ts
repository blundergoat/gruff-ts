// Smoke coverage for rules; behavioural coverage lives in rule-catalogue.test.ts.
import assert from "node:assert/strict";
import test from "node:test";
import * as rules from "./rules.ts";

test("rules module loads its public surface", () => {
  assert.equal(typeof rules.ruleDescriptors, "function");
});
