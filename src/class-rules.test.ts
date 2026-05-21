// Smoke coverage for class-rules; behavioural coverage lives in naming-rules.test.ts and cli.test.ts.
import assert from "node:assert/strict";
import test from "node:test";
import * as classRules from "./class-rules.ts";

test("class-rules module loads its public surface", () => {
  assert.equal(typeof classRules.collectDeclaredIdentifiers, "function");
});
