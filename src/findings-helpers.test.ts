// Smoke coverage for findings-helpers; behavioural coverage lives in cli.test.ts.
import assert from "node:assert/strict";
import test from "node:test";
import * as findingsHelpers from "./findings-helpers.ts";

test("findings-helpers module loads its public surface", () => {
  assert.equal(typeof findingsHelpers.escapeRegex, "function");
});
