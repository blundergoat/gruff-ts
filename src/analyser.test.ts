// Smoke coverage for analyser; behavioural coverage lives in cli.test.ts and cumulative-fixture.test.ts.
import assert from "node:assert/strict";
import test from "node:test";
import * as analyser from "./analyser.ts";

test("analyser module loads its public surface", () => {
  assert.equal(typeof analyser.analyse, "function");
});
