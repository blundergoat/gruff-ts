// Smoke coverage for discovery; behavioural coverage lives in cli.test.ts.
import assert from "node:assert/strict";
import test from "node:test";
import * as discovery from "./discovery.ts";

test("discovery module loads its public surface", () => {
  assert.equal(typeof discovery.discoverSources, "function");
});
