// Smoke coverage for test-fixtures; the helpers are exercised by every other *.test.ts file.
import assert from "node:assert/strict";
import test from "node:test";
import * as testFixtures from "./test-fixtures.ts";

test("test-fixtures module loads its public surface", () => {
  assert.equal(typeof testFixtures.analyseFixture, "function");
  assert.equal(typeof testFixtures.analyseProject, "function");
});
