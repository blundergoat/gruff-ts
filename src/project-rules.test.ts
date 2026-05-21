// Smoke coverage for project-rules; behavioural coverage lives in baseline-and-project.test.ts.
import assert from "node:assert/strict";
import test from "node:test";
import * as projectRules from "./project-rules.ts";

test("project-rules module loads its public surface", () => {
  assert.equal(typeof projectRules.buildProjectIndex, "function");
});
