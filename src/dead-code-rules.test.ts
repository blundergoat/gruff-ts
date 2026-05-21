// Smoke coverage for dead-code-rules; behavioural coverage lives in cli.test.ts.
import assert from "node:assert/strict";
import test from "node:test";
import * as deadCodeRules from "./dead-code-rules.ts";

test("dead-code-rules module loads its public surface", () => {
  assert.equal(typeof deadCodeRules.analyseDeadCode, "function");
});
