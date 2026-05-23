// Smoke coverage for naming-pushers; behavioural coverage lives in naming-rules.test.ts.
import assert from "node:assert/strict";
import test from "node:test";
import * as namingPushers from "./naming-pushers.ts";

test("naming-pushers module loads its public surface", () => {
  assert.equal(typeof namingPushers, "object");
});
