// Smoke coverage for comment-rules; behavioural coverage lives in docs-comment-rules.test.ts.
import assert from "node:assert/strict";
import test from "node:test";
import * as commentRules from "./comment-rules.ts";

test("comment-rules module loads its public surface", () => {
  assert.equal(typeof commentRules.analyseCommentQualityRules, "function");
});
