// Smoke coverage for comment-scanner; behavioural coverage lives in docs-comment-rules.test.ts.
import assert from "node:assert/strict";
import test from "node:test";
import * as commentScanner from "./comment-scanner.ts";

test("comment-scanner module loads its public surface", () => {
  assert.equal(typeof commentScanner.commentRecords, "function");
});
