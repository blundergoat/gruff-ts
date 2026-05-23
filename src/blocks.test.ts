// Smoke coverage for blocks; behavioural coverage lives in cli.test.ts and test-block-rules.test.ts.
import assert from "node:assert/strict";
import test from "node:test";
import * as blocks from "./blocks.ts";

test("blocks module loads its public surface", () => {
  assert.equal(typeof blocks.functionBlocks, "function");
  assert.equal(typeof blocks.setupLineCount, "function");
});
