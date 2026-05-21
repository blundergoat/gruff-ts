// Smoke coverage for context-doc-rules; behavioural coverage lives in docs-comment-rules.test.ts.
import assert from "node:assert/strict";
import test from "node:test";
import * as contextDocRules from "./context-doc-rules.ts";

test("context-doc-rules module loads its public surface", () => {
  assert.equal(typeof contextDocRules.pushFunctionContextFindings, "function");
});
