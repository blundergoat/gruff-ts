// Behavioural coverage for shared finding helper predicates.
import { strict as assert } from "node:assert";
import test from "node:test";

import { isCommentedOutCode } from "./findings-helpers.ts";

test("commented-out-code accepts parseable disabled source", () => {
  assert.equal(isCommentedOutCode("// const disabledLegacy = runLegacyPath();"), true);
  assert.equal(isCommentedOutCode("// if (ready) { return run(); }"), true);
  assert.equal(isCommentedOutCode("// runLegacyPath();"), true);
  assert.equal(isCommentedOutCode("// service.reset()"), true);
});

test("commented-out-code ignores prose anchors and section labels", () => {
  assert.equal(isCommentedOutCode("// type: 'both'"), false);
  assert.equal(isCommentedOutCode("// import cycle remains documented here"), false);
  assert.equal(isCommentedOutCode("// for deeply nested files - skip shorthand"), false);
  assert.equal(isCommentedOutCode("// ---------------------------------------------------------------------------"), false);
  assert.equal(isCommentedOutCode("// scanSectionAgainstSnapshot (claim patterns)"), false);
});
