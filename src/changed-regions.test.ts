// Changed-region parsing tests cover the public option-to-scope boundary near the implementation.
import assert from "node:assert/strict";
import test from "node:test";
import { changedRegionScope } from "./changed-regions.ts";

test("changedRegionScope merges explicit changed ranges", () => {
  const scope = changedRegionScope({
    paths: ["src/app.ts"],
    shouldSkipConfig: true,
    format: "json",
    failOn: "none",
    shouldIncludeIgnored: false,
    changedRanges: "2-4,4,8",
    changedScope: "hunk",
    shouldSkipBaseline: true,
  });

  assert.equal(scope?.mode, "hunk");
  assert.deepEqual(scope?.explicitRanges, [{ start: 2, end: 4 }, { start: 8, end: 8 }]);
});
