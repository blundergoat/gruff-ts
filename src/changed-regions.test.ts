// Changed-region parsing tests cover the public option-to-scope boundary near the implementation.
import assert from "node:assert/strict";
import test from "node:test";
import { changedRegionScope } from "./changed-regions.ts";
import type { AnalysisOptions } from "./types.ts";

const BASE_OPTIONS: AnalysisOptions = {
  paths: ["src/app.ts"],
  shouldSkipConfig: true,
  format: "json",
  failOn: "none",
  shouldIncludeIgnored: false,
  changedScope: "symbol",
  shouldSkipBaseline: true,
};
const CONTEXT_DIFF_PATCH = [
  "diff --git a/src/app.ts b/src/app.ts",
  "--- a/src/app.ts",
  "+++ b/src/app.ts",
  "@@ -10,5 +10,5 @@",
  " context();",
  "-oldValue();",
  "+newValue();",
  " unchanged();",
  "",
].join("\n");
const DELETION_ONLY_DIFF_PATCH = [
  "diff --git a/src/app.ts b/src/app.ts",
  "--- a/src/app.ts",
  "+++ b/src/app.ts",
  "@@ -5,1 +5,0 @@",
  "-oldValue();",
  "",
].join("\n");

test("changedRegionScope merges explicit changed ranges", () => {
  const scope = changedRegionScope({
    ...BASE_OPTIONS,
    changedRanges: "2-4,4,8",
    changedScope: "hunk",
  });

  assert.equal(scope?.mode, "hunk");
  assert.deepEqual(scope?.explicitRanges, [{ start: 2, end: 4 }, { start: 8, end: 8 }]);
});

test("changedRegionScope parses added target lines from context diffs", () => {
  const scope = changedRegionScope({
    ...BASE_OPTIONS,
    diff: "-",
    diffPatch: CONTEXT_DIFF_PATCH,
  });

  assert.deepEqual(scope?.rangesByFile.get("src/app.ts"), [{ start: 11, end: 11 }]);
});

test("changedRegionScope skips deletion-only hunks", () => {
  const scope = changedRegionScope({
    ...BASE_OPTIONS,
    diff: "-",
    diffPatch: DELETION_ONLY_DIFF_PATCH,
  });

  assert.deepEqual(scope?.rangesByFile.get("src/app.ts"), undefined);
});

test("changedRegionScope rejects direct stdin diff calls without a patch body", () => {
  assert.throws(() => changedRegionScope({ ...BASE_OPTIONS, diff: "-" }), /requires diffPatch input/);
});
