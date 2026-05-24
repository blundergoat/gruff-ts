// CSS discovery and size.stylesheet-length calibration coverage.
import assert from "node:assert/strict";
import test from "node:test";
import { analyseProject } from "./test-fixtures.ts";

test("css discovery picks up stylesheets without running TypeScript-only rules", () => {
  // A small CSS file that would parse-error under the TypeScript pipeline and would trip naming
  // rules if accidentally treated as a script. Discovery must include the file and rule routing
  // must skip every script-only check.
  const report = analyseProject({
    "app.css": `.component { color: red; }
.x { padding: 0; }
`,
  }, { shouldSkipConfig: true });

  assert.equal(report.paths.analysedFiles, 1);
  assert.deepEqual(report.diagnostics, []);
  const cssFindings = report.findings.filter((entry) => entry.filePath === "app.css");
  assert.deepEqual(cssFindings, []);
});

test("size.stylesheet-length fires on CSS files above threshold", () => {
  // Four-line stylesheet with stylesheet-length threshold of 3 must produce one finding anchored
  // at line 1 with the stylesheet-specific message shape.
  const report = analyseProject({
    "big.css": `.a { color: red; }
.b { color: blue; }
.c { color: green; }
.d { color: yellow; }
`,
  }, { config: { rules: { "size.stylesheet-length": { threshold: 3, severity: "warning" } } } });

  const stylesheetFindings = report.findings.filter((entry) => entry.ruleId === "size.stylesheet-length");
  assert.equal(stylesheetFindings.length, 1);
  assert.equal(stylesheetFindings[0]?.filePath, "big.css");
  assert.equal(stylesheetFindings[0]?.line, 1);
  assert.match(stylesheetFindings[0]?.message ?? "", /Stylesheet has 5 lines, above the threshold of 3\./);
});

test("size.file-length does not double-fire on CSS when stylesheet rule applies", () => {
  // A stylesheet that comfortably exceeds both rule thresholds. Only the CSS-specific rule should
  // fire because size.file-length is gated to skip CSS, otherwise reports would double-count one file.
  const report = analyseProject({
    "big.css": `.a { color: red; }
.b { color: blue; }
.c { color: green; }
.d { color: yellow; }
.e { color: pink; }
`,
  }, { config: { rules: { "size.file-length": { threshold: 2, severity: "warning" }, "size.stylesheet-length": { threshold: 2, severity: "warning" } } } });

  assert.equal(report.findings.some((entry) => entry.ruleId === "size.file-length" && entry.filePath === "big.css"), false);
  assert.equal(report.findings.some((entry) => entry.ruleId === "size.stylesheet-length" && entry.filePath === "big.css"), true);
});
