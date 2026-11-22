// Checks which project settings survive regeneration when a user runs `init --force`.
//
// Valid ignored paths, command gates, and sensitive exclusions carry forward from older files.
// An invalid entry is left behind so the regenerated config can load and the user's other choices survive.
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { extractPreservedConfigFields } from "./config-preservation.ts";

// Creates a temporary project directory and passes its path to the scenario callback so writes stay isolated between tests.
// Returns nothing. It attempts to remove the whole directory even if the callback throws.
function withTempProjectRoot(action: (path: string) => void): void {
  const projectRoot = mkdtempSync(join(tmpdir(), "gruff-config-preservation-"));
  try {
    action(projectRoot);
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
}

test("extractPreservedConfigFields reads paths.ignore from a pre-schemaVersion YAML config", () => {
  withTempProjectRoot((projectRoot) => {
    const configPath = join(projectRoot, ".gruff-ts.yaml");
    writeFileSync(configPath, "paths:\n  ignore:\n    - \"legacy/**\"\n    - \"vendored/**\"\n");

    const preserved = extractPreservedConfigFields(configPath);

    assert.deepEqual(preserved.ignoredPaths, ["legacy/**", "vendored/**"]);
    assert.equal(preserved.failOn.size, 0);
  });
});

test("extractPreservedConfigFields preserves valid gate entries under either spelling and drops the rest", () => {
  withTempProjectRoot((projectRoot) => {
    const configPath = join(projectRoot, ".gruff-ts.yaml");
    writeFileSync(configPath, "minimumSeverity:\n  analyse: warning\n  summary: garbage\n  dashboard: error\n  report: none\n");

    const preserved = extractPreservedConfigFields(configPath);

    assert.equal(preserved.failOn.get("analyse"), "warning");
    assert.equal(preserved.failOn.get("report"), "none");
    assert.equal(preserved.failOn.has("summary"), false);
    assert.equal(preserved.failOn.has("dashboard" as never), false);

    // A 0.6.0 file spells the same block failOn, and a file carrying both is read from the current key.
    writeFileSync(configPath, "failOn:\n  analyse: error\nminimumSeverity: warning\n");
    assert.equal(extractPreservedConfigFields(configPath).failOn.get("analyse"), "error");
  });
});

test("extractPreservedConfigFields returns empty fields for an empty config file", () => {
  withTempProjectRoot((projectRoot) => {
    const configPath = join(projectRoot, ".gruff-ts.yaml");
    writeFileSync(configPath, "rules: {}\n");

    const preserved = extractPreservedConfigFields(configPath);

    assert.deepEqual(preserved.ignoredPaths, []);
    assert.equal(preserved.failOn.size, 0);
  });
});

// Proves the carry-over bundle keeps every well-formed reviewed suppression, including the optional
// symbol, and drops an entry missing a required field so the strict parser reports it at load time.
// Writes a `.gruff-ts.yaml` into a temporary project root and removes that root afterwards.
test("extractPreservedConfigFields carries reviewed sensitive exclusions through regeneration", () => {
  withTempProjectRoot((projectRoot) => {
    const configPath = join(projectRoot, ".gruff-ts.yaml");
    writeFileSync(
      configPath,
      [
        "sensitiveExclusions:",
        "  - rule: sensitive-data.aws-access-key",
        "    path: src/fixtures/sample.ts",
        "    reason: Synthetic key used by the loader fixture.",
        "  - rule: sensitive-data.jwt-token",
        "    path: src/fixtures/token.ts",
        "    symbol: Fixtures.sessionToken",
        "    reason: Synthetic token used by the session fixture.",
        "  - rule: sensitive-data.private-key",
        "    path: src/fixtures/key.ts",
        "  - rule: sensitive-data.aws-access-key",
        "    path: src/fixtures/scoped.ts",
        "    symbol: 123",
        "    reason: An invalid symbol must never become a file-wide exclusion.",
        "",
      ].join("\n"),
    );

    const preserved = extractPreservedConfigFields(configPath);

    assert.equal(preserved.sensitiveExclusions.length, 2);
    assert.deepEqual(preserved.sensitiveExclusions[0], {
      rule: "sensitive-data.aws-access-key",
      path: "src/fixtures/sample.ts",
      reason: "Synthetic key used by the loader fixture.",
    });
    assert.equal(preserved.sensitiveExclusions[1]?.symbol, "Fixtures.sessionToken");
  });
});
