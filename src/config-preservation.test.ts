// Covers the best-effort field extraction used by `gruff-ts init --force` to preserve curated
// `paths.ignore` and `minimumSeverity` entries across a config regeneration, including the
// pre-0.1.2 migration path where the source config lacks a `schemaVersion:` field.
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { extractPreservedConfigFields } from "./config-preservation.ts";

// Provides a disposable project root for each scenario so writes do not leak between tests.
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
    assert.equal(preserved.minimumSeverity.size, 0);
  });
});

test("extractPreservedConfigFields preserves valid minimumSeverity entries and drops the rest", () => {
  withTempProjectRoot((projectRoot) => {
    const configPath = join(projectRoot, ".gruff-ts.yaml");
    writeFileSync(configPath, "minimumSeverity:\n  analyse: warning\n  summary: garbage\n  dashboard: error\n  report: none\n");

    const preserved = extractPreservedConfigFields(configPath);

    assert.equal(preserved.minimumSeverity.get("analyse"), "warning");
    assert.equal(preserved.minimumSeverity.get("report"), "none");
    assert.equal(preserved.minimumSeverity.has("summary"), false);
    assert.equal(preserved.minimumSeverity.has("dashboard" as never), false);
  });
});

test("extractPreservedConfigFields returns empty fields for an empty config file", () => {
  withTempProjectRoot((projectRoot) => {
    const configPath = join(projectRoot, ".gruff-ts.yaml");
    writeFileSync(configPath, "rules: {}\n");

    const preserved = extractPreservedConfigFields(configPath);

    assert.deepEqual(preserved.ignoredPaths, []);
    assert.equal(preserved.minimumSeverity.size, 0);
  });
});
