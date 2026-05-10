import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { chdir, cwd } from "node:process";
import test from "node:test";
import { analyse, renderReport } from "./cli.ts";

test("analysis finds core TypeScript smells", () => {
  const dir = mkdtempSync(join(tmpdir(), "gruff-ts-"));
  const previous = cwd();
  try {
    writeFileSync(
      join(dir, "bad.ts"),
      `export class Bad {
  public name = "demo";
  public process(a: boolean, b: string[], c: string, d: string, e: string, f: string): void {
    if (a) {
      eval(c);
    }
    console.log(b, d, e, f);
  }
}

test("sleeps without assertion", async () => {
  await new Promise((resolve) => setTimeout(resolve, 1));
});
`,
    );
    chdir(dir);
    const report = analyse({
      paths: ["."],
      noConfig: true,
      format: "json",
      failOn: "none",
      includeIgnored: false,
      noBaseline: true,
    });
    const ruleIds = new Set(report.findings.map((finding) => finding.ruleId));
    assert.equal(ruleIds.has("security.eval-call"), true);
    assert.equal(ruleIds.has("size.parameter-count"), true);
    assert.equal(ruleIds.has("test-quality.no-assertions"), true);
    assert.equal(ruleIds.has("modernisation.public-property"), true);
  } finally {
    chdir(previous);
    rmSync(dir, { recursive: true, force: true });
  }
});

test("json report uses schema version", () => {
  const report = analyse({
    paths: [],
    noConfig: true,
    format: "json",
    failOn: "none",
    includeIgnored: false,
    noBaseline: true,
  });
  const rendered = renderReport(report, "json");
  assert.match(rendered, /"schemaVersion": "gruff\.analysis\.v1"/);
});
