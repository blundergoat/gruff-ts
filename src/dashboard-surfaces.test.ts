// Dashboard surface tests covering loopback safety, escaped controls, and secret redaction.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fetchText, URL_CREDENTIAL_FIXTURE_VALUE, withDashboard } from "./test-fixtures.ts";

test("dashboard root uses parity shell and escapes controls", async () => {
  const projectRoot = mkdtempSync(join(tmpdir(), "gruff-ts-dashboard-<bad>-"));
  try {
    writeFileSync(join(projectRoot, "sample.ts"), `export function sample(): string {
  return "ok";
}
`);
    await withDashboard(projectRoot, async (baseUrl) => {
      const rootHtml = await fetchText(`${baseUrl}/?projectRoot=${encodeURIComponent(projectRoot)}&path=sample.ts`);
      ["controls-toggle", "controls-panel", "report-frame", "scan-form"].forEach((anchor) => {
        assert.match(rootHtml, new RegExp(`class="${anchor}`));
      });
      assert.match(rootHtml, /Project root/);
      assert.match(rootHtml, /Paths/);
      assert.match(rootHtml, /&lt;bad&gt;/);
      assert.match(rootHtml, /src="\/scan\?projectRoot=/);
      assert.equal(rootHtml.includes("<bad>"), false);
    });
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
});

test("dashboard scan returns report shell with escaped dashboard context", async () => {
  const projectRoot = mkdtempSync(join(tmpdir(), "gruff-ts-dashboard-<bad>-"));
  try {
    writeFileSync(join(projectRoot, "sample.ts"), `export function sample(): string {
  return "ok";
}
`);
    await withDashboard(projectRoot, async (baseUrl) => {
      const scanHtml = await fetchText(`${baseUrl}/scan?projectRoot=${encodeURIComponent(projectRoot)}&path=sample.ts`);
      assert.match(scanHtml, /class="paper"/);
      assert.match(scanHtml, /class="dashboard-context"/);
      assert.match(scanHtml, /Project root/);
      assert.match(scanHtml, /sample\.ts/);
      assert.match(scanHtml, /&lt;bad&gt;/);
      assert.equal(scanHtml.includes("<bad>"), false);
    });
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
});

test("dashboard scan redacts sensitive findings without leaking raw secrets", async () => {
  const projectRoot = mkdtempSync(join(tmpdir(), "gruff-ts-dashboard-secret-"));
  try {
    writeFileSync(join(projectRoot, ".env"), `REMOTE_CONTROL_URL=${URL_CREDENTIAL_FIXTURE_VALUE}\n`);
    await withDashboard(projectRoot, async (baseUrl) => {
      const scanHtml = await fetchText(`${baseUrl}/scan?projectRoot=${encodeURIComponent(projectRoot)}&path=.env`);
      assert.match(scanHtml, /sensitive-data\.database-url-password/);
      assert.match(scanHtml, /redacted/);
      assert.equal(scanHtml.includes(URL_CREDENTIAL_FIXTURE_VALUE), false);
      assert.equal(scanHtml.includes("clientSecret42"), false);
    });
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
});

test("dashboard rejects non-loopback hosts", () => {
  const result = spawnSync("./bin/gruff-ts", ["dashboard", "--host", "0.0.0.0", "--port", "0"], { encoding: "utf8" });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Dashboard host must be 127\.0\.0\.1 or localhost/);
});
