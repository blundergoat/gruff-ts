// Baseline v3 as users meet it: reviewed debt that survives an edit, and secrets that never do.
// The cases here are the family cases, so a reviewed finding stays hidden through line movement while a new
// sibling, a grown count, and every secret stay visible and keep failing the run.
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { existsSync, linkSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { applyBaseline, migrateBaseline, requireOverwritableDefaultPath, writeBaseline } from "./baseline-file.ts";
import { baselineSubject, computeIdentityFor, findingIdentities, normaliseMeasuredValues } from "./baseline-identity.ts";
import type { Finding } from "./types.ts";

// The digests the family case file pins for other ports; reproducing them is the only proof the rule is one rule.
const ORACLE_PINS = [
  { toolLanguage: "rs", ruleId: "docs.missing-readme", path: "src/widget.rs", subject: "process#1", identity: "aff839f0cf33b11e" },
  { toolLanguage: "rs", ruleId: "docs.missing-readme", path: "src/widget.rs", subject: "process#2", identity: "4ab8dc0e1ec4b969" },
  { toolLanguage: "rs", ruleId: "docs.missing-readme", path: "src/widget.rs", subject: "File has no module documentation", identity: "bdb4503a37614a4f" },
  { toolLanguage: "ts", ruleId: "docs.missing-readme", path: "src/widget.rs", subject: "process#1", identity: "caa4bb2431af313d" },
  { toolLanguage: "rs", ruleId: "docs.missing-readme", path: "src/gadget.rs", subject: "process#1", identity: "8f717ea2d0f8af15" },
];

test("identity matches the family oracle", () => {
  for (const pin of ORACLE_PINS) {
    assert.equal(computeIdentityFor(pin.toolLanguage, pin.ruleId, pin.path, pin.subject), pin.identity, `identity for ${pin.toolLanguage} ${pin.subject}`);
  }
});

test("measured values never enter a symbol-less identity", () => {
  assert.equal(normaliseMeasuredValues("File has 1010 lines (limit 1000)"), "File has # lines (limit #)");
  assert.equal(normaliseMeasuredValues("12.5% over 1,234 lines in v0.5.2"), "#% over # lines in v#");
  assert.equal(normaliseMeasuredValues("File has no module documentation"), "File has no module documentation");
});

// A symbol the ordinal separator makes ambiguous is a property of the scanned code, not a failure of the tool.
// gruff-ts used to throw here, uncaught, so one Angular test named after a GitHub issue ended the whole run with
// no output at all. The finding must survive without an identity, exactly as a sensitive finding does.
test("a finding whose own text cannot name it is reported without an identity, and does not end the run", () => {
  const unnameableSymbol = finding({ symbol: "should allow lookahead binding on second pass #35118" });
  const noSymbolNoMessage = finding({ symbol: "", message: "" });

  assert.deepEqual(findingIdentities([unnameableSymbol]), [undefined]);
  assert.deepEqual(findingIdentities([noSymbolNoMessage]), [undefined]);

  // The unnameable finding must not cost its neighbours their identities either.
  const named = finding({ symbol: "process" });
  const identities = findingIdentities([unnameableSymbol, named]);

  assert.equal(identities[0], undefined);
  assert.equal(identities[1]?.subject, "process#1");
});

// The declaration ordinal is this module's own invariant: it ranks a symbol this module already accepted, so
// losing it is a defect here rather than anything the scanned project did. Keeping that one case fatal is why the
// repair above is a narrow return rather than a blanket catch, which would have hidden this contract breaking.
test("a symbol accepted without a declaration ordinal still throws, because that is this module's own defect", () => {
  assert.throws(
    () => baselineSubject(finding({ symbol: "process" }), 0),
    /without a declaration ordinal/u,
  );
});

test("a generated baseline stores one line-free row per identity", () => {
  withProject((dir) => {
    const path = join(dir, "baseline.json");
    writeBaseline(path, [finding()]);
    const document = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;

    assert.equal(document.schemaVersion, "gruff.baseline.v3");
    assert.equal(document.toolLanguage, "ts");
    assert.deepEqual(document.occurrences, [
      { identity: computeIdentityFor("ts", "naming.short", "src/app.ts", "process#1"), count: 1, ruleId: "naming.short", path: "src/app.ts", subject: "process#1" },
    ]);
  });
});

test("a line-shifted finding stays hidden and a new sibling does not", () => {
  withProject((dir) => {
    const path = join(dir, "baseline.json");
    writeBaseline(path, [finding()]);

    const sibling = finding({ symbol: "other", line: 400 });
    const application = applyBaseline(path, [finding({ line: 300 }), sibling]);

    assert.deepEqual(application.findings, [sibling]);
    assert.equal(application.counts.unchanged, 1);
    assert.equal(application.counts.new, 1);
  });
});

test("a second occurrence beyond the reviewed count is new and the lowest line is spent", () => {
  withProject((dir) => {
    const path = join(dir, "baseline.json");
    writeBaseline(path, [finding({ symbol: "", message: "Function has 12 parameters", line: 10 })]);

    // The run is supplied out of order, so a port spending the count in scan order would hide the wrong occurrence.
    const later = finding({ symbol: "", message: "Function has 12 parameters", line: 90 });
    const earlier = finding({ symbol: "", message: "Function has 12 parameters", line: 10 });
    const application = applyBaseline(path, [later, earlier]);

    assert.equal(application.counts.unchanged, 1);
    assert.deepEqual(application.findings, [later]);
  });
});

test("a measured file-level finding survives the file growing", () => {
  withProject((dir) => {
    const path = join(dir, "baseline.json");
    writeBaseline(path, [finding({ symbol: "", message: "File has 1010 lines (limit 1000)", line: 1 })]);

    const application = applyBaseline(path, [finding({ symbol: "", message: "File has 1200 lines (limit 1000)", line: 1 })]);

    assert.equal(application.findings.length, 0);
    assert.equal(application.counts.unchanged, 1);
    assert.equal(application.counts.collision, 0);
  });
});

test("a sensitive finding is never stored and never hidden", () => {
  withProject((dir) => {
    const path = join(dir, "baseline.json");
    const secret = finding({ ruleId: "sensitive-data.high-entropy-string", pillar: "sensitive-data", symbol: "", message: "Possible secret" });
    writeBaseline(path, [secret]);
    const document = JSON.parse(readFileSync(path, "utf8")) as { occurrences: unknown[]; sensitive: { counts: { total: number } } };

    assert.deepEqual(document.occurrences, []);
    assert.equal(document.sensitive.counts.total, 1);

    const application = applyBaseline(path, [secret]);

    assert.deepEqual(application.findings, [secret]);
    assert.equal(application.counts.notEligible, 1);
  });
});

test("a baseline written by another port is refused", () => {
  withProject((dir) => {
    const path = join(dir, "baseline.json");
    writeBaseline(path, [finding()]);
    const document = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
    writeFileSync(path, JSON.stringify({ ...document, toolLanguage: "go" }));

    assert.throws(() => applyBaseline(path, [finding()]), /written by go/u);
  });
});

test("a row that could expire or leak fails the file", () => {
  withProject((dir) => {
    const path = join(dir, "baseline.json");
    writeFileSync(path, JSON.stringify({ schemaVersion: "gruff.baseline.v3", toolLanguage: "ts", occurrences: [{ identity: "0".repeat(16), count: 1, line: 12 }] }));

    assert.throws(() => applyBaseline(path, []), /forbidden key "line"/u);
  });
});

test("a 0.5 baseline fails closed and names the migration command", () => {
  withProject((dir) => {
    writeLegacyInput(dir);

    assert.throws(() => applyBaseline(join(dir, "legacy.json"), [finding()]), /--migrate-baseline/u);
  });
});

test("migration carries reviews forward and leaves its input byte-identical", () => {
  withProject((dir) => {
    const original = writeLegacyInput(dir);
    const outputPath = join(dir, "migrated.json");

    const migration = migrateBaseline(join(dir, "legacy.json"), outputPath, [finding(), finding({ symbol: "unreviewed", line: 400 })]);
    const migrated = JSON.parse(readFileSync(outputPath, "utf8")) as { occurrences: Array<{ identity: string }> };

    assert.equal(migration.accepted, 1);
    // The 0.5 digest named a line and this one does not, so the migration re-identifies rather than translates.
    assert.equal(migrated.occurrences[0]?.identity, computeIdentityFor("ts", "naming.short", "src/app.ts", "process#1"));
    assert.deepEqual(readFileSync(join(dir, "legacy.json")), original);
  });
});

test("migration refuses to write over its own input", () => {
  withProject((dir) => {
    const original = writeLegacyInput(dir);
    const inputPath = join(dir, "legacy.json");

    assert.throws(() => migrateBaseline(inputPath, inputPath, [finding()]), /different file/u);
    assert.deepEqual(readFileSync(inputPath), original);
  });
});

test("a 0.5 input naming two row containers is refused, and its bytes are left alone", () => {
  withProject((dir) => {
    const inputPath = join(dir, "legacy.json");
    const ambiguous = Buffer.from(`${JSON.stringify({ schemaVersion: "gruff.baseline.v1", entries: [], findings: [] }, null, 2)}\n`);
    writeFileSync(inputPath, ambiguous);

    assert.throws(() => migrateBaseline(inputPath, join(dir, "migrated.json"), [finding()]), /more than one row container/u);
    assert.deepEqual(readFileSync(inputPath), ambiguous);
    // A refused migration writes nothing, so the user is not left with a half-migrated second file.
    assert.equal(existsSync(join(dir, "migrated.json")), false);
  });
});

test("an output hard-linked to the input is refused, because it is the same inode under another name", () => {
  withProject((dir) => {
    const original = writeLegacyInput(dir);
    const outputPath = join(dir, "hard-link.json");
    linkSync(join(dir, "legacy.json"), outputPath);

    assert.throws(() => migrateBaseline(join(dir, "legacy.json"), outputPath, [finding()]), /different file/u);
    assert.deepEqual(readFileSync(join(dir, "legacy.json")), original);
  });
});

test("a baseline only ever removes reviewed findings from the score and the exit code", () => {
  withProject((dir) => {
    const path = join(dir, "baseline.json");
    const reviewed = finding();
    const fresh = finding({ symbol: "other", line: 400 });
    const secret = finding({ ruleId: "sensitive-data.high-entropy-string", pillar: "sensitive-data", symbol: "", message: "Possible secret" });
    writeBaseline(path, [reviewed, secret]);

    const application = applyBaseline(path, [reviewed, fresh, secret]);

    // Only the reviewed finding leaves the gated set; the new one and the secret still fail the run.
    assert.deepEqual(application.findings, [fresh, secret]);
    assert.equal(application.counts.unchanged, 1);
    assert.equal(application.counts.new, 1);
    assert.equal(application.counts.notEligible, 1);
  });
});

test("a generate at the default path keeps the retreat copy unless the user forces it", () => {
  withProject((dir) => {
    const defaultPath = join(dir, "gruff-baseline.json");
    const legacyBytes = Buffer.from(JSON.stringify({ schemaVersion: "gruff.baseline.v1", entries: [] }));

    // An empty project has nothing to protect.
    requireOverwritableDefaultPath(defaultPath, false);

    writeFileSync(defaultPath, legacyBytes);
    assert.throws(() => requireOverwritableDefaultPath(defaultPath, false), /--force/u);
    // The refusal is not a write: the retreat copy is exactly as the user left it.
    assert.deepEqual(readFileSync(defaultPath), legacyBytes);
    // The destructive case stays available and stays explicit.
    requireOverwritableDefaultPath(defaultPath, true);

    // Regenerating v3 over v3 is not destructive, because v3 is what the tool now reads.
    writeBaseline(defaultPath, [finding()]);
    requireOverwritableDefaultPath(defaultPath, false);
  });
});

test("a written baseline carries no sentinel, raw, partial, hashed or encoded", () => {
  withProject((dir) => {
    // A synthetic AWS-shaped literal, not a live credential; it exists to be searched for.
    const sentinel = `AKIA${"IOSFODNN7EXAMPLE"}`;
    const secret = finding({
      ruleId: "sensitive-data.aws-access-key",
      pillar: "sensitive-data",
      symbol: "",
      message: `possible AWS access key ${sentinel} in a literal`,
    });
    const path = join(dir, "gruff-baseline.json");
    writeBaseline(path, [secret]);
    const written = readFileSync(path, "utf8");

    for (const [name, form] of Object.entries(sentinelForms(sentinel))) {
      assert.equal(written.includes(form), false, `the written baseline carries the ${name} form of the sentinel`);
    }
    // What it does carry is a count, which is what makes the secret auditable without naming it.
    assert.equal(written.includes('"sensitive-data.aws-access-key": 1'), true);
  });
});

// Returns every shape a leaked secret could take in an artifact, so a derived value is caught as well as a raw one.
function sentinelForms(sentinel: string): Record<string, string> {
  return {
    raw: sentinel,
    partial: sentinel.slice(0, 8),
    hashed: createHash("sha256").update(sentinel).digest("hex"),
    encoded: Buffer.from(sentinel).toString("base64"),
  };
}

// What one test varies about an ordinary finding; a symbol-less case sets `symbol` to the empty string.
// Stable contract: every other field is fixed, so a case varies exactly the input whose effect it proves.
interface FindingOverrides {
  ruleId?: string;
  message?: string;
  pillar?: Finding["pillar"];
  symbol?: string;
  line?: number;
}

// Builds one ordinary finding; each test varies only the field whose effect on the identity it is proving.
// Stable contract: the fingerprint and stable identity are placeholders, because baseline v3 reads neither.
function finding(overrides: FindingOverrides = {}): Finding {
  const symbol = overrides.symbol ?? "process";
  return {
    ruleId: overrides.ruleId ?? "naming.short",
    message: overrides.message ?? "naming.short message",
    filePath: "src/app.ts",
    line: overrides.line ?? 12,
    severity: "advisory",
    pillar: overrides.pillar ?? "naming",
    secondaryPillars: [],
    tier: "v0.1",
    confidence: "high",
    // A file-level finding names no symbol, and is then named by its message with measurements stripped.
    ...(symbol === "" ? {} : { symbol }),
    metadata: {},
    fingerprint: "0".repeat(16),
    stableIdentity: "0".repeat(16),
  };
}

// Stages the 0.5 baseline a migration reads, and hands back its bytes for the comparison after the migration.
// Stable contract: those bytes are exactly what the migration must leave untouched.
function writeLegacyInput(dir: string): Buffer {
  const legacy = Buffer.from(
    `${JSON.stringify(
      {
        schemaVersion: "gruff.baseline.v1",
        generatedAt: "2026-08-01T00:00:00.000Z",
        entries: [{ fingerprint: "3f6a8b2d5c9e1704", ruleId: "naming.short", filePath: "src/app.ts", line: 12, symbol: "process", message: "naming.short message" }],
      },
      null,
      2,
    )}\n`,
  );
  writeFileSync(join(dir, "legacy.json"), legacy);
  return legacy;
}

// Writes a temp directory, runs one case inside it, and removes it afterwards, so no case sees another's baseline file.
function withProject(run: (dir: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), "gruff-ts-baseline-"));
  try {
    run(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
