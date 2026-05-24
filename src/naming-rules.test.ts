// Naming-rule tests for blacklist config, boolean names, acronym casing, and overlap boundaries.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { ruleDescriptors } from "./cli.ts";
import { analyseFixture, analyseProject } from "./test-fixtures.ts";

test("naming blacklists default to current behavior", () => {
  const report = analyseFixture(`function process(): void {}

function walk(): void {}

const strName = "demo";

const enabled = true;

const value = 1;

console.log(process, walk, strName, enabled, value);
`);

  // Collects finding symbols for one rule in the naming fixture assertions. Keeps rule output deterministic for snapshots.
  const byRule = (ruleId: string) => report.findings.filter((finding) => finding.ruleId === ruleId).map((finding) => finding.symbol);
  assert.deepEqual(byRule("naming.generic-function"), ["process"]);
  assert.deepEqual(byRule("naming.generic-function").includes("walk"), false);
  assert.deepEqual(byRule("naming.hungarian-notation"), ["strName"]);
  assert.deepEqual(byRule("naming.boolean-prefix"), ["enabled"]);
  assert.deepEqual(byRule("naming.identifier-quality"), ["value"]);
});

test("naming blacklists accept config overrides", () => {
  const report = analyseFixture(
    `function process(): void {}

function walk(): void {}

console.log(process, walk);
`,
    { config: { allowlists: { bannedGenericNames: ["walk"] } } },
  );
  const generic = report.findings.filter((finding) => finding.ruleId === "naming.generic-function").map((finding) => finding.symbol);
  assert.deepEqual(generic, ["walk"]);
});

test("naming blacklist disable empties the list", () => {
  const report = analyseFixture(
    `const value = 1;
const foo1 = 2;
console.log(value, foo1);
`,
    { config: { allowlists: { placeholderNames: [] } } },
  );
  const quality = report.findings.filter((finding) => finding.ruleId === "naming.identifier-quality").map((finding) => finding.metadata?.variant);
  assert.deepEqual(quality, ["numbered"]);
});

test("naming blacklists preserve fingerprint identity", () => {
  const report = analyseFixture(`function process(): void {}
console.log(process);
`);
  const finding = report.findings.find((entry) => entry.ruleId === "naming.generic-function" && entry.symbol === "process");
  assert.equal(finding?.fingerprint, "6786a041045d82a8");
});

test("naming short-variable flags single-letter parameter", () => {
  const report = analyseFixture(`function takesOne(x: number): number {
  return x;
}
`);
  const shorts = report.findings.filter((finding) => finding.ruleId === "naming.short-variable");
  assert.equal(shorts.length, 1);
  assert.equal(shorts[0]?.symbol, "x");
  assert.equal(shorts[0]?.metadata?.surface, "parameter");
});

test("naming short-variable flags destructured single-letter", () => {
  const report = analyseFixture(`function unpack(): void {
  const { a, b } = { a: 1, b: 2 };
  console.log(a, b);
}
`);
  const shorts = report.findings.filter((finding) => finding.ruleId === "naming.short-variable" && finding.metadata?.surface === "destructure");
  assert.deepEqual(shorts.map((finding) => finding.symbol).sort(), ["a", "b"]);
});

test("naming short-variable accepts filesystem adapter abbreviation", () => {
  // Fixture covers `fs` as both an injected filesystem parameter and a local adapter binding.
  const report = analyseFixture(`interface ReadonlyFS {
  exists(path: string): boolean;
}

function loadConfig(fs: ReadonlyFS): boolean {
  return fs.exists(".goat-flow/config.yaml");
}

const fs = createFS(".");
console.log(loadConfig(fs));
`);
  const shorts = report.findings.filter((finding) => finding.ruleId === "naming.short-variable");
  assert.deepEqual(shorts.map((finding) => finding.symbol), []);
});

test("naming identifier-quality flags placeholder parameter", () => {
  const report = analyseFixture(`function takesValue(data: unknown): unknown {
  return data;
}
`);
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.identifier-quality" && finding.metadata?.surface === "parameter");
  assert.deepEqual(findings.map((finding) => finding.symbol), ["data"]);
});

test("naming boolean-prefix flags untyped-prefixed boolean parameter", () => {
  const report = analyseFixture(`function configure(enabled = true): void {
  console.log(enabled);
}
`);
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.boolean-prefix" && finding.metadata?.surface === "parameter");
  assert.deepEqual(findings.map((finding) => finding.symbol), ["enabled"]);
});

test("naming boolean-prefix flags interface boolean field", () => {
  const report = analyseFixture(`interface Status {
  ready: boolean;
  isOpen: boolean;
}
`);
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.boolean-prefix" && finding.metadata?.surface === "interface-field");
  assert.deepEqual(findings.map((finding) => finding.symbol), ["ready"]);
});

test("naming boolean-prefix ignores inferred boolean parameter without annotation or literal default", () => {
  const report = analyseFixture(`function takes(enabled): unknown {
  return enabled;
}
`);
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.boolean-prefix");
  assert.deepEqual(findings, []);
});

test("naming boolean-prefix accepts scanner state and capability booleans", () => {
  // Fixture covers accepted scanner-state, capability, modal, and adjective boolean names.
  const report = analyseFixture(`interface HarnessCheck {
  acknowledged?: boolean;
  supportsAggregate?: boolean;
  requiresStack?: boolean;
  exists?: boolean;
  artifactRequired?: boolean;
  nodePtyAvailable?: boolean;
  mayWriteFiles?: boolean;
}

function scanContent(scanFenced = true): void {
  let inCodeBlock = false;
  const acknowledged = true;
  const provenanceValidated = true;
  console.log(scanFenced, inCodeBlock, acknowledged, provenanceValidated);
}
`);
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.boolean-prefix");
  assert.deepEqual(findings.map((finding) => finding.symbol), []);
});

test("naming widening preserves fingerprints for unchanged code", () => {
  const report = analyseFixture(`function process(): void {}
console.log(process);
`);
  const finding = report.findings.find((entry) => entry.ruleId === "naming.generic-function" && entry.symbol === "process");
  assert.equal(finding?.fingerprint, "6786a041045d82a8");
});

test("naming negative-boolean flags disableCache and noEnabled style names", () => {
  const report = analyseFixture(`const disableCache = true;

function configure(noEnabled = true): void {
  console.log(disableCache, noEnabled);
}
`);
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.negative-boolean");
  assert.deepEqual(findings.map((finding) => finding.symbol).sort(), ["disableCache", "noEnabled"]);
});

test("naming negative-boolean ignores noStore via allowlist", () => {
  const report = analyseFixture(`function writeResponse(noStore: boolean): void {
  console.log(noStore);
}
`);
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.negative-boolean");
  assert.deepEqual(findings, []);
});

test("naming negative-boolean message points to inversion not prefix-addition", () => {
  const report = analyseFixture(`const disableCache = true;
console.log(disableCache);
`);
  const finding = report.findings.find((entry) => entry.ruleId === "naming.negative-boolean");
  assert.match(finding?.remediation ?? "", /[Ii]nvert/);
});

test("naming generic-parameter fires only in multi-param functions above thresholds", () => {
  const positive = analyseFixture(`export function expandHelpers(data: unknown, options: unknown, target: unknown): unknown {
  return [data, options, target];
}
`);
  const flagged = positive.findings.filter((finding) => finding.ruleId === "naming.generic-parameter").map((finding) => finding.symbol);
  assert.deepEqual(flagged.sort(), ["data"]);

  const single = analyseFixture(`function double(value: number): number {
  return value * 2;
}
`);
  const noneFlagged = single.findings.filter((finding) => finding.ruleId === "naming.generic-parameter");
  assert.deepEqual(noneFlagged, []);
});

test("naming inconsistent-casing flags URL_PATH next to urlPath in one file", () => {
  const report = analyseFixture(`const URL_PATH = "/a";
const urlPath = "/b";
console.log(URL_PATH, urlPath);
`);
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.inconsistent-casing");
  assert.equal(findings.length, 1);
  assert.deepEqual(findings[0]?.metadata?.variants, ["URL_PATH", "urlPath"]);
});

test("naming inconsistent-casing ignores distinct concepts across files", () => {
  const report = analyseProject({
    "a.ts": `const URL_PATH = "/x";\nconsole.log(URL_PATH);\n`,
    "b.ts": `function handler(urlPath: string): string {\n  return urlPath;\n}\n`,
  });
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.inconsistent-casing");
  assert.deepEqual(findings, []);
});

test("naming inconsistent-casing ignores legitimate enum cases", () => {
  const report = analyseFixture(`enum Status { Ok = "OK", Error = "ERROR" }
console.log(Status.Ok, Status.Error);
`);
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.inconsistent-casing");
  assert.deepEqual(findings, []);
});

test("naming acronym-case flags URL next to Url in identifiers", () => {
  const report = analyseFixture(`const databaseUrl = "/a";
const SERVICE_URL = "/b";
console.log(databaseUrl, SERVICE_URL);
`);
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.acronym-case");
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.metadata?.acronym, "URL");
});

test("naming acronym-case respects custom knownAcronyms", () => {
  const report = analyseFixture(
    `const grpcChannel = "/a";
const GRPC_HOST = "/b";
console.log(grpcChannel, GRPC_HOST);
`,
    { config: { allowlists: { knownAcronyms: ["grpc"] } } },
  );
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.acronym-case");
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.metadata?.acronym, "GRPC");
});

test("naming acronym-case ignores acronym not in the seed and not in config", () => {
  const report = analyseFixture(`const widgetEtag = "/a";
const WIDGET_ETAG = "/b";
console.log(widgetEtag, WIDGET_ETAG);
`);
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.acronym-case");
  assert.deepEqual(findings, []);
});

test("naming acronym-case ignores fixture constants beside idiomatic locals", () => {
  const report = analyseFixture(`const API_TOKEN_FIXTURE_VALUE = "redacted";
const googleApiKey = "redacted";
console.log(API_TOKEN_FIXTURE_VALUE, googleApiKey);
`);
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.acronym-case");
  assert.deepEqual(findings, []);
});

test("naming acronym-case ignores lower and title acronym mix without all caps", () => {
  const report = analyseFixture(`const apiToken = "redacted";
const googleApiKey = "redacted";
console.log(apiToken, googleApiKey);
`);
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.acronym-case");
  assert.deepEqual(findings, []);
});

// Canonical list of naming-pillar rule ids. Ordering matters: the catalogue test asserts the
// descriptor output matches this list exactly.
const NAMING_PILLAR_RULE_IDS = [
  "naming.acronym-case",
  "naming.boolean-prefix",
  "naming.class-file-mismatch",
  "naming.generic-function",
  "naming.generic-parameter",
  "naming.hungarian-notation",
  "naming.identifier-quality",
  "naming.inconsistent-casing",
  "naming.negative-boolean",
  "naming.short-variable",
];

test("naming rule pack catalogue coverage", () => {
  const descriptors = ruleDescriptors().map((descriptor) => descriptor.ruleId).filter((ruleId) => ruleId.startsWith("naming."));
  assert.deepEqual(descriptors, NAMING_PILLAR_RULE_IDS);
  const yamlSource = readFileSync(".gruff-ts.yaml", "utf8");
  NAMING_PILLAR_RULE_IDS.forEach((ruleId) => {
    assert.match(yamlSource, new RegExp(`\\b${ruleId.replace(".", "\\.")}\\b`), `missing yaml entry for ${ruleId}`);
  });
});

test("naming rule pack config disable independence", () => {
  const source = `const URL_PATH = "/a";
const urlPath = "/b";
const databaseUrl = "/c";
const DATABASE_URL = "/d";
console.log(URL_PATH, urlPath, databaseUrl, DATABASE_URL);
`;
  const both = analyseFixture(source);
  assert.equal(both.findings.some((finding) => finding.ruleId === "naming.inconsistent-casing"), true);
  assert.equal(both.findings.some((finding) => finding.ruleId === "naming.acronym-case"), true);

  const onlyAcronym = analyseFixture(source, {
    config: { rules: { "naming.inconsistent-casing": { enabled: false } } },
  });
  assert.equal(onlyAcronym.findings.some((finding) => finding.ruleId === "naming.inconsistent-casing"), false);
  assert.equal(onlyAcronym.findings.some((finding) => finding.ruleId === "naming.acronym-case"), true);

  const onlyCasing = analyseFixture(source, {
    config: { rules: { "naming.acronym-case": { enabled: false } } },
  });
  assert.equal(onlyCasing.findings.some((finding) => finding.ruleId === "naming.acronym-case"), false);
  assert.equal(onlyCasing.findings.some((finding) => finding.ruleId === "naming.inconsistent-casing"), true);
});

test("naming rule pack cross-rule overlap stays disjoint", () => {
  const report = analyseFixture(`const disableCache = true;
console.log(disableCache);
`);
  const negative = report.findings.filter((finding) => finding.ruleId === "naming.negative-boolean").map((finding) => finding.symbol);
  const booleanPrefix = report.findings.filter((finding) => finding.ruleId === "naming.boolean-prefix").map((finding) => finding.symbol);
  assert.equal(negative.includes("disableCache"), true);
  assert.equal(booleanPrefix.includes("disableCache"), true);
  assert.notEqual(
    report.findings.find((finding) => finding.ruleId === "naming.negative-boolean" && finding.symbol === "disableCache")?.fingerprint,
    report.findings.find((finding) => finding.ruleId === "naming.boolean-prefix" && finding.symbol === "disableCache")?.fingerprint,
  );
});

test("naming generic-parameter ignores typed parameters in exported helpers below thresholds", () => {
  const report = analyseFixture(`export function escape(value: string): string {
  return value;
}
`,
    { config: { rules: { "naming.generic-parameter": { enabled: true, options: { minParameters: 3, minLineCount: 30, minCyclomatic: 8 } } } } },
  );
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.generic-parameter");
  assert.deepEqual(findings, []);
});
