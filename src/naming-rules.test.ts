// Naming-rule regression suite for configured blacklists, boolean names, casing, and overlaps.
// Full-pipeline fixtures prove the findings a CLI or report user receives, including stable
// identity and declaration-owner metadata at contract and lexical boundaries.
import assert from "node:assert/strict";
import { cwd } from "node:process";
import test from "node:test";
import { ruleDescriptors } from "./cli.ts";
import { loadConfig, ruleEnabled } from "./config.ts";
import { analyseFixture, analyseProject } from "./test-fixtures.ts";

// Returns only casing-drift diagnostics so these tests model what a CLI user sees without noise.
// Stable contract: owner-boundary assertions stay independent of other rule families.
function inconsistentCasingFindings(source: string) {
  return analyseFixture(source).findings.filter((finding) => finding.ruleId === "naming.inconsistent-casing");
}

// Both fixtures place their second spelling on line six because the assertion pins report identity.
const MERGED_CONTRACT_DRIFT_LINE = 6;
const FILE_WIDE_ACRONYM_DRIFT_LINE = 6;

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

test("naming short-variable accepts conventional comparator parameters", () => {
  const callback = analyseFixture(`interface Item {
  name: string;
}

const byName = (a: Item, b: Item) => a.name.localeCompare(b.name);
console.log(byName);
`);
  assert.deepEqual(callback.findings.filter((finding) => finding.ruleId === "naming.short-variable"), []);

  const comparator = analyseFixture(`function compareNames(a: string, b: string): number {
  return a.localeCompare(b);
}
`);
  assert.deepEqual(comparator.findings.filter((finding) => finding.ruleId === "naming.short-variable"), []);

  const ordinary = analyseFixture(`function combine(a: string, b: string): string {
  return a + b;
}
`);
  assert.deepEqual(ordinary.findings.filter((finding) => finding.ruleId === "naming.short-variable").map((finding) => finding.symbol), ["a", "b"]);
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

test("naming inconsistent-casing flags snake_case local next to camelCase local in one file", () => {
  const report = analyseFixture(`const url_path = "/a";
const urlPath = "/b";
console.log(url_path, urlPath);
`);
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.inconsistent-casing");
  assert.equal(findings.length, 1);
  assert.deepEqual(findings[0]?.metadata?.variants, ["urlPath", "url_path"]);
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

test("naming inconsistent-casing preserves semantic digits", () => {
  const report = analyseFixture(`const adr013 = "accepted";
const adr020 = "superseded";
console.log(adr013, adr020);
`);
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.inconsistent-casing");
  assert.deepEqual(findings, []);
});

test("naming inconsistent-casing ignores constant and contract boundaries", () => {
  // Purpose: one boundary fixture proves the casing rule ignores constants, DTO field adaptation,
  // and intentionally-unused `_` parameters in the same fixture.
  const report = analyseFixture(`const NODE_FRAMEWORKS = ["next"];
const nodeFrameworks = new Set(NODE_FRAMEWORKS);

interface EnvelopeInput {
  event_kind: string;
}

function adapt(input: EnvelopeInput, _event: string): string {
  const eventKind = input.event_kind;
  const event = eventKind.toUpperCase();
  return nodeFrameworks.has(event) ? event : _event;
}
`);
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.inconsistent-casing");
  assert.deepEqual(findings, []);
});

test("naming inconsistent-casing keeps local drift visible beside contract fields", () => {
  const report = analyseFixture(`interface UserRow {
  user_id: string;
}

function adapt(row: UserRow): string {
  const userID = row.user_id;
  const userId = userID.toLowerCase();
  return userId;
}
`);
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.inconsistent-casing");
  assert.equal(findings.length, 1);
  assert.deepEqual(findings[0]?.metadata?.variants, ["userID", "userId"]);
});

// A raw API contract and its normalized UI model are separate user-facing ownership boundaries.
test("naming inconsistent-casing scopes fields to their interface owner", () => {
  const separateContractFindings = inconsistentCasingFindings(`interface RawNote {
  note_id: string;
}

interface NoteView {
  noteId: string;
}
`);
  assert.deepEqual(separateContractFindings, []);

  const sharedContractFinding = inconsistentCasingFindings(`interface NoteView {
  note_id: string;
  noteId: string;
}
`)[0];
  assert.equal(sharedContractFinding?.fingerprint, "931dd174033c0466");
  assert.equal(sharedContractFinding?.stableIdentity, "1fae3dcbce266b17");
  assert.equal(sharedContractFinding?.line, 3);
  assert.equal(sharedContractFinding?.symbol, "noteId");
  assert.deepEqual(sharedContractFinding?.metadata, {
    variants: ["noteId", "note_id"],
    ownerId: "interface:module:NoteView",
    ownerKind: "interface",
    ownerName: "NoteView",
  });

  const acceptedAliasFindings = analyseFixture(`interface NoteView {
  note_id: string;
  noteId: string;
}
`, { config: { allowlists: { acceptedCasingPairs: ["note_id:noteId"] } } }).findings.filter((finding) => finding.ruleId === "naming.inconsistent-casing");
  assert.deepEqual(acceptedAliasFindings, []);

  const unlistedThirdVariant = analyseFixture(`interface NoteView {
  note_id: string;
  noteId: string;
  noteID: string;
}
`, { config: { allowlists: { acceptedCasingPairs: ["note_id:noteId"] } } }).findings.filter((finding) => finding.ruleId === "naming.inconsistent-casing");
  assert.equal(unlistedThirdVariant.length, 1);
  assert.equal(unlistedThirdVariant[0]?.symbol, "noteID");
});

// Unrelated request handlers should not ask a CLI user to unify private local conventions.
test("naming inconsistent-casing scopes locals to their nearest function", () => {
  const separateFunctionFindings = inconsistentCasingFindings(`function readRaw(): void {
  const note_id = "raw";
  console.log(note_id);
}

function readView(): void {
  const noteId = "view";
  console.log(noteId);
}
`);
  assert.deepEqual(separateFunctionFindings, []);
});

// Stable fixture contract: two forms inside one handler retain the original identity tuple.
test("naming inconsistent-casing keeps same-function drift reportable", () => {
  const sharedFunctionSource = `function normalizeNote(): void {
  const note_id = "raw";
  const noteId = note_id;
  console.log(noteId);
}
`;
  const sharedFunctionFinding = inconsistentCasingFindings(sharedFunctionSource)[0];
  const repeatedFunctionFinding = inconsistentCasingFindings(sharedFunctionSource)[0];
  assert.equal(sharedFunctionFinding?.fingerprint, "931dd174033c0466");
  assert.equal(sharedFunctionFinding?.stableIdentity, "1fae3dcbce266b17");
  assert.equal(sharedFunctionFinding?.line, 3);
  assert.equal(sharedFunctionFinding?.symbol, "noteId");
  assert.equal(sharedFunctionFinding?.metadata?.ownerKind, "function");
  assert.equal(sharedFunctionFinding?.metadata?.ownerName, "normalizeNote");
  assert.match(String(sharedFunctionFinding?.metadata?.ownerId), /^function:\d+:\d+$/);
  assert.deepEqual(repeatedFunctionFinding?.metadata, sharedFunctionFinding?.metadata);
  assert.equal(String(sharedFunctionFinding?.metadata?.ownerId).includes("/"), false);
});

// Stable fixture contract: module declarations share one surface because users review them together.
test("naming inconsistent-casing keeps module declarations grouped", () => {
  const moduleFinding = inconsistentCasingFindings(`const note_id = "raw";
const noteId = note_id;
console.log(noteId);
`)[0];
  assert.equal(moduleFinding?.fingerprint, "d2d4bb3b30732a27");
  assert.equal(moduleFinding?.metadata?.ownerId, "module");
  assert.equal(moduleFinding?.metadata?.ownerKind, "module");
  assert.equal(moduleFinding?.metadata?.ownerName, undefined);
});

// Type contracts and function parameters reach the same owner policy as existing inventory rows.
test("naming inconsistent-casing owns type-literal fields and parameters", () => {
  const typeLiteralFinding = inconsistentCasingFindings(`type NoteShape = {
  note_id: string;
  noteId: string;
};
`)[0];
  assert.deepEqual(typeLiteralFinding?.metadata, {
    variants: ["noteId", "note_id"],
    ownerId: "type-literal:module:NoteShape",
    ownerKind: "type-literal",
    ownerName: "NoteShape",
  });

  const parameterFinding = inconsistentCasingFindings(`function normalizeNote(note_id: string): string {
  const noteId = note_id;
  return noteId;
}
`)[0];
  assert.equal(parameterFinding?.metadata?.ownerKind, "function");
  assert.equal(parameterFinding?.metadata?.ownerName, "normalizeNote");
  assert.deepEqual(parameterFinding?.metadata?.variants, ["noteId", "note_id"]);
});

// A nested callback owns its locals, so its spelling does not create an outer-handler warning.
test("naming inconsistent-casing isolates nested function locals", () => {
  const nestedFunctionFindings = inconsistentCasingFindings(`function normalizeNote(): string {
  const note_id = "raw";
  function presentNote(): string {
    const noteId = "view";
    return noteId;
  }
  return note_id + presentNote();
}
`);
  assert.deepEqual(nestedFunctionFindings, []);
});

// Stable fixture contract: TypeScript merges same-name interface blocks into one user surface.
test("naming inconsistent-casing merges same-name interface declarations", () => {
  const mergedContractFinding = inconsistentCasingFindings(`interface NoteView {
  note_id: string;
}

interface NoteView {
  noteId: string;
}
`)[0];
  assert.equal(mergedContractFinding?.line, MERGED_CONTRACT_DRIFT_LINE);
  assert.equal(mergedContractFinding?.symbol, "noteId");
  assert.deepEqual(mergedContractFinding?.metadata, {
    variants: ["noteId", "note_id"],
    ownerId: "interface:module:NoteView",
    ownerKind: "interface",
    ownerName: "NoteView",
  });
});

// Stable fixture contract: acronym diagnostics remain file-wide across separate function owners.
test("naming acronym-case remains file-wide across declaration owners", () => {
  const acronymFinding = analyseFixture(`function readRaw(): void {
  const serviceURL = "raw";
  console.log(serviceURL);
}
function readView(): void {
  const serviceUrl = "view";
  console.log(serviceUrl);
}
`).findings.find((finding) => finding.ruleId === "naming.acronym-case");
  assert.equal(acronymFinding?.line, FILE_WIDE_ACRONYM_DRIFT_LINE);
  assert.equal(acronymFinding?.symbol, "serviceUrl");
  assert.equal(acronymFinding?.fingerprint, "47d338275a661d6e");
  assert.equal(acronymFinding?.stableIdentity, "a482b06b398e16d4");
  assert.deepEqual(acronymFinding?.metadata, { acronym: "URL", variants: ["title", "upper"] });
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

test("naming boolean-prefix accepts exact contract field names", () => {
  const report = analyseFixture(`interface CliOptions {
  all: boolean;
  check: boolean;
  enabled: boolean;
  force: boolean;
  fresh: boolean;
  harness: boolean;
  ok: boolean;
  verbose: boolean;
  ready: boolean;
}
`);
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.boolean-prefix" && finding.metadata?.surface === "interface-field");
  assert.deepEqual(findings.map((finding) => finding.symbol), ["ready"]);
});

test("naming boolean-prefix scopes acceptedBooleanNames to contract fields", () => {
  const report = analyseFixture(
    `interface CliOptions {
  ready: boolean;
}

const ready = true;
console.log(ready);
`,
    { config: { allowlists: { acceptedBooleanNames: ["ready"] } } },
  );
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.boolean-prefix");
  assert.deepEqual(findings.map((finding) => `${finding.metadata?.surface}:${finding.symbol}`), ["declaration:ready"]);
});

test("naming identifier-quality accepts domain-numbered identifiers", () => {
  const report = analyseFixture(`const step0 = "bootstrap";
const installedStep0 = true;
const adr020 = "accepted";
const V110 = "version";
const foo1 = "placeholder";
console.log(step0, installedStep0, adr020, V110, foo1);
`);
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.identifier-quality");
  assert.deepEqual(findings.map((finding) => finding.symbol), ["foo1"]);
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
  // The repo ships `profile: recommended`, which enables every pillar; assert the loaded config keeps
  // each naming rule enabled rather than grepping for a per-rule entry the profile no longer needs.
  const config = loadConfig(cwd(), { paths: ["."], shouldSkipConfig: false, format: "json", failOn: "none", shouldIncludeIgnored: false, changedScope: "symbol", shouldSkipBaseline: true });
  NAMING_PILLAR_RULE_IDS.forEach((ruleId) => {
    assert.equal(ruleEnabled(config, ruleId), true, `repo config does not enable ${ruleId}`);
  });
});

test("naming rule pack config disable independence", () => {
  const source = `const url_path = "/a";
const urlPath = "/b";
const databaseUrl = "/c";
const DATABASE_URL = "/d";
console.log(url_path, urlPath, databaseUrl, DATABASE_URL);
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

test("naming short-variable still flags C-style for binding", () => {
  // §2.8(b) exemption is scoped to `for (const X of Y)` heads; classic `for (let x = …)` stays covered.
  const report = analyseFixture(`export function loop(): number {
  let total = 0;
  for (let x = 0; x < 3; x += 1) {
    total += x;
  }
  return total;
}
`);
  const findings = report.findings.filter((entry) => entry.ruleId === "naming.short-variable" && entry.symbol === "x");
  assert.equal(findings.length, 1);
});

test("naming short-variable still flags for-in binding", () => {
  // §2.8(b) scopes the exemption to `of` heads; `for ... in` over string keys stays covered.
  const report = analyseFixture(`export function listKeys(obj: Record<string, number>): string[] {
  const keys: string[] = [];
  for (const x in obj) {
    keys.push(x);
  }
  return keys;
}
`);
  const findings = report.findings.filter((entry) => entry.ruleId === "naming.short-variable" && entry.symbol === "x");
  assert.equal(findings.length, 1);
});

// Proves reports distinguish safe local boolean renames from contract keys a user may map or configure.
test("naming boolean-prefix emits contract-aware remediation actions without widening acceptance", () => {
  const contractFindings = analyseFixture(`type BookingState = {
  onlineBookableOnly: boolean;
  selectedOnlineBookableOnly: boolean;
  frontendLogging: boolean;
  status: boolean;
  label: string;
};
`).findings.filter((finding) => finding.ruleId === "naming.boolean-prefix");
  assert.deepEqual(contractFindings.map((finding) => [finding.symbol, finding.metadata.remediationAction, finding.metadata.configurationKey]), [
    ["onlineBookableOnly", "CONFIGURE", "allowlists.acceptedBooleanNames"],
    ["selectedOnlineBookableOnly", "CONFIGURE", "allowlists.acceptedBooleanNames"],
    ["frontendLogging", "CONFIGURE", "allowlists.acceptedBooleanNames"],
    ["status", "CONFIGURE", "allowlists.acceptedBooleanNames"],
  ]);
  assert.equal(contractFindings.every((finding) => /complete replacement list|serialization boundary/.test(finding.remediation ?? "")), true);
  assert.equal(contractFindings.some((finding) => "suggestedAction" in finding.metadata), false);
  assert.equal(contractFindings[0]?.fingerprint, "b748b11095d15a5a");

  const configuredContractFindings = analyseFixture(`interface BookingState {
  onlineBookableOnly: boolean;
  selectedOnlineBookableOnly: boolean;
  frontendLogging: boolean;
  status: boolean;
  onlineBookableOnlyLabel: string;
}
`, { config: { allowlists: { acceptedBooleanNames: ["onlineBookableOnly", "selectedOnlineBookableOnly", "frontendLogging"] } } }).findings.filter((finding) => finding.ruleId === "naming.boolean-prefix");
  assert.deepEqual(configuredContractFindings.map((finding) => finding.symbol), ["status"]);

  const localFindings = analyseFixture(`const frontendLogging = true;
function configure(status: boolean): void {
  console.log(frontendLogging, status);
}
`, { config: { allowlists: { acceptedBooleanNames: ["frontendLogging", "status"] } } }).findings.filter((finding) => finding.ruleId === "naming.boolean-prefix");
  assert.deepEqual(localFindings.map((finding) => [finding.metadata.surface, finding.metadata.remediationAction]), [["declaration", "APPLY"], ["parameter", "APPLY"]]);
  assert.equal(localFindings.every((finding) => /Rename this boolean/.test(finding.remediation ?? "")), true);
  assert.deepEqual(localFindings.map((finding) => finding.fingerprint), ["34b1bedb856c4634", "624fecfb81983768"]);
});

// Contract fixture proves class/file advice reaches only one-primary-export modules across export syntax.
test("naming class-file mismatch requires one public declaration across export forms", () => {
  // This fixture covers every supported public-declaration kind plus default and re-export spelling.
  const exportScenarios = [
    { fileName: "helpers.ts", source: "export class PaymentController {}\n", expected: 1 },
    { fileName: "with-interface.ts", source: "export class PaymentController {}\nexport interface PaymentContract {}\n", expected: 0 },
    { fileName: "focusModeTranscript.ts", source: "export type TranscriptState = { label: string };\nexport class TranscriptFocusController {}\n", expected: 0 },
    { fileName: "with-enum.ts", source: "export class PaymentController {}\nexport enum PaymentStatus { Ready }\n", expected: 0 },
    { fileName: "with-function.ts", source: "export class PaymentController {}\nexport function createPayment(): void {}\n", expected: 0 },
    { fileName: "with-default.ts", source: "export class PaymentController {}\nexport default function createPayment(): void {}\n", expected: 0 },
    { fileName: "with-reexport.ts", source: "export class PaymentController {}\nclass PaymentHelper {}\nexport { PaymentHelper };\n", expected: 0 },
    { fileName: "default-helper.ts", source: "export default class PaymentController {}\n", expected: 1 },
    { fileName: "reexport-helper.ts", source: "class PaymentController {}\nexport { PaymentController };\n", expected: 1 },
  ] as const;
  const findingsByFile = new Map(exportScenarios.map((scenario) => [
    scenario.fileName,
    analyseFixture(scenario.source, { fileName: scenario.fileName }).findings.filter((finding) => finding.ruleId === "naming.class-file-mismatch"),
  ] as const));
  assert.deepEqual(exportScenarios.map((scenario) => findingsByFile.get(scenario.fileName)?.length), exportScenarios.map((scenario) => scenario.expected));
  const retainedFinding = findingsByFile.get("helpers.ts")?.[0];
  assert.equal(retainedFinding?.fingerprint, "41a529f0d00d2fcd");
  assert.equal(retainedFinding?.stableIdentity, "ec592eb253c6c1b3");
  assert.deepEqual(retainedFinding?.metadata, { className: "PaymentController", fileName: "helpers", candidatePrimaryExport: true, publicExports: ["class:PaymentController"] });

  const acceptedPairFindings = analyseFixture("export class TranscriptFocusController {}\n", {
    fileName: "focusModeTranscript.ts",
    config: { allowlists: { acceptedClassFilePairs: ["focusModeTranscript:TranscriptFocusController"] } },
  }).findings.filter((finding) => finding.ruleId === "naming.class-file-mismatch");
  assert.deepEqual(acceptedPairFindings, []);
});
