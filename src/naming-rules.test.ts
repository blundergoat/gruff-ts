// Naming-rule regression suite for parameter parsing, configured placeholder lists, short names and
// class/file names. Full-pipeline fixtures prove the findings a CLI or report user receives, including
// stable identity.
import assert from "node:assert/strict";
import { cwd } from "node:process";
import test from "node:test";
import { ruleDescriptors } from "./cli.ts";
import { loadConfig, ruleEnabled } from "./config.ts";
import { parameterNames } from "./findings-helpers.ts";
import { analyseFixture } from "./test-fixtures.ts";

test("parameter parsing keeps commas inside defaults and type expressions", () => {
  assert.deepEqual(
    parameterNames("opts = { a: 1, b: 2 }, public readonly name: string, handler: (left: string, right: number) => void, values: Map<string, number>"),
    [
      { name: "opts", raw: "opts = { a: 1, b: 2 }", isParameterProperty: false },
      { name: "name", raw: "name: string", isParameterProperty: true },
      { name: "handler", raw: "handler: (left: string, right: number) => void", isParameterProperty: false },
      { name: "values", raw: "values: Map<string, number>", isParameterProperty: false },
    ],
  );
});

test("parameter parsing keeps commas between comparison defaults", () => {
  assert.deepEqual(parameterNames("lo = min<max, hi = max>min, tag: string").map(({ name }) => name), ["lo", "hi", "tag"]);
});

test("parameter parsing keeps commas inside generic call defaults", () => {
  assert.deepEqual(parameterNames("fn = factory<T, U>(x), next = 1").map(({ name }) => name), ["fn", "next"]);
});

test("parameter parsing keeps commas inside generic arrow defaults", () => {
  assert.deepEqual(parameterNames("fn = <T, U = string>(value: T) => value, tag: string").map(({ name }) => name), ["fn", "tag"]);
});

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
  assert.deepEqual(byRule("naming.identifier-quality"), ["value"]);
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

test("naming short-variable skips locally bound callable parameters", () => {
  const report = analyseFixture(`const transform = (x: number): number => x + 1;
const predicate = function (y: number): boolean {
  return y > 0;
};
test("uses a callback", (t) => {
  console.log(t);
});
function declared(z: number): number {
  return z + 1;
}
`);
  const parameters = report.findings
    .filter((finding) => finding.ruleId === "naming.short-variable" && finding.metadata?.surface === "parameter")
    .map((finding) => finding.symbol);
  assert.deepEqual(parameters, ["z"]);
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
  "naming.class-file-mismatch",
  "naming.identifier-quality",
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
    { fileName: "merged-helper.ts", source: "interface PaymentController { id: string; }\nclass PaymentController { id = \"payment\"; }\nexport { PaymentController };\n", expected: 1 },
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
