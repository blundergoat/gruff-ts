// Rule catalogue tests that keep descriptors, fixture coverage, and rule-quality doctrine aligned.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { ruleDescriptors } from "./cli.ts";
import { SECURITY_EXPANSION_RISKY_RULE_IDS, SECURITY_EXPANSION_RULE_QUALITY_DOCTRINE } from "./fixtures/rule-catalogue-security-doctrine.ts";
import { ruleCatalogueCoverageRuleIds } from "./test-fixtures.ts";

const RULE_QUALITY_FIXTURE_CATEGORIES = ["valid", "invalid", "noisy-valid", "missing-invalid"] as const;

// Asserts the descriptor's optionKeys list is sorted and unique. Factored out of the descriptor
// catalogue test body to preserve a stable sort invariant without an inline `if` branch.
function assertSortedUniqueOptionKeys(descriptor: { ruleId: string; optionKeys?: readonly string[] }): void {
  const optionKeys = descriptor.optionKeys ?? [];
  assert.deepEqual(optionKeys, [...optionKeys].sort(), `option key ordering for ${descriptor.ruleId}`);
  assert.equal(new Set(optionKeys).size, optionKeys.length, `option key uniqueness for ${descriptor.ruleId}`);
}

// Asserts the descriptor either has a fixture exemption with a real reason or is covered by a
// catalogue fixture id. Factored out so the descriptor catalogue test body avoids a branch.
function assertDescriptorCoverageOrExemption(descriptor: { ruleId: string; fixtureExemption?: string }, coverageIds: Set<string>): void {
  const exemption = descriptor.fixtureExemption ?? "";
  const hasExemption = exemption.length > 0;
  assert.equal(hasExemption || coverageIds.has(descriptor.ruleId), true, `missing positive fixture coverage for ${descriptor.ruleId}`);
  assert.ok(!hasExemption || exemption.length > 10, `fixture exemption reason for ${descriptor.ruleId}`);
}

type RuleQualityCategory = (typeof RULE_QUALITY_FIXTURE_CATEGORIES)[number];
type RuleQualityDescriptor = ReturnType<typeof ruleDescriptors>[number];

// Tracks the rule/options section while scanning the YAML config fixture.
interface YamlRuleOptionsState {
  isInRules: boolean;
  currentRule: string;
  isInOptions: boolean;
}

// Pairs valid, invalid, and noisy fixtures for one rule-doctrine assertion.
interface RuleQualityDoctrineCase {
  ruleId: string;
  signalSource: string;
  expectedPillar: RuleQualityDescriptor["pillar"];
  expectedSeverity: RuleQualityDescriptor["severity"];
  expectedConfidence: RuleQualityDescriptor["confidence"];
  fixtureCategories: readonly RuleQualityCategory[];
  invalidFixture: string;
  noisyValidFixture: string;
  missingInvalidFixture: string;
  falsePositiveEscapeHatch: string;
  fingerprintStability: string;
}

const riskyRuleIdsRequiringNoisyValidProof = [
  "docs.fixture-purpose-missing",
  "docs.magic-threshold-without-rationale",
  "docs.missing-error-behavior-doc",
  "docs.missing-invariant-doc",
  "docs.missing-side-effect-doc",
  "docs.missing-why-for-complex-code",
  "docs.stale-comment",
  "docs.suppression-without-rationale",
  "docs.todo-without-tracking",
  "docs.useless-docblock",
  "security.disabled-tls-verification",
  "security.eval-call",
  ...SECURITY_EXPANSION_RISKY_RULE_IDS,
  "security.new-function",
  "security.string-timer",
  "security.inner-html",
  "security.javascript-url",
  "security.process-exec",
  "security.proto-access",
  "security.weak-crypto",
  "sensitive-data.api-key-pattern",
  "sensitive-data.high-entropy-string",
  "test-quality.only-skip",
  "waste.commented-out-code",
] as const;

const riskyRuleQualityDoctrine = [
  {
    ruleId: "docs.fixture-purpose-missing",
    signalSource: "test and fixture file scan for large source literals, generated fixture sources, and fixture-heavy setup blocks",
    expectedPillar: "documentation",
    expectedSeverity: "advisory",
    expectedConfidence: "medium",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "large inline source fixture, generated fixture source, or fixture-heavy test setup without a nearby purpose comment",
    noisyValidFixture: "ordinary prose strings, UI text, markdown snippets, snapshots, short code examples, and purpose-commented fixtures",
    missingInvalidFixture: "large scanner-relevant fixture remains reported when unrelated strings and documented fixtures are present",
    falsePositiveEscapeHatch: "scope to test/fixture-like files, require large source-like content or fixture setup signals, and accept bounded purpose markers",
    fingerprintStability: "anchor to the fixture declaration, helper call, or test invocation line rather than fixture body text",
  },
  {
    ruleId: "docs.magic-threshold-without-rationale",
    signalSource: "masked executable-line scan for named threshold constants and threshold() defaults",
    expectedPillar: "documentation",
    expectedSeverity: "advisory",
    expectedConfidence: "medium",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "threshold-like numeric constant or config default without nearby rationale",
    noisyValidFixture: "ordinary numeric literals, test assertions, strings, templates, and rationale-commented thresholds",
    missingInvalidFixture: "unexplained threshold remains reported when explained thresholds are nearby",
    falsePositiveEscapeHatch: "skip common safe values and test files, require threshold-like names or threshold() defaults",
    fingerprintStability: "anchor to the numeric policy line and threshold label without including surrounding prose",
  },
  {
    ruleId: "docs.missing-error-behavior-doc",
    signalSource: "commented function body scan for throw, catch, process.exit, diagnostics, or finding pushes",
    expectedPillar: "documentation",
    expectedSeverity: "advisory",
    expectedConfidence: "medium",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "commented function with throw/catch/reporting behavior but no error-behavior marker",
    noisyValidFixture: "ordinary pure functions and comments that explicitly mention throws, reports, exits, or recovery",
    missingInvalidFixture: "error behavior remains reported when unrelated useful comments are present",
    falsePositiveEscapeHatch: "require an existing leading comment and bounded observable error-behavior tokens",
    fingerprintStability: "anchor to the leading comment line plus function symbol",
  },
  {
    ruleId: "docs.missing-invariant-doc",
    signalSource: "commented declaration scan for schema, fingerprint, baseline, report, and deterministic contracts",
    expectedPillar: "documentation",
    expectedSeverity: "advisory",
    expectedConfidence: "medium",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "commented function or interface that owns schemaVersion or fingerprint fields without invariant wording",
    noisyValidFixture: "contract-bearing comments that mention schema, fingerprint, stable, deterministic, or invariant",
    missingInvalidFixture: "contract-bearing declaration remains reported when unrelated comments are present",
    falsePositiveEscapeHatch: "require an existing leading comment and explicit contract vocabulary in declaration or body",
    fingerprintStability: "anchor to the leading comment line plus declaration symbol",
  },
  {
    ruleId: "docs.missing-side-effect-doc",
    signalSource: "commented function body scan for explicit filesystem, process, environment, server, and child-process APIs",
    expectedPillar: "documentation",
    expectedSeverity: "advisory",
    expectedConfidence: "medium",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "commented function that writes files, mutates process state, or spawns a process without naming the side effect",
    noisyValidFixture: "pure parsing/string helpers and comments that explicitly mention writes, persists, spawns, or environment",
    missingInvalidFixture: "observable side effect remains reported when unrelated comments are present",
    falsePositiveEscapeHatch: "do not infer from function names alone except known persistence entry points",
    fingerprintStability: "anchor to the leading comment line plus function symbol",
  },
  {
    ruleId: "docs.missing-why-for-complex-code",
    signalSource: "commented function metrics reused from existing size, cyclomatic, cognitive, NPath, and nesting thresholds",
    expectedPillar: "documentation",
    expectedSeverity: "advisory",
    expectedConfidence: "medium",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "commented function over an existing complexity threshold without because/why/tradeoff context",
    noisyValidFixture: "simple commented functions and complex functions whose comments mention why, because, or tradeoffs",
    missingInvalidFixture: "complex control flow remains reported when a restating or generic comment is present",
    falsePositiveEscapeHatch: "missing comments stay owned by docs.missing-function-doc; the context-doc rules require a leading comment to fire",
    fingerprintStability: "anchor to the leading comment line plus function symbol",
  },
  {
    ruleId: "docs.stale-comment",
    signalSource: "comment-text scanner with declaration, rule, flag, and path cross-checks",
    expectedPillar: "documentation",
    expectedSeverity: "advisory",
    expectedConfidence: "medium",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "comments naming missing files, unknown rule ids, stale flags, or the wrong declaration",
    noisyValidFixture: "historical comments with legacy or migration context and valid file/rule/flag references",
    missingInvalidFixture: "stale references still report when valid historical context appears nearby",
    falsePositiveEscapeHatch: "skip explicitly historical context and only match narrow quoted paths and known rule prefixes",
    fingerprintStability: "anchor to the comment line rather than the prose body so wording edits do not churn identity",
  },
  {
    ruleId: "docs.suppression-without-rationale",
    signalSource: "comment-text scanner over lint, formatter, coverage, and tool suppression markers",
    expectedPillar: "documentation",
    expectedSeverity: "advisory",
    expectedConfidence: "medium",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "eslint, biome, oxlint, coverage, or prettier suppression without because/reason/tracking text",
    noisyValidFixture: "suppression markers with because, reason, false-positive, issue, ADR, or task context",
    missingInvalidFixture: "unexplained suppression remains reported beside documented suppressions",
    falsePositiveEscapeHatch: "TypeScript directives keep the existing modernisation rule to avoid duplicate findings",
    fingerprintStability: "anchor to the suppression comment line and not to the suppression rationale body",
  },
  {
    ruleId: "docs.todo-without-tracking",
    signalSource: "comment-text scanner requiring issue, owner, date, ADR, milestone, or task tracking markers",
    expectedPillar: "documentation",
    expectedSeverity: "advisory",
    expectedConfidence: "high",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "TODO, FIXME, HACK, or XXX comment with no tracking context",
    noisyValidFixture: "marker words inside strings/templates/regexes plus comments with explicit tracking markers",
    missingInvalidFixture: "untracked marker remains reported when tracked marker examples are present",
    falsePositiveEscapeHatch: "scan extracted comments only and accept bounded tracking patterns",
    fingerprintStability: "anchor to the marker comment line and keep raw TODO text out of the fingerprint",
  },
  {
    ruleId: "docs.useless-docblock",
    signalSource: "leading-comment scanner comparing normalized comment words with declaration names",
    expectedPillar: "documentation",
    expectedSeverity: "advisory",
    expectedConfidence: "medium",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "JSDoc or line comment that only repeats the function or interface name",
    noisyValidFixture: "comments that explain contract, side effects, invariants, fallback, or why context",
    missingInvalidFixture: "restating comment remains reported beside useful context comments",
    falsePositiveEscapeHatch: "skip comments with explicit maintainer-context marker phrases",
    fingerprintStability: "anchor to the declaration comment line and symbol, not the full prose",
  },
  {
    ruleId: "security.eval-call",
    signalSource: "masked source executable-line scan",
    expectedPillar: "security",
    expectedSeverity: "error",
    expectedConfidence: "high",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "direct eval call in executable code",
    noisyValidFixture: "eval text inside comments, strings, regex bodies, and templates",
    missingInvalidFixture: "direct eval remains reported when noisy fixtures are present",
    falsePositiveEscapeHatch: "run only against masked executable source",
    fingerprintStability: "keep file path, rule id, executable line, and symbol identity stable",
  },
  {
    ruleId: "security.new-function",
    signalSource: "masked source executable-line scan",
    expectedPillar: "security",
    expectedSeverity: "error",
    expectedConfidence: "high",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "direct Function constructor in executable code",
    noisyValidFixture: "constructor text inside comments, strings, regex bodies, and templates",
    missingInvalidFixture: "constructor call remains reported when noisy fixtures are present",
    falsePositiveEscapeHatch: "run only against masked executable source",
    fingerprintStability: "keep the executable line as the finding anchor",
  },
  {
    ruleId: "security.disabled-tls-verification",
    signalSource: "raw text scan anchored to executable TLS-disable tokens",
    expectedPillar: "security",
    expectedSeverity: "error",
    expectedConfidence: "high",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "NODE_TLS_REJECT_UNAUTHORIZED zero or rejectUnauthorized false",
    noisyValidFixture: "safe TLS settings and prose references to rejectUnauthorized",
    missingInvalidFixture: "literal TLS-disable tokens remain reported alongside safe settings",
    falsePositiveEscapeHatch: "require an exact disable assignment or object-property value",
    fingerprintStability: "keep the concrete TLS-disable line as the finding anchor",
  },
  {
    ruleId: "security.string-timer",
    signalSource: "masked source executable-line scan",
    expectedPillar: "security",
    expectedSeverity: "warning",
    expectedConfidence: "high",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "timer call with a string callback",
    noisyValidFixture: "timer text inside comments, strings, regex bodies, templates, and arbitrary receiver methods",
    missingInvalidFixture: "string timer remains reported when noisy fixtures are present",
    falsePositiveEscapeHatch: "require a global or browser timer call with a string-like first argument",
    fingerprintStability: "keep the timer call line as the finding anchor",
  },
  {
    ruleId: "security.inner-html",
    signalSource: "masked source executable-line scan",
    expectedPillar: "security",
    expectedSeverity: "warning",
    expectedConfidence: "high",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "innerHTML assignment in executable code",
    noisyValidFixture: "innerHTML text inside comments, strings, regex bodies, and templates",
    missingInvalidFixture: "assignment remains reported when noisy fixtures are present",
    falsePositiveEscapeHatch: "require an executable assignment token",
    fingerprintStability: "keep the assignment line as the finding anchor",
  },
  {
    ruleId: "security.javascript-url",
    signalSource: "raw string-literal scan guarded by executable-code position",
    expectedPillar: "security",
    expectedSeverity: "error",
    expectedConfidence: "high",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "string literal that begins with javascript:",
    noisyValidFixture: "plain text mentioning javascript URLs in comments or nonmatching strings",
    missingInvalidFixture: "javascript URL literal remains reported with noisy strings present",
    falsePositiveEscapeHatch: "require the javascript: token to start in executable code",
    fingerprintStability: "anchor to the literal line without including the URL body",
  },
  ...SECURITY_EXPANSION_RULE_QUALITY_DOCTRINE,
  {
    ruleId: "security.process-exec",
    signalSource: "masked source executable-line scan with fixed test harness exemption",
    expectedPillar: "security",
    expectedSeverity: "warning",
    expectedConfidence: "high",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "spawn, exec, or execFile called with runtime-controlled command input",
    noisyValidFixture: "fixed local spawn or execFile command vectors inside test harness files",
    missingInvalidFixture: "dynamic child-process calls remain reported when fixed harnesses are present",
    falsePositiveEscapeHatch: "exempt only fixed local command vectors in test-like files",
    fingerprintStability: "keep the child-process call line as the finding anchor",
  },
  {
    ruleId: "security.proto-access",
    signalSource: "masked executable-line and guarded raw bracket-property scans",
    expectedPillar: "security",
    expectedSeverity: "warning",
    expectedConfidence: "medium",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "direct dot or bracket __proto__ property access",
    noisyValidFixture: "__proto__ text inside comments and unrelated string literals",
    missingInvalidFixture: "direct prototype access remains reported beside noisy strings",
    falsePositiveEscapeHatch: "require a real property access token in code",
    fingerprintStability: "keep the prototype access line as the finding anchor",
  },
  {
    ruleId: "security.weak-crypto",
    signalSource: "raw text scan anchored to executable crypto API tokens",
    expectedPillar: "security",
    expectedSeverity: "warning",
    expectedConfidence: "high",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "md5, sha1, createCipher, or legacy TLS protocol options",
    noisyValidFixture: "sha256 and modern TLS options plus prose references to old algorithms",
    missingInvalidFixture: "weak crypto tokens remain reported with safe crypto nearby",
    falsePositiveEscapeHatch: "require exact weak algorithm or legacy protocol tokens",
    fingerprintStability: "keep the weak crypto line as the finding anchor",
  },
  {
    ruleId: "sensitive-data.high-entropy-string",
    signalSource: "raw text literal scanner with redacted preview metadata",
    expectedPillar: "sensitive-data",
    expectedSeverity: "error",
    expectedConfidence: "medium",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "secret-like high-entropy literal",
    noisyValidFixture: "package integrity hash and obvious placeholder literals",
    missingInvalidFixture: "secret-like literal remains reported with redacted output",
    falsePositiveEscapeHatch: "allowlist known non-secret encodings before reporting",
    fingerprintStability: "anchor to the literal line without including raw secret text",
  },
  {
    ruleId: "test-quality.only-skip",
    signalSource: "test block scan against masked executable body",
    expectedPillar: "test-quality",
    expectedSeverity: "advisory",
    expectedConfidence: "high",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "focused or skipped test marker in executable test code",
    noisyValidFixture: "focused/skipped marker text inside fixtures and documentation",
    missingInvalidFixture: "focused or skipped test remains reported when noisy fixtures are present",
    falsePositiveEscapeHatch: "run against masked test block source only",
    fingerprintStability: "anchor to the test block start line",
  },
  {
    ruleId: "waste.commented-out-code",
    signalSource: "raw line comment scanner",
    expectedPillar: "maintainability",
    expectedSeverity: "advisory",
    expectedConfidence: "high",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "single-line comment that starts with disabled source syntax",
    noisyValidFixture: "ordinary prose comments that mention code tokens",
    missingInvalidFixture: "disabled source line remains reported when prose comments are present",
    falsePositiveEscapeHatch: "require the uncommented text to look like a statement, declaration, or call",
    fingerprintStability: "anchor to the commented-out source line",
  },
] as const satisfies readonly RuleQualityDoctrineCase[];

const riskyRuleQualityExceptions = [
  {
    ruleId: "sensitive-data.api-key-pattern",
    reason:
      "Vendor key patterns intentionally scan raw text so committed secrets in comments, fixtures, and config are still findings; noisy-valid proof is deferred to rule-specific allowlist refinements.",
  },
] as const;

test("documentation catalogue covers comment rule pack", () => {
  const descriptors = ruleDescriptors();
  const descriptorByRuleId = new Map(descriptors.map((descriptor) => [descriptor.ruleId, descriptor]));
  const configSource = readFileSync(".gruff-ts.yaml", "utf8");
  const coverageIds = ruleCatalogueCoverageRuleIds();
  const doctrineIds: Set<string> = new Set(riskyRuleQualityDoctrine.filter((entry) => entry.expectedPillar === "documentation").map((entry) => entry.ruleId));
  const documentationRuleIds = descriptors.filter((descriptor) => descriptor.pillar === "documentation").map((descriptor) => descriptor.ruleId);

  documentationRuleIds.forEach((ruleId) => {
    assert.notEqual(descriptorByRuleId.get(ruleId), undefined, `missing descriptor for ${ruleId}`);
    assert.equal(configSource.includes(`  ${ruleId}:`), true, `missing config entry for ${ruleId}`);
    assert.equal(coverageIds.has(ruleId), true, `missing cumulative fixture coverage for ${ruleId}`);
  });
  riskyRuleIdsRequiringNoisyValidProof.filter((ruleId) => ruleId.startsWith("docs.")).forEach((ruleId) => {
    assert.equal(doctrineIds.has(ruleId), true, `missing documentation doctrine for ${ruleId}`);
  });
});

test("rule descriptors cover emitted rules and fixture-backed coverage", () => {
  const descriptors = ruleDescriptors();
  const descriptorIds = descriptors.map((descriptor) => descriptor.ruleId);
  assert.deepEqual(descriptorIds, [...descriptorIds].sort());
  assert.equal(new Set(descriptorIds).size, descriptorIds.length);

  descriptors.forEach((descriptor) => {
    assert.match(descriptor.ruleId, /^[a-z-]+\.[a-z0-9-]+$/);
    assert.ok(descriptor.description.length > 10, `description for ${descriptor.ruleId}`);
    assert.ok(descriptor.remediation.length > 10, `remediation for ${descriptor.ruleId}`);
    assertSortedUniqueOptionKeys(descriptor);
  });

  const coverageIds = ruleCatalogueCoverageRuleIds();
  const descriptorIdSet = new Set(descriptorIds);
  coverageIds.forEach((ruleId) => {
    assert.equal(descriptorIdSet.has(ruleId), true, `missing descriptor for emitted rule ${ruleId}`);
  });
  descriptors.forEach((descriptor) => {
    assertDescriptorCoverageOrExemption(descriptor, coverageIds);
  });
});

test("rule quality doctrine covers risky scanner descriptors", () => {
  const descriptors = new Map(ruleDescriptors().map((descriptor) => [descriptor.ruleId, descriptor]));
  const doctrine = new Map<string, RuleQualityDoctrineCase>(riskyRuleQualityDoctrine.map((entry) => [entry.ruleId, entry]));
  const exceptions = new Map<string, string>(riskyRuleQualityExceptions.map((entry) => [entry.ruleId, entry.reason]));
  const categoryVocabulary = [...RULE_QUALITY_FIXTURE_CATEGORIES].sort();

  const exceptionOnlyIds = riskyRuleIdsRequiringNoisyValidProof.filter((ruleId) => !doctrine.has(ruleId));
  const doctrineRuleIds = riskyRuleIdsRequiringNoisyValidProof.filter((ruleId) => doctrine.has(ruleId));

  riskyRuleIdsRequiringNoisyValidProof.forEach((ruleId) => {
    assert.notEqual(descriptors.get(ruleId), undefined, `risky rule has no descriptor: ${ruleId}`);
    assert.equal(Boolean(doctrine.get(ruleId)) || Boolean(exceptions.get(ruleId)), true, `risky rule missing noisy-valid doctrine or exception: ${ruleId}`);
  });

  exceptionOnlyIds.forEach((ruleId) => {
    const exception = exceptions.get(ruleId) ?? "";
    assert.ok(exception.length > 80, `risky rule exception is too terse: ${ruleId}`);
  });

  doctrineRuleIds.forEach((ruleId) => assertRiskyRuleDoctrineEntry({ ruleId, descriptors, doctrine, exceptions, categoryVocabulary }));
});

// `RiskyRuleDoctrineCheck` bundles per-rule lookup tables for risky-rule doctrine assertions.
// Passed as a single object so the helper stays under the size.parameter-count budget.
interface RiskyRuleDoctrineCheck {
  ruleId: string;
  descriptors: Map<string, RuleQualityDescriptor>;
  doctrine: Map<string, RuleQualityDoctrineCase>;
  exceptions: Map<string, string>;
  categoryVocabulary: readonly string[];
}

// Verifies that a single doctrine entry matches its descriptor and that every fixture-category
// field is non-terse. Factored out so the test body avoids an inline branch; the descriptor-to-
// entry mapping must stay stable so doctrine drift is caught even when entries are added.
function assertRiskyRuleDoctrineEntry(check: RiskyRuleDoctrineCheck): void {
  const { ruleId, descriptors, doctrine, exceptions, categoryVocabulary } = check;
  const descriptor = descriptors.get(ruleId);
  const entry = doctrine.get(ruleId);
  assert.ok(entry, `expected doctrine entry for ${ruleId}`);
  assert.equal(exceptions.get(ruleId), undefined, `risky rule should use doctrine or exception, not both: ${ruleId}`);
  assert.equal(descriptor?.pillar, entry.expectedPillar, `pillar drift for ${ruleId}`);
  assert.equal(descriptor?.severity, entry.expectedSeverity, `severity drift for ${ruleId}`);
  assert.equal(descriptor?.confidence, entry.expectedConfidence, `confidence drift for ${ruleId}`);
  assert.deepEqual([...entry.fixtureCategories].sort(), categoryVocabulary, `fixture vocabulary for ${ruleId}`);
  ([
    ["signalSource", entry.signalSource],
    ["invalidFixture", entry.invalidFixture],
    ["noisyValidFixture", entry.noisyValidFixture],
    ["missingInvalidFixture", entry.missingInvalidFixture],
    ["falsePositiveEscapeHatch", entry.falsePositiveEscapeHatch],
    ["fingerprintStability", entry.fingerprintStability],
  ] as const).forEach(([field, value]) => {
    assert.ok(value.length > 20, `${field} is too terse for ${ruleId}`);
  });
}

test("rule descriptor thresholds and options match implementation and config defaults", () => {
  const descriptors = ruleDescriptors();
  const descriptorThresholds = new Map(
    descriptors.filter((descriptor) => typeof descriptor.threshold === "number").map((descriptor) => [descriptor.ruleId, descriptor.threshold ?? 0]),
  );
  const descriptorSeverities = new Map(
    descriptors.filter((descriptor) => typeof descriptor.threshold === "number").map((descriptor) => [descriptor.ruleId, descriptor.severity]),
  );
  const descriptorOptions = new Map(
    descriptors.filter((descriptor) => (descriptor.optionKeys ?? []).length > 0).map((descriptor) => [descriptor.ruleId, [...(descriptor.optionKeys ?? [])].sort()]),
  );
  const implementationSources = ["src/cli.ts", "src/analyser.ts", "src/blocks.ts", "src/comment-rules.ts", "src/project-rules.ts", "src/sensitive-data-rules.ts", "src/test-block-rules.ts"].map((path) => readFileSync(path, "utf8")).join("\n");
  const implementationThresholds = thresholdUsages(implementationSources);
  assert.deepEqual(descriptorThresholds, implementationThresholds);
  assert.deepEqual(descriptorOptions, optionUsages(implementationSources));

  const configSource = readFileSync(".gruff-ts.yaml", "utf8");
  const configThresholds = yamlThresholdDefaults(configSource);
  assert.deepEqual(configThresholds, descriptorThresholds);
  assert.deepEqual(yamlSeverityDefaults(configSource), descriptorSeverities);
  assert.deepEqual(yamlOptionDefaults(configSource), descriptorOptions);
});

// Preserves the descriptor/default invariant by extracting threshold(config, ruleId, default) calls.
function thresholdUsages(source: string): Map<string, number> {
  const usages = new Map<string, number>();
  for (const match of source.matchAll(/threshold\((?:[A-Za-z_$][A-Za-z0-9_$]*\.)?config,\s*"([^"]+)",\s*(-?\d+(?:\.\d+)?)\)/g)) {
    const ruleId = match[1] ?? "";
    const thresholdValue = Number(match[2] ?? "0");
    usages.set(ruleId, thresholdValue);
  }
  return new Map([...usages.entries()].sort(([left], [right]) => left.localeCompare(right)));
}

// Preserves the descriptor/options invariant by extracting optionNumber(config, ruleId, key) calls.
function optionUsages(source: string): Map<string, string[]> {
  const usages = new Map<string, Set<string>>();
  for (const match of source.matchAll(/optionNumber\((?:[A-Za-z_$][A-Za-z0-9_$]*\.)?config,\s*"([^"]+)",\s*"([^"]+)"/g)) {
    const ruleId = match[1] ?? "";
    const key = match[2] ?? "";
    usages.set(ruleId, usages.get(ruleId) ?? new Set<string>());
    usages.get(ruleId)?.add(key);
  }
  return new Map([...usages.entries()].sort(([left], [right]) => left.localeCompare(right)).map(([ruleId, keys]) => [ruleId, [...keys].sort()]));
}

// Preserves the config/descriptor invariant by reading threshold defaults from .gruff-ts.yaml.
function yamlThresholdDefaults(source: string): Map<string, number> {
  const result = new Map<string, number>();
  let isInRules = false;
  let currentRule = "";
  for (const line of source.split(/\r?\n/)) {
    if (line.trim() === "rules:") {
      isInRules = true;
      continue;
    }
    if (!isInRules) {
      continue;
    }
    const ruleMatch = line.match(/^  ([a-z-]+\.[a-z0-9-]+):\s*$/);
    if (ruleMatch?.[1]) {
      currentRule = ruleMatch[1];
      continue;
    }
    const thresholdMatch = line.match(/^    threshold:\s*(-?\d+(?:\.\d+)?)\s*$/);
    if (currentRule && thresholdMatch?.[1]) {
      result.set(currentRule, Number(thresholdMatch[1]));
    }
  }
  return new Map([...result.entries()].sort(([left], [right]) => left.localeCompare(right)));
}

// Reads severities only for threshold-owning YAML rules so the pair contract stays in sync.
function yamlSeverityDefaults(source: string): Map<string, string> {
  const thresholdRules = new Set(yamlThresholdDefaults(source).keys());
  const result = new Map<string, string>();
  let isInRules = false;
  let currentRule = "";
  for (const line of source.split(/\r?\n/)) {
    if (line.trim() === "rules:") {
      isInRules = true;
      continue;
    }
    if (!isInRules) {
      continue;
    }
    const ruleMatch = line.match(/^  ([a-z-]+\.[a-z0-9-]+):\s*$/);
    if (ruleMatch?.[1]) {
      currentRule = ruleMatch[1];
      continue;
    }
    const severityMatch = line.match(/^    severity:\s*(advisory|warning|error)\s*$/);
    if (currentRule && thresholdRules.has(currentRule) && severityMatch?.[1]) {
      result.set(currentRule, severityMatch[1]);
    }
  }
  return new Map([...result.entries()].sort(([left], [right]) => left.localeCompare(right)));
}

// Preserves the YAML option-key invariant with a state machine for per-rule option blocks.
function yamlOptionDefaults(source: string): Map<string, string[]> {
  const result = new Map<string, string[]>();
  const state: YamlRuleOptionsState = { isInRules: false, currentRule: "", isInOptions: false };
  for (const line of source.split(/\r?\n/)) {
    updateYamlOptionDefaults(line, state, result);
  }
  return new Map([...result.entries()].sort(([left], [right]) => left.localeCompare(right)).map(([ruleId, keys]) => [ruleId, keys.sort()]));
}

// Advances the tiny YAML state machine for one config line.
function updateYamlOptionDefaults(line: string, state: YamlRuleOptionsState, result: Map<string, string[]>): void {
  if (line.trim() === "rules:") {
    state.isInRules = true;
    return;
  }
  if (!state.isInRules) {
    return;
  }
  if (recordYamlOptionRule(line, state)) {
    return;
  }
  if (recordYamlOptionsStart(line, state, result)) {
    return;
  }
  recordYamlOptionKey(line, state, result);
}

// Records a rule heading and resets option collection until an options block appears.
function recordYamlOptionRule(line: string, state: YamlRuleOptionsState): boolean {
  const ruleId = yamlRuleId(line);
  if (!ruleId) {
    return false;
  }
  state.currentRule = ruleId;
  state.isInOptions = false;
  return true;
}

// Starts collecting option keys for the current rule when the config block declares options.
function recordYamlOptionsStart(line: string, state: YamlRuleOptionsState, result: Map<string, string[]>): boolean {
  if (state.currentRule === "") {
    return false;
  }
  if (!/^    options:\s*$/.test(line)) {
    return false;
  }
  state.isInOptions = true;
  result.set(state.currentRule, []);
  return true;
}

// Appends an option key inside the current rule's options block.
function recordYamlOptionKey(line: string, state: YamlRuleOptionsState, result: Map<string, string[]>): void {
  if (state.currentRule === "") {
    return;
  }
  if (!state.isInOptions) {
    return;
  }
  const key = yamlOptionKey(line);
  if (key) {
    result.get(state.currentRule)?.push(key);
  }
}

// Extracts a rule id from a two-space-indented YAML heading.
function yamlRuleId(line: string): string | undefined {
  return line.match(/^  ([a-z-]+\.[a-z0-9-]+):\s*$/)?.[1];
}

// Extracts an option key from a six-space-indented YAML property.
function yamlOptionKey(line: string): string | undefined {
  return line.match(/^      ([A-Za-z0-9_-]+):/)?.[1];
}
