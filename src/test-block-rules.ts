// Per-test-block rule pass: assertion quality (no-assertions, trivial, snapshot-only,
// no-throw-only, exception-type-only, magic-number), mock quality (unused-mock, mock-only-test),
// setup bloat + global-state-mutation, and structural checks (sleep/loop/conditional/only-skip).
// Invoked from the analyseBlocks orchestrator when `block.isTest` is true.
import { blockFinding, blockFindingWithMetadata, type FunctionBlock, hasAssertion, setupLineCount } from "./blocks.ts";
import { ruleSeverity, threshold } from "./config.ts";
import { type SourceFile } from "./discovery.ts";
import { escapeRegex } from "./findings-helpers.ts";
import { countMatches } from "./text-scans.ts";
import type { Config, Finding, Severity } from "./types.ts";

// Provisional rule output gathered during a test-block walk. Built before the surrounding context
// (file, line) is known, then promoted into a real Finding by the caller.
interface TestBlockCheck {
  ruleId: string;
  message: string;
  severity: Severity;
}

// Captures one assertion matcher plus the capture indexes that hold actual expression and literal.
interface MagicNumberAssertionPattern {
  pattern: RegExp;
  expressionIndex: number;
  matcherIndex?: number;
  valueIndex: number;
}

/*
 * Reached when `block.isTest` is true. Four sub-passes in a stable, deterministic order: assertion
 * quality, mock quality, setup bloat, structural rules.
 */
export function analyseTestBlock(file: SourceFile, block: FunctionBlock, config: Config, findings: Finding[]): void {
  const body = block.codeBody;
  analyseAssertionQuality(file, block, body, findings);
  analyseMockQuality(file, block, body, findings);
  analyseSetupBloat(file, block, body, config, findings);
  analyseTestStructureChecks(file, block, body, findings);
}

// Five assertion-shape checks (no-assertions, trivial, snapshot-only, no-throw-only, exception-type-only)
// plus the magic-number sub-pass. Reports findings with stable test-block metadata.
function analyseAssertionQuality(file: SourceFile, block: FunctionBlock, body: string, findings: Finding[]): void {
  for (const check of assertionQualityChecks(block, body)) {
    findings.push(blockFinding({ ruleId: check.ruleId, message: check.message, file, block, severity: check.severity, pillar: "test-quality" }));
  }
  pushMagicNumberAssertionFindings(file, block, body, findings);
}

// Lazy evaluation: only checks whose `active` predicate fired are returned. The five rule IDs are
// part of the public test-quality pillar; their ordering here is the stable emission order.
function assertionQualityChecks(block: FunctionBlock, body: string): TestBlockCheck[] {
  const testName = block.name;
  const checks: Array<TestBlockCheck & { active: boolean }> = [
    { active: !hasAssertion(body), ruleId: "test-quality.no-assertions", message: `Test \`${testName}\` does not appear to make an assertion.`, severity: "warning" },
    { active: hasTrivialAssertion(body), ruleId: "test-quality.trivial-assertion", message: `Test \`${testName}\` contains an assertion that compares a value to itself.`, severity: "warning" },
    { active: isSnapshotOnlyTest(body), ruleId: "test-quality.snapshot-only-test", message: `Test \`${testName}\` relies only on snapshot assertions.`, severity: "advisory" },
    { active: isNoThrowOnlyTest(body), ruleId: "test-quality.no-throw-only-test", message: `Test \`${testName}\` only verifies that code does not throw.`, severity: "advisory" },
    { active: hasExceptionTypeOnlyAssertion(body), ruleId: "test-quality.exception-type-only", message: `Test \`${testName}\` checks only the exception type.`, severity: "advisory" },
  ];
  return checks.filter((check) => check.active).map(({ active: _active, ...check }) => check);
}

/*
 * Targets `expect(x).toBe(42)` / `assert.equal(x, 42)` patterns where 42 has no name. Reports
 * `test-quality.magic-number-assertion` with stable literal metadata for downstream review tools.
 */
function pushMagicNumberAssertionFindings(file: SourceFile, block: FunctionBlock, body: string, findings: Finding[]): void {
  if (isConstantContractTestName(block.name)) {
    return;
  }
  for (const assertion of magicNumberAssertions(body)) {
    findings.push(
      blockFindingWithMetadata({
        ruleId: "test-quality.magic-number-assertion",
        message: `Test \`${block.name}\` asserts against unexplained numeric literal ${assertion.value}.`,
        file,
        block,
        severity: "advisory",
        pillar: "test-quality",
        metadata: { value: assertion.value },
      }),
    );
  }
}

// Two distinct findings emitted from one walk: per-unused-mock and a single mock-only flag.
// Reports `test-quality.unused-mock` / `test-quality.mock-only-test` with stable test-block metadata.
function analyseMockQuality(file: SourceFile, block: FunctionBlock, body: string, findings: Finding[]): void {
  const unusedMocks = unusedMockVariables(body);
  for (const mock of unusedMocks) {
    findings.push(
      blockFindingWithMetadata({
        ruleId: "test-quality.unused-mock",
        message: `Mock \`${mock}\` is created but not used.`,
        file,
        block,
        severity: "advisory",
        pillar: "test-quality",
        metadata: { mockName: mock },
      }),
    );
  }
  if (isMockOnlyTest(body)) {
    findings.push(blockFinding({ ruleId: "test-quality.mock-only-test", message: `Test \`${block.name}\` only verifies mock interaction.`, file, block, severity: "advisory", pillar: "test-quality" }));
  }
}

/*
 * Two rules off one pass: `test-quality.global-state-mutation` for tests that touch process state,
 * and `test-quality.setup-bloat` (threshold 12) for excessive arrange before the first assertion.
 * Reports both with stable metadata so downstream tooling can track the setup-line counts.
 */
function analyseSetupBloat(file: SourceFile, block: FunctionBlock, body: string, config: Config, findings: Finding[]): void {
  if (hasGlobalStateMutation(body)) {
    findings.push(blockFinding({ ruleId: "test-quality.global-state-mutation", message: `Test \`${block.name}\` mutates global process or runtime state.`, file, block, severity: "warning", pillar: "test-quality" }));
  }
  const setupLines = setupLineCount(body);
  const maxSetupLines = setupBloatThreshold(file, config);
  if (setupLines > maxSetupLines) {
    findings.push(
      blockFindingWithMetadata({
        ruleId: "test-quality.setup-bloat",
        message: `Test \`${block.name}\` has ${setupLines} setup lines before its first assertion.`,
        file,
        block,
        severity: ruleSeverity(config, "test-quality.setup-bloat", "advisory"),
        pillar: "test-quality",
        metadata: { setupLines, maxSetupLines },
      }),
    );
  }
}

// Pattern-driven checks for sleep/loop/conditional logic plus the `.only`/`.skip` commit gate.
// Reports each detected structural issue as a stable test-quality finding.
function analyseTestStructureChecks(file: SourceFile, block: FunctionBlock, body: string, findings: Finding[]): void {
  const checks: Array<[string, boolean, string]> = [
    ["test-quality.sleep-in-test", /\b(setTimeout|sleep|waitForTimeout)\s*\(/.test(body), "Test sleeps instead of synchronising on behaviour."],
    ["test-quality.loop-in-test", controlFlowContainsNonFixtureLoop(body), "Test contains loop logic around assertions."],
    ["test-quality.conditional-logic", controlFlowContainsAssertion(body, /\b(?:if|switch)\b/g), "Test contains conditional logic around assertions."],
    ["test-quality.only-skip", /\.(only|skip)\s*\(/.test(body), "Focused or skipped test is committed."],
  ];
  for (const [ruleId, active, message] of checks) {
    if (active) {
      findings.push(blockFinding({ ruleId, message, file, block, severity: "advisory", pillar: "test-quality" }));
    }
  }
}

// Loop variant of `controlFlowContainsAssertion` that suppresses fixture loops (table-test pattern):
// loops over a literal array or `Object.entries|keys|values` of a literal where every code path
// inside the body reaches an assertion. The existing rule fires on ANY loop wrapping an assertion;
// this widens the precision so parametric coverage doesn't read as control-flow noise.
function controlFlowContainsNonFixtureLoop(source: string): boolean {
  for (const match of source.matchAll(/\b(?:for|while)\b/g)) {
    const start = match.index ?? 0;
    const segment = controlFlowSegment(source, start);
    if (!hasAssertion(segment)) {
      continue;
    }
    if (isFixtureLoop(source, start, segment)) {
      continue;
    }
    return true;
  }
  return false;
}

// A "fixture loop" is the table-test pattern: iterable is an inline fixture OR a local const-bound
// fixture table, AND every path through the body terminates in an assertion call. Guard branches
// without assertions are allowed, but assertion-bearing branches still opt out.
function isFixtureLoop(source: string, start: number, segment: string): boolean {
  const braceIndex = segment.indexOf("{");
  const header = braceIndex === -1 ? segment : segment.slice(0, braceIndex);
  if (!hasFixtureIterable(source, start, header)) {
    return false;
  }
  if (braceIndex === -1) {
    return false;
  }
  const body = segment.slice(braceIndex + 1, segment.length - 1);
  if (hasUnsafeFixtureLoopBranch(source.slice(0, start + braceIndex + 1), body)) {
    return false;
  }
  const statements = body.split(/[;\n]/).map((statement) => statement.trim()).filter((statement) => statement.length > 0 && statement !== "}" && !/^(?:break|continue)\b/.test(statement));
  const lastStatement = statements[statements.length - 1] ?? "";
  return /^(?:assert\.[a-z]+\s*\(|expect\s*\(|[a-z][A-Za-z0-9_]*\.should(?:Be|Equal)?\s*\()/i.test(lastStatement);
}

// Fixture sweeps may carry invariant guards such as `if (expectedIds.has(case.id))`; other branches
// still opt out because they can hide case-specific expectations inside the loop.
function hasUnsafeFixtureLoopBranch(sourceBeforeLoopBody: string, body: string): boolean {
  if (/\bswitch\s*\(|\bcase\s|\bdefault\s*:/.test(body)) {
    return true;
  }
  for (const match of body.matchAll(/\bif\b/g)) {
    const start = match.index ?? 0;
    const segment = controlFlowSegment(body, start);
    const sourceBeforeCondition = `${sourceBeforeLoopBody}${body.slice(0, start)}`;
    if (hasAssertion(segment) && !isInvariantAssertionConditional(sourceBeforeCondition, sourceBeforeCondition.length, segment)) {
      return true;
    }
  }
  return false;
}

// Inline fixture tables cover `for (... of [...])` and `Object.entries({ ... })`. Const-bound
// tables cover the common contract-test shape where the named case table is declared immediately
// before the sweep for readability.
function hasFixtureIterable(source: string, start: number, header: string): boolean {
  if (/\bof\s*\[/.test(header) || /\bof\s+Object\.(?:entries|keys|values)\s*\(/.test(header)) {
    return true;
  }
  const iterableName = header.match(/\bof\s+([A-Za-z_$][A-Za-z0-9_$]*)\b/)?.[1] ?? "";
  return iterableName !== "" && (isFixtureConstantIterableName(iterableName) || hasConstBoundFixtureIterable(source.slice(0, start), iterableName));
}

// Accepts const-bound fixture loops only when the iterable name and initializer both look like a
// deterministic case table or discovered fixture set.
function hasConstBoundFixtureIterable(sourceBeforeLoop: string, iterableName: string): boolean {
  if (!isFixtureIterableName(iterableName)) {
    return false;
  }
  const assignment = sourceBeforeLoop.match(new RegExp(`\\bconst\\s+${escapeRegex(iterableName)}\\s*=\\s*([\\s\\S]*?);\\s*$`));
  const initializer = assignment?.[1]?.trim() ?? "";
  return initializer.startsWith("[") || /^Object\.(?:entries|keys|values)\s*\(/.test(initializer) || isFixtureDiscoveryCall(initializer);
}

// Limits const-bound loop suppression to table/sweep vocabulary rather than arbitrary arrays.
function isFixtureIterableName(name: string): boolean {
  return /(?:agents|cases|checks|entries|examples|fixtures|files|ids|paths|records|scenarios|scores|snapshots)$/i.test(name);
}

// UPPER_CASE fixture constants such as HARNESS_CHECKS are named case tables even when imported.
function isFixtureConstantIterableName(name: string): boolean {
  return /^[A-Z0-9_]+$/.test(name) && isFixtureIterableName(name);
}

// Recognises local fixture discovery calls used by contract sweeps without accepting unknown calls.
function isFixtureDiscoveryCall(initializer: string): boolean {
  return /\b(?:glob|globSync|readdir|readdirSync|discover[A-Za-z0-9_$]*|find[A-Za-z0-9_$]*|list[A-Za-z0-9_$]*)\s*\(/.test(initializer);
}

// Integration, contract, smoke, and performance tests naturally need more environment setup than
// focused unit tests; keep the default strict for unit tests and double it for broad-flow suites.
function setupBloatThreshold(file: SourceFile, config: Config): number {
  const baseThreshold = threshold(config, "test-quality.setup-bloat", 12);
  return isBroadFlowTestPath(file.displayPath) ? baseThreshold * 2 : baseThreshold;
}

// Broad-flow tests exercise systems rather than one unit, so longer setup stays below the bloat line.
function isBroadFlowTestPath(path: string): boolean {
  return /(?:^|\/)test\/(?:integration|contract|smoke|performance)\//.test(path);
}

// Structural loop/branch findings now require the control flow to wrap an assertion; setup-only
// conditionals and fixture-building loops are noisy but not direct test-quality failures.
function controlFlowContainsAssertion(source: string, pattern: RegExp): boolean {
  for (const match of source.matchAll(pattern)) {
    const start = match.index ?? 0;
    const segment = controlFlowSegment(source, start);
    if (hasAssertion(segment) && !isInvariantAssertionConditional(source, start, segment)) {
      return true;
    }
  }
  return false;
}

// Accepts guard conditionals whose assertion proves a shared invariant rather than branch policy.
function isInvariantAssertionConditional(source: string, start: number, segment: string): boolean {
  const condition = segment.slice(0, Math.max(0, segment.indexOf("{"))).trim();
  return isFixtureMembershipGuard(source.slice(0, start), condition);
}

// Membership guards over const-bound fixtures keep invariant sweeps readable.
function isFixtureMembershipGuard(sourceBeforeCondition: string, condition: string): boolean {
  const guardTarget = condition.match(/\b([A-Za-z_$][A-Za-z0-9_$]*)\.(?:has|includes)\s*\(/)?.[1] ?? "";
  if (!guardTarget) {
    return false;
  }
  return new RegExp(`\\bconst\\s+${escapeRegex(guardTarget)}\\s*=\\s*(?:new\\s+Set\\s*\\(|\\[)`).test(sourceBeforeCondition);
}

// Captures the smallest control-flow segment so assertion detection does not scan the whole test.
function controlFlowSegment(source: string, start: number): string {
  const lineEnd = source.indexOf("\n", start);
  const openBrace = source.indexOf("{", start);
  if (openBrace === -1 || (lineEnd !== -1 && openBrace > lineEnd)) {
    return source.slice(start, lineEnd === -1 ? source.length : lineEnd);
  }
  const closeBrace = matchingCloseBrace(source, openBrace);
  return source.slice(start, closeBrace === undefined ? openBrace + 1 : closeBrace + 1);
}

// Lightweight brace matcher for already-isolated test block text; enough to bound loop/if bodies.
function matchingCloseBrace(source: string, openBrace: number): number | undefined {
  let depth = 0;
  for (let index = openBrace; index < source.length; index += 1) {
    const character = source[index];
    if (character === "{") {
      depth += 1;
    } else if (character === "}") {
      depth -= 1;
      if (depth === 0) {
        return index;
      }
    }
  }
  return undefined;
}

// Aggregator over the three trivial-assertion shapes - literal-comparison, mirrored-`assert`
// arguments, mirrored-`expect` arguments. Splitting the checks keeps each regex focused and
// debuggable while this top-level keeps the call site for `test-quality.trivial-assertion` short.
function hasTrivialAssertion(source: string): boolean {
  return hasLiteralTrivialAssertion(source) || hasRepeatedAssertArgument(source) || hasRepeatedExpectArgument(source);
}

// Targets `assert.ok(true)` and `assert.equal(literal, sameLiteral)` shapes - both prove nothing
// at runtime. The backreference `\1` is what makes the second pattern detect mirrored literals
// across the supported `equal` / `strictEqual` / `deepEqual` variants.
function hasLiteralTrivialAssertion(source: string): boolean {
  return (
    /\bassert\.ok\s*\(\s*true\s*\)/.test(source) ||
    /\bassert\.(?:equal|strictEqual|deepEqual)\s*\(\s*(true|false|null|undefined|\d+|["'][^"']*["'])\s*,\s*\1\s*\)/.test(source)
  );
}

// Walks every `assert.equal(a, b)` call and normalises both arguments before comparison so that
// `foo;` and `foo` collapse to the same key. Mirrored expressions indicate the assertion would
// pass regardless of behaviour - reports as a trivial assertion.
function hasRepeatedAssertArgument(source: string): boolean {
  for (const match of source.matchAll(/\bassert\.(?:equal|strictEqual|deepEqual)\s*\(\s*([^,\n]+?)\s*,\s*([^,\n)]+?)(?:\s*,|\s*\))/g)) {
    if (normalizeAssertionExpression(match[1] ?? "") === normalizeAssertionExpression(match[2] ?? "")) {
      return true;
    }
  }
  return false;
}

// Jest/Vitest counterpart to `hasRepeatedAssertArgument`. Targets `expect(a).toBe(b)` and the
// equality variants; the matcher set is intentionally narrow so async / negation forms don't
// produce false positives on argument equality.
function hasRepeatedExpectArgument(source: string): boolean {
  for (const match of source.matchAll(/\bexpect\s*\(\s*([^)]+?)\s*\)\s*\.\s*to(?:Be|Equal|StrictEqual)\s*\(\s*([^)]+?)\s*\)/g)) {
    if (normalizeAssertionExpression(match[1] ?? "") === normalizeAssertionExpression(match[2] ?? "")) {
      return true;
    }
  }
  return false;
}

// Trims whitespace and strips a trailing semicolon so that `foo;` and `foo` compare as equal -
// preserves the deterministic mirrored-argument detection across whitespace variations.
function normalizeAssertionExpression(expression: string): string {
  return expression.trim().replace(/;$/, "");
}

// Strips every snapshot-shaped assertion plus `expect.assertions(...)` and re-checks whether any
// assertion remains. A body that empties out is flagged for `test-quality.snapshot-only-test`,
// since snapshot fixtures alone don't constrain behaviour.
function isSnapshotOnlyTest(source: string): boolean {
  if (!/\.\s*toMatch(?:Inline)?Snapshot\s*\(/.test(source)) {
    return false;
  }
  const withoutSnapshots = source
    .replace(/\bexpect\s*\([\s\S]*?\)\s*\.\s*toMatch(?:Inline)?Snapshot\s*\([^)]*\)\s*;?/g, "")
    .replace(/\bexpect\.(?:assertions|hasAssertions)\s*\([^)]*\)\s*;?/g, "");
  return !hasAssertion(withoutSnapshots);
}

// Same shape as `isSnapshotOnlyTest` but for `doesNotThrow` / `not.toThrow`. A test that asserts
// only the absence of an exception is weak - `test-quality.no-throw-only-test` reports it so
// authors can add a real behaviour assertion alongside.
function isNoThrowOnlyTest(source: string): boolean {
  if (!/\bassert\.doesNotThrow\s*\(|\.\s*not\s*\.\s*toThrow\s*\(/.test(source)) {
    return false;
  }
  const withoutNoThrow = source
    .replace(/\bassert\.doesNotThrow\s*\([\s\S]*?\)\s*;?/g, "")
    .replace(/\bexpect\s*\([\s\S]*?\)\s*\.\s*not\s*\.\s*toThrow\s*\([^)]*\)\s*;?/g, "")
    .replace(/\bexpect\.(?:assertions|hasAssertions)\s*\([^)]*\)\s*;?/g, "");
  return !hasAssertion(withoutNoThrow);
}

// Pulls every numeric expected value out of `expect(...).toBe(n)` and `assert.equal(actual, n)`
// shapes. Small cardinalities and length/count matchers are excluded because the literal often is
// the test contract; larger opaque values still surface for naming or rationale.
function magicNumberAssertions(source: string): Array<{ value: number }> {
  return MAGIC_NUMBER_ASSERTION_PATTERNS.flatMap((candidate) => magicNumberAssertionMatches(source, candidate));
}

const MAGIC_NUMBER_ASSERTION_PATTERNS: MagicNumberAssertionPattern[] = [
  { pattern: /\bexpect\s*\(\s*([^)]+?)\s*\)\s*\.\s*(to(?:Be|Equal|HaveLength|HaveCount))\s*\(\s*(-?\d+(?:\.\d+)?)\s*\)/g, expressionIndex: 1, matcherIndex: 2, valueIndex: 3 },
  { pattern: /\bassert\.(?:equal|strictEqual|deepEqual)\s*\(\s*([^,\n]+?)\s*,\s*(-?\d+(?:\.\d+)?)(?:\s*,|\s*\))/g, expressionIndex: 1, valueIndex: 2 },
];

// Extracts reportable numeric literals for one assertion grammar while keeping HTTP statuses quiet.
function magicNumberAssertionMatches(source: string, candidate: MagicNumberAssertionPattern): Array<{ value: number }> {
  const results: Array<{ value: number }> = [];
  for (const match of source.matchAll(candidate.pattern)) {
    const expression = match[candidate.expressionIndex] ?? "";
    const matcher = candidate.matcherIndex === undefined ? "" : match[candidate.matcherIndex] ?? "";
    const expectedNumber = Number(match[candidate.valueIndex] ?? "0");
    if (!isIgnoredMagicNumberAssertion(expression, matcher, expectedNumber)) {
      results.push({ value: expectedNumber });
    }
  }
  return results;
}

// Centralises the rule's non-findings so cardinal, count, and HTTP-status exemptions stay aligned.
function isIgnoredMagicNumberAssertion(expression: string, matcher: string, expectedNumber: number): boolean {
  return isSmallCardinal(expectedNumber) || isLengthOrCountMatcher(matcher) || isHttpStatusAssertion(expression, expectedNumber);
}

// Small integer cardinals usually express the expected case count directly.
function isSmallCardinal(cardinal: number): boolean {
  return Number.isInteger(cardinal) && cardinal >= -1 && cardinal <= 3;
}

// Length/count matchers already name the measurement, so the numeric literal is the assertion.
function isLengthOrCountMatcher(matcher: string): boolean {
  return matcher === "toHaveLength" || matcher === "toHaveCount";
}

// Contract-named tests may assert the documented number directly; the name supplies the rationale.
function isConstantContractTestName(name: string): boolean {
  return /\b(?:constant|threshold|limit|budget|default|contract)\b/i.test(name);
}

// HTTP response status codes are intentionally numeric at assertion sites; naming every 200/404
// would add ceremony without making the test clearer.
function isHttpStatusAssertion(expression: string, expectedNumber: number): boolean {
  return Number.isInteger(expectedNumber) && expectedNumber >= 100 && expectedNumber <= 599 && /\b(?:status|statusCode)\b/.test(expression);
}

// `const mockX = vi.fn(...)` declarations whose binding appears only once in the body - that one
// occurrence is the declaration itself, so the mock is created but never wired in. Reports the
// names for `test-quality.unused-mock` to anchor on.
function unusedMockVariables(source: string): string[] {
  const names: string[] = [];
  for (const match of source.matchAll(/\bconst\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:(?:vi|jest)\.fn|sinon\.stub|createMock|mock)\s*\(/g)) {
    const name = match[1] ?? "";
    if (name) {
      const escaped = escapeRegex(name);
      if (countMatches(source, new RegExp(`\\b${escaped}\\b`, "g")) <= 1) {
        names.push(name);
      }
    }
  }
  return names;
}

// Three gates in order: a mock factory must exist, a mock-call matcher must be asserted, and
// *every* `expect(target)` argument must look like a mock/stub/spy name. All three together
// signal a test that only verifies its own scaffolding - flagged for `test-quality.mock-only-test`.
function isMockOnlyTest(source: string): boolean {
  if (!/\b(?:vi|jest)\.fn\s*\(|\b(?:createMock|mock|sinon\.stub)\s*\(/.test(source)) {
    return false;
  }
  if (!/\.(?:toHaveBeenCalled|toHaveBeenCalledWith|toHaveBeenNthCalledWith|toBeCalled|toBeCalledWith)\s*\(/.test(source)) {
    return false;
  }
  const targets = [...source.matchAll(/\bexpect\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\)/g)].map((match) => match[1] ?? "");
  return targets.length > 0 && targets.every((target) => /(?:mock|stub|spy)$/i.test(target));
}

// `toThrow(Error)` / `assert.throws(fn, Error)` constrain only the constructor, not the message
// or properties. Reports `test-quality.exception-type-only` so authors tighten the assertion.
function hasExceptionTypeOnlyAssertion(source: string): boolean {
  return /\.toThrow\s*\(\s*(?:Error|[A-Z][A-Za-z0-9_$]*Error)\s*\)/.test(source) || /\bassert\.throws\s*\([^,\n]+,\s*(?:Error|[A-Z][A-Za-z0-9_$]*Error)\s*\)/.test(source);
}

// Three known anti-patterns: writing to `process.env`, writing to `globalThis.*`, or reassigning
// `Date.now` / `Math.random`. Each leaks state across tests; reports
// `test-quality.global-state-mutation` so the author isolates the fixture.
function hasGlobalStateMutation(source: string): boolean {
  return /\bprocess\.env\.[A-Za-z0-9_]+\s*=/.test(source) || /\bglobalThis\.[A-Za-z0-9_$]+\s*=/.test(source) || /\b(?:Date\.now|Math\.random)\s*=/.test(source);
}
