// Reports test-quality findings developers can act on in each parsed test block.

// Assertion and mock checks run before global-state and structural checks.
// The block orchestrator calls this file when it finds a test body.
import { blockFinding, blockFindingWithMetadata, type FunctionBlock, hasAssertion } from "./blocks.ts";
import { type SourceFile } from "./discovery.ts";
import { escapeRegex } from "./findings-helpers.ts";
import { pushStaticAnalysisRedundantTestFindings, type StaticAnalysisSourceContext } from "./static-analysis-redundant-rules.ts";
import { countMatches, matchingCloseParen } from "./text-scans.ts";
import type { Finding, Severity } from "./types.ts";

// Provisional rule output gathered during a test-block walk. Built before the surrounding context
// (file, line) is known, then promoted into a real Finding by the caller.
interface TestBlockCheck {
  ruleId: string;
  message: string;
  severity: Severity;
}

/**
 * Check a test block in stable order: assertion quality, mock quality, shared-state mutation, and loop structure.
 *
 * @param file - source file used to locate findings
 * @param block - test block whose executable text and location the checks use
 * @param findings - caller's list that receives findings from every check
 * @param staticContext - surrounding source for assertion analysis; omission limits it to the block's own source and starting line
 * @returns Nothing. Appends the findings from this test block to the supplied list.
 */
export function analyseTestBlock(file: SourceFile, block: FunctionBlock, findings: Finding[], staticContext?: StaticAnalysisSourceContext): void {
  const body = block.codeBody;
  const sourceContext = staticContext ?? { source: block.body, codeSource: block.codeBody, startLine: block.startLine };
  analyseAssertionQuality(file, block, body, sourceContext, findings);
  analyseMockQuality(file, block, body, findings);
  analyseGlobalStateMutation(file, block, body, findings);
  analyseTestStructureChecks(file, block, body, findings);
}

// Checks the test body for assertion-quality problems, using the file and block to anchor stable findings.
// Uses the block's original text and staticContext to assess whether static evidence makes an assertion redundant.
// Returns nothing. Appends findings from both checks to the supplied list.
function analyseAssertionQuality(file: SourceFile, block: FunctionBlock, body: string, staticContext: StaticAnalysisSourceContext, findings: Finding[]): void {
  for (const check of assertionQualityChecks(block, body)) {
    findings.push(blockFinding({ ruleId: check.ruleId, message: check.message, file, block, severity: check.severity, pillar: "test-quality" }));
  }
  pushStaticAnalysisRedundantTestFindings(file, block, block.body, body, staticContext, findings);
}

// Return active assertion-quality checks for masked body, using block.name in their messages; an empty list means none matched.
// Predicates are evaluated before filtering, and retained checks keep their declared emission order.
function assertionQualityChecks(block: FunctionBlock, body: string): TestBlockCheck[] {
  const testName = block.name;
  const checks: Array<TestBlockCheck & { active: boolean }> = [
    { active: hasTrivialAssertion(body), ruleId: "test-quality.trivial-assertion", message: `Test \`${testName}\` contains an assertion that compares a value to itself.`, severity: "warning" },
  ];
  return checks.filter((check) => check.active).map(({ active: _active, ...check }) => check);
}

// Checks the test body for unused mock variables, using the file and block to locate each advisory.
// Returns nothing. Appends one stable test-quality.unused-mock finding with the mock name to the supplied list for each match.
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
}

// Checks the test body for changes to process or runtime state that other tests may share.
// Returns nothing. On a match, appends a stable test-quality.global-state-mutation warning for the supplied file and block to findings.
function analyseGlobalStateMutation(file: SourceFile, block: FunctionBlock, body: string, findings: Finding[]): void {
  if (hasGlobalStateMutation(body)) {
    findings.push(blockFinding({ ruleId: "test-quality.global-state-mutation", message: `Test \`${block.name}\` mutates global process or runtime state.`, file, block, severity: "warning", pillar: "test-quality" }));
  }
}

/**
 * Flag loops that may hide which test iteration failed. Confidence is medium because the label heuristic can miss indirect messages.
 *
 * @param file - source file used to locate the advisory
 * @param block - test block used to anchor and name the advisory
 * @param body - test code checked for loops the heuristic considers reportable
 * @param findings - caller's list that receives the advisory
 * @returns Nothing. Appends a stable test-quality.loop-in-test finding when the heuristic matches.
 */
function analyseTestStructureChecks(file: SourceFile, block: FunctionBlock, body: string, findings: Finding[]): void {
  if (controlFlowContainsNonFixtureLoop(body)) {
    findings.push(blockFindingWithMetadata({ ruleId: "test-quality.loop-in-test", message: "Test contains loop logic that hides which iteration failed.", file, block, severity: "advisory", pillar: "test-quality", metadata: {} }));
  }
}

// Return true when masked source contains a for or while segment with an assertion that neither fixture nor labeled-case checks exempt.
// Return false when all scanned loops are exempt or no assertion-bearing loop is found.
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
    if (isLabeledCaseLoop(segment)) {
      continue;
    }
    return true;
  }
  return false;
}

/**
 * Checks whether a loop can skip the loop-in-test finding because its recognized assertions identify the failed case.
 * A multiline message can mention the label. A supported expected operand must equal the label name after trimming.
 * A label can be a loop binding or a const whose initializer mentions that binding directly.
 *
 * @param segment - masked loop text containing the header and body to check
 * @returns True if each recognized chain has a label. False for an unrecognized loop, an unsafe branch, or missing bindings or recognized calls.
 */
function isLabeledCaseLoop(segment: string): boolean {
  const parts = loopSegmentParts(segment);
  if (!parts) {
    return false;
  }
  if (hasUnsafeFixtureLoopBranch("", parts.body)) {
    return false;
  }
  const boundNames = loopBoundNames(parts.header);
  if (boundNames.length === 0) {
    return false;
  }
  const assertionCalls = assertionCallChains(parts.body);
  if (assertionCalls.length === 0) {
    return false;
  }
  const labelNames = [...boundNames, ...loopDerivedLocalNames(parts.body, boundNames)];
  return assertionCalls.every((call) => hasLoopCaseLabel(call, labelNames));
}

// Only call forms with supported per-case label arguments can clear a loop warning; `.should.be` matchers have no proved label form.
const ASSERTION_CALL_OPENER = /\b(?:assert(?:\.[A-Za-z]+|[A-Z][A-Za-z0-9_$]*)?|expect(?:\.(?:assertions|hasAssertions)|[A-Z][A-Za-z0-9_$]*)?|[A-Za-z_$][A-Za-z0-9_$]*Check)\s*(?:<[^;]*?>\s*)?\(/g;
// One chained call such as `.toBe(` after a closed call.
const CHAINED_CALL_LINK = /^\s*\.\s*[A-Za-z_$][A-Za-z0-9_$]*\s*(?:<[^;]*?>\s*)?\(/;

// Return recognized assertion-chain slices from the masked loop body, including nested calls inside their outer assertion slice.
// Skip an unmatched opening call; if a later chained call is unclosed, retain the complete prefix already measured.
// Return an empty list when no opener can be matched.
function assertionCallChains(body: string): string[] {
  const calls: string[] = [];
  let measuredUntil = 0;
  for (const match of body.matchAll(ASSERTION_CALL_OPENER)) {
    const start = match.index ?? 0;
    if (start < measuredUntil) {
      continue;
    }
    let close = matchingCloseParen(body, start + match[0].length - 1);
    if (close === undefined) {
      continue;
    }
    for (let link = body.slice(close + 1).match(CHAINED_CALL_LINK); link; link = body.slice(close + 1).match(CHAINED_CALL_LINK)) {
      const linkClose = matchingCloseParen(body, close + link[0].length);
      if (linkClose === undefined) {
        break;
      }
      close = linkClose;
    }
    calls.push(body.slice(start, close + 1));
    measuredUntil = close + 1;
  }
  return calls;
}

// Return const-local names whose initializer text in body has a whole-word match from boundNames, for use as assertion labels.
// Follow one level only; locals derived solely from other derived locals and unmatched declarations are excluded.
function loopDerivedLocalNames(body: string, boundNames: string[]): string[] {
  const derived: string[] = [];
  for (const match of body.matchAll(/\bconst\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*([^;\n]+)/g)) {
    const initializer = match[2] ?? "";
    if (boundNames.some((name) => new RegExp(`\\b${escapeRegex(name)}\\b`).test(initializer))) {
      derived.push(match[1] ?? "");
    }
  }
  return derived.filter(Boolean);
}

// Identifier names bound by for-of, for-in or C-style headers.
// While-loops bind nothing here, so they never take the labeled opt-out.
function loopBoundNames(header: string): string[] {
  const binding = header.match(/\b(?:const|let|var)\s+([^)]*?)\s+(?:of|in)\b/)?.[1]
    ?? header.match(/\b(?:let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=/)?.[1]
    ?? "";
  return [...binding.matchAll(/[A-Za-z_$][A-Za-z0-9_$]*/g)].map((match) => match[0] ?? "").filter(Boolean);
}

// Return whether the assertion call text in statement labels a case with one of the loop bindings or derived locals in boundNames.
// Look for a whole-word match in argument three for recognized binary assert calls, or in argument two for all other calls.
// A bare name also counts in a binary assert's second argument or a direct expect call's first matcher argument. No match returns false.
function hasLoopCaseLabel(statement: string, boundNames: string[]): boolean {
  const argumentsList = assertionArguments(statement);
  const isBinaryAssert = /^assert\.(?:(?:not)?(?:strictEqual|deepStrictEqual|equal|deepEqual)|throws|rejects|match|doesNotMatch)\b/i.test(statement);
  const isExpect = /^expect\s*\(/.test(statement);
  const message = argumentsList[isBinaryAssert ? 2 : 1] ?? "";
  const matcher = isExpect ? statement.slice((matchingCloseParen(statement, statement.indexOf("(")) ?? statement.length) + 1) : "";
  const expected = isBinaryAssert ? argumentsList[1] ?? "" : isExpect ? assertionArguments(matcher)[0] ?? "" : "";
  return boundNames.some((name) => new RegExp(`\\b${escapeRegex(name)}\\b`).test(message) || expected.trim() === name);
}

// Return comma-separated argument slices from statement's outer call; strings and comments must already be masked.
// Nested delimiters stay within a slice. Unmatched outer parentheses yield an empty list; an empty call retains its interior slice.
function assertionArguments(statement: string): string[] {
  const open = statement.indexOf("(");
  const close = matchingCloseParen(statement, open);
  if (open < 0 || close === undefined) {
    return [];
  }
  const argumentsList: string[] = [];
  let depth = 0;
  let start = open + 1;
  for (let index = start; index < close; index += 1) {
    const character = statement[index] ?? "";
    if ("([{".includes(character)) depth += 1;
    else if (")]}".includes(character)) depth -= 1;
    else if (character === "," && depth === 0) {
      argumentsList.push(statement.slice(start, index));
      start = index + 1;
    }
  }
  argumentsList.push(statement.slice(start, close));
  return argumentsList;
}

// Return whether segment has an accepted fixture iterable and a final non-ignored statement starting with a recognized assertion.
// Uses source before offset start for iterable lookup. Switch, case, or default markers disqualify the loop.
// An if containing an assertion disqualifies it unless the condition matches the fixture membership heuristic.
function isFixtureLoop(source: string, start: number, segment: string): boolean {
  const parts = loopSegmentParts(segment);
  if (!parts || !hasFixtureIterable(source, start, parts.header)) {
    return false;
  }
  if (hasUnsafeFixtureLoopBranch(source.slice(0, start + parts.bodyBraceIndex + 1), parts.body)) {
    return false;
  }
  // A bare void-name marker can follow the terminal assertion without disqualifying the loop. A void-wrapped call still counts.
  const statements = parts.body.split(/[;\n]/).map((statement) => statement.trim()).filter((statement) => statement.length > 0 && statement !== "}" && !/^(?:break|continue)\b/.test(statement) && !/^void\s+[A-Za-z_$][A-Za-z0-9_$]*$/.test(statement));
  const lastStatement = statements[statements.length - 1] ?? "";
  return /^(?:assert\.[a-z]+\s*\(|expect\s*\(|[a-z][A-Za-z0-9_]*\.should(?:Be|Equal)?\s*\()/i.test(lastStatement);
}

// Splits a loop segment into header and body at the body-opening brace, walking past the header's
// balanced parentheses first so that a destructured binding such as `for (const { name } of rows)`
// does not end the header at the destructuring brace. Braceless bodies return undefined.
function loopSegmentParts(segment: string): { header: string; body: string; bodyBraceIndex: number } | undefined {
  const parenIndex = segment.indexOf("(");
  if (parenIndex === -1) {
    return undefined;
  }
  const headerCloseIndex = matchingHeaderCloseParen(segment, parenIndex);
  if (headerCloseIndex === undefined) {
    return undefined;
  }
  const bodyBraceIndex = segment.indexOf("{", headerCloseIndex);
  if (bodyBraceIndex === -1) {
    return undefined;
  }
  return { header: segment.slice(0, bodyBraceIndex), body: segment.slice(bodyBraceIndex + 1, segment.length - 1), bodyBraceIndex };
}

// Return the closing-parenthesis index for the loop-header opener at parenIndex in segment, counting nested parentheses.
// Return undefined if the outer group does not close before segment ends.
function matchingHeaderCloseParen(segment: string, parenIndex: number): number | undefined {
  let depth = 0;
  for (let index = parenIndex; index < segment.length; index += 1) {
    const character = segment[index];
    if (character === "(") {
      depth += 1;
    } else if (character === ")") {
      depth -= 1;
      if (depth === 0) {
        return index;
      }
    }
  }
  return undefined;
}

// Return whether loop body contains a switch-like construct or an assertion-bearing if segment without a recognized fixture-membership guard.
// sourceBeforeLoopBody supplies preceding declarations for guard lookup; other if segments do not reject the fixture loop.
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

// Return whether header looks like an inline fixture iterable or names a recognized fixture constant or const-bound table.
// source and the loop offset start provide preceding declarations for the const-bound check; false means no accepted shape was found.
function hasFixtureIterable(source: string, start: number, header: string): boolean {
  if (/\bof\s*\[/.test(header) || /\bof\s+Object\.(?:entries|keys|values)\s*\(/.test(header)) {
    return true;
  }
  const iterableName = header.match(/\bof\s+([A-Za-z_$][A-Za-z0-9_$]*)\b/)?.[1] ?? "";
  return iterableName !== "" && (isFixtureConstantIterableName(iterableName) || hasConstBoundFixtureIterable(source.slice(0, start), iterableName));
}

// Return whether iterableName has fixture vocabulary and a const assignment in sourceBeforeLoop with an accepted initializer shape.
// The assignment text must reach a semicolon at the end of the prefix, ignoring trailing whitespace.
// A leading array or Object.entries/keys/values call qualifies, as does a recognized discovery call anywhere in that text. No match returns false.
function hasConstBoundFixtureIterable(sourceBeforeLoop: string, iterableName: string): boolean {
  if (!isFixtureIterableName(iterableName)) {
    return false;
  }
  const assignment = sourceBeforeLoop.match(new RegExp(`\\bconst\\s+${escapeRegex(iterableName)}\\s*=\\s*([\\s\\S]*?);\\s*$`));
  const initializer = assignment?.[1]?.trim() ?? "";
  return initializer.startsWith("[") || /^Object\.(?:entries|keys|values)\s*\(/.test(initializer) || isFixtureDiscoveryCall(initializer);
}

// Return whether name has a recognized fixture-table suffix for the loop-exemption heuristic.
function isFixtureIterableName(name: string): boolean {
  return /(?:agents|cases|checks|entries|examples|fixtures|files|ids|paths|records|scenarios|scores|snapshots)$/i.test(name);
}

// Return whether name uses only uppercase letters, digits and underscores and has a fixture suffix; no local declaration is required.
function isFixtureConstantIterableName(name: string): boolean {
  return /^[A-Z0-9_]+$/.test(name) && isFixtureIterableName(name);
}

// Return whether initializer contains a call named glob, globSync, readdir, readdirSync, or beginning with discover, find or list.
// This name heuristic does not verify where the function was declared or whether it discovers fixtures.
function isFixtureDiscoveryCall(initializer: string): boolean {
  return /\b(?:glob|globSync|readdir|readdirSync|discover[A-Za-z0-9_$]*|find[A-Za-z0-9_$]*|list[A-Za-z0-9_$]*)\s*\(/.test(initializer);
}

// Return whether segment's condition matches the fixture-membership guard heuristic using source text before offset start.
// The invariant heuristic checks text before the first opening brace as the condition. With no brace, the guard cannot qualify.
function isInvariantAssertionConditional(source: string, start: number, segment: string): boolean {
  const condition = segment.slice(0, Math.max(0, segment.indexOf("{"))).trim();
  return isFixtureMembershipGuard(source.slice(0, start), condition);
}

// Return whether condition's first has/includes target is declared as a const with a new Set or array initializer in sourceBeforeCondition.
// Return false when the target or its declaration cannot be matched.
function isFixtureMembershipGuard(sourceBeforeCondition: string, condition: string): boolean {
  const guardTarget = condition.match(/\b([A-Za-z_$][A-Za-z0-9_$]*)\.(?:has|includes)\s*\(/)?.[1] ?? "";
  if (!guardTarget) {
    return false;
  }
  return new RegExp(`\\bconst\\s+${escapeRegex(guardTarget)}\\s*=\\s*(?:new\\s+Set\\s*\\(|\\[)`).test(sourceBeforeCondition);
}

// Return bounded control-flow text in masked source beginning at keyword offset start for assertion detection.
// With no same-line body brace, return the rest of that line; an unmatched brace limits the result to the header and opening brace.
function controlFlowSegment(source: string, start: number): string {
  const lineEnd = source.indexOf("\n", start);
  const openBrace = controlFlowBodyBraceIndex(source, start, lineEnd);
  if (openBrace === undefined) {
    return source.slice(start, lineEnd === -1 ? source.length : lineEnd);
  }
  const closeBrace = matchingCloseBrace(source, openBrace);
  return source.slice(start, closeBrace === undefined ? openBrace + 1 : closeBrace + 1);
}

// In masked source, scan from the keyword offset start up to lineEnd for the first opening brace outside parentheses.
// Return its index, or undefined if none is found; lineEnd of -1 uses the end of source.
function controlFlowBodyBraceIndex(source: string, start: number, lineEnd: number): number | undefined {
  const limit = lineEnd === -1 ? source.length : lineEnd;
  let parenDepth = 0;
  for (let index = start; index < limit; index += 1) {
    const character = source[index];
    if (character === "(") {
      parenDepth += 1;
    } else if (character === ")") {
      parenDepth = Math.max(0, parenDepth - 1);
    } else if (character === "{" && parenDepth === 0) {
      return index;
    }
  }
  return undefined;
}

// Return the closing-brace index for the opening-brace offset openBrace in masked source, to bound a loop or conditional body.
// Return undefined when the braces never balance before source ends.
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

// Returns true for assert.ok(true) or for matching operands in the supported assert or expect equality checks in the test source.
// Returns false when none of these forms match, so the caller can skip `test-quality.trivial-assertion`.
function hasTrivialAssertion(source: string): boolean {
  return hasLiteralTrivialAssertion(source) || hasRepeatedAssertArgument(source) || hasRepeatedExpectArgument(source);
}

// Return true for supported assert.ok(true) or identical-literal equality patterns in source, and false otherwise.
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

// Return whether source contains a direct expect equality call using toBe, toEqual or toStrictEqual with identical normalized argument text.
// Async and negated matcher chains do not match; false means no supported pair was found.
function hasRepeatedExpectArgument(source: string): boolean {
  for (const match of source.matchAll(/\bexpect\s*\(\s*([^)]+?)\s*\)\s*\.\s*to(?:Be|Equal|StrictEqual)\s*\(\s*([^)]+?)\s*\)/g)) {
    if (normalizeAssertionExpression(match[1] ?? "") === normalizeAssertionExpression(match[2] ?? "")) {
      return true;
    }
  }
  return false;
}

// Return expression's comparison key after trimming surrounding whitespace and one trailing semicolon, so mirrored arguments compare equally.
function normalizeAssertionExpression(expression: string): string {
  return expression.trim().replace(/;$/, "");
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

// Return whether source matches the supported process.env, globalThis, Date.now or Math.random assignment patterns.
// The caller uses true to report possible shared-state mutation; this textual check does not establish whether state is restored.
function hasGlobalStateMutation(source: string): boolean {
  return /\bprocess\.env\.[A-Za-z0-9_]+\s*=/.test(source) || /\bglobalThis\.[A-Za-z0-9_$]+\s*=/.test(source) || /\b(?:Date\.now|Math\.random)\s*=/.test(source);
}
