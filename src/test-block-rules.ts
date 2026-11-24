// Evaluates test-quality rules on each parsed `test(...)` or `it(...)` block in a project scan.
//
// Checks for unlabeled loops inside tests and overly broad test structure patterns while exempting clear table-driven tests.
// Called by the block orchestrator whenever a discovered callable is flagged as a test registration.
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

/**
 * Checks the test body for assertion-quality problems and static-analysis redundancy.
 * Uses the block's original text and staticContext to assess whether static evidence makes an assertion redundant.
 *
 * @param file - source file used to anchor stable findings
 * @param block - test block providing original text and location metadata for findings
 * @param body - masked test body scanned by assertion-quality checks
 * @param staticContext - surrounding source context used to evaluate redundant assertions
 * @param findings - caller's list that receives findings from both checks
 * @returns Nothing. Appends stable findings from both assertion-quality checks to the supplied list.
 */
function analyseAssertionQuality(file: SourceFile, block: FunctionBlock, body: string, staticContext: StaticAnalysisSourceContext, findings: Finding[]): void {
  for (const check of assertionQualityChecks(block, body)) {
    findings.push(blockFinding({ ruleId: check.ruleId, message: check.message, file, block, severity: check.severity, pillar: "test-quality" }));
  }
  pushStaticAnalysisRedundantTestFindings(file, block, block.body, body, staticContext, findings);
}

/**
 * Return active assertion-quality checks for the masked test body.
 * Predicates are evaluated before filtering, and retained checks keep their declared emission order.
 *
 * @param block - test block whose name appears in emitted check messages
 * @param body - masked test body scanned for trivial assertions
 * @returns Matched assertion-quality checks in declared order, or an empty list when none matched.
 */
function assertionQualityChecks(block: FunctionBlock, body: string): TestBlockCheck[] {
  const testName = block.name;
  const checks: Array<TestBlockCheck & { active: boolean }> = [
    { active: hasTrivialAssertion(body), ruleId: "test-quality.trivial-assertion", message: `Test \`${testName}\` contains an assertion that compares a value to itself.`, severity: "warning" },
  ];
  return checks.filter((check) => check.active).map(({ active: _active, ...check }) => check);
}

/**
 * Checks the test body for unused mock variables.
 *
 * @param file - source file used to locate each advisory
 * @param block - test block used to anchor each advisory
 * @param body - masked test body scanned for unused mock declarations
 * @param findings - caller's list that receives one advisory per unused mock
 * @returns Nothing. Appends one stable test-quality.unused-mock finding with the mock name to the supplied list for each match.
 */
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

/**
 * Checks the test body for changes to process or runtime state that other tests may share.
 *
 * @param file - source file used to locate the warning
 * @param block - test block used to anchor and name the warning
 * @param body - masked test body checked for shared-state assignments
 * @param findings - caller's list that receives the warning when a mutation matches
 * @returns Nothing. On a match, appends a stable test-quality.global-state-mutation warning for the supplied file and block to findings.
 */
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

/**
 * Checks whether masked source contains a reportable for or while loop with an assertion.
 *
 * @param source - masked test body scanned for loop segments
 * @returns True when a loop with an assertion is exempt by neither fixture nor labeled-case checks; false otherwise.
 */
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
  // Reject the exemption when the loop mixes in assertion forms (`should.be`, `.resolves`/`.rejects`) that have no verified per-case label.
  if (/\.\s*should\s*\.\s*be\s*\./.test(parts.body) || /\.\s*(?:rejects|resolves)\b/.test(parts.body)) {
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
const ASSERTION_CALL_OPENER = /\b(?:assert(?:\.[A-Za-z]+|[A-Z][A-Za-z0-9_$]*)?|expect(?:\.(?:assertions|hasAssertions)|[A-Z][A-Za-z0-9_$]*)?|[A-Za-z_$][A-Za-z0-9_$]*Check)\s*(?:<(?!\s)(?:(?!&&|\|\|)[^;\r\n])+>\s*)?\(/g;
// One chained call such as `.toBe(` after a closed call.
const CHAINED_CALL_LINK = /^\s*\.\s*[A-Za-z_$][A-Za-z0-9_$]*\s*(?:<[^;]*?>\s*)?\(/;

/**
 * Return recognized assertion-chain slices from the masked loop body, including nested assertion calls inside outer assertion arguments.
 * Skip an unmatched opening call or member-chained property call; if a later chained call is unclosed, retain the complete prefix already measured.
 *
 * @param body - masked loop body scanned for assertion openers and chained calls
 * @returns Matched assertion-chain slices in source order, or an empty list when no opener can be matched.
 */
function assertionCallChains(body: string): string[] {
  const calls: string[] = [];
  for (const match of body.matchAll(ASSERTION_CALL_OPENER)) {
    const start = match.index ?? 0;
    // Skip member calls chained onto an earlier expression (such as `foo.expectCheck(`), while keeping nested standalone assertions checked.
    if (start > 0 && body[start - 1] === ".") {
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
  }
  return calls;
}

/**
 * Return const-local names whose initializer text in body has a whole-word match from boundNames, for use as assertion labels.
 * Follow one level only; locals derived solely from other derived locals and unmatched declarations are excluded.
 *
 * @param body - masked loop body searched for const declarations
 * @param boundNames - loop-bound identifier names tested against each const initializer
 * @returns Derived local names eligible as assertion labels.
 */
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

/**
 * Extract identifier names bound by for-of, for-in or C-style headers.
 * While-loops bind nothing here, so they never take the labeled opt-out.
 *
 * @param header - loop header text preceding the body brace
 * @returns Bound identifier names from the loop header, or an empty list when none are declared.
 */
function loopBoundNames(header: string): string[] {
  const binding = header.match(/\b(?:const|let|var)\s+([^)]*?)\s+(?:of|in)\b/)?.[1]
    ?? header.match(/\b(?:let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=/)?.[1]
    ?? "";
  return [...binding.matchAll(/[A-Za-z_$][A-Za-z0-9_$]*/g)].map((match) => match[0] ?? "").filter(Boolean);
}

/**
 * Return whether the assertion call text in statement labels a case with one of the loop bindings or derived locals.
 * Looks for a whole-word match in argument three for binary assert calls or argument two otherwise, plus bare expected operands.
 *
 * @param statement - recognized assertion-chain text from a loop body
 * @param boundNames - loop bindings and derived local names accepted as case labels
 * @returns True when the assertion message or expected operand matches a label name; false otherwise.
 */
function hasLoopCaseLabel(statement: string, boundNames: string[]): boolean {
  const argumentsList = assertionArguments(statement);
  const isBinaryAssert = /^assert\.(?:(?:not)?(?:strictEqual|deepStrictEqual|equal|deepEqual)|throws|rejects|match|doesNotMatch)\b/i.test(statement);
  const isExpect = /^expect\s*\(/.test(statement);
  const message = argumentsList[isBinaryAssert ? 2 : 1] ?? "";
  const matcher = isExpect ? statement.slice((matchingCloseParen(statement, statement.indexOf("(")) ?? statement.length) + 1) : "";
  const expected = isBinaryAssert ? argumentsList[1] ?? "" : isExpect ? assertionArguments(matcher)[0] ?? "" : "";
  return boundNames.some((name) => new RegExp(`\\b${escapeRegex(name)}\\b`).test(message) || expected.trim() === name);
}

/**
 * Return comma-separated argument slices from statement's outer call; strings and comments must already be masked.
 * Nested delimiters stay within a slice.
 *
 * @param statement - masked call expression whose outer argument list is split
 * @returns Argument slices from the outer call (retaining an interior slice on an empty call), or an empty list if parentheses are unmatched.
 */
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

/**
 * Return whether segment has an accepted fixture iterable and a final non-ignored statement starting with a recognized assertion.
 * Switch, case, or default markers disqualify the loop; an assertion-bearing if disqualifies it unless matched as a fixture guard.
 *
 * @param source - masked source surrounding the loop for preceding declaration lookup
 * @param start - character offset in source where the loop keyword begins
 * @param segment - bounded loop text containing header and body
 * @returns True when the loop iterates an accepted fixture table safely and ends with a recognized assertion; false otherwise.
 */
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

/**
 * Splits a loop segment into header and body at the body-opening brace, walking past the header's balanced parentheses first
 * so that a destructured binding such as `for (const { name } of rows)` does not end the header at the destructuring brace.
 *
 * @param segment - bounded loop text beginning at the loop keyword
 * @returns Header slice, body interior slice, and body-brace offset, or undefined for braceless or unclosed headers.
 */
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

/**
 * Find the closing-parenthesis index for the loop-header opener at parenIndex in segment, counting nested parentheses.
 *
 * @param segment - loop text containing the header parentheses
 * @param parenIndex - offset of the header's opening parenthesis inside segment
 * @returns Closing-parenthesis offset in segment, or undefined if the outer group does not close before segment ends.
 */
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

/**
 * Return whether loop body contains a switch-like construct or an assertion-bearing if segment without a recognized fixture-membership guard.
 * Other if segments without assertions do not reject the fixture loop.
 *
 * @param sourceBeforeLoopBody - preceding source text supplying declarations for fixture guard lookup
 * @param body - loop body text checked for switch markers and conditional assertions
 * @returns True when an unsafe switch or unguarded assertion branch is found; false otherwise.
 */
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

/**
 * Return whether header looks like an inline fixture iterable or names a recognized fixture constant or const-bound table.
 *
 * @param source - masked source providing preceding declarations for const-bound lookup
 * @param start - character offset in source where the loop begins
 * @param header - loop header text inspected for an inline or named fixture iterable
 * @returns True when the header iterates a recognized fixture iterable; false when no accepted shape was found.
 */
function hasFixtureIterable(source: string, start: number, header: string): boolean {
  if (/\bof\s*\[/.test(header) || /\bof\s+Object\.(?:entries|keys|values)\s*\(/.test(header)) {
    return true;
  }
  const iterableName = header.match(/\bof\s+([A-Za-z_$][A-Za-z0-9_$]*)\b/)?.[1] ?? "";
  return iterableName !== "" && (isFixtureConstantIterableName(iterableName) || hasConstBoundFixtureIterable(source.slice(0, start), iterableName));
}

/**
 * Return whether iterableName has fixture vocabulary and a const assignment in sourceBeforeLoop with an accepted initializer shape.
 * The assignment text must reach a semicolon at the end of the prefix; arrays, Object.entries/keys/values, or discovery calls qualify.
 *
 * @param sourceBeforeLoop - source prefix preceding the loop header
 * @param iterableName - identifier bound by the loop's `of` clause
 * @returns True when the identifier matches fixture vocabulary and an accepted const initializer; false otherwise.
 */
function hasConstBoundFixtureIterable(sourceBeforeLoop: string, iterableName: string): boolean {
  if (!isFixtureIterableName(iterableName)) {
    return false;
  }
  const assignment = sourceBeforeLoop.match(new RegExp(`\\bconst\\s+${escapeRegex(iterableName)}\\s*=\\s*([\\s\\S]*?);\\s*$`));
  const initializer = assignment?.[1]?.trim() ?? "";
  return initializer.startsWith("[") || /^Object\.(?:entries|keys|values)\s*\(/.test(initializer) || isFixtureDiscoveryCall(initializer);
}

/**
 * Check whether an identifier carries a recognized fixture-table suffix for the loop-exemption heuristic.
 *
 * @param name - identifier name from a loop iterable
 * @returns True when the name ends with an accepted fixture-table suffix; false otherwise.
 */
function isFixtureIterableName(name: string): boolean {
  return /(?:agents|cases|checks|entries|examples|fixtures|files|ids|paths|records|scenarios|scores|snapshots)$/i.test(name);
}

/**
 * Check whether an identifier uses only uppercase letters, digits and underscores and has a fixture suffix; no local declaration is required.
 *
 * @param name - identifier name from a loop iterable
 * @returns True when the name matches constant-case naming and a fixture suffix; false otherwise.
 */
function isFixtureConstantIterableName(name: string): boolean {
  return /^[A-Z0-9_]+$/.test(name) && isFixtureIterableName(name);
}

/**
 * Check whether initializer contains a call named glob, globSync, readdir, readdirSync, or beginning with discover, find or list.
 * This name heuristic does not verify where the function was declared or whether it discovers fixtures.
 *
 * @param initializer - trimmed initializer expression from a const fixture binding
 * @returns True when a recognized discovery call pattern appears in the initializer; false otherwise.
 */
function isFixtureDiscoveryCall(initializer: string): boolean {
  return /\b(?:glob|globSync|readdir|readdirSync|discover[A-Za-z0-9_$]*|find[A-Za-z0-9_$]*|list[A-Za-z0-9_$]*)\s*\(/.test(initializer);
}

/**
 * Check whether segment's condition matches the fixture-membership guard heuristic using source text before offset start.
 * The invariant heuristic checks text before the first opening brace as the condition; with no brace, the guard cannot qualify.
 *
 * @param source - preceding source text containing declarations visible before the conditional
 * @param start - character offset in source where the conditional segment starts
 * @param segment - conditional segment text beginning at `if`
 * @returns True when the condition matches the fixture-membership guard heuristic; false otherwise.
 */
function isInvariantAssertionConditional(source: string, start: number, segment: string): boolean {
  const condition = segment.slice(0, Math.max(0, segment.indexOf("{"))).trim();
  return isFixtureMembershipGuard(source.slice(0, start), condition);
}

/**
 * Check whether condition's first has/includes target is declared as a const with a new Set or array initializer in sourceBeforeCondition.
 *
 * @param sourceBeforeCondition - source prefix preceding the conditional statement
 * @param condition - conditional header text before the opening brace
 * @returns True when the guarded target is declared as a const Set or array; false when the target or declaration cannot be matched.
 */
function isFixtureMembershipGuard(sourceBeforeCondition: string, condition: string): boolean {
  const guardTarget = condition.match(/\b([A-Za-z_$][A-Za-z0-9_$]*)\.(?:has|includes)\s*\(/)?.[1] ?? "";
  if (!guardTarget) {
    return false;
  }
  return new RegExp(`\\bconst\\s+${escapeRegex(guardTarget)}\\s*=\\s*(?:new\\s+Set\\s*\\(|\\[)`).test(sourceBeforeCondition);
}

/**
 * Extract bounded control-flow text in masked source beginning at keyword offset start for assertion detection.
 * With no same-line body brace, returns the rest of that line; an unmatched brace limits the result to the header and opening brace.
 *
 * @param source - masked source text containing the control-flow construct
 * @param start - character offset in source where the control-flow keyword begins
 * @returns Bounded control-flow slice starting at the keyword offset.
 */
function controlFlowSegment(source: string, start: number): string {
  const lineEnd = source.indexOf("\n", start);
  const openBrace = controlFlowBodyBraceIndex(source, start, lineEnd);
  if (openBrace === undefined) {
    return source.slice(start, lineEnd === -1 ? source.length : lineEnd);
  }
  const closeBrace = matchingCloseBrace(source, openBrace);
  return source.slice(start, closeBrace === undefined ? openBrace + 1 : closeBrace + 1);
}

/**
 * In masked source, scan from the keyword offset start up to lineEnd for the first opening brace outside parentheses.
 *
 * @param source - masked source text being scanned
 * @param start - character offset of the control-flow keyword
 * @param lineEnd - end-of-line offset bounding the scan, or -1 to scan to the end of source
 * @returns Offset of the first body-opening brace outside parentheses, or undefined if none is found.
 */
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

/**
 * Find the closing-brace index for the opening-brace offset openBrace in masked source, to bound a loop or conditional body.
 *
 * @param source - masked source text containing the braced block
 * @param openBrace - offset of the opening brace in source
 * @returns Offset of the matching closing brace, or undefined when the braces never balance before source ends.
 */
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

/**
 * Check whether the test source contains assert.ok(true) or matching operands in supported assert or expect equality checks.
 *
 * @param source - masked test body scanned for trivial assertions
 * @returns True when a trivial assertion form matches; false when none match, so the caller can skip `test-quality.trivial-assertion`.
 */
function hasTrivialAssertion(source: string): boolean {
  return hasLiteralTrivialAssertion(source) || hasRepeatedAssertArgument(source) || hasRepeatedExpectArgument(source);
}

/**
 * Check for supported assert.ok(true) or identical-literal equality patterns in source.
 *
 * @param source - masked test body scanned for literal trivial assertions
 * @returns True when a literal trivial assertion matches; false otherwise.
 */
function hasLiteralTrivialAssertion(source: string): boolean {
  return (
    /\bassert\.ok\s*\(\s*true\s*\)/.test(source) ||
    /\bassert\.(?:equal|strictEqual|deepEqual)\s*\(\s*(true|false|null|undefined|\d+|["'][^"']*["'])\s*,\s*\1\s*\)/.test(source)
  );
}

/**
 * Walks every `assert.equal(a, b)` call and normalises both arguments before comparison so that
 * `foo;` and `foo` collapse to the same key, because mirrored expressions pass regardless of behaviour.
 *
 * @param source - masked test body scanned for repeated assert arguments
 * @returns True when an assert equality call compares identical normalized arguments; false otherwise.
 */
function hasRepeatedAssertArgument(source: string): boolean {
  for (const match of source.matchAll(/\bassert\.(?:equal|strictEqual|deepEqual)\s*\(\s*([^,\n]+?)\s*,\s*([^,\n)]+?)(?:\s*,|\s*\))/g)) {
    if (normalizeAssertionExpression(match[1] ?? "") === normalizeAssertionExpression(match[2] ?? "")) {
      return true;
    }
  }
  return false;
}

/**
 * Check whether source contains a direct expect equality call using toBe, toEqual or toStrictEqual with identical normalized argument text.
 * Async and negated matcher chains do not match.
 *
 * @param source - masked test body scanned for repeated expect arguments
 * @returns True when a direct expect equality call has identical normalized operands; false means no supported pair was found.
 */
function hasRepeatedExpectArgument(source: string): boolean {
  for (const match of source.matchAll(/\bexpect\s*\(\s*([^)]+?)\s*\)\s*\.\s*to(?:Be|Equal|StrictEqual)\s*\(\s*([^)]+?)\s*\)/g)) {
    if (normalizeAssertionExpression(match[1] ?? "") === normalizeAssertionExpression(match[2] ?? "")) {
      return true;
    }
  }
  return false;
}

/**
 * Build expression's comparison key after trimming surrounding whitespace and one trailing semicolon, so mirrored arguments compare equally.
 *
 * @param expression - raw operand text captured from an assertion call
 * @returns Normalized comparison key for the assertion operand.
 */
function normalizeAssertionExpression(expression: string): string {
  return expression.trim().replace(/;$/, "");
}

/**
 * Find `const mockX = vi.fn(...)` declarations whose binding appears only once in the body,
 * because that single occurrence is the declaration itself and the mock is never wired in.
 *
 * @param source - masked test body scanned for mock variable declarations and references
 * @returns Unused mock variable names for `test-quality.unused-mock` to anchor on.
 */
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

/**
 * Check whether source matches the supported process.env, globalThis, Date.now or Math.random assignment patterns.
 * This textual check does not establish whether state is restored.
 *
 * @param source - masked test body scanned for shared-state assignments
 * @returns True when a supported shared-state assignment pattern matches, used to report possible mutation; false otherwise.
 */
function hasGlobalStateMutation(source: string): boolean {
  return /\bprocess\.env\.[A-Za-z0-9_]+\s*=/.test(source) || /\bglobalThis\.[A-Za-z0-9_$]+\s*=/.test(source) || /\b(?:Date\.now|Math\.random)\s*=/.test(source);
}
