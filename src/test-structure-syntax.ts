// Uses each test's shared syntax node to distinguish control scaffolding from test policy.
import { createRequire } from "node:module";
import type { CallExpression, Node, Statement } from "typescript";

const require = createRequire(import.meta.url);
const syntax = require("typescript") as typeof import("typescript");

// Legacy text-only callers retain their existing checks when no shared callable is available.
interface TestStructureResult {
  hasFixedWait: boolean;
  hasConditionalAssertion: boolean;
  hasCommittedSkip: boolean;
}

/**
 * Inspect test-owned control flow without parsing the script again.
 *
 * @param callable - shared test callback; absent for legacy text-only probes
 * @returns structural decisions, or undefined when the caller must use its text fallback
 */
export function testStructureSyntax(callable: Node | undefined): TestStructureResult | undefined {
  if (!callable) return undefined;
  const result = { hasFixedWait: false, hasConditionalAssertion: false, hasCommittedSkip: false };
  // Visit shared nodes once; nested callbacks remain visible to timer and skip checks.
  const visit = (node: Node): void => {
    if (syntax.isCallExpression(node)) {
      result.hasFixedWait ||= isFixedWait(node, callable);
      result.hasCommittedSkip ||= isCommittedSkip(node, callable);
    }
    if ((syntax.isIfStatement(node) || syntax.isSwitchStatement(node))
      && containsAssertion(node) && !isAllowedConditional(node)) {
      result.hasConditionalAssertion = true;
    }
    syntax.forEachChild(node, visit);
  };
  visit(callable);
  return result;
}

// A clock switch inside a nested callback does not prove that the test activated it before its timer.
function isTestOwned(node: Node, callable: Node): boolean {
  for (let parent = node.parent; parent && parent !== callable; parent = parent.parent) {
    if (syntax.isFunctionLike(parent)) return false;
  }
  return true;
}

// Direct callbacks can execute assertions as part of the workflow; assigned helpers need their own call evidence.
function isInlineCallback(node: Node): boolean {
  const owner = node.parent;
  return (syntax.isCallExpression(owner) || syntax.isNewExpression(owner))
    && (owner.arguments?.some((argument) => argument === node) ?? false);
}

// A surrounding branch can gate assertions in its inline callbacks as well as direct assertions.
function containsAssertion(node: Node): boolean {
  if (syntax.isCallExpression(node) && isAssertionCall(node)) return true;
  if (syntax.isFunctionLike(node) && !isInlineCallback(node)) return false;
  return syntax.forEachChild(node, containsAssertion) ?? false;
}

// Keep the existing assertion-helper spellings when moving their control-flow check onto syntax nodes.
function isAssertionCall(call: CallExpression): boolean {
  return /(?:^|\.)(?:assert(?:\.|[A-Z]|$)|expect(?:\.|\(|[A-Z]|$)|[A-Za-z_$][\w$]*Check$)/.test(call.expression.getText());
}

// Host guards select supported platforms; narrowing guards require a prior assertion proving the tag.
function isAllowedConditional(node: import("typescript").IfStatement | import("typescript").SwitchStatement): boolean {
  if (!syntax.isIfStatement(node)) return false;
  if (isHostExpression(node.expression) && containsHostRead(node.expression)) return true;
  const statements = syntax.isBlock(node.thenStatement) ? node.thenStatement.statements : [node.thenStatement];
  if (statements.length > 0 && statements.every(isFailureStatement) && !node.elseStatement) return true;
  return !node.elseStatement && isProvedNarrowing(node, statements);
}

// Every non-literal operand must read an explicit host capability; mixed result-policy guards still report.
function isHostExpression(node: Node): boolean {
  if (syntax.isParenthesizedExpression(node) || syntax.isTypeOfExpression(node)) {
    return isHostExpression(node.expression);
  }
  if (syntax.isPrefixUnaryExpression(node)) return isHostExpression(node.operand);
  if (syntax.isBinaryExpression(node)) {
    return /^(?:===?|!==?|&&|\|\||[<>]=?)$/.test(node.operatorToken.getText())
      && isHostExpression(node.left) && isHostExpression(node.right);
  }
  if (syntax.isStringLiteralLike(node) || syntax.isNumericLiteral(node)
    || node.kind === syntax.SyntaxKind.TrueKeyword || node.kind === syntax.SyntaxKind.FalseKeyword) return true;
  const text = node.getText();
  return /^(?:process\.(?:platform|arch)|process\.env(?:\.[A-Za-z_$][\w$]*|\[["'][^"']+["']\])|(?:os\.(?:platform|type|arch)|process\.get(?:e?uid|e?gid))\(\))$/.test(text);
}

// A constant condition alone is not host scaffolding, even though literals can occur in host comparisons.
function containsHostRead(node: Node): boolean {
  if ((syntax.isPropertyAccessExpression(node) || syntax.isCallExpression(node)) && isHostExpression(node)) return true;
  return syntax.forEachChild(node, containsHostRead) ?? false;
}

// These branches fail the test directly rather than choosing which expected outcome to assert.
function isFailureStatement(statement: Statement): boolean {
  return syntax.isThrowStatement(statement) || syntax.isExpressionStatement(statement)
    && syntax.isCallExpression(statement.expression) && statement.expression.expression.getText() === "assert.fail";
}

// Require the immediately preceding assertion because intervening mutation can invalidate the narrowed value.
function isProvedNarrowing(node: import("typescript").IfStatement, statements: readonly Statement[]): boolean {
  const proof = precedingDiscriminantAssertion(node);
  if (!proof || statements.length === 0) return false;
  const { discriminant, expected } = proof;
  const condition = node.expression.getText().replace(/\s+/g, "");
  const proved = condition === `!${discriminant}` && expected === "false"
    || condition === discriminant && expected === "true"
    || condition === `${discriminant}===${expected}` || condition === `${discriminant}==${expected}`;
  const base = discriminant.split(".")[0] ?? "";
  return proved && base !== "" && statements.every((statement) => assertionReadsBase(statement, base));
}

// Only a direct preceding equality assertion establishes the discriminant's expected value.
function precedingDiscriminantAssertion(node: import("typescript").IfStatement): { discriminant: string; expected: string } | undefined {
  if (!syntax.isBlock(node.parent)) return undefined;
  const previous = node.parent.statements[node.parent.statements.indexOf(node) - 1];
  if (!previous || !syntax.isExpressionStatement(previous) || !syntax.isCallExpression(previous.expression)) return undefined;
  const assertion = previous.expression;
  if (!/^assert\.(?:equal|strictEqual)$/.test(assertion.expression.getText())) return undefined;
  const discriminant = assertion.arguments[0]?.getText() ?? "";
  const expected = assertion.arguments[1]?.getText() ?? "";
  return { discriminant, expected };
}

// A narrowing branch may verify the same result, but cannot hide mutations or unrelated assertions.
function assertionReadsBase(statement: Statement, base: string): boolean {
  if (!syntax.isExpressionStatement(statement) || !syntax.isCallExpression(statement.expression)) return false;
  const call = statement.expression;
  const actual = call.arguments[0]?.getText() ?? "";
  return isAssertionCall(call) && (actual === base || actual.startsWith(`${base}.`));
}

// A guarded runtime skip has a reason. Registration skips and every .only call still report.
function isCommittedSkip(call: CallExpression, callable: Node): boolean {
  if (!syntax.isPropertyAccessExpression(call.expression)) return false;
  const member = call.expression.name.text;
  if (member === "only") return true;
  if (member !== "skip") return false;
  const receiver = call.expression.expression.getText();
  const parameters = "parameters" in callable ? (callable as import("typescript").FunctionLikeDeclaration).parameters : [];
  const isContext = parameters.some((parameter) => parameter.name.getText() === receiver);
  if (/^(?:it|test|describe|context)$/.test(receiver) && !isContext) return true;
  return call.arguments.length === 0 || !hasSkipGuard(call, callable);
}

// Follow the skip's actual ancestors so an adjacent guard cannot hide an unconditional skip.
function hasSkipGuard(call: CallExpression, callable: Node): boolean {
  for (let parent: Node = call; parent !== callable && parent.parent; parent = parent.parent) {
    const owner = parent.parent;
    if (syntax.isIfStatement(owner) && (owner.thenStatement === parent || owner.elseStatement === parent)) return true;
    if (syntax.isCatchClause(owner) || syntax.isConditionalExpression(owner) && owner.condition !== parent) return true;
    if (syntax.isBinaryExpression(owner) && owner.right === parent
      && [syntax.SyntaxKind.AmpersandAmpersandToken, syntax.SyntaxKind.BarBarToken].includes(owner.operatorToken.kind)) return true;
    if (syntax.isFunctionLike(owner) && owner !== callable) break;
  }
  return false;
}

// Timer fixtures and explicit fake clocks do not impose a fixed wait on the test workflow.
function isFixedWait(call: CallExpression, callable: Node): boolean {
  const target = call.expression.getText();
  if (!/(?:^|\.)(?:setTimeout|sleep|waitForTimeout)$/.test(target)) return false;
  if (usesFakeClock(call, callable) || isTimerFixture(call, callable)) return false;
  if (/(?:^|\.)setTimeout$/.test(target) && isFailureDeadline(call, callable)) return false;
  return true;
}

// A local fake-clock switch must remain active at the timer; a later useRealTimers cancels it.
function usesFakeClock(call: CallExpression, callable: Node): boolean {
  if (hasActiveLocalFakeClock(call, callable)) return true;
  for (let parent = call.parent; parent; parent = parent.parent) {
    if (syntax.isCallExpression(parent) && /^(?:fakeAsync|fakeAsyncTestZone\.run)$/.test(parent.expression.getText())) return true;
    if (parent === callable.parent) break;
  }
  return false;
}

// Read actual clock-switch calls so comments, strings and unexecuted helper bodies cannot enable a fake clock.
function hasActiveLocalFakeClock(timer: CallExpression, callable: Node): boolean {
  let isActive = false;
  // Only preceding test-owned switches can affect this timer's clock.
  const visit = (node: Node): void => {
    if (node.getStart() >= timer.getStart()) return;
    if (syntax.isCallExpression(node) && isTestOwned(node, callable)) {
      const target = node.expression.getText();
      if (/^(?:jest|vi)\.useFakeTimers$/.test(target)) isActive = true;
      else if (/^(?:jest|vi)\.useRealTimers$/.test(target)) isActive = false;
    }
    syntax.forEachChild(node, visit);
  };
  visit(callable);
  return isActive;
}

// A deferred validator with no elapsed-time delay expresses pending state. Other nested callbacks
// can still impose real waits, so callback nesting alone cannot exempt a timer.
function isTimerFixture(call: CallExpression, callable: Node): boolean {
  const delay = call.arguments[1];
  const isDeferred = !delay || syntax.isNumericLiteral(delay) && Number(delay.text) === 0;
  for (let parent = call.parent; parent && parent !== callable; parent = parent.parent) {
    if (isDeferred && syntax.isPropertyAssignment(parent) && parent.name.getText() === "loader") return true;
  }
  if (syntax.isPropertyAccessExpression(call.expression)) {
    const receiver = call.expression.expression.getText();
    return new RegExp(`\\bconst\\s+${receiver.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*=\\s*\\{[\\s\\S]*?setTimeout\\s*:`).test(callable.getText());
  }
  return false;
}

// Deadline callbacks may clean up resources, but must end by throwing or rejecting the owning promise.
function isFailureDeadline(call: CallExpression, callable: Node): boolean {
  const callback = timerCallback(call, callable);
  if (!callback || !syntax.isArrowFunction(callback) && !syntax.isFunctionExpression(callback)) return false;
  const body = callback.body;
  const last = syntax.isBlock(body) ? body.statements.at(-1) : body;
  if (!last) return false;
  if (syntax.isThrowStatement(last)) return true;
  const expression = syntax.isExpressionStatement(last) ? last.expression : last;
  if (!syntax.isCallExpression(expression) || !syntax.isIdentifier(expression.expression)) return false;
  return isOwningPromiseReject(call, callable, expression.expression.text);
}

// The Promise executor's second parameter proves rejection without relying on a conventional name.
function isOwningPromiseReject(call: CallExpression, callable: Node, name: string): boolean {
  for (let parent = call.parent; parent && parent !== callable; parent = parent.parent) {
    if ((syntax.isArrowFunction(parent) || syntax.isFunctionExpression(parent))
      && syntax.isNewExpression(parent.parent) && parent.parent.expression.getText() === "Promise") {
      return parent.parameters[1]?.name.getText() === name;
    }
  }
  return false;
}

// Follow one uniquely declared callback so a named rejection fallback has the same proof as an inline one.
function timerCallback(call: CallExpression, callable: Node): import("typescript").Expression | undefined {
  const callback = call.arguments[0];
  if (!callback || !syntax.isIdentifier(callback)) return callback;
  const declarations: import("typescript").VariableDeclaration[] = [];
  // Multiple declarations leave callback identity ambiguous and cannot establish a deadline exemption.
  const visit = (node: Node): void => {
    if (syntax.isVariableDeclaration(node) && node.name.getText() === callback.text) declarations.push(node);
    syntax.forEachChild(node, visit);
  };
  visit(callable);
  return declarations.length === 1 ? declarations[0]?.initializer : undefined;
}
