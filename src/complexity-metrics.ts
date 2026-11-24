// Syntax-aware complexity measurement for each callable discovered by the shared script parse.
// It turns real decision nodes into the values shown in CLI and JSON findings while leaving
// defaulting, optional access, presentation objects, and ordinary blocks out of the score.
// Nested callable ownership follows the same M07 block inventory, so every body counts once.
import { createRequire } from "node:module";

// TypeScript is CommonJS at runtime; this module only walks nodes from the existing shared parse.
const require = createRequire(import.meta.url);
const typescriptSyntax = require("typescript") as typeof import("typescript");

// Syntax node identity links measurements to the callable inventory from the shared parser.
// Nodes never leave the internal scan pipeline or appear in JSON and UI report payloads.
// Equality is object identity within one parse, which preserves single ownership.
type TypeScriptNode = import("typescript").Node;

/**
 * Stable per-kind decision counts attached to complexity findings for report consumers.
 * Every key is always present, including zero values, so JSON comparisons stay deterministic.
 * `case` counts one decision per switch with a non-default case, however many cases it has.
 * `maxNesting` describes control-flow nesting only, never object or callback braces.
 */
export interface ComplexityBreakdown {
  if: number;
  loop: number;
  catch: number;
  case: number;
  ternary: number;
  logicalAnd: number;
  logicalOr: number;
  maxNesting: number;
}

/**
 * One callable's shared complexity result used by both findings and documentation checks.
 * Cyclomatic starts at one; cognitive adds maximum control-flow nesting to that value.
 * A CLI user reaches these measurements when a configured threshold produces a finding.
 */
export interface ComplexityMetrics {
  cyclomatic: number;
  cognitive: number;
  maximumControlFlowNesting: number;
  breakdown: ComplexityBreakdown;
}

/**
 * Mutable counters used only during one syntax-tree walk for one reported callable.
 * The accumulator is converted to an immutable report-shaped result after traversal.
 * No state survives between files or CLI scans.
 */
interface ComplexityAccumulator {
  ifCount: number;
  loopCount: number;
  catchCount: number;
  caseCount: number;
  ternaryCount: number;
  logicalAndCount: number;
  logicalOrCount: number;
  maximumControlFlowNesting: number;
}

/**
 * Context threaded through the recursive walk so nested callable bodies keep one owner.
 * `callableNode` is the node being measured; `ownedCallableNodes` includes nested callables measured separately.
 * The shared accumulator becomes metadata visible to report and hook consumers.
 */
interface ComplexityWalkContext {
  callableNode: TypeScriptNode;
  ownedCallableNodes: ReadonlySet<TypeScriptNode>;
  accumulator: ComplexityAccumulator;
}

/**
 * Base measurement used only when a caller has no parsed script, such as a legacy span probe.
 *
 * @returns Base complexity metrics with cyclomatic and cognitive complexity of 1, 0 nesting, and a zeroed breakdown.
 */
export function baseComplexityMetrics(): ComplexityMetrics {
  return {
    cyclomatic: 1,
    cognitive: 1,
    maximumControlFlowNesting: 0,
    breakdown: emptyBreakdown(),
  };
}

/**
 * Measures the supplied parsed callable for complexity findings and documentation checks.
 *
 * @param callableNode - Root parsed callable syntax node to measure.
 * @param ownedCallableNodes - Ownership set identifying separately reported nested callables to skip.
 * @returns Cyclomatic and cognitive complexity, maximum nesting, and a breakdown of the counts.
 */
export function complexityMetrics(callableNode: TypeScriptNode, ownedCallableNodes: ReadonlySet<TypeScriptNode>): ComplexityMetrics {
  const accumulator: ComplexityAccumulator = {
    ifCount: 0,
    loopCount: 0,
    catchCount: 0,
    caseCount: 0,
    ternaryCount: 0,
    logicalAndCount: 0,
    logicalOrCount: 0,
    maximumControlFlowNesting: 0,
  };
  const context: ComplexityWalkContext = { callableNode, ownedCallableNodes, accumulator };
  // The root callable owns its parameters and body; separately reported nested callables are pruned below.
  callableNode.forEachChild((child) => walkComplexityNode(child, 0, context));
  const decisionCount = accumulator.ifCount
    + accumulator.loopCount
    + accumulator.catchCount
    + accumulator.caseCount
    + accumulator.ternaryCount
    + accumulator.logicalAndCount
    + accumulator.logicalOrCount;
  const cyclomatic = decisionCount + 1;
  const breakdown: ComplexityBreakdown = {
    if: accumulator.ifCount,
    loop: accumulator.loopCount,
    catch: accumulator.catchCount,
    case: accumulator.caseCount,
    ternary: accumulator.ternaryCount,
    logicalAnd: accumulator.logicalAndCount,
    logicalOr: accumulator.logicalOrCount,
    maxNesting: accumulator.maximumControlFlowNesting,
  };
  return {
    cyclomatic,
    cognitive: cyclomatic + accumulator.maximumControlFlowNesting,
    maximumControlFlowNesting: accumulator.maximumControlFlowNesting,
    breakdown,
  };
}

/**
 * Measures the supplied syntax node and its owned descendants from the current control-flow depth,
 * pruning reported nested callables to preserve separate totals.
 *
 * @param node - Current syntax node being visited during traversal.
 * @param controlFlowDepth - Current control-flow nesting depth at this node.
 * @param context - Walk state carrying the root callable, ownership set, and mutable accumulator.
 * @returns Nothing. Updates counts and maximum nesting in the walk context.
 */
function walkComplexityNode(node: TypeScriptNode, controlFlowDepth: number, context: ComplexityWalkContext): void {
  // A separately reported nested callable contributes to its own measurements.
  if (node !== context.callableNode && context.ownedCallableNodes.has(node)) {
    return;
  }
  // An if adds one decision; an early-exit guard keeps the current nesting level.
  if (typescriptSyntax.isIfStatement(node)) {
    walkIfStatement(node, controlFlowDepth, context);
    return;
  }
  // Every loop form adds one decision and one control-flow nesting level.
  if (isLoopStatement(node)) {
    context.accumulator.loopCount += 1;
    walkNestedControlFlow(node, controlFlowDepth, context);
    return;
  }
  // A switch adds one nesting level. A switch with any case clause also adds one dispatch decision.
  if (typescriptSyntax.isSwitchStatement(node)) {
    if (node.caseBlock.clauses.some((clause) => typescriptSyntax.isCaseClause(clause))) {
      context.accumulator.caseCount += 1;
    }
    walkNestedControlFlow(node, controlFlowDepth, context);
    return;
  }
  // Catch represents one recovery path and one control-flow nesting level.
  if (typescriptSyntax.isCatchClause(node)) {
    context.accumulator.catchCount += 1;
    walkNestedControlFlow(node, controlFlowDepth, context);
    return;
  }
  // A conditional expression adds one decision and one control-flow nesting level.
  if (typescriptSyntax.isConditionalExpression(node)) {
    context.accumulator.ternaryCount += 1;
    walkNestedControlFlow(node, controlFlowDepth, context);
    return;
  }
  // Logical AND and OR add decisions at the current nesting depth.
  if (typescriptSyntax.isBinaryExpression(node)) {
    walkBinaryExpression(node, controlFlowDepth, context);
    return;
  }
  // Optional access, nullish coalescing, ordinary blocks, and presentation syntax keep the same depth.
  walkChildrenAtDepth(node, controlFlowDepth, context);
}

/**
 * Records the supplied if statement and its branches in the walk context's complexity totals.
 * Uses the incoming depth for an early-exit guard and else-if peers; other branch bodies add a nesting level.
 *
 * @param node - Parsed `if` statement whose condition and branches are visited.
 * @param controlFlowDepth - Incoming control-flow nesting depth before entering this statement.
 * @param context - Walk state holding the mutable complexity accumulator and ownership set.
 * @returns Nothing. Increments `ifCount` and recurses through the condition, then, and else branches.
 */
function walkIfStatement(node: import("typescript").IfStatement, controlFlowDepth: number, context: ComplexityWalkContext): void {
  context.accumulator.ifCount += 1;
  const nestedDepth = isEarlyExitGuard(node) ? controlFlowDepth : enterControlFlow(controlFlowDepth, context.accumulator);
  walkComplexityNode(node.expression, nestedDepth, context);
  walkComplexityNode(node.thenStatement, nestedDepth, context);
  if (!node.elseStatement) {
    return;
  }
  // Visit an else-if at the incoming depth so the chain stays a set of peer decisions.
  if (typescriptSyntax.isIfStatement(node.elseStatement)) {
    walkComplexityNode(node.elseStatement, controlFlowDepth, context);
    return;
  }
  walkComplexityNode(node.elseStatement, nestedDepth, context);
}

/**
 * Counts a logical AND or OR in the supplied walk context and visits both operands at the supplied depth.
 * Other binary operators add no decision of their own.
 *
 * @param node - Binary expression syntax node to inspect for logical operators.
 * @param controlFlowDepth - Current control-flow nesting depth passed to both operands.
 * @param context - Walk state holding the accumulator updated with logical operator counts.
 * @returns Nothing. Updates `logicalAndCount` or `logicalOrCount` in `context` and walks child operands.
 */
function walkBinaryExpression(node: import("typescript").BinaryExpression, controlFlowDepth: number, context: ComplexityWalkContext): void {
  if (node.operatorToken.kind === typescriptSyntax.SyntaxKind.AmpersandAmpersandToken) {
    context.accumulator.logicalAndCount += 1;
  }
  if (node.operatorToken.kind === typescriptSyntax.SyntaxKind.BarBarToken) {
    context.accumulator.logicalOrCount += 1;
  }
  walkChildrenAtDepth(node, controlFlowDepth, context);
}

/**
 * Visits a control-flow construct's children one level deeper than the supplied depth.
 *
 * @param node - Control-flow construct whose children execute at increased nesting depth.
 * @param controlFlowDepth - Control-flow nesting depth prior to entering this construct.
 * @param context - Walk state whose accumulator tracks maximum nesting and child decisions.
 * @returns Nothing. Updates maximum nesting and accumulates the children's decisions in the walk context.
 */
function walkNestedControlFlow(node: TypeScriptNode, controlFlowDepth: number, context: ComplexityWalkContext): void {
  const nestedDepth = enterControlFlow(controlFlowDepth, context.accumulator);
  walkChildrenAtDepth(node, nestedDepth, context);
}

/**
 * Visits the supplied node's children at the given depth so ordinary braces add no nesting.
 *
 * @param node - Parent syntax node whose direct children are traversed.
 * @param controlFlowDepth - Control-flow nesting depth preserved across the child traversal.
 * @param context - Walk state used to enforce callable ownership and accumulate child measurements.
 * @returns Nothing. Accumulates the children's measurements into the supplied walk context.
 */
function walkChildrenAtDepth(node: TypeScriptNode, controlFlowDepth: number, context: ComplexityWalkContext): void {
  // Every child stays with the nearest reported callable unless the ownership guard prunes it.
  node.forEachChild((child) => walkComplexityNode(child, controlFlowDepth, context));
}

/**
 * Enters a nested control-flow level and raises the supplied accumulator's maximum if the new depth exceeds it.
 *
 * @param controlFlowDepth - Current control-flow nesting depth before entering the construct.
 * @param accumulator - Mutable complexity accumulator whose `maximumControlFlowNesting` is updated.
 * @returns Current control-flow depth plus one.
 */
function enterControlFlow(controlFlowDepth: number, accumulator: ComplexityAccumulator): number {
  const nestedDepth = controlFlowDepth + 1;
  accumulator.maximumControlFlowNesting = Math.max(accumulator.maximumControlFlowNesting, nestedDepth);
  return nestedDepth;
}

/**
 * Determines whether an `if` statement is an early-exit guard clause.
 * A guard clause has no else and a body of one return, throw, break, or continue, braced or not.
 *
 * @param node - Parsed `if` statement to check for early-exit guard structure.
 * @returns True when `node` has no `elseStatement` and a single exit statement body; otherwise false.
 */
function isEarlyExitGuard(node: import("typescript").IfStatement): boolean {
  if (node.elseStatement) {
    return false;
  }
  const body = typescriptSyntax.isBlock(node.thenStatement) ? node.thenStatement.statements : [node.thenStatement];
  const exit = body.length === 1 ? body[0] : undefined;
  return exit !== undefined && (typescriptSyntax.isReturnStatement(exit)
    || typescriptSyntax.isThrowStatement(exit)
    || typescriptSyntax.isBreakStatement(exit)
    || typescriptSyntax.isContinueStatement(exit));
}

/**
 * Recognizes every loop syntax counted by the public complexity policy.
 *
 * @param node - Syntax node to test against `for`, `for..in`, `for..of`, `while`, and `do..while` forms.
 * @returns True when `node` is one of the counted loop statement kinds; otherwise false.
 */
function isLoopStatement(node: TypeScriptNode): boolean {
  return typescriptSyntax.isForStatement(node)
    || typescriptSyntax.isForInStatement(node)
    || typescriptSyntax.isForOfStatement(node)
    || typescriptSyntax.isWhileStatement(node)
    || typescriptSyntax.isDoStatement(node);
}

/**
 * Creates a fresh zeroed breakdown for the base measurement used when a callable has no computed metrics.
 *
 * @returns Fresh breakdown with every decision counter and `maxNesting` set to zero.
 */
function emptyBreakdown(): ComplexityBreakdown {
  return {
    if: 0,
    loop: 0,
    catch: 0,
    case: 0,
    ternary: 0,
    logicalAnd: 0,
    logicalOr: 0,
    maxNesting: 0,
  };
}
