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

// Returns the base measurement used only when a caller has no parsed script, such as a legacy span probe.
export function baseComplexityMetrics(): ComplexityMetrics {
  return {
    cyclomatic: 1,
    cognitive: 1,
    maximumControlFlowNesting: 0,
    breakdown: emptyBreakdown(),
  };
}

// Measures one parsed callable without reparsing the source or walking another reported callable.
// It reports one deterministic breakdown to CLI complexity findings and documentation checks.
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

// Walks one node using the counting law, carrying only control-flow depth between syntax children.
function walkComplexityNode(node: TypeScriptNode, controlFlowDepth: number, context: ComplexityWalkContext): void {
  // When M07 reports a nested callable separately, its body belongs to that report block, not this parent.
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
  // A switch is one dispatch decision however many cases it has, and one control-flow nesting level.
  if (typescriptSyntax.isSwitchStatement(node)) {
    // A switch with only a default clause chooses nothing, so it adds no decision.
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
  // Logical operators count as decisions but do not deepen control flow.
  if (typescriptSyntax.isBinaryExpression(node)) {
    walkBinaryExpression(node, controlFlowDepth, context);
    return;
  }
  // Optional access, nullish coalescing, ordinary blocks, and presentation syntax keep the same depth.
  walkChildrenAtDepth(node, controlFlowDepth, context);
}

// Counts an if and keeps an `else if` at peer depth while ordinary else bodies stay nested.
// Returning early is the flattening the cognitive advice asks for, so a guard adds its decision but no nesting level.
function walkIfStatement(node: import("typescript").IfStatement, controlFlowDepth: number, context: ComplexityWalkContext): void {
  context.accumulator.ifCount += 1;
  const nestedDepth = isEarlyExitGuard(node) ? controlFlowDepth : enterControlFlow(controlFlowDepth, context.accumulator);
  walkComplexityNode(node.expression, nestedDepth, context);
  walkComplexityNode(node.thenStatement, nestedDepth, context);
  // A source without an else branch has no further control-flow subtree for the user to review.
  if (!node.elseStatement) {
    return;
  }
  // An `else if` is another peer decision, not an extra nesting layer created by AST parentage.
  if (typescriptSyntax.isIfStatement(node.elseStatement)) {
    walkComplexityNode(node.elseStatement, controlFlowDepth, context);
    return;
  }
  walkComplexityNode(node.elseStatement, nestedDepth, context);
}

// Counts each logical binary node once; all other binary operators, including `??`, stay neutral.
function walkBinaryExpression(node: import("typescript").BinaryExpression, controlFlowDepth: number, context: ComplexityWalkContext): void {
  // A user's logical AND adds one decision without changing nesting depth.
  if (node.operatorToken.kind === typescriptSyntax.SyntaxKind.AmpersandAmpersandToken) {
    context.accumulator.logicalAndCount += 1;
  }
  // A user's logical OR adds one decision without changing nesting depth.
  if (node.operatorToken.kind === typescriptSyntax.SyntaxKind.BarBarToken) {
    context.accumulator.logicalOrCount += 1;
  }
  walkChildrenAtDepth(node, controlFlowDepth, context);
}

// Enters one control construct, records the deepest user-visible level, and walks its children there.
function walkNestedControlFlow(node: TypeScriptNode, controlFlowDepth: number, context: ComplexityWalkContext): void {
  const nestedDepth = enterControlFlow(controlFlowDepth, context.accumulator);
  walkChildrenAtDepth(node, nestedDepth, context);
}

// Visits every syntax child at an unchanged depth so punctuation and ordinary braces stay free.
function walkChildrenAtDepth(node: TypeScriptNode, controlFlowDepth: number, context: ComplexityWalkContext): void {
  // Every child stays with the nearest reported callable unless the ownership guard prunes it.
  node.forEachChild((child) => walkComplexityNode(child, controlFlowDepth, context));
}

// Advances and records control-flow depth for an if, loop, switch, catch, or ternary.
function enterControlFlow(controlFlowDepth: number, accumulator: ComplexityAccumulator): number {
  const nestedDepth = controlFlowDepth + 1;
  accumulator.maximumControlFlowNesting = Math.max(accumulator.maximumControlFlowNesting, nestedDepth);
  return nestedDepth;
}

// A guard clause has no else and a body of one return, throw, break or continue, braced or not.
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

// Recognizes every loop syntax counted by the public complexity policy.
function isLoopStatement(node: TypeScriptNode): boolean {
  return typescriptSyntax.isForStatement(node)
    || typescriptSyntax.isForInStatement(node)
    || typescriptSyntax.isForOfStatement(node)
    || typescriptSyntax.isWhileStatement(node)
    || typescriptSyntax.isDoStatement(node);
}

// Builds the fixed zero-valued metadata shape used when a source has no decisions.
// It never throws because no source or parser state is read here.
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
