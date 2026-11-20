// Class rules: exported-declaration docs, class/file-name mismatch and readonly candidates.
// Pulls the declaration walkers out of cli.ts so the orchestrator just calls the entry point.
import { exportedDeclarations, pushMissingPublicDocFinding } from "./doc-rules.ts";
import { type SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import { fileBaseName, normalizedIdentifier } from "./findings-helpers.ts";
import { type ParsedScript } from "./parsed-script.ts";
import { publicExportDeclarations, type PublicExportDeclaration } from "./public-exports.ts";
import { byteLine } from "./text-scans.ts";
import type { Config, Finding } from "./types.ts";
import { createRequire } from "node:module";

// Syntax-only TypeScript parser (ADR-012): node guards for walking the shared parse - no type
// checker, program, language service, or emit. Loaded via createRequire because typescript ships
// as CommonJS.
const require = createRequire(import.meta.url);
const typescriptSyntax = require("typescript") as typeof import("typescript");

type TsSourceFile = import("typescript").SourceFile;
type TsNode = import("typescript").Node;
type TsExpression = import("typescript").Expression;
type TsClassLike = import("typescript").ClassLikeDeclaration;

/**
 * Runs class rules in stable order, checking export documentation and file naming before readonly candidates.
 *
 * @param file - source file used for finding anchors and class/file name comparisons
 * @param source - original text used for source lines and documentation checks
 * @param codeSource - masked text searched for declarations and fields
 * @param config - naming configuration, including accepted class/file pairs
 * @param findings - shared collector that receives the class rule findings
 * @param parsed - shared syntax tree. Without it, naming uses direct exports and the readonly check is skipped.
 * @returns Nothing. It appends any findings from the class rules.
 */
export function analyseClassRules(file: SourceFile, source: string, codeSource: string, config: Config, findings: Finding[], parsed?: ParsedScript): void {
  analyseExportedDeclarations(file, source, codeSource, config, findings, parsed);
  analyseReadonlyCandidates(file, source, codeSource, findings, parsed);
}

/**
 * Checks documentation on direct exports, then uses the syntax inventory when available to cover default exports and re-exports in naming checks.
 * This preserves the direct-export documentation contract.
 *
 * @param file - source file used for finding anchors and the class/file name comparison
 * @param source - original text used to locate declarations and leading documentation
 * @param codeSource - masked text searched for direct exports
 * @param config - naming configuration, including accepted class/file pairs
 * @param findings - shared collector for documentation and naming findings
 * @param parsed - shared export syntax. When absent, the naming check uses the direct-export inventory.
 * @returns Nothing. It appends any documentation and class/file naming findings to the collector.
 */
function analyseExportedDeclarations(file: SourceFile, source: string, codeSource: string, config: Config, findings: Finding[], parsed?: ParsedScript): void {
  const directlyExportedDeclarations = exportedDeclarations(source, codeSource);
  // Public-doc findings retain their existing direct-export policy and deterministic source order.
  for (const declaration of directlyExportedDeclarations) {
    pushMissingPublicDocFinding(file, source, declaration, findings);
  }
  // Direct internal callers without a parse retain the legacy five-kind inventory; normal scans use syntax.
  const modulePublicDeclarations = parsed
    ? publicExportDeclarations(parsed)
    : directlyExportedDeclarations.map((declaration) => ({ ...declaration, kind: declaration.kind as PublicExportDeclaration["kind"] }));
  pushClassFileMismatchFinding(file, modulePublicDeclarations, config, findings);
}

/**
 * Reports a class/file mismatch for a sole named public class, using normalized names to avoid warnings for equivalent spellings.
 *
 * @param file - file whose base name is compared and whose path anchors a stable finding
 * @param publicDeclarations - module exports used to decide whether one class represents the file and whether its alias matches
 * @param config - configured class/file pairs that are accepted even when the names differ
 * @param findings - collector that receives the mismatch when the class and its alias differ from the file name
 * @returns Nothing. It appends at most one class/file mismatch finding.
 */
function pushClassFileMismatchFinding(file: SourceFile, publicDeclarations: PublicExportDeclaration[], config: Config, findings: Finding[]): void {
  // Feature modules with a second public declaration do not claim one primary class-to-file convention.
  if (publicDeclarations.length !== 1) {
    return;
  }
  const declaration = publicDeclarations[0];
  // Anonymous defaults and non-class exports have no named class for a user to align with the file.
  if (!declaration || declaration.kind !== "class" || declaration.name === "default") {
    return;
  }
  const fileName = fileBaseName(file.displayPath);
  const acceptedPair = `${fileName}:${declaration.name}`.toLowerCase();
  // Pair-level configuration preserves an intentional feature-file/class-role convention narrowly.
  if (config.acceptedClassFilePairs.has(acceptedPair)) {
    return;
  }
  // A normalized name match already lets a report user locate the class from the file name. An
  // alias counts too: `export { Foo as Bar }` in `bar.ts` already advertises the matching name, so
  // telling the reader to rename would undo an alignment they have made.
  const publicNames = declaration.exportedName === undefined ? [declaration.name] : [declaration.name, declaration.exportedName];
  if (publicNames.some((publicName) => normalizedIdentifier(publicName) === normalizedIdentifier(fileName))) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "naming.class-file-mismatch",
      message: `Exported class \`${declaration.name}\` does not match file name \`${fileName}\`.`,
      filePath: file.displayPath,
      line: declaration.line,
      severity: "advisory",
      pillar: "naming",
      confidence: "medium",
      symbol: declaration.name,
      remediation: "Rename the class or file, or add the exact fileBase:ClassName pair to allowlists.acceptedClassFilePairs.",
      metadata: {
        className: declaration.name,
        fileName,
        candidatePrimaryExport: true,
        publicExports: publicDeclarations.map((publicDeclaration) => `${publicDeclaration.kind}:${publicDeclaration.name}`).sort(),
      },
    }),
  );
}

/**
 * Suggests readonly for typed private instance fields without an initializer when the syntax scan detects no writes outside construction.
 * Restricts candidates to private fields because writes to public or protected fields can occur outside the scanned file.
 *
 * @param file - source file whose display path anchors any finding
 * @param source - original text used to retain stable finding lines
 * @param codeSource - masked text searched for field declarations
 * @param findings - collector that receives readonly candidate findings
 * @param parsed - shared syntax tree used to check writes. A missing parse or syntax diagnostics skip the rule.
 * @returns Nothing. It appends findings for qualifying fields.
 */
function analyseReadonlyCandidates(file: SourceFile, source: string, codeSource: string, findings: Finding[], parsed?: ParsedScript): void {
  const syntax = parsed?.diagnostics.length === 0 ? parsed.sourceFile : undefined;
  if (syntax === undefined) {
    return;
  }
  const constructionOnlyNames = constructionOnlyFieldNameStarts(syntax);
  const readonlyCandidate = /\bprivate\s+(?!readonly\b)([A-Za-z_$][A-Za-z0-9_$]*)\s*:\s*[^;=\n]+;/g;
  for (const match of codeSource.matchAll(readonlyCandidate)) {
    const name = match[1] ?? "";
    const nameStart = (match.index ?? 0) + match[0].indexOf(name, "private".length);
    // A match that is not a field declaration, or a field written after construction, is no candidate.
    if (!constructionOnlyNames.has(nameStart)) {
      continue;
    }
    findings.push(
      makeFinding({
        ruleId: "modernisation.readonly-property-candidate",
        message: `Property \`${name}\` can be marked readonly if it is only assigned during construction.`,
        filePath: file.displayPath,
        line: byteLine(source, match.index ?? 0),
        severity: "advisory",
        pillar: "modernisation",
        confidence: "medium",
        symbol: name,
        remediation: "Mark the property readonly when mutation is not part of the type contract.",
      }),
    );
  }
}

// Scans sourceFile for mutable private instance fields that can proceed to the readonly check.
// Returns name offsets for fields without disqualifying writes, allowing direct this.name writes in the class's own constructor.
// Skips classes with bracket writes on this or Object.assign calls targeting this because the scan treats their targets as uncertain.
function constructionOnlyFieldNameStarts(sourceFile: TsSourceFile): Set<number> {
  const starts = new Set<number>();
  // Returns nothing. Adds candidate field offsets to starts for classes and class expressions in the syntax subtree rooted at node.
  const visit = (node: TsNode): void => {
    if (typescriptSyntax.isClassLike(node)) {
      addConstructionOnlyFields(sourceFile, node, starts);
    }
    node.forEachChild(visit);
  };
  sourceFile.forEachChild(visit);
  return starts;
}

// Returns nothing. Adds the sourceFile name offsets of classNode's readonly candidates to starts.
function addConstructionOnlyFields(sourceFile: TsSourceFile, classNode: TsClassLike, starts: Set<number>): void {
  const written = writtenMemberNames(classNode);
  // Skip readonly suggestions for this class when a bracket write on this or Object.assign(this, ...) leaves the target members uncertain.
  if (written === undefined) {
    return;
  }
  for (const member of classNode.members) {
    if (typescriptSyntax.isPropertyDeclaration(member) && typescriptSyntax.isIdentifier(member.name)
      && isMutablePrivateInstanceField(member) && !written.has(member.name.text)) {
      starts.add(member.name.getStart(sourceFile));
    }
  }
}

// A `private` field that is neither `static` nor already `readonly`.
function isMutablePrivateInstanceField(member: import("typescript").PropertyDeclaration): boolean {
  const kinds = new Set((member.modifiers ?? []).map((modifier) => modifier.kind));
  return kinds.has(typescriptSyntax.SyntaxKind.PrivateKeyword)
    && !kinds.has(typescriptSyntax.SyntaxKind.ReadonlyKeyword)
    && !kinds.has(typescriptSyntax.SyntaxKind.StaticKeyword);
}

/*
 * Scans classNode for identifiable member writes, including writes on other receivers and inside nested functions.
 * Returns their names, excluding direct this.name targets in the class's own constructor. An empty set rules out no fields.
 * Returns undefined for bracket writes on this or Object.assign targeting this so the caller skips readonly suggestions for the class.
 */
function writtenMemberNames(classNode: TsClassLike): Set<string> | undefined {
  const written = new Set<string>();
  let writesDynamically = false;
  // Update written for property targets in target, excluding direct this.name writes in classNode's own constructor.
  // Use write to locate the enclosing constructor; any this[...] target sets writesDynamically instead.
  // Recurse through destructuring targets. On other receivers, record string literals or templates without substitutions. Returns nothing.
  const record = (target: TsExpression, write: TsNode): void => {
    const inner = withoutWrappers(target);
    if (typescriptSyntax.isPropertyAccessExpression(inner)) {
      if (!(isThisKeyword(inner.expression) && isInOwnConstructor(write, classNode))) {
        written.add(inner.name.text);
      }
    } else if (typescriptSyntax.isElementAccessExpression(inner)) {
      if (isThisKeyword(inner.expression)) {
        writesDynamically = true;
      } else if (typescriptSyntax.isStringLiteralLike(inner.argumentExpression)) {
        written.add(inner.argumentExpression.text);
      }
    } else if (typescriptSyntax.isObjectLiteralExpression(inner) || typescriptSyntax.isArrayLiteralExpression(inner)) {
      for (const element of destructuringTargets(inner)) {
        record(element, write);
      }
    }
  };
  // Scan node and its descendants for writes, updating written and writesDynamically through record.
  // Object.assign(this, ...) sets writesDynamically because its sources may supply keys known only at runtime. Returns nothing.
  const visit = (node: TsNode): void => {
    if (typescriptSyntax.isBinaryExpression(node) && isAssignmentOperator(node.operatorToken.kind)) {
      record(node.left, node);
    } else if ((typescriptSyntax.isPrefixUnaryExpression(node) || typescriptSyntax.isPostfixUnaryExpression(node))
      && (node.operator === typescriptSyntax.SyntaxKind.PlusPlusToken || node.operator === typescriptSyntax.SyntaxKind.MinusMinusToken)) {
      record(node.operand, node);
    } else if (typescriptSyntax.isDeleteExpression(node)) {
      record(node.expression, node);
    } else if ((typescriptSyntax.isForOfStatement(node) || typescriptSyntax.isForInStatement(node))
      && !typescriptSyntax.isVariableDeclarationList(node.initializer)) {
      record(node.initializer, node);
    } else if (isObjectAssignToThis(node)) {
      writesDynamically = true;
    }
    node.forEachChild(visit);
  };
  classNode.forEachChild(visit);
  return writesDynamically ? undefined : written;
}

// Returns explicit property-value targets, array targets and rest targets from the destructuring pattern for the member-write scan.
// Defaults contribute only the assigned target. Array holes and shorthand object properties contribute no member target.
function destructuringTargets(pattern: import("typescript").ObjectLiteralExpression | import("typescript").ArrayLiteralExpression): TsExpression[] {
  // Returns the assigned side of `element`: the left of `target = default`, otherwise `element` itself.
  const withoutDefault = (element: TsExpression): TsExpression =>
    typescriptSyntax.isBinaryExpression(element) && element.operatorToken.kind === typescriptSyntax.SyntaxKind.EqualsToken ? element.left : element;
  if (typescriptSyntax.isArrayLiteralExpression(pattern)) {
    return pattern.elements.filter((element) => !typescriptSyntax.isOmittedExpression(element))
      .map((element) => withoutDefault(typescriptSyntax.isSpreadElement(element) ? element.expression : element));
  }
  return pattern.properties.flatMap((property) => {
    if (typescriptSyntax.isPropertyAssignment(property)) {
      return [withoutDefault(property.initializer)];
    }
    return typescriptSyntax.isSpreadAssignment(property) ? [property.expression] : [];
  });
}

// Returns true when write reaches a constructor owned by classNode before crossing another function, class, field or static block.
// This ancestry check also includes writes in constructor parameter initializers.
function isInOwnConstructor(write: TsNode, classNode: TsClassLike): boolean {
  for (let current = write.parent; current !== undefined; current = current.parent) {
    if (typescriptSyntax.isConstructorDeclaration(current)) {
      return current.parent === classNode;
    }
    if (typescriptSyntax.isFunctionLike(current) || typescriptSyntax.isClassLike(current)
      || typescriptSyntax.isPropertyDeclaration(current) || typescriptSyntax.isClassStaticBlockDeclaration(current)) {
      return false;
    }
  }
  return false;
}

// Detects a call spelled Object.assign with this as its first argument so the caller can treat the member writes as uncertain.
function isObjectAssignToThis(node: TsNode): boolean {
  if (!typescriptSyntax.isCallExpression(node) || !typescriptSyntax.isPropertyAccessExpression(node.expression)) {
    return false;
  }
  const callee = node.expression;
  const firstArgument = node.arguments[0];
  return typescriptSyntax.isIdentifier(callee.expression) && callee.expression.text === "Object" && callee.name.text === "assign"
    && firstArgument !== undefined && isThisKeyword(firstArgument);
}

// Returns whether the expression is this after looking through parentheses, non-null assertions, type assertions and satisfies expressions.
function isThisKeyword(expression: TsExpression): boolean {
  return withoutWrappers(expression).kind === typescriptSyntax.SyntaxKind.ThisKeyword;
}

// Returns whether `kind` is `=` or a compound assignment such as `+=` or `??=`.
function isAssignmentOperator(kind: import("typescript").SyntaxKind): boolean {
  return kind >= typescriptSyntax.SyntaxKind.FirstAssignment && kind <= typescriptSyntax.SyntaxKind.LastAssignment;
}

// Returns the underlying write target or receiver after stripping parentheses, non-null assertions, type assertions and satisfies expressions.
function withoutWrappers(expression: TsExpression): TsExpression {
  let current = expression;
  while (typescriptSyntax.isParenthesizedExpression(current) || typescriptSyntax.isNonNullExpression(current)
    || typescriptSyntax.isAsExpression(current) || typescriptSyntax.isTypeAssertionExpression(current)
    || typescriptSyntax.isSatisfiesExpression(current)) {
    current = current.expression;
  }
  return current;
}
