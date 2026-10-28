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

/*
 * Class-pillar rules in their stable, deterministic emission order: exported-declaration
 * docs and file-name mismatch, then readonly candidates.
 */
export function analyseClassRules(file: SourceFile, source: string, codeSource: string, config: Config, findings: Finding[], parsed?: ParsedScript): void {
  analyseExportedDeclarations(file, source, codeSource, config, findings, parsed);
  analyseReadonlyCandidates(file, source, codeSource, findings, parsed);
}

/*
 * Keeps public-doc checks on direct exports, then evaluates class/file naming against the complete
 * syntax inventory so reports cover default/re-export forms without changing the documentation contract.
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

/*
 * Reports a normalized class/file mismatch only when one named class is the module's sole public
 * declaration, keeping feature modules quiet while preserving the stable finding anchor.
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

// `private name: Type;` fields without `readonly` whose rewrite to `readonly` compiles. Only private
// fields qualify: a public or protected field can be written from another file this scan never reads.
// Without a clean parse the class's writes are unknown, so the file reports nothing. A reported field
// keeps the line, message and symbol the regex match gives it, so its stable finding identity is unchanged.
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

// Name start offsets of private instance fields, not yet readonly, that their class writes, if at all,
// only through `this` in its own constructor.
function constructionOnlyFieldNameStarts(sourceFile: TsSourceFile): Set<number> {
  const starts = new Set<number>();
  // Checks each class, then recurses so nested and expression classes are checked too.
  const visit = (node: TsNode): void => {
    if (typescriptSyntax.isClassLike(node)) {
      addConstructionOnlyFields(sourceFile, node, starts);
    }
    node.forEachChild(visit);
  };
  sourceFile.forEachChild(visit);
  return starts;
}

// Adds to `starts` the name offset of each candidate field in `classNode` that nothing writes after construction.
function addConstructionOnlyFields(sourceFile: TsSourceFile, classNode: TsClassLike, starts: Set<number>): void {
  const written = writtenMemberNames(classNode);
  // `undefined` means the class writes through `this[...]` or `Object.assign(this, ...)`, so no field is safe.
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
 * Every member name the class body writes outside its constructor's own `this.<name>` assignments:
 * assignment and compound assignment, `++`/`--`, `delete`, destructuring targets and `for...in/of`
 * targets, on any receiver, including another instance or a nested function inside the constructor.
 * Returns `undefined` when the class writes through `this[...]` or `Object.assign(this, ...)`, whose
 * member names a syntax walk cannot know.
 */
function writtenMemberNames(classNode: TsClassLike): Set<string> | undefined {
  const written = new Set<string>();
  let writesDynamically = false;
  // Adds the member name `target` writes; `write` is the enclosing write expression, whose position
  // decides whether a `this.<name>` target is a constructor assignment.
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
  // Records the target of each write form at `node`, then recurses through the whole class body.
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

// The expressions a destructuring pattern assigns: property values, array elements and rest targets, without defaults.
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

// Whether a write runs in this class's constructor body itself, not in a function, class or initializer nested in it.
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

// `Object.assign(this, ...)`, which writes members the syntax tree does not name.
function isObjectAssignToThis(node: TsNode): boolean {
  if (!typescriptSyntax.isCallExpression(node) || !typescriptSyntax.isPropertyAccessExpression(node.expression)) {
    return false;
  }
  const callee = node.expression;
  const firstArgument = node.arguments[0];
  return typescriptSyntax.isIdentifier(callee.expression) && callee.expression.text === "Object" && callee.name.text === "assign"
    && firstArgument !== undefined && isThisKeyword(firstArgument);
}

// Returns whether `expression` is `this`, looking through parentheses and type assertions.
function isThisKeyword(expression: TsExpression): boolean {
  return withoutWrappers(expression).kind === typescriptSyntax.SyntaxKind.ThisKeyword;
}

// Returns whether `kind` is `=` or a compound assignment such as `+=` or `??=`.
function isAssignmentOperator(kind: import("typescript").SyntaxKind): boolean {
  return kind >= typescriptSyntax.SyntaxKind.FirstAssignment && kind <= typescriptSyntax.SyntaxKind.LastAssignment;
}

// Strips parentheses, `!` and type assertions, which change neither the write target nor its receiver.
function withoutWrappers(expression: TsExpression): TsExpression {
  let current = expression;
  while (typescriptSyntax.isParenthesizedExpression(current) || typescriptSyntax.isNonNullExpression(current)
    || typescriptSyntax.isAsExpression(current) || typescriptSyntax.isTypeAssertionExpression(current)
    || typescriptSyntax.isSatisfiesExpression(current)) {
    current = current.expression;
  }
  return current;
}
