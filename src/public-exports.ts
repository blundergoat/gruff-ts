// Builds a syntax-backed public-export inventory from the shared script parse for naming checks.
//
// Resolves direct, default, and bottom `export { ... }` forms into one declaration list without re-parsing the file.
// Used by `naming.class-file-mismatch` to check whether a mismatched class is the sole public declaration in a module.
import { createRequire } from "node:module";
import type { ParsedScript } from "./parsed-script.ts";

const require = createRequire(import.meta.url);
const typescriptSyntax = require("typescript") as typeof import("typescript");

type TsSourceFile = import("typescript").SourceFile;
type TsStatement = import("typescript").Statement;
type TsExportDeclaration = import("typescript").ExportDeclaration;
type TsExportAssignment = import("typescript").ExportAssignment;

/*
 * Stable declaration categories shown inside class/file finding metadata. `default` and
 * `re-export` represent public values whose local declaration kind is unavailable without type
 * checking, so report users still see why a class was not treated as the sole export.
 */
export type PublicExportKind = "class" | "interface" | "type" | "enum" | "function" | "default" | "re-export";

/*
 * One public declaration extracted from a module for class/file naming checks.
 *
 * Local re-exports preserve their local kind, name, and line; external or anonymous defaults anchor on the export statement line.
 * `exportedName` is set only when an `as` alias renames the export so naming checks judge the name callers actually import.
 */
export interface PublicExportDeclaration {
  kind: PublicExportKind;
  name: string;
  line: number;
  exportedName?: string;
}

/*
 * The five named declaration forms already covered by the public-doc scan. Keeping this syntax
 * set explicit prevents value exports from silently widening the class/file policy beyond the
 * module shapes named in the rule's user documentation.
 */
type SupportedDeclaration =
  | import("typescript").ClassDeclaration
  | import("typescript").InterfaceDeclaration
  | import("typescript").TypeAliasDeclaration
  | import("typescript").EnumDeclaration
  | import("typescript").FunctionDeclaration;

/**
 * Builds the stable sorted public-declaration contract used by class/file naming diagnostics.
 *
 * @param parsed - shared syntax tree supplying the module declarations and source anchors
 * @returns Sorted declarations; an empty array means the module exposes none of the supported forms.
 */
export function publicExportDeclarations(parsed: ParsedScript): PublicExportDeclaration[] {
  const localDeclarations = localDeclarationIndex(parsed.sourceFile);
  const publicDeclarations = new Map<string, PublicExportDeclaration>();
  // A second top-level pass can resolve bottom exports because every local declaration is indexed first.
  for (const statement of parsed.sourceFile.statements) {
    collectDirectExport(parsed.sourceFile, statement, publicDeclarations);
    // Export declarations cover named, namespace, wildcard, local, and external re-export syntax.
    if (typescriptSyntax.isExportDeclaration(statement)) {
      collectNamedOrExternalExport(parsed.sourceFile, statement, localDeclarations, publicDeclarations);
    }
    // Export assignments include identifier defaults, expression defaults, and export-equals assignments.
    if (typescriptSyntax.isExportAssignment(statement)) {
      collectExportAssignment(parsed.sourceFile, statement, localDeclarations, publicDeclarations);
    }
  }
  return [...publicDeclarations.values()].sort(comparePublicDeclarations);
}

/**
 * Indexes supported named top-level declarations by local name before export statements are resolved.
 *
 * @param sourceFile - Parsed TypeScript syntax tree whose top-level statements are indexed.
 * @returns Map of local names to declarations; empty when the source has no supported named declarations.
 */
function localDeclarationIndex(sourceFile: TsSourceFile): Map<string, PublicExportDeclaration> {
  const declarations = new Map<string, PublicExportDeclaration>();
  // A named export can precede the declaration it exposes, so index the whole module before resolving exports.
  for (const statement of sourceFile.statements) {
    const declaration = supportedDeclaration(sourceFile, statement);
    // Anonymous default declarations have no local name for another export statement to reference.
    if (!declaration || declaration.name === "default") {
      continue;
    }
    const existingDeclaration = declarations.get(declaration.name);
    // Keep the class anchor when declarations merge because it can drive class/file naming advice.
    // Otherwise retain the earliest declaration anchor for deterministic output.
    if (!existingDeclaration || declaration.kind === "class" && existingDeclaration.kind !== "class") {
      declarations.set(declaration.name, declaration);
    }
  }
  return declarations;
}

/**
 * Collects a directly exported supported declaration from a top-level statement.
 *
 * @param sourceFile - Parsed syntax tree used to compute source line anchors.
 * @param statement - Top-level statement inspected for a supported declaration with an export modifier.
 * @param publicDeclarations - Destination map updated with any qualifying declaration.
 * @returns Nothing. Adds a qualifying declaration to `publicDeclarations` and leaves the map alone otherwise.
 */
function collectDirectExport(sourceFile: TsSourceFile, statement: TsStatement, publicDeclarations: Map<string, PublicExportDeclaration>): void {
  const declaration = supportedDeclaration(sourceFile, statement);
  // A separate export list can expose a declaration that has no export modifier.
  if (!declaration || !hasModifier(statement, typescriptSyntax.SyntaxKind.ExportKeyword)) {
    return;
  }
  addPublicDeclaration(publicDeclarations, declaration);
}

/**
 * Resolves named, namespace, wildcard, and external exports for class/file naming diagnostics.
 *
 * @param sourceFile - Parsed syntax tree used for export line anchors.
 * @param statement - Export declaration statement to resolve.
 * @param localDeclarations - Index of local top-level declarations keyed by local name.
 * @param publicDeclarations - Destination map updated with resolved local or re-export entries.
 * @returns Nothing. Records local entries or external and unresolved names as re-exports to avoid sole-class advice.
 */
function collectNamedOrExternalExport(sourceFile: TsSourceFile, statement: TsExportDeclaration, localDeclarations: Map<string, PublicExportDeclaration>, publicDeclarations: Map<string, PublicExportDeclaration>): void {
  const exportLine = sourceLine(sourceFile, statement);
  const exportClause = statement.exportClause;
  // A wildcard still exposes another module surface even though syntax alone cannot name each item.
  if (!exportClause) {
    addPublicDeclaration(publicDeclarations, { kind: "re-export", name: "*", line: exportLine });
    return;
  }
  // Namespace exports have one explicit public name, such as export * as tools.
  if (typescriptSyntax.isNamespaceExport(exportClause)) {
    addPublicDeclaration(publicDeclarations, { kind: "re-export", name: exportClause.name.text, line: exportLine });
    return;
  }
  // Local aliases share their declaration's entry. Repeated re-exports with the same public name also share an entry.
  for (const exportSpecifier of exportClause.elements) {
    // For a local export, look up the original name when aliased and the public name otherwise.
    const localName = (exportSpecifier.propertyName ?? exportSpecifier.name).text;
    const publicName = exportSpecifier.name.text;
    const localDeclaration = statement.moduleSpecifier ? undefined : localDeclarations.get(localName);
    // External or unresolved names remain visible as re-exports so they still prevent sole-class advice.
    addPublicDeclaration(publicDeclarations, localDeclaration
      // A rename keeps the local kind and anchor but records the name consumers actually import.
      ? { ...localDeclaration, ...(publicName === localDeclaration.name ? {} : { exportedName: publicName }) }
      : { kind: "re-export", name: publicName, line: exportLine });
  }
}

/**
 * Resolves a default or export-equals assignment so locally resolved identifiers retain their declaration kind, name, and line.
 * Unresolved identifiers and expressions record a default or export-equals placeholder anchored at the assignment.
 *
 * @param sourceFile - Parsed syntax tree supplying source line anchors.
 * @param statement - Export assignment statement (`export default` or `export =`) to resolve.
 * @param localDeclarations - Index of local declarations used to resolve exported identifiers.
 * @param publicDeclarations - Destination map updated with the resolved entry or placeholder.
 * @returns Nothing. Adds the locally resolved declaration or a default/export-equals placeholder to `publicDeclarations`.
 */
function collectExportAssignment(sourceFile: TsSourceFile, statement: TsExportAssignment, localDeclarations: Map<string, PublicExportDeclaration>, publicDeclarations: Map<string, PublicExportDeclaration>): void {
  const localDeclaration = typescriptSyntax.isIdentifier(statement.expression) ? localDeclarations.get(statement.expression.text) : undefined;
  // A named local class exported as default must retain its class name and declaration anchor.
  if (localDeclaration) {
    addPublicDeclaration(publicDeclarations, localDeclaration);
    return;
  }
  const unresolvedExport = statement.isExportEquals
    ? { kind: "re-export" as const, name: "export=", line: sourceLine(sourceFile, statement) }
    : { kind: "default" as const, name: "default", line: sourceLine(sourceFile, statement) };
  addPublicDeclaration(publicDeclarations, unresolvedExport);
}

/**
 * Extracts a supported statement's kind, name, and starting line for class/file naming diagnostics.
 * Anonymous default declarations use the placeholder name `default`.
 *
 * @param sourceFile - Parsed syntax tree supplying source line positions.
 * @param statement - Top-level statement to inspect.
 * @returns Declaration metadata, or undefined for unsupported statements or declarations without a usable name.
 */
function supportedDeclaration(sourceFile: TsSourceFile, statement: TsStatement): PublicExportDeclaration | undefined {
  // Other top-level statements, such as imports and exported constants, do not enter this policy slice.
  if (!isSupportedDeclaration(statement)) {
    return undefined;
  }
  const kind = supportedDeclarationKind(statement);
  // Named declarations retain their symbol; anonymous defaults use one stable placeholder.
  const name = statement.name?.text ?? (hasModifier(statement, typescriptSyntax.SyntaxKind.DefaultKeyword) ? "default" : undefined);
  // A non-default anonymous declaration has no stable symbol a class/file finding could present.
  if (!name) {
    return undefined;
  }
  return { kind, name, line: sourceLine(sourceFile, statement) };
}

/**
 * Narrows top-level syntax to the declaration forms named by the class/file rule policy.
 *
 * @param statement - Top-level AST statement to check.
 * @returns True when `statement` is a supported class, interface, type alias, enum, or function declaration.
 */
function isSupportedDeclaration(statement: TsStatement): statement is SupportedDeclaration {
  return typescriptSyntax.isClassDeclaration(statement)
    || typescriptSyntax.isInterfaceDeclaration(statement)
    || typescriptSyntax.isTypeAliasDeclaration(statement)
    || typescriptSyntax.isEnumDeclaration(statement)
    || typescriptSyntax.isFunctionDeclaration(statement);
}

/**
 * Converts a narrowed syntax declaration to the stable lowercase metadata category.
 *
 * @param declaration - Narrowed supported AST declaration.
 * @returns Stable lowercase kind string (`class`, `interface`, `type`, `enum`, or `function`).
 */
function supportedDeclarationKind(declaration: SupportedDeclaration): Exclude<PublicExportKind, "default" | "re-export"> {
  // The class/file rule uses this category to recognize a sole public class.
  if (typescriptSyntax.isClassDeclaration(declaration)) {
    return "class";
  }
  if (typescriptSyntax.isInterfaceDeclaration(declaration)) {
    return "interface";
  }
  if (typescriptSyntax.isTypeAliasDeclaration(declaration)) {
    return "type";
  }
  if (typescriptSyntax.isEnumDeclaration(declaration)) {
    return "enum";
  }
  return "function";
}

/**
 * Checks whether a statement carries a given TypeScript modifier using the syntax API.
 *
 * @param statement - Top-level statement whose modifiers are inspected.
 * @param modifierKind - TypeScript syntax kind of the modifier to look up.
 * @returns True when `statement` can have modifiers and includes `modifierKind`.
 */
function hasModifier(statement: TsStatement, modifierKind: import("typescript").SyntaxKind): boolean {
  // Statement kinds without modifier storage behave as an empty modifier list for the user.
  const modifiers = typescriptSyntax.canHaveModifiers(statement) ? typescriptSyntax.getModifiers(statement) : undefined;
  return modifiers?.some((modifier) => modifier.kind === modifierKind) === true;
}

/**
 * Records a public declaration keyed by kind and name, keeping the earliest source anchor for deterministic user output.
 * Repeated aliases and same-kind merged declarations stay one public item.
 *
 * @param publicDeclarations - Destination map of public declarations keyed by `kind:name`.
 * @param declaration - Candidate public declaration to insert if unseen or earlier in source order.
 * @returns Nothing. Updates `publicDeclarations` only when the key is new or `declaration.line` is earlier.
 */
function addPublicDeclaration(publicDeclarations: Map<string, PublicExportDeclaration>, declaration: PublicExportDeclaration): void {
  const key = `${declaration.kind}:${declaration.name}`;
  const existingDeclaration = publicDeclarations.get(key);
  // A line tie keeps the first recorded entry, so a later alias cannot replace its public spelling.
  if (!existingDeclaration || declaration.line < existingDeclaration.line) {
    publicDeclarations.set(key, declaration);
  }
}

/**
 * Computes a statement's one-based starting line for the public export inventory and class/file finding anchors.
 *
 * @param sourceFile - Parsed syntax tree containing the statement.
 * @param statement - AST statement whose starting line is measured.
 * @returns One-based line number of `statement`'s start position.
 */
function sourceLine(sourceFile: TsSourceFile, statement: TsStatement): number {
  return sourceFile.getLineAndCharacterOfPosition(statement.getStart(sourceFile)).line + 1;
}

/**
 * Compares two public declarations by `kind:name` and then starting line for stable export output.
 *
 * @param left - First public declaration to compare.
 * @param right - Second public declaration to compare.
 * @returns Negative, zero, or positive comparison value for sorting `left` relative to `right`.
 */
function comparePublicDeclarations(left: PublicExportDeclaration, right: PublicExportDeclaration): number {
  const labelOrder = `${left.kind}:${left.name}`.localeCompare(`${right.kind}:${right.name}`);
  return labelOrder || left.line - right.line;
}
