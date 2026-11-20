// Syntax-backed public-export inventory for naming diagnostics. It reads the shared parsed
// script, resolves direct, default, and bottom re-export forms to one declaration list, and never
// parses a user's file again. The class/file rule reaches this module when deciding whether a
// mismatched class is the only public declaration a CLI or report user needs to locate.
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
 * One deterministic public declaration from the user's module. Resolved local re-exports retain
 * the local kind, name, and declaration line; unresolved external/default values use the export
 * statement line so the inventory remains complete without a semantic program.
 * `exportedName` is present only when an alias renames the declaration on its way out, because the
 * name a consumer imports is the one a naming rule about the public surface has to judge.
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

// Indexes sourceFile's supported named top-level declarations by local name before export statements are resolved.
// Returns an empty map when the source has no supported named declarations.
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

// Uses sourceFile for source anchors and inspects statement for a supported declaration with an export modifier.
// Returns nothing. Adds a qualifying declaration to publicDeclarations and leaves the map alone otherwise.
function collectDirectExport(sourceFile: TsSourceFile, statement: TsStatement, publicDeclarations: Map<string, PublicExportDeclaration>): void {
  const declaration = supportedDeclaration(sourceFile, statement);
  // A separate export list can expose a declaration that has no export modifier.
  if (!declaration || !hasModifier(statement, typescriptSyntax.SyntaxKind.ExportKeyword)) {
    return;
  }
  addPublicDeclaration(publicDeclarations, declaration);
}

// Resolves statement against localDeclarations and adds public entries to publicDeclarations for class/file naming diagnostics.
// Returns nothing. Uses sourceFile for export anchors and records external or unresolved names as re-exports to avoid sole-class advice.
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

// Returns nothing. Resolves statement's default or export-equals assignment via localDeclarations and adds the result to publicDeclarations.
// sourceFile supplies source anchors; a locally resolved identifier retains its declaration kind, name, and line.
// Unresolved identifiers and expressions use one default or export-equals placeholder anchored at the assignment.
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

// Returns the supported statement's kind, name, and starting line from sourceFile for class/file naming diagnostics.
// Returns undefined for unsupported statements or declarations without a usable name; anonymous defaults use the name default.
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

// Narrows top-level syntax to the declaration forms named by the class/file rule policy.
function isSupportedDeclaration(statement: TsStatement): statement is SupportedDeclaration {
  return typescriptSyntax.isClassDeclaration(statement)
    || typescriptSyntax.isInterfaceDeclaration(statement)
    || typescriptSyntax.isTypeAliasDeclaration(statement)
    || typescriptSyntax.isEnumDeclaration(statement)
    || typescriptSyntax.isFunctionDeclaration(statement);
}

// Converts a narrowed syntax declaration to the stable lowercase metadata category.
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

// Returns whether statement has modifierKind, using the syntax API to support declaration checks across statement kinds.
function hasModifier(statement: TsStatement, modifierKind: import("typescript").SyntaxKind): boolean {
  // Statement kinds without modifier storage behave as an empty modifier list for the user.
  const modifiers = typescriptSyntax.canHaveModifiers(statement) ? typescriptSyntax.getModifiers(statement) : undefined;
  return modifiers?.some((modifier) => modifier.kind === modifierKind) === true;
}

// Adds declaration to publicDeclarations by kind/name key. Repeated aliases and same-kind merged declarations stay one
// public item, with the earliest source anchor retained for deterministic user output. Returns nothing.
function addPublicDeclaration(publicDeclarations: Map<string, PublicExportDeclaration>, declaration: PublicExportDeclaration): void {
  const key = `${declaration.kind}:${declaration.name}`;
  const existingDeclaration = publicDeclarations.get(key);
  // A line tie keeps the first recorded entry, so a later alias cannot replace its public spelling.
  if (!existingDeclaration || declaration.line < existingDeclaration.line) {
    publicDeclarations.set(key, declaration);
  }
}

// Returns statement's one-based starting line in sourceFile for the public export inventory and class/file finding anchors.
function sourceLine(sourceFile: TsSourceFile, statement: TsStatement): number {
  return sourceFile.getLineAndCharacterOfPosition(statement.getStart(sourceFile)).line + 1;
}

// Returns a negative, zero, or positive comparison for left versus right, ordered by kind:name then line for stable export output.
function comparePublicDeclarations(left: PublicExportDeclaration, right: PublicExportDeclaration): number {
  const labelOrder = `${left.kind}:${left.name}`.localeCompare(`${right.kind}:${right.name}`);
  return labelOrder || left.line - right.line;
}
