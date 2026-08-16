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
 * @param parsed Shared parse for the user's script; callers never pass null or undefined.
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
    // Export assignments cover `export default LocalName` and expression-valued defaults.
    if (typescriptSyntax.isExportAssignment(statement)) {
      collectExportAssignment(parsed.sourceFile, statement, localDeclarations, publicDeclarations);
    }
  }
  return [...publicDeclarations.values()].sort(comparePublicDeclarations);
}

// Indexes supported top-level declarations before export statements are resolved. Empty source
// produces an empty map, which means a later external re-export remains explicitly unresolved.
function localDeclarationIndex(sourceFile: TsSourceFile): Map<string, PublicExportDeclaration> {
  const declarations = new Map<string, PublicExportDeclaration>();
  // Bottom-of-file exports need declarations from the entire module, including later source lines.
  for (const statement of sourceFile.statements) {
    const declaration = supportedDeclaration(sourceFile, statement);
    // Anonymous default declarations have no local name for another export statement to reference.
    if (!declaration || declaration.name === "default") {
      continue;
    }
    const existingDeclaration = declarations.get(declaration.name);
    // A merged class is the runtime value a bottom export exposes; otherwise retain the earliest
    // declaration anchor for deterministic output.
    if (!existingDeclaration || declaration.kind === "class" && existingDeclaration.kind !== "class") {
      declarations.set(declaration.name, declaration);
    }
  }
  return declarations;
}

// Adds a supported declaration only when the user exported it on its declaration line.
function collectDirectExport(sourceFile: TsSourceFile, statement: TsStatement, publicDeclarations: Map<string, PublicExportDeclaration>): void {
  const declaration = supportedDeclaration(sourceFile, statement);
  // Local-only declarations are indexed for possible bottom exports but are not public yet.
  if (!declaration || !hasModifier(statement, typescriptSyntax.SyntaxKind.ExportKeyword)) {
    return;
  }
  addPublicDeclaration(publicDeclarations, declaration);
}

// Resolves one export declaration to local declaration facts when possible, otherwise records the
// external public name. This is what keeps class selection syntax-independent for CLI users.
function collectNamedOrExternalExport(sourceFile: TsSourceFile, statement: TsExportDeclaration, localDeclarations: Map<string, PublicExportDeclaration>, publicDeclarations: Map<string, PublicExportDeclaration>): void {
  const exportLine = sourceLine(sourceFile, statement);
  const exportClause = statement.exportClause;
  // A wildcard still exposes another module surface even though syntax alone cannot name each item.
  if (!exportClause) {
    addPublicDeclaration(publicDeclarations, { kind: "re-export", name: "*", line: exportLine });
    return;
  }
  // Namespace exports have one explicit public name, such as `export * as tools`.
  if (typescriptSyntax.isNamespaceExport(exportClause)) {
    addPublicDeclaration(publicDeclarations, { kind: "re-export", name: exportClause.name.text, line: exportLine });
    return;
  }
  // Each named export is one public declaration unless it resolves to the same local declaration.
  for (const exportSpecifier of exportClause.elements) {
    // An alias resolves through its local source name; an unaliased export uses its public name.
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

// Resolves an identifier-valued default/export-equals assignment to its declaration. Expression
// defaults remain one explicit public item because the user still exported a second module value.
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

// Projects a supported top-level syntax node into the user-visible kind, name, and line tuple.
// Undefined means the statement is outside the class/interface/type/enum/function policy surface.
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
  // The class check comes first because it is the only kind eligible for the eventual finding.
  if (typescriptSyntax.isClassDeclaration(declaration)) {
    return "class";
  }
  // Interfaces and type aliases remain distinct so users can understand a multi-export contract surface.
  if (typescriptSyntax.isInterfaceDeclaration(declaration)) {
    return "interface";
  }
  if (typescriptSyntax.isTypeAliasDeclaration(declaration)) {
    return "type";
  }
  // Enums keep their own category so a report explains why a module is multi-public.
  if (typescriptSyntax.isEnumDeclaration(declaration)) {
    return "enum";
  }
  return "function";
}

// Reads one modifier without assuming every statement kind exposes a modifier array.
function hasModifier(statement: TsStatement, modifierKind: import("typescript").SyntaxKind): boolean {
  // Statement kinds without modifier storage behave as an empty modifier list for the user.
  const modifiers = typescriptSyntax.canHaveModifiers(statement) ? typescriptSyntax.getModifiers(statement) : undefined;
  return modifiers?.some((modifier) => modifier.kind === modifierKind) === true;
}

// Adds one declaration by stable kind/name key. Repeated aliases and merged declarations stay one
// public item, with the earliest source anchor retained for deterministic user output.
function addPublicDeclaration(publicDeclarations: Map<string, PublicExportDeclaration>, declaration: PublicExportDeclaration): void {
  const key = `${declaration.kind}:${declaration.name}`;
  const existingDeclaration = publicDeclarations.get(key);
  // The first source occurrence is the clearest anchor when aliases expose the same declaration twice.
  if (!existingDeclaration || declaration.line < existingDeclaration.line) {
    publicDeclarations.set(key, declaration);
  }
}

// Converts a syntax start offset to the one-based source line shown in findings and metadata probes.
function sourceLine(sourceFile: TsSourceFile, statement: TsStatement): number {
  return sourceFile.getLineAndCharacterOfPosition(statement.getStart(sourceFile)).line + 1;
}

// Sorts by the serialized kind:name value, then line as a deterministic tie-breaker.
function comparePublicDeclarations(left: PublicExportDeclaration, right: PublicExportDeclaration): number {
  const labelOrder = `${left.kind}:${left.name}`.localeCompare(`${right.kind}:${right.name}`);
  return labelOrder || left.line - right.line;
}
