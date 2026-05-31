import { createRequire } from "node:module";
import type { SourceFile } from "./discovery.ts";

/**
 * Syntax-only TypeScript/JavaScript parser adapter (ADR-012).
 *
 * Uses `ts.createSourceFile` and nothing else: no type checker, no
 * `ts.Program`, no language service, no emit, no network. The TypeScript
 * package ships as CommonJS, so it is loaded through `createRequire` - the same
 * runtime-interop pattern the analyser already uses for runtime-only deps -
 * while types come from a `typeof import(...)` cast.
 *
 * Every entry point degrades to `null` rather than throwing, so a file the
 * parser cannot handle falls back to the same-line masked-text heuristics
 * instead of crashing or dropping findings.
 */
const require = createRequire(import.meta.url);
// Exported so rule modules can walk nodes through the one syntax-only entry
// point. Usage stays bounded by ADR-012: no type checker, program, or emit.
export const ts = require("typescript") as typeof import("typescript");

type TsSourceFile = import("typescript").SourceFile;
type TsNode = import("typescript").Node;

// Keyed by the discovery SourceFile, which is one stable object per file per
// run, so several security rules over the same file parse it only once.
const astCache = new WeakMap<SourceFile, TsSourceFile | null>();

/**
 * Parse a discovered script to a syntax-only AST, cached for the run. Returns
 * null when parsing throws, so callers fall back to the same-line scan.
 */
export function getSourceFile(file: SourceFile, source: string): TsSourceFile | null {
  const cached = astCache.get(file);
  if (cached !== undefined) return cached;
  let parsed: TsSourceFile | null = null;
  try {
    parsed = ts.createSourceFile(
      file.displayPath,
      source,
      ts.ScriptTarget.Latest,
      true,
      scriptKindFor(file.displayPath),
    );
  } catch {
    parsed = null;
  }
  astCache.set(file, parsed);
  return parsed;
}

function scriptKindFor(path: string) {
  if (path.endsWith(".tsx")) return ts.ScriptKind.TSX;
  if (path.endsWith(".jsx")) return ts.ScriptKind.JSX;
  if (path.endsWith(".js") || path.endsWith(".mjs") || path.endsWith(".cjs")) {
    return ts.ScriptKind.JS;
  }
  return ts.ScriptKind.TS;
}

/** Depth-first walk. Return false from `visit` to skip a node's children. */
export function walk(node: TsNode, visit: (node: TsNode) => boolean | void): void {
  if (visit(node) === false) return;
  ts.forEachChild(node, (child) => {
    walk(child, visit);
  });
}

/**
 * Name of the nearest enclosing named function, method, class, or
 * function-valued variable, for use as a finding `symbol`. Returns undefined at
 * module scope.
 */
export function enclosingFunctionName(node: TsNode): string | undefined {
  let current: TsNode | undefined = node;
  while (current) {
    const name = declarationName(current);
    if (name !== undefined) return name;
    current = current.parent;
  }
  return undefined;
}

function declarationName(node: TsNode): string | undefined {
  if (
    (ts.isFunctionDeclaration(node) ||
      ts.isMethodDeclaration(node) ||
      ts.isClassDeclaration(node)) &&
    node.name &&
    ts.isIdentifier(node.name)
  ) {
    return node.name.text;
  }
  if (
    ts.isVariableDeclaration(node) &&
    ts.isIdentifier(node.name) &&
    node.initializer &&
    (ts.isArrowFunction(node.initializer) ||
      ts.isFunctionExpression(node.initializer))
  ) {
    return node.name.text;
  }
  return undefined;
}

/** Zero-based start line of a node, for aligning with source line numbers. */
export function lineIndexOf(sf: TsSourceFile, node: TsNode): number {
  return sf.getLineAndCharacterOfPosition(node.getStart(sf)).line;
}

export type { TsSourceFile, TsNode };
