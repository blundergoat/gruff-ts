// Static-analysis-redundant assertion scanner for test blocks. It reports tests that only prove
// TypeScript-visible code shape, keeping the main per-test-block pass focused on orchestration.
import { type FunctionBlock } from "./blocks.ts";
import { type SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import { lineOffset } from "./findings-helpers.ts";
import type { Confidence, Finding } from "./types.ts";

// Candidate assertion contract promoted into a real Finding after its test-block line is known.
interface StaticAnalysisRedundantAssertion {
  assertion: string;
  staticFact: string;
  sourceProof?: string;
  confidence: Confidence;
  recommendation: string;
  reasonCategory?: string;
  suggestedAction?: string;
  index: number;
}

// Non-nullable declaration evidence captured from a test block before assertion matching runs.
interface NonNullableReturnDeclaration {
  name: string;
  returnType: string;
  lineOffset: number;
}

// Full-file source context used to prove imports and declarations outside the current test body.
export interface StaticAnalysisSourceContext {
  source: string;
  codeSource: string;
  startLine: number;
}

// One TypeScript-visible function fact and the line that proves it to reviewers.
interface StaticFunctionFact {
  staticFact: string;
  sourceProof: string;
}

// Function facts are split by identifier and namespace import so member lookups stay explicit.
interface StaticFunctionFacts {
  identifiers: Map<string, StaticFunctionFact>;
  namespaceImports: Map<string, StaticFunctionFact>;
}

const TYPEOF_FUNCTION_ASSERTION_PATTERNS = [
  /\bassert\.(?:equal|strictEqual)\s*\(\s*typeof\s+([A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)\s*,\s*["']function["']\s*(?:,[^)]*)?\)/g,
  /\bassert\.(?:equal|strictEqual)\s*\(\s*["']function["']\s*,\s*typeof\s+([A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)\s*(?:,[^)]*)?\)/g,
  /\bexpect\s*\(\s*typeof\s+([A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)\s*\)\s*\.\s*to(?:Be|Equal|StrictEqual)\s*\(\s*["']function["']\s*\)/g,
] as const;

const DIRECT_CONSTRUCTION_ASSERTION_PATTERNS = [
  /\bassert\.ok\s*\(\s*new\s+([A-Z][A-Za-z0-9_$]*)\s*\([^)]*\)\s+instanceof\s+\1\s*(?:,[^)]*)?\)/g,
  /\bassert\.(?:equal|strictEqual)\s*\(\s*new\s+([A-Z][A-Za-z0-9_$]*)\s*\([^)]*\)\s+instanceof\s+\1\s*,\s*true\s*(?:,[^)]*)?\)/g,
  /\bexpect\s*\(\s*new\s+([A-Z][A-Za-z0-9_$]*)\s*\([^)]*\)\s*\)\s*\.\s*toBeInstanceOf\s*\(\s*\1\s*\)/g,
] as const;

const NON_NULLABLE_ASSERTION_PATTERNS = [
  /\bassert\.not(?:Equal|StrictEqual)\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\([^)]*\)\s*,\s*(?:null|undefined)\s*(?:,[^)]*)?\)/g,
  /\bexpect\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\([^)]*\)\s*\)\s*\.\s*toBeDefined\s*\(\s*\)/g,
  /\bexpect\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\([^)]*\)\s*\)\s*\.\s*not\s*\.\s*toBeNull\s*\(\s*\)/g,
] as const;

const NON_NULLABLE_DECLARATION_PATTERNS = [
  /\bfunction\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\([^)]*\)\s*:\s*([A-Za-z_$][A-Za-z0-9_$<>,\s.[\]]*)\s*\{/g,
  /\bconst\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*:\s*([A-Za-z_$][A-Za-z0-9_$<>,\s.[\]]*)\s*=>/g,
] as const;

/*
 * Reports stable `test-quality.static-analysis-redundant-test` findings. The contract keeps source
 * proof and recommendation in metadata because reviewers need the assertion and proof side by side.
 */
export function pushStaticAnalysisRedundantTestFindings(file: SourceFile, block: FunctionBlock, rawBody: string, codeBody: string, staticContext: StaticAnalysisSourceContext, findings: Finding[]): void {
  for (const candidate of staticAnalysisRedundantAssertions(file, block, rawBody, codeBody, staticContext)) {
    const line = block.startLine + lineOffset(rawBody, candidate.index);
    findings.push(
      makeFinding({
        ruleId: "test-quality.static-analysis-redundant-test",
        message: staticAnalysisRedundantMessage(block, candidate),
        filePath: file.displayPath,
        line,
        severity: "advisory",
        pillar: "test-quality",
        confidence: candidate.confidence,
        symbol: block.name,
        remediation: candidate.recommendation,
        metadata: {
          testFile: file.displayPath,
          testMethod: block.name,
          assertion: candidate.assertion,
          staticFact: candidate.staticFact,
          sourceProof: candidate.sourceProof ?? `${file.displayPath}:${line}`,
          confidence: candidate.confidence,
          recommendation: candidate.recommendation,
          ...(candidate.reasonCategory ? { reasonCategory: candidate.reasonCategory } : {}),
          ...(candidate.suggestedAction ? { suggestedAction: candidate.suggestedAction } : {}),
        },
      }),
    );
  }
}

// Runs the three static-shape detectors and preserves deterministic source-order emission.
function staticAnalysisRedundantAssertions(file: SourceFile, block: FunctionBlock, rawSource: string, codeSource: string, staticContext: StaticAnalysisSourceContext): StaticAnalysisRedundantAssertion[] {
  return [
    ...typeofFunctionAssertions(file, rawSource, codeSource, staticContext),
    ...directConstructionInstanceAssertions(file, rawSource, codeSource),
    ...nonNullableReturnAssertions(file, block, rawSource, codeSource),
  ]
    .map((candidate) => staticAnalysisActionabilityCandidate(block, candidate))
    .sort((left, right) => left.index - right.index);
}

// Detects `typeof x === "function"`-style assertions when TypeScript already proves the function.
function typeofFunctionAssertions(file: SourceFile, rawSource: string, codeSource: string, staticContext: StaticAnalysisSourceContext): StaticAnalysisRedundantAssertion[] {
  const functionFacts = staticFunctionFacts(file, staticContext);
  return TYPEOF_FUNCTION_ASSERTION_PATTERNS.flatMap((pattern) => typeofFunctionAssertionsForPattern(file, rawSource, codeSource, functionFacts, pattern));
}

// Evaluates one typeof-function assertion grammar while keeping executable-source checks local.
function typeofFunctionAssertionsForPattern(file: SourceFile, rawSource: string, codeSource: string, functionFacts: StaticFunctionFacts, pattern: RegExp): StaticAnalysisRedundantAssertion[] {
  return [...rawSource.matchAll(pattern)]
    .map((match) => typeofFunctionCandidateFromMatch(file, rawSource, codeSource, functionFacts, match))
    .filter(isStaticAnalysisRedundantAssertion);
}

// Builds one typeof-function candidate only when the expression has static declaration evidence.
function typeofFunctionCandidateFromMatch(file: SourceFile, rawSource: string, codeSource: string, functionFacts: StaticFunctionFacts, match: RegExpMatchArray): StaticAnalysisRedundantAssertion | undefined {
  const index = match.index ?? 0;
  if (!isExecutableAssertionAt(codeSource, index)) {
    return undefined;
  }
  const expression = match[1] ?? "";
  const fact = staticFunctionFactForExpression(expression, functionFacts);
  if (!fact) {
    return undefined;
  }
  return staticRedundantCandidate({
    file,
    source: rawSource,
    index,
    assertion: normalizedAssertionText(match[0] ?? ""),
    staticFact: fact.staticFact,
    sourceProof: fact.sourceProof,
  });
}

// Gathers declaration and import facts from the full source context once per test-block scan.
function staticFunctionFacts(file: SourceFile, context: StaticAnalysisSourceContext): StaticFunctionFacts {
  const facts: StaticFunctionFacts = { identifiers: new Map(), namespaceImports: new Map() };
  pushFunctionDeclarationFacts(file, context, facts.identifiers);
  pushConstFunctionFacts(file, context, facts.identifiers);
  pushImportFunctionFacts(file, context, facts);
  return facts;
}

// Adds facts for `function name()` declarations because comments and strings can mimic syntax.
function pushFunctionDeclarationFacts(file: SourceFile, context: StaticAnalysisSourceContext, facts: Map<string, StaticFunctionFact>): void {
  for (const match of context.source.matchAll(/\bfunction\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/g)) {
    const index = match.index ?? 0;
    if (!isExecutableFunctionDeclarationAt(context.codeSource, index)) {
      continue;
    }
    const name = match[1] ?? "";
    if (name) {
      facts.set(name, {
        staticFact: `\`${name}\` is declared as a function in this file.`,
        sourceProof: sourceProof(file, context, index),
      });
    }
  }
}

// Adds facts for const-bound functions because these declarations are common test helper shapes.
function pushConstFunctionFacts(file: SourceFile, context: StaticAnalysisSourceContext, facts: Map<string, StaticFunctionFact>): void {
  const pattern = /\bconst\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?(?:function\b|(?:\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*)\s*(?::\s*[^=;]+?)?=>)/g;
  for (const match of context.source.matchAll(pattern)) {
    const index = match.index ?? 0;
    if (!isExecutableFunctionDeclarationAt(context.codeSource, index)) {
      continue;
    }
    const name = match[1] ?? "";
    if (name) {
      facts.set(name, {
        staticFact: `\`${name}\` is declared as a function-valued const in this file.`,
        sourceProof: sourceProof(file, context, index),
      });
    }
  }
}

// Dispatches named and namespace import evidence into separate maps for later expression lookup.
function pushImportFunctionFacts(file: SourceFile, context: StaticAnalysisSourceContext, facts: StaticFunctionFacts): void {
  pushNamedImportFunctionFacts(file, context, facts.identifiers);
  pushNamespaceImportFunctionFacts(file, context, facts.namespaceImports);
}

// Adds facts for static named imports, including aliases, when the import is executable code.
function pushNamedImportFunctionFacts(file: SourceFile, context: StaticAnalysisSourceContext, facts: Map<string, StaticFunctionFact>): void {
  for (const match of context.source.matchAll(/\bimport\s+(?!type\b)\{([^}]+)\}\s*from\b/g)) {
    const index = match.index ?? 0;
    if (!isExecutableImportAt(context.codeSource, index)) {
      continue;
    }
    const proof = sourceProof(file, context, index);
    for (const importedName of namedImportLocals(match[1] ?? "")) {
      facts.set(importedName, namedImportFunctionFact(importedName, proof));
    }
  }
}

// Adds facts for namespace imports because `namespace.member` assertions need import-level proof.
function pushNamespaceImportFunctionFacts(file: SourceFile, context: StaticAnalysisSourceContext, facts: Map<string, StaticFunctionFact>): void {
  for (const match of context.source.matchAll(/\bimport\s+\*\s+as\s+([A-Za-z_$][A-Za-z0-9_$]*)\s+from\b/g)) {
    const index = match.index ?? 0;
    if (!isExecutableImportAt(context.codeSource, index)) {
      continue;
    }
    const namespaceName = match[1] ?? "";
    if (namespaceName) {
      facts.set(namespaceName, {
        staticFact: `\`${namespaceName}\` is a static ES module namespace import.`,
        sourceProof: sourceProof(file, context, index),
      });
    }
  }
}

// Builds the reviewer-facing fact text for one named import.
function namedImportFunctionFact(importedName: string, proof: string): StaticFunctionFact {
  return {
    staticFact: `\`${importedName}\` is a static ES module named import, so TypeScript can validate the imported binding's declared function type without executing this test assertion.`,
    sourceProof: proof,
  };
}

// Normalises `import { original as local }` clauses to the local binding names used in tests.
function namedImportLocals(importClause: string): string[] {
  return importClause
    .split(",")
    .map((specifier) => namedImportLocal(specifier))
    .filter((value): value is string => value !== undefined);
}

// Returns the local binding name for one named import specifier, ignoring type-only entries.
function namedImportLocal(specifier: string): string | undefined {
  const trimmed = specifier.trim();
  if (trimmed === "" || /^type\b/.test(trimmed)) {
    return undefined;
  }
  const aliased = trimmed.match(/\bas\s+([A-Za-z_$][A-Za-z0-9_$]*)$/);
  if (aliased) {
    return aliased[1];
  }
  const direct = trimmed.match(/^([A-Za-z_$][A-Za-z0-9_$]*)$/);
  return direct?.[1];
}

// Looks up direct identifiers and namespace-member expressions against static import facts.
function staticFunctionFactForExpression(expression: string, facts: StaticFunctionFacts): StaticFunctionFact | undefined {
  const direct = facts.identifiers.get(expression);
  if (direct) {
    return direct;
  }
  const namespaceMember = expression.match(/^([A-Za-z_$][A-Za-z0-9_$]*)\.([A-Za-z_$][A-Za-z0-9_$]*)$/);
  if (!namespaceMember) {
    return undefined;
  }
  const namespaceName = namespaceMember[1] ?? "";
  const memberName = namespaceMember[2] ?? "";
  const namespaceFact = facts.namespaceImports.get(namespaceName);
  if (!namespaceFact || !memberName) {
    return undefined;
  }
  return {
    staticFact: `\`${expression}\` is a statically named member of the \`${namespaceName}\` namespace import, so TypeScript can validate that member's declared function type without executing this test assertion.`,
    sourceProof: namespaceFact.sourceProof,
  };
}

// Converts a byte offset in the source context into the display path and 1-based proof line.
function sourceProof(file: SourceFile, context: StaticAnalysisSourceContext, index: number): string {
  return `${file.displayPath}:${context.startLine + lineOffset(context.source, index)}`;
}

// Detects self-instance assertions where the constructor expression itself proves the relationship.
function directConstructionInstanceAssertions(file: SourceFile, rawSource: string, codeSource: string): StaticAnalysisRedundantAssertion[] {
  return DIRECT_CONSTRUCTION_ASSERTION_PATTERNS.flatMap((pattern) => directConstructionInstanceAssertionsForPattern(file, rawSource, codeSource, pattern));
}

// Evaluates one direct-construction assertion grammar against executable test code.
function directConstructionInstanceAssertionsForPattern(file: SourceFile, rawSource: string, codeSource: string, pattern: RegExp): StaticAnalysisRedundantAssertion[] {
  return [...rawSource.matchAll(pattern)]
    .map((match) => directConstructionInstanceCandidate(file, rawSource, codeSource, match))
    .filter(isStaticAnalysisRedundantAssertion);
}

// Builds one direct-construction candidate with a source-order index for stable sorting.
function directConstructionInstanceCandidate(file: SourceFile, rawSource: string, codeSource: string, match: RegExpMatchArray): StaticAnalysisRedundantAssertion | undefined {
  const index = match.index ?? 0;
  if (!isExecutableAssertionAt(codeSource, index)) {
    return undefined;
  }
  const className = match[1] ?? "";
  return staticRedundantCandidate({
    file,
    source: rawSource,
    index,
    assertion: normalizedAssertionText(match[0] ?? ""),
    staticFact: `\`new ${className}()\` constructs \`${className}\`, so the self-instance relationship is established by the expression shape.`,
  });
}

// Detects assertions that only check non-nullability already guaranteed by a return type.
function nonNullableReturnAssertions(file: SourceFile, block: FunctionBlock, rawSource: string, codeSource: string): StaticAnalysisRedundantAssertion[] {
  const declarations = nonNullableReturnDeclarations(rawSource, codeSource);
  return NON_NULLABLE_ASSERTION_PATTERNS.flatMap((pattern) => nonNullableReturnAssertionsForPattern(file, block, rawSource, codeSource, declarations, pattern));
}

// Evaluates one non-nullable assertion grammar against collected return-type declarations.
function nonNullableReturnAssertionsForPattern(file: SourceFile, block: FunctionBlock, rawSource: string, codeSource: string, declarations: Map<string, NonNullableReturnDeclaration>, pattern: RegExp): StaticAnalysisRedundantAssertion[] {
  return [...rawSource.matchAll(pattern)]
    .map((match) => nonNullableReturnCandidate(file, block, rawSource, codeSource, declarations, match))
    .filter(isStaticAnalysisRedundantAssertion);
}

// Builds one non-nullable-return candidate only when declaration evidence exists.
function nonNullableReturnCandidate(file: SourceFile, block: FunctionBlock, rawSource: string, codeSource: string, declarations: Map<string, NonNullableReturnDeclaration>, match: RegExpMatchArray): StaticAnalysisRedundantAssertion | undefined {
  const index = match.index ?? 0;
  if (!isExecutableAssertionAt(codeSource, index)) {
    return undefined;
  }
  const declaration = declarations.get(match[1] ?? "");
  if (!declaration) {
    return undefined;
  }
  return staticRedundantCandidate({
    file,
    source: rawSource,
    index,
    assertion: normalizedAssertionText(match[0] ?? ""),
    staticFact: `\`${declaration.name}()\` declares a non-nullable \`${declaration.returnType}\` return type.`,
    sourceProof: `${file.displayPath}:${block.startLine + declaration.lineOffset}`,
  });
}

// Collects function and const-arrow declarations whose return type excludes null and undefined.
function nonNullableReturnDeclarations(source: string, codeSource: string): Map<string, NonNullableReturnDeclaration> {
  const declarations = new Map<string, NonNullableReturnDeclaration>();
  for (const pattern of NON_NULLABLE_DECLARATION_PATTERNS) {
    pushNonNullableReturnDeclarationsForPattern(declarations, source, codeSource, pattern);
  }
  return declarations;
}

// Adds declaration evidence for one grammar while ignoring masked comments and strings.
function pushNonNullableReturnDeclarationsForPattern(declarations: Map<string, NonNullableReturnDeclaration>, source: string, codeSource: string, pattern: RegExp): void {
  for (const match of source.matchAll(pattern)) {
    if (!isExecutableFunctionDeclarationAt(codeSource, match.index ?? 0)) {
      continue;
    }
    pushNonNullableReturnDeclaration(declarations, source, match.index ?? 0, match[1] ?? "", match[2] ?? "");
  }
}

// Gives each static-shape candidate the shared confidence and remediation contract.
function staticRedundantCandidate(args: Omit<StaticAnalysisRedundantAssertion, "confidence" | "recommendation"> & { file: SourceFile; source: string }): StaticAnalysisRedundantAssertion {
  const { file: _file, source: _source, ...candidate } = args;
  return {
    ...candidate,
    confidence: "high",
    recommendation: "Remove this assertion if it is the only behavior being tested, or replace it with an assertion about the returned value or observable behavior.",
  };
}

// Downgrades importability sentinel tests to review/document guidance instead of delete guidance.
function staticAnalysisActionabilityCandidate(block: FunctionBlock, candidate: StaticAnalysisRedundantAssertion): StaticAnalysisRedundantAssertion {
  if (!isImportabilitySentinelCandidate(block, candidate)) {
    return candidate;
  }
  return {
    ...candidate,
    confidence: "medium",
    recommendation:
      "Review or document this importability sentinel instead of deleting it mechanically; document why runtime module-load coverage matters if it protects export wiring, or replace it with observable behavior if it only repeats type information.",
    reasonCategory: "importability-sentinel",
    suggestedAction: "review-or-document",
  };
}

// Sentinel candidates need both a module-load style test name and static import evidence.
function isImportabilitySentinelCandidate(block: FunctionBlock, candidate: StaticAnalysisRedundantAssertion): boolean {
  return hasImportabilitySentinelName(block.name) && hasStaticImportProof(candidate);
}

// Test names that say export/import/module contract imply the assertion may protect wiring.
function hasImportabilitySentinelName(testName: string): boolean {
  return /\b(?:importability|module[-\s]+load|load[-\s]+graph|exports?|contract)\b/i.test(testName);
}

// Static import proof distinguishes module-load sentinels from ordinary type-shape assertions.
function hasStaticImportProof(candidate: StaticAnalysisRedundantAssertion): boolean {
  return candidate.sourceProof !== undefined && /\bimport\b/i.test(candidate.staticFact) && /\bstatic(?:ally)?\b/i.test(candidate.staticFact);
}

// Renders the finding message from the final confidence/actionability decision.
function staticAnalysisRedundantMessage(block: FunctionBlock, candidate: StaticAnalysisRedundantAssertion): string {
  if (candidate.reasonCategory === "importability-sentinel") {
    return `Review importability sentinel: ${candidate.confidence} confidence. Test \`${block.name}\` asserts static import shape rather than behaviour: ${candidate.assertion}.`;
  }
  return `Static-analysis-redundant candidate: ${candidate.confidence} confidence. Test \`${block.name}\` asserts code shape rather than behaviour: ${candidate.assertion}.`;
}

// Type guard used after optional candidate builders so callers keep precise arrays.
function isStaticAnalysisRedundantAssertion(candidate: StaticAnalysisRedundantAssertion | undefined): candidate is StaticAnalysisRedundantAssertion {
  return candidate !== undefined;
}

// Collapses whitespace so finding messages carry readable one-line assertion snippets.
function normalizedAssertionText(assertion: string): string {
  return assertion.replace(/\s+/g, " ").trim();
}

// Checks masked code at the match offset so comment/string matches cannot create findings.
function isExecutableAssertionAt(codeSource: string, index: number): boolean {
  return /\b(?:assert|expect)\b/.test(codeSource.slice(index, index + 12));
}

// Checks masked code at the match offset so comment/string declarations are ignored.
function isExecutableFunctionDeclarationAt(codeSource: string, index: number): boolean {
  return /\b(?:function|const)\b/.test(codeSource.slice(index, index + 12));
}

// Checks masked code at the match offset so commented import examples are ignored.
function isExecutableImportAt(codeSource: string, index: number): boolean {
  return /\bimport\b/.test(codeSource.slice(index, index + 12));
}

// Stores one declaration only when the name is present and the return type is non-nullable.
function pushNonNullableReturnDeclaration(declarations: Map<string, NonNullableReturnDeclaration>, source: string, index: number, name: string, returnType: string): void {
  const normalizedReturnType = returnType.replace(/\s+/g, " ").trim();
  if (!name || !isNonNullableReturnType(normalizedReturnType)) {
    return;
  }
  declarations.set(name, { name, returnType: normalizedReturnType, lineOffset: lineOffset(source, index) });
}

// Treats explicit nullable, unknown, and non-returning types as not useful static proof.
function isNonNullableReturnType(returnType: string): boolean {
  if (returnType === "" || /^(?:any|unknown|void|null|undefined|never)$/.test(returnType)) {
    return false;
  }
  return !/\b(?:null|undefined)\b/.test(returnType);
}
