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

/**
 * Report stable test-quality.static-analysis-redundant-test findings with the assertion, proof, and recommendation together for review.
 * The finding location stands in when the candidate has no proof location.
 *
 * @param file - source file used to locate findings and their evidence
 * @param block - test block that supplies the name and starting line
 * @param rawBody - original test text used to match assertions and compute line offsets
 * @param codeBody - test text used to confirm matches occur in executable code
 * @param staticContext - surrounding source used to establish static facts
 * @param findings - caller's list that receives each qualifying advisory
 * @returns Nothing. Appends findings and their review evidence to the supplied list.
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

// Returns redundant assertion candidates with recommendations for the test block, in deterministic source order.
// Uses the file to anchor evidence, rawSource for assertion text, codeSource to check executable code, and staticContext for declaration facts.
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

// Apply pattern to rawSource and return supported typeof-function candidates, or an empty list when none qualify.
// Forward file to the builder that discards it. Use codeSource to screen masked matches and functionFacts for declaration or import evidence.
function typeofFunctionAssertionsForPattern(file: SourceFile, rawSource: string, codeSource: string, functionFacts: StaticFunctionFacts, pattern: RegExp): StaticAnalysisRedundantAssertion[] {
  return [...rawSource.matchAll(pattern)]
    .map((match) => typeofFunctionCandidateFromMatch(file, rawSource, codeSource, functionFacts, match))
    .filter(isStaticAnalysisRedundantAssertion);
}

// Convert match from rawSource into a candidate using functionFacts as evidence. The shared builder discards file and rawSource.
// codeSource checks executable code; return undefined for a non-executable match or an expression without a static fact.
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

// Build and return identifier and namespace-import facts from context's raw and masked source, using file for proof locations.
function staticFunctionFacts(file: SourceFile, context: StaticAnalysisSourceContext): StaticFunctionFacts {
  const facts: StaticFunctionFacts = { identifiers: new Map(), namespaceImports: new Map() };
  pushFunctionDeclarationFacts(file, context, facts.identifiers);
  pushConstFunctionFacts(file, context, facts.identifiers);
  pushImportFunctionFacts(file, context, facts);
  return facts;
}

// Adds facts for function declarations, checking context's masked source because comments and strings can mimic declarations.
// Use context's raw source with file and context.startLine for proof locations.
// Returns nothing and adds entries to facts in place, replacing any existing entry with the same name.
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
// Read executable declarations from context, using file and context.startLine for proof locations.
// Returns nothing and adds entries to facts in place, replacing any existing entry with the same name.
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
// Read context's source and masked code, using file and context.startLine for proof locations.
// Returns nothing and mutates facts.identifiers and facts.namespaceImports in place, replacing entries with matching names.
function pushImportFunctionFacts(file: SourceFile, context: StaticAnalysisSourceContext, facts: StaticFunctionFacts): void {
  pushNamedImportFunctionFacts(file, context, facts.identifiers);
  pushNamespaceImportFunctionFacts(file, context, facts.namespaceImports);
}

// Adds facts for static named imports, including aliases, when the import is executable code.
// Use context's raw and masked source with file and context.startLine for proof locations; skip type-only imports and specifiers.
// Returns nothing and adds entries to facts in place, replacing any existing entry with the same local name.
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

// Adds facts for namespace imports because namespace member assertions need import-level proof.
// Use context's raw and masked source with file and context.startLine for proof locations.
// Returns nothing and adds entries to facts in place, replacing any existing entry with the same namespace name.
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
// Use importedName in the fact text and preserve proof as sourceProof in the returned fact.
function namedImportFunctionFact(importedName: string, proof: string): StaticFunctionFact {
  return {
    staticFact: `\`${importedName}\` is a static ES module named import, so TypeScript can validate the imported binding's declared function type without executing this test assertion.`,
    sourceProof: proof,
  };
}

// Finds the local binding names available to test assertions.
// importClause supplies the comma-separated text between import braces. Return the local value names.
// Omit empty, type-only, and unsupported specifiers; return an empty array if none remain.
function namedImportLocals(importClause: string): string[] {
  return importClause
    .split(",")
    .map((specifier) => namedImportLocal(specifier))
    .filter((value): value is string => value !== undefined);
}

// Returns the local binding name for one named import specifier, ignoring type-only entries.
// Return undefined for empty text, an initial word type, or text with neither a trailing alias nor a plain identifier.
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

// Return declaration or import evidence for expression using the identifier and namespace maps in facts.
// Returns undefined unless an identifier fact matches or expression names a single member of a recorded namespace import.
// For a namespace expression, the evidence comes from the import and the member name is checked only for its syntax.
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

// Return file's display path and 1-based proof line for the UTF-16 code-unit index in context.source, based at context.startLine.
function sourceProof(file: SourceFile, context: StaticAnalysisSourceContext, index: number): string {
  return `${file.displayPath}:${context.startLine + lineOffset(context.source, index)}`;
}

// Detects self-instance assertions where the constructor expression itself proves the relationship.
function directConstructionInstanceAssertions(file: SourceFile, rawSource: string, codeSource: string): StaticAnalysisRedundantAssertion[] {
  return DIRECT_CONSTRUCTION_ASSERTION_PATTERNS.flatMap((pattern) => directConstructionInstanceAssertionsForPattern(file, rawSource, codeSource, pattern));
}

// Evaluates one direct-construction assertion grammar against executable test code.
// Apply global pattern to rawSource and validate positions with codeSource; file is forwarded to the shared builder but not retained.
// Return the surviving candidates, or an empty array if none qualify.
function directConstructionInstanceAssertionsForPattern(file: SourceFile, rawSource: string, codeSource: string, pattern: RegExp): StaticAnalysisRedundantAssertion[] {
  return [...rawSource.matchAll(pattern)]
    .map((match) => directConstructionInstanceCandidate(file, rawSource, codeSource, match))
    .filter(isStaticAnalysisRedundantAssertion);
}

// Builds one direct-construction candidate with a source-order index for stable sorting.
// Use match for assertion text and codeSource for executable-position checks; file and rawSource are forwarded but not retained.
// Return undefined for a masked assertion, otherwise return the candidate.
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

// Looks for assertions that repeat non-nullability suggested by a local return annotation, using a text check.
// Read rawSource for local declarations and assertions, using codeSource to reject masked positions.
// Use file and block for proof locations; return the matching candidates, or an empty array if none qualify.
function nonNullableReturnAssertions(file: SourceFile, block: FunctionBlock, rawSource: string, codeSource: string): StaticAnalysisRedundantAssertion[] {
  const declarations = nonNullableReturnDeclarations(rawSource, codeSource);
  return NON_NULLABLE_ASSERTION_PATTERNS.flatMap((pattern) => nonNullableReturnAssertionsForPattern(file, block, rawSource, codeSource, declarations, pattern));
}

// Evaluates one non-nullable assertion grammar against collected return-type declarations.
// Match global pattern against rawSource, using declarations for evidence and codeSource for executable-position checks.
// Use file and block for proof locations; return matching candidates or an empty array when none qualify.
function nonNullableReturnAssertionsForPattern(file: SourceFile, block: FunctionBlock, rawSource: string, codeSource: string, declarations: Map<string, NonNullableReturnDeclaration>, pattern: RegExp): StaticAnalysisRedundantAssertion[] {
  return [...rawSource.matchAll(pattern)]
    .map((match) => nonNullableReturnCandidate(file, block, rawSource, codeSource, declarations, match))
    .filter(isStaticAnalysisRedundantAssertion);
}

// Builds one non-nullable-return candidate only when declaration evidence exists.
// Use match for assertion text and callee lookup in declarations, codeSource to reject masked positions, and file plus block for proof lines.
// Return a candidate only for an executable match with a declaration, otherwise undefined; rawSource is forwarded but not retained.
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

// Collects function and const-arrow declarations whose return annotations pass the text check for non-nullability.
// Use source for declaration text and codeSource for executable positions; return a map keyed by name, empty when no declarations qualify.
function nonNullableReturnDeclarations(source: string, codeSource: string): Map<string, NonNullableReturnDeclaration> {
  const declarations = new Map<string, NonNullableReturnDeclaration>();
  for (const pattern of NON_NULLABLE_DECLARATION_PATTERNS) {
    pushNonNullableReturnDeclarationsForPattern(declarations, source, codeSource, pattern);
  }
  return declarations;
}

// Adds declaration evidence for one grammar while ignoring masked comments and strings.
// Match global pattern against source and use codeSource to reject masked declarations.
// Returns nothing and mutates declarations in place with accepted return types and line offsets, replacing entries with the same name.
function pushNonNullableReturnDeclarationsForPattern(declarations: Map<string, NonNullableReturnDeclaration>, source: string, codeSource: string, pattern: RegExp): void {
  for (const match of source.matchAll(pattern)) {
    if (!isExecutableFunctionDeclarationAt(codeSource, match.index ?? 0)) {
      continue;
    }
    pushNonNullableReturnDeclaration(declarations, source, match.index ?? 0, match[1] ?? "", match[2] ?? "");
  }
}

// Return the candidate fields in args with high confidence and shared removal advice, omitting its file and source context.
function staticRedundantCandidate(args: Omit<StaticAnalysisRedundantAssertion, "confidence" | "recommendation"> & { file: SourceFile; source: string }): StaticAnalysisRedundantAssertion {
  const { file: _file, source: _source, ...candidate } = args;
  return {
    ...candidate,
    confidence: "high",
    recommendation: "Remove this assertion if it is the only behavior being tested, or replace it with an assertion about the returned value or observable behavior.",
  };
}

// Downgrades importability sentinel tests to review/document guidance instead of delete guidance.
// Use block's test name and candidate's static-import evidence to select the guidance.
// Return a medium-confidence copy for sentinels or candidate unchanged otherwise; the input candidate is not mutated.
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

// Returns true for test names with importability, module load, load graph, export, or contract cues that suggest a wiring check.
function hasImportabilitySentinelName(testName: string): boolean {
  return /\b(?:importability|module[-\s]+load|load[-\s]+graph|exports?|contract)\b/i.test(testName);
}

// Static import proof distinguishes module-load sentinels from ordinary type-shape assertions.
// Return whether candidate has sourceProof and whole-word import plus static or statically in staticFact, ignoring case.
function hasStaticImportProof(candidate: StaticAnalysisRedundantAssertion): boolean {
  return candidate.sourceProof !== undefined && /\bimport\b/i.test(candidate.staticFact) && /\bstatic(?:ally)?\b/i.test(candidate.staticFact);
}

// Renders the finding message from the final confidence/actionability decision.
// Return text containing block's test name and candidate's assertion and confidence, with sentinel-specific wording when applicable.
function staticAnalysisRedundantMessage(block: FunctionBlock, candidate: StaticAnalysisRedundantAssertion): string {
  if (candidate.reasonCategory === "importability-sentinel") {
    return `Review importability sentinel: ${candidate.confidence} confidence. Test \`${block.name}\` asserts static import shape rather than behaviour: ${candidate.assertion}.`;
  }
  return `Static-analysis-redundant candidate: ${candidate.confidence} confidence. Test \`${block.name}\` asserts code shape rather than behaviour: ${candidate.assertion}.`;
}

// Type guard used after optional candidate builders so callers keep precise arrays.
// Return false for undefined candidate values; return true and narrow candidate for retained assertions.
function isStaticAnalysisRedundantAssertion(candidate: StaticAnalysisRedundantAssertion | undefined): candidate is StaticAnalysisRedundantAssertion {
  return candidate !== undefined;
}

// Collapses whitespace so finding messages carry readable one-line assertion snippets.
function normalizedAssertionText(assertion: string): string {
  return assertion.replace(/\s+/g, " ").trim();
}

// Returns true if assert or expect appears as a whole word in the first 12 masked characters starting at the raw assertion match.
// The caller discards the candidate when this check fails.
function isExecutableAssertionAt(codeSource: string, index: number): boolean {
  return /\b(?:assert|expect)\b/.test(codeSource.slice(index, index + 12));
}

// Returns true if function or const appears as a whole word in the 12 masked characters starting at the raw declaration match.
// The caller skips the declaration candidate when this check fails.
function isExecutableFunctionDeclarationAt(codeSource: string, index: number): boolean {
  return /\b(?:function|const)\b/.test(codeSource.slice(index, index + 12));
}

// Returns true if import appears as a whole word in the 12 masked characters starting at the raw import match.
// The caller skips the import candidate when this check fails.
function isExecutableImportAt(codeSource: string, index: number): boolean {
  return /\bimport\b/.test(codeSource.slice(index, index + 12));
}

// Stores one declaration only when the name is present and the return annotation passes the text check for non-nullability.
// Update declarations in place under name, replacing an existing entry; normalize returnType before checking it.
// Returns nothing and leaves declarations unchanged for an empty name or rejected return type. Uses source and index for the line offset.
function pushNonNullableReturnDeclaration(declarations: Map<string, NonNullableReturnDeclaration>, source: string, index: number, name: string, returnType: string): void {
  const normalizedReturnType = returnType.replace(/\s+/g, " ").trim();
  if (!name || !isNonNullableReturnType(normalizedReturnType)) {
    return;
  }
  declarations.set(name, { name, returnType: normalizedReturnType, lineOffset: lineOffset(source, index) });
}

// Assess returnType as non-nullability evidence; empty text and standalone any, unknown, void, null, undefined, or never yield false.
// Otherwise return true unless the annotation contains null or undefined as a word.
function isNonNullableReturnType(returnType: string): boolean {
  if (returnType === "" || /^(?:any|unknown|void|null|undefined|never)$/.test(returnType)) {
    return false;
  }
  return !/\b(?:null|undefined)\b/.test(returnType);
}
