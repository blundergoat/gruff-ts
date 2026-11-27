// Detects tests whose assertions only re-verify facts TypeScript's type checker already proves at compile time.
//
// Keeps the main per-test-block pass in `test-block-rules.ts` focused on structural orchestration.
// Distinguishes runtime payload checks from redundant shape or importability sentinels before emitting advisories.
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

/**
 * Collect redundant assertion candidates with recommendations for a test block in deterministic source order.
 *
 * @param file - source file used to anchor proof locations
 * @param block - test block checked for importability-sentinel naming and declaration line offsets
 * @param rawSource - raw test body text matched for assertions and local declarations
 * @param codeSource - masked test body text used to confirm matches lie in executable code
 * @param staticContext - surrounding file source used to gather function declaration and import facts
 * @returns Redundant assertion candidates sorted by source index.
 */
function staticAnalysisRedundantAssertions(file: SourceFile, block: FunctionBlock, rawSource: string, codeSource: string, staticContext: StaticAnalysisSourceContext): StaticAnalysisRedundantAssertion[] {
  return [
    ...typeofFunctionAssertions(file, rawSource, codeSource, staticContext),
    ...directConstructionInstanceAssertions(file, rawSource, codeSource),
    ...nonNullableReturnAssertions(file, block, rawSource, codeSource),
  ]
    .map((candidate) => staticAnalysisActionabilityCandidate(block, candidate))
    .sort((left, right) => left.index - right.index);
}

/**
 * Detect `typeof x === "function"`-style assertions when TypeScript already proves the function binding.
 *
 * @param file - source file used to anchor static proof locations
 * @param rawSource - raw test body text scanned against typeof-function assertion patterns
 * @param codeSource - masked test body text used to confirm matches lie in executable code
 * @param staticContext - surrounding file source scanned for function declarations and static imports
 * @returns Matching typeof-function redundant assertion candidates across all supported patterns.
 */
function typeofFunctionAssertions(file: SourceFile, rawSource: string, codeSource: string, staticContext: StaticAnalysisSourceContext): StaticAnalysisRedundantAssertion[] {
  const functionFacts = staticFunctionFacts(file, staticContext);
  return TYPEOF_FUNCTION_ASSERTION_PATTERNS.flatMap((pattern) => typeofFunctionAssertionsForPattern(file, rawSource, codeSource, functionFacts, pattern));
}

/**
 * Apply one typeof-function assertion pattern to raw test source and keep candidates backed by static facts.
 *
 * @param file - source file forwarded to the shared candidate builder
 * @param rawSource - raw test body text matched with the assertion pattern
 * @param codeSource - masked test body text used to screen out non-executable matches
 * @param functionFacts - collected identifier and namespace-import facts used as static evidence
 * @param pattern - global regular expression matching one typeof-function assertion form
 * @returns Qualifying typeof-function candidates for this pattern, or an empty array when none qualify.
 */
function typeofFunctionAssertionsForPattern(file: SourceFile, rawSource: string, codeSource: string, functionFacts: StaticFunctionFacts, pattern: RegExp): StaticAnalysisRedundantAssertion[] {
  return [...rawSource.matchAll(pattern)]
    .map((match) => typeofFunctionCandidateFromMatch(file, rawSource, codeSource, functionFacts, match))
    .filter(isStaticAnalysisRedundantAssertion);
}

/**
 * Convert one typeof-function regex match into a redundant-assertion candidate when static evidence exists.
 *
 * @param file - source file forwarded to the shared candidate builder (not retained)
 * @param rawSource - raw test body text forwarded to the shared candidate builder (not retained)
 * @param codeSource - masked test body text used to verify the match is executable code
 * @param functionFacts - collected identifier and namespace-import facts used to look up the tested expression
 * @param match - regex match carrying the assertion slice, start index, and captured target expression
 * @returns Candidate with static fact and proof, or undefined when non-executable or lacking a static fact.
 */
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

/**
 * Collect identifier and namespace-import function facts from the surrounding source context.
 *
 * @param file - source file whose display path anchors generated proof locations
 * @param context - full-file raw and masked source context with starting line offset
 * @returns Collected identifier and namespace-import function fact maps.
 */
function staticFunctionFacts(file: SourceFile, context: StaticAnalysisSourceContext): StaticFunctionFacts {
  const facts: StaticFunctionFacts = { identifiers: new Map(), namespaceImports: new Map() };
  pushFunctionDeclarationFacts(file, context, facts.identifiers);
  pushConstFunctionFacts(file, context, facts.identifiers);
  pushImportFunctionFacts(file, context, facts);
  return facts;
}

/**
 * Record facts for executable function declarations, checking masked source because comments and strings can mimic declarations.
 *
 * @param file - source file whose display path anchors proof locations
 * @param context - source context supplying raw source, masked code source, and start line
 * @param facts - identifier fact map populated in place, replacing any existing entry with the same name
 * @returns Nothing. Adds executable function declaration facts to `facts` in place.
 */
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

/**
 * Record facts for executable const-bound functions because these declarations are common test helper shapes.
 *
 * @param file - source file whose display path anchors proof locations
 * @param context - source context supplying raw source, masked code source, and start line
 * @param facts - identifier fact map populated in place, replacing any existing entry with the same name
 * @returns Nothing. Reads executable declarations from `context` and adds entries to `facts` in place.
 */
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

/**
 * Dispatch named and namespace import evidence into separate fact maps for later expression lookup.
 *
 * @param file - source file whose display path anchors proof locations
 * @param context - source context supplying raw source, masked code source, and start line
 * @param facts - fact bundle whose `identifiers` and `namespaceImports` maps are populated in place
 * @returns Nothing. Reads `context` and mutates `facts.identifiers` and `facts.namespaceImports` in place.
 */
function pushImportFunctionFacts(file: SourceFile, context: StaticAnalysisSourceContext, facts: StaticFunctionFacts): void {
  pushNamedImportFunctionFacts(file, context, facts.identifiers);
  pushNamespaceImportFunctionFacts(file, context, facts.namespaceImports);
}

/**
 * Record facts for static named imports, including aliases, while skipping type-only imports and specifiers.
 *
 * @param file - source file whose display path anchors proof locations
 * @param context - source context supplying raw source, masked code source, and start line
 * @param facts - identifier fact map populated in place, replacing any existing entry with the same local name
 * @returns Nothing. Adds executable named-import facts to `facts` in place.
 */
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

/**
 * Record facts for namespace imports because namespace member assertions need import-level proof.
 *
 * @param file - source file whose display path anchors proof locations
 * @param context - source context supplying raw source, masked code source, and start line
 * @param facts - namespace-import fact map populated in place, replacing any existing entry with the same name
 * @returns Nothing. Adds executable namespace-import facts to `facts` in place.
 */
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

/**
 * Build the reviewer-facing static fact record for one named import binding.
 *
 * @param importedName - local binding name embedded in the generated static fact text
 * @param proof - formatted `path:line` proof location preserved as `sourceProof`
 * @returns Static function fact containing the named-import explanation and source proof.
 */
function namedImportFunctionFact(importedName: string, proof: string): StaticFunctionFact {
  return {
    staticFact: `\`${importedName}\` is a static ES module named import, so TypeScript can validate the imported binding's declared function type without executing this test assertion.`,
    sourceProof: proof,
  };
}

/**
 * Extract local value binding names from a braced named-import clause, omitting empty, type-only, and unsupported specifiers.
 *
 * @param importClause - comma-separated specifier text inside an `import { ... }` clause
 * @returns Local value binding names available to assertions, or an empty array if none remain.
 */
function namedImportLocals(importClause: string): string[] {
  return importClause
    .split(",")
    .map((specifier) => namedImportLocal(specifier))
    .filter((value): value is string => value !== undefined);
}

/**
 * Extract the local binding name from a single named-import specifier, ignoring empty and type-only entries.
 *
 * @param specifier - single comma-separated import specifier segment to inspect
 * @returns Local identifier or alias name, or undefined for empty, `type`-prefixed, or unsupported forms.
 */
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

/**
 * Look up declaration or import evidence for a tested expression using identifier and namespace-import facts.
 * For namespace members, evidence comes from the namespace import and the member name is checked only for identifier syntax.
 *
 * @param expression - target identifier or `namespace.member` expression from a `typeof` assertion
 * @param facts - collected identifier and namespace-import facts for the file
 * @returns Matching static fact, or undefined unless an identifier or valid namespace member matches.
 */
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

/**
 * Format a `displayPath:line` proof string for a UTF-16 code-unit offset within the source context.
 *
 * @param file - source file providing the display path
 * @param context - source context supplying `source` and its 1-based `startLine`
 * @param index - UTF-16 code-unit index within `context.source`
 * @returns Formatted `path:line` proof location anchored at `context.startLine`.
 */
function sourceProof(file: SourceFile, context: StaticAnalysisSourceContext, index: number): string {
  return `${file.displayPath}:${context.startLine + lineOffset(context.source, index)}`;
}

/**
 * Detect `new Foo() instanceof Foo`-style assertions where the constructor expression itself proves the instance relationship.
 *
 * @param file - source file forwarded to the shared candidate builder
 * @param rawSource - raw test body text scanned against direct-construction assertion patterns
 * @param codeSource - masked test body text used to confirm matches lie in executable code
 * @returns Qualifying direct-construction redundant assertion candidates across all supported patterns.
 */
function directConstructionInstanceAssertions(file: SourceFile, rawSource: string, codeSource: string): StaticAnalysisRedundantAssertion[] {
  return DIRECT_CONSTRUCTION_ASSERTION_PATTERNS.flatMap((pattern) => directConstructionInstanceAssertionsForPattern(file, rawSource, codeSource, pattern));
}

/**
 * Evaluate one direct-construction assertion pattern against executable test code.
 *
 * @param file - source file forwarded to the shared candidate builder (not retained)
 * @param rawSource - raw test body text matched with the global assertion pattern
 * @param codeSource - masked test body text used to validate executable match positions
 * @param pattern - global regular expression matching one direct-construction assertion grammar
 * @returns Surviving direct-construction candidates, or an empty array when none qualify.
 */
function directConstructionInstanceAssertionsForPattern(file: SourceFile, rawSource: string, codeSource: string, pattern: RegExp): StaticAnalysisRedundantAssertion[] {
  return [...rawSource.matchAll(pattern)]
    .map((match) => directConstructionInstanceCandidate(file, rawSource, codeSource, match))
    .filter(isStaticAnalysisRedundantAssertion);
}

/**
 * Build one direct-construction candidate with a source-order index for stable sorting.
 *
 * @param file - source file forwarded to the shared candidate builder (not retained)
 * @param rawSource - raw test body text forwarded to the shared candidate builder (not retained)
 * @param codeSource - masked test body text used to confirm the match is in executable code
 * @param match - regex match supplying the assertion text, index, and constructed class name
 * @returns Candidate for an executable match, or undefined when the match is masked.
 */
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

/**
 * Detect assertions that repeat non-nullability already declared on a local function return annotation.
 *
 * @param file - source file whose display path anchors declaration proof locations
 * @param block - test block providing the starting line for declaration offsets
 * @param rawSource - raw test body text read for local declarations and non-nullability assertions
 * @param codeSource - masked test body text used to reject masked declaration and assertion positions
 * @returns Matching non-nullable-return candidates, or an empty array when none qualify.
 */
function nonNullableReturnAssertions(file: SourceFile, block: FunctionBlock, rawSource: string, codeSource: string): StaticAnalysisRedundantAssertion[] {
  const declarations = nonNullableReturnDeclarations(rawSource, codeSource);
  return NON_NULLABLE_ASSERTION_PATTERNS.flatMap((pattern) => nonNullableReturnAssertionsForPattern(file, block, rawSource, codeSource, declarations, pattern));
}

/**
 * Evaluate one non-nullable assertion pattern against collected local return-type declarations.
 *
 * @param file - source file whose display path anchors declaration proof locations
 * @param block - test block providing the starting line for declaration offsets
 * @param rawSource - raw test body text matched against the global assertion pattern
 * @param codeSource - masked test body text used to verify executable assertion positions
 * @param declarations - map of local declarations with non-nullable return annotations
 * @param pattern - global regular expression matching one non-nullable assertion grammar
 * @returns Matching candidates for this pattern, or an empty array when none qualify.
 */
function nonNullableReturnAssertionsForPattern(file: SourceFile, block: FunctionBlock, rawSource: string, codeSource: string, declarations: Map<string, NonNullableReturnDeclaration>, pattern: RegExp): StaticAnalysisRedundantAssertion[] {
  return [...rawSource.matchAll(pattern)]
    .map((match) => nonNullableReturnCandidate(file, block, rawSource, codeSource, declarations, match))
    .filter(isStaticAnalysisRedundantAssertion);
}

/**
 * Build one non-nullable-return candidate only when matching local declaration evidence exists.
 *
 * @param file - source file used to format the declaration proof path
 * @param block - test block whose `startLine` anchors the declaration line offset
 * @param rawSource - raw test body text forwarded to the shared candidate builder (not retained)
 * @param codeSource - masked test body text used to reject masked match positions
 * @param declarations - collected local declarations keyed by callee name
 * @param match - regex match providing the assertion text, index, and called function name
 * @returns Candidate only for an executable match backed by a declaration, otherwise undefined.
 */
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

/**
 * Collect local function and const-arrow declarations whose return annotations pass the non-nullability text check.
 *
 * @param source - raw source text scanned for local declaration signatures
 * @param codeSource - masked source text used to filter out non-executable declarations
 * @returns Map of qualifying declarations keyed by function name, empty when none qualify.
 */
function nonNullableReturnDeclarations(source: string, codeSource: string): Map<string, NonNullableReturnDeclaration> {
  const declarations = new Map<string, NonNullableReturnDeclaration>();
  for (const pattern of NON_NULLABLE_DECLARATION_PATTERNS) {
    pushNonNullableReturnDeclarationsForPattern(declarations, source, codeSource, pattern);
  }
  return declarations;
}

/**
 * Collect non-nullable return declaration evidence for one declaration grammar while ignoring masked comments and strings.
 *
 * @param declarations - declaration map mutated in place with accepted entries, replacing duplicates by name
 * @param source - raw source text matched against the declaration pattern
 * @param codeSource - masked source text used to reject masked declaration matches
 * @param pattern - global regular expression matching one annotated declaration grammar
 * @returns Nothing. Mutates `declarations` in place with qualifying return types and line offsets.
 */
function pushNonNullableReturnDeclarationsForPattern(declarations: Map<string, NonNullableReturnDeclaration>, source: string, codeSource: string, pattern: RegExp): void {
  for (const match of source.matchAll(pattern)) {
    if (!isExecutableFunctionDeclarationAt(codeSource, match.index ?? 0)) {
      continue;
    }
    pushNonNullableReturnDeclaration(declarations, source, match.index ?? 0, match[1] ?? "", match[2] ?? "");
  }
}

/**
 * Assemble a redundant-assertion candidate with default high confidence and shared removal advice, omitting context fields.
 *
 * @param args - candidate payload fields plus transient `file` and `source` context fields to strip
 * @returns Candidate object with `confidence` set to `"high"` and the shared `recommendation`.
 */
function staticRedundantCandidate(args: Omit<StaticAnalysisRedundantAssertion, "confidence" | "recommendation"> & { file: SourceFile; source: string }): StaticAnalysisRedundantAssertion {
  const { file: _file, source: _source, ...candidate } = args;
  return {
    ...candidate,
    confidence: "high",
    recommendation: "Remove this assertion if it is the only behavior being tested, or replace it with an assertion about the returned value or observable behavior.",
  };
}

/**
 * Downgrade importability sentinel tests to review-or-document guidance instead of mechanical deletion advice.
 *
 * @param block - test block whose name is checked for importability-sentinel cues
 * @param candidate - candidate assertion evaluated for static-import proof without mutating the input
 * @returns Medium-confidence copy with sentinel guidance when applicable, or `candidate` unchanged.
 */
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

/**
 * Check whether a candidate represents an importability sentinel combining module-load test naming and static import evidence.
 *
 * @param block - test block supplying the test name
 * @param candidate - candidate carrying static fact text and optional source proof
 * @returns True when both the test name and candidate proof indicate an importability sentinel.
 */
function isImportabilitySentinelCandidate(block: FunctionBlock, candidate: StaticAnalysisRedundantAssertion): boolean {
  return hasImportabilitySentinelName(block.name) && hasStaticImportProof(candidate);
}

/**
 * Check whether a test name contains importability, module-load, load-graph, export, or contract cues suggesting a wiring check.
 *
 * @param testName - display name of the test block under review
 * @returns True if `testName` matches any importability-sentinel keyword.
 */
function hasImportabilitySentinelName(testName: string): boolean {
  return /\b(?:importability|module[-\s]+load|load[-\s]+graph|exports?|contract)\b/i.test(testName);
}

/**
 * Check whether a candidate carries static-import proof distinguishing module-load sentinels from ordinary type-shape assertions.
 *
 * @param candidate - candidate whose `sourceProof` and `staticFact` fields are inspected
 * @returns True when `sourceProof` is defined and `staticFact` mentions both `import` and `static`/`statically`.
 */
function hasStaticImportProof(candidate: StaticAnalysisRedundantAssertion): boolean {
  return candidate.sourceProof !== undefined && /\bimport\b/i.test(candidate.staticFact) && /\bstatic(?:ally)?\b/i.test(candidate.staticFact);
}

/**
 * Render the reviewer-facing finding message from the final confidence and actionability decision.
 *
 * @param block - test block supplying the test name embedded in the message
 * @param candidate - final candidate supplying confidence, normalized assertion, and optional sentinel category
 * @returns Formatted message with sentinel review wording or standard redundant-candidate wording.
 */
function staticAnalysisRedundantMessage(block: FunctionBlock, candidate: StaticAnalysisRedundantAssertion): string {
  if (candidate.reasonCategory === "importability-sentinel") {
    return `Review importability sentinel: ${candidate.confidence} confidence. Test \`${block.name}\` asserts static import shape rather than behaviour: ${candidate.assertion}.`;
  }
  return `Static-analysis-redundant candidate: ${candidate.confidence} confidence. Test \`${block.name}\` asserts code shape rather than behaviour: ${candidate.assertion}.`;
}

/**
 * Narrow optional candidate results after pattern matching so callers retain a non-nullable array.
 *
 * @param candidate - candidate value or undefined returned from a single-match builder
 * @returns True when `candidate` is defined, narrowing its type; false for undefined.
 */
function isStaticAnalysisRedundantAssertion(candidate: StaticAnalysisRedundantAssertion | undefined): candidate is StaticAnalysisRedundantAssertion {
  return candidate !== undefined;
}

/**
 * Collapse internal whitespace runs and trim an assertion match into a readable one-line snippet.
 *
 * @param assertion - raw matched assertion substring from the test body
 * @returns Normalized single-line assertion text.
 */
function normalizedAssertionText(assertion: string): string {
  return assertion.replace(/\s+/g, " ").trim();
}

/**
 * Verify that an assertion match starts on executable `assert` or `expect` tokens rather than masked text.
 *
 * @param codeSource - masked source text where comments and strings are blanked out
 * @param index - starting UTF-16 offset of the raw assertion match
 * @returns True if `assert` or `expect` appears as a whole word within the 12-character slice at `index`.
 */
function isExecutableAssertionAt(codeSource: string, index: number): boolean {
  return /\b(?:assert|expect)\b/.test(codeSource.slice(index, index + 12));
}

/**
 * Verify that a declaration match starts on executable `function` or `const` tokens rather than masked text.
 *
 * @param codeSource - masked source text where comments and strings are blanked out
 * @param index - starting UTF-16 offset of the raw declaration match
 * @returns True if `function` or `const` appears as a whole word within the 12-character slice at `index`.
 */
function isExecutableFunctionDeclarationAt(codeSource: string, index: number): boolean {
  return /\b(?:function|const)\b/.test(codeSource.slice(index, index + 12));
}

/**
 * Verify that an import match starts on an executable `import` keyword rather than masked text.
 *
 * @param codeSource - masked source text where comments and strings are blanked out
 * @param index - starting UTF-16 offset of the raw import match
 * @returns True if `import` appears as a whole word within the 12-character slice at `index`.
 */
function isExecutableImportAt(codeSource: string, index: number): boolean {
  return /\bimport\b/.test(codeSource.slice(index, index + 12));
}

/**
 * Store one declaration only when `name` is non-empty and its normalized return annotation passes the non-nullability text check.
 *
 * @param declarations - declaration map updated in place under `name`, replacing any existing entry
 * @param source - raw source text used with `index` to compute the declaration line offset
 * @param index - UTF-16 offset of the declaration match in `source`
 * @param name - declared function or const-arrow identifier name
 * @param returnType - raw captured return-type annotation normalized before validation
 * @returns Nothing. Updates `declarations` in place, or leaves it unchanged for empty names or rejected return types.
 */
function pushNonNullableReturnDeclaration(declarations: Map<string, NonNullableReturnDeclaration>, source: string, index: number, name: string, returnType: string): void {
  const normalizedReturnType = returnType.replace(/\s+/g, " ").trim();
  if (!name || !isNonNullableReturnType(normalizedReturnType)) {
    return;
  }
  declarations.set(name, { name, returnType: normalizedReturnType, lineOffset: lineOffset(source, index) });
}

/**
 * Assess whether a normalized return-type annotation serves as non-nullability evidence.
 * Rejects empty text, standalone `any`/`unknown`/`void`/`null`/`undefined`/`never`, and annotations mentioning `null` or `undefined`.
 *
 * @param returnType - trimmed, whitespace-normalized return-type annotation text
 * @returns True when the annotation names a non-nullable return type; false otherwise.
 */
function isNonNullableReturnType(returnType: string): boolean {
  if (returnType === "" || /^(?:any|unknown|void|null|undefined|never)$/.test(returnType)) {
    return false;
  }
  return !/\b(?:null|undefined)\b/.test(returnType);
}
