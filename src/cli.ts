#!/usr/bin/env node
import { Command } from "commander";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { createServer } from "node:http";
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { argv, chdir, cwd } from "node:process";
import { basename, dirname as dirnamePath, extname, isAbsolute, join, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const VERSION = "0.1.0";
const DEFAULT_BASELINE = "gruff-baseline.json";
const DEFAULT_CONFIG_FILES = [".gruff.json", ".gruff.yaml", ".gruff.yml"] as const;
const NPATH_CAP = 1_000_000;

export type Severity = "advisory" | "warning" | "error";
export type Pillar =
  | "size"
  | "complexity"
  | "dead-code"
  | "waste"
  | "naming"
  | "documentation"
  | "modernisation"
  | "security"
  | "sensitive-data"
  | "test-quality"
  | "design";
type Confidence = "low" | "medium" | "high";
type OutputFormat = "text" | "json" | "html" | "markdown" | "github" | "hotspot";
type FailThreshold = "none" | "advisory" | "warning" | "error";
type RuleListFormat = "text" | "json";

export interface Finding {
  ruleId: string;
  message: string;
  filePath: string;
  line?: number;
  endLine?: number;
  column?: number;
  severity: Severity;
  pillar: Pillar;
  secondaryPillars: Pillar[];
  tier: "v0.1";
  confidence: Confidence;
  symbol?: string;
  remediation?: string;
  metadata: Record<string, unknown>;
  fingerprint: string;
}

interface RunDiagnostic {
  diagnosticType: string;
  message: string;
  filePath?: string;
  line?: number;
}

export interface AnalysisReport {
  schemaVersion: "gruff.analysis.v1";
  tool: { name: "gruff-ts"; version: string };
  run: { projectRoot: string; format: OutputFormat; failOn: FailThreshold; generatedAt: string };
  summary: { advisory: number; warning: number; error: number; total: number };
  paths: { analysedFiles: number; ignoredPaths: string[]; missingPaths: string[] };
  diagnostics: RunDiagnostic[];
  findings: Finding[];
  score: {
    composite: number;
    grade: string;
    pillars: Array<{ pillar: Pillar; score: number; findings: number }>;
    topOffenders: Array<{ filePath: string; score: number; findings: number }>;
  };
  baseline?: { path: string; source: string; suppressed: number; generated: boolean };
}

interface AnalysisOptions {
  paths: string[];
  config?: string;
  noConfig: boolean;
  format: OutputFormat;
  failOn: FailThreshold;
  includeIgnored: boolean;
  diff?: string;
  historyFile?: string;
  baseline?: string;
  generateBaseline?: string;
  noBaseline: boolean;
}

interface Config {
  ignoredPaths: string[];
  acceptedAbbreviations: Set<string>;
  secretPreviews: Set<string>;
  rules: Map<string, { enabled?: boolean; thresholds: Map<string, number> }>;
}

interface SourceFile {
  absolutePath: string;
  displayPath: string;
  isTypeScript: boolean;
}

interface ProjectSource {
  file: SourceFile;
  source: string;
  lines: string[];
}

interface ProjectIndex {
  sources: ProjectSource[];
  typeScriptSources: ProjectSource[];
  sourcePaths: Set<string>;
  importsByFile: Map<string, ImportEdge[]>;
}

interface ImportEdge {
  specifier: string;
  line: number;
  parentSegments: number;
  targetPath?: string;
}

interface FunctionBlock {
  name: string;
  params: string;
  startLine: number;
  lineCount: number;
  body: string;
  isPublic: boolean;
  isTest: boolean;
}

interface NormalizeContext {
  allowBaselineFlag: boolean;
}

export interface RuleDescriptor {
  ruleId: string;
  pillar: Pillar;
  severity: Severity;
  confidence: Confidence;
  description: string;
  remediation: string;
  thresholdKeys?: readonly string[];
  fixtureExemption?: string;
}

const RULE_DESCRIPTORS: readonly RuleDescriptor[] = [
  { ruleId: "complexity.cognitive", pillar: "complexity", severity: "warning", confidence: "high", description: "Flags functions with high combined branch and nesting complexity.", remediation: "Split nested decisions into smaller named functions.", thresholdKeys: ["warn"] },
  { ruleId: "complexity.cyclomatic", pillar: "complexity", severity: "warning", confidence: "high", description: "Flags functions with many independent branch paths.", remediation: "Reduce branching or move policy tables out of imperative code.", thresholdKeys: ["error", "warn"] },
  { ruleId: "complexity.npath", pillar: "complexity", severity: "warning", confidence: "medium", description: "Flags functions with high approximate NPath complexity.", remediation: "Break apart compound branch combinations.", thresholdKeys: ["error", "warn"] },
  { ruleId: "dead-code.unused-private-method", pillar: "dead-code", severity: "advisory", confidence: "low", description: "Flags private methods without an apparent same-file call site.", remediation: "Remove the method or add a direct call site." },
  { ruleId: "design.circular-import", pillar: "design", severity: "warning", confidence: "medium", description: "Flags simple relative import cycles inside the discovered source set.", remediation: "Extract the shared contract or invert one dependency." },
  { ruleId: "design.deep-relative-import", pillar: "design", severity: "advisory", confidence: "medium", description: "Flags relative imports that climb too many parent directories.", remediation: "Move the shared module closer or add a local boundary.", thresholdKeys: ["maxParentSegments"] },
  { ruleId: "design.god-function", pillar: "design", severity: "warning", confidence: "high", description: "Flags functions that are both long and complex.", remediation: "Split responsibilities into smaller functions." },
  { ruleId: "design.large-module-concentration", pillar: "design", severity: "advisory", confidence: "medium", description: "Flags a production module that dominates project source lines.", remediation: "Split unrelated responsibilities once stable seams are visible.", thresholdKeys: ["maxSharePercent", "minFiles", "minLines"] },
  { ruleId: "design.package-bin-missing", pillar: "design", severity: "warning", confidence: "high", description: "Flags package bin entries that point at missing files.", remediation: "Update the bin path or add the executable file." },
  { ruleId: "design.package-bin-not-executable", pillar: "design", severity: "warning", confidence: "high", description: "Flags package bin targets that are not executable.", remediation: "Make the bin target executable and keep its shebang valid." },
  { ruleId: "docs.missing-param-tag", pillar: "documentation", severity: "advisory", confidence: "medium", description: "Flags documented exports with parameters missing @param tags.", remediation: "Document every current parameter in the JSDoc." },
  { ruleId: "docs.missing-public-doc", pillar: "documentation", severity: "advisory", confidence: "medium", description: "Flags exported APIs without a nearby doc comment.", remediation: "Add a short comment explaining the public API contract." },
  { ruleId: "docs.missing-return-tag", pillar: "documentation", severity: "advisory", confidence: "medium", description: "Flags documented non-void exports without @returns.", remediation: "Document the returned value or remove stale JSDoc." },
  { ruleId: "docs.stale-param-tag", pillar: "documentation", severity: "advisory", confidence: "medium", description: "Flags @param tags for parameters no longer in the signature.", remediation: "Remove stale tags or update the function signature." },
  { ruleId: "docs.todo-density", pillar: "documentation", severity: "advisory", confidence: "high", description: "Flags files with a high count of TODO/FIXME markers.", remediation: "Resolve stale markers or link them to tracked work.", thresholdKeys: ["markers"] },
  { ruleId: "docs.useless-docblock", pillar: "documentation", severity: "advisory", confidence: "medium", description: "Flags docblocks that only restate the symbol name.", remediation: "Replace the comment with useful contract or behavior detail." },
  { ruleId: "modernisation.double-cast", pillar: "modernisation", severity: "warning", confidence: "medium", description: "Flags casts through unknown or any into another type.", remediation: "Use a parser, type guard, or narrower assertion." },
  { ruleId: "modernisation.non-null-assertion", pillar: "modernisation", severity: "warning", confidence: "medium", description: "Flags non-null assertions that bypass null checks.", remediation: "Narrow the value or handle null and undefined explicitly." },
  { ruleId: "modernisation.nullish-coalescing-candidate", pillar: "modernisation", severity: "advisory", confidence: "medium", description: "Flags || fallbacks that may erase valid falsy values.", remediation: "Use ?? when only null or undefined should fall back." },
  { ruleId: "modernisation.optional-chaining-candidate", pillar: "modernisation", severity: "advisory", confidence: "medium", description: "Flags repeated guard-and-property access patterns.", remediation: "Use optional chaining for clearer null-safe access." },
  { ruleId: "modernisation.public-property", pillar: "modernisation", severity: "advisory", confidence: "high", description: "Flags public class properties that expose representation.", remediation: "Prefer readonly properties or accessors when invariants matter." },
  { ruleId: "modernisation.readonly-property-candidate", pillar: "modernisation", severity: "advisory", confidence: "medium", description: "Flags class properties that appear readonly-worthy.", remediation: "Mark the property readonly when mutation is not part of the contract." },
  { ruleId: "modernisation.ts-comment-without-rationale", pillar: "modernisation", severity: "warning", confidence: "medium", description: "Flags TypeScript suppression comments without a rationale.", remediation: "Add a short reason or remove the suppression." },
  { ruleId: "modernisation.tsconfig-exact-optional-disabled", pillar: "modernisation", severity: "warning", confidence: "high", description: "Flags tsconfig files without exactOptionalPropertyTypes enabled.", remediation: "Enable exactOptionalPropertyTypes unless migration is blocked." },
  { ruleId: "modernisation.tsconfig-index-safety-disabled", pillar: "modernisation", severity: "warning", confidence: "high", description: "Flags tsconfig files without noUncheckedIndexedAccess enabled.", remediation: "Enable noUncheckedIndexedAccess unless migration is blocked." },
  { ruleId: "modernisation.tsconfig-strict-disabled", pillar: "modernisation", severity: "warning", confidence: "high", description: "Flags tsconfig files without strict mode enabled.", remediation: "Enable strict unless migration is blocked." },
  { ruleId: "modernisation.var-declaration", pillar: "modernisation", severity: "advisory", confidence: "high", description: "Flags var declarations.", remediation: "Use let or const with the narrowest useful scope." },
  { ruleId: "naming.boolean-prefix", pillar: "naming", severity: "advisory", confidence: "medium", description: "Flags boolean names without intent-revealing prefixes.", remediation: "Use prefixes such as is, has, can, should, or will." },
  { ruleId: "naming.class-file-mismatch", pillar: "naming", severity: "advisory", confidence: "medium", description: "Flags exported classes whose name differs from the file name.", remediation: "Rename the class or file so the primary export is easy to locate." },
  { ruleId: "naming.generic-function", pillar: "naming", severity: "advisory", confidence: "high", description: "Flags generic function names that hide intent.", remediation: "Name the domain action instead of a generic operation." },
  { ruleId: "naming.hungarian-notation", pillar: "naming", severity: "advisory", confidence: "medium", description: "Flags identifiers named after storage type prefixes.", remediation: "Name the domain concept instead of the storage type." },
  { ruleId: "naming.identifier-quality", pillar: "naming", severity: "advisory", confidence: "medium", description: "Flags placeholder or numbered identifiers.", remediation: "Use names that explain domain role or intent." },
  { ruleId: "naming.short-variable", pillar: "naming", severity: "advisory", confidence: "medium", description: "Flags very short variable names outside common loop counters.", remediation: "Use a name that describes the domain role." },
  { ruleId: "security.async-foreach", pillar: "security", severity: "warning", confidence: "medium", description: "Flags async callbacks passed to forEach.", remediation: "Use for...of with await, Promise.all, or an explicit queue." },
  { ruleId: "security.disabled-tls-verification", pillar: "security", severity: "error", confidence: "high", description: "Flags code that disables TLS certificate verification.", remediation: "Remove the override and fix certificate trust at the source." },
  { ruleId: "security.document-write", pillar: "security", severity: "warning", confidence: "high", description: "Flags document.write usage.", remediation: "Use safe DOM APIs and encode untrusted content." },
  { ruleId: "security.eval-call", pillar: "security", severity: "error", confidence: "high", description: "Flags eval() dynamic code execution.", remediation: "Replace eval with explicit parsing or a safe dispatch table." },
  { ruleId: "security.floating-promise", pillar: "security", severity: "warning", confidence: "medium", description: "Flags promise-like calls without await, return, or void.", remediation: "Await it, return it, or mark intentional fire-and-forget with void." },
  { ruleId: "security.inner-html", pillar: "security", severity: "warning", confidence: "high", description: "Flags innerHTML assignment.", remediation: "Use safe DOM APIs or sanitize trusted HTML centrally." },
  { ruleId: "security.insecure-random", pillar: "security", severity: "warning", confidence: "high", description: "Flags Math.random usage in source.", remediation: "Use crypto-backed randomness for security-sensitive values." },
  { ruleId: "security.new-function", pillar: "security", severity: "error", confidence: "high", description: "Flags Function constructor dynamic code execution.", remediation: "Replace dynamic construction with explicit functions or dispatch." },
  { ruleId: "security.process-exec", pillar: "security", severity: "warning", confidence: "high", description: "Flags child-process execution calls.", remediation: "Validate arguments and prefer fixed command vectors." },
  { ruleId: "security.remote-install-script", pillar: "security", severity: "error", confidence: "medium", description: "Flags package scripts that pipe remote content to a shell.", remediation: "Vendor, pin, or remove remote shell execution." },
  { ruleId: "security.risky-lifecycle-script", pillar: "security", severity: "warning", confidence: "medium", description: "Flags package lifecycle scripts that run automatically.", remediation: "Move setup behind an explicit command when possible." },
  { ruleId: "security.sql-concatenation", pillar: "security", severity: "warning", confidence: "high", description: "Flags SQL text composed with runtime string interpolation.", remediation: "Use parameterized queries or query builders." },
  { ruleId: "security.string-timer", pillar: "security", severity: "warning", confidence: "high", description: "Flags string callbacks passed to timers.", remediation: "Pass a function callback instead of source text." },
  { ruleId: "security.throw-non-error", pillar: "security", severity: "warning", confidence: "medium", description: "Flags thrown non-Error values.", remediation: "Throw an Error subclass with a clear message." },
  { ruleId: "security.url-dependency", pillar: "security", severity: "warning", confidence: "medium", description: "Flags dependencies installed from URL or git specs.", remediation: "Prefer registry versions that can be locked and audited." },
  { ruleId: "security.weak-crypto", pillar: "security", severity: "warning", confidence: "high", description: "Flags weak crypto primitives such as md5, sha1, or createCipher.", remediation: "Use modern algorithms and authenticated encryption." },
  { ruleId: "sensitive-data.api-key-pattern", pillar: "sensitive-data", severity: "error", confidence: "high", description: "Flags vendor API key patterns.", remediation: "Remove the secret and load it from a secure runtime source." },
  { ruleId: "sensitive-data.aws-access-key", pillar: "sensitive-data", severity: "error", confidence: "high", description: "Flags AWS access key looking values.", remediation: "Remove the key and rotate it immediately." },
  { ruleId: "sensitive-data.database-url-password", pillar: "sensitive-data", severity: "error", confidence: "high", description: "Flags database URLs that include passwords.", remediation: "Move credentials into a secret store or runtime environment." },
  { ruleId: "sensitive-data.hardcoded-env-value", pillar: "sensitive-data", severity: "error", confidence: "medium", description: "Flags environment-style secret values committed in text.", remediation: "Load secret-like values from secure runtime configuration.", thresholdKeys: ["minLength"] },
  { ruleId: "sensitive-data.high-entropy-string", pillar: "sensitive-data", severity: "error", confidence: "medium", description: "Flags high-entropy string literals that may be secrets.", remediation: "Remove the value and load it from a secure runtime source.", thresholdKeys: ["minLength"] },
  { ruleId: "sensitive-data.jwt-token", pillar: "sensitive-data", severity: "error", confidence: "high", description: "Flags JWT-looking token literals.", remediation: "Remove the token and rotate the credential if real." },
  { ruleId: "sensitive-data.pii-pattern", pillar: "sensitive-data", severity: "error", confidence: "high", description: "Flags PII-like identifier patterns.", remediation: "Remove personal data from source and fixtures." },
  { ruleId: "sensitive-data.private-key", pillar: "sensitive-data", severity: "error", confidence: "high", description: "Flags private key block markers.", remediation: "Remove the key material and rotate affected credentials." },
  { ruleId: "size.file-length", pillar: "size", severity: "warning", confidence: "high", description: "Flags files longer than configured thresholds.", remediation: "Split unrelated responsibilities into smaller files.", thresholdKeys: ["error", "warn"] },
  { ruleId: "size.function-length", pillar: "size", severity: "warning", confidence: "high", description: "Flags functions longer than configured thresholds.", remediation: "Extract named helpers or split workflows.", thresholdKeys: ["error", "warn"] },
  { ruleId: "size.parameter-count", pillar: "size", severity: "warning", confidence: "high", description: "Flags functions with too many parameters.", remediation: "Group related options or reduce the function's responsibility.", thresholdKeys: ["warn"] },
  { ruleId: "test-quality.conditional-logic", pillar: "test-quality", severity: "advisory", confidence: "high", description: "Flags tests with conditional logic.", remediation: "Split branch-specific expectations into separate tests." },
  { ruleId: "test-quality.exception-type-only", pillar: "test-quality", severity: "advisory", confidence: "high", description: "Flags tests that only assert exception type.", remediation: "Assert message, code, or observable behavior as well." },
  { ruleId: "test-quality.global-state-mutation", pillar: "test-quality", severity: "warning", confidence: "high", description: "Flags tests mutating process or global runtime state.", remediation: "Isolate state changes and restore them around the test." },
  { ruleId: "test-quality.loop-in-test", pillar: "test-quality", severity: "advisory", confidence: "high", description: "Flags loops inside test bodies.", remediation: "Use table tests or separate named cases." },
  { ruleId: "test-quality.magic-number-assertion", pillar: "test-quality", severity: "advisory", confidence: "medium", description: "Flags assertions against unexplained numeric literals.", remediation: "Name expected values or assert domain-specific outcomes." },
  { ruleId: "test-quality.missing-nearby-test", pillar: "test-quality", severity: "advisory", confidence: "medium", description: "Flags exported production files without nearby tests.", remediation: "Add a focused test beside the source or in a nearby test directory." },
  { ruleId: "test-quality.mock-only-test", pillar: "test-quality", severity: "advisory", confidence: "high", description: "Flags tests that only verify mock interaction.", remediation: "Assert observable behavior in addition to collaboration." },
  { ruleId: "test-quality.no-assertions", pillar: "test-quality", severity: "warning", confidence: "high", description: "Flags tests without apparent assertions.", remediation: "Add assertions for observable behavior." },
  { ruleId: "test-quality.no-throw-only-test", pillar: "test-quality", severity: "advisory", confidence: "high", description: "Flags tests that only assert code does not throw.", remediation: "Assert the observable result or state change." },
  { ruleId: "test-quality.only-skip", pillar: "test-quality", severity: "advisory", confidence: "high", description: "Flags focused or skipped test markers.", remediation: "Remove .only and either enable or delete skipped tests." },
  { ruleId: "test-quality.setup-bloat", pillar: "test-quality", severity: "advisory", confidence: "medium", description: "Flags tests with too much setup before the first assertion.", remediation: "Extract builders or reduce fixture setup.", thresholdKeys: ["maxSetupLines"] },
  { ruleId: "test-quality.sleep-in-test", pillar: "test-quality", severity: "advisory", confidence: "high", description: "Flags sleeps in tests.", remediation: "Synchronize on behavior instead of wall-clock time." },
  { ruleId: "test-quality.snapshot-only-test", pillar: "test-quality", severity: "advisory", confidence: "high", description: "Flags tests that rely only on snapshots.", remediation: "Add targeted assertions for important behavior." },
  { ruleId: "test-quality.trivial-assertion", pillar: "test-quality", severity: "warning", confidence: "high", description: "Flags tautological assertions.", remediation: "Assert a real result from the system under test." },
  { ruleId: "test-quality.unused-mock", pillar: "test-quality", severity: "advisory", confidence: "medium", description: "Flags mocks created but not used.", remediation: "Remove unused mocks or wire them into the behavior under test." },
  { ruleId: "waste.any-type", pillar: "waste", severity: "warning", confidence: "high", description: "Flags any type usage.", remediation: "Use unknown with validation or a precise type." },
  { ruleId: "waste.broad-runtime-version", pillar: "waste", severity: "advisory", confidence: "medium", description: "Flags broad runtime dependency version ranges.", remediation: "Use bounded semver ranges and lockfiles." },
  { ruleId: "waste.commented-out-code", pillar: "waste", severity: "advisory", confidence: "high", description: "Flags comments that appear to contain disabled code.", remediation: "Delete dead code or restore it behind a real feature path." },
  { ruleId: "waste.console-log", pillar: "waste", severity: "advisory", confidence: "high", description: "Flags console log/debug calls in source.", remediation: "Remove debug logging or route through structured logging." },
  { ruleId: "waste.empty-function", pillar: "waste", severity: "advisory", confidence: "high", description: "Flags functions with no executable body.", remediation: "Delete the function or add the missing implementation." },
  { ruleId: "waste.exported-any", pillar: "waste", severity: "warning", confidence: "medium", description: "Flags exported APIs exposing any.", remediation: "Use a named interface, unknown with validation, or precise generics." },
  { ruleId: "waste.redundant-variable", pillar: "waste", severity: "advisory", confidence: "medium", description: "Flags variables returned immediately after assignment.", remediation: "Return the expression directly." },
  { ruleId: "waste.swallowed-catch", pillar: "waste", severity: "warning", confidence: "medium", description: "Flags empty catch blocks.", remediation: "Handle, report, rethrow, or document intentional ignore paths." },
  { ruleId: "waste.unreachable-code", pillar: "waste", severity: "warning", confidence: "high", description: "Flags statements after terminating statements.", remediation: "Delete unreachable code or restructure the control flow." },
  { ruleId: "waste.unused-import", pillar: "waste", severity: "advisory", confidence: "medium", description: "Flags named imports with no apparent usage.", remediation: "Remove unused imports." },
  { ruleId: "waste.unused-parameter", pillar: "waste", severity: "advisory", confidence: "medium", description: "Flags parameters with no apparent usage.", remediation: "Remove the parameter or prefix it with _ if intentional." },
];

export function ruleDescriptors(): RuleDescriptor[] {
  return [...RULE_DESCRIPTORS].sort((left, right) => left.ruleId.localeCompare(right.ruleId));
}

export function analyse(options: AnalysisOptions): AnalysisReport {
  const projectRoot = cwd();
  const config = loadConfig(projectRoot, options);
  const diagnostics: RunDiagnostic[] = [];
  const discovery = discoverSources(projectRoot, options, config);

  if (options.diff) {
    const changed = changedFiles(options.diff);
    discovery.files = discovery.files.filter((file) => changed.has(file.displayPath));
  }

  for (const missingPath of discovery.missingPaths) {
    diagnostics.push({
      diagnosticType: "missing-path",
      message: `Input path does not exist: ${missingPath}`,
      filePath: missingPath,
    });
  }

  let findings: Finding[] = [];
  const projectSources: ProjectSource[] = [];
  for (const file of discovery.files) {
    try {
      const source = readFileSync(file.absolutePath, "utf8");
      const lines = source.split(/\r?\n/);
      projectSources.push({ file, source, lines });
      diagnostics.push(...parseDiagnostics(file, source));
      findings.push(...analyseSource(file, source, config));
    } catch (error) {
      diagnostics.push({
        diagnosticType: "read-error",
        message: `Unable to read file: ${String(error)}`,
        filePath: file.displayPath,
        line: 1,
      });
    }
  }
  findings.push(...analyseProjectIndex(projectSources, config).filter((finding) => ruleEnabled(config, finding.ruleId)));

  let baseline: AnalysisReport["baseline"];
  if (options.generateBaseline) {
    const baselinePath = absolutize(projectRoot, options.generateBaseline);
    writeBaseline(baselinePath, findings);
    baseline = {
      path: displayPath(projectRoot, baselinePath),
      source: "generated",
      suppressed: 0,
      generated: true,
    };
  } else if (!options.noBaseline) {
    const selected = options.baseline
      ? { path: absolutize(projectRoot, options.baseline), source: "explicit" }
      : existsSync(join(projectRoot, DEFAULT_BASELINE))
        ? { path: join(projectRoot, DEFAULT_BASELINE), source: "default" }
        : undefined;
    if (selected) {
      const before = findings.length;
      findings = applyBaseline(selected.path, findings);
      baseline = {
        path: displayPath(projectRoot, selected.path),
        source: selected.source,
        suppressed: before - findings.length,
        generated: false,
      };
    }
  }

  findings.sort(
    (left, right) =>
      left.filePath.localeCompare(right.filePath) ||
      (left.line ?? 0) - (right.line ?? 0) ||
      left.ruleId.localeCompare(right.ruleId) ||
      left.message.localeCompare(right.message),
  );
  findings = dedupeFindings(findings);

  if (options.historyFile) {
    recordHistory(projectRoot, options.historyFile, findings, diagnostics);
  }

  return {
    schemaVersion: "gruff.analysis.v1",
    tool: { name: "gruff-ts", version: VERSION },
    run: {
      projectRoot,
      format: options.format,
      failOn: options.failOn,
      generatedAt: new Date().toISOString(),
    },
    summary: summarize(findings),
    paths: {
      analysedFiles: discovery.files.length,
      ignoredPaths: discovery.ignoredPaths,
      missingPaths: discovery.missingPaths,
    },
    diagnostics,
    findings,
    score: scoreReport(findings),
    ...(baseline ? { baseline } : {}),
  };
}

function defaultConfig(): Config {
  return {
    ignoredPaths: [],
    acceptedAbbreviations: new Set(["id", "db", "io", "ui", "tx", "rx"]),
    secretPreviews: new Set(),
    rules: new Map(),
  };
}

function loadConfig(projectRoot: string, options: AnalysisOptions): Config {
  const config = defaultConfig();
  if (options.noConfig) {
    return config;
  }
  const path = options.config ? absolutize(projectRoot, options.config) : defaultConfigPath(projectRoot);
  if (!path) {
    return config;
  }

  const raw = parseConfigFile(path);
  const paths = objectValue(raw.paths);
  config.ignoredPaths = arrayValue(paths?.ignore).filter(isString);

  const allowlists = objectValue(raw.allowlists);
  const abbreviations = arrayValue(allowlists?.acceptedAbbreviations).filter(isString);
  if (abbreviations.length > 0) {
    config.acceptedAbbreviations = new Set(abbreviations.map((value) => value.toLowerCase()));
  }
  config.secretPreviews = new Set(arrayValue(allowlists?.secretPreviews).filter(isString));

  const rules = objectValue(raw.rules);
  if (rules) {
    for (const [ruleId, value] of Object.entries(rules)) {
      const rule = objectValue(value);
      if (!rule) {
        continue;
      }
      const thresholds = new Map<string, number>();
      const rawThresholds = objectValue(rule.thresholds);
      if (rawThresholds) {
        for (const [name, threshold] of Object.entries(rawThresholds)) {
          if (typeof threshold === "number") {
            thresholds.set(name, threshold);
          }
        }
      }
      config.rules.set(ruleId, {
        ...(typeof rule.enabled === "boolean" ? { enabled: rule.enabled } : {}),
        thresholds,
      });
    }
  }

  return config;
}

function defaultConfigPath(projectRoot: string): string | undefined {
  for (const fileName of DEFAULT_CONFIG_FILES) {
    const candidate = join(projectRoot, fileName);
    if (existsSync(candidate)) {
      return candidate;
    }
  }
  return undefined;
}

function parseConfigFile(path: string): Record<string, unknown> {
  const source = readFileSync(path, "utf8");
  const extension = extname(path).toLowerCase();
  const parsed = extension === ".yaml" || extension === ".yml" ? parseYamlConfig(source) : (JSON.parse(source) as unknown);
  const config = objectValue(parsed);
  if (!config) {
    throw new Error(`Config file must contain an object: ${path}`);
  }
  return config;
}

interface YamlLine {
  indent: number;
  content: string;
}

function parseYamlConfig(source: string): Record<string, unknown> {
  const lines = yamlLines(source);
  let index = 0;

  function parseBlock(indent: number): unknown {
    const line = lines[index];
    if (!line || line.indent < indent) {
      return {};
    }
    return line.content.startsWith("- ") || line.content === "-" ? parseYamlArray(line.indent) : parseYamlObject(line.indent);
  }

  function parseYamlObject(indent: number): Record<string, unknown> {
    const result: Record<string, unknown> = {};
    while (index < lines.length) {
      const line = lines[index];
      if (!line || line.indent < indent) {
        break;
      }
      if (line.indent > indent) {
        throw new Error(`Invalid YAML indentation near "${line.content}".`);
      }
      if (line.content.startsWith("- ") || line.content === "-") {
        break;
      }

      const pair = splitYamlKeyValue(line.content);
      if (!pair) {
        throw new Error(`Invalid YAML mapping line: "${line.content}".`);
      }
      const [rawKey, rawValue] = pair;
      const key = unquoteYaml(rawKey.trim());
      const value = rawValue.trim();
      index += 1;

      if (value.length > 0) {
        result[key] = parseYamlScalar(value);
        continue;
      }

      const next = lines[index];
      result[key] = next && next.indent > indent ? parseBlock(next.indent) : {};
    }
    return result;
  }

  function parseYamlArray(indent: number): unknown[] {
    const result: unknown[] = [];
    while (index < lines.length) {
      const line = lines[index];
      if (!line || line.indent < indent) {
        break;
      }
      if (line.indent > indent) {
        throw new Error(`Invalid YAML indentation near "${line.content}".`);
      }
      if (!line.content.startsWith("- ") && line.content !== "-") {
        break;
      }

      const item = line.content === "-" ? "" : line.content.slice(2).trim();
      index += 1;
      if (item.length === 0) {
        const next = lines[index];
        result.push(next && next.indent > indent ? parseBlock(next.indent) : null);
        continue;
      }

      const pair = splitYamlKeyValue(item);
      if (pair) {
        const [rawKey, rawValue] = pair;
        const value = rawValue.trim();
        const entry: Record<string, unknown> = {};
        const next = lines[index];
        entry[unquoteYaml(rawKey.trim())] = value.length > 0 ? parseYamlScalar(value) : next && next.indent > indent ? parseBlock(next.indent) : {};
        result.push(entry);
        continue;
      }

      result.push(parseYamlScalar(item));
    }
    return result;
  }

  const parsed = lines.length === 0 ? {} : parseBlock(lines[0]?.indent ?? 0);
  const config = objectValue(parsed);
  if (!config) {
    throw new Error("Config YAML must contain a mapping object.");
  }
  return config;
}

function yamlLines(source: string): YamlLine[] {
  const lines: YamlLine[] = [];
  for (const rawLine of source.replace(/\r\n/g, "\n").split("\n")) {
    const withoutComment = stripYamlComment(rawLine).trimEnd();
    if (withoutComment.trim().length === 0) {
      continue;
    }
    const indentText = withoutComment.match(/^\s*/)?.[0] ?? "";
    if (indentText.includes("\t")) {
      throw new Error("Tabs are not supported in gruff YAML config indentation.");
    }
    lines.push({ indent: indentText.length, content: withoutComment.trimStart() });
  }
  return lines;
}

function stripYamlComment(line: string): string {
  let quote: string | undefined;
  let escaped = false;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if (!character) {
      continue;
    }
    if (quote) {
      if (quote === "\"" && character === "\\" && !escaped) {
        escaped = true;
        continue;
      }
      if (character === quote && !escaped) {
        quote = undefined;
      }
      escaped = false;
      continue;
    }
    if (character === "\"" || character === "'") {
      quote = character;
      continue;
    }
    if (character === "#") {
      return line.slice(0, index);
    }
  }
  return line;
}

function splitYamlKeyValue(value: string): [string, string] | undefined {
  let quote: string | undefined;
  let escaped = false;
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (!character) {
      continue;
    }
    if (quote) {
      if (quote === "\"" && character === "\\" && !escaped) {
        escaped = true;
        continue;
      }
      if (character === quote && !escaped) {
        quote = undefined;
      }
      escaped = false;
      continue;
    }
    if (character === "\"" || character === "'") {
      quote = character;
      continue;
    }
    const next = value[index + 1];
    if (character === ":" && (!next || /\s/.test(next))) {
      return [value.slice(0, index), value.slice(index + 1)];
    }
  }
  return undefined;
}

function parseYamlScalar(value: string): unknown {
  const trimmed = value.trim();
  if (trimmed === "[]") {
    return [];
  }
  if (trimmed === "{}") {
    return {};
  }
  if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
    return parseYamlInlineArray(trimmed);
  }
  if (isQuotedYaml(trimmed)) {
    return unquoteYaml(trimmed);
  }
  if (/^(?:true|false)$/i.test(trimmed)) {
    return trimmed.toLowerCase() === "true";
  }
  if (/^(?:null|~)$/i.test(trimmed)) {
    return null;
  }
  if (/^-?(?:0|[1-9]\d*)(?:\.\d+)?$/.test(trimmed)) {
    return Number(trimmed);
  }
  return trimmed;
}

function parseYamlInlineArray(value: string): unknown[] {
  const inner = value.slice(1, -1).trim();
  if (inner.length === 0) {
    return [];
  }
  return splitYamlInlineItems(inner).map((item) => parseYamlScalar(item));
}

function splitYamlInlineItems(value: string): string[] {
  const items: string[] = [];
  let quote: string | undefined;
  let escaped = false;
  let start = 0;
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (!character) {
      continue;
    }
    if (quote) {
      if (quote === "\"" && character === "\\" && !escaped) {
        escaped = true;
        continue;
      }
      if (character === quote && !escaped) {
        quote = undefined;
      }
      escaped = false;
      continue;
    }
    if (character === "\"" || character === "'") {
      quote = character;
      continue;
    }
    if (character === ",") {
      items.push(value.slice(start, index).trim());
      start = index + 1;
    }
  }
  items.push(value.slice(start).trim());
  return items;
}

function isQuotedYaml(value: string): boolean {
  return value.length >= 2 && ((value.startsWith("\"") && value.endsWith("\"")) || (value.startsWith("'") && value.endsWith("'")));
}

function unquoteYaml(value: string): string {
  if (!isQuotedYaml(value)) {
    return value;
  }
  const quote = value[0];
  const body = value.slice(1, -1);
  if (quote === "'") {
    return body.replace(/''/g, "'");
  }
  return body.replace(/\\(["\\nrt])/g, (_match, escaped: string) => {
    if (escaped === "n") {
      return "\n";
    }
    if (escaped === "r") {
      return "\r";
    }
    if (escaped === "t") {
      return "\t";
    }
    return escaped;
  });
}

function discoverSources(projectRoot: string, options: AnalysisOptions, config: Config) {
  const files: SourceFile[] = [];
  const missingPaths: string[] = [];
  const ignoredPaths = new Set<string>();
  const inputs = options.paths.length > 0 ? options.paths : ["."];

  for (const input of inputs) {
    const absolute = absolutize(projectRoot, input);
    if (!existsSync(absolute)) {
      missingPaths.push(input);
      continue;
    }
    const stats = statSync(absolute);
    if (stats.isFile()) {
      pushSourceFile(projectRoot, absolute, files);
      continue;
    }
    walk(projectRoot, absolute, options, config, ignoredPaths, files);
  }

  files.sort((left, right) => left.displayPath.localeCompare(right.displayPath));
  return { files: uniqueFiles(files), missingPaths, ignoredPaths: [...ignoredPaths].sort() };
}

function walk(
  projectRoot: string,
  directory: string,
  options: AnalysisOptions,
  config: Config,
  ignoredPaths: Set<string>,
  files: SourceFile[],
): void {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const absolute = join(directory, entry.name);
    const display = displayPath(projectRoot, absolute);
    if (entry.isDirectory()) {
      if (
        (!options.includeIgnored && isDefaultIgnoredDir(display)) ||
        config.ignoredPaths.some((pattern) => pathMatches(pattern, display))
      ) {
        ignoredPaths.add(display);
        continue;
      }
      walk(projectRoot, absolute, options, config, ignoredPaths, files);
    } else if (entry.isFile()) {
      pushSourceFile(projectRoot, absolute, files);
    }
  }
}

function pushSourceFile(projectRoot: string, absolutePath: string, files: SourceFile[]): void {
  const extension = extname(absolutePath).slice(1).toLowerCase();
  const name = basename(absolutePath);
  const isTypeScript = ["ts", "tsx", "js", "jsx", "mjs", "cjs"].includes(extension);
  const isText =
    ["conf", "config", "env", "ini", "json", "toml", "xml", "yaml", "yml"].includes(extension) ||
    name.startsWith(".env");
  if (isTypeScript || isText) {
    files.push({ absolutePath, displayPath: displayPath(projectRoot, absolutePath), isTypeScript });
  }
}

function parseDiagnostics(file: SourceFile, source: string): RunDiagnostic[] {
  if (!file.isTypeScript) {
    return [];
  }
  let braces = 0;
  let parentheses = 0;
  let brackets = 0;
  const scan: DelimiterScanState = {
    quote: undefined,
    escaped: false,
    blockComment: false,
    regex: false,
    regexCharClass: false,
    regexEscaped: false,
    previousCode: "",
  };
  const lines = source.split(/\r?\n/);
  for (const [index, line] of lines.entries()) {
    for (let offset = 0; offset < line.length; offset += 1) {
      const character = line[offset] ?? "";
      const next = line[offset + 1] ?? "";
      if (scan.blockComment) {
        if (character === "*" && next === "/") {
          scan.blockComment = false;
          offset += 1;
        }
        continue;
      }
      if (scan.quote) {
        if (scan.escaped) {
          scan.escaped = false;
          continue;
        }
        if (character === "\\") {
          scan.escaped = true;
          continue;
        }
        if (character === scan.quote) {
          scan.quote = undefined;
        }
        continue;
      }
      if (scan.regex) {
        if (scan.regexEscaped) {
          scan.regexEscaped = false;
          continue;
        }
        if (character === "\\") {
          scan.regexEscaped = true;
          continue;
        }
        if (character === "[") {
          scan.regexCharClass = true;
          continue;
        }
        if (character === "]") {
          scan.regexCharClass = false;
          continue;
        }
        if (character === "/" && !scan.regexCharClass) {
          scan.regex = false;
          scan.previousCode = "x";
        }
        continue;
      }
      if (character === "/" && next === "/") {
        break;
      }
      if (character === "/" && next === "*") {
        scan.blockComment = true;
        offset += 1;
        continue;
      }
      if (character === "\"" || character === "'" || character === "`") {
        scan.quote = character;
        continue;
      }
      if (character === "/" && isRegexLiteralStart(scan.previousCode, line.slice(0, offset))) {
        scan.regex = true;
        scan.regexCharClass = false;
        scan.regexEscaped = false;
        continue;
      }
      if (character === "{") {
        braces += 1;
      } else if (character === "}") {
        braces -= 1;
      } else if (character === "(") {
        parentheses += 1;
      } else if (character === ")") {
        parentheses -= 1;
      } else if (character === "[") {
        brackets += 1;
      } else if (character === "]") {
        brackets -= 1;
      }
      if (character.trim() !== "") {
        scan.previousCode = character;
      }
    }
    if (braces < 0 || parentheses < 0 || brackets < 0) {
      return [
        {
          diagnosticType: "parse-error",
          message: "Unbalanced TypeScript delimiters detected.",
          filePath: file.displayPath,
          line: index + 1,
        },
      ];
    }
  }
  if (braces !== 0 || parentheses !== 0 || brackets !== 0) {
    return [
      {
        diagnosticType: "parse-error",
        message: "Unbalanced TypeScript delimiters detected.",
        filePath: file.displayPath,
        line: lines.length,
      },
    ];
  }
  return [];
}

interface DelimiterScanState {
  quote: string | undefined;
  escaped: boolean;
  blockComment: boolean;
  regex: boolean;
  regexCharClass: boolean;
  regexEscaped: boolean;
  previousCode: string;
}

function isRegexLiteralStart(previousCode: string, beforeSlash: string): boolean {
  return previousCode === "" || "([{=,:!&|?;".includes(previousCode) || /\breturn$/.test(beforeSlash.trimEnd());
}

function analyseSource(file: SourceFile, source: string, config: Config): Finding[] {
  const findings: Finding[] = [];
  analyseTextRules(file, source, config, findings);
  if (file.isTypeScript) {
    analyseTypeScriptRules(file, source, config, findings);
  }
  return findings.filter((finding) => ruleEnabled(config, finding.ruleId));
}

function analyseProjectIndex(projectSources: ProjectSource[], config: Config): Finding[] {
  const index = buildProjectIndex(projectSources);
  const findings: Finding[] = [];
  analyseArchitectureRules(index, config, findings);
  analyseTestAdequacyRules(index, findings);
  return findings;
}

function buildProjectIndex(projectSources: ProjectSource[]): ProjectIndex {
  const sources = [...projectSources].sort((left, right) => left.file.displayPath.localeCompare(right.file.displayPath));
  const typeScriptSources = sources.filter((source) => source.file.isTypeScript);
  const sourcePaths = new Set(typeScriptSources.map((source) => source.file.displayPath));
  const importsByFile = new Map<string, ImportEdge[]>();
  for (const source of typeScriptSources) {
    importsByFile.set(source.file.displayPath, importEdgesForSource(source, sourcePaths));
  }
  return { sources, typeScriptSources, sourcePaths, importsByFile };
}

function analyseArchitectureRules(index: ProjectIndex, config: Config, findings: Finding[]): void {
  analyseDeepRelativeImports(index, config, findings);
  analyseCircularImports(index, findings);
  analyseLargeModuleConcentration(index, config, findings);
}

function analyseTestAdequacyRules(index: ProjectIndex, findings: Finding[]): void {
  analyseMissingNearbyTests(index, findings);
}

function analyseDeepRelativeImports(index: ProjectIndex, config: Config, findings: Finding[]): void {
  const maxParentSegments = threshold(config, "design.deep-relative-import", "maxParentSegments", 2);
  for (const source of index.typeScriptSources) {
    const edges = index.importsByFile.get(source.file.displayPath) ?? [];
    for (const edge of edges) {
      if (edge.parentSegments <= maxParentSegments) {
        continue;
      }
      findings.push(
        makeFinding({
          ruleId: "design.deep-relative-import",
          message: `Relative import \`${edge.specifier}\` climbs ${edge.parentSegments} directories.`,
          filePath: source.file.displayPath,
          line: edge.line,
          severity: "advisory",
          pillar: "design",
          confidence: "medium",
          symbol: edge.specifier,
          remediation: "Move the shared module closer to the caller or introduce a local barrel/module boundary.",
          metadata: { specifier: edge.specifier, parentSegments: edge.parentSegments, maxParentSegments },
        }),
      );
    }
  }
}

function analyseCircularImports(index: ProjectIndex, findings: Finding[]): void {
  const cycles = importCycles(index);
  for (const cycle of cycles) {
    const anchorPath = cycle.files[0] ?? "";
    const anchorSource = index.typeScriptSources.find((source) => source.file.displayPath === anchorPath);
    if (!anchorSource) {
      continue;
    }
    const anchorEdges = index.importsByFile.get(anchorPath) ?? [];
    const line = anchorEdges.find((edge) => edge.targetPath && cycle.files.includes(edge.targetPath))?.line ?? 1;
    const cycleLabel = cycle.files.join(" -> ");
    findings.push(
      makeFinding({
        ruleId: "design.circular-import",
        message: `Import cycle detected among ${cycle.files.join(", ")}.`,
        filePath: anchorSource.file.displayPath,
        line,
        severity: "warning",
        pillar: "design",
        confidence: "medium",
        symbol: cycleLabel,
        remediation: "Extract the shared contract or move one dependency behind an explicit boundary.",
        metadata: { files: cycle.files },
      }),
    );
  }
}

function analyseLargeModuleConcentration(index: ProjectIndex, config: Config, findings: Finding[]): void {
  const minFiles = threshold(config, "design.large-module-concentration", "minFiles", 4);
  const minLines = threshold(config, "design.large-module-concentration", "minLines", 80);
  const maxSharePercent = threshold(config, "design.large-module-concentration", "maxSharePercent", 55);
  const modules = index.typeScriptSources
    .filter((source) => isProductionSourcePath(source.file.displayPath))
    .map((source) => ({ source, lines: source.lines.length }))
    .sort((left, right) => right.lines - left.lines || left.source.file.displayPath.localeCompare(right.source.file.displayPath));
  if (modules.length < minFiles) {
    return;
  }
  const totalLines = modules.reduce((sum, module) => sum + module.lines, 0);
  const largest = modules[0];
  if (!largest || totalLines === 0) {
    return;
  }
  const sharePercent = Math.round((largest.lines / totalLines) * 1000) / 10;
  if (largest.lines < minLines || sharePercent <= maxSharePercent) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "design.large-module-concentration",
      message: `Module \`${largest.source.file.displayPath}\` contains ${sharePercent}% of production source lines.`,
      filePath: largest.source.file.displayPath,
      line: 1,
      severity: "advisory",
      pillar: "design",
      confidence: "medium",
      symbol: fileBaseName(largest.source.file.displayPath),
      remediation: "Split unrelated responsibilities into smaller modules once stable seams are visible.",
      metadata: { lines: largest.lines, totalLines, sharePercent, minFiles, minLines, maxSharePercent },
    }),
  );
}

function importEdgesForSource(source: ProjectSource, sourcePaths: Set<string>): ImportEdge[] {
  const edges: ImportEdge[] = [];
  for (const [index, line] of source.lines.entries()) {
    for (const match of line.matchAll(/\b(?:import|export)\b(?:[^"'`]*?\bfrom\s*)?\s*["']([^"']+)["']/g)) {
      const specifier = match[1] ?? "";
      if (!specifier.startsWith(".")) {
        continue;
      }
      const targetPath = resolveRelativeImport(source.file.displayPath, specifier, sourcePaths);
      edges.push({
        specifier,
        line: index + 1,
        parentSegments: specifier.split("/").filter((segment) => segment === "..").length,
        ...(targetPath ? { targetPath } : {}),
      });
    }
  }
  return edges.sort((left, right) => left.line - right.line || left.specifier.localeCompare(right.specifier));
}

function resolveRelativeImport(importerPath: string, specifier: string, sourcePaths: Set<string>): string | undefined {
  const basePath = normalizeDisplayPath(join(dirnamePath(importerPath), specifier));
  for (const candidate of importPathCandidates(basePath)) {
    if (sourcePaths.has(candidate)) {
      return candidate;
    }
  }
  return undefined;
}

function importPathCandidates(basePath: string): string[] {
  const extensions = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"];
  const candidates = new Set<string>();
  if (extname(basePath)) {
    candidates.add(basePath);
    const withoutExtension = basePath.slice(0, -extname(basePath).length);
    for (const extension of extensions) {
      candidates.add(`${withoutExtension}${extension}`);
    }
  } else {
    for (const extension of extensions) {
      candidates.add(`${basePath}${extension}`);
      candidates.add(`${basePath}/index${extension}`);
    }
  }
  return [...candidates].map(normalizeDisplayPath);
}

function importCycles(index: ProjectIndex): Array<{ files: string[] }> {
  const cycles = new Map<string, string[]>();
  const paths = [...index.importsByFile.keys()].sort();
  for (const start of paths) {
    visitImportCycle(index, start, start, [start], new Set([start]), cycles);
  }
  return [...cycles.values()]
    .map((files) => ({ files }))
    .sort((left, right) => left.files.join("\0").localeCompare(right.files.join("\0")));
}

function visitImportCycle(
  index: ProjectIndex,
  start: string,
  current: string,
  path: string[],
  seen: Set<string>,
  cycles: Map<string, string[]>,
): void {
  const targets = [...new Set((index.importsByFile.get(current) ?? []).map((edge) => edge.targetPath).filter(isString))].sort();
  for (const target of targets) {
    if (target === start && path.length > 1) {
      const files = [...path].sort();
      cycles.set(files.join("\0"), files);
      continue;
    }
    if (seen.has(target) || path.length >= 12) {
      continue;
    }
    seen.add(target);
    visitImportCycle(index, start, target, [...path, target], seen, cycles);
    seen.delete(target);
  }
}

function isProductionSourcePath(path: string): boolean {
  return !isTestPath(path) && !isDeclarationPath(path) && !isFixtureLikePath(path) && !path.split("/").includes("generated");
}

function analyseMissingNearbyTests(index: ProjectIndex, findings: Finding[]): void {
  const testPaths = new Set(index.typeScriptSources.filter((source) => isTestPath(source.file.displayPath)).map((source) => source.file.displayPath));
  for (const source of index.typeScriptSources.filter((candidate) => isProductionSourcePath(candidate.file.displayPath))) {
    const exported = exportedSurface(source.source);
    if (!exported || hasNearbyTest(source.file.displayPath, testPaths)) {
      continue;
    }
    findings.push(
      makeFinding({
        ruleId: "test-quality.missing-nearby-test",
        message: `Exported source file \`${source.file.displayPath}\` has no nearby test file.`,
        filePath: source.file.displayPath,
        line: exported.line,
        severity: "advisory",
        pillar: "test-quality",
        confidence: "medium",
        symbol: exported.symbol,
        remediation: "Add a focused test beside the source file or under a nearby __tests__/tests directory.",
        metadata: { expectedTestBase: fileBaseName(source.file.displayPath) },
      }),
    );
  }
}

function exportedSurface(source: string): { symbol: string; line: number } | undefined {
  const match = source.match(/\bexport\s+(?:default\s+)?(?:async\s+)?(?:function|class|interface|type|enum|const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)/);
  if (!match?.[1]) {
    return undefined;
  }
  return { symbol: match[1], line: byteLine(source, match.index ?? 0) };
}

function hasNearbyTest(sourcePath: string, testPaths: Set<string>): boolean {
  const sourceBase = stripSourceExtension(sourcePath);
  const sourceName = basename(sourceBase);
  const sourceDir = displayDir(sourcePath);
  const nearbyDirs = new Set([sourceDir, joinDisplay(sourceDir, "__tests__"), joinDisplay(sourceDir, "tests"), "test", "tests"]);
  for (const testPath of testPaths) {
    const testBase = stripTestMarker(stripSourceExtension(testPath));
    if (basename(testBase) !== sourceName) {
      continue;
    }
    if (testBase === sourceBase || nearbyDirs.has(displayDir(testPath))) {
      return true;
    }
  }
  return false;
}

function stripSourceExtension(path: string): string {
  return path.replace(/\.[cm]?[tj]sx?$/, "");
}

function stripTestMarker(path: string): string {
  return path.replace(/\.(?:test|spec)$/, "");
}

function displayDir(path: string): string {
  const dir = normalizeDisplayPath(dirnamePath(path));
  return dir === "." ? "" : dir;
}

function joinDisplay(left: string, right: string): string {
  return left ? `${left}/${right}` : right;
}

function isTestPath(path: string): boolean {
  return /(?:^|\/)(?:__tests__|tests?|spec)\//.test(path) || /\.(?:test|spec)\.[cm]?[tj]sx?$/.test(path);
}

function isDeclarationPath(path: string): boolean {
  return /\.d\.[cm]?ts$/.test(path);
}

function isFixtureLikePath(path: string): boolean {
  return /(?:^|\/)(?:__fixtures__|fixtures?|testdata)\//.test(path);
}

function normalizeDisplayPath(path: string): string {
  return path.replaceAll("\\", "/").replace(/^\.\//, "");
}

function analyseTextRules(file: SourceFile, source: string, config: Config, findings: Finding[]): void {
  const lines = source.split(/\r?\n/).length;
  const warn = threshold(config, "size.file-length", "warn", 400);
  const error = threshold(config, "size.file-length", "error", 800);
  if (lines > error) {
    findings.push(finding("size.file-length", `File has ${lines} lines, above the error threshold of ${error}.`, file, 1, "error", "size"));
  } else if (lines > warn) {
    findings.push(finding("size.file-length", `File has ${lines} lines, above the warning threshold of ${warn}.`, file, 1, "warning", "size"));
  }

  const todoCount = countMatches(source, /\b(TODO|FIXME)\b/g);
  if (todoCount >= threshold(config, "docs.todo-density", "markers", 4)) {
    findings.push(finding("docs.todo-density", `File contains ${todoCount} TODO/FIXME markers.`, file, firstLine(source, /TODO|FIXME/), "advisory", "documentation"));
  }

  analyseSensitiveData(file, source, config, findings);
  analyseProjectConfigRules(file, source, findings);
}

function analyseProjectConfigRules(file: SourceFile, source: string, findings: Finding[]): void {
  const name = basename(file.displayPath);
  if (name !== "package.json" && name !== "tsconfig.json") {
    return;
  }
  const data = parseJsonObject(source);
  if (!data) {
    return;
  }
  if (name === "package.json") {
    analysePackageJson(file, source, data, findings);
  } else {
    analyseTsconfigJson(file, source, data, findings);
  }
}

function analysePackageJson(file: SourceFile, source: string, pkg: Record<string, unknown>, findings: Finding[]): void {
  const scripts = objectValue(pkg.scripts);
  if (scripts) {
    for (const [scriptName, value] of Object.entries(scripts)) {
      if (!isString(value)) {
        continue;
      }
      const line = jsonKeyLine(source, scriptName);
      if (isRemoteInstallScript(value)) {
        findings.push(
          makeFinding({
            ruleId: "security.remote-install-script",
            message: `Package script \`${scriptName}\` downloads and executes remote shell content.`,
            filePath: file.displayPath,
            line,
            severity: "error",
            pillar: "security",
            confidence: "medium",
            symbol: scriptName,
            remediation: "Vendor the installer, pin an audited package, or remove remote shell execution.",
            metadata: { scriptName },
          }),
        );
      }
      if (isLifecycleScript(scriptName)) {
        findings.push(
          makeFinding({
            ruleId: "security.risky-lifecycle-script",
            message: `Package lifecycle script \`${scriptName}\` runs automatically during install or publish flows.`,
            filePath: file.displayPath,
            line,
            severity: "warning",
            pillar: "security",
            confidence: "medium",
            symbol: scriptName,
            remediation: "Move setup behind an explicit command unless lifecycle execution is required.",
            metadata: { scriptName },
          }),
        );
      }
    }
  }

  for (const section of ["dependencies", "optionalDependencies", "peerDependencies", "devDependencies"]) {
    const dependencies = objectValue(pkg[section]);
    if (!dependencies) {
      continue;
    }
    const runtimeDependency = section !== "devDependencies";
    for (const [packageName, value] of Object.entries(dependencies)) {
      if (!isString(value)) {
        continue;
      }
      const line = jsonKeyLine(source, packageName);
      if (isUrlDependency(value)) {
        findings.push(
          makeFinding({
            ruleId: "security.url-dependency",
            message: `Dependency \`${packageName}\` in \`${section}\` installs from a URL or git spec.`,
            filePath: file.displayPath,
            line,
            severity: "warning",
            pillar: "security",
            confidence: "medium",
            symbol: packageName,
            remediation: "Prefer a registry package version that can be locked and audited.",
            metadata: { packageName, section, runtimeDependency },
          }),
        );
      }
      if (runtimeDependency && isBroadRuntimeVersion(value)) {
        findings.push(
          makeFinding({
            ruleId: "waste.broad-runtime-version",
            message: `Runtime dependency \`${packageName}\` uses overly broad version spec \`${value}\`.`,
            filePath: file.displayPath,
            line,
            severity: "advisory",
            pillar: "waste",
            confidence: "medium",
            symbol: packageName,
            remediation: "Use a bounded semver range and rely on the lockfile for repeatable installs.",
            metadata: { packageName, section, versionSpec: value },
          }),
        );
      }
    }
  }

  analysePackageBins(file, source, pkg, findings);
}

function analysePackageBins(file: SourceFile, source: string, pkg: Record<string, unknown>, findings: Finding[]): void {
  const bins = packageBinEntries(pkg);
  for (const [command, target] of bins) {
    const line = jsonKeyLine(source, command);
    const absolute = isAbsolute(target) ? target : join(dirnamePath(file.absolutePath), target);
    if (!existsSync(absolute)) {
      findings.push(
        makeFinding({
          ruleId: "design.package-bin-missing",
          message: `Package bin \`${command}\` points to missing file \`${target}\`.`,
          filePath: file.displayPath,
          line,
          severity: "warning",
          pillar: "design",
          confidence: "high",
          symbol: command,
          remediation: "Update the bin path or add the executable file.",
          metadata: { command, target },
        }),
      );
      continue;
    }
    const stats = statSync(absolute);
    if (!stats.isFile() || (stats.mode & 0o111) === 0) {
      findings.push(
        makeFinding({
          ruleId: "design.package-bin-not-executable",
          message: `Package bin \`${command}\` points to a file that is not executable.`,
          filePath: file.displayPath,
          line,
          severity: "warning",
          pillar: "design",
          confidence: "high",
          symbol: command,
          remediation: "Make the bin target executable and keep its shebang valid.",
          metadata: { command, target },
        }),
      );
    }
  }
}

function analyseTsconfigJson(file: SourceFile, source: string, data: Record<string, unknown>, findings: Finding[]): void {
  const compilerOptions = objectValue(data.compilerOptions) ?? {};
  const checks: Array<[string, string, string]> = [
    ["strict", "modernisation.tsconfig-strict-disabled", "`strict` is disabled, reducing TypeScript's baseline safety checks."],
    ["noUncheckedIndexedAccess", "modernisation.tsconfig-index-safety-disabled", "`noUncheckedIndexedAccess` is disabled, so indexed reads can silently ignore undefined."],
    ["exactOptionalPropertyTypes", "modernisation.tsconfig-exact-optional-disabled", "`exactOptionalPropertyTypes` is disabled, weakening optional property contracts."],
  ];
  for (const [optionName, ruleId, message] of checks) {
    if (compilerOptions[optionName] === true) {
      continue;
    }
    findings.push(
      makeFinding({
        ruleId,
        message,
        filePath: file.displayPath,
        line: jsonKeyLine(source, optionName),
        severity: "warning",
        pillar: "modernisation",
        confidence: "high",
        symbol: optionName,
        remediation: `Set compilerOptions.${optionName} to true unless a documented migration blocker exists.`,
        metadata: { optionName, currentValue: compilerOptions[optionName] ?? null },
      }),
    );
  }
}

function parseJsonObject(source: string): Record<string, unknown> | undefined {
  try {
    return objectValue(JSON.parse(source));
  } catch {
    return undefined;
  }
}

function jsonKeyLine(source: string, key: string): number {
  return firstLine(source, new RegExp(`"${escapeRegex(key)}"\\s*:`));
}

function isRemoteInstallScript(command: string): boolean {
  return /\b(?:curl|wget)\b[^\n|;&]*https?:\/\/[^\n|;&]*(?:\|\s*(?:sh|bash|zsh)\b|\b(?:sh|bash|zsh)\b)/i.test(command);
}

function isLifecycleScript(scriptName: string): boolean {
  return ["preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly"].includes(scriptName);
}

function isUrlDependency(versionSpec: string): boolean {
  return /^(?:https?:\/\/|git(?:\+https?|\+ssh)?:\/\/|ssh:\/\/|github:|gitlab:|bitbucket:)/i.test(versionSpec);
}

function isBroadRuntimeVersion(versionSpec: string): boolean {
  const normalized = versionSpec.trim().toLowerCase();
  return normalized === "*" || normalized === "x" || normalized === "latest" || /^>=\s*\d/.test(normalized) || normalized.includes("||");
}

function packageBinEntries(pkg: Record<string, unknown>): Array<[string, string]> {
  const bin = pkg.bin;
  if (isString(bin)) {
    const name = isString(pkg.name) ? pkg.name : "bin";
    return [[name, bin]];
  }
  const bins = objectValue(bin);
  if (!bins) {
    return [];
  }
  return Object.entries(bins).filter((entry): entry is [string, string] => isString(entry[1]));
}

function analyseSensitiveData(file: SourceFile, source: string, config: Config, findings: Finding[]): void {
  const patterns: Array<[string, RegExp, string]> = [
    ["sensitive-data.aws-access-key", /AKIA[0-9A-Z]{16}/g, "AWS access key pattern detected."],
    ["sensitive-data.private-key", /BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY/g, "Private key block detected."],
    ["sensitive-data.jwt-token", /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, "JWT-looking token detected."],
    ["sensitive-data.database-url-password", /[a-z]+:\/\/[^:\s]+:[^@\s]+@/g, "Database URL appears to include a password."],
    ["sensitive-data.api-key-pattern", /\b(?:sk_live_[A-Za-z0-9_-]{12,}|sk_test_[A-Za-z0-9_-]{12,}|sk-proj-[A-Za-z0-9_-]{16,}|sk-ant-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b/g, "API key pattern detected."],
    ["sensitive-data.pii-pattern", /\b\d{3}-\d{2}-\d{4}\b/g, "PII-like identifier pattern detected."],
  ];

  for (const [ruleId, pattern, message] of patterns) {
    for (const match of source.matchAll(pattern)) {
      const raw = match[0] ?? "";
      pushSensitiveFinding(config, findings, file, ruleId, message, byteLine(source, match.index ?? 0), raw, "high");
    }
  }

  const hardcodedEnvMinLength = threshold(config, "sensitive-data.hardcoded-env-value", "minLength", 16);
  const lines = source.split(/\r?\n/);
  for (const [index, line] of lines.entries()) {
    const envValue = hardcodedEnvValue(line, hardcodedEnvMinLength);
    if (!envValue) {
      continue;
    }
    pushSensitiveFinding(
      config,
      findings,
      file,
      "sensitive-data.hardcoded-env-value",
      `Environment-style value \`${envValue.keyName}\` appears to be hardcoded with secret-like content.`,
      index + 1,
      envValue.value,
      "medium",
      { keyName: envValue.keyName, length: envValue.value.length },
    );
  }

  const minLength = threshold(config, "sensitive-data.high-entropy-string", "minLength", 32);
  for (const match of source.matchAll(/(["'`])([A-Za-z0-9_+=./-]{32,})\1/g)) {
    const raw = match[2] ?? "";
    if (!isHighEntropySecretCandidate(raw, minLength)) {
      continue;
    }
    pushSensitiveFinding(
      config,
      findings,
      file,
      "sensitive-data.high-entropy-string",
      "High-entropy string literal may be an embedded secret.",
      byteLine(source, match.index ?? 0),
      raw,
      "medium",
      { length: raw.length, detector: "high-entropy-string" },
    );
  }
}

function pushSensitiveFinding(
  config: Config,
  findings: Finding[],
  file: SourceFile,
  ruleId: string,
  message: string,
  line: number,
  raw: string,
  confidence: Finding["confidence"],
  metadata: Record<string, unknown> = {},
): void {
  const preview = redact(raw);
  if (config.secretPreviews.has(preview)) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId,
      message: `${message} Redacted preview: ${preview}.`,
      filePath: file.displayPath,
      line,
      severity: "error",
      pillar: "sensitive-data",
      confidence,
      remediation: "Remove the sensitive value and load it from a secure runtime source.",
      metadata: { ...metadata, preview },
    }),
  );
}

function hardcodedEnvValue(line: string, minLength: number): { keyName: string; value: string } | undefined {
  const match = line.match(/^\s*([A-Z][A-Z0-9_]*(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|DATABASE_URL|DSN)[A-Z0-9_]*)\s*[:=]\s*["']?([^"'\s#]+)["']?/i);
  const keyName = match?.[1] ?? "";
  const value = match?.[2] ?? "";
  if (!keyName || value.length < minLength) {
    return undefined;
  }
  if (/^(?:x-api-key|token|secret|password|example|sample|placeholder)$/i.test(value)) {
    return undefined;
  }
  if (!/[A-Za-z]/.test(value) || !/[0-9]/.test(value)) {
    return undefined;
  }
  return { keyName, value };
}

function analyseTypeScriptRules(file: SourceFile, source: string, config: Config, findings: Finding[]): void {
  const blocks = functionBlocks(source);
  analyseBlocks(file, blocks, config, findings);
  analyseLineRules(file, source, config, findings);
  analyseDocRules(file, source, findings);
  analyseClassRules(file, source, findings);
  analyseDeadCode(file, source, findings);
}

function analyseBlocks(file: SourceFile, blocks: FunctionBlock[], config: Config, findings: Finding[]): void {
  for (const block of blocks) {
    const functionWarn = threshold(config, "size.function-length", "warn", 30);
    const functionError = threshold(config, "size.function-length", "error", 60);
    if (block.lineCount > functionError) {
      findings.push(blockFinding("size.function-length", `Function \`${block.name}\` has ${block.lineCount} lines, above the error threshold of ${functionError}.`, file, block, "error", "size"));
    } else if (block.lineCount > functionWarn) {
      findings.push(blockFinding("size.function-length", `Function \`${block.name}\` has ${block.lineCount} lines, above the warning threshold of ${functionWarn}.`, file, block, "warning", "size"));
    }

    const params = block.params.split(",").map((value) => value.trim()).filter(Boolean).length;
    if (params > threshold(config, "size.parameter-count", "warn", 5)) {
      findings.push(blockFinding("size.parameter-count", `Function \`${block.name}\` declares ${params} parameters.`, file, block, "warning", "size"));
    }

    const cyclomatic = countMatches(block.body, /\b(if|else if|switch|case|for|while|catch)\b|\?|&&|\|\|/g) + 1;
    if (cyclomatic > threshold(config, "complexity.cyclomatic", "error", 20)) {
      findings.push(blockFinding("complexity.cyclomatic", `Function \`${block.name}\` has cyclomatic complexity ${cyclomatic}.`, file, block, "error", "complexity"));
    } else if (cyclomatic > threshold(config, "complexity.cyclomatic", "warn", 10)) {
      findings.push(blockFinding("complexity.cyclomatic", `Function \`${block.name}\` has cyclomatic complexity ${cyclomatic}.`, file, block, "warning", "complexity"));
    }

    const nesting = maxNestingDepth(block.body);
    const cognitive = cyclomatic + nesting;
    if (cognitive > threshold(config, "complexity.cognitive", "warn", 15)) {
      findings.push(blockFinding("complexity.cognitive", `Function \`${block.name}\` has cognitive complexity ${cognitive}.`, file, block, "warning", "complexity"));
    }
    const npath = approximateNpath(functionBodyContent(block.body));
    const npathWarn = threshold(config, "complexity.npath", "warn", 20);
    const npathError = threshold(config, "complexity.npath", "error", 80);
    if (npath.value > npathError) {
      findings.push(
        blockFindingWithMetadata(
          "complexity.npath",
          `Function \`${block.name}\` has approximate NPath complexity ${npath.value} (capped at ${NPATH_CAP}).`,
          file,
          block,
          "error",
          "complexity",
          { npath: npath.value, capped: npath.capped, cap: NPATH_CAP },
        ),
      );
    } else if (npath.value > npathWarn) {
      findings.push(
        blockFindingWithMetadata(
          "complexity.npath",
          `Function \`${block.name}\` has approximate NPath complexity ${npath.value} (capped at ${NPATH_CAP}).`,
          file,
          block,
          "warning",
          "complexity",
          { npath: npath.value, capped: npath.capped, cap: NPATH_CAP },
        ),
      );
    }
    if (block.lineCount > 45 && cyclomatic > 10) {
      findings.push(blockFinding("design.god-function", `Function \`${block.name}\` is both long and complex.`, file, block, "warning", "design"));
    }
    if (isGenericName(block.name)) {
      findings.push(blockFinding("naming.generic-function", `Function \`${block.name}\` is too generic to explain intent.`, file, block, "advisory", "naming"));
    }
    if (block.isPublic && !hasDocCommentBefore(block.body)) {
      findings.push(blockFinding("docs.missing-public-doc", `Exported function \`${block.name}\` is missing a doc comment.`, file, block, "advisory", "documentation"));
    }
    if (isEmptyFunctionBody(block.body)) {
      findings.push(blockFinding("waste.empty-function", `Function \`${block.name}\` has no executable body.`, file, block, "advisory", "waste"));
    }
    for (const parameter of parameterNames(block.params)) {
      if (!parameter.name.startsWith("_") && !new RegExp(`\\b${escapeRegex(parameter.name)}\\b`).test(functionBodyContent(block.body))) {
        findings.push(
          makeFinding({
            ruleId: "waste.unused-parameter",
            message: `Parameter \`${parameter.name}\` does not appear to be used.`,
            filePath: file.displayPath,
            line: block.startLine,
            severity: "advisory",
            pillar: "waste",
            confidence: "medium",
            symbol: block.name,
            remediation: "Remove the parameter or prefix it with _ if it is intentionally unused.",
            metadata: { parameter: parameter.name },
          }),
        );
      }
    }
    for (const redundant of redundantVariableReturns(block.body)) {
      findings.push(
        makeFinding({
          ruleId: "waste.redundant-variable",
          message: `Variable \`${redundant.name}\` is returned immediately after assignment.`,
          filePath: file.displayPath,
          line: block.startLine + redundant.lineOffset,
          severity: "advisory",
          pillar: "waste",
          confidence: "medium",
          symbol: redundant.name,
          remediation: "Return the expression directly.",
          metadata: { variable: redundant.name },
        }),
      );
    }
    if (block.isTest) {
      analyseTestBlock(file, block, config, findings);
    }
  }
}

function analyseTestBlock(file: SourceFile, block: FunctionBlock, config: Config, findings: Finding[]): void {
  if (!hasAssertion(block.body)) {
    findings.push(blockFinding("test-quality.no-assertions", `Test \`${block.name}\` does not appear to make an assertion.`, file, block, "warning", "test-quality"));
  }
  if (hasTrivialAssertion(block.body)) {
    findings.push(blockFinding("test-quality.trivial-assertion", `Test \`${block.name}\` contains an assertion that compares a value to itself.`, file, block, "warning", "test-quality"));
  }
  if (isSnapshotOnlyTest(block.body)) {
    findings.push(blockFinding("test-quality.snapshot-only-test", `Test \`${block.name}\` relies only on snapshot assertions.`, file, block, "advisory", "test-quality"));
  }
  if (isNoThrowOnlyTest(block.body)) {
    findings.push(blockFinding("test-quality.no-throw-only-test", `Test \`${block.name}\` only verifies that code does not throw.`, file, block, "advisory", "test-quality"));
  }
  for (const assertion of magicNumberAssertions(block.body)) {
    findings.push(
      blockFindingWithMetadata(
        "test-quality.magic-number-assertion",
        `Test \`${block.name}\` asserts against unexplained numeric literal ${assertion.value}.`,
        file,
        block,
        "advisory",
        "test-quality",
        { value: assertion.value },
      ),
    );
  }
  const unusedMocks = unusedMockVariables(block.body);
  for (const mock of unusedMocks) {
    findings.push(
      blockFindingWithMetadata(
        "test-quality.unused-mock",
        `Mock \`${mock}\` is created but not used.`,
        file,
        block,
        "advisory",
        "test-quality",
        { mockName: mock },
      ),
    );
  }
  if (isMockOnlyTest(block.body)) {
    findings.push(blockFinding("test-quality.mock-only-test", `Test \`${block.name}\` only verifies mock interaction.`, file, block, "advisory", "test-quality"));
  }
  if (hasExceptionTypeOnlyAssertion(block.body)) {
    findings.push(blockFinding("test-quality.exception-type-only", `Test \`${block.name}\` checks only the exception type.`, file, block, "advisory", "test-quality"));
  }
  if (hasGlobalStateMutation(block.body)) {
    findings.push(blockFinding("test-quality.global-state-mutation", `Test \`${block.name}\` mutates global process or runtime state.`, file, block, "warning", "test-quality"));
  }
  const setupLines = setupLineCount(block.body);
  const maxSetupLines = threshold(config, "test-quality.setup-bloat", "maxSetupLines", 8);
  if (setupLines > maxSetupLines) {
    findings.push(
      blockFindingWithMetadata(
        "test-quality.setup-bloat",
        `Test \`${block.name}\` has ${setupLines} setup lines before its first assertion.`,
        file,
        block,
        "advisory",
        "test-quality",
        { setupLines, maxSetupLines },
      ),
    );
  }
  const checks: Array<[string, RegExp, string]> = [
    ["test-quality.sleep-in-test", /\b(setTimeout|sleep|waitForTimeout)\s*\(/, "Test sleeps instead of synchronising on behaviour."],
    ["test-quality.loop-in-test", /\b(for|while)\b/, "Test contains loop logic."],
    ["test-quality.conditional-logic", /\b(if|switch)\b/, "Test contains conditional logic."],
    ["test-quality.only-skip", /\.(only|skip)\s*\(/, "Focused or skipped test is committed."],
  ];
  for (const [ruleId, pattern, message] of checks) {
    if (pattern.test(block.body)) {
      findings.push(blockFinding(ruleId, message, file, block, "advisory", "test-quality"));
    }
  }
}

function analyseLineRules(file: SourceFile, source: string, config: Config, findings: Finding[]): void {
  analyseUnusedImports(file, source, findings);
  const codeChecks: Array<[string, RegExp, string, Severity, Pillar]> = [
    ["security.eval-call", /\beval\s*\(/, "eval() executes dynamic code.", "error", "security"],
    ["security.new-function", /\bnew\s+Function\s*\(|(?:^|[=(:,])\s*Function\s*\(/, "Function constructor executes dynamic code.", "error", "security"],
    ["security.string-timer", /\bset(?:Timeout|Interval)\s*\(\s*["'`]/, "Timer callback is provided as a string.", "warning", "security"],
    ["security.process-exec", /\b(exec|spawn|execFile)\s*\(/, "Child-process execution is used; validate arguments are not user-controlled.", "warning", "security"],
    ["security.insecure-random", /\bMath\.random\s*\(/, "Math.random() is not suitable for security-sensitive randomness.", "warning", "security"],
    ["security.inner-html", /\.innerHTML\s*=/, "innerHTML assignment can introduce XSS.", "warning", "security"],
    ["security.document-write", /\bdocument\.write\s*\(/, "document.write() can introduce injection risks.", "warning", "security"],
  ];
  const literalChecks: Array<[string, RegExp, string, Severity, Pillar]> = [
    ["security.weak-crypto", /\b(?:createHash|createHmac)\s*\(\s*["'](?:md5|sha1)["']|\bcreateCipher\s*\(/, "Weak cryptographic primitive is used.", "warning", "security"],
    ["security.disabled-tls-verification", /\b(?:process\.env\.)?NODE_TLS_REJECT_UNAUTHORIZED\b\s*=\s*["']0["']/, "TLS certificate verification is disabled.", "error", "security"],
    ["security.sql-concatenation", /\b(?:query|execute|raw)\s*\(\s*(?:`[^`]*(?:SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{|["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)[^"']*["']\s*\+)/i, "SQL text is composed with runtime string interpolation.", "warning", "security"],
    ["waste.console-log", /\bconsole\.(log|debug)\s*\(/, "console logging is committed in source.", "advisory", "waste"],
    ["waste.any-type", /:\s*any\b|as\s+any\b/, "any weakens TypeScript's type guarantees.", "warning", "waste"],
    ["modernisation.var-declaration", /\bvar\s+[A-Za-z_$]/, "var declaration should usually be let or const.", "advisory", "modernisation"],
  ];
  const variables = /\b(?:const|let|for\s*\(\s*const|for\s*\(\s*let)\s+([A-Za-z_$][A-Za-z0-9_$]*)/g;

  source.split(/\r?\n/).forEach((line, index) => {
    const lineNumber = index + 1;
    const codeLine = codeLineForMatching(line);
    analyseTypeSafetyLine(file, line, codeLine, lineNumber, findings);
    analyseReliabilityLine(file, codeLine, lineNumber, findings);
    if (isCommentedOutCode(line)) {
      findings.push(finding("waste.commented-out-code", "Comment appears to contain disabled source code.", file, lineNumber, "advisory", "waste"));
    }
    const booleanDeclaration = line.match(/\b(?:const|let|var|public|private|protected)\s+([A-Za-z_$][A-Za-z0-9_$]*)\??(?:\s*:\s*boolean|\s*=\s*(?:true|false)\b)/);
    if (booleanDeclaration?.[1] && !hasBooleanPrefix(booleanDeclaration[1])) {
      findings.push(
        makeFinding({
          ruleId: "naming.boolean-prefix",
          message: `Boolean identifier \`${booleanDeclaration[1]}\` should use an intent-revealing prefix.`,
          filePath: file.displayPath,
          line: lineNumber,
          severity: "advisory",
          pillar: "naming",
          confidence: "medium",
          symbol: booleanDeclaration[1],
          remediation: "Use a prefix such as is, has, can, should, or will.",
          metadata: { identifierName: booleanDeclaration[1] },
        }),
      );
    }
    for (const hungarian of line.matchAll(/\b(?:const|let|var|public|private|protected)\s+((?:str|obj|arr|bool|int|num)[A-Z][A-Za-z0-9_$]*)/g)) {
      const name = hungarian[1] ?? "";
      findings.push(
        makeFinding({
          ruleId: "naming.hungarian-notation",
          message: `Identifier \`${name}\` uses type-style Hungarian notation.`,
          filePath: file.displayPath,
          line: lineNumber,
          severity: "advisory",
          pillar: "naming",
          confidence: "medium",
          symbol: name,
          remediation: "Name the domain concept instead of the storage type.",
          metadata: { identifierName: name },
        }),
      );
    }
    for (const optional of line.matchAll(/\b([A-Za-z_$][A-Za-z0-9_$]*)\s*&&\s*\1\.[A-Za-z_$][A-Za-z0-9_$]*/g)) {
      const name = optional[1] ?? "";
      findings.push(
        makeFinding({
          ruleId: "modernisation.optional-chaining-candidate",
          message: `Guarded property access on \`${name}\` can usually use optional chaining.`,
          filePath: file.displayPath,
          line: lineNumber,
          severity: "advisory",
          pillar: "modernisation",
          confidence: "medium",
          symbol: name,
          remediation: "Use optional chaining for the guarded property access.",
        }),
      );
    }
    for (const fallback of line.matchAll(/=\s*([A-Za-z_$][A-Za-z0-9_$.]*)\s*\|\|\s*(["'`][^"'`]*["'`]|\d+|true|false)/g)) {
      const name = fallback[1] ?? "";
      findings.push(
        makeFinding({
          ruleId: "modernisation.nullish-coalescing-candidate",
          message: `Fallback for \`${name}\` can usually use nullish coalescing to preserve falsy values.`,
          filePath: file.displayPath,
          line: lineNumber,
          severity: "advisory",
          pillar: "modernisation",
          confidence: "medium",
          symbol: name,
          remediation: "Use ?? when only null or undefined should trigger the fallback.",
        }),
      );
    }
    for (const [ruleId, pattern, message, severity, pillar] of codeChecks) {
      if (pattern.test(codeLine)) {
        findings.push(finding(ruleId, message, file, lineNumber, severity, pillar));
      }
    }
    for (const [ruleId, pattern, message, severity, pillar] of literalChecks) {
      if (pattern.test(line)) {
        findings.push(finding(ruleId, message, file, lineNumber, severity, pillar));
      }
    }

    for (const match of line.matchAll(variables)) {
      const name = match[1] ?? "";
      if (name.length <= 2 && !["i", "j", "k"].includes(name) && !config.acceptedAbbreviations.has(name.toLowerCase())) {
        findings.push(
          makeFinding({
            ruleId: "naming.short-variable",
            message: `Variable \`${name}\` is too short to explain intent.`,
            filePath: file.displayPath,
            line: lineNumber,
            severity: "advisory",
            pillar: "naming",
            confidence: "medium",
            symbol: name,
            remediation: "Use a name that describes the domain role.",
          }),
        );
      }
      const variant = identifierQualityVariant(name);
      if (variant) {
        findings.push(
          makeFinding({
            ruleId: "naming.identifier-quality",
            message: `Identifier \`${name}\` is a ${variant} name that does not explain domain intent.`,
            filePath: file.displayPath,
            line: lineNumber,
            severity: "advisory",
            pillar: "naming",
            confidence: "medium",
            symbol: name,
            remediation: "Use an identifier that names the domain role.",
            metadata: { identifierName: name, variant },
          }),
        );
      }
    }
  });

  analyseSwallowedCatches(file, source, findings);
  analyseUnreachable(file, source, findings);
}

function analyseTypeSafetyLine(file: SourceFile, line: string, codeLine: string, lineNumber: number, findings: Finding[]): void {
  const directive = tsDirectiveWithoutRationale(line);
  if (directive) {
    findings.push(
      makeFinding({
        ruleId: "modernisation.ts-comment-without-rationale",
        message: `${directive.directive} suppresses TypeScript without a nearby rationale.`,
        filePath: file.displayPath,
        line: lineNumber,
        severity: "warning",
        pillar: "modernisation",
        confidence: "medium",
        remediation: "Add a short reason after the directive or remove the suppression.",
        metadata: { directive: directive.directive },
      }),
    );
  }

  for (const match of codeLine.matchAll(/\b([A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)!(?=\.|\[|\)|,|;|\s+(?:as|in|instanceof)\b|\s*$)/g)) {
    const expression = match[1] ?? "";
    findings.push(
      makeFinding({
        ruleId: "modernisation.non-null-assertion",
        message: `Non-null assertion on \`${expression}\` bypasses TypeScript's null checks.`,
        filePath: file.displayPath,
        line: lineNumber,
        severity: "warning",
        pillar: "modernisation",
        confidence: "medium",
        symbol: expression,
        remediation: "Narrow the value with a guard or handle the null/undefined case explicitly.",
        metadata: { expression },
      }),
    );
  }

  for (const match of codeLine.matchAll(/\bas\s+(unknown|any)\s+as\s+([^;,\n]+)/g)) {
    const sourceType = match[1] ?? "";
    const targetType = (match[2] ?? "").trim().replace(/[.)]+$/, "");
    findings.push(
      makeFinding({
        ruleId: "modernisation.double-cast",
        message: `Double cast through \`${sourceType}\` bypasses structural type checks.`,
        filePath: file.displayPath,
        line: lineNumber,
        severity: "warning",
        pillar: "modernisation",
        confidence: "medium",
        remediation: "Prefer a typed parser, type guard, or narrower assertion at the trust boundary.",
        metadata: { sourceType, targetType },
      }),
    );
  }

  const exportedAny = exportedAnySymbol(codeLine);
  if (exportedAny) {
    findings.push(
      makeFinding({
        ruleId: "waste.exported-any",
        message: `Exported API \`${exportedAny}\` exposes \`any\` in its public contract.`,
        filePath: file.displayPath,
        line: lineNumber,
        severity: "warning",
        pillar: "waste",
        confidence: "medium",
        symbol: exportedAny,
        remediation: "Use a named interface, unknown plus validation, or a precise generic type.",
        metadata: { symbolName: exportedAny },
      }),
    );
  }
}

function analyseReliabilityLine(file: SourceFile, codeLine: string, lineNumber: number, findings: Finding[]): void {
  if (/\.forEach\s*\(\s*async\b/.test(codeLine)) {
    findings.push(
      makeFinding({
        ruleId: "security.async-foreach",
        message: "async callbacks passed to forEach are not awaited by the caller.",
        filePath: file.displayPath,
        line: lineNumber,
        severity: "warning",
        pillar: "security",
        confidence: "medium",
        remediation: "Use for...of with await, Promise.all, or an explicit queue.",
        metadata: { callName: "forEach" },
      }),
    );
  }

  const floating = floatingPromiseCall(codeLine);
  if (floating) {
    findings.push(
      makeFinding({
        ruleId: "security.floating-promise",
        message: `Promise-like call \`${floating}\` is started without await, return, or void.`,
        filePath: file.displayPath,
        line: lineNumber,
        severity: "warning",
        pillar: "security",
        confidence: "medium",
        symbol: floating,
        remediation: "Await it, return it, or prefix with void when fire-and-forget is intentional.",
        metadata: { callName: floating },
      }),
    );
  }

  const thrown = nonErrorThrowExpression(codeLine);
  if (thrown) {
    findings.push(
      makeFinding({
        ruleId: "security.throw-non-error",
        message: "Throwing non-Error values loses stack and error-shape information.",
        filePath: file.displayPath,
        line: lineNumber,
        severity: "warning",
        pillar: "security",
        confidence: "medium",
        remediation: "Throw an Error subclass with a clear message and structured properties.",
        metadata: { expression: thrown },
      }),
    );
  }
}

function analyseSwallowedCatches(file: SourceFile, source: string, findings: Finding[]): void {
  for (const match of source.matchAll(/\bcatch\s*(?:\(([^)]*)\))?\s*\{([\s\S]*?)\}/g)) {
    const body = match[2] ?? "";
    if (!isSwallowedCatchBody(body)) {
      continue;
    }
    const binding = (match[1] ?? "").trim();
    findings.push(
      makeFinding({
        ruleId: "waste.swallowed-catch",
        message: "catch block swallows an error without rethrowing, returning, or reporting it.",
        filePath: file.displayPath,
        line: byteLine(source, match.index ?? 0),
        severity: "warning",
        pillar: "waste",
        confidence: "medium",
        remediation: "Handle the error explicitly, rethrow it, or document an intentional ignore path.",
        metadata: { ...(binding ? { binding } : {}) },
      }),
    );
  }
}

function tsDirectiveWithoutRationale(line: string): { directive: string } | undefined {
  const match = line.match(/@ts-(ignore|expect-error)\b(.*)$/);
  if (!match?.[1]) {
    return undefined;
  }
  const rationale = match[2] ?? "";
  if (hasDirectiveRationale(rationale)) {
    return undefined;
  }
  return { directive: `@ts-${match[1]}` };
}

function hasDirectiveRationale(value: string): boolean {
  const cleaned = value.replace(/^[-:\s]+/, "").trim();
  const words = cleaned.match(/[A-Za-z]{3,}/g) ?? [];
  return words.length >= 3;
}

function exportedAnySymbol(codeLine: string): string | undefined {
  if (!/\bexport\b/.test(codeLine) || !/\bany\b/.test(codeLine)) {
    return undefined;
  }
  const match = codeLine.match(/\bexport\s+(?:async\s+)?(?:function|const|let|var|class|interface|type)\s+([A-Za-z_$][A-Za-z0-9_$]*)/);
  return match?.[1];
}

function floatingPromiseCall(codeLine: string): string | undefined {
  const trimmed = codeLine.trim();
  if (!trimmed || /^(?:await|return|void|throw|yield)\b/.test(trimmed) || /^(?:const|let|var)\s+/.test(trimmed)) {
    return undefined;
  }
  const match = trimmed.match(/^([A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)\s*\(/);
  const callName = match?.[1] ?? "";
  if (!callName) {
    return undefined;
  }
  const localName = callName.split(".").at(-1) ?? callName;
  return callName === "fetch" || /(?:Async|Promise)$/.test(localName) ? callName : undefined;
}

function nonErrorThrowExpression(codeLine: string): string | undefined {
  const match = codeLine.match(/\bthrow\s+(.+?);?$/);
  const expression = (match?.[1] ?? "").trim();
  if (!expression) {
    return undefined;
  }
  if (/^(?:new\s+[A-Za-z_$][A-Za-z0-9_$]*Error\b|[A-Za-z_$][A-Za-z0-9_$]*)/.test(expression)) {
    return undefined;
  }
  return /^(?:["'`]|\d|\{|\[|true\b|false\b|null\b|undefined\b)/.test(expression) ? expression.slice(0, 40) : undefined;
}

function isSwallowedCatchBody(body: string): boolean {
  const meaningful = body
    .replace(/\/\/.*$/gm, "")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .trim();
  return meaningful === "";
}

function codeLineForMatching(line: string): string {
  let result = "";
  let quote: string | undefined;
  let escaped = false;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index] ?? "";
    const next = line[index + 1] ?? "";
    if (!quote && character === "/" && next === "/") {
      break;
    }
    if (quote) {
      if (escaped) {
        escaped = false;
        continue;
      }
      if (character === "\\") {
        escaped = true;
        continue;
      }
      if (character === quote) {
        result += character;
        quote = undefined;
      }
      continue;
    }
    if (character === "\"" || character === "'" || character === "`") {
      quote = character;
      result += character;
      continue;
    }
    result += character;
  }
  return result;
}

function analyseClassRules(file: SourceFile, source: string, findings: Finding[]): void {
  for (const match of source.matchAll(/\bexport\s+(class|interface|type|enum|function)\s+([A-Za-z_$][A-Za-z0-9_$]*)/g)) {
    const kind = match[1] ?? "";
    const name = match[2] ?? "";
    const line = byteLine(source, match.index ?? 0);
    if (!hasDocCommentBeforeLine(source, line)) {
      findings.push(
        makeFinding({
          ruleId: "docs.missing-public-doc",
          message: `Exported item \`${name}\` is missing a doc comment.`,
          filePath: file.displayPath,
          line,
          severity: "advisory",
          pillar: "documentation",
          confidence: "medium",
          symbol: name,
          remediation: "Add a /** ... */ comment explaining the exported API.",
        }),
      );
    }
    if (kind === "class" && normalizedIdentifier(name) !== normalizedIdentifier(fileBaseName(file.displayPath))) {
      findings.push(
        makeFinding({
          ruleId: "naming.class-file-mismatch",
          message: `Exported class \`${name}\` does not match file name \`${fileBaseName(file.displayPath)}\`.`,
          filePath: file.displayPath,
          line,
          severity: "advisory",
          pillar: "naming",
          confidence: "medium",
          symbol: name,
          remediation: "Rename the class or file so the primary export is easy to locate.",
          metadata: { className: name, fileName: fileBaseName(file.displayPath) },
        }),
      );
    }
  }

  const publicProperty = /\bpublic\s+[A-Za-z_$][A-Za-z0-9_$]*\s*[=:]/g;
  for (const match of source.matchAll(publicProperty)) {
    findings.push(finding("modernisation.public-property", "Public class property exposes representation; prefer readonly or accessors when invariants matter.", file, byteLine(source, match.index ?? 0), "advisory", "modernisation"));
  }

  const readonlyCandidate = /\b(?:public|private|protected)\s+(?!readonly\b)([A-Za-z_$][A-Za-z0-9_$]*)\s*:\s*[^;=\n]+;/g;
  for (const match of source.matchAll(readonlyCandidate)) {
    const name = match[1] ?? "";
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

function analyseDocRules(file: SourceFile, source: string, findings: Finding[]): void {
  const documentedExport = /\/\*\*([\s\S]*?)\*\/\s*export\s+function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)\s*(?::\s*([^\x7b\n]+))?/g;
  for (const match of source.matchAll(documentedExport)) {
    const doc = match[1] ?? "";
    const name = match[2] ?? "";
    const params = parameterNames(match[3] ?? "").map((parameter) => parameter.name);
    const paramTags = docParamTags(doc);
    const line = byteLine(source, match.index ?? 0);
    for (const tag of paramTags) {
      if (!params.includes(tag)) {
        findings.push(docFinding("docs.stale-param-tag", `Docblock for \`${name}\` has stale @param tag \`${tag}\`.`, file, line, name, tag));
      }
    }
    for (const param of params) {
      if (!paramTags.includes(param)) {
        findings.push(docFinding("docs.missing-param-tag", `Docblock for \`${name}\` is missing @param for \`${param}\`.`, file, line, name, param));
      }
    }
    const returnType = (match[4] ?? "").trim();
    if (returnType && !/^void\b/.test(returnType) && !/@returns?\b/.test(doc)) {
      findings.push(docFinding("docs.missing-return-tag", `Docblock for \`${name}\` is missing @returns.`, file, line, name));
    }
    if (isUselessDocblock(doc, name)) {
      findings.push(docFinding("docs.useless-docblock", `Docblock for \`${name}\` only restates the signature.`, file, line, name));
    }
  }
}

function docFinding(ruleId: string, message: string, file: SourceFile, line: number, symbol: string, parameter?: string): Finding {
  return makeFinding({
    ruleId,
    message,
    filePath: file.displayPath,
    line,
    severity: "advisory",
    pillar: "documentation",
    confidence: "medium",
    symbol,
    remediation: "Update the JSDoc so it documents the current signature and return value.",
    metadata: { ...(parameter ? { parameter } : {}) },
  });
}

function analyseDeadCode(file: SourceFile, source: string, findings: Finding[]): void {
  for (const match of source.matchAll(/\bprivate\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/g)) {
    const name = match[1] ?? "";
    if (countMatches(source, new RegExp(`${escapeRegex(name)}\\s*\\(`, "g")) <= 1) {
      findings.push(
        makeFinding({
          ruleId: "dead-code.unused-private-method",
          message: `Private method \`${name}\` appears to be unused in this file.`,
          filePath: file.displayPath,
          line: byteLine(source, match.index ?? 0),
          severity: "advisory",
          pillar: "dead-code",
          confidence: "low",
          symbol: name,
          remediation: "Remove the method or add a real call site.",
        }),
      );
    }
  }
}

function analyseUnreachable(file: SourceFile, source: string, findings: Finding[]): void {
  let previousTerminated = false;
  source.split(/\r?\n/).forEach((line, index) => {
    const trimmed = line.trim();
    if (previousTerminated && /\S/.test(trimmed) && !trimmed.startsWith(String.fromCharCode(125))) {
      findings.push(finding("waste.unreachable-code", "Statement appears after a terminating statement.", file, index + 1, "warning", "waste"));
    }
    previousTerminated = /\b(return|throw|process\.exit)\b/.test(trimmed) && trimmed.endsWith(";");
  });
}

function analyseUnusedImports(file: SourceFile, source: string, findings: Finding[]): void {
  const lines = source.split(/\r?\n/);
  for (const [index, line] of lines.entries()) {
    const trimmed = line.trim();
    if (!trimmed.startsWith("import ") || !trimmed.includes(" from ")) {
      continue;
    }
    const openBrace = trimmed.indexOf(String.fromCharCode(123));
    const closeBrace = trimmed.indexOf(String.fromCharCode(125), openBrace + 1);
    if (openBrace === -1 || closeBrace === -1 || closeBrace <= openBrace) {
      continue;
    }
    for (const specifier of trimmed.slice(openBrace + 1, closeBrace).split(",")) {
      const name = localImportName(specifier);
      if (!name || countMatches(source, new RegExp(`\\b${escapeRegex(name)}\\b`, "g")) > 1) {
        continue;
      }
      findings.push(
        makeFinding({
          ruleId: "waste.unused-import",
          message: `Imported symbol \`${name}\` does not appear to be used.`,
          filePath: file.displayPath,
          line: index + 1,
          severity: "advisory",
          pillar: "waste",
          confidence: "medium",
          symbol: name,
          remediation: "Remove the unused import.",
          metadata: { importName: name },
        }),
      );
    }
  }
}

function localImportName(specifier: string): string | undefined {
  const parts = specifier.trim().split(/\s+as\s+/);
  const candidate = parts[1] ?? parts[0] ?? "";
  const match = candidate.trim().match(/^[A-Za-z_$][A-Za-z0-9_$]*/);
  return match?.[0];
}

function approximateNpath(source: string): { value: number; capped: boolean } {
  let value = 1;
  let capped = false;
  const normalized = source.replace(/\?\./g, "").replace(/\?\?/g, "");
  const decisionCount = countMatches(normalized, /\b(if|else if|case|catch|for|while)\b|\?|&&|\|\|/g);
  for (let index = 0; index < decisionCount; index += 1) {
    value *= 2;
    if (value >= NPATH_CAP) {
      value = NPATH_CAP;
      capped = true;
      break;
    }
  }
  return { value, capped };
}

function isEmptyFunctionBody(source: string): boolean {
  const body = functionBodyContent(source)
    .replace(/\/\/.*$/gm, "")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .trim();
  return body === "";
}

function functionBodyContent(source: string): string {
  const start = source.indexOf("{");
  const end = source.lastIndexOf("}");
  if (start === -1 || end <= start) {
    return "";
  }
  return source.slice(start + 1, end);
}

function parameterNames(params: string): Array<{ name: string }> {
  return params
    .split(",")
    .map((parameter) => parameter.trim())
    .filter(Boolean)
    .map((parameter) => parameter.replace(/^(?:public|private|protected|readonly)\s+/, "").replace(/^\.\.\./, "").split(/[?:=]/)[0]?.trim() ?? "")
    .filter((name): name is string => /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(name))
    .map((name) => ({ name }));
}

function redundantVariableReturns(source: string): Array<{ name: string; lineOffset: number }> {
  const results: Array<{ name: string; lineOffset: number }> = [];
  for (const match of source.matchAll(/\b(?:const|let)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*[^;]+;\s*return\s+\1\s*;/g)) {
    results.push({ name: match[1] ?? "", lineOffset: lineOffset(source, match.index ?? 0) });
  }
  return results.filter((result) => result.name !== "");
}

function lineOffset(source: string, index: number): number {
  return source.slice(0, Math.max(0, index)).split("\n").length - 1;
}

function isCommentedOutCode(line: string): boolean {
  const trimmed = line.trim();
  if (!trimmed.startsWith("//")) {
    return false;
  }
  const uncommented = trimmed.replace(/^\/\/+\s?/, "");
  if (/^(const|let|var|function|class|interface|type|enum|import|export|if|for|while|switch|return|throw|await)\b/.test(uncommented)) {
    return true;
  }
  return /^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)?\s*\([^)]*\);?$/.test(uncommented);
}

function identifierQualityVariant(name: string): string | undefined {
  const lower = name.toLowerCase();
  if (["foo", "bar", "baz", "tmp", "temp", "thing", "stuff", "data", "value", "item"].includes(lower)) {
    return "generic";
  }
  if (/^[A-Za-z_$]+[0-9]+$/.test(name)) {
    return "numbered";
  }
  return undefined;
}

function hasBooleanPrefix(name: string): boolean {
  return /^(?:is|has|can|should|does|did|was|will)[A-Z_]/.test(name);
}

function fileBaseName(path: string): string {
  return basename(path).replace(/\.[^.]+$/, "");
}

function normalizedIdentifier(value: string): string {
  return value.replace(/[^A-Za-z0-9]/g, "").toLowerCase();
}

function docParamTags(doc: string): string[] {
  const names: string[] = [];
  for (const line of doc.split(/\r?\n/)) {
    const marker = line.indexOf("@param");
    if (marker === -1) {
      continue;
    }
    let rest = line.slice(marker + "@param".length).trim();
    if (rest.startsWith(String.fromCharCode(123))) {
      const end = rest.indexOf(String.fromCharCode(125));
      rest = end === -1 ? "" : rest.slice(end + 1).trim();
    }
    const match = rest.match(/^([A-Za-z_$][A-Za-z0-9_$]*)/);
    if (match?.[1]) {
      names.push(match[1]);
    }
  }
  return names;
}

function isUselessDocblock(doc: string, symbol: string): boolean {
  const words = doc
    .split(/\r?\n/)
    .map((line) => line.replace(/^\s*\*\s?/, "").trim())
    .filter((line) => line !== "" && !line.startsWith("@"))
    .join(" ")
    .toLowerCase()
    .replace(/[^a-z0-9 ]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (!words) {
    return true;
  }
  return words === splitIdentifierWords(symbol).join(" ") || normalizedIdentifier(words) === normalizedIdentifier(symbol);
}

function splitIdentifierWords(value: string): string[] {
  return value
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .split(/[^A-Za-z0-9]+/)
    .map((word) => word.toLowerCase())
    .filter(Boolean);
}

function hasTrivialAssertion(source: string): boolean {
  if (/\bassert\.ok\s*\(\s*true\s*\)/.test(source)) {
    return true;
  }
  if (/\bassert\.(?:equal|strictEqual|deepEqual)\s*\(\s*(true|false|null|undefined|\d+|["'][^"']*["'])\s*,\s*\1\s*\)/.test(source)) {
    return true;
  }
  for (const match of source.matchAll(/\bassert\.(?:equal|strictEqual|deepEqual)\s*\(\s*([^,\n]+?)\s*,\s*([^,\n)]+?)(?:\s*,|\s*\))/g)) {
    if (normalizeAssertionExpression(match[1] ?? "") === normalizeAssertionExpression(match[2] ?? "")) {
      return true;
    }
  }
  for (const match of source.matchAll(/\bexpect\s*\(\s*([^)]+?)\s*\)\s*\.\s*to(?:Be|Equal|StrictEqual)\s*\(\s*([^)]+?)\s*\)/g)) {
    if (normalizeAssertionExpression(match[1] ?? "") === normalizeAssertionExpression(match[2] ?? "")) {
      return true;
    }
  }
  return false;
}

function normalizeAssertionExpression(expression: string): string {
  return expression.trim().replace(/;$/, "");
}

function hasAssertion(source: string): boolean {
  return /\bassert(?:\.[A-Za-z]+)?\s*\(/.test(source) || /\bexpect(?:\.(?:assertions|hasAssertions))?\s*\(/.test(source);
}

function isSnapshotOnlyTest(source: string): boolean {
  if (!/\.\s*toMatch(?:Inline)?Snapshot\s*\(/.test(source)) {
    return false;
  }
  const withoutSnapshots = source
    .replace(/\bexpect\s*\([\s\S]*?\)\s*\.\s*toMatch(?:Inline)?Snapshot\s*\([^)]*\)\s*;?/g, "")
    .replace(/\bexpect\.(?:assertions|hasAssertions)\s*\([^)]*\)\s*;?/g, "");
  return !hasAssertion(withoutSnapshots);
}

function isNoThrowOnlyTest(source: string): boolean {
  if (!/\bassert\.doesNotThrow\s*\(|\.\s*not\s*\.\s*toThrow\s*\(/.test(source)) {
    return false;
  }
  const withoutNoThrow = source
    .replace(/\bassert\.doesNotThrow\s*\([\s\S]*?\)\s*;?/g, "")
    .replace(/\bexpect\s*\([\s\S]*?\)\s*\.\s*not\s*\.\s*toThrow\s*\([^)]*\)\s*;?/g, "")
    .replace(/\bexpect\.(?:assertions|hasAssertions)\s*\([^)]*\)\s*;?/g, "");
  return !hasAssertion(withoutNoThrow);
}

function magicNumberAssertions(source: string): Array<{ value: number }> {
  const results: Array<{ value: number }> = [];
  const ignored = new Set([-1, 0, 1]);
  const patterns = [
    /\bexpect\s*\([^)]+\)\s*\.\s*to(?:Be|Equal|HaveLength|HaveCount)\s*\(\s*(-?\d+(?:\.\d+)?)\s*\)/g,
    /\bassert\.(?:equal|strictEqual|deepEqual)\s*\(\s*[^,\n]+,\s*(-?\d+(?:\.\d+)?)(?:\s*,|\s*\))/g,
  ];
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) {
      const value = Number(match[1] ?? "0");
      if (!ignored.has(value)) {
        results.push({ value });
      }
    }
  }
  return results;
}

function unusedMockVariables(source: string): string[] {
  const names: string[] = [];
  for (const match of source.matchAll(/\bconst\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:(?:vi|jest)\.fn|sinon\.stub|createMock|mock)\s*\(/g)) {
    const name = match[1] ?? "";
    if (name && countMatches(source, new RegExp(`\\b${escapeRegex(name)}\\b`, "g")) <= 1) {
      names.push(name);
    }
  }
  return names;
}

function isMockOnlyTest(source: string): boolean {
  if (!/\b(?:vi|jest)\.fn\s*\(|\b(?:createMock|mock|sinon\.stub)\s*\(/.test(source)) {
    return false;
  }
  if (!/\.(?:toHaveBeenCalled|toHaveBeenCalledWith|toHaveBeenNthCalledWith|toBeCalled|toBeCalledWith)\s*\(/.test(source)) {
    return false;
  }
  const targets = [...source.matchAll(/\bexpect\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\)/g)].map((match) => match[1] ?? "");
  return targets.length > 0 && targets.every((target) => /(?:mock|stub|spy)$/i.test(target));
}

function hasExceptionTypeOnlyAssertion(source: string): boolean {
  return /\.toThrow\s*\(\s*(?:Error|[A-Z][A-Za-z0-9_$]*Error)\s*\)/.test(source) || /\bassert\.throws\s*\([^,\n]+,\s*(?:Error|[A-Z][A-Za-z0-9_$]*Error)\s*\)/.test(source);
}

function hasGlobalStateMutation(source: string): boolean {
  return /\bprocess\.env\.[A-Za-z0-9_]+\s*=/.test(source) || /\bglobalThis\.[A-Za-z0-9_$]+\s*=/.test(source) || /\b(?:Date\.now|Math\.random)\s*=/.test(source);
}

function setupLineCount(source: string): number {
  let count = 0;
  for (const line of functionBodyContent(source).split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed === "});" || trimmed === "}") {
      continue;
    }
    if (hasAssertion(trimmed)) {
      break;
    }
    count += 1;
  }
  return count;
}

function isTestInvocationLine(line: string): boolean {
  return /^\s*(?:test|it)\s*\(/.test(line);
}

function functionBlocks(source: string): FunctionBlock[] {
  const lines = source.split(/\r?\n/);
  const blocks: FunctionBlock[] = [];
  const patterns = [
    /(?:test|it)\s*\(\s*["'`]([^"'`]+)["'`]\s*,\s*(?:async\s*)?\(([^)]*)\)\s*=>/,
    /(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)/,
    /(?:public|private|protected)?\s*(?:async\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)\s*[:{]/,
    /(?:const|let)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>/,
  ];
  lines.forEach((line, index) => {
    const match = patterns.map((pattern) => line.match(pattern)).find(Boolean);
    if (!match?.[1]) {
      return;
    }
    if (isControlBlockName(match[1])) {
      return;
    }
    const start = functionStartIndex(lines, index);
    let depth = 0;
    let seenOpen = false;
    let end = index;
    for (let current = index; current < lines.length; current += 1) {
      for (const character of lines[current] ?? "") {
        if (character === "{") {
          depth += 1;
          seenOpen = true;
        } else if (character === "}") {
          depth -= 1;
        }
      }
      end = current;
      if (seenOpen && depth <= 0) {
        break;
      }
    }
    const body = lines.slice(start, end + 1).join("\n");
    blocks.push({
      name: match[1],
      params: match[2] ?? "",
      startLine: start + 1,
      lineCount: end - start + 1,
      body,
      isPublic: /\bexport\b|\bpublic\b/.test(lines.slice(start, index + 1).join("\n")),
      isTest: isTestInvocationLine(lines[index] ?? ""),
    });
  });
  return blocks;
}

function isControlBlockName(name: string): boolean {
  return ["if", "for", "while", "switch", "catch"].includes(name);
}

function functionStartIndex(lines: string[], index: number): number {
  let start = index;
  while (start > 0) {
    const previous = lines[start - 1]?.trim() ?? "";
    if (previous.startsWith("@") || previous.startsWith("/**") || previous.startsWith("*") || previous === "") {
      start -= 1;
      continue;
    }
    break;
  }
  return start;
}

function makeFinding(input: {
  ruleId: string;
  message: string;
  filePath: string;
  line?: number;
  severity: Severity;
  pillar: Pillar;
  confidence: Confidence;
  symbol?: string;
  remediation?: string;
  metadata?: Record<string, unknown>;
}): Finding {
  const fingerprint = createHash("sha256")
    .update([input.ruleId, input.filePath, input.line ?? "", input.symbol ?? ""].join("\0"))
    .digest("hex")
    .slice(0, 16);
  return {
    ruleId: input.ruleId,
    message: input.message,
    filePath: input.filePath,
    ...(input.line ? { line: input.line } : {}),
    severity: input.severity,
    pillar: input.pillar,
    secondaryPillars: [],
    tier: "v0.1",
    confidence: input.confidence,
    ...(input.symbol ? { symbol: input.symbol } : {}),
    ...(input.remediation ? { remediation: input.remediation } : {}),
    metadata: input.metadata ?? {},
    fingerprint,
  };
}

function finding(ruleId: string, message: string, file: SourceFile, line: number, severity: Severity, pillar: Pillar): Finding {
  return makeFinding({ ruleId, message, filePath: file.displayPath, line, severity, pillar, confidence: "high" });
}

function blockFinding(ruleId: string, message: string, file: SourceFile, block: FunctionBlock, severity: Severity, pillar: Pillar): Finding {
  return makeFinding({ ruleId, message, filePath: file.displayPath, line: block.startLine, severity, pillar, confidence: "high", symbol: block.name });
}

function blockFindingWithMetadata(ruleId: string, message: string, file: SourceFile, block: FunctionBlock, severity: Severity, pillar: Pillar, metadata: Record<string, unknown>): Finding {
  return makeFinding({ ruleId, message, filePath: file.displayPath, line: block.startLine, severity, pillar, confidence: "medium", symbol: block.name, metadata });
}

function renderReport(report: AnalysisReport, format: OutputFormat): string {
  switch (format) {
    case "json":
      return JSON.stringify(report, null, 2);
    case "html":
      return renderHtml(report);
    case "markdown":
      return renderMarkdown(report);
    case "github":
      return renderGithub(report);
    case "hotspot":
      return JSON.stringify({ schemaVersion: "gruff.hotspot.v1", tool: report.tool, score: report.score.composite, files: report.score.topOffenders }, null, 2);
    case "text":
      return renderText(report);
  }
}

function renderRuleList(format: RuleListFormat): string {
  const descriptors = ruleDescriptors();
  if (format === "json") {
    return `${JSON.stringify({ tool: { name: "gruff-ts", version: VERSION }, rules: descriptors }, null, 2)}\n`;
  }
  const lines = [`gruff-ts ${VERSION} rules (${descriptors.length})`, ""];
  for (const descriptor of descriptors) {
    const thresholds = descriptor.thresholdKeys && descriptor.thresholdKeys.length > 0 ? ` | thresholds: ${descriptor.thresholdKeys.join(",")}` : "";
    lines.push(`${descriptor.ruleId} | ${descriptor.pillar} | ${descriptor.severity} | ${descriptor.confidence} | ${descriptor.description}${thresholds}`);
  }
  return `${lines.join("\n")}\n`;
}

function renderText(report: AnalysisReport): string {
  const lines = [
    `gruff-ts ${report.tool.version}`,
    `Score: ${report.score.composite.toFixed(1)} (${report.score.grade}) | Findings: ${report.summary.advisory} advisory, ${report.summary.warning} warning, ${report.summary.error} error`,
    `Analysed files: ${report.paths.analysedFiles}`,
  ];
  if (report.diagnostics.length > 0) {
    lines.push("", "Diagnostics:", ...report.diagnostics.map((diagnostic) => `- ${diagnostic.diagnosticType}: ${diagnostic.message}${diagnostic.filePath ? ` (${diagnostic.filePath})` : ""}`));
  }
  if (report.findings.length > 0) {
    lines.push("", "Findings:", ...report.findings.map((finding) => `- [${finding.severity}] ${finding.filePath}:${finding.line ?? 1} ${finding.ruleId} - ${finding.message}`));
  }
  return `${lines.join("\n")}\n`;
}

function renderMarkdown(report: AnalysisReport): string {
  return [
    "# gruff-ts report",
    "",
    `Score: **${report.score.composite.toFixed(1)} (${report.score.grade})**`,
    "",
    `Findings: ${report.summary.advisory} advisory, ${report.summary.warning} warning, ${report.summary.error} error.`,
    ...report.findings.slice(0, 50).map((finding) => `- \`${finding.ruleId}\` \`${finding.filePath}\`:${finding.line ?? 1} - ${finding.message}`),
  ].join("\n");
}

function renderGithub(report: AnalysisReport): string {
  return report.findings
    .map((finding) => `::${githubLevel(finding.severity)} file=${finding.filePath},line=${finding.line ?? 1},title=${escapeCommand(finding.ruleId)}::${escapeCommand(finding.message)}`)
    .join("\n");
}

interface DashboardRenderContext {
  projectRoot: string;
  scanPath: string;
}

function renderHtml(report: AnalysisReport, dashboardContext?: DashboardRenderContext): string {
  return `<!doctype html>
<html lang="en-NZ">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>gruff-ts report - ${escapeHtml(report.score.grade)}</title>
<style>${htmlReportCss(report.diagnostics.length > 0)}</style>
</head>
<body>
<main class="paper"><span class="corner-tr"></span><span class="corner-bl"></span>
${htmlMasthead(report)}
${htmlDiagnostics(report)}
${dashboardContext ? htmlDashboardContext(dashboardContext) : ""}
${htmlVerdict(report)}
${htmlPillars(report)}
${htmlOffenders(report)}
${htmlDistribution(report)}
${htmlFindings(report)}
${htmlFooter(report)}
</main>
</body>
</html>`;
}

function htmlMasthead(report: AnalysisReport): string {
  const paths = report.paths.analysedFiles === 0 ? "." : `${report.paths.analysedFiles} analysed ${report.paths.analysedFiles === 1 ? "file" : "files"}`;
  return `<header class="masthead"><div class="brand"><div class="wordmark">gruff</div><div class="tagline">ts/js code quality - inspection report</div></div><div class="meta">${htmlMetaRow("paths", paths)}${htmlMetaRow("format", report.run.format)}${htmlMetaRow("fail", report.run.failOn)}${htmlMetaRow("schema", report.schemaVersion)}<div class="inspection-id">gruff-ts ${escapeHtml(report.tool.version)}</div></div></header>`;
}

function htmlMetaRow(label: string, value: string): string {
  return `<div><span class="label">${escapeHtml(label)}</span><span class="val">${escapeHtml(value)}</span></div>`;
}

function htmlDiagnostics(report: AnalysisReport): string {
  if (report.diagnostics.length === 0) {
    return "";
  }
  const diagnostics = report.diagnostics
    .map((diagnostic) => {
      const location = diagnostic.filePath ? `<span class="diagnostic-location">${escapeHtml(diagnostic.filePath)}${diagnostic.line ? `:${diagnostic.line}` : ""}</span>` : "";
      return `<div class="diagnostic"><span class="diagnostic-type">${escapeHtml(diagnostic.diagnosticType)}</span><span class="diagnostic-message">${escapeHtml(diagnostic.message)}</span>${location}</div>`;
    })
    .join("");
  return `<section class="diagnostics"><h2 class="section-head">diagnostics <span class="aside">run messages</span></h2><div class="diagnostic-list">${diagnostics}</div></section>`;
}

function htmlDashboardContext(context: DashboardRenderContext): string {
  return `<section class="dashboard-context"><h2 class="section-head">dashboard scan <span class="aside">local run</span></h2><div class="dashboard-context-grid"><div><span class="label">Project root</span><span class="val">${escapeHtml(context.projectRoot)}</span></div><div><span class="label">Path</span><span class="val">${escapeHtml(context.scanPath)}</span></div></div></section>`;
}

function htmlVerdict(report: AnalysisReport): string {
  return `<section class="verdict"><div class="grade-stamp ${gradeClass(report.score.grade)}"><div class="grade-letter">${escapeHtml(report.score.grade)}</div><div class="grade-score">${report.score.composite.toFixed(1)} / 100</div></div><div class="verdict-body"><div class="verdict-headline">Inspection complete.<br><em>${escapeHtml(verdictSummary(report))}</em></div><div class="verdict-stats">${htmlStat(String(report.summary.total), "findings", "")}${htmlStat(String(report.summary.error), "errors", "fail")}${htmlStat(String(report.summary.warning), "warnings", "warn")}${htmlStat(String(report.summary.advisory), "advisories", "note")}</div></div></section>`;
}

function verdictSummary(report: AnalysisReport): string {
  const thresholdFindings = report.summary.warning + report.summary.error;
  if (thresholdFindings === 0) {
    return "No warning or error findings flagged.";
  }
  const pillars = new Set(report.findings.filter((finding) => finding.severity === "warning" || finding.severity === "error").map((finding) => finding.pillar));
  return `${thresholdFindings} ${thresholdFindings === 1 ? "finding" : "findings"} at warning or error severity across ${pillars.size} ${pillars.size === 1 ? "pillar" : "pillars"}.`;
}

function htmlStat(number: string, label: string, className: string): string {
  return `<div class="stat"><div class="num ${escapeHtml(className)}">${escapeHtml(number)}</div><div class="lbl">${escapeHtml(label)}</div></div>`;
}

function htmlPillars(report: AnalysisReport): string {
  const items =
    report.score.pillars.length === 0
      ? '<div class="empty">No pillar findings.</div>'
      : report.score.pillars
          .map((pillar) => {
            const letter = grade(pillar.score);
            return `<div class="pillar"><div class="name">${escapeHtml(pillar.pillar)}</div><div class="grade ${gradeClass(letter)}">${letter}</div><div class="breakdown"><div class="row"><span class="key">score</span><span class="val">${pillar.score.toFixed(1)}</span></div><div class="row"><span class="key">findings</span><span class="val">${pillar.findings}</span></div></div></div>`;
          })
          .join("");
  return `<section class="pillars"><h2 class="section-head">pillar grades <span class="aside">weighted composite</span></h2><div class="pillar-grid">${items}</div></section>`;
}

function htmlOffenders(report: AnalysisReport): string {
  const rows =
    report.score.topOffenders.length === 0
      ? '<tr><td colspan="4">No offenders found.</td></tr>'
      : report.score.topOffenders
          .map((file) => {
            const letter = grade(file.score);
            return `<tr><td class="file-path">${htmlLocation(file.filePath)}</td><td class="num">${file.score.toFixed(1)}</td><td class="num">${file.findings}</td><td class="num"><span class="grade-pill ${gradeClass(letter)}">${letter}</span></td></tr>`;
          })
          .join("");
  return `<section class="offenders"><h2 class="section-head">top offenders <span class="aside">sorted by score</span></h2><table class="offender-list"><thead><tr><th scope="col">file</th><th scope="col" class="num">score</th><th scope="col" class="num">findings</th><th scope="col" class="num">grade</th></tr></thead><tbody>${rows}</tbody></table></section>`;
}

function htmlDistribution(report: AnalysisReport): string {
  const distribution = cyclomaticDistribution(report);
  const max = Math.max(1, ...Object.values(distribution));
  const bars = Object.entries(distribution)
    .map(([label, count]) => {
      const height = Math.max(4, Math.round((count / max) * 100));
      const className = label === "16-20" || label === "21+" ? " fail" : label === "11-15" ? " warn" : "";
      return `<div class="bar${className}" style="height:${height}%;"><span class="count">${count}</span></div>`;
    })
    .join("");
  const axis = Object.keys(distribution)
    .map((label) => `<span>${escapeHtml(label)}</span>`)
    .join("");
  return `<section class="chart-section"><h2 class="section-head">distribution <span class="aside">cyclomatic complexity</span></h2><p class="chart-summary">${escapeHtml(cyclomaticSummary(distribution))}</p><div class="chart-card"><div class="title">cyclomatic complexity - flagged functions</div><div class="histogram">${bars}</div><div class="histogram-axis">${axis}</div></div></section>`;
}

function cyclomaticDistribution(report: AnalysisReport): Record<string, number> {
  const distribution: Record<string, number> = { "1-5": 0, "6-10": 0, "11-15": 0, "16-20": 0, "21+": 0 };
  for (const finding of report.findings) {
    if (finding.ruleId !== "complexity.cyclomatic") {
      continue;
    }
    const match = finding.message.match(/cyclomatic complexity (\d+)/);
    const value = match?.[1] ? Number(match[1]) : 0;
    const bucket = value >= 21 ? "21+" : value >= 16 ? "16-20" : value >= 11 ? "11-15" : value >= 6 ? "6-10" : value > 0 ? "1-5" : "";
    if (bucket !== "") {
      distribution[bucket] = (distribution[bucket] ?? 0) + 1;
    }
  }
  return distribution;
}

function cyclomaticSummary(distribution: Record<string, number>): string {
  const moderate = distribution["11-15"] ?? 0;
  const high = distribution["16-20"] ?? 0;
  const severe = distribution["21+"] ?? 0;
  const exceeds = moderate + high + severe;
  return `${exceeds} ${exceeds === 1 ? "function" : "functions"} ${exceeds === 1 ? "exceeds" : "exceed"} CC 10 (${moderate} in 11-15, ${high} in 16-20, ${severe} at 21+).`;
}

function htmlFindings(report: AnalysisReport): string {
  const findings =
    report.findings.length === 0
      ? '<div class="empty">No findings.</div>'
      : report.findings
          .slice(0, 250)
          .map(
            (finding) =>
              `<div class="finding"><div class="severity ${severityClass(finding.severity)}">${escapeHtml(finding.severity)}</div><div class="finding-body"><h3 class="rule">${escapeHtml(finding.ruleId)}</h3><div class="msg">${escapeHtml(finding.message)}</div><div class="loc"><code>${htmlLocation(finding.filePath, finding.line)}</code></div></div><div class="points"><b>${escapeHtml(finding.pillar)}</b></div></div>`,
          )
          .join("");
  const capped = report.findings.length > 250 ? ` <span class="aside">first 250 of ${report.findings.length}</span>` : ` <span class="aside">${report.findings.length} shown</span>`;
  return `<section class="findings"><h2 class="section-head">flagged findings${capped}</h2><div class="findings-list">${findings}</div></section>`;
}

function htmlFooter(report: AnalysisReport): string {
  return `<footer class="footer"><div class="left">gruff-ts - v${escapeHtml(report.tool.version)}</div><div class="center">strong opinions, opinionated defaults</div><div class="right">schema - ${escapeHtml(report.schemaVersion)}</div></footer>`;
}

function htmlLocation(filePath: string, line?: number): string {
  const text = line === undefined ? filePath : `${filePath}:${line}`;
  return `<span class="loc-link" tabindex="0" data-path="${escapeHtml(text)}">${escapeHtml(text)}</span>`;
}

function severityClass(severity: Severity): string {
  return severity === "error" ? "fail" : severity === "warning" ? "warn" : "note";
}

function gradeClass(value: string): string {
  const letter = value[0]?.toLowerCase() ?? "n";
  return ["a", "b", "c", "d", "f"].includes(letter) ? letter : "n";
}

function htmlReportCss(includeDiagnostics: boolean): string {
  const css = `:root{--ink:#0d0c0a;--ink-2:#161412;--ink-3:#1f1c19;--paper:#f3e9d2;--paper-dim:#b5ab94;--paper-mute:#7d735f;--rule:#2a2622;--forge:#e85d04;--grade-a:#7fa15a;--grade-b:#b8b450;--grade-c:#d08c36;--grade-d:#c2552b;--grade-f:#8b2828;--advisory:#b5ab94;--serif:Georgia,'Iowan Old Style',serif;--mono:'JetBrains Mono','IBM Plex Mono',ui-monospace,monospace}*{box-sizing:border-box;margin:0;padding:0}html{background:var(--ink);scrollbar-gutter:stable}body{font-family:var(--mono);color:var(--paper);background:var(--ink);min-height:100vh;line-height:1.5;font-size:14px;padding:48px 32px}.paper{max-width:1180px;margin:0 auto 24px;background:var(--ink-2);border:1px solid var(--rule);position:relative;padding:56px 64px 48px;scrollbar-gutter:stable}.corner-tr,.corner-bl,.paper:before,.paper:after{content:'';position:absolute;width:22px;height:22px;border:1px solid var(--forge)}.paper:before{top:12px;left:12px;border-right:0;border-bottom:0}.paper:after{bottom:12px;right:12px;border-left:0;border-top:0}.corner-tr{top:12px;right:12px;border-left:0;border-bottom:0}.corner-bl{bottom:12px;left:12px;border-right:0;border-top:0}.masthead{display:grid;grid-template-columns:1fr auto;gap:32px;padding-bottom:28px;border-bottom:1px solid var(--rule);align-items:end}.wordmark{font-family:var(--serif);font-weight:900;font-size:96px;line-height:.85;color:var(--paper);font-style:italic}.wordmark:after{content:'-ts';color:var(--forge);font-style:normal;font-size:.45em;margin-left:.15em;vertical-align:super}.tagline{margin-top:12px;font-size:11px;letter-spacing:0;color:var(--paper-mute);text-transform:uppercase}.meta{text-align:right;font-size:11px;color:var(--paper-dim);line-height:1.9}.label{color:var(--paper-mute);text-transform:uppercase;letter-spacing:0;margin-right:8px}.val{color:var(--paper)}.inspection-id{margin-top:10px;color:var(--forge);font-weight:700;font-size:12px;letter-spacing:0}.section-head{font-size:11px;letter-spacing:0;color:var(--paper-mute);text-transform:uppercase;padding-bottom:16px;margin-bottom:20px;border-bottom:1px solid var(--rule);display:flex;justify-content:space-between;align-items:baseline;font-family:var(--mono);font-weight:500;line-height:1.5}.section-head:before{content:'>';margin-right:10px;color:var(--forge);font-family:var(--serif);font-size:14px;font-style:italic}.aside{color:var(--paper-mute);font-size:10px;letter-spacing:0}.verdict{display:grid;grid-template-columns:auto 1fr;gap:56px;padding:48px 0;border-bottom:1px solid var(--rule);align-items:center}.grade-stamp{width:220px;height:220px;border:3px solid currentColor;color:var(--grade-b);display:flex;flex-direction:column;align-items:center;justify-content:center;transform:rotate(-4deg)}.grade-stamp.a,.grade.a,.grade-pill.a{color:var(--grade-a)}.grade-stamp.b,.grade.b,.grade-pill.b{color:var(--grade-b)}.grade-stamp.c,.grade.c,.grade-pill.c{color:var(--grade-c)}.grade-stamp.d,.grade.d,.grade-pill.d{color:var(--grade-d)}.grade-stamp.f,.grade.f,.grade-pill.f{color:var(--grade-f)}.grade-letter{font-family:var(--serif);font-style:italic;font-weight:900;font-size:112px;line-height:1}.grade-score{font-size:13px;letter-spacing:0}.verdict-body{display:flex;flex-direction:column;gap:18px}.verdict-headline{font-family:var(--serif);font-style:italic;font-weight:600;font-size:38px;line-height:1.15}.verdict-headline em{color:var(--forge)}.verdict-stats{display:grid;grid-template-columns:repeat(4,1fr);border-top:1px solid var(--rule);padding-top:20px}.stat{border-right:1px solid var(--rule);padding:0 18px}.stat:first-child{padding-left:0}.stat:last-child{border-right:0}.verdict-stats .num{font-family:var(--serif);font-weight:800;font-size:32px;line-height:1}.verdict-stats .num.warn{color:var(--grade-c)}.verdict-stats .num.fail{color:var(--grade-f)}.verdict-stats .num.note{color:var(--advisory)}.lbl{font-size:10px;text-transform:uppercase;letter-spacing:0;color:var(--paper-mute);margin-top:8px}.pillars,.offenders,.chart-section{padding:48px 0;border-bottom:1px solid var(--rule)}.pillar-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--rule);border:1px solid var(--rule)}.pillar{background:var(--ink-2);padding:24px 20px;display:flex;flex-direction:column;gap:14px}.pillar .name{font-size:10px;text-transform:uppercase;letter-spacing:0;color:var(--paper-mute)}.pillar .grade{font-family:var(--serif);font-weight:800;font-style:italic;font-size:52px;line-height:.9}.breakdown{font-size:11px;color:var(--paper-dim);line-height:1.7}.row{display:flex;justify-content:space-between;gap:8px}.key{color:var(--paper-mute)}table{width:100%;border-collapse:collapse;font-size:13px;table-layout:auto;font-family:var(--mono)}th{text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:0;color:var(--paper-mute);font-weight:500;padding:12px 14px 12px 0;border-bottom:1px solid var(--rule)}th:last-child,td:last-child{padding-right:0}th.num,td.num{text-align:right;padding-left:18px}td{padding:14px 14px 14px 0;border-bottom:1px solid var(--ink-3);color:var(--paper-dim);font-size:13px;font-family:var(--mono);font-weight:500;line-height:1.4}td.num{color:var(--paper);font-variant-numeric:tabular-nums}.file-path{color:var(--paper);font-weight:500}.grade-pill{display:inline-block;font-family:var(--serif);font-style:italic;font-weight:800;font-size:18px;line-height:1;padding:4px 10px;border:1.5px solid currentColor;min-width:36px;text-align:center}.chart-summary{color:var(--paper-dim);font-size:12px;margin:-6px 0 18px}.chart-card{border:1px solid var(--rule);padding:24px;background:var(--ink-3)}.title{font-size:10px;text-transform:uppercase;letter-spacing:0;color:var(--paper-mute);margin-bottom:24px}.histogram{display:flex;align-items:flex-end;gap:6px;height:180px;padding-bottom:20px;border-bottom:1px solid var(--rule)}.bar{flex:1;background:var(--forge);position:relative;min-height:4px}.bar.warn{background:var(--grade-c)}.bar.fail{background:var(--grade-f)}.bar .count{position:absolute;top:-22px;left:50%;transform:translateX(-50%);font-size:11px}.histogram-axis{display:flex;gap:6px;margin-top:8px;font-size:10px;color:var(--paper-mute)}.histogram-axis span{flex:1;text-align:center}.findings{padding:48px 0}.finding{display:grid;grid-template-columns:auto 1fr auto;gap:24px;padding:18px 0;border-bottom:1px solid var(--ink-3);align-items:start}.severity{font-size:9px;text-transform:uppercase;letter-spacing:0;padding:4px 10px;border:1px solid currentColor;margin-top:2px;min-width:76px;text-align:center}.severity.fail{color:var(--grade-f)}.severity.warn{color:var(--grade-c)}.severity.note{color:var(--paper-mute)}.rule{font-size:10px;color:var(--forge);text-transform:uppercase;letter-spacing:0;margin-bottom:6px;font-family:var(--mono);font-weight:700;line-height:1.5}.msg{font-family:var(--serif);font-weight:500;font-size:17px;color:var(--paper);line-height:1.4}.loc{font-size:11px;color:var(--paper-mute);margin-top:8px}.loc code{color:var(--paper-dim);background:var(--ink-3);padding:1px 6px;border:1px solid var(--rule)}.loc-link{color:inherit;text-decoration:none}.loc-link:focus-visible{outline:2px solid var(--forge);outline-offset:3px}.points{font-size:10px;color:var(--paper-mute);text-align:right;letter-spacing:0;min-width:96px;padding-left:12px}.empty{color:var(--paper-dim);font-size:12px}.footer{margin-top:48px;padding-top:24px;border-top:1px solid var(--rule);display:grid;grid-template-columns:1fr auto 1fr;gap:24px;align-items:center;font-size:10px;color:var(--paper-mute);letter-spacing:0;text-transform:uppercase}.center{font-family:var(--serif);font-style:italic;font-size:13px;color:var(--paper-dim);text-transform:none;letter-spacing:0}.right{text-align:right}@media(max-width:900px){body{padding:16px}.paper{padding:28px 20px}.wordmark{font-size:64px}.masthead,.verdict{grid-template-columns:1fr}.meta{text-align:left}.grade-stamp{margin:0 auto}.pillar-grid{grid-template-columns:repeat(2,1fr)}.verdict-stats{grid-template-columns:repeat(2,1fr);gap:16px}.stat{border-right:0;padding:0}.verdict-headline{font-size:28px}.footer{grid-template-columns:1fr}.center,.right{text-align:left}}@media(max-width:560px){.pillar-grid{grid-template-columns:1fr}.finding{grid-template-columns:1fr}.points{text-align:left;padding-left:0}.verdict-stats{grid-template-columns:1fr}.histogram{height:140px}}`;
  const reportCss = `${css}.dashboard-context{padding:28px 0;border-bottom:1px solid var(--rule)}.dashboard-context-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.dashboard-context-grid>div{border:1px solid var(--rule);background:var(--ink-3);padding:12px 14px}.dashboard-context .label{display:block;margin:0 0 6px}.dashboard-context .val{overflow-wrap:anywhere}@media(max-width:700px){.dashboard-context-grid{grid-template-columns:1fr}}@media(max-width:560px){.offender-list thead{display:none}.offender-list,.offender-list tbody,.offender-list tr,.offender-list td{display:block;width:100%}.offender-list tr{border-bottom:1px solid var(--ink-3);padding:10px 0}.offender-list td{border-bottom:0;padding:6px 0}.offender-list td.num{text-align:left;padding-left:0}}`;
  if (!includeDiagnostics) {
    return reportCss;
  }
  return `${reportCss}.diagnostics{padding:28px 0 0}.diagnostic-list{display:grid;gap:10px}.diagnostic{display:grid;grid-template-columns:auto 1fr;gap:10px 14px;border:1px solid var(--rule);background:var(--ink-3);padding:12px 14px;color:var(--paper-dim);font-size:12px}.diagnostic-type{text-transform:uppercase;letter-spacing:0;color:var(--forge);font-size:10px}.diagnostic-location{grid-column:2;color:var(--paper-mute);font-size:11px}`;
}

function scoreReport(findings: Finding[]): AnalysisReport["score"] {
  const byPillar = new Map<Pillar, Finding[]>();
  const byFile = new Map<string, Finding[]>();
  for (const finding of findings) {
    byPillar.set(finding.pillar, [...(byPillar.get(finding.pillar) ?? []), finding]);
    byFile.set(finding.filePath, [...(byFile.get(finding.filePath) ?? []), finding]);
  }
  const pillars = [...byPillar.entries()].map(([pillar, pillarFindings]) => {
    const penalty = pillarFindings.reduce((sum, finding) => sum + severityPenalty(finding.severity), 0);
    return { pillar, score: Math.max(0, 100 - penalty), findings: pillarFindings.length };
  });
  const composite = pillars.length === 0 ? 100 : pillars.reduce((sum, pillar) => sum + pillar.score, 0) / pillars.length;
  const topOffenders = [...byFile.entries()]
    .map(([filePath, fileFindings]) => ({
      filePath,
      score: Math.max(0, 100 - fileFindings.reduce((sum, finding) => sum + severityPenalty(finding.severity), 0)),
      findings: fileFindings.length,
    }))
    .sort((left, right) => left.score - right.score)
    .slice(0, 10);
  return { composite, grade: grade(composite), pillars, topOffenders };
}

function summarize(findings: Finding[]) {
  return {
    advisory: findings.filter((finding) => finding.severity === "advisory").length,
    warning: findings.filter((finding) => finding.severity === "warning").length,
    error: findings.filter((finding) => finding.severity === "error").length,
    total: findings.length,
  };
}

function exitFor(report: AnalysisReport, failOn: FailThreshold): number {
  if (report.diagnostics.length > 0) {
    return 2;
  }
  return report.findings.some((finding) => thresholdTriggered(failOn, finding.severity)) ? 1 : 0;
}

function thresholdTriggered(thresholdValue: FailThreshold, severity: Severity): boolean {
  if (thresholdValue === "none") {
    return false;
  }
  if (thresholdValue === "advisory") {
    return true;
  }
  if (thresholdValue === "warning") {
    return severity === "warning" || severity === "error";
  }
  return severity === "error";
}

function startDashboard(host: string, port: number, projectRoot: string): void {
  const server = createServer((request, response) => {
    const url = new URL(request.url ?? "/", `http://${host}:${port}`);
    if (url.pathname === "/health") {
      response.writeHead(200, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
      response.end("ok");
      return;
    }
    if (url.pathname === "/scan") {
      const root = url.searchParams.get("projectRoot") ?? projectRoot;
      const scanPath = url.searchParams.get("path") ?? ".";
      const previous = cwd();
      try {
        chdir(root);
        const report = analyse({
          paths: [scanPath],
          noConfig: false,
          format: "html",
          failOn: "none",
          includeIgnored: false,
          noBaseline: false,
        });
        response.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
        response.end(renderHtml(report, { projectRoot: root, scanPath }));
      } catch (error) {
        response.writeHead(500, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
        response.end(dashboardErrorHtml(String(error), root, scanPath));
      } finally {
        chdir(previous);
      }
      return;
    }
    if (url.pathname !== "/") {
      response.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
      response.end("not found");
      return;
    }
    const root = url.searchParams.get("projectRoot") ?? projectRoot;
    const scanPath = url.searchParams.get("path") ?? ".";
    response.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
    response.end(dashboardHomeHtml(root, scanPath));
  });
  server.listen(port, host, () => {
    console.log(`gruff-ts dashboard listening at http://${host}:${port}`);
  });
}

function dashboardHomeHtml(projectRoot: string, scanPath: string): string {
  const initialScan = dashboardScanUrl(projectRoot, scanPath);
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>gruff-ts dashboard</title>
  <style>${dashboardCss()}</style>
</head>
<body>
  <iframe class="report-frame" name="report-frame" title="gruff-ts report" src="${escapeHtml(initialScan)}"></iframe>
  <button class="controls-toggle" type="button" aria-expanded="false" aria-controls="controls-panel" title="Dashboard controls">&#9881;</button>
  <aside class="controls-panel" id="controls-panel" hidden>
    <header class="controls-head">
      <h1>Dashboard controls</h1>
      <p>local scan settings</p>
    </header>
    <form class="scan-form" data-scan-form action="/scan" method="get" target="report-frame">
      <label>Project root <input name="projectRoot" value="${escapeHtml(projectRoot)}" autocomplete="off"></label>
      <label>Paths <input name="path" value="${escapeHtml(scanPath)}" autocomplete="off"></label>
      <div class="scan-state"><span>Status</span><strong data-scan-status>Loading report</strong></div>
      <div class="actions">
        <button class="secondary" type="button" data-refresh>Refresh</button>
        <button type="submit">Run scan</button>
      </div>
    </form>
  </aside>
  <script>${dashboardJs()}</script>
</body>
</html>`;
}

function dashboardScanUrl(projectRoot: string, scanPath: string): string {
  const params = new URLSearchParams({ projectRoot, path: scanPath });
  return `/scan?${params.toString()}`;
}

function dashboardErrorHtml(message: string, projectRoot: string, scanPath: string): string {
  return `<!doctype html>
<html lang="en-NZ">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>gruff-ts dashboard scan failed</title>
<style>${dashboardCss()}</style>
</head>
<body class="error-page">
  <main class="scan-error">
    <h1>Scan failed</h1>
    <p>${escapeHtml(message)}</p>
    <dl>
      <dt>Project root</dt><dd>${escapeHtml(projectRoot)}</dd>
      <dt>Paths</dt><dd>${escapeHtml(scanPath)}</dd>
    </dl>
  </main>
</body>
</html>`;
}

function dashboardCss(): string {
  return `:root{color-scheme:dark;--ink:#0d0c0a;--ink-2:#161412;--panel:#1f1c19;--paper:#f3e9d2;--paper-dim:#b5ab94;--paper-mute:#7d735f;--rule:#2a2622;--forge:#e85d04;--forge-dark:#b94402;--mono:'JetBrains Mono','IBM Plex Mono',ui-monospace,monospace}*{box-sizing:border-box}html,body{height:100%;margin:0;background:var(--ink);color:var(--paper);font-family:var(--mono);font-size:14px;line-height:1.5}.report-frame{position:fixed;inset:0;width:100%;height:100%;border:0;background:var(--ink)}.controls-toggle{position:fixed;top:18px;right:18px;z-index:3;width:44px;height:44px;border:1px solid rgba(232,93,4,.75);border-radius:8px;background:var(--forge);color:#170b05;font:700 22px/1 var(--mono);display:grid;place-items:center;cursor:pointer;box-shadow:0 16px 36px rgba(0,0,0,.38)}.controls-toggle:hover,.controls-toggle:focus-visible{background:#ff7a1a;outline:2px solid rgba(243,233,210,.75);outline-offset:3px}.controls-panel{position:fixed;z-index:2;top:74px;right:18px;width:min(420px,calc(100vw - 36px));max-height:calc(100vh - 92px);overflow:auto;background:rgba(31,28,25,.98);border:1px solid var(--rule);border-radius:8px;padding:20px;box-shadow:0 24px 70px rgba(0,0,0,.5)}[hidden]{display:none!important}.controls-head{border-bottom:1px solid var(--rule);padding-bottom:14px;margin-bottom:16px}.controls-head h1{margin:0;font-size:18px;font-weight:800}.controls-head p{margin:4px 0 0;color:var(--paper-mute);font-size:12px;text-transform:uppercase}.scan-form{display:grid;gap:14px}.scan-form label{display:grid;gap:6px;color:var(--paper-dim);font-size:12px;text-transform:uppercase}.scan-form input{width:100%;font:inherit;color:var(--paper);background:var(--ink-2);border:1px solid var(--rule);border-radius:6px;padding:10px 11px;min-width:0}.scan-form input:focus{outline:2px solid var(--forge);outline-offset:2px}.scan-state{display:flex;justify-content:space-between;gap:12px;border:1px solid var(--rule);background:var(--ink-2);border-radius:6px;padding:10px 11px;color:var(--paper-mute)}.scan-state strong{color:var(--paper);font-weight:700;text-align:right}.actions{display:grid;grid-template-columns:1fr 1fr;gap:10px}.actions button{font:inherit;border:1px solid var(--forge);border-radius:6px;padding:10px 12px;background:var(--forge);color:#170b05;font-weight:800;cursor:pointer}.actions button.secondary{background:transparent;color:var(--paper);border-color:var(--rule)}.actions button:disabled{opacity:.6;cursor:wait}.scan-error{max-width:720px;margin:8vh auto;padding:48px;background:var(--panel);border:1px solid var(--rule);color:var(--paper)}.scan-error h1{margin:0 0 16px;font-size:28px}.scan-error p{color:var(--paper-dim);overflow-wrap:anywhere}.scan-error dl{display:grid;grid-template-columns:auto 1fr;gap:8px 16px;margin:24px 0 0}.scan-error dt{color:var(--paper-mute);text-transform:uppercase}.scan-error dd{margin:0;overflow-wrap:anywhere}@media(max-width:560px){.controls-toggle{top:12px;right:12px}.controls-panel{top:64px;right:12px;width:calc(100vw - 24px);max-height:calc(100vh - 76px);padding:16px}.actions{grid-template-columns:1fr}.scan-error{margin:0;min-height:100vh;padding:28px 20px}.scan-error dl{grid-template-columns:1fr}}`;
}

function dashboardJs(): string {
  return `const form=document.querySelector("[data-scan-form]");const frame=document.querySelector(".report-frame");const toggle=document.querySelector(".controls-toggle");const panel=document.querySelector(".controls-panel");const refresh=document.querySelector("[data-refresh]");const status=document.querySelector("[data-scan-status]");function setOpen(open){panel.hidden=!open;toggle.setAttribute("aria-expanded",String(open));if(open){const input=form.querySelector("input");if(input){input.focus();}}}function params(){return new URLSearchParams(new FormData(form));}function runScan(){const query=params();status.textContent="Scanning";refresh.disabled=true;form.querySelector("button[type=submit]").disabled=true;frame.src="/scan?"+query.toString();history.replaceState(null,"","/?"+query.toString());}toggle.addEventListener("click",()=>setOpen(panel.hidden));document.addEventListener("keydown",(event)=>{if(event.key==="Escape"){setOpen(false);}});form.addEventListener("submit",(event)=>{event.preventDefault();runScan();});refresh.addEventListener("click",runScan);frame.addEventListener("load",()=>{status.textContent="Ready";refresh.disabled=false;form.querySelector("button[type=submit]").disabled=false;});`;
}

function buildProgram(): Command {
  const program = new Command();
  program.name("gruff-ts").version(VERSION);

  program
    .command("analyse")
    .description("Run gruff analysis.")
    .argument("[paths...]", "Files or directories to analyse.")
    .option("--config <path>", "Path to a gruff JSON/YAML config file.")
    .option("--no-config", "Skip auto-applying the default .gruff.json/.gruff.yaml/.gruff.yml file for this run.")
    .option("--format <format>", "Output format: text, json, html, markdown, github, or hotspot.", "text")
    .option("--fail-on <severity>", "Finding severity that fails the run: advisory, warning, error, or none.", "error")
    .option("--include-ignored", "Include files under default ignored directories.")
    .option("--diff [mode]", "Filter findings to changed files. Use working-tree, staged, unstaged, or a base ref.")
    .option("--history-file <path>", "Append score trend history to this JSON file.")
    .option("--baseline [path]", "Suppress findings that match a gruff baseline JSON file.")
    .option("--generate-baseline [path]", "Write current findings to a gruff baseline JSON file.")
    .option("--no-baseline", "Skip auto-applying the default baseline file for this run.")
    .action((paths: string[], rawOptions: Record<string, unknown>) => {
      const options = normalizeOptions(paths, rawOptions, { allowBaselineFlag: true });
      const report = analyse(options);
      console.log(renderReport(report, options.format));
      process.exitCode = exitFor(report, options.failOn);
    });

  program
    .command("report")
    .description("Render a static gruff report.")
    .argument("[paths...]", "Files or directories to analyse.")
    .option("--format <format>", "Report format: html or json.", "html")
    .option("--output <path>", "Write report to a file.")
    .option("--config <path>", "Path to a gruff JSON/YAML config file.")
    .option("--no-config", "Skip auto-applying the default .gruff.json/.gruff.yaml/.gruff.yml file for this run.")
    .option("--fail-on <severity>", "Finding severity that fails the run.", "none")
    .option("--include-ignored", "Include files under default ignored directories.")
    .option("--no-baseline", "Skip auto-applying the default baseline file for this run.")
    .action((paths: string[], rawOptions: Record<string, unknown>) => {
      const format = rawOptions.format === "json" ? "json" : "html";
      const options = normalizeOptions(paths, { ...rawOptions, format }, { allowBaselineFlag: false });
      const report = analyse(options);
      const rendered = renderReport(report, format);
      if (typeof rawOptions.output === "string") {
        writeFileSync(rawOptions.output, rendered);
      } else {
        console.log(rendered);
      }
      process.exitCode = exitFor(report, options.failOn);
    });

  program
    .command("list-rules")
    .description("List rule catalogue metadata.")
    .option("--format <format>", "Output format: text or json.", "text")
    .action((rawOptions: Record<string, unknown>) => {
      const format: RuleListFormat = rawOptions.format === "json" ? "json" : "text";
      console.log(renderRuleList(format));
    });

  program
    .command("dashboard")
    .description("Start the local gruff dashboard.")
    .option("--host <host>", "Host to bind.", "127.0.0.1")
    .option("--port <port>", "Port to bind.", "8767")
    .option("--project-root <path>", "Default project root.", ".")
    .action((rawOptions: Record<string, unknown>) => {
      startDashboard(String(rawOptions.host ?? "127.0.0.1"), Number(rawOptions.port ?? 8767), resolve(String(rawOptions.projectRoot ?? ".")));
    });

  return program;
}

function normalizeOptions(paths: string[], rawOptions: Record<string, unknown>, context: NormalizeContext): AnalysisOptions {
  const format = stringChoice(rawOptions.format, ["text", "json", "html", "markdown", "github", "hotspot"], "text");
  const failOn = stringChoice(rawOptions.failOn, ["none", "advisory", "warning", "error"], "error");
  const baselineValue = rawOptions.baseline;
  const noBaseline = baselineValue === false || rawOptions.noBaseline === true;
  return {
    paths,
    ...(typeof rawOptions.config === "string" ? { config: rawOptions.config } : {}),
    noConfig: rawOptions.config === false || rawOptions.noConfig === true,
    format,
    failOn,
    includeIgnored: rawOptions.includeIgnored === true,
    ...(typeof rawOptions.diff === "string" ? { diff: rawOptions.diff } : rawOptions.diff === true ? { diff: "working-tree" } : {}),
    ...(typeof rawOptions.historyFile === "string" ? { historyFile: rawOptions.historyFile } : {}),
    ...(context.allowBaselineFlag && typeof baselineValue === "string" ? { baseline: baselineValue } : context.allowBaselineFlag && baselineValue === true ? { baseline: DEFAULT_BASELINE } : {}),
    ...(typeof rawOptions.generateBaseline === "string"
      ? { generateBaseline: rawOptions.generateBaseline }
      : rawOptions.generateBaseline === true
        ? { generateBaseline: DEFAULT_BASELINE }
        : {}),
    noBaseline,
  };
}

function changedFiles(mode: string): Set<string> {
  const args = ["diff", "--name-only"];
  if (mode === "staged") {
    args.push("--cached");
  } else if (mode !== "working-tree" && mode !== "unstaged") {
    args.push(mode);
  }
  return new Set(execFileSync("git", args, { encoding: "utf8" }).split(/\r?\n/).filter(Boolean).map((line) => line.replaceAll("\\", "/")));
}

function writeBaseline(path: string, findings: Finding[]): void {
  writeFileSync(
    path,
    JSON.stringify(
      {
        schemaVersion: "gruff.baseline.v1",
        generatedAt: new Date().toISOString(),
        entries: findings.map((finding) => ({
          fingerprint: finding.fingerprint,
          ruleId: finding.ruleId,
          filePath: finding.filePath,
          line: finding.line,
          symbol: finding.symbol,
          message: finding.message,
        })),
      },
      null,
      2,
    ),
  );
}

function applyBaseline(path: string, findings: Finding[]): Finding[] {
  const data = JSON.parse(readFileSync(path, "utf8")) as { schemaVersion?: string; entries?: Array<{ fingerprint: string; ruleId: string; filePath: string }> };
  if (data.schemaVersion !== "gruff.baseline.v1") {
    throw new Error(`unsupported baseline schema in ${path}`);
  }
  const keys = new Set((data.entries ?? []).map((entry) => [entry.fingerprint, entry.ruleId, entry.filePath].join("\0")));
  return findings.filter((finding) => !keys.has([finding.fingerprint, finding.ruleId, finding.filePath].join("\0")));
}

function recordHistory(projectRoot: string, historyFile: string, findings: Finding[], diagnostics: RunDiagnostic[]): void {
  const path = absolutize(projectRoot, historyFile);
  try {
    const entries = existsSync(path) ? (JSON.parse(readFileSync(path, "utf8")) as unknown[]) : [];
    entries.push({ recordedAt: new Date().toISOString(), findings: findings.length, score: scoreReport(findings).composite });
    writeFileSync(path, JSON.stringify(entries.slice(-100), null, 2));
  } catch (error) {
    diagnostics.push({ diagnosticType: "history-error", message: `Unable to write history file: ${String(error)}`, filePath: displayPath(projectRoot, path) });
  }
}

function ruleEnabled(config: Config, ruleId: string): boolean {
  return config.rules.get(ruleId)?.enabled ?? true;
}

function threshold(config: Config, ruleId: string, name: string, defaultValue: number): number {
  return config.rules.get(ruleId)?.thresholds.get(name) ?? defaultValue;
}

function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((finding) => {
    if (seen.has(finding.fingerprint)) {
      return false;
    }
    seen.add(finding.fingerprint);
    return true;
  });
}

function isDefaultIgnoredDir(path: string): boolean {
  const first = path.split("/")[0] ?? path;
  return [".git", ".hg", ".svn", ".idea", ".vscode", "build", "cache", "coverage", "dist", "generated", "node_modules", "target", "tmp", "vendor"].includes(first);
}

function pathMatches(pattern: string, path: string): boolean {
  if (pattern === path) {
    return true;
  }
  if (pattern.endsWith("/**")) {
    const prefix = pattern.slice(0, -3);
    return path === prefix || path.startsWith(`${prefix}/`);
  }
  if (pattern.includes("*")) {
    const regex = new RegExp(`^${escapeRegex(pattern).replaceAll("\\*\\*", ".*").replaceAll("\\*", "[^/]*")}$`);
    return regex.test(path);
  }
  return path.startsWith(pattern.replace(/\/$/, ""));
}

function uniqueFiles(files: SourceFile[]): SourceFile[] {
  const seen = new Set<string>();
  return files.filter((file) => {
    if (seen.has(file.absolutePath)) {
      return false;
    }
    seen.add(file.absolutePath);
    return true;
  });
}

function maxNestingDepth(source: string): number {
  let depth = 0;
  let maxDepth = 0;
  for (const character of source) {
    if (character === "{") {
      depth += 1;
      maxDepth = Math.max(maxDepth, depth);
    } else if (character === "}") {
      depth = Math.max(0, depth - 1);
    }
  }
  return Math.max(0, maxDepth - 1);
}

function hasDocCommentBefore(block: string): boolean {
  return block
    .split(/\r?\n/)
    .filter((line) => !/\b(function|class|interface|type|enum)\b/.test(line))
    .some((line) => line.trimStart().startsWith("/**") || line.trimStart().startsWith("*"));
}

function hasDocCommentBeforeLine(source: string, line: number): boolean {
  const lines = source.split(/\r?\n/);
  let index = line - 2;
  while (index >= 0) {
    const current = lines[index]?.trim() ?? "";
    if (current.startsWith("/**") || current.startsWith("*")) {
      return true;
    }
    if (current !== "" && !current.startsWith("@")) {
      return false;
    }
    index -= 1;
  }
  return false;
}

function isGenericName(name: string): boolean {
  return ["process", "handle", "doit", "run", "execute", "manage"].includes(name.toLowerCase());
}

function isHighEntropySecretCandidate(value: string, minLength: number): boolean {
  if (value.length < minLength || /^[0-9a-f]+$/i.test(value) || /^sha(?:256|384|512)-[A-Za-z0-9+/=]+$/.test(value)) {
    return false;
  }
  if (!/[a-z]/.test(value) || !/[A-Z]/.test(value) || !/[0-9]/.test(value)) {
    return false;
  }
  if (new Set(value).size < Math.min(12, Math.ceil(value.length / 3))) {
    return false;
  }
  return shannonEntropy(value) >= 4;
}

function shannonEntropy(value: string): number {
  const counts = new Map<string, number>();
  for (const character of value) {
    counts.set(character, (counts.get(character) ?? 0) + 1);
  }
  return [...counts.values()].reduce((sum, count) => {
    const probability = count / value.length;
    return sum - probability * Math.log2(probability);
  }, 0);
}

function countMatches(source: string, pattern: RegExp): number {
  return [...source.matchAll(pattern)].length;
}

function firstLine(source: string, pattern: RegExp): number {
  return source.split(/\r?\n/).findIndex((line) => pattern.test(line)) + 1 || 1;
}

function byteLine(source: string, index: number): number {
  return source.slice(0, Math.max(0, index)).split("\n").length;
}

function redact(value: string): string {
  if (value.length <= 8) {
    return `${"*".repeat(value.length)} (redacted, ${value.length} chars)`;
  }
  return `${value.slice(0, 4)}...${value.slice(-4)} (redacted, ${value.length} chars)`;
}

function severityPenalty(severity: Severity): number {
  return severity === "error" ? 8 : severity === "warning" ? 4 : 1.5;
}

function grade(score: number): string {
  if (score >= 90) {
    return "A";
  }
  if (score >= 80) {
    return "B";
  }
  if (score >= 70) {
    return "C";
  }
  if (score >= 60) {
    return "D";
  }
  return "F";
}

function githubLevel(severity: Severity): "notice" | "warning" | "error" {
  return severity === "error" ? "error" : severity === "warning" ? "warning" : "notice";
}

function escapeCommand(value: string): string {
  return value.replaceAll("%", "%25").replaceAll("\n", "%0A").replaceAll("\r", "%0D");
}

function escapeHtml(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function absolutize(projectRoot: string, path: string): string {
  return isAbsolute(path) ? path : join(projectRoot, path);
}

function displayPath(projectRoot: string, path: string): string {
  const value = relative(projectRoot, path).replaceAll("\\", "/");
  return value === "" ? "." : value;
}

function stringChoice<T extends string>(value: unknown, choices: readonly T[], fallback: T): T {
  return typeof value === "string" && choices.includes(value as T) ? (value as T) : fallback;
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;
}

function arrayValue(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function isString(value: unknown): value is string {
  return typeof value === "string";
}

if (import.meta.url === pathToFileURL(argv[1] ?? "").href) {
  buildProgram().parse(argv);
}

export { buildProgram, renderReport };
