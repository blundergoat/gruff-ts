#!/usr/bin/env node
import { Command } from "commander";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { createServer } from "node:http";
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { argv, chdir, cwd } from "node:process";
import { basename, extname, isAbsolute, join, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const VERSION = "0.1.0-dev";
const DEFAULT_BASELINE = "gruff-baseline.json";

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
  for (const file of discovery.files) {
    try {
      const source = readFileSync(file.absolutePath, "utf8");
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
  const path = options.config
    ? absolutize(projectRoot, options.config)
    : existsSync(join(projectRoot, ".gruff.json"))
      ? join(projectRoot, ".gruff.json")
      : undefined;
  if (!path) {
    return config;
  }

  const raw = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
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
  const lines = source.split(/\r?\n/);
  for (const [index, line] of lines.entries()) {
    for (const character of line) {
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

function analyseSource(file: SourceFile, source: string, config: Config): Finding[] {
  const findings: Finding[] = [];
  analyseTextRules(file, source, config, findings);
  if (file.isTypeScript) {
    analyseTypeScriptRules(file, source, config, findings);
  }
  return findings.filter((finding) => ruleEnabled(config, finding.ruleId));
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
}

function analyseSensitiveData(file: SourceFile, source: string, config: Config, findings: Finding[]): void {
  const patterns: Array<[string, RegExp, string]> = [
    ["sensitive-data.aws-access-key", /AKIA[0-9A-Z]{16}/g, "AWS access key pattern detected."],
    ["sensitive-data.private-key", /BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY/g, "Private key block detected."],
    ["sensitive-data.jwt-token", /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, "JWT-looking token detected."],
    ["sensitive-data.database-url-password", /[a-z]+:\/\/[^:\s]+:[^@\s]+@/g, "Database URL appears to include a password."],
    ["sensitive-data.api-key-pattern", /(sk_live_|ghp_|sk-ant-|xox[baprs]-|OPENAI_API_KEY)/g, "API key pattern detected."],
  ];

  for (const [ruleId, pattern, message] of patterns) {
    for (const match of source.matchAll(pattern)) {
      const raw = match[0] ?? "";
      const preview = redact(raw);
      if (config.secretPreviews.has(preview)) {
        continue;
      }
      findings.push(
        makeFinding({
          ruleId,
          message,
          filePath: file.displayPath,
          line: byteLine(source, match.index ?? 0),
          severity: "error",
          pillar: "sensitive-data",
          confidence: "high",
          remediation: "Remove the secret and load it from a secure runtime source.",
          metadata: { preview },
        }),
      );
    }
  }
}

function analyseTypeScriptRules(file: SourceFile, source: string, config: Config, findings: Finding[]): void {
  const blocks = functionBlocks(source);
  analyseBlocks(file, blocks, config, findings);
  analyseLineRules(file, source, config, findings);
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
    if (block.lineCount > 45 && cyclomatic > 10) {
      findings.push(blockFinding("design.god-function", `Function \`${block.name}\` is both long and complex.`, file, block, "warning", "design"));
    }
    if (isGenericName(block.name)) {
      findings.push(blockFinding("naming.generic-function", `Function \`${block.name}\` is too generic to explain intent.`, file, block, "advisory", "naming"));
    }
    if (block.isPublic && !hasDocCommentBefore(block.body)) {
      findings.push(blockFinding("docs.missing-public-doc", `Exported function \`${block.name}\` is missing a doc comment.`, file, block, "advisory", "documentation"));
    }
    if (block.isTest) {
      analyseTestBlock(file, block, findings);
    }
  }
}

function analyseTestBlock(file: SourceFile, block: FunctionBlock, findings: Finding[]): void {
  if (!/\b(expect\s*\(|assert\.|assert\s*\()/.test(block.body)) {
    findings.push(blockFinding("test-quality.no-assertions", `Test \`${block.name}\` does not appear to make an assertion.`, file, block, "warning", "test-quality"));
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
  const literalChecks: Array<[string, RegExp, string, Severity, Pillar]> = [
    ["security.eval-call", /\beval\s*\(/, "eval() executes dynamic code.", "error", "security"],
    ["security.process-exec", /\b(exec|spawn|execFile)\s*\(/, "Child-process execution is used; validate arguments are not user-controlled.", "warning", "security"],
    ["security.inner-html", /\.innerHTML\s*=/, "innerHTML assignment can introduce XSS.", "warning", "security"],
    ["security.document-write", /\bdocument\.write\s*\(/, "document.write() can introduce injection risks.", "warning", "security"],
    ["waste.console-log", /\bconsole\.(log|debug)\s*\(/, "console logging is committed in source.", "advisory", "waste"],
    ["waste.any-type", /:\s*any\b|as\s+any\b/, "any weakens TypeScript's type guarantees.", "warning", "waste"],
    ["modernisation.var-declaration", /\bvar\s+[A-Za-z_$]/, "var declaration should usually be let or const.", "advisory", "modernisation"],
  ];
  const variables = /\b(?:const|let|for\s*\(\s*const|for\s*\(\s*let)\s+([A-Za-z_$][A-Za-z0-9_$]*)/g;

  source.split(/\r?\n/).forEach((line, index) => {
    const lineNumber = index + 1;
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
    }
  });

  analyseUnreachable(file, source, findings);
}

function analyseClassRules(file: SourceFile, source: string, findings: Finding[]): void {
  for (const match of source.matchAll(/\bexport\s+(class|interface|type|enum|function)\s+([A-Za-z_$][A-Za-z0-9_$]*)/g)) {
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
  }

  const publicProperty = /\bpublic\s+[A-Za-z_$][A-Za-z0-9_$]*\s*[=:]/g;
  for (const match of source.matchAll(publicProperty)) {
    findings.push(finding("modernisation.public-property", "Public class property exposes representation; prefer readonly or accessors when invariants matter.", file, byteLine(source, match.index ?? 0), "advisory", "modernisation"));
  }
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
    if (previousTerminated && /\S/.test(trimmed) && !trimmed.startsWith("}")) {
      findings.push(finding("waste.unreachable-code", "Statement appears after a terminating statement.", file, index + 1, "warning", "waste"));
    }
    previousTerminated = /\b(return|throw|process\.exit)\b/.test(trimmed) && trimmed.endsWith(";");
  });
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
      isTest: /\b(test|it|describe)\s*\(/.test(lines.slice(start, index + 1).join("\n")) || match[1].startsWith("test"),
    });
  });
  return blocks;
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

function renderHtml(report: AnalysisReport): string {
  const findings = report.findings
    .slice(0, 250)
    .map((finding) => `<li><strong>${escapeHtml(finding.ruleId)}</strong> <code>${escapeHtml(finding.filePath)}</code>:${finding.line ?? 1}<br>${escapeHtml(finding.message)}</li>`)
    .join("\n");
  const pillars = report.score.pillars
    .map((pillar) => `<tr><td>${pillar.pillar}</td><td>${pillar.score.toFixed(1)}</td><td>${pillar.findings}</td></tr>`)
    .join("\n");
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>gruff-ts report</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 0; color: #172026; background: #f7f8fa; }
    header { background: #172026; color: white; padding: 24px; }
    main { max-width: 1120px; margin: 0 auto; padding: 24px; }
    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; }
    .stat, section { background: white; border: 1px solid #d9e0e7; border-radius: 8px; padding: 16px; }
    code { background: #eef2f6; padding: 1px 4px; border-radius: 4px; }
    li { margin: 0 0 12px; }
    table { width: 100%; border-collapse: collapse; }
    td, th { border-bottom: 1px solid #e5e9ef; padding: 8px; text-align: left; }
  </style>
</head>
<body>
  <header>
    <h1>gruff-ts</h1>
    <p>Score ${report.score.composite.toFixed(1)} (${report.score.grade}) · ${report.summary.total} findings · ${report.paths.analysedFiles} files</p>
  </header>
  <main>
    <div class="stats">
      <div class="stat"><strong>${report.summary.advisory}</strong><br>Advisory</div>
      <div class="stat"><strong>${report.summary.warning}</strong><br>Warning</div>
      <div class="stat"><strong>${report.summary.error}</strong><br>Error</div>
      <div class="stat"><strong>${report.paths.analysedFiles}</strong><br>Files</div>
    </div>
    <section>
      <h2>Pillars</h2>
      <table><thead><tr><th>Pillar</th><th>Score</th><th>Findings</th></tr></thead><tbody>${pillars}</tbody></table>
    </section>
    <section>
      <h2>Findings</h2>
      <ol>${findings}</ol>
    </section>
  </main>
</body>
</html>`;
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
        response.end(renderHtml(report).replace("<main>", `<main><section><strong>Dashboard scan</strong><br>Project: <code>${escapeHtml(root)}</code><br><a href="/">Change target</a></section>`));
      } catch (error) {
        response.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
        response.end(String(error));
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
    response.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
    response.end(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>gruff-ts dashboard</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 0; background: #f7f8fa; color: #172026; }
    header { background: #172026; color: white; padding: 20px 24px; }
    main { max-width: 960px; margin: 0 auto; padding: 24px; }
    form { display: grid; gap: 12px; background: white; border: 1px solid #d9e0e7; border-radius: 8px; padding: 16px; }
    input, button { font: inherit; padding: 10px; }
    button { background: #146c5f; color: white; border: 0; border-radius: 6px; cursor: pointer; }
  </style>
</head>
<body>
  <header><h1>gruff-ts dashboard</h1></header>
  <main>
    <form action="/scan" method="get">
      <label>Project root <input name="projectRoot" value="${escapeHtml(projectRoot)}"></label>
      <label>Path <input name="path" value="."></label>
      <button type="submit">Run scan</button>
    </form>
  </main>
</body>
</html>`);
  });
  server.listen(port, host, () => {
    console.log(`gruff-ts dashboard listening at http://${host}:${port}`);
  });
}

function buildProgram(): Command {
  const program = new Command();
  program.name("gruff-ts").version(VERSION);

  program
    .command("analyse")
    .description("Run gruff analysis.")
    .argument("[paths...]", "Files or directories to analyse.")
    .option("--config <path>", "Path to a gruff JSON config file.")
    .option("--no-config", "Skip auto-applying the default .gruff.json file for this run.")
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
    .option("--config <path>", "Path to a gruff JSON config file.")
    .option("--no-config", "Skip auto-applying the default .gruff.json file for this run.")
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
