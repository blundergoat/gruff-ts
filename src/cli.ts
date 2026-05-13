#!/usr/bin/env node
import { Command } from "commander";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { createServer } from "node:http";
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { argv, chdir, cwd } from "node:process";
import { basename, dirname as dirnamePath, extname, isAbsolute, join, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const VERSION = "0.1.0-dev";
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
