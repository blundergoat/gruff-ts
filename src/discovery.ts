import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { basename, extname, isAbsolute, join, relative } from "node:path";
import type { AnalysisOptions, Config } from "./types.ts";

export interface SourceFile {
  absolutePath: string;
  displayPath: string;
  isScript: boolean;
}

interface SourceDiscovery {
  files: SourceFile[];
  missingPaths: string[];
  ignoredPaths: Set<string>;
}

export interface SourceDiscoveryResult {
  files: SourceFile[];
  missingPaths: string[];
  ignoredPaths: string[];
}

interface GitIgnoreRule {
  basePath: string;
  pattern: string;
  negated: boolean;
  directoryOnly: boolean;
  anchored: boolean;
  hasSlash: boolean;
}

export function discoverSources(projectRoot: string, options: AnalysisOptions, config: Config): SourceDiscoveryResult {
  const discovery: SourceDiscovery = { files: [], missingPaths: [], ignoredPaths: new Set<string>() };
  const inputs = options.paths.length > 0 ? options.paths : ["."];

  for (const input of inputs) {
    discoverSourceInput(projectRoot, input, options, config, discovery);
  }

  discovery.files.sort((left, right) => left.displayPath.localeCompare(right.displayPath));
  return { files: uniqueFiles(discovery.files), missingPaths: discovery.missingPaths, ignoredPaths: [...discovery.ignoredPaths].sort() };
}

function discoverSourceInput(projectRoot: string, input: string, options: AnalysisOptions, config: Config, discovery: SourceDiscovery): void {
  const absolute = absolutize(projectRoot, input);
  if (!existsSync(absolute)) {
    discovery.missingPaths.push(input);
    return;
  }
  const stats = statSync(absolute);
  if (stats.isFile()) {
    pushSourceFile(projectRoot, absolute, discovery.files);
    return;
  }
  const gitIgnoreRules = options.includeIgnored ? [] : gitIgnoreRulesForDirectory(projectRoot, absolute);
  walk(projectRoot, absolute, options, config, discovery.ignoredPaths, discovery.files, gitIgnoreRules);
}

function walk(
  projectRoot: string,
  directory: string,
  options: AnalysisOptions,
  config: Config,
  ignoredPaths: Set<string>,
  files: SourceFile[],
  gitIgnoreRules: GitIgnoreRule[],
): void {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const absolute = join(directory, entry.name);
    const display = displayPath(projectRoot, absolute);
    if (entry.isDirectory() || entry.isFile()) {
      if (isIgnoredDiscoveryPath(display, entry.isDirectory(), options, config, gitIgnoreRules)) {
        ignoredPaths.add(display);
        continue;
      }
    }
    if (entry.isDirectory()) {
      walk(projectRoot, absolute, options, config, ignoredPaths, files, options.includeIgnored ? gitIgnoreRules : appendGitIgnoreRules(projectRoot, absolute, gitIgnoreRules));
    } else if (entry.isFile()) {
      pushSourceFile(projectRoot, absolute, files);
    }
  }
}

function pushSourceFile(projectRoot: string, absolutePath: string, files: SourceFile[]): void {
  const extension = extname(absolutePath).slice(1).toLowerCase();
  const name = basename(absolutePath);
  const isScript = ["ts", "tsx", "js", "jsx", "mjs", "cjs"].includes(extension);
  const isText =
    ["conf", "config", "env", "ini", "json", "toml", "xml", "yaml", "yml"].includes(extension) ||
    name.startsWith(".env");
  if (isScript || isText) {
    files.push({ absolutePath, displayPath: displayPath(projectRoot, absolutePath), isScript });
  }
}

function isDefaultIgnoredDir(path: string): boolean {
  const first = path.split("/")[0] ?? path;
  return [".git", ".hg", ".svn", ".idea", ".vscode", "build", "cache", "coverage", "dist", "generated", "node_modules", "target", "tmp", "vendor"].includes(first);
}

function isIgnoredDiscoveryPath(display: string, isDirectory: boolean, options: AnalysisOptions, config: Config, gitIgnoreRules: GitIgnoreRule[]): boolean {
  if (isDefaultIgnoredDiscoveryPath(display, isDirectory, options)) {
    return true;
  }
  if (isGitIgnoredDiscoveryPath(display, isDirectory, options, gitIgnoreRules)) {
    return true;
  }
  return config.ignoredPaths.some((pattern) => pathMatches(pattern, display));
}

function isDefaultIgnoredDiscoveryPath(display: string, isDirectory: boolean, options: AnalysisOptions): boolean {
  return !options.includeIgnored && isDirectory && isDefaultIgnoredDir(display);
}

function isGitIgnoredDiscoveryPath(display: string, isDirectory: boolean, options: AnalysisOptions, gitIgnoreRules: GitIgnoreRule[]): boolean {
  return !options.includeIgnored && isGitIgnoredPath(gitIgnoreRules, display, isDirectory);
}

function gitIgnoreRulesForDirectory(projectRoot: string, directory: string): GitIgnoreRule[] {
  if (!isInsideProject(projectRoot, directory)) {
    return [];
  }

  const relativeDirectory = displayPath(projectRoot, directory);
  const segments = relativeDirectory === "." ? [] : relativeDirectory.split("/");
  let current = projectRoot;
  let rules = appendGitIgnoreRules(projectRoot, current, []);
  for (const segment of segments) {
    current = join(current, segment);
    rules = appendGitIgnoreRules(projectRoot, current, rules);
  }
  return rules;
}

function appendGitIgnoreRules(projectRoot: string, directory: string, inheritedRules: GitIgnoreRule[]): GitIgnoreRule[] {
  const ignoreFile = join(directory, ".gitignore");
  if (!existsSync(ignoreFile) || !statSync(ignoreFile).isFile()) {
    return inheritedRules;
  }

  const basePath = displayPath(projectRoot, directory);
  const parsedRules = parseGitIgnoreRules(readFileSync(ignoreFile, "utf8"), basePath === "." ? "" : basePath);
  return parsedRules.length > 0 ? [...inheritedRules, ...parsedRules] : inheritedRules;
}

function parseGitIgnoreRules(source: string, basePath: string): GitIgnoreRule[] {
  const rules: GitIgnoreRule[] = [];
  for (const rawLine of source.replace(/\r\n/g, "\n").split("\n")) {
    const rule = parseGitIgnoreRule(rawLine, basePath);
    if (rule) {
      rules.push(rule);
    }
  }
  return rules;
}

function parseGitIgnoreRule(rawLine: string, basePath: string): GitIgnoreRule | undefined {
  const initial = unescapedGitIgnoreLine(rawLine);
  if (!initial) {
    return undefined;
  }
  const negated = initial.startsWith("!");
  const withoutNegation = negated ? initial.slice(1) : initial;
  if (withoutNegation.length === 0) {
    return undefined;
  }
  const anchored = withoutNegation.startsWith("/");
  const directoryOnly = withoutNegation.endsWith("/");
  const pattern = normalizedGitIgnorePattern(withoutNegation);
  if (pattern.length === 0) {
    return undefined;
  }
  return { basePath, pattern, negated, directoryOnly, anchored, hasSlash: pattern.includes("/") };
}

function unescapedGitIgnoreLine(rawLine: string): string | undefined {
  const line = rawLine.trimEnd();
  if (line.length === 0 || line.startsWith("#")) {
    return undefined;
  }
  return line.startsWith("\\#") || line.startsWith("\\!") ? line.slice(1) : line;
}

function normalizedGitIgnorePattern(line: string): string {
  return line
    .replace(/^\/+/, "")
    .replace(/\/+$/, "")
    .split("/")
    .filter((segment) => segment.length > 0)
    .join("/");
}

function isGitIgnoredPath(rules: GitIgnoreRule[], display: string, isDirectory: boolean): boolean {
  let isIgnored = false;
  for (const rule of rules) {
    if (gitIgnoreRuleMatches(rule, display, isDirectory)) {
      isIgnored = !rule.negated;
    }
  }
  return isIgnored;
}

function gitIgnoreRuleMatches(rule: GitIgnoreRule, display: string, isDirectory: boolean): boolean {
  const relativePath = pathRelativeToBase(rule.basePath, display);
  if (relativePath === undefined || relativePath.length === 0) {
    return false;
  }

  if (rule.directoryOnly) {
    return gitIgnoreDirectoryRuleMatches(rule, relativePath, isDirectory);
  }
  return gitIgnoreFileRuleMatches(rule, relativePath, isDirectory);
}

function gitIgnoreFileRuleMatches(rule: GitIgnoreRule, relativePath: string, isDirectory: boolean): boolean {
  if (isPathScopedGitIgnoreRule(rule)) {
    return gitIgnorePathCandidates(relativePath, isDirectory, true).some((candidate) => gitIgnoreGlobMatches(rule.pattern, candidate));
  }
  return relativePath.split("/").some((segment) => gitIgnoreGlobMatches(rule.pattern, segment));
}

function gitIgnoreDirectoryRuleMatches(rule: GitIgnoreRule, relativePath: string, isDirectory: boolean): boolean {
  if (isPathScopedGitIgnoreRule(rule)) {
    return gitIgnorePathCandidates(relativePath, isDirectory, false).some((candidate) => gitIgnoreGlobMatches(rule.pattern, candidate));
  }
  const segments = relativePath.split("/");
  const directorySegments = isDirectory ? segments : segments.slice(0, -1);
  return directorySegments.some((segment) => gitIgnoreGlobMatches(rule.pattern, segment));
}

function isPathScopedGitIgnoreRule(rule: GitIgnoreRule): boolean {
  return rule.anchored || rule.hasSlash;
}

function gitIgnorePathCandidates(relativePath: string, isDirectory: boolean, includeFilePath: boolean): string[] {
  const segments = relativePath.split("/");
  const limit = isDirectory || includeFilePath ? segments.length : segments.length - 1;
  const candidates: string[] = [];
  for (let index = 1; index <= limit; index += 1) {
    candidates.push(segments.slice(0, index).join("/"));
  }
  return candidates;
}

function gitIgnoreGlobMatches(pattern: string, value: string): boolean {
  return gitIgnoreGlobRegex(pattern).test(value);
}

function gitIgnoreGlobRegex(pattern: string): RegExp {
  let source = "^";
  for (let index = 0; index < pattern.length; index += 1) {
    const fragment = gitIgnoreGlobFragment(pattern, index);
    source += fragment.source;
    index += fragment.skip;
  }
  return new RegExp(`${source}$`);
}

function gitIgnoreGlobFragment(pattern: string, index: number): { source: string; skip: number } {
  const character = pattern[index] ?? "";
  if (character === "*") {
    return gitIgnoreStarFragment(pattern, index);
  }
  if (character === "?") {
    return { source: "[^/]", skip: 0 };
  }
  return { source: escapeRegex(character), skip: 0 };
}

function gitIgnoreStarFragment(pattern: string, index: number): { source: string; skip: number } {
  const next = pattern[index + 1];
  const afterNext = pattern[index + 2];
  if (next !== "*") {
    return { source: "[^/]*", skip: 0 };
  }
  if (afterNext === "/") {
    return { source: "(?:.*/)?", skip: 2 };
  }
  return { source: ".*", skip: 1 };
}

function pathRelativeToBase(basePath: string, display: string): string | undefined {
  if (basePath.length === 0) {
    return display === "." ? "" : display;
  }
  if (display === basePath) {
    return "";
  }
  return display.startsWith(`${basePath}/`) ? display.slice(basePath.length + 1) : undefined;
}

function isInsideProject(projectRoot: string, path: string): boolean {
  const relativePath = relative(projectRoot, path).replaceAll("\\", "/");
  return relativePath === "" || (!relativePath.startsWith("../") && relativePath !== ".." && !isAbsolute(relativePath));
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

export function absolutize(projectRoot: string, path: string): string {
  return isAbsolute(path) ? path : join(projectRoot, path);
}

export function displayPath(projectRoot: string, path: string): string {
  const relativePath = relative(projectRoot, path).replaceAll("\\", "/");
  return relativePath === "" ? "." : relativePath;
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
