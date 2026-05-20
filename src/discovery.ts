import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { basename, extname, isAbsolute, join, relative } from "node:path";
import type { AnalysisOptions, Config } from "./types.ts";

// `absolutePath` is what `node:fs` operates on; `displayPath` is the project-relative POSIX form
// embedded in findings and baselines. They must stay aligned — diverging them breaks fingerprint stability.
export interface SourceFile {
  absolutePath: string;
  displayPath: string;
  isScript: boolean;
}

// Mutable accumulator used during the walk. `ignoredPaths` is a Set because the walker may visit
// the same parent path through multiple roots; finalised into a sorted array on return.
interface SourceDiscovery {
  files: SourceFile[];
  missingPaths: string[];
  ignoredPaths: Set<string>;
}

// Public discovery result. `files` are sorted by display path and deduped; `ignoredPaths` is sorted
// so reports stay deterministic even when the underlying filesystem returns directory entries in arbitrary order.
export interface SourceDiscoveryResult {
  files: SourceFile[];
  missingPaths: string[];
  ignoredPaths: string[];
}

// A single line from a `.gitignore`. The combination of `anchored`, `directoryOnly`, and `hasSlash`
// reproduces git's documented matching semantics; missing any one of them yields wrong matches.
interface GitIgnoreRule {
  basePath: string;
  pattern: string;
  negated: boolean;
  directoryOnly: boolean;
  anchored: boolean;
  hasSlash: boolean;
}

// Public entry point. Reads from the filesystem and returns a sorted, deduped, deterministic
// result so finding ordering and report-path metadata remain stable across runs — this is part of
// the schema invariant that makes baseline matching reproducible.
export function discoverSources(projectRoot: string, options: AnalysisOptions, config: Config): SourceDiscoveryResult {
  const discovery: SourceDiscovery = { files: [], missingPaths: [], ignoredPaths: new Set<string>() };
  const inputs = options.paths.length > 0 ? options.paths : ["."];

  for (const input of inputs) {
    discoverSourceInput(projectRoot, input, options, config, discovery);
  }

  discovery.files.sort((left, right) => left.displayPath.localeCompare(right.displayPath));
  return { files: uniqueFiles(discovery.files), missingPaths: discovery.missingPaths, ignoredPaths: [...discovery.ignoredPaths].sort() };
}

// Resolves the input against `node:fs`. Missing inputs go into `missingPaths` so the CLI can
// report them as diagnostics rather than silently producing no findings — that distinction matters
// for CI runs and reads the .gitignore stack only when ignored paths are not requested.
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

// Single source of truth for which extensions count as scannable. Adding a new file kind here will
// expand the rule set's reach across an entire project — coordinate with rule descriptors before changing.
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

// The default-ignore list is part of the documented schema contract: callers can override with
// `--include-ignored`, but the list itself must not silently change between releases without notice.
function isDefaultIgnoredDir(path: string): boolean {
  const first = path.split("/")[0] ?? path;
  return [".git", ".hg", ".svn", ".idea", ".vscode", "build", "cache", "coverage", "dist", "generated", "node_modules", "target", "tmp", "vendor"].includes(first);
}

// Three independent ignore sources combined with OR. Order is for short-circuit only — semantically
// the union of (built-in defaults, parsed .gitignore stack, user config patterns) is what counts.
function isIgnoredDiscoveryPath(display: string, isDirectory: boolean, options: AnalysisOptions, config: Config, gitIgnoreRules: GitIgnoreRule[]): boolean {
  if (isDefaultIgnoredDiscoveryPath(display, isDirectory, options)) {
    return true;
  }
  if (isGitIgnoredDiscoveryPath(display, isDirectory, options, gitIgnoreRules)) {
    return true;
  }
  return config.ignoredPaths.some((pattern) => pathMatches(pattern, display));
}

// Default directory ignores only apply to directories, never to files — a file named "tmp" should
// still be scanned. `--include-ignored` opts out entirely.
function isDefaultIgnoredDiscoveryPath(display: string, isDirectory: boolean, options: AnalysisOptions): boolean {
  return !options.includeIgnored && isDirectory && isDefaultIgnoredDir(display);
}

// Mirrors git's own rule evaluation order; bypassed entirely by `--include-ignored` for callers
// that want to scan the full tree.
function isGitIgnoredDiscoveryPath(display: string, isDirectory: boolean, options: AnalysisOptions, gitIgnoreRules: GitIgnoreRule[]): boolean {
  return !options.includeIgnored && isGitIgnoredPath(gitIgnoreRules, display, isDirectory);
}

// Walks .gitignore files top-down from project root to the target directory so child rules can
// override parents — this must match git's documented inheritance order or the scan will diverge
// from `git status` on the same tree, and reads each `.gitignore` it encounters along the way.
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

// Reads one `.gitignore` and appends its rules to the inherited stack. Returns the original array
// untouched when no file exists so the walker can pass results around without spurious allocations.
function appendGitIgnoreRules(projectRoot: string, directory: string, inheritedRules: GitIgnoreRule[]): GitIgnoreRule[] {
  const ignoreFile = join(directory, ".gitignore");
  if (!existsSync(ignoreFile) || !statSync(ignoreFile).isFile()) {
    return inheritedRules;
  }

  const basePath = displayPath(projectRoot, directory);
  const parsedRules = parseGitIgnoreRules(readFileSync(ignoreFile, "utf8"), basePath === "." ? "" : basePath);
  return parsedRules.length > 0 ? [...inheritedRules, ...parsedRules] : inheritedRules;
}

// One rule per non-empty, non-comment line. Empty results are dropped here so downstream matchers
// never need to guard against undefined patterns.
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

// Extracts the four flags git applies per pattern: negation (`!`), directory-only (trailing `/`),
// path-scoped (leading `/` or contains `/`), and the cleaned pattern itself. Undefined return means
// the line was blank or a comment — callers must not treat it as a "match nothing" rule.
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

// `\#` and `\!` are the documented git escapes for literal `#` / `!` at line start; everything
// else stays as-is. Blank and comment lines return undefined so the caller can skip them cleanly.
function unescapedGitIgnoreLine(rawLine: string): string | undefined {
  const line = rawLine.trimEnd();
  if (line.length === 0 || line.startsWith("#")) {
    return undefined;
  }
  return line.startsWith("\\#") || line.startsWith("\\!") ? line.slice(1) : line;
}

// Strips leading and trailing slashes (those flags are already captured in `anchored` /
// `directoryOnly`) and collapses any internal `//` runs so the glob matcher sees canonical segments.
function normalizedGitIgnorePattern(line: string): string {
  return line
    .replace(/^\/+/, "")
    .replace(/\/+$/, "")
    .split("/")
    .filter((segment) => segment.length > 0)
    .join("/");
}

// Sequential evaluation, last match wins. This is the same algorithm git uses and is the reason
// negations later in a file (or in a child `.gitignore`) can reinstate previously ignored paths.
function isGitIgnoredPath(rules: GitIgnoreRule[], display: string, isDirectory: boolean): boolean {
  let isIgnored = false;
  for (const rule of rules) {
    if (gitIgnoreRuleMatches(rule, display, isDirectory)) {
      isIgnored = !rule.negated;
    }
  }
  return isIgnored;
}

// First rebases the display path against the rule's basePath (rules don't reach outside their
// owning directory), then dispatches to the directory-only or file matcher.
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

// Path-scoped patterns (with `/` or anchored) match against progressive sub-paths; bare patterns
// match any path segment. Mirrors git's distinction between `foo` (any segment) and `dir/foo`.
function gitIgnoreFileRuleMatches(rule: GitIgnoreRule, relativePath: string, isDirectory: boolean): boolean {
  if (isPathScopedGitIgnoreRule(rule)) {
    return gitIgnorePathCandidates(relativePath, isDirectory, true).some((candidate) => gitIgnoreGlobMatches(rule.pattern, candidate));
  }
  return relativePath.split("/").some((segment) => gitIgnoreGlobMatches(rule.pattern, segment));
}

// Like the file matcher but only considers directory segments — `node_modules/` must not match the
// leaf file name even if a file happened to be called `node_modules`.
function gitIgnoreDirectoryRuleMatches(rule: GitIgnoreRule, relativePath: string, isDirectory: boolean): boolean {
  if (isPathScopedGitIgnoreRule(rule)) {
    return gitIgnorePathCandidates(relativePath, isDirectory, false).some((candidate) => gitIgnoreGlobMatches(rule.pattern, candidate));
  }
  const segments = relativePath.split("/");
  const directorySegments = isDirectory ? segments : segments.slice(0, -1);
  return directorySegments.some((segment) => gitIgnoreGlobMatches(rule.pattern, segment));
}

// A rule is "path scoped" when it was anchored (leading `/`) or contained a `/` — both signal that
// the pattern should be matched against multi-segment sub-paths rather than individual names.
function isPathScopedGitIgnoreRule(rule: GitIgnoreRule): boolean {
  return rule.anchored || rule.hasSlash;
}

// Enumerates progressively longer prefixes of `relativePath` so a single-segment pattern can match
// at any nesting depth. `includeFilePath` controls whether the leaf segment is part of the prefix set
// — directory-only rules omit it because `dir/` must not match a file called `dir`.
function gitIgnorePathCandidates(relativePath: string, isDirectory: boolean, includeFilePath: boolean): string[] {
  const segments = relativePath.split("/");
  const limit = isDirectory || includeFilePath ? segments.length : segments.length - 1;
  const candidates: string[] = [];
  for (let index = 1; index <= limit; index += 1) {
    candidates.push(segments.slice(0, index).join("/"));
  }
  return candidates;
}

// Compiles the pattern on demand. Compilation is cheap relative to the surrounding walk so caching
// across calls is not worth the cache-invalidation footgun.
function gitIgnoreGlobMatches(pattern: string, candidatePath: string): boolean {
  return gitIgnoreGlobRegex(pattern).test(candidatePath);
}

// Translates a git glob into a JS RegExp. `**`, `*`, and `?` get their git-flavoured semantics:
// `*` matches a single segment (`[^/]*`), `**` can cross segment boundaries, and `?` matches one
// non-slash character.
function gitIgnoreGlobRegex(pattern: string): RegExp {
  let source = "^";
  for (let index = 0; index < pattern.length; index += 1) {
    const fragment = gitIgnoreGlobFragment(pattern, index);
    source += fragment.source;
    index += fragment.skip;
  }
  return new RegExp(`${source}$`);
}

// One pattern character → one regex fragment. `*` dispatches to the star helper because `**` and
// `**/ ` need special handling; everything else falls through to literal escape via `escapeRegex`.
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

// Three star modes from the git spec: single `*` is segment-local, `**/` matches zero or more
// segments, and trailing `**` matches anything. The `skip` return lets the caller advance past the
// extra characters consumed.
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

// Strips the basePath prefix so a rule from `subdir/.gitignore` is matched against paths relative
// to `subdir`. Returns undefined when `display` is outside the base — those rules cannot apply.
function pathRelativeToBase(basePath: string, display: string): string | undefined {
  if (basePath.length === 0) {
    return display === "." ? "" : display;
  }
  if (display === basePath) {
    return "";
  }
  return display.startsWith(`${basePath}/`) ? display.slice(basePath.length + 1) : undefined;
}

// Guards against `..`-traversal and absolute-path inputs that point outside the requested root.
// Required so a malformed CLI path cannot drag the .gitignore walker into the user's home directory.
function isInsideProject(projectRoot: string, path: string): boolean {
  const relativePath = relative(projectRoot, path).replaceAll("\\", "/");
  return relativePath === "" || (!relativePath.startsWith("../") && relativePath !== ".." && !isAbsolute(relativePath));
}

// User config ignore patterns. Simpler than gitignore: literal, `prefix/**`, glob with `*` / `**`,
// or plain prefix. No negation — config ignores are additive on top of gitignore.
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

// Same absolute path can be reached through multiple CLI inputs. First-seen wins because that
// preserves the deterministic sort imposed by `discoverSources` and keeps fingerprint stability.
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

// Anchors a relative CLI argument against the project root; absolute paths pass through unchanged.
export function absolutize(projectRoot: string, path: string): string {
  return isAbsolute(path) ? path : join(projectRoot, path);
}

// Project-relative form with forward slashes — the report contract uses POSIX-style display paths
// on every platform. "" collapses to "." so the root has a stable label in findings.
export function displayPath(projectRoot: string, path: string): string {
  const relativePath = relative(projectRoot, path).replaceAll("\\", "/");
  return relativePath === "" ? "." : relativePath;
}

// Escapes the standard regex metacharacters so untrusted patterns can be embedded literally.
function escapeRegex(rawText: string): string {
  return rawText.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
