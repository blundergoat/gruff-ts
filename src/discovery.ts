// Filesystem discovery, ignore-policy matching, and display-path normalization for deterministic scans.
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { basename, dirname, extname, isAbsolute, join, relative } from "node:path";
import type { AnalysisOptions, Config, IgnoreSource, ScanSurfaceNote, SkippedPath } from "./types.ts";

// `absolutePath` is what `node:fs` operates on; `displayPath` is project-relative inside the run
// root and absolute outside it. They must stay aligned - diverging them breaks fingerprint stability.
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
  skipped: Map<string, SkippedPath>;
}

// Public discovery result. `files` are sorted by display path and deduped; `ignoredPaths` (the
// back-compatible string[] of excluded paths) and `skipped` (the same paths enriched with ignore
// source + matched pattern) are sorted so reports stay deterministic even when the underlying
// filesystem returns directory entries in arbitrary order. `notes` carries one entry per requested
// input that exists but contributed zero analysable files, so an all-skipped scan is never a
// silent zero-finding success.
export interface SourceDiscoveryResult {
  files: SourceFile[];
  missingPaths: string[];
  ignoredPaths: string[];
  skipped: SkippedPath[];
  notes: ScanSurfaceNote[];
}

// A single line from a `.gitignore`. The combination of `isAnchored`, `isDirectoryOnly`, and `hasSlash`
// reproduces git's documented matching semantics; missing any one of them yields wrong matches.
interface GitIgnoreRule {
  basePath: string;
  pattern: string;
  isNegated: boolean;
  isDirectoryOnly: boolean;
  isAnchored: boolean;
  hasSlash: boolean;
}

// Reads the filesystem, resolving options' paths against projectRoot and using config and options to decide what to skip.
// With no paths, scans projectRoot. Deduplicates files by absolute path and sorts files and skips to preserve stable report order.
// Returns files, missing paths, skipped paths and reasons, and notes for inputs that add no files or missing paths.
export function discoverSources(projectRoot: string, options: AnalysisOptions, config: Config): SourceDiscoveryResult {
  const discovery: SourceDiscovery = { files: [], missingPaths: [], skipped: new Map<string, SkippedPath>() };
  const inputs = options.paths.length > 0 ? options.paths : ["."];
  const notes: ScanSurfaceNote[] = [];

  for (const input of inputs) {
    const filesBefore = discovery.files.length;
    const missingBefore = discovery.missingPaths.length;
    const skippedBefore = discovery.skipped.size;
    discoverSourceInput(projectRoot, input, options, config, discovery);
    if (discovery.missingPaths.length === missingBefore && discovery.files.length === filesBefore) {
      notes.push(zeroFileInputNote(input, discovery.skipped.size - skippedBefore));
    }
  }

  discovery.files.sort((left, right) => left.displayPath.localeCompare(right.displayPath));
  const skipped = [...discovery.skipped.values()].sort((left, right) => left.path.localeCompare(right.path));
  return { files: uniqueFiles(discovery.files), missingPaths: discovery.missingPaths, ignoredPaths: skipped.map((entry) => entry.path), skipped, notes };
}

// Returns an informational note for an existing input that contributed no analysable files, so zero findings cannot be mistaken for a clean scan.
// A positive count reports newly recorded skips. A zero count reports no analysable source files.
function zeroFileInputNote(input: string, skippedCount: number): ScanSurfaceNote {
  const cause = skippedCount > 0
    ? `${skippedCount} path(s) under it were excluded by ignore rules`
    : "it contains no analysable source files";
  return {
    noteType: "no-analysable-files",
    path: input,
    message: `Requested path '${input}' was not analysed: ${cause}. 0 findings here does not mean the path is clean.`,
  };
}

/**
 * Collects files, missing inputs, and exclusion reasons for one requested path.
 * Explicit files honour config and VCS exclusions and bypass Git ignore rules and all other default exclusions.
 * If no exclusion matches, an explicit file outside the scan allowlist adds no entry.
 *
 * @param projectRoot - base directory for resolving input and formatting report paths
 * @param input - requested file or directory path
 * @param options - scan options controlling inclusion of ignored paths
 * @param config - user configuration supplying explicit ignore patterns
 * @param discovery - accumulator mutated with files, missingPaths, and skipped entries
 * @returns Nothing. Records discovered files, missing paths, or exclusions in discovery.
 */
function discoverSourceInput(projectRoot: string, input: string, options: AnalysisOptions, config: Config, discovery: SourceDiscovery): void {
  const absolute = absolutize(projectRoot, input);
  if (!existsSync(absolute)) {
    discovery.missingPaths.push(input);
    return;
  }
  const stats = statSync(absolute);
  if (stats.isFile()) {
    const display = displayPath(projectRoot, absolute);
    const match = classifyIgnore({
      projectRoot,
      absolute,
      display,
      isDirectory: false,
      options,
      config,
      gitIgnoreRules: [],
      isExplicitFile: true,
    });
    if (match) {
      discovery.skipped.set(display, { path: display, source: match.source, pattern: match.pattern });
      return;
    }
    pushSourceFile(projectRoot, absolute, discovery.files);
    return;
  }
  const gitIgnoreRules = options.shouldIncludeIgnored ? [] : gitIgnoreRulesForDirectory(projectRoot, absolute);
  walk(projectRoot, absolute, options, config, discovery.skipped, discovery.files, gitIgnoreRules);
}

/**
 * Reads directory entries depth first to collect supported files and prunes ignored subtrees to avoid reading their contents.
 *
 * @param projectRoot - base directory for report paths and ignore-rule ownership
 * @param directory - directory whose entries are scanned
 * @param options - controls whether to bypass Git rules and non-VCS defaults
 * @param config - user configuration supplying explicit ignore patterns
 * @param skipped - map mutated with excluded paths and their reasons
 * @param files - array mutated with admitted source records
 * @param gitIgnoreRules - inherited rules extended for each child directory unless ignored paths are included
 * @returns Nothing. Adds eligible source records to files and records exclusions in skipped.
 */
function walk(
  projectRoot: string,
  directory: string,
  options: AnalysisOptions,
  config: Config,
  skipped: Map<string, SkippedPath>,
  files: SourceFile[],
  gitIgnoreRules: GitIgnoreRule[],
): void {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const absolute = join(directory, entry.name);
    const display = displayPath(projectRoot, absolute);
    if (entry.isDirectory() || entry.isFile()) {
      const match = classifyIgnore({
        projectRoot,
        absolute,
        display,
        isDirectory: entry.isDirectory(),
        options,
        config,
        gitIgnoreRules,
        isExplicitFile: false,
      });
      if (match) {
        // If the minified-file pattern matched, record a skip only for paths whose file type gruff-ts would otherwise scan.
        if (match.pattern !== MINIFIED_FILE_PATTERN || isScannableSourceFile(absolute)) {
          skipped.set(display, { path: display, source: match.source, pattern: match.pattern });
        }
        continue;
      }
    }
    if (entry.isDirectory()) {
      walk(projectRoot, absolute, options, config, skipped, files, options.shouldIncludeIgnored ? gitIgnoreRules : appendGitIgnoreRules(projectRoot, absolute, gitIgnoreRules));
    } else if (entry.isFile()) {
      pushSourceFile(projectRoot, absolute, files);
    }
  }
}

/** Extensions parsed as code. Widening this reaches every rule that inspects script syntax. */
export const SCRIPT_FILE_EXTENSIONS: readonly string[] = ["ts", "tsx", "js", "jsx", "mjs", "cjs"];

/** Extensions read as config or text assets, which only the text-oriented rules inspect. */
export const TEXT_FILE_EXTENSIONS: readonly string[] = ["conf", "config", "env", "ini", "json", "toml", "xml", "yaml", "yml"];

/** Extensionless credential files that stay scannable without admitting every dotfile. */
export const EXACT_SECRET_TEXT_FILES: readonly string[] = [".npmrc", ".pypirc", ".envrc", ".netrc"];

/**
 * Adds a supported path to the scan list; release-truth.test.ts pins the allowlists defining the documented scan surface.
 *
 * @param projectRoot - base directory for formatting the file's report path
 * @param absolutePath - candidate file path checked against the script and text allowlists
 * @param files - accumulator receiving a source record for supported files; unsupported paths leave it unchanged
 * @returns Nothing. Adds the source record for a supported path to files.
 */
function pushSourceFile(projectRoot: string, absolutePath: string, files: SourceFile[]): void {
  if (isScannableSourceFile(absolutePath)) {
    files.push({ absolutePath, displayPath: displayPath(projectRoot, absolutePath), isScript: isScriptFile(absolutePath) });
  }
}

// Reports whether pushSourceFile would admit a path, so the walk lists a skipped minified file only when it is scannable.
function isScannableSourceFile(absolutePath: string): boolean {
  const name = basename(absolutePath);
  const isText = TEXT_FILE_EXTENSIONS.includes(extname(absolutePath).slice(1).toLowerCase()) || name.startsWith(".env") || EXACT_SECRET_TEXT_FILES.includes(name);
  return isScriptFile(absolutePath) || isText;
}

// Reports whether a path's extension is parsed as code.
function isScriptFile(absolutePath: string): boolean {
  return SCRIPT_FILE_EXTENSIONS.includes(extname(absolutePath).slice(1).toLowerCase());
}

const VCS_DIRECTORIES = [".git", ".hg", ".svn"] as const;
const FALLBACK_DIRECTORIES = [".fleet", ".idea", ".vscode", "build", "coverage", "node_modules"] as const;

// Directories holding third-party copies, and `dist`, the one build-output name section 7 adds; `build` and `coverage`
// stay fallback-only. Like the fallback directories they match at any depth, but they are skipped even under a
// governing .gitignore and compared over ASCII case, because a committed copy is still someone else's code
// (FAMILY-CONTRACT.md section 7, amended by precision-floor M04).
const THIRD_PARTY_DIRECTORIES: readonly string[] = ["bower_components", "dist", "third-party", "third_party", "vendor", "vendors"];

/** Pattern recorded for a minified file such as `jquery.min.js`, which section 7 skips as generated. */
export const MINIFIED_FILE_PATTERN = "*.min.*";

// Returns the path component with only ASCII capitals lowercased so directory and filename checks use consistent case folding.
function asciiLower(pathComponent: string): string {
  return pathComponent.replace(/[A-Z]/gu, (character) => character.toLowerCase());
}

// Returns the lowercase outermost third-party or build-output directory on display, or undefined when this policy supplies no exclusion.
// isDirectory controls whether to check the final component, so a/Vendor/x.ts gives vendor and the filename dist alone gives no match.
function matchedThirdPartyDirectory(display: string, isDirectory: boolean): string | undefined {
  const components = display.split("/");
  const directories = isDirectory ? components : components.slice(0, -1);
  return directories.map(asciiLower).find((component) => THIRD_PARTY_DIRECTORIES.includes(component));
}

// Reports whether the base name has an ASCII case-insensitive .min. marker directly before its final extension.
// For example, jquery.MIN.js matches, while app.min.js.map and admin.mini.js do not.
function isMinifiedName(name: string): boolean {
  return /\.min\.[^.]+$/u.test(asciiLower(name));
}

// The matched ignore source and the exact pattern that excluded a path. Returned by `classifyIgnore`.
interface IgnoreMatch {
  source: IgnoreSource;
  pattern: string;
}

// Bundles one ignore decision so adding policy context does not expand the helper's parameter list.
interface IgnoreClassificationInput {
  projectRoot: string;
  absolute: string;
  display: string;
  isDirectory: boolean;
  options: AnalysisOptions;
  config: Config;
  gitIgnoreRules: GitIgnoreRule[];
  isExplicitFile: boolean;
}

// Classifies the path in input using its location, kind, scan options, config and Git ignore rules.
// Returns the first ignore source and pattern, or undefined to keep the path eligible. Config and VCS exclusions always apply.
// Explicit files and --include-ignored bypass Git and the remaining default exclusions after those checks.
function classifyIgnore(input: IgnoreClassificationInput): IgnoreMatch | undefined {
  const { projectRoot, absolute, display, isDirectory, options, config, gitIgnoreRules, isExplicitFile } = input;
  const configPattern = config.ignoredPaths.find((pattern) => pathMatches(pattern, display));
  if (configPattern !== undefined) {
    return { source: "config", pattern: configPattern };
  }
  const vcsComponent = matchedDirectoryComponent(display, VCS_DIRECTORIES);
  if (vcsComponent !== undefined) {
    return { source: "default", pattern: `${vcsComponent}/` };
  }
  if (options.shouldIncludeIgnored || isExplicitFile) {
    return undefined;
  }
  const rule = matchedGitIgnoreRule(gitIgnoreRules, display, isDirectory);
  if (rule) {
    return { source: "gitignore", pattern: rule.pattern };
  }
  // When Git has no match, a third-party directory takes priority over a minified file name in the reported reason.
  const thirdPartyDirectory = matchedThirdPartyDirectory(display, isDirectory);
  if (thirdPartyDirectory !== undefined) {
    return { source: "default", pattern: `${thirdPartyDirectory}/` };
  }
  if (!isDirectory && isMinifiedName(basename(display))) {
    return { source: "default", pattern: MINIFIED_FILE_PATTERN };
  }
  const fallbackComponent = matchedDirectoryComponent(display, FALLBACK_DIRECTORIES);
  if (fallbackComponent !== undefined && fallbackAppliesAt(projectRoot, absolute)) {
    return { source: "default", pattern: `${fallbackComponent}/` };
  }
  return undefined;
}

// Ignore classification for a single path, sharing the exact engine discovery uses. Powers
// `check-ignore`: O(1) per path, no analysis. `options.shouldIncludeIgnored` suppresses
// default/gitignore matches but never config `paths.ignore`.
export interface PathIgnoreClassification {
  path: string;
  isIgnored: boolean;
  source?: IgnoreSource;
  pattern?: string;
}

/**
 * Reports the shared ignore decision for one path without scanning its contents.
 * Existing regular files bypass Git and default exclusions, while config and VCS exclusions still apply.
 *
 * @param projectRoot - base directory for resolving input and formatting the reported path
 * @param input - path to classify. Missing paths are treated as non-directories and receive no explicit-file bypass
 * @param options - controls whether ignored paths are included
 * @param config - user configuration supplying explicit ignore patterns
 * @returns display path and isIgnored; ignored paths also include the exclusion source and pattern
 */
export function classifyPathIgnore(projectRoot: string, input: string, options: AnalysisOptions, config: Config): PathIgnoreClassification {
  const absolute = absolutize(projectRoot, input);
  const display = displayPath(projectRoot, absolute);
  const exists = existsSync(absolute);
  const isDirectory = exists && statSync(absolute).isDirectory();
  const isExplicitFile = exists && statSync(absolute).isFile();
  const gitIgnoreRules = options.shouldIncludeIgnored || isExplicitFile
    ? []
    : gitIgnoreRulesForDirectory(projectRoot, dirname(absolute));
  const match = classifyIgnore({
    projectRoot,
    absolute,
    display,
    isDirectory,
    options,
    config,
    gitIgnoreRules,
    isExplicitFile,
  });
  return match ? { path: display, isIgnored: true, source: match.source, pattern: match.pattern } : { path: display, isIgnored: false };
}

// Finds the first path component owned by one directory-policy set.
// Returns undefined when no component belongs to candidates, so this directory policy contributes no exclusion.
function matchedDirectoryComponent(path: string, candidates: readonly string[]): string | undefined {
  return path.split("/").find((component) => candidates.includes(component));
}

// Reports whether fallback exclusions apply to absolute: outside projectRoot they always apply.
// Inside projectRoot they apply only if no regular .gitignore exists from the root through the candidate's parent.
function fallbackAppliesAt(projectRoot: string, absolute: string): boolean {
  if (!isInsideProject(projectRoot, absolute)) {
    return true;
  }
  const relativeParent = relative(projectRoot, dirname(absolute)).replaceAll("\\", "/");
  const segments = relativeParent === "" ? [] : relativeParent.split("/");
  let current = projectRoot;
  if (isGitIgnoreFile(join(current, ".gitignore"))) {
    return false;
  }
  for (const segment of segments) {
    current = join(current, segment);
    if (isGitIgnoreFile(join(current, ".gitignore"))) {
      return false;
    }
  }
  return true;
}

// Distinguishes a regular .gitignore file from a missing path or directory.
function isGitIgnoreFile(path: string): boolean {
  return existsSync(path) && statSync(path).isFile();
}

// Returns .gitignore rules from projectRoot through directory in parent-before-child order, so later child rules can override parents.
// Reads every regular .gitignore along the chain. Returns an empty list outside projectRoot or when no file contributes usable rules.
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

// Reads directory's .gitignore with rule paths based at projectRoot and returns its rules after inheritedRules.
// Returns inheritedRules unchanged when .gitignore is missing, is not a regular file, or has no usable rules.
// Otherwise returns a new array, preserving the caller's inherited stack.
function appendGitIgnoreRules(projectRoot: string, directory: string, inheritedRules: GitIgnoreRule[]): GitIgnoreRule[] {
  const ignoreFile = join(directory, ".gitignore");
  if (!existsSync(ignoreFile) || !statSync(ignoreFile).isFile()) {
    return inheritedRules;
  }

  const basePath = displayPath(projectRoot, directory);
  const parsedRules = parseGitIgnoreRules(readFileSync(ignoreFile, "utf8"), basePath === "." ? "" : basePath);
  return parsedRules.length > 0 ? [...inheritedRules, ...parsedRules] : inheritedRules;
}

// Parses .gitignore source into ordered rules owned by basePath; an empty basePath means the project root.
// Drops comments, blanks, and marker-only lines; returns an empty array when no usable rules remain.
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

// Parses rawLine from the .gitignore owned by basePath into its normalized pattern and matching flags.
// Returns undefined for comments, blank lines, or lines whose negation or slash markers leave no pattern.
// An empty basePath attaches the rule to the project root.
function parseGitIgnoreRule(rawLine: string, basePath: string): GitIgnoreRule | undefined {
  const initial = unescapedGitIgnoreLine(rawLine);
  if (!initial) {
    return undefined;
  }
  const isNegated = initial.startsWith("!");
  const withoutNegation = isNegated ? initial.slice(1) : initial;
  if (withoutNegation.length === 0) {
    return undefined;
  }
  const isAnchored = withoutNegation.startsWith("/");
  const isDirectoryOnly = withoutNegation.endsWith("/");
  const pattern = normalizedGitIgnorePattern(withoutNegation);
  if (pattern.length === 0) {
    return undefined;
  }
  return { basePath, pattern, isNegated, isDirectoryOnly, isAnchored, hasSlash: pattern.includes("/") };
}

// Blank and comment lines return undefined so the caller can skip them cleanly. Trailing spaces are
// ignored only when they are not escaped, matching gitignore's literal-space escape.
function unescapedGitIgnoreLine(rawLine: string): string | undefined {
  const line = trimUnescapedTrailingSpaces(rawLine);
  if (line.length === 0 || line.startsWith("#")) {
    return undefined;
  }
  return line;
}

// Returns the raw .gitignore line without unescaped trailing spaces because Git treats them as padding.
// A backslash-escaped trailing space stays part of the pattern.
function trimUnescapedTrailingSpaces(rawLine: string): string {
  let end = rawLine.length;
  while (end > 0 && rawLine[end - 1] === " " && !isEscapedAt(rawLine, end - 1)) {
    end -= 1;
  }
  return rawLine.slice(0, end);
}

// True when the character at index in source has an odd number of backslashes immediately before it.
// Even runs cancel out because a pair represents a literal backslash and leaves the next character unescaped.
function isEscapedAt(source: string, index: number): boolean {
  let slashCount = 0;
  for (let cursor = index - 1; cursor >= 0 && source[cursor] === "\\"; cursor -= 1) {
    slashCount += 1;
  }
  return slashCount % 2 === 1;
}

// Returns the canonical matcher pattern for a gitignore line after its anchor and directory-only flags have been captured.
// Removes edge slashes and empty internal segments; an all-slash line returns an empty string so the caller drops the rule.
function normalizedGitIgnorePattern(line: string): string {
  return line
    .replace(/^\/+/, "")
    .replace(/\/+$/, "")
    .split("/")
    .filter((segment) => segment.length > 0)
    .join("/");
}

// Evaluates rules in inherited file order against display; isDirectory identifies the candidate's kind.
// The last matching rule decides whether the path is ignored, allowing later negations to clear an earlier exclusion.
// Returns the deciding rule for an ignored path, or undefined when no rule matches or the last match is a negation.
function matchedGitIgnoreRule(rules: GitIgnoreRule[], display: string, isDirectory: boolean): GitIgnoreRule | undefined {
  let matched: GitIgnoreRule | undefined;
  let isIgnored = false;
  for (const rule of rules) {
    if (gitIgnoreRuleMatches(rule, display, isDirectory)) {
      isIgnored = !rule.isNegated;
      matched = rule;
    }
  }
  return isIgnored ? matched : undefined;
}

// Reports whether rule matches the candidate display path after rebasing it against the rule's owning directory. The owner never matches.
// Nested rules reject paths outside their base. Discovery supplies project paths to project-root rules.
// isDirectory tells directory-only rules whether they can test the leaf itself. A file can still match through an ancestor directory.
function gitIgnoreRuleMatches(rule: GitIgnoreRule, display: string, isDirectory: boolean): boolean {
  const relativePath = pathRelativeToBase(rule.basePath, display);
  if (relativePath === undefined || relativePath.length === 0) {
    return false;
  }

  if (rule.isDirectoryOnly) {
    return gitIgnoreDirectoryRuleMatches(rule, relativePath, isDirectory);
  }
  return gitIgnoreFileRuleMatches(rule, relativePath, isDirectory);
}

// Reports whether rule matches relativePath, a path relative to the rule's owning directory.
// isDirectory passes the candidate kind to the prefix helper. Both files and directories include the leaf among the candidates.
// Path-scoped patterns test successive prefixes, while bare patterns test individual components.
function gitIgnoreFileRuleMatches(rule: GitIgnoreRule, relativePath: string, isDirectory: boolean): boolean {
  if (isPathScopedGitIgnoreRule(rule)) {
    return gitIgnorePathCandidates(relativePath, isDirectory, true).some((candidate) => gitIgnoreGlobMatches(rule.pattern, candidate));
  }
  return relativePath.split("/").some((segment) => gitIgnoreGlobMatches(rule.pattern, segment));
}

// Returns whether rule matches a directory in relativePath. Includes the final segment as a candidate only when isDirectory is true.
// Path-scoped rules match directory prefixes. A rule such as node_modules/ must skip a same-named file leaf.
function gitIgnoreDirectoryRuleMatches(rule: GitIgnoreRule, relativePath: string, isDirectory: boolean): boolean {
  if (isPathScopedGitIgnoreRule(rule)) {
    return gitIgnorePathCandidates(relativePath, isDirectory, false).some((candidate) => gitIgnoreGlobMatches(rule.pattern, candidate));
  }
  const segments = relativePath.split("/");
  const directorySegments = isDirectory ? segments : segments.slice(0, -1);
  return directorySegments.some((segment) => gitIgnoreGlobMatches(rule.pattern, segment));
}

// Returns whether rule has a leading slash or an internal slash, so its pattern is tested against prefixes from its owning directory.
// A prefix can be a single component, such as the candidate for an anchored pattern with one name.
function isPathScopedGitIgnoreRule(rule: GitIgnoreRule): boolean {
  return rule.isAnchored || rule.hasSlash;
}

// Returns successive prefixes of relativePath so a matching ancestor can exclude descendants.
// When isDirectory is true the leaf is included. For files, shouldIncludeFilePath decides whether to include it.
// Excluding the leaf of a single-component file path returns an empty list because there is no ancestor prefix to test.
function gitIgnorePathCandidates(relativePath: string, isDirectory: boolean, shouldIncludeFilePath: boolean): string[] {
  const segments = relativePath.split("/");
  const limit = isDirectory || shouldIncludeFilePath ? segments.length : segments.length - 1;
  const candidates: string[] = [];
  for (let index = 1; index <= limit; index += 1) {
    candidates.push(segments.slice(0, index).join("/"));
  }
  return candidates;
}

// Reports whether candidatePath matches the complete gitignore pattern.
function gitIgnoreGlobMatches(pattern: string, candidatePath: string): boolean {
  return gitIgnoreGlobRegex(pattern).test(candidatePath);
}

// Translates a git glob pattern into a JS RegExp with Git wildcard semantics.
// Single stars stay within a segment, supported double-star forms can cross segments, and question marks match one non-slash character.
function gitIgnoreGlobRegex(pattern: string): RegExp {
  let source = "^";
  for (let index = 0; index < pattern.length; index += 1) {
    const fragment = gitIgnoreGlobFragment(pattern, index);
    source += fragment.source;
    index += fragment.skip;
  }
  return new RegExp(`${source}$`);
}

// Returns the regex fragment at index in the gitignore pattern, plus the number of extra characters consumed.
// Handles stars, single-character wildcards, classes, and backslash escapes; other characters are matched literally.
// An unparsed class opener is matched literally; a final backslash is also kept as a literal.
function gitIgnoreGlobFragment(pattern: string, index: number): { source: string; skip: number } {
  const character = pattern[index] ?? "";
  if (character === "*") {
    return gitIgnoreStarFragment(pattern, index);
  }
  if (character === "?") {
    return { source: "[^/]", skip: 0 };
  }
  if (character === "[") {
    return gitIgnoreCharacterClassFragment(pattern, index) ?? { source: escapeRegex(character), skip: 0 };
  }
  if (character === "\\") {
    return { source: escapeRegex(pattern[index + 1] ?? character), skip: pattern[index + 1] ? 1 : 0 };
  }
  return { source: escapeRegex(character), skip: 0 };
}

// Converts the star at index in pattern to regex source and returns how many extra pattern characters were consumed.
// A leading or slash-delimited star pair followed by a slash can consume zero or more directories.
// A trailing star pair after a slash can cross directories; other stars and pairs stay within one path segment.
function gitIgnoreStarFragment(pattern: string, index: number): { source: string; skip: number } {
  const next = pattern[index + 1];
  const afterNext = pattern[index + 2];
  if (next !== "*") {
    return { source: "[^/]*", skip: 0 };
  }
  if (afterNext === "/" && (index === 0 || pattern[index - 1] === "/")) {
    return { source: "(?:.*/)?", skip: 2 };
  }
  if (index > 0 && pattern[index - 1] === "/" && index + 2 === pattern.length) {
    return { source: ".*", skip: 1 };
  }
  return { source: "[^/]*", skip: 1 };
}

// Converts the character class starting at index in pattern to regex source and an extra-character skip count.
// Returns undefined for an unterminated or empty class so the caller can match the opening bracket literally.
function gitIgnoreCharacterClassFragment(pattern: string, index: number): { source: string; skip: number } | undefined {
  const parsed = parseGitIgnoreCharacterClass(pattern, index);
  if (!parsed) {
    return undefined;
  }
  return { source: parsed.isNegated ? `[^/${parsed.body}]` : `[${parsed.body}]`, skip: parsed.skip };
}

// Parsed gitignore character-class body before conversion to regex syntax.
interface GitIgnoreCharacterClass {
  body: string;
  isNegated: boolean;
  skip: number;
}

// Parses a character class beginning at index in pattern, including a literal ] allowed first after optional negation.
// Returns its regex body, negation flag, and extra-character skip count, or undefined when no valid closing bracket is found.
function parseGitIgnoreCharacterClass(pattern: string, index: number): GitIgnoreCharacterClass | undefined {
  const header = gitIgnoreCharacterClassHeader(pattern, index);
  let cursor = header.cursor;
  let body = header.body;
  for (; cursor < pattern.length; cursor += 1) {
    const character = pattern[cursor] ?? "";
    if (character === "]" && body.length > 0) {
      return { body, isNegated: header.isNegated, skip: cursor - index };
    }
    const fragment = gitIgnoreClassBodyFragment(pattern, cursor);
    body += fragment.source;
    cursor += fragment.skip;
  }
  return undefined;
}

// Reads negation (! or ^) and an initial literal ] after the opening bracket at index in pattern.
// Returns the next body cursor, body text (empty unless ] was consumed), and the negation flag.
function gitIgnoreCharacterClassHeader(pattern: string, index: number): { cursor: number; body: string; isNegated: boolean } {
  let cursor = index + 1;
  const isNegated = pattern[cursor] === "!" || pattern[cursor] === "^";
  if (isNegated) {
    cursor += 1;
  }
  if (pattern[cursor] === "]") {
    return { cursor: cursor + 1, body: "\\]", isNegated };
  }
  return { cursor, body: "", isNegated };
}

// Returns the regex-ready body fragment for one class character, consuming an escaped literal pair
// when gitignore used a backslash.
function gitIgnoreClassBodyFragment(pattern: string, cursor: number): { source: string; skip: number } {
  if (pattern[cursor] === "\\" && pattern[cursor + 1]) {
    return { source: escapeRegexClassCharacter(pattern[cursor + 1] ?? ""), skip: 1 };
  }
  return { source: escapeRegexClassCharacter(pattern[cursor] ?? ""), skip: 0 };
}

// Escapes only characters with special meaning inside a regex character class. Escaping hyphen would
// change valid git ranges like [a-z], so the set is intentionally narrower than normal regex escaping.
function escapeRegexClassCharacter(character: string): string {
  return character.replace(/[\\\]^]/g, "\\$&");
}

// Returns display relative to basePath for matching rules owned by that directory; undefined means the path is outside the base.
// An empty basePath means the project root; the base itself returns an empty string and is not matched by the caller.
function pathRelativeToBase(basePath: string, display: string): string | undefined {
  if (basePath.length === 0) {
    return display === "." ? "" : display;
  }
  if (display === basePath) {
    return "";
  }
  return display.startsWith(`${basePath}/`) ? display.slice(basePath.length + 1) : undefined;
}

// Reports whether path is lexically equal to projectRoot or lies below it.
// The ignore walker uses this check to restrict project .gitignore lookup to paths within the requested root.
function isInsideProject(projectRoot: string, path: string): boolean {
  const relativePath = relative(projectRoot, path).replaceAll("\\", "/");
  return relativePath === "" || (!relativePath.startsWith("../") && relativePath !== ".." && !isAbsolute(relativePath));
}

// Reports whether the candidate path matches a user config ignore pattern; these exclusions are additive and have no negation.
// Supports literal directory prefixes and star globs.
// A pattern ending in slash and two stars includes the literal prefix and its descendants, even if that prefix contains stars.
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
  const prefix = pattern.replace(/\/$/, "");
  return path === prefix || path.startsWith(`${prefix}/`);
}

// Returns a new list with one entry per absolute path because multiple CLI inputs can reach the same file.
// Keeps the first entry for each path in files to preserve the deterministic sort imposed by discoverSources.
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

/**
 * Formats a scanned path for findings, diagnostics, and baselines.
 * Paths inside the run root stay relative; outside paths are absolute so editor and CI links remain usable.
 *
 * @param projectRoot - run root that anchors relative report paths
 * @param inputPath - scanned path; an empty path addresses the run root itself
 * @returns POSIX report path; a single dot means the input is the run root
 */
export function displayPath(projectRoot: string, inputPath: string): string {
  const absoluteInputPath = isAbsolute(inputPath) ? inputPath : join(projectRoot, inputPath);
  const projectRelativePath = relative(projectRoot, absoluteInputPath).replaceAll("\\", "/");
  // The run root itself needs a non-empty label in reports.
  if (projectRelativePath === "") {
    return ".";
  }
  // Give paths outside the run root an absolute label so report consumers can resolve them without the original run root.
  if (projectRelativePath === ".." || projectRelativePath.startsWith("../") || isAbsolute(projectRelativePath)) {
    return absoluteInputPath.replaceAll("\\", "/");
  }
  return projectRelativePath;
}

// Escapes the standard regex metacharacters so untrusted patterns can be embedded literally.
function escapeRegex(rawText: string): string {
  return rawText.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
