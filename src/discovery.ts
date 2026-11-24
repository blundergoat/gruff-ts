// Discovers scannable TypeScript, JavaScript, and config files under a project root for every CLI command.
//
// Owns the single allowlist of scannable extensions (`pushSourceFile`), applies ignore rules in precedence order
// (`paths.ignore`, VCS directories, `.gitignore`, third-party/minified defaults, and fallback directories), and normalizes display paths.
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { basename, dirname, extname, isAbsolute, join, relative } from "node:path";
import type { AnalysisOptions, Config, IgnoreSource, ScanSurfaceNote, SkippedPath } from "./types.ts";

// `absolutePath` is what `node:fs` operates on; `displayPath` is project-relative inside the run root and absolute outside it.
// Both paths must stay aligned because finding fingerprints hash `displayPath`.
export interface SourceFile {
  absolutePath: string;
  displayPath: string;
  isScript: boolean;
}

// Mutable accumulator used during the directory walk; `skipped` is keyed by display path so repeated roots deduplicate before sorting.
interface SourceDiscovery {
  files: SourceFile[];
  missingPaths: string[];
  skipped: Map<string, SkippedPath>;
}

// Deterministic discovery output returned to the analyser and `check-ignore`:
//
// - `files` are sorted and deduplicated by `displayPath` so reports never depend on filesystem readdir order;
// - `ignoredPaths` and `skipped` record excluded paths with their ignore source and matched pattern;
// - `notes` lists existing targets that produced zero analysable files so an all-skipped run never looks silently clean.
export interface SourceDiscoveryResult {
  files: SourceFile[];
  missingPaths: string[];
  ignoredPaths: string[];
  skipped: SkippedPath[];
  notes: ScanSurfaceNote[];
}

// One parsed `.gitignore` line whose flags (`isAnchored`, `isDirectoryOnly`, `hasSlash`, `isNegated`) preserve git's matching semantics.
interface GitIgnoreRule {
  basePath: string;
  pattern: string;
  isNegated: boolean;
  isDirectoryOnly: boolean;
  isAnchored: boolean;
  hasSlash: boolean;
}

/**
 * Reads the filesystem, resolving options' paths against projectRoot and using config and options to decide what to skip.
 * With no paths, scans projectRoot. Deduplicates files by absolute path and sorts files and skips to preserve stable report order.
 *
 * @param projectRoot - base directory used to resolve requested paths and format report paths
 * @param options - scan options supplying target paths and ignore bypass settings
 * @param config - user configuration supplying explicit ignore patterns
 * @returns discovered files, missing paths, skipped paths and reasons, and notes for inputs that add no files or missing paths
 */
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

/**
 * Builds an informational note for an existing input that contributed no analysable files, so zero findings cannot be mistaken for a clean scan.
 * A positive count reports newly recorded skips, while a zero count reports no analysable source files.
 *
 * @param input - requested file or directory path that produced no analysable files
 * @param skippedCount - number of newly recorded skipped paths under the input
 * @returns scan surface note describing why the input contributed no analysable files
 */
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
        // Default minified-file exclusions record skips only for scannable file types; explicit config or .gitignore rules always record skips.
        if (match.source !== "default" || match.pattern !== MINIFIED_FILE_PATTERN || isScannableSourceFile(absolute)) {
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

/**
 * Reports whether pushSourceFile would admit a path, so the walk lists a skipped minified file only when it is scannable.
 *
 * @param absolutePath - candidate file path whose extension and basename are checked against script and text allowlists
 * @returns true when the file matches a supported script, text, or secret-file allowlist entry
 */
function isScannableSourceFile(absolutePath: string): boolean {
  const name = basename(absolutePath);
  const isText = TEXT_FILE_EXTENSIONS.includes(extname(absolutePath).slice(1).toLowerCase()) || name.startsWith(".env") || EXACT_SECRET_TEXT_FILES.includes(name);
  return isScriptFile(absolutePath) || isText;
}

/**
 * Reports whether a path's extension is parsed as code.
 *
 * @param absolutePath - candidate file path whose lowercase extension is checked
 * @returns true when the extension belongs to the script file allowlist
 */
function isScriptFile(absolutePath: string): boolean {
  return SCRIPT_FILE_EXTENSIONS.includes(extname(absolutePath).slice(1).toLowerCase());
}

const VCS_DIRECTORIES = [".git", ".hg", ".svn"] as const;
const FALLBACK_DIRECTORIES = [".fleet", ".idea", ".vscode", "build", "coverage", "node_modules"] as const;

// Third-party copy directories plus `dist`, skipped at any depth under ASCII case folding even when a `.gitignore` governs the directory.
// `build` and `coverage` stay fallback-only (FAMILY-CONTRACT.md section 7, amended by precision-floor M04).
const THIRD_PARTY_DIRECTORIES: readonly string[] = ["bower_components", "dist", "third-party", "third_party", "vendor", "vendors"];

/** Pattern recorded for a minified file such as `jquery.min.js`, which section 7 skips as generated. */
export const MINIFIED_FILE_PATTERN = "*.min.*";

/**
 * Folds only ASCII capital letters to lowercase so directory and filename checks use consistent case folding.
 *
 * @param pathComponent - single path segment or filename to normalize
 * @returns the path component with ASCII uppercase letters converted to lowercase
 */
function asciiLower(pathComponent: string): string {
  return pathComponent.replace(/[A-Z]/gu, (character) => character.toLowerCase());
}

/**
 * Finds the outermost third-party or build-output directory on display using ASCII-lowercased components.
 *
 * @param display - slash-separated display path to inspect
 * @param isDirectory - controls whether to check the final component, so a/Vendor/x.ts gives vendor and a file named dist gives no match
 * @returns lowercase matched directory name, or undefined when this policy supplies no exclusion
 */
function matchedThirdPartyDirectory(display: string, isDirectory: boolean): string | undefined {
  const components = display.split("/");
  const directories = isDirectory ? components : components.slice(0, -1);
  return directories.map(asciiLower).find((component) => THIRD_PARTY_DIRECTORIES.includes(component));
}

/**
 * Reports whether the base name has an ASCII case-insensitive .min. marker directly before its final extension.
 * For example, jquery.MIN.js matches, while app.min.js.map and admin.mini.js do not.
 *
 * @param name - file basename to check for a minified marker
 * @returns true when the name ends with a .min. marker followed by a single final extension
 */
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

/**
 * Classifies the path in input using its location, kind, scan options, config, and Git ignore rules.
 * Config and VCS exclusions always apply; explicit files and --include-ignored bypass Git and remaining default exclusions.
 *
 * @param input - bundled path coordinates, kind, options, config, and inherited Git ignore rules
 * @returns the first matching ignore source and pattern, or undefined to keep the path eligible
 */
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
  const gitIgnoreLookupDirectory = isInsideProject(projectRoot, dirname(absolute)) ? dirname(absolute) : projectRoot;
  const gitIgnoreRules = options.shouldIncludeIgnored || isExplicitFile
    ? []
    : gitIgnoreRulesForDirectory(projectRoot, gitIgnoreLookupDirectory);
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

/**
 * Finds the first path component owned by one directory-policy set.
 *
 * @param path - slash-separated path whose components are inspected
 * @param candidates - directory names belonging to a specific exclusion policy
 * @returns the first matching component, or undefined when no component belongs to candidates
 */
function matchedDirectoryComponent(path: string, candidates: readonly string[]): string | undefined {
  return path.split("/").find((component) => candidates.includes(component));
}

/**
 * Reports whether fallback exclusions apply to absolute: outside projectRoot they always apply.
 * Inside projectRoot they apply only if no regular .gitignore exists from the root through the candidate's parent.
 *
 * @param projectRoot - run root directory that bounds .gitignore lookup
 * @param absolute - resolved candidate path being evaluated
 * @returns true when fallback directory exclusions govern the candidate path
 */
function fallbackAppliesAt(projectRoot: string, absolute: string): boolean {
  if (!isInsideProject(projectRoot, absolute)) {
    return true;
  }
  const parentDirectory = dirname(absolute);
  const relativeParent = isInsideProject(projectRoot, parentDirectory)
    ? relative(projectRoot, parentDirectory).replaceAll("\\", "/")
    : "";
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

/**
 * Distinguishes a regular .gitignore file from a missing path or directory.
 *
 * @param path - filesystem path to check for a regular file
 * @returns true when the path exists on the filesystem and is a regular file
 */
function isGitIgnoreFile(path: string): boolean {
  return existsSync(path) && statSync(path).isFile();
}

/**
 * Collects .gitignore rules from projectRoot through directory in parent-before-child order, so later child rules can override parents.
 * Reads every regular .gitignore along the chain.
 *
 * @param projectRoot - root directory beyond which .gitignore files are not read
 * @param directory - target directory whose ancestor .gitignore chain is loaded
 * @returns ordered ignore rules, or an empty list outside projectRoot or when no file contributes usable rules
 */
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

/**
 * Reads directory's .gitignore with rule paths based at projectRoot and appends its rules after inheritedRules.
 * Preserves the caller's inherited stack by returning a new array when rules are added.
 *
 * @param projectRoot - root directory used to compute the .gitignore basePath
 * @param directory - directory inspected for a regular .gitignore file
 * @param inheritedRules - parent ignore rules that stay unchanged when no usable rules are found
 * @returns inheritedRules unchanged if no usable rules apply, otherwise a new combined array
 */
function appendGitIgnoreRules(projectRoot: string, directory: string, inheritedRules: GitIgnoreRule[]): GitIgnoreRule[] {
  const ignoreFile = join(directory, ".gitignore");
  if (!existsSync(ignoreFile) || !statSync(ignoreFile).isFile()) {
    return inheritedRules;
  }

  const basePath = displayPath(projectRoot, directory);
  const parsedRules = parseGitIgnoreRules(readFileSync(ignoreFile, "utf8"), basePath === "." ? "" : basePath);
  return parsedRules.length > 0 ? [...inheritedRules, ...parsedRules] : inheritedRules;
}

/**
 * Parses .gitignore source into ordered rules owned by basePath, dropping comments, blanks, and marker-only lines.
 *
 * @param source - raw .gitignore file text with LF or CRLF line endings
 * @param basePath - directory path owning these rules relative to the project root, or empty string for the root
 * @returns ordered parsed rules, or an empty array when no usable rules remain
 */
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

/**
 * Parses rawLine from the .gitignore owned by basePath into its normalized pattern and matching flags.
 *
 * @param rawLine - single line from a .gitignore file
 * @param basePath - owning directory path relative to the project root; an empty string attaches the rule to the root
 * @returns parsed rule, or undefined for comments, blank lines, or lines whose negation or slash markers leave no pattern
 */
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

/**
 * Normalizes a raw .gitignore line, ignoring trailing spaces only when they are not escaped to match gitignore's literal-space escape.
 *
 * @param rawLine - single line read from a .gitignore file
 * @returns trimmed pattern text, or undefined for blank or comment lines so the caller can skip them cleanly
 */
function unescapedGitIgnoreLine(rawLine: string): string | undefined {
  const line = trimUnescapedTrailingSpaces(rawLine);
  if (line.length === 0 || line.startsWith("#")) {
    return undefined;
  }
  return line;
}

/**
 * Strips unescaped trailing spaces from a .gitignore line because Git treats them as padding.
 * A backslash-escaped trailing space stays part of the pattern.
 *
 * @param rawLine - raw line from a .gitignore file
 * @returns line text without unescaped trailing spaces
 */
function trimUnescapedTrailingSpaces(rawLine: string): string {
  let end = rawLine.length;
  while (end > 0 && rawLine[end - 1] === " " && !isEscapedAt(rawLine, end - 1)) {
    end -= 1;
  }
  return rawLine.slice(0, end);
}

/**
 * Checks whether the character at index in source has an odd number of backslashes immediately before it.
 * Even runs cancel out because a pair represents a literal backslash and leaves the next character unescaped.
 *
 * @param source - string containing the character to test
 * @param index - zero-based position of the character in source
 * @returns true when an odd run of backslashes precedes index
 */
function isEscapedAt(source: string, index: number): boolean {
  let slashCount = 0;
  for (let cursor = index - 1; cursor >= 0 && source[cursor] === "\\"; cursor -= 1) {
    slashCount += 1;
  }
  return slashCount % 2 === 1;
}

/**
 * Builds the canonical matcher pattern for a gitignore line after its anchor and directory-only flags have been captured.
 * Removes edge slashes and empty internal segments.
 *
 * @param line - unescaped gitignore line without negation prefix
 * @returns normalized pattern, or an empty string for an all-slash line so the caller drops the rule
 */
function normalizedGitIgnorePattern(line: string): string {
  return line
    .replace(/^\/+/, "")
    .replace(/\/+$/, "")
    .split("/")
    .filter((segment) => segment.length > 0)
    .join("/");
}

/**
 * Evaluates rules in inherited file order against display so later negations can clear an earlier exclusion.
 * The last matching rule decides whether the path is ignored.
 *
 * @param rules - ordered .gitignore rules from root through parent directories
 * @param display - candidate path formatted relative to the project root
 * @param isDirectory - identifies whether the candidate path is a directory
 * @returns the deciding rule for an ignored path, or undefined when no rule matches or the last match is a negation
 */
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

/**
 * Reports whether rule matches the candidate display path after rebasing it against the rule's owning directory.
 * The owner never matches, and nested rules reject paths outside their base; files can still match through an ancestor directory.
 *
 * @param rule - parsed .gitignore rule to evaluate
 * @param display - candidate project-relative display path supplied by discovery
 * @param isDirectory - tells directory-only rules whether they can test the leaf itself
 * @returns true when the rule matches the rebased path
 */
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

/**
 * Reports whether a non-directory-only rule matches relativePath, testing successive prefixes for path-scoped patterns and segments for bare ones.
 *
 * @param rule - parsed .gitignore rule without a trailing slash restriction
 * @param relativePath - candidate path relative to the rule's owning directory
 * @param isDirectory - candidate kind passed to the prefix helper while both files and directories include the leaf
 * @returns true when the rule pattern matches any candidate prefix or segment
 */
function gitIgnoreFileRuleMatches(rule: GitIgnoreRule, relativePath: string, isDirectory: boolean): boolean {
  if (isPathScopedGitIgnoreRule(rule)) {
    return gitIgnorePathCandidates(relativePath, isDirectory, true).some((candidate) => gitIgnoreGlobMatches(rule.pattern, candidate));
  }
  return relativePath.split("/").some((segment) => gitIgnoreGlobMatches(rule.pattern, segment));
}

/**
 * Reports whether a directory-only rule matches a directory in relativePath.
 * A rule such as node_modules/ must skip a same-named file leaf while still matching ancestor directories.
 *
 * @param rule - parsed directory-only .gitignore rule
 * @param relativePath - candidate path relative to the rule's owning directory
 * @param isDirectory - includes the final segment as a candidate only when true
 * @returns true when the rule pattern matches a directory prefix or directory segment
 */
function gitIgnoreDirectoryRuleMatches(rule: GitIgnoreRule, relativePath: string, isDirectory: boolean): boolean {
  if (isPathScopedGitIgnoreRule(rule)) {
    return gitIgnorePathCandidates(relativePath, isDirectory, false).some((candidate) => gitIgnoreGlobMatches(rule.pattern, candidate));
  }
  const segments = relativePath.split("/");
  const directorySegments = isDirectory ? segments : segments.slice(0, -1);
  return directorySegments.some((segment) => gitIgnoreGlobMatches(rule.pattern, segment));
}

/**
 * Reports whether rule has a leading slash or an internal slash, so its pattern is tested against prefixes from its owning directory.
 * A prefix can be a single component, such as the candidate for an anchored pattern with one name.
 *
 * @param rule - parsed .gitignore rule to inspect
 * @returns true when the rule is anchored or contains an internal slash
 */
function isPathScopedGitIgnoreRule(rule: GitIgnoreRule): boolean {
  return rule.isAnchored || rule.hasSlash;
}

/**
 * Builds successive prefixes of relativePath so a matching ancestor can exclude descendants.
 * Excluding the leaf of a single-component file path yields an empty list because there is no ancestor prefix to test.
 *
 * @param relativePath - slash-separated path relative to the rule's owning directory
 * @param isDirectory - includes the leaf prefix when true
 * @param shouldIncludeFilePath - decides whether to include the leaf when isDirectory is false
 * @returns ordered path prefixes from shallowest ancestor to the permitted leaf
 */
function gitIgnorePathCandidates(relativePath: string, isDirectory: boolean, shouldIncludeFilePath: boolean): string[] {
  const segments = relativePath.split("/");
  const limit = isDirectory || shouldIncludeFilePath ? segments.length : segments.length - 1;
  const candidates: string[] = [];
  for (let index = 1; index <= limit; index += 1) {
    candidates.push(segments.slice(0, index).join("/"));
  }
  return candidates;
}

/**
 * Reports whether candidatePath matches the complete gitignore pattern.
 *
 * @param pattern - normalized gitignore glob pattern
 * @param candidatePath - path prefix or segment tested against the compiled pattern
 * @returns true when the entire candidatePath matches the pattern
 */
function gitIgnoreGlobMatches(pattern: string, candidatePath: string): boolean {
  return gitIgnoreGlobRegex(pattern).test(candidatePath);
}

/**
 * Translates a git glob pattern into a JS RegExp with Git wildcard semantics.
 * Single stars stay within a segment, supported double-star forms cross segments, and question marks match one non-slash character.
 *
 * @param pattern - normalized gitignore glob pattern
 * @returns anchored regular expression matching complete candidate strings
 */
function gitIgnoreGlobRegex(pattern: string): RegExp {
  let source = "^";
  for (let index = 0; index < pattern.length; index += 1) {
    const fragment = gitIgnoreGlobFragment(pattern, index);
    source += fragment.source;
    index += fragment.skip;
  }
  return new RegExp(`${source}$`);
}

/**
 * Converts the token at index in pattern into a regex fragment, handling stars, wildcards, classes, and escapes.
 * An unparsed class opener or trailing backslash is kept as a literal.
 *
 * @param pattern - normalized gitignore glob pattern
 * @param index - zero-based cursor position in pattern
 * @returns regex source fragment and the number of extra characters consumed past index
 */
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

/**
 * Converts the star at index in pattern to regex source according to Git single-star and double-star rules.
 * Leading or slash-delimited star pairs followed by a slash consume zero or more directories; trailing star pairs after a slash cross directories.
 *
 * @param pattern - normalized gitignore glob pattern
 * @param index - index of the leading asterisk in pattern
 * @returns regex source fragment and extra pattern character count consumed
 */
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

/**
 * Converts the character class starting at index in pattern to regex source and an extra-character skip count.
 *
 * @param pattern - normalized gitignore glob pattern
 * @param index - index of the opening bracket in pattern
 * @returns regex fragment and skip count, or undefined for an unterminated or empty class so the caller matches `[` literally
 */
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

/**
 * Parses a character class beginning at index in pattern, including a literal `]` allowed first after optional negation.
 *
 * @param pattern - normalized gitignore glob pattern
 * @param index - index of the opening bracket in pattern
 * @returns regex body, negation flag, and extra-character skip count, or undefined when no valid closing bracket is found
 */
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

/**
 * Parses optional negation (`!` or `^`) and an initial literal `]` after the opening bracket at index in pattern.
 *
 * @param pattern - normalized gitignore glob pattern
 * @param index - index of the opening bracket in pattern
 * @returns next body cursor, initial body text (empty unless `]` was consumed), and negation flag
 */
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

/**
 * Builds the regex-ready body fragment for one class character, consuming an escaped literal pair when gitignore used a backslash.
 *
 * @param pattern - normalized gitignore glob pattern
 * @param cursor - index of the current character inside the character class
 * @returns escaped class character fragment and extra character skip count (1 for a backslash pair, 0 otherwise)
 */
function gitIgnoreClassBodyFragment(pattern: string, cursor: number): { source: string; skip: number } {
  if (pattern[cursor] === "\\" && pattern[cursor + 1]) {
    return { source: escapeRegexClassCharacter(pattern[cursor + 1] ?? ""), skip: 1 };
  }
  return { source: escapeRegexClassCharacter(pattern[cursor] ?? ""), skip: 0 };
}

/**
 * Escapes only characters with special meaning inside a regex character class, preserving hyphens so valid git ranges like `[a-z]` stay intact.
 *
 * @param character - single character to place inside a JavaScript RegExp character class
 * @returns escaped character safe for regex character-class interpolation without altering range hyphens
 */
function escapeRegexClassCharacter(character: string): string {
  return character.replace(/[\\\]^]/g, "\\$&");
}

/**
 * Rebases display relative to basePath for matching rules owned by that directory.
 * An empty basePath means the project root; the base itself yields an empty string and is not matched by the caller.
 *
 * @param basePath - project-relative owning directory of a .gitignore rule, or empty string for the root
 * @param display - candidate project-relative display path
 * @returns path relative to basePath, empty string for the base itself, or undefined when outside the base
 */
function pathRelativeToBase(basePath: string, display: string): string | undefined {
  if (basePath.length === 0) {
    return display === "." ? "" : display;
  }
  if (display === basePath) {
    return "";
  }
  return display.startsWith(`${basePath}/`) ? display.slice(basePath.length + 1) : undefined;
}

/**
 * Reports whether path is lexically equal to projectRoot or lies below it.
 * The ignore walker uses this check to restrict project .gitignore lookup to paths within the requested root.
 *
 * @param projectRoot - root directory defining the project boundary
 * @param path - filesystem path tested for lexical containment
 * @returns true when path equals projectRoot or is a descendant of it
 */
function isInsideProject(projectRoot: string, path: string): boolean {
  const relativePath = relative(projectRoot, path).replaceAll("\\", "/");
  return relativePath === "" || (!relativePath.startsWith("../") && relativePath !== ".." && !isAbsolute(relativePath));
}

/**
 * Reports whether the candidate path matches a user config ignore pattern; these exclusions are additive and have no negation.
 * Supports literal directory prefixes, star globs, and patterns ending in slash and two stars for a literal prefix and its descendants.
 *
 * @param pattern - user config ignore pattern from config.ignoredPaths
 * @param path - candidate display path to test
 * @returns true when the candidate path matches the config ignore pattern
 */
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

/**
 * Deduplicates files by absolute path because multiple CLI inputs can reach the same file.
 * Keeps the first entry for each path in files to preserve the deterministic sort imposed by discoverSources.
 *
 * @param files - sorted list of discovered source file records
 * @returns new array containing the first record for each unique absolutePath
 */
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

/**
 * Anchors a relative CLI argument against the project root; absolute paths pass through unchanged.
 *
 * @param projectRoot - base directory used to resolve relative paths
 * @param path - CLI path argument, either relative or absolute
 * @returns resolved absolute path
 */
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

/**
 * Escapes the standard regex metacharacters so untrusted patterns can be embedded literally.
 *
 * @param rawText - raw literal text to embed in a regular expression
 * @returns text with regex metacharacters backslash-escaped
 */
function escapeRegex(rawText: string): string {
  return rawText.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
