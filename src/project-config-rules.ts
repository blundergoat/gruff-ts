// Package and tsconfig health checks that emit deterministic project-config findings from JSON files.
import { existsSync, statSync } from "node:fs";
import { basename, dirname as dirnamePath, isAbsolute, join } from "node:path";
import { platform } from "node:process";
import { isString, objectValue } from "./config-parse.ts";
import { makeFinding } from "./findings.ts";
import { firstLine } from "./text-scans.ts";
import type { Finding } from "./types.ts";

// Both paths are required: `displayPath` anchors findings, `absolutePath` resolves bin targets
// against the owning package.json. Diverging them would break bin-existence checks on Windows.
interface ConfigSourceFile {
  absolutePath: string;
  displayPath: string;
}

/**
 * Run configuration checks for package.json, tsconfig.json, and named variants such as tsconfig.build.json.
 * Keep finding order stable so that baseline reports are reproducible.
 *
 * @param file - Configuration file whose basename selects the checks and whose path identifies their findings.
 * @param source - Original JSON text to parse and use when locating findings.
 * @param findings - Collector for package or TypeScript configuration findings.
 * @returns Nothing. Appends findings only for supported filenames whose contents parse as a JSON object.
 */
function analyseProjectConfigRules(file: ConfigSourceFile, source: string, findings: Finding[]): void {
  const name = basename(file.displayPath);
  if (name !== "package.json" && !isTsconfigFileName(name)) {
    return;
  }
  const configObject = parseJsonObject(source);
  if (!configObject) {
    return;
  }
  if (name === "package.json") {
    analysePackageJson(file, source, configObject, findings);
  } else {
    analyseTsconfigJson(file, source, configObject, findings);
  }
}

/**
 * Reports whether a filename is `tsconfig.json` or a named variant such as `tsconfig.base.json`.
 * Keeps shared and workspace configs subject to the same strictness checks as the root config.
 *
 * @param name - Config basename to match against supported tsconfig naming patterns.
 * @returns True when `name` is `tsconfig.json` or `tsconfig.<variant>.json`; false otherwise.
 */
function isTsconfigFileName(name: string): boolean {
  return name === "tsconfig.json" || /^tsconfig\.[^.]+(?:\.[^.]+)*\.json$/.test(name);
}

/**
 * Runs script, dependency, and bin checks in that order to preserve the stable order of finding groups.
 *
 * @param file - Package manifest file whose path identifies findings and resolves relative bin targets.
 * @param source - Original manifest text used to locate script, dependency, and bin declarations.
 * @param pkg - Parsed package object supplying `scripts`, dependency sections, and `bin` fields to check.
 * @param findings - Collector to which any reported package findings are appended.
 * @returns Nothing. Appends any reported findings to the supplied list.
 */
function analysePackageJson(file: ConfigSourceFile, source: string, pkg: Record<string, unknown>, findings: Finding[]): void {
  analysePackageScripts(file, source, objectValue(pkg.scripts), findings);
  analysePackageDependencies(file, source, pkg, findings);
  analysePackageBins(file, source, pkg, findings);
}

/**
 * Checks script strings for remote shell execution in stable object entry order.
 *
 * @param file - package manifest whose path is reported
 * @param source - manifest text used to locate each script
 * @param scripts - parsed script entries, with missing sections and nonstring commands skipped
 * @param findings - destination for remote execution findings
 * @returns Nothing. Appends findings for matching commands to the supplied list.
 */
function analysePackageScripts(file: ConfigSourceFile, source: string, scripts: Record<string, unknown> | undefined, findings: Finding[]): void {
  if (!scripts) {
    return;
  }
  for (const [scriptName, scriptCommand] of Object.entries(scripts)) {
    if (!isString(scriptCommand)) {
      continue;
    }
    pushRemoteInstallScriptFinding(file, source, scriptName, scriptCommand, findings);
  }
}

/**
 * Flags curl or wget with an HTTP(S) URL piped to sh, bash or zsh, optionally via sudo, under the security.remote-install-script contract.
 * The finding is an error because running a matching script can execute code fetched from a remote server.
 *
 * @param file - package manifest whose path is reported
 * @param source - manifest text used to locate the named script
 * @param scriptName - manifest key to report for a matching command
 * @param scriptCommand - script text inspected for remote shell execution
 * @param findings - destination for the error finding
 * @returns Nothing. Appends an error only when the script matches.
 */
function pushRemoteInstallScriptFinding(file: ConfigSourceFile, source: string, scriptName: string, scriptCommand: string, findings: Finding[]): void {
  if (!isRemoteInstallScript(scriptCommand)) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "security.remote-install-script",
      message: `Package script \`${scriptName}\` downloads and executes remote shell content.`,
      filePath: file.displayPath,
      line: jsonKeyLine(source, scriptName),
      severity: "error",
      pillar: "security",
      confidence: "medium",
      symbol: scriptName,
      remediation: "Vendor the installer, pin an audited package, or remove remote shell execution.",
      metadata: { scriptName },
    }),
  );
}

/**
 * Checks string entries in dependencies, optionalDependencies, peerDependencies and devDependencies in that stable order.
 * The broad-version check applies only to dependencies and optionalDependencies because those are the runtime sections for this rule.
 *
 * @param file - package manifest whose path is reported
 * @param source - manifest text used to locate dependency entries
 * @param pkg - parsed manifest supplying the dependency sections, with missing or non-object sections skipped
 * @param findings - destination for findings from the dependency checks
 * @returns Nothing. Appends findings from the checks on eligible entries.
 */
function analysePackageDependencies(file: ConfigSourceFile, source: string, pkg: Record<string, unknown>, findings: Finding[]): void {
  for (const section of ["dependencies", "optionalDependencies", "peerDependencies", "devDependencies"]) {
    const dependencies = objectValue(pkg[section]);
    if (!dependencies) {
      continue;
    }
    const isRuntimeDependency = section === "dependencies" || section === "optionalDependencies";
    for (const [packageName, value] of Object.entries(dependencies)) {
      if (isString(value)) {
        analysePackageDependency(file, source, section, packageName, value, isRuntimeDependency, findings);
      }
    }
  }
}

/**
 * Checks one dependency for a URL spec, then checks for a broad spec when the runtime flag is set, to preserve stable finding order.
 *
 * @param file - Package manifest file whose display path is recorded on any emitted findings.
 * @param source - Manifest text searched by section, name, and version for URL findings and by name for broad versions.
 * @param section - Dependency section name where the entry was declared.
 * @param packageName - Declared dependency name used as the finding symbol and for line lookup.
 * @param versionSpec - Declared dependency version or target specifier to inspect.
 * @param isRuntimeDependency - Whether the entry belongs to a runtime dependency section (`dependencies` or `optionalDependencies`).
 * @param findings - Collector for matching URL-dependency or broad-runtime-version findings.
 * @returns Nothing. Appends any matching findings to the supplied list.
 */
function analysePackageDependency(
  file: ConfigSourceFile,
  source: string,
  section: string,
  packageName: string,
  versionSpec: string,
  isRuntimeDependency: boolean,
  findings: Finding[],
): void {
  pushUrlDependencyFinding(file, source, section, packageName, versionSpec, isRuntimeDependency, findings);
  pushBroadRuntimeDependencyFinding(file, source, section, packageName, versionSpec, isRuntimeDependency, findings);
}

/**
 * Appends one stable `security.url-dependency` finding for recognized URL, Git, or file specs because they bypass normal registry auditing.
 *
 * @param file - Package manifest file whose display path is reported on the finding.
 * @param source - Manifest text used to locate the entry by section, name, and version, with a name-only fallback.
 * @param section - Dependency section name recorded in the message and metadata.
 * @param packageName - Declared dependency name recorded as the finding symbol and in metadata.
 * @param versionSpec - Declared specifier checked against recognized URL, Git, and local file formats.
 * @param isRuntimeDependency - Runtime dependency flag recorded in the finding metadata.
 * @param findings - Collector that receives the finding when `versionSpec` matches.
 * @returns Nothing. Leaves `findings` unchanged for non-URL version specs.
 */
function pushUrlDependencyFinding(
  file: ConfigSourceFile,
  source: string,
  section: string,
  packageName: string,
  versionSpec: string,
  isRuntimeDependency: boolean,
  findings: Finding[],
): void {
  if (!isUrlDependency(versionSpec)) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "security.url-dependency",
      message: `Dependency \`${packageName}\` in \`${section}\` installs from a URL, git, or local file spec.`,
      filePath: file.displayPath,
      line: dependencyEntryLine(source, section, packageName, versionSpec),
      severity: "warning",
      pillar: "security",
      confidence: "medium",
      symbol: packageName,
      remediation: "Prefer a registry package version that can be locked and audited.",
      metadata: { packageName, section, runtimeDependency: isRuntimeDependency },
    }),
  );
}

/**
 * Under the stable `waste.broad-runtime-version` contract, flags broad specs such as `*`, `x`, or `latest` for runtime entries.
 *
 * @param file - Package manifest file whose display path is reported on the finding.
 * @param source - Manifest text used to locate the dependency key line.
 * @param section - Dependency section name recorded in finding metadata.
 * @param packageName - Declared dependency name used as the finding symbol and in metadata.
 * @param versionSpec - Declared specifier tested for overly broad version ranges and recorded in metadata.
 * @param isRuntimeDependency - Whether the dependency belongs to a runtime section; non-runtime entries are skipped.
 * @param findings - Collector that receives the advisory finding when both checks qualify.
 * @returns Nothing. Appends to `findings` only when `isRuntimeDependency` and the broad-version check both qualify the entry.
 */
function pushBroadRuntimeDependencyFinding(
  file: ConfigSourceFile,
  source: string,
  section: string,
  packageName: string,
  versionSpec: string,
  isRuntimeDependency: boolean,
  findings: Finding[],
): void {
  if (!isRuntimeDependency || !isBroadRuntimeVersion(versionSpec)) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "waste.broad-runtime-version",
      message: `Runtime dependency \`${packageName}\` uses overly broad version spec \`${versionSpec}\`.`,
      filePath: file.displayPath,
      line: jsonKeyLine(source, packageName),
      severity: "advisory",
      pillar: "maintainability",
      confidence: "medium",
      symbol: packageName,
      remediation: "Use a bounded semver range and rely on the lockfile for repeatable installs.",
      metadata: { packageName, section, versionSpec },
    }),
  );
}

/**
 * Checks string bin declarations and string targets in bin maps in stable entry order. Missing declarations and nonstring targets are skipped.
 *
 * @param file - package manifest used to resolve relative bin targets
 * @param source - manifest text used to locate bin declarations
 * @param pkg - parsed manifest supplying the bin declaration, scripts, and the name for a string bin, which defaults to bin
 * @param findings - destination for findings raised by the target checks
 * @returns Nothing. Appends any findings from checking the declared targets.
 */
function analysePackageBins(file: ConfigSourceFile, source: string, pkg: Record<string, unknown>, findings: Finding[]): void {
  const hasBuildScript = hasPackageBuildScript(pkg);
  for (const [command, target] of packageBinEntries(pkg)) {
    analysePackageBin(file, source, command, target, hasBuildScript, findings);
  }
}

/**
 * Checks a declared CLI target on disk. The stable rules distinguish missing targets from existing targets that are not executable files.
 * Windows skips the executable-file check because POSIX execute bits do not apply there.
 *
 * @param file - package manifest used to resolve and report the target
 * @param source - manifest text used to locate the bin declaration
 * @param command - declared CLI name to report if the check fails
 * @param target - declared path checked as given when absolute and relative to the manifest directory otherwise
 * @param hasBuildScript - true when `package.json` defines a non-empty `scripts.build` command
 * @param findings - destination for any finding raised by this check
 * @returns Nothing. Appends a finding for a missing target or, outside Windows, a target that is not an executable file.
 */
function analysePackageBin(file: ConfigSourceFile, source: string, command: string, target: string, hasBuildScript: boolean, findings: Finding[]): void {
  const absolute = packageBinPath(file, target);
  if (!existsSync(absolute)) {
    pushMissingPackageBinFinding(file, source, command, target, hasBuildScript && isBuildOutputBinTarget(target), findings);
    return;
  }
  const stats = statSync(absolute);
  if (platform === "win32") {
    return;
  }
  if (!stats.isFile() || (stats.mode & 0o111) === 0) {
    pushNonExecutablePackageBinFinding(file, source, command, target, findings);
  }
}

/**
 * Reports whether `package.json` declares a non-empty `scripts.build` entry, signaling that compiled bin artifacts may not exist before building.
 *
 * @param pkg - parsed `package.json` manifest object
 * @returns True when `pkg.scripts.build` is a non-empty string; false otherwise.
 */
function hasPackageBuildScript(pkg: Record<string, unknown>): boolean {
  const scripts = objectValue(pkg.scripts);
  return typeof scripts?.build === "string" && scripts.build.trim().length > 0;
}

/**
 * Reports whether a relative package bin target points into a conventional compiled output directory (`dist/`, `build/`, or `lib/`).
 *
 * @param target - bin target string declared in `package.json`
 * @returns True when the normalized relative path begins with `dist/`, `build/`, or `lib/`; false otherwise.
 */
function isBuildOutputBinTarget(target: string): boolean {
  const normalized = target.replaceAll("\\", "/").replace(/^\.\//, "");
  return /^(?:dist|build|lib)\//.test(normalized);
}

/**
 * Resolves a declared bin target against the owning `package.json` directory because workspace packages can live in subdirectories.
 *
 * @param file - Package manifest file whose `absolutePath` directory anchors relative bin targets.
 * @param target - Declared bin path from `package.json`.
 * @returns `target` unchanged when already absolute, or joined with the owning manifest directory otherwise.
 */
function packageBinPath(file: ConfigSourceFile, target: string): string {
  return isAbsolute(target) ? target : join(dirnamePath(file.absolutePath), target);
}

/**
 * Records design.package-bin-missing for a declared CLI whose target is missing, with stable command and target metadata.
 * Downgrades unbuilt build-output targets to advisory so fresh unbuilt checkouts do not draw a hard warning.
 *
 * @param file - package manifest whose path is reported
 * @param source - manifest text used to locate the bin declaration
 * @param command - declared CLI name recorded in the finding
 * @param target - missing path as declared in the manifest
 * @param isUnbuiltOutput - true when the missing path sits under `dist/`, `build/`, or `lib/` in a package with a `build` script
 * @param findings - destination for the finding
 * @returns Nothing. Appends the finding to the supplied list.
 */
function pushMissingPackageBinFinding(file: ConfigSourceFile, source: string, command: string, target: string, isUnbuiltOutput: boolean, findings: Finding[]): void {
  findings.push(
    packageBinFinding({
      file,
      source,
      ruleId: "design.package-bin-missing",
      message: isUnbuiltOutput
        ? `Package bin \`${command}\` points to unbuilt output \`${target}\` (run the package build script first).`
        : `Package bin \`${command}\` points to missing file \`${target}\`.`,
      command,
      target,
      severity: isUnbuiltOutput ? "advisory" : "warning",
      isUnbuiltOutput,
      remediation: isUnbuiltOutput
        ? "Run the package build script before verifying compiled bin targets, or update the bin path if the output path changed."
        : "Update the bin path or add the executable file.",
    }),
  );
}

/**
 * Records the stable design.package-bin-not-executable finding when the caller finds an existing target that is not an executable file.
 *
 * @param file - package manifest whose path is reported
 * @param source - manifest text used to locate the bin declaration
 * @param command - declared CLI name used in the finding
 * @param target - declared bin path recorded with the command
 * @param findings - destination for the finding
 * @returns Nothing. Appends the finding to the supplied list.
 */
function pushNonExecutablePackageBinFinding(file: ConfigSourceFile, source: string, command: string, target: string, findings: Finding[]): void {
  findings.push(
    packageBinFinding({
      file,
      source,
      ruleId: "design.package-bin-not-executable",
      message: `Package bin \`${command}\` points to a file that is not executable.`,
      command,
      target,
      severity: "warning",
      isUnbuiltOutput: false,
      remediation: "Make the bin target executable and keep its shebang valid.",
    }),
  );
}

// Argument bundle for `packageBinFinding`. Grouped into a struct because the helper accepts nine
// fields and an inline parameter list would silently break call sites on field shuffles.
interface PackageBinFindingInput {
  file: ConfigSourceFile;
  source: string;
  ruleId: string;
  message: string;
  command: string;
  target: string;
  severity: "advisory" | "warning";
  isUnbuiltOutput: boolean;
  remediation: string;
}

/**
 * Builds the missing-bin or non-executable-bin finding described by `input`, including its package location and remediation.
 * The `command` symbol contributes to the fingerprint, so renaming a bin entry changes its baseline identity.
 *
 * @param input - Finding inputs including manifest file, source text, rule details, bin command, target, and build status.
 * @returns Constructed `design` finding anchored at the declared `command` line in `input.source`.
 */
function packageBinFinding(input: PackageBinFindingInput): Finding {
  return makeFinding({
    ruleId: input.ruleId,
    message: input.message,
    filePath: input.file.displayPath,
    line: jsonKeyLine(input.source, input.command),
    severity: input.severity,
    pillar: "design",
    confidence: "high",
    symbol: input.command,
    remediation: input.remediation,
    metadata: input.isUnbuiltOutput ? { command: input.command, target: input.target, unbuiltOutput: true } : { command: input.command, target: input.target },
  });
}

/**
 * Checks the TypeScript strictness contract covered by the rule documentation.
 * An extends entry can supply an omitted flag, so the check skips omissions when inheritance is declared.
 *
 * @param file - Config file used to name the path in each finding.
 * @param source - Config text used to locate the option in each finding.
 * @param tsconfigData - Parsed config used to read compilerOptions and detect extends.
 * @param findings - Accumulator for the strictness findings.
 * @returns Nothing. Appends one finding per checked flag that is neither true nor omitted with extends.
 */
function analyseTsconfigJson(file: ConfigSourceFile, source: string, tsconfigData: Record<string, unknown>, findings: Finding[]): void {
  const compilerOptions = objectValue(tsconfigData.compilerOptions) ?? {};
  const hasExtends = typeof tsconfigData.extends === "string" || Array.isArray(tsconfigData.extends);
  const checks: Array<[string, string, string]> = [
    ["strict", "modernisation.tsconfig-strict-disabled", "`strict` is disabled, reducing TypeScript's baseline safety checks."],
    ["noUncheckedIndexedAccess", "modernisation.tsconfig-index-safety-disabled", "`noUncheckedIndexedAccess` is disabled, so indexed reads can silently ignore undefined."],
    ["exactOptionalPropertyTypes", "modernisation.tsconfig-exact-optional-disabled", "`exactOptionalPropertyTypes` is disabled, weakening optional property contracts."],
  ];
  for (const [optionName, ruleId, message] of checks) {
    const optionValue = compilerOptions[optionName];
    if (optionValue === true) {
      continue;
    }
    // Skip an omitted flag with extends because the unresolved base config may already enable it.
    if (optionValue === undefined && hasExtends) {
      continue;
    }
    findings.push(
      tsconfigFinding({
        file,
        source,
        ruleId,
        message,
        optionName,
        currentValue: optionValue ?? null,
      }),
    );
  }
}

// Argument bundle for `tsconfigFinding`. `currentValue` is preserved as-is (could be `false`, a
// non-`true` truthy value, or `null` for missing) so consumers can distinguish opt-outs from omissions.
interface TsconfigFindingInput {
  file: ConfigSourceFile;
  source: string;
  ruleId: string;
  message: string;
  optionName: string;
  currentValue: unknown;
}

/**
 * Builds a strictness finding from the supplied tsconfig file, source text, rule details, and observed option value.
 * The stable contract uses `optionName` as the symbol and retains `currentValue` in metadata.
 *
 * @param input - Finding inputs including config file, source text to locate the option key, rule details, option name, and current value.
 * @returns Constructed `modernisation` finding anchored at the option key line in `input.source`.
 */
function tsconfigFinding(input: TsconfigFindingInput): Finding {
  return makeFinding({
    ruleId: input.ruleId,
    message: input.message,
    filePath: input.file.displayPath,
    line: jsonKeyLine(input.source, input.optionName),
    severity: "warning",
    pillar: "modernisation",
    confidence: "high",
    symbol: input.optionName,
    remediation: `Set compilerOptions.${input.optionName} to true unless a documented migration blocker exists.`,
    metadata: { optionName: input.optionName, currentValue: input.currentValue },
  });
}

/**
 * Parses `source` as JSONC and returns its object root so rules skip malformed text and non-object roots.
 * Parse failures stay unlogged because this rule pass only emits findings for successfully decoded objects.
 *
 * @param source - Raw JSON or JSONC file text to strip and parse.
 * @returns Parsed root object, or `undefined` when parsing fails or the root is not a plain object.
 */
function parseJsonObject(source: string): Record<string, unknown> | undefined {
  try {
    return objectValue(JSON.parse(jsonParseSource(source)));
  } catch {
    return undefined;
  }
}

/**
 * Locates the first quoted key followed by a colon in `source` for approximate finding locations.
 * Nested keys and text inside comments can match; a missing match falls back to line 1.
 *
 * @param source - Raw JSON or JSONC text to scan.
 * @param key - Unescaped property name to find before a colon.
 * @returns One-based line number of the first match, or `1` when absent.
 */
function jsonKeyLine(source: string, key: string): number {
  const escapedKey = escapeRegex(key);
  return firstLine(source, new RegExp(`"${escapedKey}"\\s*:`));
}

/**
 * Finds `packageName` with `versionSpec` in `source` starting from the first `section` key, or from line 1 when `section` is absent.
 * The search can extend beyond `section` and falls back to the first `packageName` key or line 1.
 *
 * @param source - Raw manifest text to search line by line.
 * @param section - Dependency section key where the search begins if present.
 * @param packageName - Dependency name to match alongside its version specifier.
 * @param versionSpec - Dependency version or URL specifier paired with `packageName`.
 * @returns One-based line number of the matched dependency entry, or the key-only fallback line.
 */
function dependencyEntryLine(source: string, section: string, packageName: string, versionSpec: string): number {
  const lines = source.split(/\r?\n/);
  const sectionStart = Math.max(lines.findIndex((line) => new RegExp(`"${escapeRegex(section)}"\\s*:`).test(line)), 0);
  const entry = new RegExp(`${escapeRegex(JSON.stringify(packageName))}\\s*:\\s*${escapeRegex(JSON.stringify(versionSpec))}`);
  const offset = lines.slice(sectionStart).findIndex((line) => entry.test(line));
  return offset >= 0 ? sectionStart + offset + 1 : jsonKeyLine(source, packageName);
}

/**
 * Reports whether `command` downloads an HTTP(S) URL via `curl` or `wget` and pipes it to `sh`, `bash`, or `zsh`, optionally via `sudo`.
 * The pattern stops at shell separators or a newline before that pipe to avoid matching across commands.
 *
 * @param command - Package script command text to inspect.
 * @returns True when `command` matches the remote install pipeline pattern; false otherwise.
 */
function isRemoteInstallScript(command: string): boolean {
  return /\b(?:curl|wget)\b[^\n|;&]*https?:\/\/[^\n|;&]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b/i.test(command);
}

/**
 * Reports whether `versionSpec` starts with a recognized URL, Git, or local file prefix or matches a bare repository shortcut.
 *
 * @param versionSpec - Dependency specifier value from `package.json`.
 * @returns True when `versionSpec` resolves outside the standard package registry; false otherwise.
 */
function isUrlDependency(versionSpec: string): boolean {
  return /^(?:https?:\/\/|git(?:\+https?|\+ssh)?:\/\/|ssh:\/\/|github:|gitlab:|bitbucket:|file:|git@[^:]+:[^/]+\/|[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:#.+)?$)/i.test(versionSpec);
}

/**
 * Reports whether `versionSpec` matches the broad-version heuristic after trimming and case folding.
 * Matches bare `*`, `x`, or `latest`, any `||`, or a leading `>=` followed by optional whitespace and a digit with no `<` anywhere.
 *
 * @param versionSpec - Dependency version specifier to evaluate.
 * @returns True when `versionSpec` represents an unbounded or overly broad range; false otherwise.
 */
function isBroadRuntimeVersion(versionSpec: string): boolean {
  const normalized = versionSpec.trim().toLowerCase();
  return normalized === "*" || normalized === "x" || normalized === "latest" || (/^>=\s*\d/.test(normalized) && !normalized.includes("<")) || normalized.includes("||");
}

/**
 * Strips a leading BOM, JSONC comments, and trailing commas from `source` while keeping LF line breaks for `JSON.parse`.
 *
 * @param source - Raw JSON or JSONC input text.
 * @returns Normalized JSON text ready for `JSON.parse`.
 */
function jsonParseSource(source: string): string {
  return stripJsonTrailingCommas(stripJsonComments(source.replace(/^\uFEFF/, "")));
}

/**
 * Replaces line and block comments outside strings in `source` with spaces while preserving LF line breaks.
 * Keeps output length unchanged so each character outside a comment stays at its original offset in this step.
 *
 * @param source - JSONC text that may contain line or block comments and string literals.
 * @returns Text of the same length with non-string comments replaced by spaces and preserved newlines.
 */
function stripJsonComments(source: string): string {
  let result = "";
  const quoteState: JsonQuoteState = { quote: "", isEscaped: false };
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index] ?? "";
    const next = source[index + 1] ?? "";
    if (!quoteState.quote && character === "/" && next === "/") {
      const comment = lineCommentSpan(source, index);
      result += comment.replacement;
      index = comment.endIndex;
      continue;
    }
    if (!quoteState.quote && character === "/" && next === "*") {
      const comment = blockCommentSpan(source, index);
      result += comment.replacement;
      index = comment.endIndex;
      continue;
    }
    updateJsonQuoteState(character, quoteState);
    result += character;
  }
  return result;
}

/**
 * Scans `source` from a line comment's `startIndex` up to (but not including) the next newline so the caller retains the newline.
 * A line comment reaching EOF ends at `source.length - 1`.
 *
 * @param source - JSONC source text being stripped of comments.
 * @param startIndex - Index of the opening slash of the line comment.
 * @returns Equal-width space replacement string and the last replaced index (`endIndex`).
 */
function lineCommentSpan(source: string, startIndex: number): { replacement: string; endIndex: number } {
  let endIndex = startIndex;
  while (endIndex < source.length && source[endIndex] !== "\n") {
    endIndex += 1;
  }
  return { replacement: " ".repeat(endIndex - startIndex), endIndex: endIndex - 1 };
}

/**
 * Computes replacement text for a block comment while preserving every newline encountered across multi-line comments.
 * Turns unterminated block comments into spaces through EOF because malformed JSONC should simply reach `JSON.parse` failure.
 *
 * @param source - JSONC source text being stripped of comments.
 * @param startIndex - Index of the opening slash of the block comment.
 * @returns Space-and-newline replacement string and the index of the closing slash or EOF (`endIndex`).
 */
function blockCommentSpan(source: string, startIndex: number): { replacement: string; endIndex: number } {
  let endIndex = startIndex + 2;
  let replacement = "  ";
  while (endIndex < source.length) {
    const character = source[endIndex] ?? "";
    const next = source[endIndex + 1] ?? "";
    if (character === "*" && next === "/") {
      return { replacement: `${replacement}  `, endIndex: endIndex + 1 };
    }
    replacement += character === "\n" ? "\n" : " ";
    endIndex += 1;
  }
  return { replacement, endIndex: source.length - 1 };
}

/**
 * Removes commas followed only by whitespace and a JSON object or array closer, using quote state to preserve commas inside string literals.
 *
 * @param source - Comment-stripped JSON text that may contain trailing commas.
 * @returns JSON text with structural trailing commas removed.
 */
function stripJsonTrailingCommas(source: string): string {
  let result = "";
  const quoteState: JsonQuoteState = { quote: "", isEscaped: false };
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index] ?? "";
    updateJsonQuoteState(character, quoteState);
    if (!quoteState.quote && character === "," && isJsonClosingTokenAhead(source, index + 1)) {
      continue;
    }
    result += character;
  }
  return result;
}

/**
 * Scans ahead in `source` from `startIndex` to determine whether a comma precedes an object or array closing token.
 *
 * @param source - Comment-stripped JSON text being scanned for trailing commas.
 * @param startIndex - Index immediately after the candidate comma.
 * @returns True if the next non-whitespace character is `}` or `]`; false for any other token or end of input.
 */
function isJsonClosingTokenAhead(source: string, startIndex: number): boolean {
  for (let index = startIndex; index < source.length; index += 1) {
    const character = source[index] ?? "";
    if (!/\s/.test(character)) {
      return character === "}" || character === "]";
    }
  }
  return false;
}

// Minimal JSON string lexer state shared by comment and trailing-comma stripping passes.
interface JsonQuoteState {
  quote: string;
  isEscaped: boolean;
}

/**
 * Consumes `character` and mutates `quoteState` to track JSON string membership and whether the next character is escaped.
 * Preserves comment-like and comma-like text inside strings for callers.
 *
 * @param character - Single character at the current scan position.
 * @param quoteState - Mutable lexer state tracking active quote delimiter and escape flag.
 * @returns Nothing. Updates `quoteState` in place.
 */
function updateJsonQuoteState(character: string, quoteState: JsonQuoteState): void {
  if (!quoteState.quote && character === "\"") {
    quoteState.quote = character;
    return;
  }
  if (!quoteState.quote) {
    return;
  }
  if (quoteState.isEscaped) {
    quoteState.isEscaped = false;
  } else if (character === "\\") {
    quoteState.isEscaped = true;
  } else if (character === quoteState.quote) {
    quoteState.quote = "";
  }
}

/**
 * Extracts command/target pairs from `pkg.bin`, defaulting string declarations to `pkg.name` or `"bin"` when `pkg.name` is not a string.
 * Missing or invalid `bin` declarations yield no pairs, and non-string targets are dropped.
 *
 * @param pkg - Parsed `package.json` manifest object.
 * @returns Array of `[command, target]` tuples for valid string bin targets.
 */
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

/**
 * Escapes regular-expression metacharacters in `rawText` so callers can match it literally.
 *
 * @param rawText - Literal text to embed into a `RegExp` pattern.
 * @returns Escaped string safe for literal regex matching.
 */
function escapeRegex(rawText: string): string {
  return rawText.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export { analyseProjectConfigRules };
