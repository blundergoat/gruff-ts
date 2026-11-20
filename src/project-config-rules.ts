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

// Returns true for the filename tsconfig.json or a named variant such as tsconfig.base.json.
// This keeps shared and workspace configs subject to the same strictness checks as the root config.
function isTsconfigFileName(name: string): boolean {
  return name === "tsconfig.json" || /^tsconfig\.[^.]+(?:\.[^.]+)*\.json$/.test(name);
}

// Runs script, dependency and bin checks in that order to preserve the stable order of finding groups.
// The file identifies the manifest, its text locates declarations, and the parsed package supplies the fields to check.
// Returns nothing. Appends any reported findings to the supplied list.
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

// Checks one dependency for a URL spec, then checks for a broad spec when the runtime flag is set, to preserve stable finding order.
// The manifest supplies the reported path. Its text is searched by section, name and version for URL findings and by name for broad versions.
// Returns nothing. Appends any matching findings to the supplied list.
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

// Appends one stable security.url-dependency finding for recognized URL, Git or file specs because they bypass normal registry auditing.
// Uses the manifest path and text to locate the entry by section, name and version, with a name-only fallback. Records the runtime flag.
// Returns nothing. Other version specs leave the supplied findings list unchanged.
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

// Under the stable waste.broad-runtime-version contract, flags broad specs such as *, x or latest for entries marked as runtime.
// The manifest and its text locate the dependency. The section, package name and version identify it in finding metadata.
// Returns nothing. Appends to the supplied findings list only when the runtime flag and broad-version check both qualify the entry.
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
 * @param pkg - parsed manifest supplying the bin declaration and the name for a string bin, which defaults to bin
 * @param findings - destination for findings raised by the target checks
 * @returns Nothing. Appends any findings from checking the declared targets.
 */
function analysePackageBins(file: ConfigSourceFile, source: string, pkg: Record<string, unknown>, findings: Finding[]): void {
  for (const [command, target] of packageBinEntries(pkg)) {
    analysePackageBin(file, source, command, target, findings);
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
 * @param findings - destination for any finding raised by this check
 * @returns Nothing. Appends a finding for a missing target or, outside Windows, a target that is not an executable file.
 */
function analysePackageBin(file: ConfigSourceFile, source: string, command: string, target: string, findings: Finding[]): void {
  const absolute = packageBinPath(file, target);
  if (!existsSync(absolute)) {
    pushMissingPackageBinFinding(file, source, command, target, findings);
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

// Returns absolute bin targets unchanged and resolves relative ones against the owning package.json directory.
// Required because workspace packages can live in subdirectories and have their own bins.
function packageBinPath(file: ConfigSourceFile, target: string): string {
  return isAbsolute(target) ? target : join(dirnamePath(file.absolutePath), target);
}

/**
 * Records design.package-bin-missing for a declared CLI whose target is missing, with stable command and target metadata.
 *
 * @param file - package manifest whose path is reported
 * @param source - manifest text used to locate the bin declaration
 * @param command - declared CLI name recorded in the finding
 * @param target - missing path as declared in the manifest
 * @param findings - destination for the finding
 * @returns Nothing. Appends the finding to the supplied list.
 */
function pushMissingPackageBinFinding(file: ConfigSourceFile, source: string, command: string, target: string, findings: Finding[]): void {
  findings.push(
    packageBinFinding({
      file,
      source,
      ruleId: "design.package-bin-missing",
      message: `Package bin \`${command}\` points to missing file \`${target}\`.`,
      command,
      target,
      remediation: "Update the bin path or add the executable file.",
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
      remediation: "Make the bin target executable and keep its shebang valid.",
    }),
  );
}

// Argument bundle for `packageBinFinding`. Grouped into a struct because the helper accepts seven
// fields and an inline parameter list would silently break call sites on field shuffles.
interface PackageBinFindingInput {
  file: ConfigSourceFile;
  source: string;
  ruleId: string;
  message: string;
  command: string;
  target: string;
  remediation: string;
}

// Returns the missing-bin or non-executable-bin finding described by input, including its package location and remediation.
// The command symbol contributes to the fingerprint, so renaming a bin entry changes its baseline identity.
function packageBinFinding(input: PackageBinFindingInput): Finding {
  return makeFinding({
    ruleId: input.ruleId,
    message: input.message,
    filePath: input.file.displayPath,
    line: jsonKeyLine(input.source, input.command),
    severity: "warning",
    pillar: "design",
    confidence: "high",
    symbol: input.command,
    remediation: input.remediation,
    metadata: { command: input.command, target: input.target },
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

// Returns a strictness finding from the supplied tsconfig file, source text, rule details and observed option value.
// The source locates the option key. The stable contract uses optionName as the symbol and retains currentValue in metadata.
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

/*
 * Parses source as JSONC and returns its object root; malformed text and non-object roots return undefined so these rules skip the file.
 * Parse failures stay unlogged because this rule pass only emits findings for successfully decoded objects.
 */
function parseJsonObject(source: string): Record<string, unknown> | undefined {
  try {
    return objectValue(JSON.parse(jsonParseSource(source)));
  } catch {
    return undefined;
  }
}

// Returns the one-based line of the first quoted key followed by a colon in source for approximate finding locations.
// Nested keys and text inside comments can match; a missing match falls back to line 1.
function jsonKeyLine(source: string, key: string): number {
  const escapedKey = escapeRegex(key);
  return firstLine(source, new RegExp(`"${escapedKey}"\\s*:`));
}

// Finds packageName with versionSpec in source from the first section key, or from the start when section is absent.
// Returns a one-based line; falls back to the first packageName key or line 1, and the search can extend beyond section.
function dependencyEntryLine(source: string, section: string, packageName: string, versionSpec: string): number {
  const lines = source.split(/\r?\n/);
  const sectionStart = Math.max(lines.findIndex((line) => new RegExp(`"${escapeRegex(section)}"\\s*:`).test(line)), 0);
  const entry = new RegExp(`${escapeRegex(JSON.stringify(packageName))}\\s*:\\s*${escapeRegex(JSON.stringify(versionSpec))}`);
  const offset = lines.slice(sectionStart).findIndex((line) => entry.test(line));
  return offset >= 0 ? sectionStart + offset + 1 : jsonKeyLine(source, packageName);
}

// Returns true if the supplied command matches curl|wget … | sh with an HTTP(S) URL and optional sudo before sh, bash or zsh.
// The pattern stops at shell separators or a newline before that pipe to avoid matching across commands.
function isRemoteInstallScript(command: string): boolean {
  return /\b(?:curl|wget)\b[^\n|;&]*https?:\/\/[^\n|;&]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b/i.test(command);
}

// Returns true if versionSpec starts with a recognized URL, Git or file prefix or matches a bare repository shortcut.
function isUrlDependency(versionSpec: string): boolean {
  return /^(?:https?:\/\/|git(?:\+https?|\+ssh)?:\/\/|ssh:\/\/|github:|gitlab:|bitbucket:|file:|git@[^:]+:[^/]+\/|[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:#.+)?$)/i.test(versionSpec);
}

// Returns whether versionSpec matches the broad-version heuristic after trimming and case folding.
// It matches bare *, x or latest, any ||, or a leading >= followed by optional whitespace and a digit with no < anywhere.
function isBroadRuntimeVersion(versionSpec: string): boolean {
  const normalized = versionSpec.trim().toLowerCase();
  return normalized === "*" || normalized === "x" || normalized === "latest" || (/^>=\s*\d/.test(normalized) && !normalized.includes("<")) || normalized.includes("||");
}

// Returns source with a leading BOM, JSONC comments and trailing commas removed.
// Keeps LF line breaks in the text passed to JSON.parse.
function jsonParseSource(source: string): string {
  return stripJsonTrailingCommas(stripJsonComments(source.replace(/^\uFEFF/, "")));
}

// Replaces line and block comments outside strings in source with spaces and preserves LF line breaks.
// Returns text of the same length so that each character outside a comment stays at its original offset in this step.
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

// Scans source from a line comment's startIndex and returns equal-width spaces plus the last replaced index as endIndex.
// The newline is left for the caller to retain; a comment at EOF ends at source.length - 1.
function lineCommentSpan(source: string, startIndex: number): { replacement: string; endIndex: number } {
  let endIndex = startIndex;
  while (endIndex < source.length && source[endIndex] !== "\n") {
    endIndex += 1;
  }
  return { replacement: " ".repeat(endIndex - startIndex), endIndex: endIndex - 1 };
}

// Replacement text for a block comment, preserving every newline encountered. The character loop
// exists because block comments can span lines; fallback behaviour turns unterminated comments into
// spaces through EOF because malformed JSONC should simply reach JSON.parse failure.
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

// Removes commas that are followed only by whitespace and a JSON object/array closer. Quote state
// prevents commas inside string literals from being treated as structural punctuation.
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

// Looks through source from startIndex for trailing-comma removal.
// Returns true if the next non-whitespace character is } or ]; returns false for another token or end of input.
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

// Consumes character and mutates quoteState to track JSON string membership and whether the next character is escaped.
// Returns no value after updating the scan state so that callers preserve comment-like and comma-like text inside strings.
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

// Returns command/target pairs from pkg.bin: a string uses pkg.name, or bin when that name is not a string.
// Object keys supply command names; missing or invalid bin declarations yield no pairs, and non-string targets are dropped.
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

// Returns rawText with regular-expression metacharacters escaped so callers can match it literally.
function escapeRegex(rawText: string): string {
  return rawText.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export { analyseProjectConfigRules };
