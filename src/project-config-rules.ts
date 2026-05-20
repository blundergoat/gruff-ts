import { existsSync, statSync } from "node:fs";
import { basename, dirname as dirnamePath, isAbsolute, join } from "node:path";
import { isString, objectValue } from "./config.ts";
import { makeFinding } from "./findings.ts";
import { firstLine } from "./text-scans.ts";
import type { Finding } from "./types.ts";

// Both paths are required: `displayPath` anchors findings, `absolutePath` resolves bin targets
// against the owning package.json. Diverging them would break bin-existence checks on Windows.
interface ConfigSourceFile {
  absolutePath: string;
  displayPath: string;
}

/*
 * Dispatcher for package.json / tsconfig.json health rules. Only these two filenames are inspected;
 * any other JSON files in the project are out of scope to keep the rule surface bounded. The
 * stable, deterministic Finding[] emission order is what makes baselines reproducible.
 */
function analyseProjectConfigRules(file: ConfigSourceFile, source: string, findings: Finding[]): void {
  const name = basename(file.displayPath);
  if (name !== "package.json" && name !== "tsconfig.json") {
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

// Three sub-pillars in fixed order (scripts → dependencies → bins). This deterministic order is
// the stable emission contract that lets fingerprints survive cosmetic reorderings of package.json.
function analysePackageJson(file: ConfigSourceFile, source: string, pkg: Record<string, unknown>, findings: Finding[]): void {
  analysePackageScripts(file, source, objectValue(pkg.scripts), findings);
  analysePackageDependencies(file, source, pkg, findings);
  analysePackageBins(file, source, pkg, findings);
}

/*
 * Iterates `package.json#scripts` in declaration order — the stable Finding[] emission contract
 * relies on this. Each script is funnelled through both the remote-installer and lifecycle-script
 * checks because one script can match both.
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
    pushLifecycleScriptFinding(file, source, scriptName, findings);
  }
}

/*
 * Reports `security.remote-install-script` for `curl|wget … | sh` patterns. Severity is `error`
 * because remote shell execution at install time is a contract red flag in the modern supply-chain
 * landscape.
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

/*
 * Reports the stable `security.risky-lifecycle-script` finding for any preinstall/install/
 * postinstall/prepare/prepublish/prepublishOnly hook — these run automatically and even disabling
 * install scripts in npm config is not universally honoured. Flagged as `warning` rather than
 * `error` because some packages legitimately need them.
 */
function pushLifecycleScriptFinding(file: ConfigSourceFile, source: string, scriptName: string, findings: Finding[]): void {
  if (!isLifecycleScript(scriptName)) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "security.risky-lifecycle-script",
      message: `Package lifecycle script \`${scriptName}\` runs automatically during install or publish flows.`,
      filePath: file.displayPath,
      line: jsonKeyLine(source, scriptName),
      severity: "warning",
      pillar: "security",
      confidence: "medium",
      symbol: scriptName,
      remediation: "Move setup behind an explicit command unless lifecycle execution is required.",
      metadata: { scriptName },
    }),
  );
}

/*
 * Walks every dependency section in a stable, deterministic order. `runtimeDependency` flag
 * separates devDependencies from the rest because the broad-version rule should only fire for
 * runtime drift.
 */
function analysePackageDependencies(file: ConfigSourceFile, source: string, pkg: Record<string, unknown>, findings: Finding[]): void {
  for (const section of ["dependencies", "optionalDependencies", "peerDependencies", "devDependencies"]) {
    const dependencies = objectValue(pkg[section]);
    if (!dependencies) {
      continue;
    }
    const runtimeDependency = section !== "devDependencies";
    for (const [packageName, value] of Object.entries(dependencies)) {
      if (isString(value)) {
        analysePackageDependency(file, source, section, packageName, value, runtimeDependency, findings);
      }
    }
  }
}

function analysePackageDependency(
  file: ConfigSourceFile,
  source: string,
  section: string,
  packageName: string,
  versionSpec: string,
  runtimeDependency: boolean,
  findings: Finding[],
): void {
  pushUrlDependencyFinding(file, source, section, packageName, versionSpec, runtimeDependency, findings);
  pushBroadRuntimeDependencyFinding(file, source, section, packageName, versionSpec, runtimeDependency, findings);
}

function pushUrlDependencyFinding(
  file: ConfigSourceFile,
  source: string,
  section: string,
  packageName: string,
  versionSpec: string,
  runtimeDependency: boolean,
  findings: Finding[],
): void {
  if (!isUrlDependency(versionSpec)) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "security.url-dependency",
      message: `Dependency \`${packageName}\` in \`${section}\` installs from a URL or git spec.`,
      filePath: file.displayPath,
      line: jsonKeyLine(source, packageName),
      severity: "warning",
      pillar: "security",
      confidence: "medium",
      symbol: packageName,
      remediation: "Prefer a registry package version that can be locked and audited.",
      metadata: { packageName, section, runtimeDependency },
    }),
  );
}

function pushBroadRuntimeDependencyFinding(
  file: ConfigSourceFile,
  source: string,
  section: string,
  packageName: string,
  versionSpec: string,
  runtimeDependency: boolean,
  findings: Finding[],
): void {
  if (!runtimeDependency || !isBroadRuntimeVersion(versionSpec)) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "waste.broad-runtime-version",
      message: `Runtime dependency \`${packageName}\` uses overly broad version spec \`${versionSpec}\`.`,
      filePath: file.displayPath,
      line: jsonKeyLine(source, packageName),
      severity: "advisory",
      pillar: "waste",
      confidence: "medium",
      symbol: packageName,
      remediation: "Use a bounded semver range and rely on the lockfile for repeatable installs.",
      metadata: { packageName, section, versionSpec },
    }),
  );
}

/*
 * Expands `bin` into (command, target) pairs (handling both string and object forms), then checks
 * each one in a deterministic, stable order. Returns nothing when `bin` is absent — the rule does
 * not require packages to ship CLIs.
 */
function analysePackageBins(file: ConfigSourceFile, source: string, pkg: Record<string, unknown>, findings: Finding[]): void {
  for (const [command, target] of packageBinEntries(pkg)) {
    analysePackageBin(file, source, command, target, findings);
  }
}

/*
 * Reads the bin target from disk. The stable mapping: missing → `package-bin-missing`;
 * non-executable → `package-bin-not-executable`. Executable files pass silently so the rule cannot
 * fail a healthy install pipeline.
 */
function analysePackageBin(file: ConfigSourceFile, source: string, command: string, target: string, findings: Finding[]): void {
  const absolute = packageBinPath(file, target);
  if (!existsSync(absolute)) {
    pushMissingPackageBinFinding(file, source, command, target, findings);
    return;
  }
  const stats = statSync(absolute);
  if (!stats.isFile() || (stats.mode & 0o111) === 0) {
    pushNonExecutablePackageBinFinding(file, source, command, target, findings);
  }
}

// Bin targets are resolved against the directory of the owning package.json, not the project root.
// Required because workspace packages can live in subdirectories and have their own bins.
function packageBinPath(file: ConfigSourceFile, target: string): string {
  return isAbsolute(target) ? target : join(dirnamePath(file.absolutePath), target);
}

/*
 * Reports the `design.package-bin-missing` finding for a declared bin whose file does not exist
 * on disk — emitted with stable command + target metadata that other tooling can key off.
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

/*
 * Reports the stable `design.package-bin-not-executable` finding — the file exists but lacks the
 * execute bit. Common on Windows checkouts; the remediation message reminds maintainers to also
 * keep the shebang valid.
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

// Single makeFinding call site for both bin-missing and bin-not-executable. The `command` symbol
// is what the fingerprint anchors on, so renaming a bin entry intentionally invalidates the baseline.
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

/*
 * Three TypeScript strictness flags whose absence is a documentation-worthy compromise: `strict`,
 * `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`. Reports each missing flag as its own
 * finding; the list is intentionally short — adding new flags here changes the rule surface and
 * warrants a schema discussion.
 */
function analyseTsconfigJson(file: ConfigSourceFile, source: string, tsconfigData: Record<string, unknown>, findings: Finding[]): void {
  const compilerOptions = objectValue(tsconfigData.compilerOptions) ?? {};
  const checks: Array<[string, string, string]> = [
    ["strict", "modernisation.tsconfig-strict-disabled", "`strict` is disabled, reducing TypeScript's baseline safety checks."],
    ["noUncheckedIndexedAccess", "modernisation.tsconfig-index-safety-disabled", "`noUncheckedIndexedAccess` is disabled, so indexed reads can silently ignore undefined."],
    ["exactOptionalPropertyTypes", "modernisation.tsconfig-exact-optional-disabled", "`exactOptionalPropertyTypes` is disabled, weakening optional property contracts."],
  ];
  for (const [optionName, ruleId, message] of checks) {
    if (compilerOptions[optionName] !== true) {
      findings.push(
        tsconfigFinding({
          file,
          source,
          ruleId,
          message,
          optionName,
          currentValue: compilerOptions[optionName] ?? null,
        }),
      );
    }
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

// Single makeFinding site for tsconfig strictness findings. `optionName` is the symbol anchor and
// `currentValue` is preserved verbatim in metadata for downstream tooling — both are part of the stable contract.
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
 * Swallows parse errors and returns undefined as a fallback so a malformed package.json doesn't
 * fail the whole analysis run — the rest of the file scan continues.
 */
function parseJsonObject(source: string): Record<string, unknown> | undefined {
  try {
    return objectValue(JSON.parse(source));
  } catch {
    return undefined;
  }
}

// Approximate line lookup — finds the first `"key":` occurrence. JSON allows the same key in
// nested objects, but for package.json/tsconfig the top-level keys we report on are unique.
function jsonKeyLine(source: string, key: string): number {
  const escapedKey = escapeRegex(key);
  return firstLine(source, new RegExp(`"${escapedKey}"\\s*:`));
}

// Pattern matches `curl|wget … | sh` or its inline-pipe variants. The negative lookaheads for `|`,
// `;`, `&` prevent overlong matches that would span multiple shell commands.
function isRemoteInstallScript(command: string): boolean {
  return /\b(?:curl|wget)\b[^\n|;&]*https?:\/\/[^\n|;&]*(?:\|\s*(?:sh|bash|zsh)\b|\b(?:sh|bash|zsh)\b)/i.test(command);
}

// The closed list of npm/yarn/pnpm install-time hooks. Adding entries here expands rule coverage.
function isLifecycleScript(scriptName: string): boolean {
  return ["preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly"].includes(scriptName);
}

// Recognises non-registry installs: full URLs, git+ssh, and the github:/gitlab:/bitbucket: shortcuts
// npm supports. These specs cannot be reproducibly locked the way registry versions can.
function isUrlDependency(versionSpec: string): boolean {
  return /^(?:https?:\/\/|git(?:\+https?|\+ssh)?:\/\/|ssh:\/\/|github:|gitlab:|bitbucket:)/i.test(versionSpec);
}

// Catches `*`, `x`, `latest`, unbounded `>=` ranges, and OR-joined ranges. All let dependency
// resolution drift arbitrarily — lockfile or not, the declared intent is "anything goes".
function isBroadRuntimeVersion(versionSpec: string): boolean {
  const normalized = versionSpec.trim().toLowerCase();
  return normalized === "*" || normalized === "x" || normalized === "latest" || /^>=\s*\d/.test(normalized) || normalized.includes("||");
}

// Normalises both npm bin forms: a string (uses the package name as the command) and an object
// (each key is a command name). Non-string entries are silently dropped because nothing valid can
// be done with them.
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

// Local copy of the regex-escape helper — `discovery.ts` has its own copy because this module
// is intentionally a leaf with no cross-module dependency on path helpers.
function escapeRegex(rawText: string): string {
  return rawText.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export { analyseProjectConfigRules };
