import { existsSync, statSync } from "node:fs";
import { basename, dirname as dirnamePath, isAbsolute, join } from "node:path";
import { isString, objectValue } from "./config.ts";
import { makeFinding } from "./findings.ts";
import { firstLine } from "./text-scans.ts";
import type { Finding } from "./types.ts";

interface ConfigSourceFile {
  absolutePath: string;
  displayPath: string;
}

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

function analysePackageJson(file: ConfigSourceFile, source: string, pkg: Record<string, unknown>, findings: Finding[]): void {
  analysePackageScripts(file, source, objectValue(pkg.scripts), findings);
  analysePackageDependencies(file, source, pkg, findings);
  analysePackageBins(file, source, pkg, findings);
}

function analysePackageScripts(file: ConfigSourceFile, source: string, scripts: Record<string, unknown> | undefined, findings: Finding[]): void {
  if (!scripts) {
    return;
  }
  for (const [scriptName, value] of Object.entries(scripts)) {
    if (!isString(value)) {
      continue;
    }
    pushRemoteInstallScriptFinding(file, source, scriptName, value, findings);
    pushLifecycleScriptFinding(file, source, scriptName, findings);
  }
}

function pushRemoteInstallScriptFinding(file: ConfigSourceFile, source: string, scriptName: string, value: string, findings: Finding[]): void {
  if (!isRemoteInstallScript(value)) {
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

function analysePackageBins(file: ConfigSourceFile, source: string, pkg: Record<string, unknown>, findings: Finding[]): void {
  for (const [command, target] of packageBinEntries(pkg)) {
    analysePackageBin(file, source, command, target, findings);
  }
}

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

function packageBinPath(file: ConfigSourceFile, target: string): string {
  return isAbsolute(target) ? target : join(dirnamePath(file.absolutePath), target);
}

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

interface PackageBinFindingInput {
  file: ConfigSourceFile;
  source: string;
  ruleId: string;
  message: string;
  command: string;
  target: string;
  remediation: string;
}

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

function analyseTsconfigJson(file: ConfigSourceFile, source: string, data: Record<string, unknown>, findings: Finding[]): void {
  const compilerOptions = objectValue(data.compilerOptions) ?? {};
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

interface TsconfigFindingInput {
  file: ConfigSourceFile;
  source: string;
  ruleId: string;
  message: string;
  optionName: string;
  currentValue: unknown;
}

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

function parseJsonObject(source: string): Record<string, unknown> | undefined {
  try {
    return objectValue(JSON.parse(source));
  } catch {
    return undefined;
  }
}

function jsonKeyLine(source: string, key: string): number {
  const escapedKey = escapeRegex(key);
  return firstLine(source, new RegExp(`"${escapedKey}"\\s*:`));
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

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export { analyseProjectConfigRules };
