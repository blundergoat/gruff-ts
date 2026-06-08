// gruff.hook.v1 adapter: owns the agent-hook JSON shape without changing gruff.analysis.v2.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { chdir, cwd } from "node:process";
import { tmpdir } from "node:os";
import { absolutize } from "./discovery.ts";
import { VERSION } from "./constants.ts";
import { ruleDescriptors } from "./rules.ts";
import type { AnalysisOptions, AnalysisReport, Finding, Severity, SkippedPath } from "./types.ts";

type HookScope = "line" | "symbol" | "file" | "project";
type FlagOrder = "any" | "flags-before-path";
type HookAnalysisRunner = (options: AnalysisOptions) => AnalysisReport;

interface HookReportInput {
  currentOptions: AnalysisOptions;
  scopedOptions: AnalysisOptions;
  baselinePath?: string;
  diffBase?: string;
  hasChangedRegion: boolean;
}

interface HookReport {
  contractVersion: "gruff.hook.v1";
  analyzer: { name: "gruff-ts"; version: string };
  findings: HookFinding[];
  suppressed: { count: number };
  ignored: { paths: SkippedPath[] };
  config: { schemaOk: boolean; error: string | null };
}

interface HookFinding {
  ruleId: string;
  pillar: string;
  severity: Severity;
  scope: HookScope;
  file: string;
  line?: number;
  endLine?: number;
  symbol: string | null;
  message: string;
  remediation: string;
  metadata: Record<string, unknown>;
  stableIdentity: string;
  fingerprint: string;
}

interface BaselineEntry {
  stableIdentity?: string;
  ruleId?: string;
  filePath?: string;
  symbol?: string;
  message?: string;
}

const CONTRACT_VERSION = "gruff.hook.v1";
const FILE_SCOPE_RULE_IDS = new Set(["design.large-module-concentration", "docs.missing-file-overview", "size.file-length"]);
const PROJECT_SCOPE_RULE_IDS = new Set(["design.circular-import"]);
const SEVERITY_RANK: Record<Severity, number> = { error: 0, warning: 1, advisory: 2 };
const DESCRIPTORS = new Map(ruleDescriptors().map((descriptor) => [descriptor.ruleId, descriptor]));

export function renderHookCapabilities(): string {
  return `${JSON.stringify({
    contractVersion: CONTRACT_VERSION,
    analyzer: analyzerInfo(),
    supports: {
      changedRanges: true,
      diff: true,
      baseline: true,
      scopeField: true,
      metadata: true,
      stableIdentity: true,
      ignoreReport: true,
      newOnly: true,
    },
    flags: { changedRanges: "--changed-ranges", diff: "--diff", baseline: "--baseline" },
    flagOrder: "any" satisfies FlagOrder,
  }, null, 2)}\n`;
}

export function renderHookReport(runAnalyse: HookAnalysisRunner, input: HookReportInput): string {
  const currentReport = runAnalyse(input.currentOptions);
  const scopedReport = input.hasChangedRegion ? runAnalyse(input.scopedOptions) : currentReport;
  const baseIdentities = hookBaseIdentities(runAnalyse, input, currentReport);
  const findings = hookFindings(currentReport, scopedReport, input.hasChangedRegion, baseIdentities);
  const suppressedCount = hookSuppressedCount(scopedReport, input.hasChangedRegion);
  return `${JSON.stringify(hookReport(scopedReport, findings, suppressedCount, true, null), null, 2)}\n`;
}

export function renderHookConfigError(message: string, remediation: string): string {
  return `${JSON.stringify(hookReport(undefined, [], 0, false, `${message}\nSuggested fix: ${remediation}`), null, 2)}\n`;
}

function hookReport(report: AnalysisReport | undefined, findings: HookFinding[], suppressedCount: number, schemaOk: boolean, error: string | null): HookReport {
  return {
    contractVersion: CONTRACT_VERSION,
    analyzer: analyzerInfo(),
    findings: sortHookFindings(findings),
    suppressed: { count: suppressedCount },
    ignored: { paths: report?.paths.skipped ?? [] },
    config: { schemaOk, error },
  };
}

function analyzerInfo(): { name: "gruff-ts"; version: string } {
  return { name: "gruff-ts", version: VERSION };
}

function hookFindings(
  currentReport: AnalysisReport,
  scopedReport: AnalysisReport,
  hasChangedRegion: boolean,
  baseIdentities: Set<string> | undefined,
): HookFinding[] {
  const scopedFindings = scopedReport.findings
    .map(toHookFinding)
    .filter((finding) => !hasChangedRegion || (finding.scope !== "file" && finding.scope !== "project"));
  const withNewFileAndProject = hasChangedRegion && baseIdentities
    ? [...scopedFindings, ...newFileAndProjectFindings(currentReport, scopedFindings, baseIdentities)]
    : scopedFindings;
  return baseIdentities ? withNewFileAndProject.filter((finding) => !baseIdentities.has(finding.stableIdentity)) : withNewFileAndProject;
}

function newFileAndProjectFindings(currentReport: AnalysisReport, scopedFindings: HookFinding[], baseIdentities: Set<string>): HookFinding[] {
  const alreadyIncluded = new Set(scopedFindings.map((finding) => finding.fingerprint));
  return currentReport.findings
    .map(toHookFinding)
    .filter((finding) => (finding.scope === "file" || finding.scope === "project") && !baseIdentities.has(finding.stableIdentity) && !alreadyIncluded.has(finding.fingerprint));
}

function hookSuppressedCount(scopedReport: AnalysisReport, hasChangedRegion: boolean): number {
  if (!hasChangedRegion) {
    return 0;
  }
  const fileOrProjectAnchorResiduals = scopedReport.findings.filter((finding) => {
    const scope = scopeForFinding(finding);
    return scope === "file" || scope === "project";
  }).length;
  return (scopedReport.suppressedCount ?? 0) + fileOrProjectAnchorResiduals;
}

function toHookFinding(finding: Finding): HookFinding {
  const scope = scopeForFinding(finding);
  return {
    ruleId: finding.ruleId,
    pillar: finding.pillar,
    severity: finding.severity,
    scope,
    file: finding.filePath,
    ...(finding.line === undefined ? {} : { line: finding.line }),
    ...(finding.endLine === undefined ? {} : { endLine: finding.endLine }),
    symbol: finding.symbol ?? null,
    message: finding.message,
    remediation: finding.remediation ?? DESCRIPTORS.get(finding.ruleId)?.remediation ?? "Review and address this finding.",
    metadata: hookMetadata(finding),
    stableIdentity: hookStableIdentity(finding, scope),
    fingerprint: finding.fingerprint,
  };
}

function scopeForFinding(finding: Finding): HookScope {
  if (PROJECT_SCOPE_RULE_IDS.has(finding.ruleId)) {
    return "project";
  }
  if (FILE_SCOPE_RULE_IDS.has(finding.ruleId)) {
    return "file";
  }
  if (finding.symbol || (finding.endLine !== undefined && finding.line !== undefined && finding.endLine > finding.line)) {
    return "symbol";
  }
  return "line";
}

function hookMetadata(finding: Finding): Record<string, unknown> {
  const thresholdMetadata = thresholdMetadataFor(finding);
  return thresholdMetadata ?? finding.metadata;
}

function thresholdMetadataFor(finding: Finding): Record<string, unknown> | undefined {
  const metadata = finding.metadata;
  switch (finding.ruleId) {
    case "complexity.cognitive":
    case "complexity.cyclomatic":
      return metricMetadata(metadata.complexity, metadata.threshold, "points");
    case "design.deep-relative-import":
      return metricMetadata(metadata.parentSegments, metadata.maxParentSegments, "segments");
    case "design.large-module-concentration":
      return metricMetadata(metadata.sharePercent, metadata.maxSharePercent, "percent");
    case "sensitive-data.hardcoded-env-value":
    case "sensitive-data.high-entropy-string":
      return metricMetadata(metadata.length, metadata.threshold, "characters");
    case "size.file-length":
    case "size.function-length":
      return metricMetadata(metadata.lines, metadata.threshold, "lines");
    case "size.parameter-count":
      return metricMetadata(metadata.parameters, metadata.threshold, "parameters");
  }
  return undefined;
}

function metricMetadata(measured: unknown, threshold: unknown, unit: string): Record<string, unknown> | undefined {
  return typeof measured === "number" && typeof threshold === "number"
    ? { measured, threshold, unit, direction: "above" }
    : undefined;
}

function hookStableIdentity(finding: Finding, scope: HookScope): string {
  const component = stableIdentityComponent(finding, scope);
  return createHash("sha256")
    .update([finding.ruleId, finding.filePath, component].join("\0"))
    .digest("hex")
    .slice(0, 16);
}

function stableIdentityComponent(finding: { message: string; ruleId: string; symbol?: string }, scope: HookScope): string {
  if (scope === "file" || scope === "project") {
    return scope;
  }
  if (finding.symbol && finding.symbol.length > 0) {
    return `symbol:${finding.symbol}`;
  }
  // Symbol-less line findings (e.g. each hardcoded secret) key on the message so several same-rule
  // findings in one file get distinct identities. A value-insensitive `metric:${scope}` token
  // collapsed them all, letting one baselined finding suppress later new ones in the same file. The
  // message carries the per-occurrence discriminator (redacted preview) and no line number, so it
  // stays stable across surrounding edits. file/project scope above remains value-insensitive.
  return `message:${finding.message}`;
}

function hookBaseIdentities(runAnalyse: HookAnalysisRunner, input: HookReportInput, currentReport: AnalysisReport): Set<string> | undefined {
  const identities = new Set<string>();
  if (input.baselinePath) {
    for (const identity of stableIdentitiesFromBaseline(input.baselinePath)) {
      identities.add(identity);
    }
  }
  if (input.diffBase) {
    for (const identity of stableIdentitiesFromDiffBase(runAnalyse, input.currentOptions, input.diffBase, currentReport)) {
      identities.add(identity);
    }
  }
  return identities.size > 0 || input.baselinePath || input.diffBase ? identities : undefined;
}

function stableIdentitiesFromBaseline(path: string): Set<string> {
  const baselinePath = absolutize(cwd(), path);
  const baseline = JSON.parse(readFileSync(baselinePath, "utf8")) as { schemaVersion?: string; entries?: BaselineEntry[] };
  if (baseline.schemaVersion !== "gruff.baseline.v1") {
    throw new Error(`unsupported baseline schema in ${path}`);
  }
  return new Set((baseline.entries ?? []).flatMap(stableIdentityFromBaselineEntry));
}

function stableIdentityFromBaselineEntry(entry: BaselineEntry): string[] {
  if (typeof entry.stableIdentity === "string") {
    return [entry.stableIdentity];
  }
  if (typeof entry.ruleId !== "string" || typeof entry.filePath !== "string") {
    return [];
  }
  const scope = baselineScopeForRule(entry.ruleId);
  const component = stableIdentityComponent({
    ruleId: entry.ruleId,
    message: entry.message ?? "",
    ...(typeof entry.symbol === "string" ? { symbol: entry.symbol } : {}),
  }, scope);
  return [
    createHash("sha256")
      .update([entry.ruleId, entry.filePath, component].join("\0"))
      .digest("hex")
      .slice(0, 16),
  ];
}

function baselineScopeForRule(ruleId: string): HookScope {
  if (PROJECT_SCOPE_RULE_IDS.has(ruleId)) {
    return "project";
  }
  if (FILE_SCOPE_RULE_IDS.has(ruleId)) {
    return "file";
  }
  return "line";
}

function stableIdentitiesFromDiffBase(
  runAnalyse: HookAnalysisRunner,
  options: AnalysisOptions,
  diffBase: string,
  currentReport: AnalysisReport,
): Set<string> {
  const ref = diffBaseRef(diffBase);
  if (!ref) {
    return new Set();
  }
  const files = [...new Set(currentReport.findings.map((finding) => finding.filePath))];
  if (files.length === 0) {
    return new Set();
  }
  const tempRoot = mkdtempSync(join(tmpdir(), "gruff-ts-hook-base-"));
  const previous = cwd();
  try {
    const baseFiles = materializeBaseFiles(ref, files, tempRoot);
    if (baseFiles.length === 0) {
      return new Set();
    }
    chdir(tempRoot);
    const baseReport = runAnalyse(baseAnalysisOptions(options, baseFiles, previous));
    return new Set(baseReport.findings.map((finding) => hookStableIdentity(finding, scopeForFinding(finding))));
  } finally {
    chdir(previous);
    rmSync(tempRoot, { recursive: true, force: true });
  }
}

function diffBaseRef(diffBase: string): string | undefined {
  if (diffBase === "-" || diffBase === "unstaged") {
    return undefined;
  }
  return diffBase === "working-tree" || diffBase === "staged" ? "HEAD" : diffBase;
}

function materializeBaseFiles(ref: string, files: string[], root: string): string[] {
  const materialized: string[] = [];
  for (const file of files) {
    try {
      const source = execFileSync("git", ["show", `${ref}:${file}`], { encoding: "utf8" });
      const target = join(root, file);
      mkdirSync(dirname(target), { recursive: true });
      writeFileSync(target, source);
      materialized.push(file);
    } catch {
      // File did not exist at the base ref, so every current finding in it is new.
    }
  }
  return materialized;
}

function baseAnalysisOptions(options: AnalysisOptions, paths: string[], originalRoot: string): AnalysisOptions {
  return {
    ...withoutChangedRegion(options),
    paths,
    ...(options.config ? { config: absolutize(originalRoot, options.config) } : defaultConfigPathOption(originalRoot, options)),
  };
}

function defaultConfigPathOption(originalRoot: string, options: AnalysisOptions): Partial<Pick<AnalysisOptions, "config">> {
  const defaultConfigPath = join(originalRoot, ".gruff-ts.yaml");
  return !options.shouldSkipConfig && existsSync(defaultConfigPath) ? { config: defaultConfigPath } : {};
}

function withoutChangedRegion(options: AnalysisOptions): AnalysisOptions {
  const { baseline: _baseline, changedRanges: _changedRanges, diff: _diff, diffPatch: _diffPatch, generateBaseline: _generateBaseline, since: _since, ...rest } = options;
  return { ...rest, shouldSkipBaseline: true };
}

function sortHookFindings(findings: HookFinding[]): HookFinding[] {
  return [...findings].sort(
    (left, right) =>
      SEVERITY_RANK[left.severity] - SEVERITY_RANK[right.severity] ||
      left.file.localeCompare(right.file) ||
      (left.line ?? 0) - (right.line ?? 0) ||
      left.ruleId.localeCompare(right.ruleId),
  );
}
