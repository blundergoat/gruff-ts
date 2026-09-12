// Text, SARIF, hotspot, markdown, GitHub, and summary renderers for the stable analysis report.
// HTML output and dashboard chrome live in `report-html.ts` so this module stays under the
// `size.file-length` threshold; both files source `buildPillarRows` + `grade` from
// `pillar-summary.ts` so the cross-format Pillars table stays byte-aligned.
import { findingIdentities } from "./baseline-identity.ts";
import { isAbsolute, relative } from "node:path";
import type { AnalysisReport, Finding, OutputFormat, ScanSurfaceNote, Severity, SkippedPath, SuppressionSummary } from "./types.ts";
import { OUTPUT_VOLUME_HINT_THRESHOLD } from "./constants.ts";
import { countRuleSeverities } from "./findings-helpers.ts";
import { buildPillarRows, type PillarRow } from "./pillar-summary.ts";
import { ruleDescriptors } from "./rules.ts";
import { renderHtml } from "./report-html.ts";
import { compositeLine, exitFor, severityGradeBreakdown } from "./scoring.ts";
import { totalSuppressedFindings } from "./sensitive-exclusions.ts";

/*
 * Format dispatcher. `hotspot` is emitted inline (smallest schema) while every other format has a
 * dedicated renderer. The stable schema string `gruff.hotspot.v1` is part of the public contract;
 * bump it only when changing the hotspot payload shape.
 */
function renderReport(report: AnalysisReport, format: OutputFormat): string {
  switch (format) {
    case "json":
      return JSON.stringify(toJsonReport(report), null, 2);
    case "html":
      return renderHtml(report);
    case "markdown":
      return renderMarkdown(report);
    case "github":
      return renderGithub(report);
    case "hotspot":
      return JSON.stringify({ schemaVersion: "gruff.hotspot.v1", tool: report.tool, score: report.score.composite, files: report.score.topOffenders.slice(0, 10), diagnostics: report.diagnostics }, null, 2);
    case "sarif":
      return renderSarif(report);
    case "text":
      return renderText(report);
  }
}

type MachineFinding = Omit<Finding, "filePath" | "line" | "endLine" | "column" | "symbol" | "remediation" | "metadata"> & {
  file: string;
  line: number;
  endLine?: number;
  column?: number;
  symbol?: string;
  remediation: string;
  metadata: Record<string, unknown>;
};

/**
 * Canonical machine record for one skipped path.
 *
 * Invariant: `pattern` is present only for a `config` source; reason values use the family vocabulary.
 */
interface MachinePathDetail {
  path: string;
  reason: "vcs" | "dependency" | "build-output" | "local-tooling" | "gitignored" | "config-ignore";
  source: SkippedPath["source"];
  pattern?: string;
}

/**
 * Canonical machine diagnostic with omission-based optional location fields.
 *
 * Invariant: `invalidatesRun` is the schema-required field name and always carries an explicit boolean.
 */
interface MachineDiagnostic {
  type: string;
  message: string;
  "invalidatesRun": boolean;
  file?: string;
  line?: number;
}

type MachineSuppression = Omit<SuppressionSummary, "paths" | "symbol"> & {
  paths: string[];
  symbol?: string;
};

/**
 * Fields shared byte-for-byte by analysis and summary v3 envelopes.
 *
 * Invariant: summary changes only `schemaVersion` and omits the top-level findings array.
 */
interface MachineEnvelopeCore {
  tool: AnalysisReport["tool"];
  run: {
    failOn: AnalysisReport["run"]["failOn"];
    format: AnalysisReport["run"]["format"];
    inputs: string[];
    projectRoot: ".";
    config?: string;
    includeIgnored?: true;
  };
  summary: {
    analysedFiles: number;
    diagnostics: number;
    exitCode: number;
    findings: AnalysisReport["summary"];
    findingsByPillar: Record<string, number>;
    ignoredPaths: number;
    missingPaths: number;
    skippedFiles: number;
    suppressedFindings?: number;
  };
  score: {
    composite: { grade: string | null; score: number | null };
    /** Ratified scoring denominator and the pillar set the composite averaged over. */
    evaluatedFiles: number;
    scoredPillars: AnalysisReport["score"]["scoredPillars"];
    clusters: AnalysisReport["score"]["clusters"];
    ruleAttribution: AnalysisReport["score"]["ruleAttribution"];
    pillars: AnalysisReport["score"]["pillars"];
    topOffenders: Array<{ file: string; score: number | null; penalty: number; findings: number }>;
  };
  diagnostics: MachineDiagnostic[];
  paths: { analysedFiles: number; details: MachinePathDetail[]; ignoredPaths: string[]; missingPaths: string[] };
  suppressions: MachineSuppression[];
  baseline?: { applied: boolean; generated: boolean; path: string; source: string; suppressedFindings: number; entries: number; newFindings: number; unchangedFindings: number; resolvedFindings: number };
  diff?: { enabled: true; filteredFindings: number; mode: "changed-regions" };
  extensions?: { ts: { topLevel: { notes: ScanSurfaceNote[] } } };
}

type JsonAnalysisReport = MachineEnvelopeCore & { schemaVersion: "gruff.analysis.v3"; findings: MachineFinding[] };
type JsonSummaryReport = MachineEnvelopeCore & { schemaVersion: "gruff.summary.v3" };

// JSON boundary adapter for native report state.
// Invariant: the result is the exact v3 envelope, without legacy aliases or volatile timestamps.
function toJsonReport(report: AnalysisReport): JsonAnalysisReport {
  return {
    schemaVersion: "gruff.analysis.v3",
    ...machineEnvelopeCore(report),
    findings: report.findings.map((finding) => machineFinding(finding, report.run.projectRoot)),
  };
}

// Invariant: summary v3 is the analysis envelope's exact common projection with findings removed.
function toJsonSummary(report: AnalysisReport): JsonSummaryReport {
  return { schemaVersion: "gruff.summary.v3", ...machineEnvelopeCore(report) };
}

// Builds every field shared by analysis and summary once.
// Invariant: both writers receive the same run, counts, scores, diagnostics, paths, and optional sections.
function machineEnvelopeCore(report: AnalysisReport): MachineEnvelopeCore {
  const { details, ignoredPaths } = machinePathProjection(report);
  return {
    tool: report.tool,
    run: machineRun(report),
    summary: machineSummary(report, details.length),
    score: {
      composite: { grade: report.score.grade, score: report.score.composite },
      evaluatedFiles: report.score.evaluatedFiles,
      scoredPillars: report.score.scoredPillars,
      clusters: report.score.clusters,
      ruleAttribution: report.score.ruleAttribution,
      pillars: report.score.pillars,
      topOffenders: report.score.topOffenders.map((offender) => ({
        file: machinePath(offender.filePath, report.run.projectRoot),
        score: offender.score,
        penalty: offender.penalty,
        findings: offender.findings,
      })),
    },
    diagnostics: report.diagnostics.map((diagnostic) => machineDiagnostic(diagnostic, report.run.projectRoot)),
    paths: {
      analysedFiles: report.paths.analysedFiles,
      details,
      ignoredPaths,
      missingPaths: machinePaths(report.paths.missingPaths, report.run.projectRoot),
    },
    suppressions: report.suppressions.map((suppression) => machineSuppression(suppression, report.run.projectRoot)),
    ...(report.baseline === undefined ? {} : {
      baseline: {
        applied: !report.baseline.generated,
        generated: report.baseline.generated,
        path: machinePath(report.baseline.path, report.run.projectRoot),
        source: report.baseline.source,
        suppressedFindings: report.baseline.suppressed,
        // Every port publishes the same nine keys. A generate run compared against nothing, so its movement counts
        // are zero rather than absent: a reader must never have to tell an absent key from a zero.
        entries: report.baseline.entries ?? 0,
        newFindings: report.baseline.newFindings ?? 0,
        unchangedFindings: report.baseline.unchangedFindings ?? 0,
        resolvedFindings: report.baseline.resolvedFindings ?? 0,
      },
    }),
    ...(report.suppressedCount === undefined ? {} : {
      diff: { enabled: true as const, filteredFindings: report.suppressedCount, mode: "changed-regions" as const },
    }),
    ...(report.notes === undefined ? {} : {
      extensions: { ts: { topLevel: { notes: report.notes } } },
    }),
  };
}

// Projects stable run settings while replacing the host root with the portable `.` identity.
function machineRun(report: AnalysisReport): MachineEnvelopeCore["run"] {
  return {
    failOn: report.run.failOn,
    format: report.run.format,
    inputs: machinePaths(report.run.inputs ?? ["."], report.run.projectRoot),
    projectRoot: ".",
    ...(report.run.config === undefined ? {} : { config: machinePath(report.run.config, report.run.projectRoot) }),
    ...(report.run.includeIgnored === true ? { includeIgnored: true as const } : {}),
  };
}

// Derives duplicated counts from canonical arrays and the existing fail-on algorithm.
// Invariant: every published count equals its source array or finding partition.
function machineSummary(report: AnalysisReport, skippedFiles: number): MachineEnvelopeCore["summary"] {
  const pillarCounts = new Map<string, number>();
  report.findings.forEach((finding) => pillarCounts.set(finding.pillar, (pillarCounts.get(finding.pillar) ?? 0) + 1));
  return {
    analysedFiles: report.paths.analysedFiles,
    diagnostics: report.diagnostics.length,
    exitCode: exitFor(report, report.run.failOn),
    findings: report.summary,
    findingsByPillar: Object.fromEntries([...pillarCounts.entries()].sort(([left], [right]) => left.localeCompare(right))),
    ignoredPaths: skippedFiles,
    missingPaths: report.paths.missingPaths.length,
    skippedFiles,
    ...(report.suppressedCount === undefined ? {} : { suppressedFindings: report.suppressedCount }),
  };
}

// Maps one finding without mutating the native identity-bearing object.
// Invariant: fingerprints and stable identities are copied byte-for-byte; absent optionals stay omitted.
function machineFinding(finding: Finding, projectRoot: string): MachineFinding {
  const line = positiveInteger(finding.line) ?? 1;
  const column = positiveInteger(finding.column);
  const endLine = positiveInteger(finding.endLine);
  return {
    ruleId: finding.ruleId,
    message: finding.message,
    file: machinePath(finding.filePath, projectRoot),
    line,
    ...(endLine === undefined ? {} : { endLine }),
    ...(column === undefined ? {} : { column }),
    severity: finding.severity,
    pillar: finding.pillar,
    secondaryPillars: finding.secondaryPillars,
    tier: finding.tier,
    confidence: finding.confidence,
    ...(finding.symbol === undefined || finding.symbol.length === 0 ? {} : { symbol: finding.symbol }),
    remediation: finding.remediation ?? "",
    fingerprint: finding.fingerprint,
    stableIdentity: finding.stableIdentity,
    metadata: {
      ...finding.metadata,
      locationPrecision: column === undefined ? "line-only" : "scanner-pinpointed",
    },
  };
}

// Maps native diagnostic names and optional locations into the canonical vocabulary.
// Invariant: every diagnostic publishes the required type, message, and invalidation decision.
function machineDiagnostic(
  diagnostic: AnalysisReport["diagnostics"][number],
  projectRoot: string,
): MachineDiagnostic {
  const line = positiveInteger(diagnostic.line);
  return {
    type: diagnostic.diagnosticType,
    message: diagnostic.message,
    invalidatesRun: diagnostic.invalidatesRun !== false,
    ...(diagnostic.filePath === undefined ? {} : { file: machinePath(diagnostic.filePath, projectRoot) }),
    ...(line === undefined ? {} : { line }),
  };
}

// Keeps null native symbols out of the omission-based v3 suppression schema.
function machineSuppression(suppression: SuppressionSummary, projectRoot: string): MachineSuppression {
  return {
    index: suppression.index,
    rule: suppression.rule,
    paths: machinePaths(suppression.paths, projectRoot),
    ...(suppression.symbol === null || suppression.symbol.length === 0 ? {} : { symbol: suppression.symbol }),
    reason: suppression.reason,
    suppressed: suppression.suppressed,
  };
}

// Normalizes M15 skip reasons and proves the bare list is the exact detail projection.
// Invariant: `ignoredPaths` equals `details.map(({ path }) => path)` in the same order.
// Throws: when native ignored paths and skip details do not describe the same sequence.
function machinePathProjection(report: AnalysisReport): { details: MachinePathDetail[]; ignoredPaths: string[] } {
  const details = report.paths.skipped.map((skipped) => machinePathDetail(skipped, report.run.projectRoot));
  const ignoredPaths = machinePaths(report.paths.ignoredPaths, report.run.projectRoot);
  if (ignoredPaths.length !== details.length || ignoredPaths.some((path, index) => path !== details[index]?.path)) {
    throw new Error("Machine ignored paths must be the exact projection of path details.");
  }
  return { details, ignoredPaths };
}

// Converts one native skip record without publishing non-config matcher patterns.
function machinePathDetail(skipped: SkippedPath, projectRoot: string): MachinePathDetail {
  return {
    path: machinePath(skipped.path, projectRoot),
    reason: machineIgnoreReason(skipped),
    source: skipped.source,
    ...(skipped.source === "config" ? { pattern: skipped.pattern } : {}),
  };
}

// Maps TypeScript's native ignore sources onto the ratified family reason vocabulary.
// Throws: when a default ignore pattern has no canonical family reason.
function machineIgnoreReason(skipped: SkippedPath): MachinePathDetail["reason"] {
  if (skipped.source === "config") {
    return "config-ignore";
  }
  if (skipped.source === "gitignore") {
    return "gitignored";
  }
  const component = skipped.pattern.replace(/\/+$/u, "").split("/").at(-1);
  if (component === ".git" || component === ".hg" || component === ".svn") {
    return "vcs";
  }
  if (component === "node_modules" || component === "vendor") {
    return "dependency";
  }
  if (component === "build" || component === "coverage" || component === "dist") {
    return "build-output";
  }
  if (component === ".fleet" || component === ".idea" || component === ".vscode") {
    return "local-tooling";
  }
  throw new Error(`Default ignored path has no canonical reason: ${skipped.pattern}`);
}

// Produces unique portable paths in producer order.
function machinePaths(values: readonly string[], projectRoot: string): string[] {
  return [...new Set(values.map((value) => machinePath(value, projectRoot)))];
}

// Converts a native path to project-relative POSIX form.
// Throws: when the path is empty, absolute outside the project, drive-qualified, UNC, or escapes with `..`.
function machinePath(pathValue: string, projectRoot: string): string {
  const slashValue = pathValue.replaceAll("\\", "/");
  if (slashValue.length === 0 || slashValue.startsWith("//") || /^[A-Za-z]:/u.test(slashValue)) {
    throw new Error(`Machine path must be project-relative: ${JSON.stringify(pathValue)}`);
  }
  const relativeValue = isAbsolute(pathValue) ? relative(projectRoot, pathValue).replaceAll("\\", "/") : slashValue;
  const parts: string[] = [];
  for (const part of relativeValue.split("/")) {
    if (part.length === 0 || part === ".") {
      continue;
    }
    if (part === "..") {
      if (parts.length === 0) {
        throw new Error(`Machine path must stay inside the project root: ${JSON.stringify(pathValue)}`);
      }
      parts.pop();
      continue;
    }
    parts.push(part);
  }
  return parts.length === 0 ? "." : parts.join("/");
}

// Optional source locations serialize only as positive integers.
function positiveInteger(integerValue: number | undefined): number | undefined {
  return integerValue !== undefined && Number.isInteger(integerValue) && integerValue > 0 ? integerValue : undefined;
}

/*
 * SARIF 2.1.0 output for GitHub code-scanning uploads. Kept as one large object literal because
 * the SARIF schema demands a specific shape - splitting it up obscures which fields are required.
 * `partialFingerprints.gruffFingerprint` is the cross-tool stable identifier; GitHub uses it to
 * dedupe alerts across re-uploads, so it must match the Finding fingerprint exactly.
 */
function renderSarif(report: AnalysisReport): string {
  const rules = ruleDescriptors().map((descriptor) => ({
    id: descriptor.ruleId,
    name: descriptor.ruleId,
    shortDescription: { text: descriptor.description },
    fullDescription: { text: descriptor.description },
    help: { text: descriptor.remediation },
    properties: {
      pillar: descriptor.pillar,
      tier: "v0.1",
      defaultSeverity: descriptor.severity,
      confidence: descriptor.confidence,
      defaultEnabled: true,
      ...(typeof descriptor.threshold === "number" ? { threshold: descriptor.threshold } : {}),
      ...(descriptor.optionKeys ? { optionKeys: descriptor.optionKeys } : {}),
    },
  }));
  const ruleIndices = new Map(rules.map((rule, index) => [rule.id, index]));
  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: report.tool.name,
            semanticVersion: report.tool.version,
            rules,
          },
        },
        invocations: [
          {
            executionSuccessful: !report.diagnostics.some((diagnostic) => diagnostic.invalidatesRun !== false),
            toolExecutionNotifications: report.diagnostics.map(sarifDiagnostic),
          },
        ],
        results: report.findings.map((finding) => sarifResult(finding, ruleIndices)),
        properties: {
          gruffSchemaVersion: report.schemaVersion,
          generatedAt: report.run.generatedAt,
          score: report.score.composite,
          grade: report.score.grade,
        },
      },
    ],
  };
  return `${JSON.stringify(sarif, null, 2)}\n`;
}

// Contract invariant: analysis diagnostics become SARIF invocation notifications, including their
// file anchor when one exists, while non-fatal bounded scans retain SARIF's note level.
function sarifDiagnostic(diagnostic: AnalysisReport["diagnostics"][number]): Record<string, unknown> {
  return {
    descriptor: { id: diagnostic.diagnosticType },
    level: diagnostic.invalidatesRun === false ? "note" : "error",
    message: { text: diagnostic.message },
    ...(diagnostic.filePath
      ? {
          locations: [{
            physicalLocation: {
              artifactLocation: { uri: sarifUri(diagnostic.filePath) },
              ...(diagnostic.line === undefined ? {} : { region: { startLine: diagnostic.line } }),
            },
          }],
        }
      : {}),
    properties: { invalidatesRun: diagnostic.invalidatesRun !== false },
  };
}

/*
 * Projects one finding into the fingerprints GitHub code scanning groups its alerts by.
 *
 * `gruffFingerprint` is the ratified durable identity and nothing else, so an alert survives a line move while a
 * second declaration of one name opens its own alert. A sensitive finding has none, and carries no key at all:
 * publishing one would give a secret a stable name in a system gruff does not control.
 *
 * The analyser names every finding before the baseline filters any; a finding built outside it is named here,
 * ranked by its own line, so an ordinary result is never published without a fingerprint.
 */
function sarifPartialFingerprints(finding: Finding): Record<string, string> | undefined {
  if (finding.baselineIdentity !== undefined) {
    return { gruffFingerprint: finding.baselineIdentity };
  }
  const named = findingIdentities([finding])[0];
  return named === undefined ? undefined : { gruffFingerprint: named.identity };
}

/*
 * Maps one Finding into a SARIF result row.
 * Stable contract: the durable identity in `partialFingerprints` is what GitHub code scanning keys alerts off.
 */
function sarifResult(finding: Finding, ruleIndices: Map<string, number>): Record<string, unknown> {
  const result: Record<string, unknown> = {
    ruleId: finding.ruleId,
    level: sarifLevel(finding.severity),
    message: { text: finding.message },
    locations: [
      {
        physicalLocation: sarifPhysicalLocation(finding),
      },
    ],
  };
  const fingerprints = sarifPartialFingerprints(finding);
  // A sensitive finding carries no fingerprints at all, so no secret gets a durable name in code scanning.
  if (fingerprints !== undefined) {
    result.partialFingerprints = fingerprints;
  }
  const ruleIndex = ruleIndices.get(finding.ruleId);
  if (ruleIndex !== undefined) {
    result.ruleIndex = ruleIndex;
  }
  const properties: Record<string, unknown> = {
    severity: finding.severity,
    pillar: finding.pillar,
    tier: finding.tier,
    confidence: finding.confidence,
    metadata: finding.metadata,
  };
  if (finding.secondaryPillars.length > 0) {
    properties.secondaryPillars = finding.secondaryPillars;
  }
  if (finding.symbol) {
    properties.symbol = finding.symbol;
  }
  if (finding.remediation) {
    properties.remediation = finding.remediation;
  }
  result.properties = properties;
  return result;
}

/*
 * Constructs the stable SARIF `physicalLocation` object. `startLine` and column/endLine are only
 * populated when the Finding carries them - SARIF requires `region` to be omitted (not empty)
 * when there is no line context.
 */
function sarifPhysicalLocation(finding: Finding): Record<string, unknown> {
  const location: Record<string, unknown> = {
    artifactLocation: {
      uri: sarifUri(finding.filePath),
    },
  };
  if (finding.line !== undefined) {
    const region: Record<string, unknown> = {
      startLine: finding.line,
    };
    if (finding.column !== undefined) {
      region.startColumn = finding.column;
    }
    if (finding.endLine !== undefined) {
      region.endLine = finding.endLine;
    }
    location.region = region;
  }
  return location;
}

// SARIF artifact URIs are POSIX-style relative paths. Strips leading `./` (which SARIF consumers
// treat as absolute or as a different path) and converts Windows-style separators.
function sarifUri(filePath: string): string {
  return filePath
    .replaceAll("\\", "/")
    .replace(/^(?:\.\/)+/, "")
    .split("/")
    .map(encodeURIComponent)
    .join("/");
}

// SARIF has three levels; gruff's "advisory" maps to "note" because that's the documented soft-warning level.
function sarifLevel(severity: Severity): "error" | "warning" | "note" {
  switch (severity) {
    case "error":
      return "error";
    case "warning":
      return "warning";
    case "advisory":
      return "note";
  }
}

/*
 * Compact digest for humans in terminals. It intentionally stays outside the JSON schema contract
 * because the CLI should be able to improve wording/layout without a schema bump; callers that need
 * durable machine output should use `analyse --format=json` instead.
 */
function renderSummary(report: AnalysisReport, elapsedMs?: number, pathLabel?: string, top = 10): string {
  const ruleCounts = countBy(report.findings, (finding) => finding.ruleId);
  const pillarRows = buildPillarRows(report);
  const breakdown = severityGradeBreakdown(report.findings);
  // FAMILY-CONTRACT section 1: masthead, then the two-line composite block, then this port's own
  // lines. The scan card used to sit between the masthead and the composite, which put the number a
  // reader came for two lines further down than the contract allows.
  const lines = [
    `gruff-ts ${report.tool.version} summary`,
    compositeLine(report.score.composite, report.score.grade),
    `Findings: ${report.summary.total} total · ${report.summary.error} error · ${report.summary.warning} warning · ${report.summary.advisory} advisory`,
    `Path: ${pathLabel ?? report.run.projectRoot}`,
    ...(typeof elapsedMs === "number" ? [`Duration: ${formatSummaryDuration(elapsedMs)}`] : []),
    `  Errors:   ${breakdown.error.grade} (${breakdown.error.count})`,
    `  Warnings: ${breakdown.warning.grade} (${breakdown.warning.count})`,
    `  Advisory: ${breakdown.advisory.grade} (${breakdown.advisory.count})`,
    ...renderComplexityClusterLines(report.findings, top),
    `Analysed files: ${report.paths.analysedFiles}`,
    ...(report.baseline ? [summaryBaselineLine(report.baseline)] : []),
  ];
  if (report.diagnostics.length > 0) {
    lines.push("", "Diagnostics:", ...report.diagnostics.map(summaryDiagnosticLine));
  }
  lines.push("", ...renderPillarsBlock(pillarRows));
  lines.push("", `Top ${top} rules:`);
  lines.push(...renderRankedRuleRows(report.findings, top));
  lines.push("", `Top ${top} file offenders:`);
  lines.push(
    ...(
      report.score.topOffenders.length === 0
        ? ["- No file offenders."]
        : report.score.topOffenders.slice(0, top).map((offender) => {
            const quality = offender.score === null ? "n/a" : `${offender.score.toFixed(1)}/100`;
            return `- ${offender.filePath}: ${offender.findings} findings, quality ${quality}`;
          })
    ),
  );
  // The digest filters through the same analyse-side partition, so it owes the same audit row: a
  // surface that applies a sensitive exclusion reports its count on that surface (FAMILY-CONTRACT.md
  // section 13a, search: `Where the audit must appear`). It is an extension line below the canonical
  // block, which section 1 permits; machine summary counts live in the v3 projection.
  lines.push(...renderTextSuppressionLines(report));
  return `${lines.join("\n")}\n`;
}

/*
 * Renders `gruff.summary.v3` for `summary --format=json`.
 * Invariant: findings alone are absent; every other field comes from the shared analysis adapter.
 */
function renderSummaryJson(report: AnalysisReport): string {
  return `${JSON.stringify(toJsonSummary(report), null, 2)}\n`;
}

// Shared text formatter for diagnostic rows in plain-text summaries and the `text` format. Stable
// "- {type}: {message} (path)" shape is part of the contract that scripts grepping the text output
// rely on, so the format must stay deterministic across both call sites.
function summaryDiagnosticLine(diagnostic: AnalysisReport["diagnostics"][number]): string {
  const location = diagnostic.filePath ? ` (${diagnostic.filePath})` : "";
  return `- ${diagnostic.diagnosticType}: ${diagnostic.message}${location}`;
}

// Documents the summary baseline contract so suppressed findings are not mistaken for a clean scan.
function summaryBaselineLine(baseline: NonNullable<AnalysisReport["baseline"]>): string {
  if (baseline.generated) {
    return `Baseline: generated ${baseline.path}; current findings still shown`;
  }
  const findingNoun = baseline.suppressed === 1 ? "finding" : "findings";
  return `Baseline: ${baseline.source} ${baseline.path}; suppressed ${baseline.suppressed} ${findingNoun}`;
}

// Human-sized summary runtime without pretending sub-millisecond precision is useful.
function formatSummaryDuration(elapsedMs: number): string {
  const bounded = Math.max(0, elapsedMs);
  if (bounded < 1000) {
    return `${Math.round(bounded)}ms`;
  }
  return `${(bounded / 1000).toFixed(2)}s`;
}

// Tallies findings under the caller-supplied key; iteration order stays deterministic for renderers.
function countBy<T extends string>(findings: Finding[], keyFor: (finding: Finding) => T): Map<T, number> {
  const counts = new Map<T, number>();
  for (const finding of findings) {
    const key = keyFor(finding);
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return counts;
}

/*
 * Text renderer for the `Pillars` block in `gruff-ts summary`. Column widths are computed from the
 * actual data (max pillar-name length, max digits per severity column) with a 3-char minimum value
 * width so single-digit cells still leave visual breathing room before the next column. This
 * matches the cross-port canonical byte-for-byte layout: leading "Pillars" header, 2-space row
 * indent, pillar name padded to max-name-width + 1 space, single-letter grade, 1-space separator,
 * score right-aligned in 6 chars with 2 decimals, then findings/advisory/warning/error cells
 * separated by 3 spaces and trimmed of trailing whitespace on the final column.
 */
function renderPillarsBlock(rows: PillarRow[]): string[] {
  if (rows.length === 0) {
    return ["Pillars", "  (none)"];
  }
  const nameWidth = Math.max(...rows.map((row) => row.pillar.length));
  const findingsWidth = Math.max(3, ...rows.map((row) => String(row.findings).length));
  const advisoryWidth = Math.max(3, ...rows.map((row) => String(row.advisory).length));
  const warningWidth = Math.max(3, ...rows.map((row) => String(row.warning).length));
  const errorWidth = Math.max(3, ...rows.map((row) => String(row.error).length));
  const lines = ["Pillars"];
  for (const row of rows) {
    const name = row.pillar.padEnd(nameWidth);
    const score = row.score.toFixed(2).padStart(6);
    const findingsCell = `findings=${String(row.findings).padEnd(findingsWidth)}`;
    const advisoryCell = `advisory=${String(row.advisory).padEnd(advisoryWidth)}`;
    const warningCell = `warning=${String(row.warning).padEnd(warningWidth)}`;
    const errorCell = `error=${String(row.error).padEnd(errorWidth)}`;
    const line = `  ${name} ${row.grade} ${score} ${findingsCell}   ${advisoryCell}   ${warningCell}   ${errorCell}`.replace(/\s+$/, "");
    lines.push(line);
  }
  return lines;
}

/*
 * Enriched top-N rules renderer. Replaces the plain `- <ruleId>: <count>` form with a per-severity
 * split plus the rule's one-line description, so an operator triaging 1000+ findings can see
 * whether the top entry is one error or four hundred advisories at a glance. Description text is
 * truncated to `DESCRIPTION_BODY_LIMIT` characters with an ellipsis so the row stays legible at 100
 * columns. Sort order is preserved (count DESC, ruleId ASC) to keep the row-at-position-[0] stable.
 */
function renderRankedRuleRows(findings: Finding[], limit?: number): string[] {
  const severities = countRuleSeverities(findings);
  if (severities.size === 0) {
    return ["- No rule findings."];
  }
  const descriptions = new Map(ruleDescriptors().map((descriptor) => [descriptor.ruleId, descriptor.description]));
  const limited = [...severities.entries()]
    .sort(([leftKey, leftCounts], [rightKey, rightCounts]) => rightCounts.total - leftCounts.total || leftKey.localeCompare(rightKey))
    .slice(0, limit ?? severities.size);
  return limited.map(([ruleId, counts]) => {
    const description = truncateDescription(descriptions.get(ruleId) ?? "");
    return `- ${ruleId}: ${counts.total} (${counts.error} err / ${counts.warning} warn / ${counts.advisory} adv) - ${description}`;
  });
}

/*
 * 60-char description budget that keeps the rule-row line under ~100 columns even with the longest
 * ruleId and severity-split. The trailing ellipsis is a single Unicode glyph so terminals that
 * don't render `...` still see the truncation marker.
 */
const DESCRIPTION_BODY_LIMIT = 60;

// Applies the description budget to a single rule's description so each rule row in the summary
// Top-N block fits on one terminal line. Returns the input unchanged when already short.
function truncateDescription(text: string): string {
  return text.length <= DESCRIPTION_BODY_LIMIT ? text : `${text.slice(0, DESCRIPTION_BODY_LIMIT).trimEnd()}…`;
}

// Renders a count map as ranked text bullets; the (count DESC, key ASC) ordering is deterministic.
function renderRankedCounts<T extends string>(counts: Map<T, number>, emptyText: string, limit?: number): string[] {
  if (counts.size === 0) {
    return [`- ${emptyText}`];
  }
  return [...counts.entries()]
    .sort(([leftKey, leftCount], [rightKey, rightCount]) => rightCount - leftCount || leftKey.localeCompare(rightKey))
    .slice(0, limit ?? counts.size)
    .map(([key, count]) => `- ${key}: ${count}`);
}

// Structured variant of `renderRankedCounts` for JSON consumers; the same deterministic ordering.
function renderRankedCountRows<T extends string>(counts: Map<T, number>, limit?: number): Array<{ name: T; count: number }> {
  return [...counts.entries()]
    .sort(([leftKey, leftCount], [rightKey, rightCount]) => rightCount - leftCount || leftKey.localeCompare(rightKey))
    .slice(0, limit ?? counts.size)
    .map(([name, count]) => ({ name, count }));
}

/*
 * Default terminal output. Findings are listed verbatim (no truncation) - the analyser keeps them
 * sorted into the stable order, so piping into `grep` produces deterministic results.
 */
function renderText(report: AnalysisReport): string {
  const breakdown = severityGradeBreakdown(report.findings);
  const lines = [
    `gruff-ts ${report.tool.version} analyse`,
    compositeLine(report.score.composite, report.score.grade),
    `Findings: ${report.summary.total} total · ${report.summary.error} error · ${report.summary.warning} warning · ${report.summary.advisory} advisory`,
    `  Errors:   ${breakdown.error.grade} (${breakdown.error.count})`,
    `  Warnings: ${breakdown.warning.grade} (${breakdown.warning.count})`,
    `  Advisory: ${breakdown.advisory.grade} (${breakdown.advisory.count})`,
    ...renderComplexityClusterLines(report.findings),
    `Analysed files: ${report.paths.analysedFiles}`,
  ];
  if (report.diagnostics.length > 0) {
    lines.push("", "Diagnostics:", ...report.diagnostics.map(summaryDiagnosticLine));
  }
  if ((report.notes ?? []).length > 0) {
    lines.push("", "Notes:", ...(report.notes ?? []).map((note) => `- ${note.noteType}: ${note.message} (${note.path})`));
  }
  if (report.findings.length > 0) {
    lines.push("", "Findings:", ...report.findings.map((finding) => `- [${finding.severity}] ${finding.filePath}:${finding.line ?? 1} ${finding.ruleId} - ${finding.message}`));
  }
  if (report.findings.length >= OUTPUT_VOLUME_HINT_THRESHOLD) {
    lines.push("", `Tip: ${report.findings.length} findings is more than a flat list usefully shows. Try \`gruff-ts summary --top=20\` for a per-rule digest.`);
  }
  lines.push(...renderTextSuppressionLines(report));
  return `${lines.join("\n")}\n`;
}

/*
 * One human-readable total for the reviewed sensitive exclusions, so a suppressed finding is never
 * silently invisible on the surface most users read. The line is a stable cross-port contract whose
 * shape follows the family reference renderer (gruff-rs/src/render/text.rs, search:
 * `Suppressed findings:`). Entries that matched nothing are
 * omitted from the detail list but still publish their zero row in `report.suppressions`. Only the
 * configured rule id, count, and rationale are printed - never any matched value material.
 */
function renderTextSuppressionLines(report: AnalysisReport): string[] {
  const total = totalSuppressedFindings(report.suppressions);
  // Nothing suppressed means no line at all, matching the reference renderer.
  if (total === 0) {
    return [];
  }
  const details = report.suppressions
    .filter((summary) => summary.suppressed > 0)
    .map((summary) => `sensitiveExclusions[${summary.index}] ${summary.rule}: ${summary.suppressed} (${summary.reason})`)
    .join("; ");
  return ["", `Suppressed findings: ${total} via ${details}`];
}

/*
 * Markdown renderer for the native analysis report. Truncates to 50 findings because Markdown
 * previews (PR comments, READMEs) start mangling longer tables; the JSON and HTML renderers stay
 * the canonical full-fidelity output. Public contract / invariant: the Pillars table is inserted
 * between the severity counts and the per-finding list so CI logs and PR comment previews see it
 * first, and it shares its row data and sort order with the text/JSON/HTML pillar renderers via
 * `buildPillarRows` so all four surfaces stay deterministic and byte-aligned across runs.
 */
function renderMarkdown(report: AnalysisReport): string {
  const breakdown = severityGradeBreakdown(report.findings);
  // A repository controls each displayed value; a missing line keeps the historic line-1 fallback.
  const findingRows = report.findings
    .slice(0, 50)
    .map((finding) => `- ${markdownInlineCode(finding.ruleId)} ${markdownInlineCode(finding.filePath)}:${finding.line ?? 1} - ${escapeMarkdownFindingMessage(finding.message)}`);
  const diagnosticRows = report.diagnostics.length === 0
    ? []
    : [
        "## Diagnostics",
        "",
        ...report.diagnostics.map((diagnostic) => {
          const diagnosticLocation = diagnostic.filePath
            ? `${markdownInlineCode(diagnostic.filePath)}:${diagnostic.line ?? 1} `
            : "";
          return `- ${markdownInlineCode(diagnostic.diagnosticType)} ${diagnosticLocation}- ${escapeMarkdownFindingMessage(diagnostic.message)}`;
        }),
        "",
      ];
  return [
    "# gruff-ts report",
    "",
    // Markdown bolds the value, not the label; the canonical line shape is the text view's contract.
    report.score.composite === null || report.score.grade === null
      ? "Composite: **n/a (nothing evaluated)**"
      : `Composite: **${report.score.grade} (${report.score.composite.toFixed(2)} / 100)**`,
    `- Errors:   ${breakdown.error.grade} (${breakdown.error.count})`,
    `- Warnings: ${breakdown.warning.grade} (${breakdown.warning.count})`,
    `- Advisory: ${breakdown.advisory.grade} (${breakdown.advisory.count})`,
    ...renderMarkdownComplexityClusterLines(report.findings),
    "",
    `Findings: ${report.summary.total} total · ${report.summary.error} error · ${report.summary.warning} warning · ${report.summary.advisory} advisory`,
    "",
    ...diagnosticRows,
    ...renderMarkdownPillarsTable(buildPillarRows(report)),
    "",
    ...findingRows,
  ].join("\n");
}

/*
 * Canonical 7-column Pillars table shared by the cross-port markdown contract. The header,
 * separator (right-aligned numeric columns), and row format match the gruff-go markdown reporter
 * byte-for-byte so downstream tooling (PR comment scrapers, dashboards parsing the markdown body)
 * keys off a single shape. Row order is sourced from `buildPillarRows` (findings DESC, then pillar
 * ASC); scores render with two decimals; pipes in pillar/grade cells are escaped so a future
 * pillar/grade name containing `|` cannot break the table.
 */
function renderMarkdownPillarsTable(rows: PillarRow[]): string[] {
  const lines = [
    "## Pillars",
    "",
    "| Pillar | Grade | Score | Findings | Advisory | Warning | Error |",
    "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
  ];
  if (rows.length === 0) {
    lines.push("| _(none)_ |  |  |  |  |  |  |");
    return lines;
  }
  for (const row of rows) {
    lines.push(
      `| ${escapeMarkdownCell(row.pillar)} | ${escapeMarkdownCell(row.grade)} | ${row.score.toFixed(2)} | ${row.findings} | ${row.advisory} | ${row.warning} | ${row.error} |`,
    );
  }
  return lines;
}

// Escapes the pipe character so a pillar/grade name containing `|` cannot terminate the table row.
// Markdown's table syntax has no other reserved cell characters - newlines are already impossible
// inside a single-line `lines.push` interpolation - so this single replacement is sufficient.
function escapeMarkdownCell(cell: string): string {
  return cell.replaceAll("|", "\\|");
}

// Wraps a repository-controlled label in a CommonMark code span for PR and issue reports.
// A fence longer than the label's longest backtick run keeps the label inside one span.
function markdownInlineCode(reportLabel: string): string {
  const singleLineLabel = reportLabel.replace(/[\r\n]+/g, " ");
  // An empty analyzer label still needs content so Markdown does not merge its two fences.
  const visibleLabel = singleLineLabel.length === 0 ? " " : singleLineLabel;
  const fenceLength = Math.max(1, ...Array.from(visibleLabel.matchAll(/`+/g), (match) => match[0].length + 1));
  const fence = "`".repeat(fenceLength);
  // Edge backticks need padding so CommonMark can distinguish label content from the fence.
  const paddedLabel = visibleLabel.startsWith("`") || visibleLabel.endsWith("`") ? ` ${visibleLabel} ` : visibleLabel;
  return `${fence}${paddedLabel}${fence}`;
}

// Escapes repository-controlled finding prose before a reviewer sees the Markdown report.
// Line breaks collapse so a message cannot start a new heading, list, or HTML block.
function escapeMarkdownFindingMessage(findingMessage: string): string {
  return findingMessage
    .replace(/[\r\n]+/g, " ")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\\", "\\\\")
    .replaceAll("`", "\\`")
    .replaceAll("*", "\\*")
    .replaceAll("_", "\\_")
    .replaceAll("[", "\\[")
    .replaceAll("]", "\\]")
    .replaceAll("|", "\\|")
    .replaceAll("#", "\\#")
    .replaceAll("~", "\\~");
}

// Render-only summary of overlapping complexity findings for one function symbol.
interface ComplexityCluster {
  filePath: string;
  symbol: string;
  ruleIds: string[];
}

const CORRELATED_COMPLEXITY_RULE_IDS = new Set(["complexity.cognitive", "complexity.cyclomatic", "size.function-length"]);

// Invariant: text output surfaces linked complexity clusters without changing JSON report shape.
function renderComplexityClusterLines(findings: Finding[], limit = 10): string[] {
  const clusters = complexityClusters(findings).slice(0, limit);
  if (clusters.length === 0) {
    return [];
  }
  return [
    "Correlated complexity clusters:",
    ...clusters.map((cluster) => `- ${cluster.filePath}#${cluster.symbol}: ${cluster.ruleIds.length} linked findings (${cluster.ruleIds.join(", ")})`),
  ];
}

// Invariant: markdown mirrors text complexity clusters without adding JSON fields.
function renderMarkdownComplexityClusterLines(findings: Finding[]): string[] {
  const clusters = complexityClusters(findings);
  // A scan with no overlapping complexity findings should not show an empty review section.
  if (clusters.length === 0) {
    return [];
  }
  // Repository paths and symbols stay inside one code span in the reviewer's cluster list.
  const clusterRows = clusters.map(renderMarkdownComplexityClusterRow);
  return [
    "",
    "## Correlated Complexity Clusters",
    "",
    ...clusterRows,
  ];
}

// Formats one correlated cluster for the Markdown list a reviewer sees in pull-request output.
function renderMarkdownComplexityClusterRow(cluster: ComplexityCluster): string {
  const clusterLabel = `${cluster.filePath}#${cluster.symbol}`;
  // Every linked rule remains its own code span so a reviewer can copy its exact identifier.
  const linkedRuleLabels = cluster.ruleIds.map((ruleId) => markdownInlineCode(ruleId)).join(", ");
  return `- ${markdownInlineCode(clusterLabel)}: ${cluster.ruleIds.length} linked findings (${linkedRuleLabels})`;
}

// Invariant: groups findings by file and symbol so every renderer explains score overlap consistently.
function complexityClusters(findings: Finding[]): ComplexityCluster[] {
  const bySymbol = new Map<string, ComplexityCluster>();
  for (const finding of findings) {
    if (!finding.symbol || !CORRELATED_COMPLEXITY_RULE_IDS.has(finding.ruleId)) {
      continue;
    }
    const key = `${finding.filePath}\0${finding.symbol}`;
    const cluster = bySymbol.get(key) ?? { filePath: finding.filePath, symbol: finding.symbol, ruleIds: [] };
    if (!cluster.ruleIds.includes(finding.ruleId)) {
      cluster.ruleIds.push(finding.ruleId);
    }
    bySymbol.set(key, cluster);
  }
  return [...bySymbol.values()]
    .filter((cluster) => cluster.ruleIds.length >= 2)
    .map((cluster) => ({ ...cluster, ruleIds: cluster.ruleIds.sort() }))
    .sort((left, right) => right.ruleIds.length - left.ruleIds.length || left.filePath.localeCompare(right.filePath) || left.symbol.localeCompare(right.symbol));
}

// GitHub Actions `::workflow command` syntax. Public contract invariant: file/title properties
// must be normalized and command-escaped before interpolation because commas and colons delimit the property list.
function renderGithub(report: AnalysisReport): string {
  return [
    ...report.diagnostics.map(githubDiagnostic),
    ...report.findings.map((finding) => `::${githubLevel(finding.severity)} file=${escapeCommandProperty(githubAnnotationPath(finding.filePath))},line=${finding.line ?? 1},title=${escapeCommandProperty(finding.ruleId)}::${escapeCommand(finding.message)}`),
  ]
    .join("\n");
}

// Contract invariant: runtime diagnostics become Actions annotations; bounded deep scans stay
// notices and all fatal diagnostics remain errors, including file-less diagnostics.
function githubDiagnostic(diagnostic: AnalysisReport["diagnostics"][number]): string {
  const level = diagnostic.invalidatesRun === false ? "notice" : "error";
  const location = diagnostic.filePath
    ? ` file=${escapeCommandProperty(githubAnnotationPath(diagnostic.filePath))},line=${diagnostic.line ?? 1},`
    : " ";
  return `::${level}${location}title=${escapeCommandProperty(diagnostic.diagnosticType)}::${escapeCommand(diagnostic.message)}`;
}

// GitHub annotation paths are repository-relative POSIX paths. Leading `./` and Windows
// separators produce duplicate annotations for the same file, so normalize them once here.
function githubAnnotationPath(filePath: string): string {
  return filePath.replaceAll("\\", "/").replace(/^(?:\.\/)+/, "");
}

// Three GitHub annotation levels - gruff's "advisory" collapses to "notice" because Actions has
// no fourth tier and "notice" is the documented soft-warning level.
function githubLevel(severity: Severity): "notice" | "warning" | "error" {
  return severity === "error" ? "error" : severity === "warning" ? "warning" : "notice";
}

// Actions workflow-command escaping per the documented spec. `%` must be first - otherwise the
// `%0A` replacement would itself be re-encoded.
function escapeCommand(commandText: string): string {
  return commandText.replaceAll("%", "%25").replaceAll("\n", "%0A").replaceAll("\r", "%0D");
}

// Property-list variant of `escapeCommand`: also escapes `:` and `,` because GitHub workflow
// commands use them as the property-list delimiters between `file`, `line`, `title`, etc.
function escapeCommandProperty(propertyText: string): string {
  return escapeCommand(propertyText).replaceAll(":", "%3A").replaceAll(",", "%2C");
}

export { renderReport, renderSummary, renderSummaryJson };
