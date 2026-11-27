// Turns scan results into terminal output, shareable reports, and formats consumed by CI.
//
// Use JSON for individual findings, summary JSON for totals, and hotspot JSON for the highest-priority files.
// Converts report paths to project-relative form so a reader can compare output from different machines.
import { findingIdentities } from "./baseline-identity.ts";
import { isAbsolute, relative } from "node:path";
import type { AnalysisReport, Finding, OutputFormat, ScanSurfaceNote, Severity, SkippedPath, SuppressionSummary } from "./types.ts";
import { OUTPUT_VOLUME_HINT_THRESHOLD } from "./constants.ts";
import { MINIFIED_FILE_PATTERN } from "./discovery.ts";
import { countRuleSeverities } from "./findings-helpers.ts";
import { buildPillarRows, type PillarRow } from "./pillar-summary.ts";
import { ruleDescriptors } from "./rules.ts";
import { renderHtml } from "./report-html.ts";
import { compositeLine, exitFor, severityGradeBreakdown } from "./scoring.ts";
import { totalSuppressedFindings } from "./sensitive-exclusions.ts";

/**
 * Renders the result in the format the user selected, including the compact hotspot view for prioritizing fixes.
 *
 * @param report - Native analysis report supplying the data for the selected format.
 * @param format - Selects the human-readable renderer or machine output projection.
 * @param exitCode - decided status for JSON. Omit it when rendering directly to use the run's severity threshold.
 * @returns Rendered report text.
 * Hotspot JSON uses the stable gruff.hotspot.v1 schema, with up to ten top offenders and every scan diagnostic, such as a deep-scan budget notice.
 */
function renderReport(report: AnalysisReport, format: OutputFormat, exitCode?: number): string {
  switch (format) {
    case "json":
      return JSON.stringify(toJsonReport(report, exitCode), null, 2);
    case "html":
      return renderHtml(report);
    case "markdown":
      return renderMarkdown(report);
    case "github":
      return renderGithub(report);
    case "hotspot":
      return JSON.stringify(
        {
          schemaVersion: "gruff.hotspot.v1",
          tool: report.tool,
          score: report.score.composite,
          files: report.score.topOffenders.slice(0, 10),
          diagnostics: report.diagnostics.map((diagnostic) => machineDiagnostic(diagnostic, report.run.projectRoot)),
        },
        null,
        2,
      );
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
  reason: "vcs" | "dependency" | "build-output" | "local-tooling" | "generated" | "gitignored" | "config-ignore";
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
  baseline?: { applied: boolean; generated: boolean; path?: string; source: string; suppressedFindings: number; entries: number; newFindings: number; unchangedFindings: number; resolvedFindings: number };
  diff?: { enabled: true; filteredFindings: number; mode: "changed-regions" };
  extensions?: { ts: { topLevel: { notes: ScanSurfaceNote[] } } };
}

type JsonAnalysisReport = MachineEnvelopeCore & { schemaVersion: "gruff.analysis.v3"; findings: MachineFinding[] };
type JsonSummaryReport = MachineEnvelopeCore & { schemaVersion: "gruff.summary.v3" };

/**
 * Builds the JSON report for readers who need the run details and each individual finding.
 * Invariant: the result is the exact v3 envelope, without legacy aliases or volatile timestamps.
 *
 * @param report - Native analysis report supplying run metadata, scores, diagnostics, and findings.
 * @param exitCode - Decided CLI exit status; omit to derive it from the report's fail-on threshold.
 * @returns The gruff.analysis.v3 JSON envelope with project-relative findings.
 */
function toJsonReport(report: AnalysisReport, exitCode?: number): JsonAnalysisReport {
  return {
    schemaVersion: "gruff.analysis.v3",
    ...machineEnvelopeCore(report, exitCode),
    findings: report.findings.map((finding) => machineFinding(finding, report.run.projectRoot)),
  };
}

/**
 * Builds the JSON summary for automation that needs the outcome and totals without each finding.
 * Invariant: summary v3 has the same run details as analysis v3 and omits the individual finding list.
 *
 * @param report - Native analysis report supplying run details, totals, scores, and diagnostics.
 * @param exitCode - Decided CLI exit status; omit to derive it from the report's fail-on threshold.
 * @returns The gruff.summary.v3 JSON envelope without the top-level findings list.
 */
function toJsonSummary(report: AnalysisReport, exitCode?: number): JsonSummaryReport {
  return { schemaVersion: "gruff.summary.v3", ...machineEnvelopeCore(report, exitCode) };
}

/**
 * Shares run details and totals between analyse and summary JSON so both report the same exit outcome.
 * Invariant: a missing baseline, change selection, or note list leaves that section out of the result.
 *
 * @param report - Native analysis report supplying run, score, path, diagnostic, and suppression data.
 * @param exitCode - Exit code recorded in the summary block; defaults to the threshold exit code for the run.
 * @returns Shared v3 machine envelope with project-relative paths and optional baseline, diff, and note sections.
 */
function machineEnvelopeCore(report: AnalysisReport, exitCode = exitFor(report, report.run.failOn)): MachineEnvelopeCore {
  const { details, ignoredPaths } = machinePathProjection(report);
  const missingPaths = machinePaths(report.paths.missingPaths, report.run.projectRoot);
  return {
    tool: report.tool,
    run: machineRun(report),
    summary: machineSummary(report, details.length, missingPaths.length, exitCode),
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
      missingPaths,
    },
    suppressions: report.suppressions.map((suppression) => machineSuppression(suppression, report.run.projectRoot)),
    // Include review details only when the user applied or generated a baseline.
    ...(report.baseline === undefined ? {} : {
      baseline: {
        applied: !report.baseline.generated,
        generated: report.baseline.generated,
        ...optionalMachinePath("path", report.baseline.path, report.run.projectRoot),
        source: report.baseline.source,
        suppressedFindings: report.baseline.suppressed,
        // Generating a baseline does not compare reviews yet, so comparison counts start at zero.
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
      extensions: { ts: { topLevel: { notes: report.notes.map((note) => {
        const path = machinePath(note.path, report.run.projectRoot);
        return { ...note, path, message: note.message.replace(note.path, () => path) };
      }) } } },
    }),
  };
}

/**
 * Return stable machine run settings from the native report, with project-relative paths and a portable dot for the root.
 * Missing inputs default to the project directory. Missing or out-of-project config paths are omitted.
 * Publish includeIgnored only when enabled.
 *
 * @param report - Native analysis report supplying run configuration, inputs, and project root.
 * @returns Normalized run metadata for the v3 machine envelope.
 */
function machineRun(report: AnalysisReport): MachineEnvelopeCore["run"] {
  return {
    failOn: report.run.failOn,
    format: report.run.format,
    inputs: machinePaths(report.run.inputs ?? ["."], report.run.projectRoot),
    projectRoot: ".",
    ...(report.run.config === undefined ? {} : optionalMachinePath("config", report.run.config, report.run.projectRoot)),
    ...(report.run.includeIgnored === true ? { includeIgnored: true as const } : {}),
  };
}

/**
 * Summarizes the visible findings and path counts while preserving the exit status decided by the CLI.
 * Invariant: skipped and ignored counts both reflect the published path details. Empty pillars have no finding-count entry.
 *
 * @param report - Native analysis report supplying findings, diagnostics, summary totals, and analysed file count.
 * @param skippedFiles - Count of skipped path entries published as both skippedFiles and ignoredPaths.
 * @param missingPaths - Count of normalized missing input paths.
 * @param exitCode - Decided CLI exit status preserved in the summary block.
 * @returns Summary counts and sorted per-pillar finding totals for the machine envelope.
 */
function machineSummary(report: AnalysisReport, skippedFiles: number, missingPaths: number, exitCode: number): MachineEnvelopeCore["summary"] {
  const pillarCounts = new Map<string, number>();
  // Count displayed findings so drill-down filters and pillar totals describe the same set.
  report.findings.forEach((finding) => pillarCounts.set(finding.pillar, (pillarCounts.get(finding.pillar) ?? 0) + 1));
  return {
    analysedFiles: report.paths.analysedFiles,
    diagnostics: report.diagnostics.length,
    exitCode,
    findings: report.summary,
    findingsByPillar: Object.fromEntries([...pillarCounts.entries()].sort(([left], [right]) => left.localeCompare(right))),
    ignoredPaths: skippedFiles,
    missingPaths,
    skippedFiles,
    ...(report.suppressedCount === undefined ? {} : { suppressedFindings: report.suppressedCount }),
  };
}

/**
 * Return a new machine finding with the native fingerprint and stable identity unchanged and the path relative to projectRoot.
 * Missing or invalid lines use 1. Missing or invalid columns are omitted and give line-only precision. Missing remediation becomes empty text.
 * Omit end lines without a valid position and symbols that are absent or empty.
 *
 * @param finding - Native finding to project into the v3 machine schema.
 * @param projectRoot - Root directory used to normalize the finding's file path.
 * @returns Normalized machine finding record preserving fingerprint, stable identity, and location precision metadata.
 */
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

/**
 * Formats a diagnostic for CI readers. A scan-budget notice can leave the run valid even though some checks were skipped.
 *
 * Invariant: defaults to invalidating the run. Missing or external file paths and missing line numbers have no location field.
 * An absolute in-project path inside the message is rewritten project-relative, so host folders never reach CI logs.
 *
 * @param diagnostic - Native scan diagnostic supplying type, message, validity flag, and optional source location.
 * @param projectRoot - Root directory used to resolve an in-project diagnostic file path.
 * @returns Canonical machine diagnostic record for the v3 envelope.
 */
function machineDiagnostic(
  diagnostic: AnalysisReport["diagnostics"][number],
  projectRoot: string,
): MachineDiagnostic {
  const line = positiveInteger(diagnostic.line);
  const fileEntry = diagnostic.filePath === undefined ? {} : optionalMachinePath("file", diagnostic.filePath, projectRoot);
  const message = diagnostic.filePath !== undefined && fileEntry.file !== undefined && diagnostic.filePath !== fileEntry.file
    ? diagnostic.message.replaceAll(diagnostic.filePath, fileEntry.file)
    : diagnostic.message;
  return {
    type: diagnostic.diagnosticType,
    message,
    invalidatesRun: diagnostic.invalidatesRun !== false,
    ...fileEntry,
    ...(line === undefined ? {} : { line }),
  };
}

/**
 * Returns a machine suppression from suppression, normalizing its paths relative to projectRoot.
 * Null or empty symbols and an absent source are omitted.
 *
 * @param suppression - Native suppression summary record to normalize.
 * @param projectRoot - Root directory used to convert covered paths to project-relative POSIX form.
 * @returns Normalized machine suppression entry for the v3 envelope.
 */
function machineSuppression(suppression: SuppressionSummary, projectRoot: string): MachineSuppression {
  return {
    index: suppression.index,
    rule: suppression.rule,
    paths: machinePaths(suppression.paths, projectRoot),
    ...(suppression.symbol === null || suppression.symbol.length === 0 ? {} : { symbol: suppression.symbol }),
    reason: suppression.reason,
    suppressed: suppression.suppressed,
    // Built-in, inline, and duplicate rows retain their source; configured rows omit it.
    ...(suppression.source === undefined ? {} : { source: suppression.source }),
  };
}

/**
 * Returns report's normalized skip details and ignored paths, resolving paths against report.run.projectRoot.
 * The ignored path list must exactly match the detail paths in order.
 *
 * @param report - Native analysis report supplying skipped path records, ignored paths, and project root.
 * @returns Normalized skip details and matching ignored paths.
 * @throws {Error} Normalized ignored paths and skip-detail paths differ in length, value, or order.
 */
function machinePathProjection(report: AnalysisReport): { details: MachinePathDetail[]; ignoredPaths: string[] } {
  const details = report.paths.skipped.map((skipped) => machinePathDetail(skipped, report.run.projectRoot));
  const ignoredPaths = machinePaths(report.paths.ignoredPaths, report.run.projectRoot);
  if (ignoredPaths.length !== details.length || ignoredPaths.some((path, index) => path !== details[index]?.path)) {
    throw new Error("Machine ignored paths must be the exact projection of path details.");
  }
  return { details, ignoredPaths };
}

/**
 * Returns a machine path detail for skipped, making its path relative to projectRoot and mapping its ignore reason.
 * Only config-sourced records include their matching pattern.
 *
 * @param skipped - Skipped path entry with its path, source, and matching pattern.
 * @param projectRoot - Root directory used to normalize the skipped path.
 * @returns Canonical machine path detail with normalized path, reason, source, and optional pattern.
 */
function machinePathDetail(skipped: SkippedPath, projectRoot: string): MachinePathDetail {
  return {
    path: machinePath(skipped.path, projectRoot),
    reason: machineIgnoreReason(skipped),
    source: skipped.source,
    ...(skipped.source === "config" ? { pattern: skipped.pattern } : {}),
  };
}

// The family reason for each directory name TypeScript skips by default (FAMILY-CONTRACT.md section 7).
const DEFAULT_DIRECTORY_REASONS: ReadonlyMap<string, MachinePathDetail["reason"]> = new Map([
  [".git", "vcs"], [".hg", "vcs"], [".svn", "vcs"],
  ["node_modules", "dependency"], ["vendor", "dependency"], ["vendors", "dependency"], ["third_party", "dependency"],
  ["third-party", "dependency"], ["bower_components", "dependency"],
  ["build", "build-output"], ["coverage", "build-output"], ["dist", "build-output"],
  [".fleet", "local-tooling"], [".idea", "local-tooling"], [".vscode", "local-tooling"],
]);

/**
 * Returns the canonical ignore reason for skipped, using its source and matched default pattern.
 *
 * @param skipped - Skipped path record whose source and pattern determine the reason classification.
 * @returns Canonical reason label from the machine path detail vocabulary.
 * @throws {Error} A default pattern is neither the minified-file pattern nor one with a recognized final directory component.
 */
function machineIgnoreReason(skipped: SkippedPath): MachinePathDetail["reason"] {
  if (skipped.source === "config") {
    return "config-ignore";
  }
  if (skipped.source === "gitignore") {
    return "gitignored";
  }
  if (skipped.pattern === MINIFIED_FILE_PATTERN) {
    return "generated";
  }
  const component = skipped.pattern.replace(/\/+$/u, "").split("/").at(-1) ?? "";
  const reason = DEFAULT_DIRECTORY_REASONS.get(component);
  if (reason === undefined) {
    throw new Error(`Default ignored path has no canonical reason: ${skipped.pattern}`);
  }
  return reason;
}

/**
 * Returns values as unique project-relative POSIX paths in first-occurrence order, resolving absolute paths against projectRoot.
 *
 * @param values - Candidate file or directory paths to normalize and deduplicate.
 * @param projectRoot - Root directory against which absolute paths are resolved.
 * @returns Deduplicated project-relative POSIX path list preserving first-occurrence order.
 */
function machinePaths(values: readonly string[], projectRoot: string): string[] {
  return [...new Set(values.map((value) => machinePath(value, projectRoot)))];
}

/**
 * Includes a portable path when a report can point to a file inside the selected project.
 * An empty object omits an external path, such as a config the user keeps in a sibling project.
 *
 * @param key - Property name assigned to the normalized path when it resolves inside projectRoot.
 * @param pathValue - Candidate file path to resolve relative to projectRoot.
 * @param projectRoot - Root directory that bounds whether the path can be published.
 * @returns Single-property record keyed by key for in-project paths, or empty when external.
 */
function optionalMachinePath<Key extends string>(key: Key, pathValue: string, projectRoot: string): Partial<Record<Key, string>> {
  const relativeValue = (isAbsolute(pathValue) ? relative(projectRoot, pathValue) : pathValue).replaceAll("\\", "/");
  // An external settings file can affect the run without appearing as a location in its JSON.
  if (isAbsolute(relativeValue) || relativeValue === ".." || relativeValue.startsWith("../")) {
    return {};
  }
  return { [key]: machinePath(pathValue, projectRoot) } as Partial<Record<Key, string>>;
}

/**
 * Converts a report location to a project-relative path with slash separators. The project root is shown as ".".
 *
 * @param pathValue - File or directory path to normalize inside the project.
 * @param projectRoot - Project root directory used to resolve absolute paths.
 * @returns Normalized project-relative POSIX path, or "." when it resolves to projectRoot.
 * @throws {Error} When a required location is empty or cannot be written as a path inside the project.
 */
function machinePath(pathValue: string, projectRoot: string): string {
  const nativeRelative = isAbsolute(pathValue) ? relative(projectRoot, pathValue) : pathValue;
  const relativeValue = nativeRelative.replaceAll("\\", "/");
  // An input such as an absolute path on another drive must resolve inside the project before it can appear as a report location.
  if (pathValue.length === 0 || relativeValue.startsWith("/") || /^[A-Za-z]:/u.test(relativeValue)) {
    throw new Error(`Machine path must be project-relative: ${JSON.stringify(pathValue)}`);
  }
  const parts: string[] = [];
  // Normalize each path segment so readers see the same file regardless of how the target was typed.
  for (const part of relativeValue.split("/")) {
    // Repeated slashes and explicit current-directory segments do not add a directory to the reported path.
    if (part.length === 0 || part === ".") {
      continue;
    }
    // A user can type a path containing ".." as long as it stays inside the selected project.
    if (part === "..") {
      // Moving above the selected project leaves no valid link for a consumer to follow.
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

/**
 * Returns integerValue if it is a positive integer, or undefined for an absent or invalid location value.
 * Callers omit optional coordinates and use line 1 when a finding has no valid start line.
 *
 * @param integerValue - Candidate coordinate value to validate as a positive integer.
 * @returns Validated positive integer, or undefined when absent, non-integer, or non-positive.
 */
function positiveInteger(integerValue: number | undefined): number | undefined {
  return integerValue !== undefined && Number.isInteger(integerValue) && integerValue > 0 ? integerValue : undefined;
}

/**
 * Renders SARIF 2.1.0 for GitHub code-scanning uploads.
 * The stable partialFingerprints.gruffFingerprint uses a baseline or computed identity to preserve cross-run alert matching.
 * Results with no identity omit the field.
 *
 * @param report - Supplies findings, suppressions, diagnostics and run metadata.
 * @returns Newline-terminated SARIF JSON.
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
      defaultEnabled: descriptor.isEnabledByDefault !== false,
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
            toolExecutionNotifications: report.diagnostics.map((diagnostic) => sarifDiagnostic(diagnostic, report.run.projectRoot)),
          },
        ],
        results: [
          ...report.findings.map((finding) => sarifResult(finding, ruleIndices)),
          // A finding another tool's comment or a repeated claim removed stays a result marked suppressed, so a
          // code-scanning tool shows it as suppressed rather than fixed (FAMILY-CONTRACT.md section 13c).
          ...(report.suppressedFindings ?? []).map(({ finding, justification }) => ({
            ...sarifResult(finding, ruleIndices),
            suppressions: [{ kind: "inSource", justification }],
          })),
        ],
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

/**
 * Return a SARIF invocation notification from the analysis diagnostic with a file anchor when a path is available.
 *
 * The severity contract treats an explicit non-invalidating flag as a note. An absent or true flag marks the run invalid and emits an error.
 * A path without a line gives a file-level location, and in-project absolute paths are made relative to `projectRoot`.
 *
 * @param diagnostic - Analysis diagnostic supplying type, message, validity flag, and optional location.
 * @param projectRoot - Project root used to normalize in-project file paths in both the artifact URI and message text.
 * @returns SARIF toolExecutionNotification entry with level, message, properties, and optional location.
 */
function sarifDiagnostic(
  diagnostic: AnalysisReport["diagnostics"][number],
  projectRoot: string,
): Record<string, unknown> {
  const fileEntry = diagnostic.filePath === undefined ? {} : optionalMachinePath("file", diagnostic.filePath, projectRoot);
  // A path outside the project is left out, as in JSON, so the user's host folders never reach a SARIF upload.
  const normalizedPath = fileEntry.file;
  const message = diagnostic.filePath !== undefined && fileEntry.file !== undefined && diagnostic.filePath !== fileEntry.file
    ? diagnostic.message.replaceAll(diagnostic.filePath, fileEntry.file)
    : diagnostic.message;
  return {
    descriptor: { id: diagnostic.diagnosticType },
    level: diagnostic.invalidatesRun === false ? "note" : "error",
    message: { text: message },
    ...(normalizedPath
      ? {
          locations: [{
            physicalLocation: {
              artifactLocation: { uri: sarifUri(normalizedPath) },
              ...(diagnostic.line === undefined ? {} : { region: { startLine: diagnostic.line } }),
            },
          }],
        }
      : {}),
    properties: { invalidatesRun: diagnostic.invalidatesRun !== false },
  };
}

/**
 * Preserve the stable alert identity because the analyser considers every finding together when assigning declaration ordinals.
 *
 * @param finding - Finding whose baseline identity is reused when present. Otherwise derive an identity from this finding alone.
 * @returns A gruffFingerprint record, or undefined for a sensitive or unnameable finding so SARIF omits the fingerprint.
 */
function sarifPartialFingerprints(finding: Finding): Record<string, string> | undefined {
  if (finding.baselineIdentity !== undefined) {
    return { gruffFingerprint: finding.baselineIdentity };
  }
  const named = findingIdentities([finding])[0];
  return named === undefined ? undefined : { gruffFingerprint: named.identity };
}

/**
 * Build the SARIF result with the stable alert identity used by GitHub code scanning when available.
 *
 * @param finding - Native finding supplying the result message, location, severity, and properties.
 * @param ruleIndices - Index of rule IDs in the SARIF rule list. An unknown ID leaves ruleIndex absent.
 * @returns A SARIF result object with optional properties populated from the finding when available.
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
  // Leave the alert without a durable fingerprint when the finding is sensitive or cannot be named.
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

/**
 * Returns the stable SARIF location for the finding's file.
 * With a line, the region includes any supplied column and end line. Without a line, the location identifies only the artifact.
 *
 * @param finding - Finding supplying the file path and optional line, column, and end line.
 * @returns SARIF physicalLocation record with artifactLocation and optional region.
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

/**
 * Returns a URI-encoded artifact path from filePath, replacing backslashes and stripping leading ./ segments.
 * Encodes segments separately to preserve path separators; absolute and parent-relative paths are not rejected.
 *
 * @param filePath - Finding or diagnostic file path to convert to a SARIF artifact URI.
 * @returns Slash-separated URI with each path segment percent-encoded.
 */
function sarifUri(filePath: string): string {
  return filePath
    .replaceAll("\\", "/")
    .replace(/^(?:\.\/)+/, "")
    .split("/")
    .map(encodeURIComponent)
    .join("/");
}

/**
 * Maps a gruff severity to its SARIF result level: error and warning are unchanged, and advisory returns note.
 *
 * @param severity - Native finding severity to translate into a SARIF level.
 * @returns Matching SARIF notification/result level ("error", "warning", or "note").
 */
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

/**
 * Render a terminal digest; callers needing a stable machine contract use analyse --format=json.
 *
 * @param report - findings, scores, diagnostics, baseline, and suppression data to summarize
 * @param elapsedMs - optional elapsed duration; omitted leaves out the Duration line
 * @param pathLabel - path shown in the digest; omitted uses the report's project root
 * @param top - number of leading clusters, rules, and file offenders to display; defaults to 10
 * @returns terminal summary text followed by a newline
 */
function renderSummary(report: AnalysisReport, elapsedMs?: number, pathLabel?: string, top = 10): string {
  const pillarRows = buildPillarRows(report);
  const breakdown = severityGradeBreakdown(report.findings);
  // FAMILY-CONTRACT section 1 keeps the masthead, composite, and finding totals ahead of port-specific summary lines.
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
  // FAMILY-CONTRACT.md section 13a requires a suppression audit on each surface that applies sensitive exclusions.
  // Keep this extension below the canonical block; machine counts belong to the v3 summary projection.
  lines.push(...renderTextSuppressionLines(report));
  return `${lines.join("\n")}\n`;
}

/**
 * Renders the JSON digest used by scripts that need the summary totals and exit outcome.
 * Invariant: the digest uses gruff.summary.v3 and carries no individual finding list.
 *
 * @param report - Native analysis report supplying the common machine envelope.
 * @param exitCode - gate result before filtering. Omit it to use the run's severity threshold.
 * @returns indented summary JSON with a trailing newline. A scan with no findings still includes its run details.
 */
function renderSummaryJson(report: AnalysisReport, exitCode?: number): string {
  return `${JSON.stringify(toJsonSummary(report, exitCode), null, 2)}\n`;
}

/**
 * Returns a diagnostic row shared by terminal summaries and text reports, with type and message from diagnostic.
 * Appends the parenthesized filePath only when present; otherwise the row has no location suffix.
 * Keep this shared shape stable for scripts that grep both output surfaces.
 *
 * @param diagnostic - Scan diagnostic providing diagnosticType, message, and optional filePath.
 * @returns Formatted single-line diagnostic bullet for terminal output.
 */
function summaryDiagnosticLine(diagnostic: AnalysisReport["diagnostics"][number]): string {
  const location = diagnostic.filePath ? ` (${diagnostic.filePath})` : "";
  return `- ${diagnostic.diagnosticType}: ${diagnostic.message}${location}`;
}

/**
 * Return the summary line from the report's baseline metadata under the baseline contract.
 * A generated baseline leaves current findings visible. An applied baseline reports its source and suppression count.
 *
 * @param baseline - Applied or generated baseline metadata attached to the analysis report.
 * @returns Single-line human-readable baseline status summary.
 */
function summaryBaselineLine(baseline: NonNullable<AnalysisReport["baseline"]>): string {
  if (baseline.generated) {
    return `Baseline: generated ${baseline.path}; current findings still shown`;
  }
  const findingNoun = baseline.suppressed === 1 ? "finding" : "findings";
  return `Baseline: ${baseline.source} ${baseline.path}; suppressed ${baseline.suppressed} ${findingNoun}`;
}

/**
 * Returns elapsedMs as a summary duration, rounding to whole milliseconds below one second and two-decimal seconds otherwise.
 * Negative durations display as 0ms.
 *
 * @param elapsedMs - Measured run duration in milliseconds.
 * @returns Human-readable duration formatted in milliseconds or seconds.
 */
function formatSummaryDuration(elapsedMs: number): string {
  const bounded = Math.max(0, elapsedMs);
  if (bounded < 1000) {
    return `${Math.round(bounded)}ms`;
  }
  return `${(bounded / 1000).toFixed(2)}s`;
}

/**
 * Render the terminal Pillars block with a two-space row indent and three spaces between count cells.
 * Names and counts expand to fit; count cells use at least three characters and scores use two decimals in at least six (or `n/a` when unevaluated).
 *
 * @param rows - pillar summaries to display in their supplied order; an empty list renders a `(none)` placeholder
 * @returns Heading and formatted rows, or a heading and `(none)` marker when rows is empty.
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
    const score = (row.score === null ? "n/a" : row.score.toFixed(2)).padStart(6);
    const findingsCell = `findings=${String(row.findings).padEnd(findingsWidth)}`;
    const advisoryCell = `advisory=${String(row.advisory).padEnd(advisoryWidth)}`;
    const warningCell = `warning=${String(row.warning).padEnd(warningWidth)}`;
    const errorCell = `error=${String(row.error).padEnd(errorWidth)}`;
    const line = `  ${name} ${row.grade} ${score} ${findingsCell}   ${advisoryCell}   ${warningCell}   ${errorCell}`.replace(/\s+$/, "");
    lines.push(line);
  }
  return lines;
}

/**
 * Show severity counts and short descriptions so operators can triage the most frequent rules first.
 *
 * @param findings - Findings to group by rule and tally by severity.
 * @param limit - Cap on ranked rows. Omit it to show every rule with findings.
 * @returns Stable bullets by descending count then ascending rule ID. No findings give a placeholder. Unknown rules have blank descriptions.
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

// 60-char description budget that keeps the rule-row line compact even with long rule IDs; uses a single Unicode ellipsis glyph on truncation.
const DESCRIPTION_BODY_LIMIT = 60;

/**
 * Returns the rule description text unchanged when it fits DESCRIPTION_BODY_LIMIT.
 * Longer text is cut to that many UTF-16 code units, trimmed at the end, and given an ellipsis; row width remains variable.
 *
 * @param text - Raw rule description text to fit within the summary row budget.
 * @returns Original description or a trimmed prefix followed by a single ellipsis character.
 */
function truncateDescription(text: string): string {
  return text.length <= DESCRIPTION_BODY_LIMIT ? text : `${text.slice(0, DESCRIPTION_BODY_LIMIT).trimEnd()}…`;
}

/**
 * Returns the supplied analysis report as newline-terminated terminal text.
 * Lists full finding messages in the supplied stable order so that grep sees consistent rows.
 * A finding with no source line is displayed at line 1.
 *
 * @param report - Native analysis report supplying scores, diagnostics, notes, findings, suppressions, and baseline metadata.
 * @returns Complete terminal report text ending with a newline.
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
  // Under ADR-006, name the applied baseline and its selection source so hidden findings never read as a clean scan.
  if (report.baseline !== undefined && !report.baseline.generated) {
    lines.push("", summaryBaselineLine(report.baseline));
  }
  return `${lines.join("\n")}\n`;
}

/**
 * Render the suppression summary using the stable text contract in gruff-rs/src/render/text.rs.
 * Each positive row shows the exclusion label, rule, count, and rationale without printing matched evidence.
 *
 * @param report - Analysis report whose suppression rows supply the total and details.
 * @returns A separator and one summary line when the total is positive, or an empty list when nothing was suppressed.
 */
function renderTextSuppressionLines(report: AnalysisReport): string[] {
  const total = totalSuppressedFindings(report.suppressions);
  // Nothing suppressed means no line at all, matching the reference renderer.
  if (total === 0) {
    return [];
  }
  const details = report.suppressions
    .filter((summary) => summary.suppressed > 0)
    // Built-in and section 13c rows put the first covered path in the label brackets. A missing path leaves the brackets empty.
    .map((summary) => (summary.source === undefined
      ? `sensitiveExclusions[${summary.index}] ${summary.rule}: ${summary.suppressed} (${summary.reason})`
      : `${summary.source === "built-in" ? "builtInTestPath" : summary.source}[${summary.paths[0] ?? ""}] ${summary.rule}: ${summary.suppressed} (${summary.reason})`))
    .join("; ");
  return ["", `Suppressed findings: ${total} via ${details}`];
}

/**
 * Keep the Pillars table ahead of individual findings so readers see the breakdown in a report preview.
 * Use the shared pillar rows to preserve deterministic order across formats.
 *
 * @param report - Native analysis report supplying the score, diagnostics, pillars, and findings in display order.
 * @returns Markdown with diagnostics when present and at most the first 50 individual findings.
 */
function renderMarkdown(report: AnalysisReport): string {
  const breakdown = severityGradeBreakdown(report.findings);
  // Keep repository text from changing the Markdown structure. An unlocated finding uses line 1 as its display anchor.
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
    // A missing composite score or grade uses the same nothing-evaluated wording as the text report.
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

/**
 * Preserve the shared seven-column Markdown table contract, including two-decimal scores and escaped cell pipes.
 *
 * @param rows - Pillar rows in caller order. buildPillarRows supplies findings DESC, then pillar ASC.
 * @returns Table lines including a placeholder row when there are no pillars to list.
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
    const scoreText = row.score === null ? "n/a" : row.score.toFixed(2);
    lines.push(
      `| ${escapeMarkdownCell(row.pillar)} | ${escapeMarkdownCell(row.grade)} | ${scoreText} | ${row.findings} | ${row.advisory} | ${row.warning} | ${row.error} |`,
    );
  }
  return lines;
}

/**
 * Returns cell with pipe characters escaped for a Markdown table cell.
 * Callers supply single-line pillar and grade labels; this helper does not escape other Markdown syntax.
 *
 * @param cell - Single-line label placed inside a Markdown table column.
 * @returns Escaped cell text with literal pipe characters prefixed by a backslash.
 */
function escapeMarkdownCell(cell: string): string {
  return cell.replaceAll("|", "\\|");
}

/**
 * Wraps a repository-controlled label in a CommonMark code span for PR and issue reports.
 * A fence longer than the label's longest backtick run keeps the label inside one span.
 *
 * @param reportLabel - Rule ID, diagnostic type, or file path label to wrap in inline code.
 * @returns Single-line CommonMark inline code span safely fenced around the label.
 */
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

/**
 * Escapes finding and diagnostic messages to preserve the Markdown report's stable entry layout.
 * Line breaks collapse so a message cannot start a new heading, list, or HTML block.
 *
 * @param findingMessage - Raw finding or diagnostic message text to sanitize for Markdown output.
 * @returns Single-line message with HTML entities and Markdown control characters escaped.
 */
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

const CORRELATED_COMPLEXITY_RULE_IDS = new Set(["complexity.cyclomatic", "size.function-length"]);

/**
 * Returns a text heading and one line per selected complexity cluster from the supplied findings, in stable rank order.
 * The limit is the end position in that list and defaults to 10. An empty selection returns no heading or rows.
 *
 * @param findings - Analysis findings inspected for overlapping complexity rules on the same symbol.
 * @param limit - Maximum number of clusters to render; defaults to 10.
 * @returns Heading and cluster bullet lines, or empty when no symbol has overlapping complexity findings.
 */
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

/**
 * Returns the Markdown heading and rows for all clusters in the supplied findings, using the same grouping contract as text output.
 *
 * @param findings - Analysis findings inspected for overlapping complexity rules on the same symbol.
 * @returns Markdown section heading and bullet lines, or empty when no clusters exist.
 */
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

/**
 * Formats one correlated cluster for the Markdown list a reviewer sees in pull-request output.
 *
 * @param cluster - Correlated complexity cluster identifying a file, symbol, and linked rule IDs.
 * @returns Markdown list item showing the inline-coded symbol anchor, finding count, and rule IDs.
 */
function renderMarkdownComplexityClusterRow(cluster: ComplexityCluster): string {
  const clusterLabel = `${cluster.filePath}#${cluster.symbol}`;
  // Every linked rule remains its own code span so a reviewer can copy its exact identifier.
  const linkedRuleLabels = cluster.ruleIds.map((ruleId) => markdownInlineCode(ruleId)).join(", ");
  return `- ${markdownInlineCode(clusterLabel)}: ${cluster.ruleIds.length} linked findings (${linkedRuleLabels})`;
}

/**
 * Returns stable clusters from the supplied complexity findings so that renderers explain overlaps consistently.
 * A file and symbol qualify only when at least two distinct correlated rules fired there. Otherwise no cluster is emitted for that pair.
 * The list is empty without a qualifying overlap. Clusters rank by descending rule count, then path and symbol, with sorted rule IDs.
 *
 * @param findings - Findings to group by file path and symbol across correlated complexity rules.
 * @returns Ranked list of complexity clusters with sorted rule IDs, or empty when none qualify.
 */
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

/**
 * Returns newline-separated GitHub Actions annotations for report diagnostics and findings; missing finding lines use line 1.
 * File paths are normalized, and file and title values must be command-escaped because commas and colons are delimiters.
 * Returns an empty string when the report has neither diagnostics nor findings.
 *
 * @param report - Native analysis report supplying diagnostics and findings to annotate.
 * @returns Newline-joined GitHub workflow command lines, or an empty string when there is nothing to report.
 */
function renderGithub(report: AnalysisReport): string {
  return [
    ...report.diagnostics.map(githubDiagnostic),
    ...report.findings.map((finding) => `::${githubLevel(finding.severity)} file=${escapeCommandProperty(githubAnnotationPath(finding.filePath))},line=${finding.line ?? 1},title=${escapeCommandProperty(finding.ruleId)}::${escapeCommand(finding.message)}`),
  ]
    .join("\n");
}

/**
 * Returns a GitHub Actions annotation for the supplied run diagnostic. The level contract uses notice only when invalidatesRun is false.
 * Without a file path the annotation has no location. With a file path and no line, it defaults to line 1.
 *
 * @param diagnostic - Analysis diagnostic supplying type, message, validity flag, and optional location.
 * @returns Single GitHub Actions workflow command for the diagnostic.
 */
function githubDiagnostic(diagnostic: AnalysisReport["diagnostics"][number]): string {
  const level = diagnostic.invalidatesRun === false ? "notice" : "error";
  const location = diagnostic.filePath
    ? ` file=${escapeCommandProperty(githubAnnotationPath(diagnostic.filePath))},line=${diagnostic.line ?? 1},`
    : " ";
  return `::${level}${location}title=${escapeCommandProperty(diagnostic.diagnosticType)}::${escapeCommand(diagnostic.message)}`;
}

/**
 * Returns filePath for a GitHub annotation with forward slashes and without leading dot-slash segments.
 * Equivalent slash and dot-prefix spellings share one path. Absolute paths and parent segments are preserved.
 *
 * @param filePath - Raw file path from a finding or diagnostic.
 * @returns Normalized forward-slash path stripped of leading dot-slash prefixes.
 */
function githubAnnotationPath(filePath: string): string {
  return filePath.replaceAll("\\", "/").replace(/^(?:\.\/)+/, "");
}

/**
 * Three GitHub annotation levels - gruff's "advisory" collapses to "notice" because Actions has
 * no fourth tier and "notice" is the documented soft-warning level.
 *
 * @param severity - Native finding severity to map onto GitHub Actions annotation levels.
 * @returns Corresponding GitHub annotation command name ("error", "warning", or "notice").
 */
function githubLevel(severity: Severity): "notice" | "warning" | "error" {
  return severity === "error" ? "error" : severity === "warning" ? "warning" : "notice";
}

/**
 * Returns commandText with the base GitHub Actions escapes for messages and property values. % must be first, otherwise the
 * %0A replacement would itself be re-encoded.
 *
 * @param commandText - Raw message or property value emitted in a GitHub workflow command.
 * @returns Percent-escaped text safe for GitHub Actions workflow command payloads.
 */
function escapeCommand(commandText: string): string {
  return commandText.replaceAll("%", "%25").replaceAll("\n", "%0A").replaceAll("\r", "%0D");
}

/**
 * Returns propertyText with the base command escapes plus colon and comma escapes because GitHub workflow
 * commands use commas between properties and double colons around the command header.
 *
 * @param propertyText - Raw property value such as a file path or rule title for a workflow command.
 * @returns Escaped property value safe for key-value pairs inside a GitHub Actions command header.
 */
function escapeCommandProperty(propertyText: string): string {
  return escapeCommand(propertyText).replaceAll(":", "%3A").replaceAll(",", "%2C");
}

export { renderReport, renderSummary, renderSummaryJson };
