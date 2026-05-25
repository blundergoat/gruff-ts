// Text, SARIF, hotspot, markdown, GitHub, and summary renderers for the stable analysis report.
// HTML output and dashboard chrome live in `report-html.ts` so this module stays under the
// `size.file-length` threshold; both files source `buildPillarRows` + `grade` from
// `pillar-summary.ts` so the cross-format Pillars table stays byte-aligned.
import type { AnalysisReport, Finding, OutputFormat, Severity } from "./types.ts";
import { buildPillarRows, type PillarRow } from "./pillar-summary.ts";
import { ruleDescriptors } from "./rules.ts";
import { renderHtml } from "./report-html.ts";

/*
 * Format dispatcher. `hotspot` is emitted inline (smallest schema) while every other format has a
 * dedicated renderer. The stable schema string `gruff.hotspot.v1` is part of the public contract;
 * bump it only when changing the hotspot payload shape.
 */
function renderReport(report: AnalysisReport, format: OutputFormat): string {
  switch (format) {
    case "json":
      return JSON.stringify(report, null, 2);
    case "html":
      return renderHtml(report);
    case "markdown":
      return renderMarkdown(report);
    case "github":
      return renderGithub(report);
    case "hotspot":
      return JSON.stringify({ schemaVersion: "gruff.hotspot.v1", tool: report.tool, score: report.score.composite, files: report.score.topOffenders.slice(0, 10) }, null, 2);
    case "sarif":
      return renderSarif(report);
    case "text":
      return renderText(report);
  }
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

/*
 * Maps one Finding into a SARIF result row. The stable, deterministic fingerprint in
 * `partialFingerprints` is the public contract - GitHub code-scanning keys alerts off it.
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
    partialFingerprints: {
      gruffFingerprint: finding.fingerprint,
    },
  };
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
  const lines = [
    `gruff-ts ${report.tool.version} summary`,
    `Path: ${pathLabel ?? report.run.projectRoot}`,
    ...(typeof elapsedMs === "number" ? [`Duration: ${formatSummaryDuration(elapsedMs)}`] : []),
    `Score: ${report.score.composite.toFixed(1)} (${report.score.grade})`,
    `Findings: ${report.summary.total} total, ${report.summary.error} error, ${report.summary.warning} warning, ${report.summary.advisory} advisory`,
    `Analysed files: ${report.paths.analysedFiles}`,
    ...(report.baseline ? [summaryBaselineLine(report.baseline)] : []),
  ];
  if (report.diagnostics.length > 0) {
    lines.push("", "Diagnostics:", ...report.diagnostics.map(summaryDiagnosticLine));
  }
  lines.push("", ...renderPillarsBlock(pillarRows));
  lines.push("", `Top ${top} rules:`);
  lines.push(...renderRankedCounts(ruleCounts, "No rule findings.", top));
  lines.push("", `Top ${top} file offenders:`);
  lines.push(
    ...(
      report.score.topOffenders.length === 0
        ? ["- No file offenders."]
        : report.score.topOffenders.slice(0, top).map((offender) => `- ${offender.filePath}: ${offender.findings} findings, score ${offender.score.toFixed(1)}`)
    ),
  );
  return `${lines.join("\n")}\n`;
}

/*
 * Renders the stable public `gruff.summary.v2` JSON contract for the `summary --format=json` flow.
 * Phase 2 of the cross-port harmonisation replaces the flat `{pillar, count}` shape with rich
 * per-pillar objects carrying grade, score, applicability, and per-severity counts (findings,
 * advisory, warning, error). The schema-version string is bumped because downstream CI consumers
 * parse this payload and the field-set is no longer compatible with v1; scope/score/topRules/
 * topOffenders remain unchanged.
 */
function renderSummaryJson(report: AnalysisReport, elapsedMs?: number, pathLabel?: string, top = 10): string {
  const ruleCounts = countBy(report.findings, (finding) => finding.ruleId);
  const pillarRows = buildPillarRows(report);
  const payload = {
    schemaVersion: "gruff.summary.v2",
    tool: report.tool,
    scope: {
      paths: pathLabel ?? report.run.projectRoot,
      projectRoot: report.run.projectRoot,
      analysedFiles: report.paths.analysedFiles,
      ignoredPaths: report.paths.ignoredPaths.length,
      missingPaths: report.paths.missingPaths.length,
      diagnostics: report.diagnostics.length,
      elapsedSeconds: typeof elapsedMs === "number" ? Number((elapsedMs / 1000).toFixed(3)) : undefined,
    },
    score: report.score,
    findings: report.summary,
    baseline: report.baseline,
    pillars: pillarRows.map((row) => ({
      pillar: row.pillar,
      grade: row.grade,
      score: row.score,
      penalty: row.penalty,
      applicable: row.isApplicable,
      findings: row.findings,
      advisory: row.advisory,
      warning: row.warning,
      error: row.error,
    })),
    topRules: renderRankedCountRows(ruleCounts, top),
    topOffenders: report.score.topOffenders.slice(0, top),
  };
  return `${JSON.stringify(payload, null, 2)}\n`;
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

function renderRankedCounts<T extends string>(counts: Map<T, number>, emptyText: string, limit?: number): string[] {
  if (counts.size === 0) {
    return [`- ${emptyText}`];
  }
  return [...counts.entries()]
    .sort(([leftKey, leftCount], [rightKey, rightCount]) => rightCount - leftCount || leftKey.localeCompare(rightKey))
    .slice(0, limit ?? counts.size)
    .map(([key, count]) => `- ${key}: ${count}`);
}

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
  const lines = [
    `gruff-ts ${report.tool.version}`,
    `Score: ${report.score.composite.toFixed(1)} (${report.score.grade}) | Findings: ${report.summary.advisory} advisory, ${report.summary.warning} warning, ${report.summary.error} error`,
    `Analysed files: ${report.paths.analysedFiles}`,
  ];
  if (report.diagnostics.length > 0) {
    lines.push("", "Diagnostics:", ...report.diagnostics.map(summaryDiagnosticLine));
  }
  if (report.findings.length > 0) {
    lines.push("", "Findings:", ...report.findings.map((finding) => `- [${finding.severity}] ${finding.filePath}:${finding.line ?? 1} ${finding.ruleId} - ${finding.message}`));
  }
  return `${lines.join("\n")}\n`;
}

/*
 * Markdown renderer for the `gruff.analysis.v1` report. Truncates to 50 findings because Markdown
 * previews (PR comments, READMEs) start mangling longer tables; the JSON and HTML renderers stay
 * the canonical full-fidelity output. Public contract / invariant: the Pillars table is inserted
 * between the severity counts and the per-finding list so CI logs and PR comment previews see it
 * first, and it shares its row data and sort order with the text/JSON/HTML pillar renderers via
 * `buildPillarRows` so all four surfaces stay deterministic and byte-aligned across runs.
 */
function renderMarkdown(report: AnalysisReport): string {
  return [
    "# gruff-ts report",
    "",
    `Score: **${report.score.composite.toFixed(1)} (${report.score.grade})**`,
    "",
    `Findings: ${report.summary.advisory} advisory, ${report.summary.warning} warning, ${report.summary.error} error.`,
    "",
    ...renderMarkdownPillarsTable(buildPillarRows(report)),
    "",
    ...report.findings.slice(0, 50).map((finding) => `- \`${finding.ruleId}\` \`${finding.filePath}\`:${finding.line ?? 1} - ${finding.message}`),
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

// GitHub Actions `::workflow command` syntax. Public contract invariant: file/title properties
// must be normalized and command-escaped before interpolation because commas and colons delimit the property list.
function renderGithub(report: AnalysisReport): string {
  return report.findings
    .map((finding) => `::${githubLevel(finding.severity)} file=${escapeCommandProperty(githubAnnotationPath(finding.filePath))},line=${finding.line ?? 1},title=${escapeCommandProperty(finding.ruleId)}::${escapeCommand(finding.message)}`)
    .join("\n");
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
