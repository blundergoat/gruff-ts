// Text, HTML, SARIF, hotspot, and dashboard renderers for the stable analysis report.
import type { AnalysisReport, Finding, OutputFormat, Severity } from "./types.ts";
import { ruleDescriptors } from "./rules.ts";

const CYCLOMATIC_BUCKETS = [
  { label: "21+", minimum: 21 },
  { label: "16-20", minimum: 16 },
  { label: "11-15", minimum: 11 },
  { label: "6-10", minimum: 6 },
  { label: "1-5", minimum: 1 },
] as const;

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
      return JSON.stringify({ schemaVersion: "gruff.hotspot.v1", tool: report.tool, score: report.score.composite, files: report.score.topOffenders }, null, 2);
    case "sarif":
      return renderSarif(report);
    case "text":
      return renderText(report);
  }
}

/*
 * SARIF 2.1.0 output for GitHub code-scanning uploads. Kept as one large object literal because
 * the SARIF schema demands a specific shape — splitting it up obscures which fields are required.
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
 * `partialFingerprints` is the public contract — GitHub code-scanning keys alerts off it.
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
 * populated when the Finding carries them — SARIF requires `region` to be omitted (not empty)
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
function renderSummary(report: AnalysisReport, elapsedMs?: number, pathLabel?: string): string {
  const pillarCounts = countBy(report.findings, (finding) => finding.pillar);
  const ruleCounts = countBy(report.findings, (finding) => finding.ruleId);
  const lines = [
    `gruff-ts ${report.tool.version} summary`,
    `Path: ${pathLabel ?? report.run.projectRoot}`,
    ...(typeof elapsedMs === "number" ? [`Duration: ${formatSummaryDuration(elapsedMs)}`] : []),
    `Score: ${report.score.composite.toFixed(1)} (${report.score.grade})`,
    `Findings: ${report.summary.total} total, ${report.summary.error} error, ${report.summary.warning} warning, ${report.summary.advisory} advisory`,
    `Analysed files: ${report.paths.analysedFiles}`,
  ];
  if (report.diagnostics.length > 0) {
    lines.push("", "Diagnostics:", ...report.diagnostics.map(summaryDiagnosticLine));
  }
  lines.push("", "Per-pillar counts:");
  lines.push(...renderRankedCounts(pillarCounts, "No findings by pillar."));
  lines.push("", "Top rules:");
  lines.push(...renderRankedCounts(ruleCounts, "No rule findings."));
  lines.push("", "Top file offenders:");
  lines.push(
    ...(
      report.score.topOffenders.length === 0
        ? ["- No file offenders."]
        : report.score.topOffenders.map((offender) => `- ${offender.filePath}: ${offender.findings} findings, score ${offender.score.toFixed(1)}`)
    ),
  );
  return `${lines.join("\n")}\n`;
}

// Shared text formatter for diagnostic rows in plain-text summaries and the `text` format. Stable
// "- {type}: {message} (path)" shape is part of the contract that scripts grepping the text output
// rely on, so the format must stay deterministic across both call sites.
function summaryDiagnosticLine(diagnostic: AnalysisReport["diagnostics"][number]): string {
  const location = diagnostic.filePath ? ` (${diagnostic.filePath})` : "";
  return `- ${diagnostic.diagnosticType}: ${diagnostic.message}${location}`;
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

function renderRankedCounts<T extends string>(counts: Map<T, number>, emptyText: string): string[] {
  if (counts.size === 0) {
    return [`- ${emptyText}`];
  }
  return [...counts.entries()]
    .sort(([leftKey, leftCount], [rightKey, rightCount]) => rightCount - leftCount || leftKey.localeCompare(rightKey))
    .slice(0, 10)
    .map(([key, count]) => `- ${key}: ${count}`);
}

/*
 * Default terminal output. Findings are listed verbatim (no truncation) — the analyser keeps them
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

// Truncates to 50 findings because Markdown previews (PR comments, READMEs) start mangling longer
// tables. The stable JSON or HTML renderers stay the canonical full-fidelity output.
function renderMarkdown(report: AnalysisReport): string {
  return [
    "# gruff-ts report",
    "",
    `Score: **${report.score.composite.toFixed(1)} (${report.score.grade})**`,
    "",
    `Findings: ${report.summary.advisory} advisory, ${report.summary.warning} warning, ${report.summary.error} error.`,
    ...report.findings.slice(0, 50).map((finding) => `- \`${finding.ruleId}\` \`${finding.filePath}\`:${finding.line ?? 1} - ${finding.message}`),
  ].join("\n");
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

// Extra metadata appended to dashboard-served HTML. Static-file consumers never see it because the
// CLI calls `renderHtml` without this argument; only the dashboard route passes it in.
interface DashboardRenderContext {
  projectRoot: string;
  scanPath: string;
}

/*
 * Self-contained HTML output (CSS inlined, no external assets) so reports can be archived or
 * emailed. The schema invariant: every Finding listed in the report must be reachable through
 * deep links — the on-page JS in `dashboardJs` relies on stable `data-path` attributes.
 */
function renderHtml(report: AnalysisReport, dashboardContext?: DashboardRenderContext): string {
  const bodySections = [
    htmlMasthead(report),
    htmlDiagnostics(report),
    dashboardContext ? htmlDashboardContext(dashboardContext) : "",
    htmlVerdict(report),
    htmlPillars(report),
    htmlOffenders(report),
    htmlDistribution(report),
    htmlFindings(report),
    htmlFooter(report),
  ].join("\n");
  return `<!doctype html>
<html lang="en-NZ">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>gruff-ts report - ${escapeHtml(report.score.grade)}</title>
<style>${htmlReportCss(report.diagnostics.length > 0)}</style>
</head>
<body>
<main class="paper"><span class="corner-tr"></span><span class="corner-bl"></span>
${bodySections}
</main>
</body>
</html>`;
}

// Top banner: path count, format, fail-on, schema version. The schemaVersion text is the
// contract surface — operators eyeball it to confirm the report shape they expect.
function htmlMasthead(report: AnalysisReport): string {
  const paths = report.paths.analysedFiles === 0 ? "." : `${report.paths.analysedFiles} analysed ${report.paths.analysedFiles === 1 ? "file" : "files"}`;
  return `<header class="masthead"><div class="brand"><div class="wordmark">gruff</div><div class="tagline">ts/js code quality - inspection report</div></div><div class="meta">${htmlMetaRow("paths", paths)}${htmlMetaRow("format", report.run.format)}${htmlMetaRow("fail", report.run.failOn)}${htmlMetaRow("schema", report.schemaVersion)}<div class="inspection-id">gruff-ts ${escapeHtml(report.tool.version)}</div></div></header>`;
}

// Single key/value row. Both inputs are escaped — they reach this function as user-influenced
// strings (paths, format names) and would otherwise enable injection in archived reports.
function htmlMetaRow(label: string, metaValue: string): string {
  const escapedLabel = escapeHtml(label);
  const escapedValue = escapeHtml(metaValue);
  return `<div><span class="label">${escapedLabel}</span><span class="val">${escapedValue}</span></div>`;
}

// Diagnostics are parse/IO failures, not normal findings. HTML renders them before score sections
// because partial scans must remain visibly incomplete; omitting empty diagnostics is the stable contract.
function htmlDiagnostics(report: AnalysisReport): string {
  if (report.diagnostics.length === 0) {
    return "";
  }
  const diagnostics = report.diagnostics.map(htmlDiagnosticEntry).join("");
  return `<section class="diagnostics"><h2 class="section-head">diagnostics <span class="aside">run messages</span></h2><div class="diagnostic-list">${diagnostics}</div></section>`;
}

// HTML markup for one diagnostic entry. The `diagnostic-type`/`diagnostic-message`/`diagnostic-location`
// span classes are part of the stable HTML report contract — the dashboard CSS and any downstream
// scraping keys off them, so the structure here must stay invariant across renderer changes.
function htmlDiagnosticEntry(diagnostic: AnalysisReport["diagnostics"][number]): string {
  const lineSuffix = diagnostic.line ? `:${diagnostic.line}` : "";
  const location = diagnostic.filePath
    ? `<span class="diagnostic-location">${escapeHtml(diagnostic.filePath)}${lineSuffix}</span>`
    : "";
  return `<div class="diagnostic"><span class="diagnostic-type">${escapeHtml(diagnostic.diagnosticType)}</span><span class="diagnostic-message">${escapeHtml(diagnostic.message)}</span>${location}</div>`;
}

// Dashboard-only banner that names the project root and scan path. Static reports never include
// this; both inputs are user-controlled query parameters and are escaped before reaching HTML.
function htmlDashboardContext(context: DashboardRenderContext): string {
  const escapedProjectRoot = escapeHtml(context.projectRoot);
  const escapedScanPath = escapeHtml(context.scanPath);
  return `<section class="dashboard-context"><h2 class="section-head">dashboard scan <span class="aside">local run</span></h2><div class="dashboard-context-grid"><div><span class="label">Project root</span><span class="val">${escapedProjectRoot}</span></div><div><span class="label">Path</span><span class="val">${escapedScanPath}</span></div></div></section>`;
}

/*
 * The grade stamp + four stat cards. The verdict shape is part of the stable visual contract that
 * the dashboard relies on for parity with static reports.
 */
function htmlVerdict(report: AnalysisReport): string {
  const gradeCssClass = gradeClass(report.score.grade);
  const escapedGrade = escapeHtml(report.score.grade);
  const scoreText = report.score.composite.toFixed(1);
  const escapedSummary = escapeHtml(verdictSummary(report));
  const stats = `${htmlStat(String(report.summary.total), "findings", "")}${htmlStat(String(report.summary.error), "errors", "fail")}${htmlStat(String(report.summary.warning), "warnings", "warn")}${htmlStat(String(report.summary.advisory), "advisories", "note")}`;
  return `<section class="verdict"><div class="grade-stamp ${gradeCssClass}"><div class="grade-letter">${escapedGrade}</div><div class="grade-score">${scoreText} / 100</div></div><div class="verdict-body"><div class="verdict-headline">Inspection complete.<br><em>${escapedSummary}</em></div><div class="verdict-stats">${stats}</div></div></section>`;
}

// Headline sentence. Counts only warning/error findings — advisories are intentionally excluded
// from the verdict text because they are below the stable "needs attention" threshold.
function verdictSummary(report: AnalysisReport): string {
  const thresholdFindings = report.summary.warning + report.summary.error;
  if (thresholdFindings === 0) {
    return "No warning or error findings flagged.";
  }
  const pillars = new Set(report.findings.filter((finding) => finding.severity === "warning" || finding.severity === "error").map((finding) => finding.pillar));
  return `${thresholdFindings} ${thresholdFindings === 1 ? "finding" : "findings"} at warning or error severity across ${pillars.size} ${pillars.size === 1 ? "pillar" : "pillars"}.`;
}

// One stat card (number + label). `className` is a curated, non-escaped CSS class — callers must
// not pass user input here or it would break the layout in archived reports.
function htmlStat(number: string, label: string, className: string): string {
  const escapedClassName = escapeHtml(className);
  const escapedNumber = escapeHtml(number);
  const escapedLabel = escapeHtml(label);
  return `<div class="stat"><div class="num ${escapedClassName}">${escapedNumber}</div><div class="lbl">${escapedLabel}</div></div>`;
}

/*
 * Pillar score grid in the same order the analyser produced — the stable composite score is the
 * mean of these pillars (see `scoreReport`), so visual order matches the headline-grade derivation.
 */
function htmlPillars(report: AnalysisReport): string {
  const items =
    report.score.pillars.length === 0
      ? '<div class="empty">No pillar findings.</div>'
      : report.score.pillars
          .map((pillar) => {
            const letter = grade(pillar.score);
            return `<div class="pillar"><div class="name">${escapeHtml(pillar.pillar)}</div><div class="grade ${gradeClass(letter)}">${letter}</div><div class="breakdown"><div class="row"><span class="key">score</span><span class="val">${pillar.score.toFixed(1)}</span></div><div class="row"><span class="key">findings</span><span class="val">${pillar.findings}</span></div></div></div>`;
          })
          .join("");
  return `<section class="pillars"><h2 class="section-head">pillar grades <span class="aside">weighted composite</span></h2><div class="pillar-grid">${items}</div></section>`;
}

// Top-10 offender table, ordered by ascending score (worst first). `scoreReport` already truncated
// the list to 10 — this stable, deterministic limit is part of the public report contract.
function htmlOffenders(report: AnalysisReport): string {
  const rows =
    report.score.topOffenders.length === 0
      ? '<tr><td colspan="4">No offenders found.</td></tr>'
      : report.score.topOffenders
          .map((file) => {
            const letter = grade(file.score);
            return `<tr><td class="file-path">${htmlLocation(file.filePath)}</td><td class="num">${file.score.toFixed(1)}</td><td class="num">${file.findings}</td><td class="num"><span class="grade-pill ${gradeClass(letter)}">${letter}</span></td></tr>`;
          })
          .join("");
  return `<section class="offenders"><h2 class="section-head">top offenders <span class="aside">sorted by score</span></h2><table class="offender-list"><thead><tr><th scope="col">file</th><th scope="col" class="num">score</th><th scope="col" class="num">findings</th><th scope="col" class="num">grade</th></tr></thead><tbody>${rows}</tbody></table></section>`;
}

/*
 * Histogram of cyclomatic-complexity buckets. The 5 fixed buckets are part of the stable visual
 * vocabulary maintainers learn over time — adding a new bucket would invalidate that mental model.
 */
function htmlDistribution(report: AnalysisReport): string {
  const distribution = cyclomaticDistribution(report);
  const max = Math.max(1, ...Object.values(distribution));
  const bars = Object.entries(distribution)
    .map(([label, count]) => {
      const height = Math.max(4, Math.round((count / max) * 100));
      const className = label === "16-20" || label === "21+" ? " fail" : label === "11-15" ? " warn" : "";
      return `<div class="bar${className}" style="height:${height}%;"><span class="count">${count}</span></div>`;
    })
    .join("");
  const axis = Object.keys(distribution)
    .map((label) => `<span>${escapeHtml(label)}</span>`)
    .join("");
  return `<section class="chart-section"><h2 class="section-head">distribution <span class="aside">cyclomatic complexity</span></h2><p class="chart-summary">${escapeHtml(cyclomaticSummary(distribution))}</p><div class="chart-card"><div class="title">cyclomatic complexity - flagged functions</div><div class="histogram">${bars}</div><div class="histogram-axis">${axis}</div></div></section>`;
}

/*
 * Pre-seeded with zero counts for every bucket so the resulting record has a stable key order
 * in JSON dumps. Findings outside `complexity.cyclomatic` are ignored — see `cyclomaticFindingBucket`.
 */
function cyclomaticDistribution(report: AnalysisReport): Record<string, number> {
  const distribution: Record<string, number> = { "1-5": 0, "6-10": 0, "11-15": 0, "16-20": 0, "21+": 0 };
  for (const finding of report.findings) {
    const bucket = cyclomaticFindingBucket(finding);
    if (bucket) {
      distribution[bucket] = (distribution[bucket] ?? 0) + 1;
    }
  }
  return distribution;
}

// Extracts the cyclomatic number from the finding message because the metadata schema doesn't
// expose it as a top-level field — coupling the renderer to the message text is acceptable here
// because the message format is itself part of the stable rule contract.
function cyclomaticFindingBucket(finding: Finding): string | undefined {
  if (finding.ruleId !== "complexity.cyclomatic") {
    return undefined;
  }
  const match = finding.message.match(/cyclomatic complexity (\d+)/);
  const complexityValue = match?.[1] ? Number(match[1]) : undefined;
  return complexityValue === undefined ? undefined : cyclomaticBucket(complexityValue);
}

// Linear walk in descending-minimum order so the first match wins — required because `21+` and
// `16-20` would otherwise both apply to a value of 25.
function cyclomaticBucket(complexityValue: number): string | undefined {
  for (const bucket of CYCLOMATIC_BUCKETS) {
    if (complexityValue >= bucket.minimum) {
      return bucket.label;
    }
  }
  return undefined;
}

// One-line caption that quantifies how many functions exceed CC=10. The pluralisation handling
// matters — "1 functions exceed" reads poorly enough that a reviewer would file it as a regression.
function cyclomaticSummary(distribution: Record<string, number>): string {
  const moderate = distribution["11-15"] ?? 0;
  const high = distribution["16-20"] ?? 0;
  const severe = distribution["21+"] ?? 0;
  const exceeds = moderate + high + severe;
  return `${exceeds} ${exceeds === 1 ? "function" : "functions"} ${exceeds === 1 ? "exceeds" : "exceed"} CC 10 (${moderate} in 11-15, ${high} in 16-20, ${severe} at 21+).`;
}

// Caps the list at 250 entries because the inline-CSS report becomes painful to scroll past that.
// The footer caveat shows "first 250 of N" so the truncation stable and visible.
function htmlFindings(report: AnalysisReport): string {
  const findings =
    report.findings.length === 0
      ? '<div class="empty">No findings.</div>'
      : report.findings
          .slice(0, 250)
          .map(
            (finding) =>
              `<div class="finding"><div class="severity ${severityClass(finding.severity)}">${escapeHtml(finding.severity)}</div><div class="finding-body"><h3 class="rule">${escapeHtml(finding.ruleId)}</h3><div class="msg">${escapeHtml(finding.message)}</div><div class="loc"><code>${htmlLocation(finding.filePath, finding.line)}</code></div></div><div class="points"><b>${escapeHtml(finding.pillar)}</b></div></div>`,
          )
          .join("");
  const capped = report.findings.length > 250 ? ` <span class="aside">first 250 of ${report.findings.length}</span>` : ` <span class="aside">${report.findings.length} shown</span>`;
  return `<section class="findings"><h2 class="section-head">flagged findings${capped}</h2><div class="findings-list">${findings}</div></section>`;
}

/*
 * Page-bottom strip with tool version and schema string — those are the two stable identifiers a
 * reviewer can use to reproduce a historical report.
 */
function htmlFooter(report: AnalysisReport): string {
  const escapedVersion = escapeHtml(report.tool.version);
  const escapedSchemaVersion = escapeHtml(report.schemaVersion);
  return `<footer class="footer"><div class="left">gruff-ts - v${escapedVersion}</div><div class="center">strong opinions, opinionated defaults</div><div class="right">schema - ${escapedSchemaVersion}</div></footer>`;
}

// Renders a keyboard-focusable location pill. `data-path` is what the dashboard JS keys off when
// the user clicks to deep-link; both attributes go through `escapeHtml` because filePath is user-influenced.
function htmlLocation(filePath: string, line?: number): string {
  const text = line === undefined ? filePath : `${filePath}:${line}`;
  return `<span class="loc-link" tabindex="0" data-path="${escapeHtml(text)}">${escapeHtml(text)}</span>`;
}

// CSS class suffix used by severity badges and grade letters. Returning a curated literal (never
// arbitrary user text) is what keeps `htmlStat`/`htmlFinding` safe to interpolate without escaping.
function severityClass(severity: Severity): string {
  return severity === "error" ? "fail" : severity === "warning" ? "warn" : "note";
}

// Constrains grade text to known CSS suffixes before interpolation. Unknown future grades degrade
// to neutral styling instead of creating user-influenced class names.
function gradeClass(gradeValue: string): string {
  const letter = gradeValue[0]?.toLowerCase() ?? "n";
  return ["a", "b", "c", "d", "f"].includes(letter) ? letter : "n";
}

// Single inline stylesheet for both static reports and dashboard-served pages. `shouldIncludeDiagnostics`
// appends the diagnostic-section rules only when the report actually has them, keeping clean
// reports leaner. Hand-maintained CSS — no preprocessor.
function htmlReportCss(shouldIncludeDiagnostics: boolean): string {
  const baseCss = `:root{--ink:#0d0c0a;--ink-2:#161412;--ink-3:#1f1c19;--paper:#f3e9d2;--paper-dim:#b5ab94;--paper-mute:#7d735f;--rule:#2a2622;--forge:#e85d04;--grade-a:#7fa15a;--grade-b:#b8b450;--grade-c:#d08c36;--grade-d:#c2552b;--grade-f:#8b2828;--advisory:#b5ab94;--serif:Georgia,'Iowan Old Style',serif;--mono:'JetBrains Mono','IBM Plex Mono',ui-monospace,monospace}*{box-sizing:border-box;margin:0;padding:0}html{background:var(--ink);scrollbar-gutter:stable}body{font-family:var(--mono);color:var(--paper);background:var(--ink);min-height:100vh;line-height:1.5;font-size:14px;padding:48px 32px}.paper{max-width:1180px;margin:0 auto 24px;background:var(--ink-2);border:1px solid var(--rule);position:relative;padding:56px 64px 48px;scrollbar-gutter:stable}.corner-tr,.corner-bl,.paper:before,.paper:after{content:'';position:absolute;width:22px;height:22px;border:1px solid var(--forge)}.paper:before{top:12px;left:12px;border-right:0;border-bottom:0}.paper:after{bottom:12px;right:12px;border-left:0;border-top:0}.corner-tr{top:12px;right:12px;border-left:0;border-bottom:0}.corner-bl{bottom:12px;left:12px;border-right:0;border-top:0}.masthead{display:grid;grid-template-columns:1fr auto;gap:32px;padding-bottom:28px;border-bottom:1px solid var(--rule);align-items:end}.wordmark{font-family:var(--serif);font-weight:900;font-size:96px;line-height:.85;color:var(--paper);font-style:italic}.wordmark:after{content:'-ts';color:var(--forge);font-style:normal;font-size:.45em;margin-left:.15em;vertical-align:super}.tagline{margin-top:12px;font-size:11px;letter-spacing:0;color:var(--paper-mute);text-transform:uppercase}.meta{text-align:right;font-size:11px;color:var(--paper-dim);line-height:1.9}.label{color:var(--paper-mute);text-transform:uppercase;letter-spacing:0;margin-right:8px}.val{color:var(--paper)}.inspection-id{margin-top:10px;color:var(--forge);font-weight:700;font-size:12px;letter-spacing:0}.section-head{font-size:11px;letter-spacing:0;color:var(--paper-mute);text-transform:uppercase;padding-bottom:16px;margin-bottom:20px;border-bottom:1px solid var(--rule);display:flex;justify-content:space-between;align-items:baseline;font-family:var(--mono);font-weight:500;line-height:1.5}.section-head:before{content:'>';margin-right:10px;color:var(--forge);font-family:var(--serif);font-size:14px;font-style:italic}.aside{color:var(--paper-mute);font-size:10px;letter-spacing:0}.verdict{display:grid;grid-template-columns:auto 1fr;gap:56px;padding:48px 0;border-bottom:1px solid var(--rule);align-items:center}.grade-stamp{width:220px;height:220px;border:3px solid currentColor;color:var(--grade-b);display:flex;flex-direction:column;align-items:center;justify-content:center;transform:rotate(-4deg)}.grade-stamp.a,.grade.a,.grade-pill.a{color:var(--grade-a)}.grade-stamp.b,.grade.b,.grade-pill.b{color:var(--grade-b)}.grade-stamp.c,.grade.c,.grade-pill.c{color:var(--grade-c)}.grade-stamp.d,.grade.d,.grade-pill.d{color:var(--grade-d)}.grade-stamp.f,.grade.f,.grade-pill.f{color:var(--grade-f)}.grade-letter{font-family:var(--serif);font-style:italic;font-weight:900;font-size:112px;line-height:1}.grade-score{font-size:13px;letter-spacing:0}.verdict-body{display:flex;flex-direction:column;gap:18px}.verdict-headline{font-family:var(--serif);font-style:italic;font-weight:600;font-size:38px;line-height:1.15}.verdict-headline em{color:var(--forge)}.verdict-stats{display:grid;grid-template-columns:repeat(4,1fr);border-top:1px solid var(--rule);padding-top:20px}.stat{border-right:1px solid var(--rule);padding:0 18px}.stat:first-child{padding-left:0}.stat:last-child{border-right:0}.verdict-stats .num{font-family:var(--serif);font-weight:800;font-size:32px;line-height:1}.verdict-stats .num.warn{color:var(--grade-c)}.verdict-stats .num.fail{color:var(--grade-f)}.verdict-stats .num.note{color:var(--advisory)}.lbl{font-size:10px;text-transform:uppercase;letter-spacing:0;color:var(--paper-mute);margin-top:8px}.pillars,.offenders,.chart-section{padding:48px 0;border-bottom:1px solid var(--rule)}.pillar-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--rule);border:1px solid var(--rule)}.pillar{background:var(--ink-2);padding:24px 20px;display:flex;flex-direction:column;gap:14px}.pillar .name{font-size:10px;text-transform:uppercase;letter-spacing:0;color:var(--paper-mute)}.pillar .grade{font-family:var(--serif);font-weight:800;font-style:italic;font-size:52px;line-height:.9}.breakdown{font-size:11px;color:var(--paper-dim);line-height:1.7}.row{display:flex;justify-content:space-between;gap:8px}.key{color:var(--paper-mute)}table{width:100%;border-collapse:collapse;font-size:13px;table-layout:auto;font-family:var(--mono)}th{text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:0;color:var(--paper-mute);font-weight:500;padding:12px 14px 12px 0;border-bottom:1px solid var(--rule)}th:last-child,td:last-child{padding-right:0}th.num,td.num{text-align:right;padding-left:18px}td{padding:14px 14px 14px 0;border-bottom:1px solid var(--ink-3);color:var(--paper-dim);font-size:13px;font-family:var(--mono);font-weight:500;line-height:1.4}td.num{color:var(--paper);font-variant-numeric:tabular-nums}.file-path{color:var(--paper);font-weight:500}.grade-pill{display:inline-block;font-family:var(--serif);font-style:italic;font-weight:800;font-size:18px;line-height:1;padding:4px 10px;border:1.5px solid currentColor;min-width:36px;text-align:center}.chart-summary{color:var(--paper-dim);font-size:12px;margin:-6px 0 18px}.chart-card{border:1px solid var(--rule);padding:24px;background:var(--ink-3)}.title{font-size:10px;text-transform:uppercase;letter-spacing:0;color:var(--paper-mute);margin-bottom:24px}.histogram{display:flex;align-items:flex-end;gap:6px;height:180px;padding-bottom:20px;border-bottom:1px solid var(--rule)}.bar{flex:1;background:var(--forge);position:relative;min-height:4px}.bar.warn{background:var(--grade-c)}.bar.fail{background:var(--grade-f)}.bar .count{position:absolute;top:-22px;left:50%;transform:translateX(-50%);font-size:11px}.histogram-axis{display:flex;gap:6px;margin-top:8px;font-size:10px;color:var(--paper-mute)}.histogram-axis span{flex:1;text-align:center}.findings{padding:48px 0}.finding{display:grid;grid-template-columns:auto 1fr auto;gap:24px;padding:18px 0;border-bottom:1px solid var(--ink-3);align-items:start}.severity{font-size:9px;text-transform:uppercase;letter-spacing:0;padding:4px 10px;border:1px solid currentColor;margin-top:2px;min-width:76px;text-align:center}.severity.fail{color:var(--grade-f)}.severity.warn{color:var(--grade-c)}.severity.note{color:var(--paper-mute)}.rule{font-size:10px;color:var(--forge);text-transform:uppercase;letter-spacing:0;margin-bottom:6px;font-family:var(--mono);font-weight:700;line-height:1.5}.msg{font-family:var(--serif);font-weight:500;font-size:17px;color:var(--paper);line-height:1.4}.loc{font-size:11px;color:var(--paper-mute);margin-top:8px}.loc code{color:var(--paper-dim);background:var(--ink-3);padding:1px 6px;border:1px solid var(--rule)}.loc-link{color:inherit;text-decoration:none}.loc-link:focus-visible{outline:2px solid var(--forge);outline-offset:3px}.points{font-size:10px;color:var(--paper-mute);text-align:right;letter-spacing:0;min-width:96px;padding-left:12px}.empty{color:var(--paper-dim);font-size:12px}.footer{margin-top:48px;padding-top:24px;border-top:1px solid var(--rule);display:grid;grid-template-columns:1fr auto 1fr;gap:24px;align-items:center;font-size:10px;color:var(--paper-mute);letter-spacing:0;text-transform:uppercase}.center{font-family:var(--serif);font-style:italic;font-size:13px;color:var(--paper-dim);text-transform:none;letter-spacing:0}.right{text-align:right}@media(max-width:900px){body{padding:16px}.paper{padding:28px 20px}.wordmark{font-size:64px}.masthead,.verdict{grid-template-columns:1fr}.meta{text-align:left}.grade-stamp{margin:0 auto}.pillar-grid{grid-template-columns:repeat(2,1fr)}.verdict-stats{grid-template-columns:repeat(2,1fr);gap:16px}.stat{border-right:0;padding:0}.verdict-headline{font-size:28px}.footer{grid-template-columns:1fr}.center,.right{text-align:left}}@media(max-width:560px){.pillar-grid{grid-template-columns:1fr}.finding{grid-template-columns:1fr}.points{text-align:left;padding-left:0}.verdict-stats{grid-template-columns:1fr}.histogram{height:140px}}`;
  const reportCss = `${baseCss}.dashboard-context{padding:28px 0;border-bottom:1px solid var(--rule)}.dashboard-context-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.dashboard-context-grid>div{border:1px solid var(--rule);background:var(--ink-3);padding:12px 14px}.dashboard-context .label{display:block;margin:0 0 6px}.dashboard-context .val{overflow-wrap:anywhere}@media(max-width:700px){.dashboard-context-grid{grid-template-columns:1fr}}@media(max-width:560px){.offender-list thead{display:none}.offender-list,.offender-list tbody,.offender-list tr,.offender-list td{display:block;width:100%}.offender-list tr{border-bottom:1px solid var(--ink-3);padding:10px 0}.offender-list td{border-bottom:0;padding:6px 0}.offender-list td.num{text-align:left;padding-left:0}}`;
  if (!shouldIncludeDiagnostics) {
    return reportCss;
  }
  return `${reportCss}.diagnostics{padding:28px 0 0}.diagnostic-list{display:grid;gap:10px}.diagnostic{display:grid;grid-template-columns:auto 1fr;gap:10px 14px;border:1px solid var(--rule);background:var(--ink-3);padding:12px 14px;color:var(--paper-dim);font-size:12px}.diagnostic-type{text-transform:uppercase;letter-spacing:0;color:var(--forge);font-size:10px}.diagnostic-location{grid-column:2;color:var(--paper-mute);font-size:11px}`;
}

// Top-level dashboard chrome: iframe that loads the scan + a slide-out controls panel. The iframe
// arrangement is what lets the dashboard reload scans without losing the control form state.
function dashboardHomeHtml(projectRoot: string, scanPath: string): string {
  const initialScan = dashboardScanUrl(projectRoot, scanPath);
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>gruff-ts dashboard</title>
  <style>${dashboardCss()}</style>
</head>
<body>
  <iframe class="report-frame" name="report-frame" title="gruff-ts report" src="${escapeHtml(initialScan)}"></iframe>
  <button class="controls-toggle" type="button" aria-expanded="false" aria-controls="controls-panel" title="Dashboard controls">&#9881;</button>
  <aside class="controls-panel" id="controls-panel" hidden>
    <header class="controls-head">
      <h1>Dashboard controls</h1>
      <p>local scan settings</p>
    </header>
    <form class="scan-form" data-scan-form action="/scan" method="get" target="report-frame">
      <label>Project root <input name="projectRoot" value="${escapeHtml(projectRoot)}" autocomplete="off"></label>
      <label>Paths <input name="path" value="${escapeHtml(scanPath)}" autocomplete="off"></label>
      <div class="scan-state"><span>Status</span><strong data-scan-status>Loading report</strong></div>
      <div class="actions">
        <button class="secondary" type="button" data-refresh>Refresh</button>
        <button type="submit">Run scan</button>
      </div>
    </form>
  </aside>
  <script>${dashboardJs()}</script>
</body>
</html>`;
}

// URLSearchParams handles encoding so the projectRoot/scanPath values are safe to embed in `src`.
function dashboardScanUrl(projectRoot: string, scanPath: string): string {
  const params = new URLSearchParams({ projectRoot, path: scanPath });
  return `/scan?${params.toString()}`;
}

// Friendly failure page served when `renderDashboardScan` catches an analyser throw. All inputs
// are escaped — `message` is the error text and could contain attacker-controlled file path fragments.
function dashboardErrorHtml(message: string, projectRoot: string, scanPath: string): string {
  const escapedMessage = escapeHtml(message);
  const escapedProjectRoot = escapeHtml(projectRoot);
  const escapedScanPath = escapeHtml(scanPath);
  return `<!doctype html>
<html lang="en-NZ">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>gruff-ts dashboard scan failed</title>
<style>${dashboardCss()}</style>
</head>
<body class="error-page">
  <main class="scan-error">
    <h1>Scan failed</h1>
    <p>${escapedMessage}</p>
    <dl>
      <dt>Project root</dt><dd>${escapedProjectRoot}</dd>
      <dt>Paths</dt><dd>${escapedScanPath}</dd>
    </dl>
  </main>
</body>
</html>`;
}

// Inline stylesheet shared by the dashboard shell and its error page. Inlined (not linked) so the
// dashboard works without separate asset routes — keeping it self-contained matters for offline use.
function dashboardCss(): string {
  return `:root{color-scheme:dark;--ink:#0d0c0a;--ink-2:#161412;--panel:#1f1c19;--paper:#f3e9d2;--paper-dim:#b5ab94;--paper-mute:#7d735f;--rule:#2a2622;--forge:#e85d04;--forge-dark:#b94402;--mono:'JetBrains Mono','IBM Plex Mono',ui-monospace,monospace}*{box-sizing:border-box}html,body{height:100%;margin:0;background:var(--ink);color:var(--paper);font-family:var(--mono);font-size:14px;line-height:1.5}.report-frame{position:fixed;inset:0;width:100%;height:100%;border:0;background:var(--ink)}.controls-toggle{position:fixed;top:18px;right:18px;z-index:3;width:44px;height:44px;border:1px solid rgba(232,93,4,.75);border-radius:8px;background:var(--forge);color:#170b05;font:700 22px/1 var(--mono);display:grid;place-items:center;cursor:pointer;box-shadow:0 16px 36px rgba(0,0,0,.38)}.controls-toggle:hover,.controls-toggle:focus-visible{background:#ff7a1a;outline:2px solid rgba(243,233,210,.75);outline-offset:3px}.controls-panel{position:fixed;z-index:2;top:74px;right:18px;width:min(420px,calc(100vw - 36px));max-height:calc(100vh - 92px);overflow:auto;background:rgba(31,28,25,.98);border:1px solid var(--rule);border-radius:8px;padding:20px;box-shadow:0 24px 70px rgba(0,0,0,.5)}[hidden]{display:none!important}.controls-head{border-bottom:1px solid var(--rule);padding-bottom:14px;margin-bottom:16px}.controls-head h1{margin:0;font-size:18px;font-weight:800}.controls-head p{margin:4px 0 0;color:var(--paper-mute);font-size:12px;text-transform:uppercase}.scan-form{display:grid;gap:14px}.scan-form label{display:grid;gap:6px;color:var(--paper-dim);font-size:12px;text-transform:uppercase}.scan-form input{width:100%;font:inherit;color:var(--paper);background:var(--ink-2);border:1px solid var(--rule);border-radius:6px;padding:10px 11px;min-width:0}.scan-form input:focus{outline:2px solid var(--forge);outline-offset:2px}.scan-state{display:flex;justify-content:space-between;gap:12px;border:1px solid var(--rule);background:var(--ink-2);border-radius:6px;padding:10px 11px;color:var(--paper-mute)}.scan-state strong{color:var(--paper);font-weight:700;text-align:right}.actions{display:grid;grid-template-columns:1fr 1fr;gap:10px}.actions button{font:inherit;border:1px solid var(--forge);border-radius:6px;padding:10px 12px;background:var(--forge);color:#170b05;font-weight:800;cursor:pointer}.actions button.secondary{background:transparent;color:var(--paper);border-color:var(--rule)}.actions button:disabled{opacity:.6;cursor:wait}.scan-error{max-width:720px;margin:8vh auto;padding:48px;background:var(--panel);border:1px solid var(--rule);color:var(--paper)}.scan-error h1{margin:0 0 16px;font-size:28px}.scan-error p{color:var(--paper-dim);overflow-wrap:anywhere}.scan-error dl{display:grid;grid-template-columns:auto 1fr;gap:8px 16px;margin:24px 0 0}.scan-error dt{color:var(--paper-mute);text-transform:uppercase}.scan-error dd{margin:0;overflow-wrap:anywhere}@media(max-width:560px){.controls-toggle{top:12px;right:12px}.controls-panel{top:64px;right:12px;width:calc(100vw - 24px);max-height:calc(100vh - 76px);padding:16px}.actions{grid-template-columns:1fr}.scan-error{margin:0;min-height:100vh;padding:28px 20px}.scan-error dl{grid-template-columns:1fr}}`;
}

// Inline `<script>` body served with the dashboard shell. Updates the URL via history.replaceState
// so a maintainer can copy the current scan's URL and reproduce it later without re-typing controls.
function dashboardJs(): string {
  return `const form=document.querySelector("[data-scan-form]");const frame=document.querySelector(".report-frame");const toggle=document.querySelector(".controls-toggle");const panel=document.querySelector(".controls-panel");const refresh=document.querySelector("[data-refresh]");const status=document.querySelector("[data-scan-status]");function setOpen(open){panel.hidden=!open;toggle.setAttribute("aria-expanded",String(open));if(open){const input=form.querySelector("input");if(input){input.focus();}}}function params(){return new URLSearchParams(new FormData(form));}function runScan(){const query=params();status.textContent="Scanning";refresh.disabled=true;form.querySelector("button[type=submit]").disabled=true;frame.src="/scan?"+query.toString();history.replaceState(null,"","/?"+query.toString());}toggle.addEventListener("click",()=>setOpen(panel.hidden));document.addEventListener("keydown",(event)=>{if(event.key==="Escape"){setOpen(false);}});form.addEventListener("submit",(event)=>{event.preventDefault();runScan();});refresh.addEventListener("click",runScan);frame.addEventListener("load",()=>{status.textContent="Ready";refresh.disabled=false;form.querySelector("button[type=submit]").disabled=false;});`;
}

// Composite-score → letter grade conversion. 90/80/70/60 boundaries are part of the stable rule
// surface; changing them would shift every historical report grade and the headline on the dashboard.
function grade(score: number): string {
  if (score >= 90) {
    return "A";
  }
  if (score >= 80) {
    return "B";
  }
  if (score >= 70) {
    return "C";
  }
  if (score >= 60) {
    return "D";
  }
  return "F";
}

// Three GitHub annotation levels — gruff's "advisory" collapses to "notice" because Actions has
// no fourth tier and "notice" is the documented soft-warning level.
function githubLevel(severity: Severity): "notice" | "warning" | "error" {
  return severity === "error" ? "error" : severity === "warning" ? "warning" : "notice";
}

// Actions workflow-command escaping per the documented spec. `%` must be first — otherwise the
// `%0A` replacement would itself be re-encoded.
function escapeCommand(commandText: string): string {
  return commandText.replaceAll("%", "%25").replaceAll("\n", "%0A").replaceAll("\r", "%0D");
}

// Property-list variant of `escapeCommand`: also escapes `:` and `,` because GitHub workflow
// commands use them as the property-list delimiters between `file`, `line`, `title`, etc.
function escapeCommandProperty(propertyText: string): string {
  return escapeCommand(propertyText).replaceAll(":", "%3A").replaceAll(",", "%2C");
}

// Four-character HTML entity escape (`&`, `<`, `>`, `"`). `&` must be first so the other entities
// don't get double-encoded; missing escapes here would enable script injection in archived reports.
function escapeHtml(htmlText: string): string {
  return htmlText.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
}

export { dashboardErrorHtml, dashboardHomeHtml, grade, renderHtml, renderReport, renderSummary };
