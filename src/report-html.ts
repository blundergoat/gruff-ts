// HTML renderer for native `AnalysisReport` state plus the dashboard chrome (home shell + error
// page) that serves the same report inside a control panel. JSON uses the separate v3 machine adapter.
// Extracted from `report-renderers.ts` so the renderer module stays under the `size.file-length`
// threshold; the HTML output is part of the stable archived-report contract.
import type { AnalysisReport, Finding, Severity } from "./types.ts";
import { buildPillarRows, grade } from "./pillar-summary.ts";
import { severityGradeBreakdown } from "./scoring.ts";

const CYCLOMATIC_BUCKETS = [
  { label: "21+", minimum: 21 },
  { label: "16-20", minimum: 16 },
  { label: "11-15", minimum: 11 },
  { label: "6-10", minimum: 6 },
  { label: "1-5", minimum: 1 },
] as const;

// Extra metadata appended to dashboard-served HTML. Static-file consumers never see it because the
// CLI calls `renderHtml` without this argument; only the dashboard route passes it in.
interface DashboardRenderContext {
  projectRoot: string;
  scanPath: string;
}

/**
 * Renders a self-contained report with inline CSS so it can be archived or emailed.
 * Finding locations carry the stable data-path attribute.
 *
 * @param report - analysis results supplying the document's scores, diagnostics and findings
 * @param dashboardContext - local project root and scan path, omitted when the dashboard context section is unnecessary
 * @returns Complete HTML document for the scan, with n/a in the title when the report has no grade
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
<title>gruff-ts report - ${escapeHtml(report.score.grade ?? "n/a")}</title>
<style>${htmlReportCss(report.diagnostics.length > 0)}</style>
</head>
<body>
<main class="paper"><span class="corner-tr"></span><span class="corner-bl"></span>
${bodySections}
</main>
</body>
</html>`;
}

/**
 * Renders the report header showing the analysed file count, output format, failure threshold, schema, and tool version.
 * Zero analysed files display "." in the paths row; the schema identifies the report shape.
 *
 * @param report - analysis report supplying path counts, run settings, schemaVersion, and tool version
 * @returns HTML header element for the report masthead
 */
function htmlMasthead(report: AnalysisReport): string {
  const paths = report.paths.analysedFiles === 0 ? "." : `${report.paths.analysedFiles} analysed ${report.paths.analysedFiles === 1 ? "file" : "files"}`;
  return `<header class="masthead"><div class="brand"><div class="wordmark">gruff</div><div class="tagline">ts/js code - inspected for human sign-off</div></div><div class="meta">${htmlMetaRow("paths", paths)}${htmlMetaRow("format", report.run.format)}${htmlMetaRow("fail", report.run.failOn)}${htmlMetaRow("schema", report.schemaVersion)}<div class="inspection-id">gruff-ts ${escapeHtml(report.tool.version)}</div></div></header>`;
}

/**
 * Renders a metadata row and escapes both strings so metadata cannot inject HTML.
 *
 * @param label - field name displayed in the row label span
 * @param metaValue - value displayed beside the label after HTML escaping
 * @returns HTML div containing the escaped label and value spans
 */
function htmlMetaRow(label: string, metaValue: string): string {
  const escapedLabel = escapeHtml(label);
  const escapedValue = escapeHtml(metaValue);
  return `<div><span class="label">${escapedLabel}</span><span class="val">${escapedValue}</span></div>`;
}

/**
 * Renders the report's run diagnostics before scores in the stable HTML order because scan limits and failures
 * can affect how readers interpret the results.
 *
 * @param report - analysis report supplying run diagnostic entries
 * @returns HTML diagnostics section, or empty text when report.diagnostics is empty
 */
function htmlDiagnostics(report: AnalysisReport): string {
  if (report.diagnostics.length === 0) {
    return "";
  }
  const diagnostics = report.diagnostics.map(htmlDiagnosticEntry).join("");
  return `<section class="diagnostics"><h2 class="section-head">diagnostics <span class="aside">run messages</span></h2><div class="diagnostic-list">${diagnostics}</div></section>`;
}

/**
 * Formats a run diagnostic using the stable diagnostic-type, diagnostic-message, and diagnostic-location classes.
 * With no file path, the entry has no location span; with a path and no line, the location shows the path alone.
 *
 * @param diagnostic - run diagnostic record with type, message, and optional filePath and line
 * @returns HTML div element for the escaped diagnostic entry
 */
function htmlDiagnosticEntry(diagnostic: AnalysisReport["diagnostics"][number]): string {
  const lineSuffix = diagnostic.line ? `:${diagnostic.line}` : "";
  const location = diagnostic.filePath
    ? `<span class="diagnostic-location">${escapeHtml(diagnostic.filePath)}${lineSuffix}</span>`
    : "";
  return `<div class="diagnostic"><span class="diagnostic-type">${escapeHtml(diagnostic.diagnosticType)}</span><span class="diagnostic-message">${escapeHtml(diagnostic.message)}</span>${location}</div>`;
}

/**
 * Renders the dashboard-only banner for the requested or default project root and scan path.
 * Escapes both values because callers can override them through query parameters.
 *
 * @param context - dashboard render context holding the projectRoot and scanPath values
 * @returns HTML section element displaying the escaped project root and scan path
 */
function htmlDashboardContext(context: DashboardRenderContext): string {
  const escapedProjectRoot = escapeHtml(context.projectRoot);
  const escapedScanPath = escapeHtml(context.scanPath);
  return `<section class="dashboard-context"><h2 class="section-head">dashboard scan <span class="aside">local run</span></h2><div class="dashboard-context-grid"><div><span class="label">Project root</span><span class="val">${escapedProjectRoot}</span></div><div><span class="label">Path</span><span class="val">${escapedScanPath}</span></div></div></section>`;
}

/**
 * Renders the analysis report's grade, verdict summary, severity pills, and finding totals as HTML.
 * The stable visual contract keeps dashboard and static report verdicts consistent.
 *
 * @param report - scored or unscored analysis result to summarize
 * @returns the HTML verdict section for the shared report renderer
 */
function htmlVerdict(report: AnalysisReport): string {
  // A missing grade displays n/a. A missing composite displays not evaluated / 100 so an unscored scan cannot look perfect.
  const gradeCssClass = gradeClass(report.score.grade ?? "n/a");
  const escapedGrade = escapeHtml(report.score.grade ?? "n/a");
  const scoreText = report.score.composite === null ? "not evaluated" : report.score.composite.toFixed(1);
  const escapedSummary = escapeHtml(verdictSummary(report));
  const breakdown = severityGradeBreakdown(report.findings);
  const severityPills = htmlSeverityPills(breakdown);
  const stats = `${htmlStat(String(report.summary.total), "findings", "")}${htmlStat(String(report.summary.error), "errors", "fail")}${htmlStat(String(report.summary.warning), "warnings", "warn")}${htmlStat(String(report.summary.advisory), "advisories", "note")}`;
  return `<section class="verdict"><div class="grade-stamp ${gradeCssClass}"><div class="grade-letter">${escapedGrade}</div><div class="grade-score">${scoreText} / 100</div></div><div class="verdict-body"><div class="verdict-headline">Inspection complete.<br><em>${escapedSummary}</em></div>${severityPills}<div class="verdict-stats">${stats}</div></div></section>`;
}

/**
 * Renders three labeled grade pills (Errors, Warnings, Advisory) directly under the verdict headline.
 * Uses the breakdown's grade and count for each severity because the composite grade can hide what drove it.
 *
 * @param breakdown - per-severity grade and finding count buckets for error, warning, and advisory
 * @returns HTML container div holding the three severity grade pills
 */
function htmlSeverityPills(breakdown: ReturnType<typeof severityGradeBreakdown>): string {
  return `<div class="severity-grades">${htmlSeverityPill("Errors", breakdown.error)}${htmlSeverityPill("Warnings", breakdown.warning)}${htmlSeverityPill("Advisory", breakdown.advisory)}</div>`;
}

/**
 * Renders an HTML grade pill and escapes displayed values to avoid markup injection.
 * Uses gradeClass for a fixed CSS class, falling back to n for an unrecognized or absent initial.
 *
 * @param label - severity heading displayed before the pill
 * @param bucket - grade letter and finding count for that severity
 * @returns HTML span element for the labeled severity grade pill and count
 */
function htmlSeverityPill(label: string, bucket: { grade: string; count: number }): string {
  const cssClass = gradeClass(bucket.grade);
  const escapedLabel = escapeHtml(label);
  const escapedGradeLetter = escapeHtml(bucket.grade);
  const escapedCount = escapeHtml(String(bucket.count));
  return `<span class="severity-grade">${escapedLabel} <span class="grade-pill ${cssClass}">${escapedGradeLetter}</span> <span class="severity-count">(${escapedCount})</span></span>`;
}

/**
 * Builds the verdict headline sentence counting only warning and error findings.
 * Advisories are intentionally excluded from the verdict text because they are below the stable "needs attention" threshold.
 *
 * @param report - analysis report supplying summary counts and findings
 * @returns Plain-text verdict sentence summarizing warning and error findings across pillars
 */
function verdictSummary(report: AnalysisReport): string {
  const thresholdFindings = report.summary.warning + report.summary.error;
  if (thresholdFindings === 0) {
    return "No warning or error findings flagged.";
  }
  const pillars = new Set(report.findings.filter((finding) => finding.severity === "warning" || finding.severity === "error").map((finding) => finding.pillar));
  return `${thresholdFindings} ${thresholdFindings === 1 ? "finding" : "findings"} at warning or error severity across ${pillars.size} ${pillars.size === 1 ? "pillar" : "pillars"}.`;
}

/**
 * Renders a stat card and escapes all three strings before embedding them in HTML.
 *
 * @param number - formatted count text displayed at the top of the card
 * @param label - caption displayed below the count
 * @param className - CSS modifier class selecting the number's visual style
 * @returns HTML div element containing the escaped stat number and label
 */
function htmlStat(number: string, label: string, className: string): string {
  const escapedClassName = escapeHtml(className);
  const escapedNumber = escapeHtml(number);
  const escapedLabel = escapeHtml(label);
  return `<div class="stat"><div class="num ${escapedClassName}">${escapedNumber}</div><div class="lbl">${escapedLabel}</div></div>`;
}

/**
 * Uses shared pillar rows so that HTML follows the stable summary order, findings DESC then pillar ASC.
 * The HTML contract keeps the pillar-grid anchor and columns for pillar, grade, score, findings, advisory, warning and error.
 *
 * @param report - analysis results supplying pillar scores and findings by severity
 * @returns HTML section containing the pillar summary table
 */
function htmlPillars(report: AnalysisReport): string {
  const rows = buildPillarRows(report);
  const body =
    rows.length === 0
      ? '<tr><td colspan="7">No pillar findings.</td></tr>'
      : rows
          .map((row) => {
            const letter = row.grade;
            return `<tr><td class="pillar-name">${escapeHtml(row.pillar)}</td><td class="num"><span class="grade-pill ${gradeClass(letter)}">${escapeHtml(letter)}</span></td><td class="num">${row.score.toFixed(2)}</td><td class="num">${row.findings}</td><td class="num">${row.advisory}</td><td class="num">${row.warning}</td><td class="num">${row.error}</td></tr>`;
          })
          .join("");
  return `<section class="pillars"><h2 class="section-head">Pillars <span class="aside">grade, score, findings by severity</span></h2><div class="pillar-grid"><table class="pillar-table"><thead><tr><th scope="col">pillar</th><th scope="col" class="num">grade</th><th scope="col" class="num">score</th><th scope="col" class="num">findings</th><th scope="col" class="num">advisory</th><th scope="col" class="num">warning</th><th scope="col" class="num">error</th></tr></thead><tbody>${body}</tbody></table></div></section>`;
}

/**
 * Renders the worst-first offender table capped at 10 rows so that the layout stays stable.
 * An empty list shows No offenders found, and an unavailable score shows n/a for both the score and grade.
 *
 * @param report - analysis report supplying the topOffenders list
 * @returns HTML section element containing the top offenders table
 */
function htmlOffenders(report: AnalysisReport): string {
  const rows =
    report.score.topOffenders.length === 0
      ? '<tr><td colspan="4">No offenders found.</td></tr>'
      : report.score.topOffenders
          .slice(0, 10)
          .map((file) => {
            const letter = file.score === null ? "n/a" : grade(file.score);
            const scoreCell = file.score === null ? "n/a" : file.score.toFixed(1);
            return `<tr><td class="file-path">${htmlLocation(file.filePath)}</td><td class="num">${scoreCell}</td><td class="num">${file.findings}</td><td class="num"><span class="grade-pill ${gradeClass(letter)}">${letter}</span></td></tr>`;
          })
          .join("");
  return `<section class="offenders"><h2 class="section-head">top offenders <span class="aside">sorted by score</span></h2><table class="offender-list"><thead><tr><th scope="col">file</th><th scope="col" class="num">score</th><th scope="col" class="num">findings</th><th scope="col" class="num">grade</th></tr></thead><tbody>${rows}</tbody></table></section>`;
}

/**
 * Renders the cyclomatic-complexity histogram so that the stable bucket layout stays visible even when no findings qualify.
 *
 * @param report - analysis results supplying the cyclomatic findings to chart
 * @returns HTML chart section with a summary and bucket counts, including zero counts on minimum-height bars
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

/**
 * Counts cyclomatic findings for the HTML histogram. Findings that cannot be assigned a bucket are skipped.
 *
 * @param report - analysis report supplying the findings to count
 * @returns Counts in stable chart order, with zero retained for each empty bucket
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

/**
 * Maps a cyclomatic complexity finding to its histogram bucket, or leaves non-matching findings out of the chart.
 * Reads the complexity count from the message because the stable rule format supplies the value used by the chart.
 *
 * @param finding - finding inspected for ruleId complexity.cyclomatic and its numeric complexity
 * @returns Histogram bucket label for the finding's complexity, or undefined when not applicable
 */
function cyclomaticFindingBucket(finding: Finding): string | undefined {
  if (finding.ruleId !== "complexity.cyclomatic") {
    return undefined;
  }
  const match = finding.message.match(/cyclomatic complexity (\d+)/);
  const complexityValue = match?.[1] ? Number(match[1]) : undefined;
  return complexityValue === undefined ? undefined : cyclomaticBucket(complexityValue);
}

/**
 * Selects the highest-minimum histogram bucket label using descending minima in CYCLOMATIC_BUCKETS.
 *
 * @param complexityValue - parsed cyclomatic complexity score to classify
 * @returns Matching bucket label, or undefined when the value falls below all bucket minima
 */
function cyclomaticBucket(complexityValue: number): string | undefined {
  for (const bucket of CYCLOMATIC_BUCKETS) {
    if (complexityValue >= bucket.minimum) {
      return bucket.label;
    }
  }
  return undefined;
}

/**
 * Formats a singular or plural caption for functions above CC 10.
 * Missing 11-15, 16-20, or 21+ counts contribute zero.
 *
 * @param distribution - cyclomatic histogram counts keyed by bucket label
 * @returns Summary caption breaking down functions exceeding CC 10 across the upper three buckets
 */
function cyclomaticSummary(distribution: Record<string, number>): string {
  const moderate = distribution["11-15"] ?? 0;
  const high = distribution["16-20"] ?? 0;
  const severe = distribution["21+"] ?? 0;
  const exceeds = moderate + high + severe;
  return `${exceeds} ${exceeds === 1 ? "function" : "functions"} ${exceeds === 1 ? "exceeds" : "exceed"} CC 10 (${moderate} in 11-15, ${high} in 16-20, ${severe} at 21+).`;
}

/**
 * Renders the HTML findings section, showing No findings when empty and applying the stable 250-entry cap.
 * The heading shows first 250 of N when the list is capped so long lists stay easier to scan.
 *
 * @param report - analysis report supplying the findings array to display
 * @returns HTML section element listing up to 250 flagged findings
 */
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

/**
 * Renders the report footer with the tool version and schema string.
 * These stable identifiers tell reviewers which release and output contract produced the report.
 *
 * @param report - analysis report supplying tool.version and schemaVersion
 * @returns HTML footer element containing the escaped tool version and schema identifier
 */
function htmlFooter(report: AnalysisReport): string {
  const escapedVersion = escapeHtml(report.tool.version);
  const escapedSchemaVersion = escapeHtml(report.schemaVersion);
  return `<footer class="footer"><div class="left">gruff-ts - v${escapedVersion}</div><div class="center">strong opinions, opinionated defaults</div><div class="right">schema - ${escapedSchemaVersion}</div></footer>`;
}

/**
 * Renders a keyboard-focusable location span, HTML-escaping both the displayed text and data-path attribute.
 * An absent line leaves only the path.
 *
 * @param filePath - source file path to display and store in data-path
 * @param line - optional 1-based line number appended after a colon when defined
 * @returns HTML span element for the formatted location
 */
function htmlLocation(filePath: string, line?: number): string {
  const text = line === undefined ? filePath : `${filePath}:${line}`;
  return `<span class="loc-link" tabindex="0" data-path="${escapeHtml(text)}">${escapeHtml(text)}</span>`;
}

/**
 * Maps a finding severity to a fixed badge CSS suffix that can be interpolated into markup without HTML escaping.
 *
 * @param severity - finding severity level ("error", "warning", or "advisory")
 * @returns CSS suffix: "fail" for error, "warn" for warning, or "note" otherwise
 */
function severityClass(severity: Severity): string {
  return severity === "error" ? "fail" : severity === "warning" ? "warn" : "note";
}

/**
 * Derives a CSS suffix from the grade's first letter, ignoring case.
 * Empty grades and initials outside a, b, c, d, and f use the neutral suffix n.
 *
 * @param gradeValue - grade text whose leading character selects the color class
 * @returns Lowercase letter "a", "b", "c", "d", "f", or "n"
 */
function gradeClass(gradeValue: string): string {
  const letter = gradeValue[0]?.toLowerCase() ?? "n";
  return ["a", "b", "c", "d", "f"].includes(letter) ? letter : "n";
}

/**
 * Builds the inline stylesheet shared by static HTML reports and dashboard scan reports.
 * Omitting diagnostic rules keeps reports without diagnostics smaller.
 *
 * @param shouldIncludeDiagnostics - whether to append CSS rules for the diagnostics section
 * @returns Minified CSS text for embedding in the report style tag
 */
function htmlReportCss(shouldIncludeDiagnostics: boolean): string {
  const baseCss = `:root{--ink:#0d0c0a;--ink-2:#161412;--ink-3:#1f1c19;--paper:#f3e9d2;--paper-dim:#b5ab94;--paper-mute:#7d735f;--rule:#2a2622;--forge:#e85d04;--grade-a:#7fa15a;--grade-b:#b8b450;--grade-c:#d08c36;--grade-d:#c2552b;--grade-f:#8b2828;--advisory:#b5ab94;--serif:Georgia,'Iowan Old Style',serif;--mono:'JetBrains Mono','IBM Plex Mono',ui-monospace,monospace}*{box-sizing:border-box;margin:0;padding:0}html{background:var(--ink);scrollbar-gutter:stable}body{font-family:var(--mono);color:var(--paper);background:var(--ink);min-height:100vh;line-height:1.5;font-size:14px;padding:48px 32px}.paper{max-width:1180px;margin:0 auto 24px;background:var(--ink-2);border:1px solid var(--rule);position:relative;padding:56px 64px 48px;scrollbar-gutter:stable}.corner-tr,.corner-bl,.paper:before,.paper:after{content:'';position:absolute;width:22px;height:22px;border:1px solid var(--forge)}.paper:before{top:12px;left:12px;border-right:0;border-bottom:0}.paper:after{bottom:12px;right:12px;border-left:0;border-top:0}.corner-tr{top:12px;right:12px;border-left:0;border-bottom:0}.corner-bl{bottom:12px;left:12px;border-right:0;border-top:0}.masthead{display:grid;grid-template-columns:1fr auto;gap:32px;padding-bottom:28px;border-bottom:1px solid var(--rule);align-items:end}.wordmark{font-family:var(--serif);font-weight:900;font-size:96px;line-height:.85;color:var(--paper);font-style:italic}.wordmark:after{content:'-ts';color:var(--forge);font-style:normal;font-size:.45em;margin-left:.15em;vertical-align:super}.tagline{margin-top:12px;font-size:11px;letter-spacing:0;color:var(--paper-mute);text-transform:uppercase}.meta{text-align:right;font-size:11px;color:var(--paper-dim);line-height:1.9}.label{color:var(--paper-mute);text-transform:uppercase;letter-spacing:0;margin-right:8px}.val{color:var(--paper)}.inspection-id{margin-top:10px;color:var(--forge);font-weight:700;font-size:12px;letter-spacing:0}.section-head{font-size:11px;letter-spacing:0;color:var(--paper-mute);text-transform:uppercase;padding-bottom:16px;margin-bottom:20px;border-bottom:1px solid var(--rule);display:flex;justify-content:space-between;align-items:baseline;font-family:var(--mono);font-weight:500;line-height:1.5}.section-head:before{content:'>';margin-right:10px;color:var(--forge);font-family:var(--serif);font-size:14px;font-style:italic}.aside{color:var(--paper-mute);font-size:10px;letter-spacing:0}.verdict{display:grid;grid-template-columns:auto 1fr;gap:56px;padding:48px 0;border-bottom:1px solid var(--rule);align-items:center}.grade-stamp{width:220px;height:220px;border:3px solid currentColor;color:var(--grade-b);display:flex;flex-direction:column;align-items:center;justify-content:center;transform:rotate(-4deg)}.grade-stamp.a,.grade.a,.grade-pill.a{color:var(--grade-a)}.grade-stamp.b,.grade.b,.grade-pill.b{color:var(--grade-b)}.grade-stamp.c,.grade.c,.grade-pill.c{color:var(--grade-c)}.grade-stamp.d,.grade.d,.grade-pill.d{color:var(--grade-d)}.grade-stamp.f,.grade.f,.grade-pill.f{color:var(--grade-f)}.grade-letter{font-family:var(--serif);font-style:italic;font-weight:900;font-size:112px;line-height:1}.grade-score{font-size:13px;letter-spacing:0}.verdict-body{display:flex;flex-direction:column;gap:18px}.verdict-headline{font-family:var(--serif);font-style:italic;font-weight:600;font-size:38px;line-height:1.15}.verdict-headline em{color:var(--forge)}.verdict-stats{display:grid;grid-template-columns:repeat(4,1fr);border-top:1px solid var(--rule);padding-top:20px}.stat{border-right:1px solid var(--rule);padding:0 18px}.stat:first-child{padding-left:0}.stat:last-child{border-right:0}.verdict-stats .num{font-family:var(--serif);font-weight:800;font-size:32px;line-height:1}.verdict-stats .num.warn{color:var(--grade-c)}.verdict-stats .num.fail{color:var(--grade-f)}.verdict-stats .num.note{color:var(--advisory)}.lbl{font-size:10px;text-transform:uppercase;letter-spacing:0;color:var(--paper-mute);margin-top:8px}.pillars,.offenders,.chart-section{padding:48px 0;border-bottom:1px solid var(--rule)}.pillar-grid{background:var(--ink-2)}.pillar-table{width:100%;border-collapse:collapse}.pillar-table .pillar-name{color:var(--paper);font-weight:500;text-transform:uppercase;letter-spacing:0;font-size:11px}.pillar-table .grade-pill{font-size:14px;padding:2px 8px;min-width:30px}table{width:100%;border-collapse:collapse;font-size:13px;table-layout:auto;font-family:var(--mono)}th{text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:0;color:var(--paper-mute);font-weight:500;padding:12px 14px 12px 0;border-bottom:1px solid var(--rule)}th:last-child,td:last-child{padding-right:0}th.num,td.num{text-align:right;padding-left:18px}td{padding:14px 14px 14px 0;border-bottom:1px solid var(--ink-3);color:var(--paper-dim);font-size:13px;font-family:var(--mono);font-weight:500;line-height:1.4}td.num{color:var(--paper);font-variant-numeric:tabular-nums}.file-path{color:var(--paper);font-weight:500}.grade-pill{display:inline-block;font-family:var(--serif);font-style:italic;font-weight:800;font-size:18px;line-height:1;padding:4px 10px;border:1.5px solid currentColor;min-width:36px;text-align:center}.chart-summary{color:var(--paper-dim);font-size:12px;margin:-6px 0 18px}.chart-card{border:1px solid var(--rule);padding:24px;background:var(--ink-3)}.title{font-size:10px;text-transform:uppercase;letter-spacing:0;color:var(--paper-mute);margin-bottom:24px}.histogram{display:flex;align-items:flex-end;gap:6px;height:180px;padding-bottom:20px;border-bottom:1px solid var(--rule)}.bar{flex:1;background:var(--forge);position:relative;min-height:4px}.bar.warn{background:var(--grade-c)}.bar.fail{background:var(--grade-f)}.bar .count{position:absolute;top:-22px;left:50%;transform:translateX(-50%);font-size:11px}.histogram-axis{display:flex;gap:6px;margin-top:8px;font-size:10px;color:var(--paper-mute)}.histogram-axis span{flex:1;text-align:center}.findings{padding:48px 0}.finding{display:grid;grid-template-columns:auto 1fr auto;gap:24px;padding:18px 0;border-bottom:1px solid var(--ink-3);align-items:start}.severity{font-size:9px;text-transform:uppercase;letter-spacing:0;padding:4px 10px;border:1px solid currentColor;margin-top:2px;min-width:76px;text-align:center}.severity.fail{color:var(--grade-f)}.severity.warn{color:var(--grade-c)}.severity.note{color:var(--paper-mute)}.rule{font-size:10px;color:var(--forge);text-transform:uppercase;letter-spacing:0;margin-bottom:6px;font-family:var(--mono);font-weight:700;line-height:1.5}.msg{font-family:var(--serif);font-weight:500;font-size:17px;color:var(--paper);line-height:1.4}.loc{font-size:11px;color:var(--paper-mute);margin-top:8px}.loc code{color:var(--paper-dim);background:var(--ink-3);padding:1px 6px;border:1px solid var(--rule)}.loc-link{color:inherit;text-decoration:none}.loc-link:focus-visible{outline:2px solid var(--forge);outline-offset:3px}.points{font-size:10px;color:var(--paper-mute);text-align:right;letter-spacing:0;min-width:96px;padding-left:12px}.empty{color:var(--paper-dim);font-size:12px}.footer{margin-top:48px;padding-top:24px;border-top:1px solid var(--rule);display:grid;grid-template-columns:1fr auto 1fr;gap:24px;align-items:center;font-size:10px;color:var(--paper-mute);letter-spacing:0;text-transform:uppercase}.center{font-family:var(--serif);font-style:italic;font-size:13px;color:var(--paper-dim);text-transform:none;letter-spacing:0}.right{text-align:right}@media(max-width:900px){body{padding:16px}.paper{padding:28px 20px}.wordmark{font-size:64px}.masthead,.verdict{grid-template-columns:1fr}.meta{text-align:left}.grade-stamp{margin:0 auto}.verdict-stats{grid-template-columns:repeat(2,1fr);gap:16px}.stat{border-right:0;padding:0}.verdict-headline{font-size:28px}.footer{grid-template-columns:1fr}.center,.right{text-align:left}}@media(max-width:560px){.pillar-table thead{display:none}.pillar-table,.pillar-table tbody,.pillar-table tr,.pillar-table td{display:block;width:100%}.pillar-table tr{border-bottom:1px solid var(--ink-3);padding:10px 0}.pillar-table td{border-bottom:0;padding:6px 0}.pillar-table td.num{text-align:left;padding-left:0}.finding{grid-template-columns:1fr}.points{text-align:left;padding-left:0}.verdict-stats{grid-template-columns:1fr}.histogram{height:140px}}`;
  const reportCss = `${baseCss}.dashboard-context{padding:28px 0;border-bottom:1px solid var(--rule)}.dashboard-context-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.dashboard-context-grid>div{border:1px solid var(--rule);background:var(--ink-3);padding:12px 14px}.dashboard-context .label{display:block;margin:0 0 6px}.dashboard-context .val{overflow-wrap:anywhere}@media(max-width:700px){.dashboard-context-grid{grid-template-columns:1fr}}@media(max-width:560px){.offender-list thead{display:none}.offender-list,.offender-list tbody,.offender-list tr,.offender-list td{display:block;width:100%}.offender-list tr{border-bottom:1px solid var(--ink-3);padding:10px 0}.offender-list td{border-bottom:0;padding:6px 0}.offender-list td.num{text-align:left;padding-left:0}}`;
  if (!shouldIncludeDiagnostics) {
    return reportCss;
  }
  return `${reportCss}.diagnostics{padding:28px 0 0}.diagnostic-list{display:grid;gap:10px}.diagnostic{display:grid;grid-template-columns:auto 1fr;gap:10px 14px;border:1px solid var(--rule);background:var(--ink-3);padding:12px 14px;color:var(--paper-dim);font-size:12px}.diagnostic-type{text-transform:uppercase;letter-spacing:0;color:var(--forge);font-size:10px}.diagnostic-location{grid-column:2;color:var(--paper-mute);font-size:11px}`;
}

/**
 * Renders the dashboard shell with an iframe and control panel so scans can reload without losing form state.
 *
 * @param projectRoot - initial project root directory populating the form input and scan URL
 * @param scanPath - initial scan path populating the form input and scan URL
 * @returns Complete HTML document for the dashboard home page
 */
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

/**
 * Builds the /scan request URL encoded as form query parameters with spaces written as +.
 *
 * @param projectRoot - project root directory serialized as the projectRoot query parameter
 * @param scanPath - target scan path serialized as the path query parameter
 * @returns Relative /scan URL with encoded projectRoot and path query parameters
 */
function dashboardScanUrl(projectRoot: string, scanPath: string): string {
  const params = new URLSearchParams({ projectRoot, path: scanPath });
  return `/scan?${params.toString()}`;
}

/**
 * Renders the dashboard failure page and escapes all three values because error text and paths can contain repository-controlled content.
 *
 * @param message - failure reason displayed in the error body
 * @param projectRoot - project root directory identifying the failed scan
 * @param scanPath - target scan path identifying the failed scan
 * @returns Complete HTML document for the dashboard scan error page
 */
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

/**
 * Provides the stylesheet shared by the dashboard shell and its error page.
 * Inlined rather than linked so the dashboard stays self-contained without separate asset routes for offline use.
 *
 * @returns Minified CSS text for the dashboard shell and error page
 */
function dashboardCss(): string {
  return `:root{color-scheme:dark;--ink:#0d0c0a;--ink-2:#161412;--panel:#1f1c19;--paper:#f3e9d2;--paper-dim:#b5ab94;--paper-mute:#7d735f;--rule:#2a2622;--forge:#e85d04;--forge-dark:#b94402;--mono:'JetBrains Mono','IBM Plex Mono',ui-monospace,monospace}*{box-sizing:border-box}html,body{height:100%;margin:0;background:var(--ink);color:var(--paper);font-family:var(--mono);font-size:14px;line-height:1.5}.report-frame{position:fixed;inset:0;width:100%;height:100%;border:0;background:var(--ink)}.controls-toggle{position:fixed;top:18px;right:18px;z-index:3;width:44px;height:44px;border:1px solid rgba(232,93,4,.75);border-radius:8px;background:var(--forge);color:#170b05;font:700 22px/1 var(--mono);display:grid;place-items:center;cursor:pointer;box-shadow:0 16px 36px rgba(0,0,0,.38)}.controls-toggle:hover,.controls-toggle:focus-visible{background:#ff7a1a;outline:2px solid rgba(243,233,210,.75);outline-offset:3px}.controls-panel{position:fixed;z-index:2;top:74px;right:18px;width:min(420px,calc(100vw - 36px));max-height:calc(100vh - 92px);overflow:auto;background:rgba(31,28,25,.98);border:1px solid var(--rule);border-radius:8px;padding:20px;box-shadow:0 24px 70px rgba(0,0,0,.5)}[hidden]{display:none!important}.controls-head{border-bottom:1px solid var(--rule);padding-bottom:14px;margin-bottom:16px}.controls-head h1{margin:0;font-size:18px;font-weight:800}.controls-head p{margin:4px 0 0;color:var(--paper-mute);font-size:12px;text-transform:uppercase}.scan-form{display:grid;gap:14px}.scan-form label{display:grid;gap:6px;color:var(--paper-dim);font-size:12px;text-transform:uppercase}.scan-form input{width:100%;font:inherit;color:var(--paper);background:var(--ink-2);border:1px solid var(--rule);border-radius:6px;padding:10px 11px;min-width:0}.scan-form input:focus{outline:2px solid var(--forge);outline-offset:2px}.scan-state{display:flex;justify-content:space-between;gap:12px;border:1px solid var(--rule);background:var(--ink-2);border-radius:6px;padding:10px 11px;color:var(--paper-mute)}.scan-state strong{color:var(--paper);font-weight:700;text-align:right}.actions{display:grid;grid-template-columns:1fr 1fr;gap:10px}.actions button{font:inherit;border:1px solid var(--forge);border-radius:6px;padding:10px 12px;background:var(--forge);color:#170b05;font-weight:800;cursor:pointer}.actions button.secondary{background:transparent;color:var(--paper);border-color:var(--rule)}.actions button:disabled{opacity:.6;cursor:wait}.scan-error{max-width:720px;margin:8vh auto;padding:48px;background:var(--panel);border:1px solid var(--rule);color:var(--paper)}.scan-error h1{margin:0 0 16px;font-size:28px}.scan-error p{color:var(--paper-dim);overflow-wrap:anywhere}.scan-error dl{display:grid;grid-template-columns:auto 1fr;gap:8px 16px;margin:24px 0 0}.scan-error dt{color:var(--paper-mute);text-transform:uppercase}.scan-error dd{margin:0;overflow-wrap:anywhere}@media(max-width:560px){.controls-toggle{top:12px;right:12px}.controls-panel{top:64px;right:12px;width:calc(100vw - 24px);max-height:calc(100vh - 76px);padding:16px}.actions{grid-template-columns:1fr}.scan-error{margin:0;min-height:100vh;padding:28px 20px}.scan-error dl{grid-template-columns:1fr}}`;
}

/**
 * Provides the inline script served with the dashboard shell.
 * Updates the URL via history.replaceState so a maintainer can copy and reproduce the current scan without re-typing controls.
 *
 * @returns Minified client-side JavaScript controlling the panel toggle, scan form, and iframe state
 */
function dashboardJs(): string {
  return `const form=document.querySelector("[data-scan-form]");const frame=document.querySelector(".report-frame");const toggle=document.querySelector(".controls-toggle");const panel=document.querySelector(".controls-panel");const refresh=document.querySelector("[data-refresh]");const status=document.querySelector("[data-scan-status]");function setOpen(open){panel.hidden=!open;toggle.setAttribute("aria-expanded",String(open));if(open){const input=form.querySelector("input");if(input){input.focus();}}}function params(){return new URLSearchParams(new FormData(form));}function runScan(){const query=params();status.textContent="Scanning";refresh.disabled=true;form.querySelector("button[type=submit]").disabled=true;frame.src="/scan?"+query.toString();history.replaceState(null,"","/?"+query.toString());}toggle.addEventListener("click",()=>setOpen(panel.hidden));document.addEventListener("keydown",(event)=>{if(event.key==="Escape"){setOpen(false);}});form.addEventListener("submit",(event)=>{event.preventDefault();runScan();});refresh.addEventListener("click",runScan);frame.addEventListener("load",()=>{status.textContent="Ready";refresh.disabled=false;form.querySelector("button[type=submit]").disabled=false;});`;
}

/**
 * Escapes &, <, >, and double quotes for report text and double-quoted attributes.
 * Escapes & first so that the entities inserted by the other replacements stay intact.
 *
 * @param htmlText - raw text to sanitize before embedding in HTML content or double-quoted attributes
 * @returns Escaped text safe for HTML text nodes and double-quoted attribute values
 */
function escapeHtml(htmlText: string): string {
  return htmlText.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
}

export { dashboardErrorHtml, dashboardHomeHtml, renderHtml };
