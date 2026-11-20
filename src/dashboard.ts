// Loopback dashboard HTTP surface that renders live analyzer reports without exposing remote scans.
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { chdir, cwd, stdout } from "node:process";
import { dashboardErrorHtml, dashboardHomeHtml, renderHtml } from "./report-html.ts";
import type { AnalysisOptions, AnalysisReport, DeepScanBudgetOverride } from "./types.ts";

type DashboardAnalyse = (options: AnalysisOptions) => AnalysisReport;

// Host/port/projectRoot frozen at server start. The dashboard binds to a loopback host only -
// `startDashboard` callers must not relax this without auditing for unauthenticated remote scans.
interface DashboardContext {
  host: string;
  port: number;
  projectRoot: string;
  profile?: string;
  deepScanBudget?: DeepScanBudgetOverride;
}

// Per-request projectRoot + scanPath. Sourced from `?projectRoot` and `?path` query parameters and
// fed straight to `chdir`/`analyse`, so untrusted values would let a caller pivot the analyser to
// arbitrary directories - only acceptable because the server is loopback-only.
interface DashboardRouteInput {
  root: string;
  scanPath: string;
}

/**
 * Starts the loopback dashboard. Inject analyse to avoid the CLI import cycle documented in .goat-flow/learning-loop/lessons/verification.md.
 *
 * @param host - loopback address to bind. Use 127.0.0.1 or localhost.
 * @param port - port for the HTTP listener
 * @param projectRoot - default project directory for dashboard scans
 * @param analyse - callback that produces the analysis report for a dashboard scan
 * @param shouldWriteOutput - whether to write the listening URL to stdout. Defaults to true.
 * @param profile - optional analysis profile forwarded to dashboard scans
 * @param deepScanBudget - optional deep-scan budget override forwarded to dashboard scans
 * @returns nothing. Side effect: opens the listener and writes its URL to stdout when output is enabled.
 * @throws {Error} - the host is neither 127.0.0.1 nor localhost
 */
function startDashboard(host: string, port: number, projectRoot: string, analyse: DashboardAnalyse, shouldWriteOutput = true, profile?: string, deepScanBudget?: DeepScanBudgetOverride): void {
  assertLoopbackHost(host);
  const context: DashboardContext = {
    host,
    port,
    projectRoot,
    ...(profile !== undefined ? { profile } : {}),
    ...(deepScanBudget !== undefined ? { deepScanBudget } : {}),
  };
  const server = createServer((request, response) => handleDashboardRequest(context, analyse, request, response));
  server.listen(port, host, () => {
    if (shouldWriteOutput) {
      stdout.write(`gruff-ts dashboard listening at http://${host}:${port}\n`);
    }
  });
}

// The dashboard accepts filesystem paths from query strings, so loopback binding is its safety boundary.
// Returns nothing after validating the requested bind host before the listener opens.
// @throws {Error} - when the host is anything other than 127.0.0.1 or localhost.
function assertLoopbackHost(host: string): void {
  if (host !== "127.0.0.1" && host !== "localhost") {
    throw new Error("Dashboard host must be 127.0.0.1 or localhost.");
  }
}

// Returns nothing. Routes request using context's host, port and default project root, writing the result to response.
// Health and home responses use no-store; scans run analyse with context's profile and budget and return HTML with no-store.
// A missing request URL selects home; unrecognized paths return 404 without a cache-control override.
function handleDashboardRequest(context: DashboardContext, analyse: DashboardAnalyse, request: IncomingMessage, response: ServerResponse): void {
  const url = new URL(request.url ?? "/", `http://${context.host}:${context.port}`);
  if (url.pathname === "/health") {
    writeTextResponse(response, 200, "ok", true);
    return;
  }
  if (url.pathname === "/scan") {
    renderDashboardScan(response, dashboardRouteInput(url, context.projectRoot), analyse, context.profile, context.deepScanBudget);
    return;
  }
  if (url.pathname !== "/") {
    writeTextResponse(response, 404, "not found", false);
    return;
  }
  const input = dashboardRouteInput(url, context.projectRoot);
  writeHtmlResponse(response, 200, dashboardHomeHtml(input.root, input.scanPath));
}

// Returns the project root and scan path from the dashboard URL for the home and scan routes.
// Missing projectRoot uses the supplied launch root. Missing path uses "." within the selected root. Empty values pass through.
// The scan route passes the root to chdir and the path to analyse under the DashboardRouteInput loopback trust assumption.
function dashboardRouteInput(url: URL, projectRoot: string): DashboardRouteInput {
  return {
    root: url.searchParams.get("projectRoot") ?? projectRoot,
    scanPath: url.searchParams.get("path") ?? ".",
  };
}

// Writes HTML to response for analyse on input.scanPath from input.root. A failed switch, scan, render or write is reported in the 500 page.
// Passes profile and deepScanBudget as optional analysis overrides; omitted values leave those choices to analyse.
// Returns nothing. It attempts to restore the working directory in finally so that later requests inherit a stable environment.
// @throws {Error} - when reading or restoring the working directory fails, or writing the error page throws.
function renderDashboardScan(response: ServerResponse, input: DashboardRouteInput, analyse: DashboardAnalyse, profile?: string, deepScanBudget?: DeepScanBudgetOverride): void {
  const previous = cwd();
  try {
    chdir(input.root);
    const report = analyse({
      paths: [input.scanPath],
      shouldSkipConfig: false,
      ...(profile !== undefined ? { profile } : {}),
      ...(deepScanBudget !== undefined ? { deepScanBudget } : {}),
      format: "html",
      failOn: "none",
      shouldIncludeIgnored: false,
      changedScope: "symbol",
      shouldSkipBaseline: false,
    });
    writeHtmlResponse(response, 200, renderHtml(report, { projectRoot: input.root, scanPath: input.scanPath }));
  } catch (error) {
    writeHtmlResponse(response, 500, dashboardErrorHtml(String(error), input.root, input.scanPath));
  } finally {
    chdir(previous);
  }
}

// Returns nothing. Writes body as UTF-8 HTML to response with statusCode, then ends the response.
// Uses no-store so proxies do not serve stale findings to the maintainer.
function writeHtmlResponse(response: ServerResponse, statusCode: number, body: string): void {
  response.writeHead(statusCode, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
  response.end(body);
}

// Returns nothing. Writes body as UTF-8 plain text to response with statusCode, then ends the response.
// shouldUseNoStore adds no-store for health probes; false leaves cache policy unset, as for the constant 404 response.
function writeTextResponse(response: ServerResponse, statusCode: number, body: string, shouldUseNoStore: boolean): void {
  response.writeHead(statusCode, { "content-type": "text/plain; charset=utf-8", ...(shouldUseNoStore ? { "cache-control": "no-store" } : {}) });
  response.end(body);
}

export { startDashboard };
