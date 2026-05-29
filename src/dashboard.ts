// Loopback dashboard HTTP surface that renders live analyzer reports without exposing remote scans.
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { chdir, cwd, stdout } from "node:process";
import { dashboardErrorHtml, dashboardHomeHtml, renderHtml } from "./report-html.ts";
import type { AnalysisOptions, AnalysisReport } from "./types.ts";

type DashboardAnalyse = (options: AnalysisOptions) => AnalysisReport;

// Host/port/projectRoot frozen at server start. The dashboard binds to a loopback host only -
// `startDashboard` callers must not relax this without auditing for unauthenticated remote scans.
interface DashboardContext {
  host: string;
  port: number;
  projectRoot: string;
}

// Per-request projectRoot + scanPath. Sourced from `?projectRoot` and `?path` query parameters and
// fed straight to `chdir`/`analyse`, so untrusted values would let a caller pivot the analyser to
// arbitrary directories - only acceptable because the server is loopback-only.
interface DashboardRouteInput {
  root: string;
  scanPath: string;
}

// Starts a loopback HTTP server. `analyse` is injected (not imported) to avoid a circular import
// back into `cli.ts`; see `.goat-flow/lessons/verification.md` on the dashboard import cycle.
// Side effect: opens a listening socket and writes the URL to stdout unless `shouldWriteOutput` is false.
function startDashboard(host: string, port: number, projectRoot: string, analyse: DashboardAnalyse, shouldWriteOutput = true): void {
  assertLoopbackHost(host);
  const context: DashboardContext = { host, port, projectRoot };
  const server = createServer((request, response) => handleDashboardRequest(context, analyse, request, response));
  server.listen(port, host, () => {
    if (shouldWriteOutput) {
      stdout.write(`gruff-ts dashboard listening at http://${host}:${port}\n`);
    }
  });
}

// The dashboard accepts filesystem paths from query strings, so loopback binding is its safety
// boundary. Throws before opening the listener when a caller asks for a public host.
function assertLoopbackHost(host: string): void {
  if (host !== "127.0.0.1" && host !== "localhost") {
    throw new Error("Dashboard host must be 127.0.0.1 or localhost.");
  }
}

// Four endpoints: `/health` (uptime probes), `/scan` (runs the analyser and renders HTML),
// `/` (control page), anything else → 404. `/health` is the only response that survives proxies
// uncached - the scan and home responses set `no-store` so the dashboard always sees fresh output.
function handleDashboardRequest(context: DashboardContext, analyse: DashboardAnalyse, request: IncomingMessage, response: ServerResponse): void {
  const url = new URL(request.url ?? "/", `http://${context.host}:${context.port}`);
  if (url.pathname === "/health") {
    writeTextResponse(response, 200, "ok", true);
    return;
  }
  if (url.pathname === "/scan") {
    renderDashboardScan(response, dashboardRouteInput(url, context.projectRoot), analyse);
    return;
  }
  if (url.pathname !== "/") {
    writeTextResponse(response, 404, "not found", false);
    return;
  }
  const input = dashboardRouteInput(url, context.projectRoot);
  writeHtmlResponse(response, 200, dashboardHomeHtml(input.root, input.scanPath));
}

// Reads `?projectRoot` and `?path`, falling back to the server's launch context. Both values flow
// straight into `chdir` and `analyse`; see DashboardRouteInput for the loopback trust assumption.
function dashboardRouteInput(url: URL, projectRoot: string): DashboardRouteInput {
  return {
    root: url.searchParams.get("projectRoot") ?? projectRoot,
    scanPath: url.searchParams.get("path") ?? ".",
  };
}

// chdirs into the caller-requested project root, runs `analyse`, and always restores the previous
// cwd in `finally` - leaking the chdir would corrupt subsequent requests. The loopback server must
// keep serving on analyser failure, so the catch reports the error as a rendered fallback page.
function renderDashboardScan(response: ServerResponse, input: DashboardRouteInput, analyse: DashboardAnalyse): void {
  const previous = cwd();
  try {
    chdir(input.root);
    const report = analyse({
      paths: [input.scanPath],
      shouldSkipConfig: false,
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

// `no-store` is non-negotiable for dashboard responses: stale findings cached by a proxy would
// mislead a maintainer reading the report. Writes the HTTP response body and closes the connection.
function writeHtmlResponse(response: ServerResponse, statusCode: number, body: string): void {
  response.writeHead(statusCode, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
  response.end(body);
}

// `/health` opts in to `no-store` so uptime probes never read a cached "ok"; 404 responses do not,
// because their content is constant and proxies can safely keep them. Writes the response and closes it.
function writeTextResponse(response: ServerResponse, statusCode: number, body: string, shouldUseNoStore: boolean): void {
  response.writeHead(statusCode, { "content-type": "text/plain; charset=utf-8", ...(shouldUseNoStore ? { "cache-control": "no-store" } : {}) });
  response.end(body);
}

export { startDashboard };
