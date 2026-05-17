import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { chdir, cwd, stdout } from "node:process";
import { dashboardErrorHtml, dashboardHomeHtml, renderHtml } from "./report-renderers.ts";
import type { AnalysisOptions, AnalysisReport } from "./types.ts";

type DashboardAnalyse = (options: AnalysisOptions) => AnalysisReport;

interface DashboardContext {
  host: string;
  port: number;
  projectRoot: string;
}

interface DashboardRouteInput {
  root: string;
  scanPath: string;
}

function startDashboard(host: string, port: number, projectRoot: string, analyse: DashboardAnalyse, outputEnabled = true): void {
  const context: DashboardContext = { host, port, projectRoot };
  const server = createServer((request, response) => handleDashboardRequest(context, analyse, request, response));
  server.listen(port, host, () => {
    if (outputEnabled) {
      stdout.write(`gruff-ts dashboard listening at http://${host}:${port}\n`);
    }
  });
}

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

function dashboardRouteInput(url: URL, projectRoot: string): DashboardRouteInput {
  return {
    root: url.searchParams.get("projectRoot") ?? projectRoot,
    scanPath: url.searchParams.get("path") ?? ".",
  };
}

function renderDashboardScan(response: ServerResponse, input: DashboardRouteInput, analyse: DashboardAnalyse): void {
  const previous = cwd();
  try {
    chdir(input.root);
    const report = analyse({
      paths: [input.scanPath],
      noConfig: false,
      format: "html",
      failOn: "none",
      includeIgnored: false,
      noBaseline: false,
    });
    writeHtmlResponse(response, 200, renderHtml(report, { projectRoot: input.root, scanPath: input.scanPath }));
  } catch (error) {
    writeHtmlResponse(response, 500, dashboardErrorHtml(String(error), input.root, input.scanPath));
  } finally {
    chdir(previous);
  }
}

function writeHtmlResponse(response: ServerResponse, statusCode: number, body: string): void {
  response.writeHead(statusCode, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
  response.end(body);
}

function writeTextResponse(response: ServerResponse, statusCode: number, body: string, noStore: boolean): void {
  response.writeHead(statusCode, { "content-type": "text/plain; charset=utf-8", ...(noStore ? { "cache-control": "no-store" } : {}) });
  response.end(body);
}

export { startDashboard };
