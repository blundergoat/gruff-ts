import { Command, Help } from "commander";
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { DEFAULT_BASELINE } from "./baseline.ts";
import { VERSION } from "./constants.ts";
import { startDashboard } from "./dashboard.ts";
import { renderReport, renderSummary } from "./report-renderers.ts";
import { completionShell, renderCompletionScript, renderConsoleList, renderRuleList, type RuleListFormat } from "./rule-list.ts";
import { exitFor } from "./scoring.ts";
import type { AnalysisOptions, AnalysisReport } from "./types.ts";

type AnalyseRunner = (options: AnalysisOptions) => AnalysisReport;

// The `report` command intentionally rejects `--baseline` because its output is meant to reflect
// raw findings; this flag lets `normalizeOptions` enforce that without per-command branching.
interface NormalizeContext {
  allowBaselineFlag: boolean;
}

// Honours `--silent`/`--quiet` before writing to stdout. Always appends a trailing newline so piped
// callers (e.g., `gruff-ts analyse | jq`) see a complete line even when a renderer forgot one.
function writeCommandOutput(program: Command, output: string): void {
  if (outputSuppressed(program)) {
    return;
  }
  process.stdout.write(output.endsWith("\n") ? output : `${output}\n`);
}

// `--silent` and `--quiet` both suppress non-error stdout — they are intentionally treated the same
// here because Commander exposes them as independent flags but the CLI's contract is uniform.
function outputSuppressed(program: Command): boolean {
  const options = program.opts() as { quiet?: boolean; silent?: boolean };
  return options.quiet === true || options.silent === true;
}

// Three-state ANSI resolution: explicit `--ansi` forces colour, explicit `--no-ansi` forbids it,
// otherwise autodetect from TTY. Required because pipelines and CI logs would otherwise eat colour codes.
function ansiEnabled(program: Command): boolean {
  const options = program.opts() as { ansi?: boolean };
  if (options.ansi === true) {
    return true;
  }
  if (options.ansi === false) {
    return false;
  }
  return process.stdout.isTTY === true;
}

// `runAnalyse` is injected rather than imported to keep `cli-program.ts` off the analyser's
// dependency graph; see `.goat-flow/lessons/verification.md` on the original cli.ts ↔ cli-program.ts cycle.
export function buildProgram(runAnalyse: AnalyseRunner): Command {
  const program = new Command();
  configureRootProgram(program);
  registerAnalyseCommand(program, runAnalyse);
  registerCompletionCommand(program);
  registerDashboardCommand(program, runAnalyse);
  registerListCommand(program);
  registerListRulesCommand(program);
  registerReportCommand(program, runAnalyse);
  registerSummaryCommand(program, runAnalyse);
  return program;
}

// Adds the Symfony-style global flags (`--silent`, `--quiet`, `--ansi`, `--no-interaction`, `-v`)
// and replaces the default help formatter so the bare root command lists the catalogue instead of
// Commander's auto-generated usage block.
function configureRootProgram(program: Command): void {
  program
    .name("gruff-ts")
    .usage("command [options] [arguments]")
    .helpOption("-h, --help", "Display help for the given command. When no command is given display help for the list command")
    .version(VERSION, "-V, --version", "Display this application version")
    .option("--silent", "Do not output any message")
    .option("-q, --quiet", "Only errors are displayed. All other output is suppressed")
    .option("--ansi", "Force ANSI output")
    .option("--no-ansi", "Disable ANSI output")
    .option("-n, --no-interaction", "Do not ask any interactive question")
    .option("-v, --verbose", "Increase the verbosity of messages: 1 for normal output, 2 for more verbose output and 3 for debug", (_value, previous: number) => previous + 1, 0)
    .addHelpCommand("help [command]", "Display help for a command")
    .showHelpAfterError()
    .configureHelp({

      // Custom root help: the bare `gruff-ts` invocation prints the Symfony-style command catalogue;
      // subcommand help still uses Commander's default formatter via `rootHelpText`.
      formatHelp(command, helper) {
        return rootHelpText(program, command, helper);
      },
    })
    .action(() => {
      writeCommandOutput(program, renderConsoleList(ansiEnabled(program)));
    });
}

// Returns the catalogue view when the user asked for root help; defers to Commander's default
// formatter for subcommand help. `showGlobalOptions = true` so the global flags surface there too.
function rootHelpText(program: Command, command: Command, helper: Help): string {
  if (command === program) {
    return renderConsoleList(ansiEnabled(program));
  }
  const defaultHelp = new Help();
  defaultHelp.showGlobalOptions = true;
  if (helper.helpWidth !== undefined) {
    defaultHelp.helpWidth = helper.helpWidth;
  }
  if (helper.minWidthToWrap !== undefined) {
    defaultHelp.minWidthToWrap = helper.minWidthToWrap;
  }
  return defaultHelp.formatHelp(command, defaultHelp);
}

// The primary entry point. Sets `process.exitCode` (not `process.exit`) so async writers in the
// renderer get a chance to flush before Node tears down. Default fail-on is `error`, matching CI.
function registerAnalyseCommand(program: Command, runAnalyse: AnalyseRunner): void {
  program
    .command("analyse")
    .description("Run gruff analysis.")
    .argument("[paths...]", "Files or directories to analyse.")
    .option("--config <path>", "Path to a gruff YAML config file.")
    .option("--no-config", "Skip auto-applying the default .gruff-ts.yaml file for this run.")
    .option("--format <format>", "Output format: text, json, html, markdown, github, hotspot, or sarif.", "text")
    .option("--fail-on <severity>", "Finding severity that fails the run: advisory, warning, error, or none.", "error")
    .option("--include-ignored", "Include files under default and Git ignored paths; config ignores still apply.")
    .option("--diff [mode]", "Filter findings to changed files. Use working-tree, staged, unstaged, or a base ref.")
    .option("--history-file <path>", "Append score trend history to this JSON file.")
    .option("--baseline [path]", "Suppress findings that match a gruff baseline JSON file.")
    .option("--generate-baseline [path]", "Write current findings to a gruff baseline JSON file.")
    .option("--no-baseline", "Skip auto-applying the default baseline file for this run.")
    .action((paths: string[], rawOptions: Record<string, unknown>) => {
      const options = normalizeOptions(paths, rawOptions, { allowBaselineFlag: true });
      const report = runAnalyse(options);
      writeCommandOutput(program, renderReport(report, options.format));
      process.exitCode = exitFor(report, options.failOn);
    });
}

// Emits the static completion script for the requested shell. Does not touch the filesystem or
// run a scan — callers pipe the output into their shell config themselves.
function registerCompletionCommand(program: Command): void {
  program
    .command("completion")
    .description("Dump the shell completion script")
    .argument("[shell]", "Shell to generate completion for: bash, zsh, or fish.", "bash")
    .action((shell: string) => {
      writeCommandOutput(program, renderCompletionScript(completionShell(shell)));
    });
}

// Wires the `dashboard` subcommand to `startDashboard`. Defaults bind to loopback (127.0.0.1:8767)
// because the dashboard accepts a `projectRoot` query parameter and would otherwise be unauthenticated.
function registerDashboardCommand(program: Command, runAnalyse: AnalyseRunner): void {
  program
    .command("dashboard")
    .description("Serve the local gruff dashboard.")
    .option("--host <host>", "Host to bind.", "127.0.0.1")
    .option("--port <port>", "Port to bind.", "8767")
    .option("--project-root <path>", "Default project root.", ".")
    .action((rawOptions: Record<string, unknown>) => {
      startDashboard(String(rawOptions.host ?? "127.0.0.1"), Number(rawOptions.port ?? 8767), resolve(String(rawOptions.projectRoot ?? ".")), runAnalyse, !outputSuppressed(program));
    });
}

// Mirrors the bare-root help output. Exists so `gruff-ts list` works the way `symfony list` does
// for users coming from Symfony's console conventions.
function registerListCommand(program: Command): void {
  program
    .command("list")
    .description("List commands")
    .action(() => {
      writeCommandOutput(program, renderConsoleList(ansiEnabled(program)));
    });
}

// Read-only catalogue dump. JSON is the canonical form consumed by docs builds; text is for humans.
// Anything other than `json` falls back to `text` rather than erroring so old aliases keep working.
function registerListRulesCommand(program: Command): void {
  program
    .command("list-rules")
    .description("List gruff rule metadata.")
    .option("--format <format>", "Output format: text or json.", "text")
    .action((rawOptions: Record<string, unknown>) => {
      const format: RuleListFormat = rawOptions.format === "json" ? "json" : "text";
      writeCommandOutput(program, renderRuleList(format));
    });
}

// `report` differs from `analyse` in two ways: default format is `html`, and baseline suppression is
// disallowed (`allowBaselineFlag: false`) because reports are meant to capture the raw scan, not a
// filtered view. Writes the rendered output to `--output` when provided; otherwise to stdout.
function registerReportCommand(program: Command, runAnalyse: AnalyseRunner): void {
  program
    .command("report")
    .description("Render a gruff report to stdout or a file.")
    .argument("[paths...]", "Files or directories to analyse.")
    .option("--format <format>", "Report format: html or json.", "html")
    .option("--output <path>", "Write report to a file.")
    .option("--config <path>", "Path to a gruff YAML config file.")
    .option("--no-config", "Skip auto-applying the default .gruff-ts.yaml file for this run.")
    .option("--fail-on <severity>", "Finding severity that fails the run.", "none")
    .option("--include-ignored", "Include files under default and Git ignored paths; config ignores still apply.")
    .option("--no-baseline", "Skip auto-applying the default baseline file for this run.")
    .action((paths: string[], rawOptions: Record<string, unknown>) => {
      const format = rawOptions.format === "json" ? "json" : "html";
      const options = normalizeOptions(paths, { ...rawOptions, format }, { allowBaselineFlag: false });
      const report = runAnalyse(options);
      const rendered = renderReport(report, format);
      if (typeof rawOptions.output === "string") {
        writeFileSync(rawOptions.output, rendered);
      } else {
        writeCommandOutput(program, rendered);
      }
      process.exitCode = exitFor(report, options.failOn);
    });
}

// Same analyser run as `analyse` but renders only the pillar/rule/offender digest. Format is locked
// to `text` because the summary shape is intentionally not part of the JSON report contract.
function registerSummaryCommand(program: Command, runAnalyse: AnalyseRunner): void {
  program
    .command("summary")
    .description(
      "Print a compact digest of a scan: per-pillar finding counts, top rules, and top file offenders. Runs the analyser once and renders only the summary; no per-finding spam.",
    )
    .argument("[paths...]", "Files or directories to analyse.")
    .option("--config <path>", "Path to a gruff YAML config file.")
    .option("--no-config", "Skip auto-applying the default .gruff-ts.yaml file for this run.")
    .option("--fail-on <severity>", "Finding severity that fails the run: advisory, warning, error, or none.", "error")
    .option("--include-ignored", "Include files under default and Git ignored paths; config ignores still apply.")
    .option("--diff [mode]", "Filter findings to changed files. Use working-tree, staged, unstaged, or a base ref.")
    .option("--history-file <path>", "Append score trend history to this JSON file.")
    .option("--baseline [path]", "Suppress findings that match a gruff baseline JSON file.")
    .option("--generate-baseline [path]", "Write current findings to a gruff baseline JSON file.")
    .option("--no-baseline", "Skip auto-applying the default baseline file for this run.")
    .action((paths: string[], rawOptions: Record<string, unknown>) => {
      const options = normalizeOptions(paths, { ...rawOptions, format: "text" }, { allowBaselineFlag: true });
      const report = runAnalyse(options);
      writeCommandOutput(program, renderSummary(report));
      process.exitCode = exitFor(report, options.failOn);
    });
}

// Single source of truth for translating Commander's loose option bag into the strict
// `AnalysisOptions` shape that drives baseline matching. The fingerprint contract is the invariant:
// two CLI invocations producing identical AnalysisOptions must produce identical, stable findings —
// adding new fields here without folding them into that hash is a deterministic-output regression.
function normalizeOptions(paths: string[], rawOptions: Record<string, unknown>, context: NormalizeContext): AnalysisOptions {
  const format = stringChoice(rawOptions.format, ["text", "json", "html", "markdown", "github", "hotspot", "sarif"], "text");
  const failOn = stringChoice(rawOptions.failOn, ["none", "advisory", "warning", "error"], "error");
  const baselineValue = rawOptions.baseline;
  const noBaseline =
    baselineValue === false ||
    rawOptions.noBaseline === true;
  return {
    paths,
    ...configOption(rawOptions),
    noConfig:
      rawOptions.config === false ||
      rawOptions.noConfig === true,
    format,
    failOn,
    includeIgnored: rawOptions.includeIgnored === true,
    ...diffOption(rawOptions),
    ...historyFileOption(rawOptions),
    ...baselineOption(baselineValue, context),
    ...generateBaselineOption(rawOptions),
    noBaseline,
  };
}

// Conditional spreads (not `config: undefined`) because `AnalysisOptions` runs under
// `exactOptionalPropertyTypes` — the absent and `undefined` cases are not interchangeable.
function configOption(rawOptions: Record<string, unknown>): Partial<Pick<AnalysisOptions, "config">> {
  return typeof rawOptions.config === "string" ? { config: rawOptions.config } : {};
}

// `--diff` without an argument means "working-tree". A boolean `true` arrives when Commander parsed
// the flag standalone; an explicit string keeps whatever ref the user passed (e.g., `main`).
function diffOption(rawOptions: Record<string, unknown>): Partial<Pick<AnalysisOptions, "diff">> {
  if (typeof rawOptions.diff === "string") {
    return { diff: rawOptions.diff };
  }
  return rawOptions.diff === true ? { diff: "working-tree" } : {};
}

// Conditional spread keeps `historyFile` absent rather than `undefined` under exactOptionalPropertyTypes.
function historyFileOption(rawOptions: Record<string, unknown>): Partial<Pick<AnalysisOptions, "historyFile">> {
  return typeof rawOptions.historyFile === "string" ? { historyFile: rawOptions.historyFile } : {};
}

// `--baseline` with no value implies the conventional default file (`gruff-baseline.json`); commands
// that disallow baseline input (e.g., `report`) short-circuit so the option is never set. The fingerprint
// contract requires that two scans with the same baseline file produce identical suppression behaviour.
function baselineOption(baselineValue: unknown, context: NormalizeContext): Partial<Pick<AnalysisOptions, "baseline">> {
  if (!context.allowBaselineFlag) {
    return {};
  }
  if (typeof baselineValue === "string") {
    return { baseline: baselineValue };
  }
  return baselineValue === true ? { baseline: DEFAULT_BASELINE } : {};
}

// Mirrors `--baseline`: a bare `--generate-baseline` writes to the default path; a string value
// overrides it. Absent (not present) and absent-because-undefined are distinct here.
function generateBaselineOption(rawOptions: Record<string, unknown>): Partial<Pick<AnalysisOptions, "generateBaseline">> {
  if (typeof rawOptions.generateBaseline === "string") {
    return { generateBaseline: rawOptions.generateBaseline };
  }
  return rawOptions.generateBaseline === true ? { generateBaseline: DEFAULT_BASELINE } : {};
}

function stringChoice<T extends string>(value: unknown, choices: readonly T[], fallback: T): T {
  return typeof value === "string" && choices.includes(value as T) ? (value as T) : fallback;
}
