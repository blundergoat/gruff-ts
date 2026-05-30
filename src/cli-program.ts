// Commander CLI shell wiring that keeps option normalization and stdout behavior outside the analyzer.
import { Command, Help, InvalidArgumentError } from "commander";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { cwd } from "node:process";
import { DEFAULT_BASELINE } from "./baseline.ts";
import { checkIgnore, checkIgnoreExitCode, renderCheckIgnore, type CheckIgnoreFormat } from "./check-ignore.ts";
import { ConfigLoadError } from "./config-load-error.ts";
import { loadConfig, minimumSeverityFor } from "./config.ts";
import { VERSION } from "./constants.ts";
import { startDashboard } from "./dashboard.ts";
import { promptYesNo, shouldPromptForInit, writeDefaultConfig } from "./init-config.ts";
import { renderReport, renderSummary, renderSummaryJson } from "./report-renderers.ts";
import { completionShell, getRuleDescriptor, renderCompletionScript, renderConsoleList, renderRuleDetail, renderRuleList, type RuleListFormat } from "./rule-list.ts";
import { exitFor } from "./scoring.ts";
import type { AnalysisOptions, AnalysisReport, MinimumSeverityCommand } from "./types.ts";

type AnalyseRunner = (options: AnalysisOptions) => AnalysisReport;

// The `report` command intentionally rejects `--baseline` because its output is meant to reflect
// raw findings; this flag lets `normalizeOptions` enforce that without per-command branching.
interface NormalizeContext {
  shouldAllowBaselineFlag: boolean;
}

// Honours `--silent`/`--quiet` before writing to stdout. Always appends a trailing newline so piped
// callers (e.g., `gruff-ts analyse | jq`) see a complete line even when a renderer forgot one.
function writeCommandOutput(program: Command, output: string): void {
  if (outputSuppressed(program)) {
    return;
  }
  process.stdout.write(output.endsWith("\n") ? output : `${output}\n`);
}

// `--silent` and `--quiet` both suppress non-error stdout - they are intentionally treated the same
// here because Commander exposes them as independent flags but the CLI's contract is uniform.
function outputSuppressed(program: Command): boolean {
  const options = program.opts() as { quiet?: boolean; silent?: boolean };
  return options.quiet === true || options.silent === true;
}

// Per-command config-loading state passed into maybePromptInitConfig. analyse/summary/report
// take both flags from normalizeOptions; dashboard has no equivalent flags so it passes
// `{ shouldSkipConfig: false, hasExplicitConfig: false }`.
interface InitPromptOptions {
  shouldSkipConfig: boolean;
  hasExplicitConfig: boolean;
}

// Asks the user whether to run `init` when no config exists, then writes the file if they agree.
// Called from analyse/summary/report/dashboard before kicking off their main work so the
// freshly-written file is picked up by loadConfig on the same invocation. Pure decision logic
// lives in shouldPromptForInit; this function only handles orchestration and side effects.
async function maybePromptInitConfig(program: Command, projectRoot: string, options: InitPromptOptions): Promise<void> {
  const programOptions = program.opts() as { interaction?: boolean };
  const context = {
    projectRoot,
    shouldSkipConfig: options.shouldSkipConfig,
    hasExplicitConfig: options.hasExplicitConfig,
    isInteractionAllowed: programOptions.interaction !== false,
    isOutputSuppressed: outputSuppressed(program),
    isStdinTty: process.stdin.isTTY === true,
    isStdoutTty: process.stdout.isTTY === true,
    isStderrTty: process.stderr.isTTY === true,
  };
  if (!shouldPromptForInit(context)) {
    return;
  }
  const accepted = await promptYesNo(`No gruff config found at ${projectRoot}. Run 'gruff-ts init' to create .gruff-ts.yaml? [y/N] `);
  if (!accepted) {
    return;
  }
  const result = writeDefaultConfig(projectRoot, false);
  if (result.status === "written") {
    process.stderr.write(`Wrote ${result.path}\n`);
  }
}

// AnalysisOptions → InitPromptOptions shim used by analyse/summary/report so they share one
// branch and shouldSkipConfig stays the single source of truth for opt-out behaviour.
function promptOptionsFromAnalysis(options: AnalysisOptions): InitPromptOptions {
  return { shouldSkipConfig: options.shouldSkipConfig, hasExplicitConfig: typeof options.config === "string" };
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
  registerCheckIgnoreCommand(program);
  registerCompletionCommand(program);
  registerDashboardCommand(program, runAnalyse);
  registerInitCommand(program);
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
// renderer get a chance to flush before Node tears down. The default fail-on is `advisory` because
// the project's gating philosophy is "show everything, fail on anything"; CI flows that want the
// old `error`-only behaviour pass `--fail-on=error` explicitly or pin `minimumSeverity.analyse:
// error` in `.gruff-ts.yaml`. See ADR-004.
function registerAnalyseCommand(program: Command, runAnalyse: AnalyseRunner): void {
  program
    .command("analyse")
    .description("Run gruff analysis.")
    .argument("[paths...]", "Files or directories to analyse.")
    .option("--config <path>", "Path to a gruff YAML config file.")
    .option("--no-config", "Skip auto-applying the default .gruff-ts.yaml file for this run.")
    .option("--format <format>", "Output format: text, json, html, markdown, github, hotspot, or sarif.", "text")
    .option("--fail-on <severity>", "Finding severity that fails the run: advisory, warning, error, or none.", "advisory")
    .option("--include-ignored", "Include files under default and Git ignored paths; config ignores still apply.")
    .option("--changed-ranges <ranges>", "Filter findings to changed regions, for example 3-3,8-10.")
    .option("--since <ref>", "Filter findings to regions changed against a git base ref.")
    .option("--diff [mode]", "Filter findings to changed regions. Use working-tree, staged, unstaged, a base ref, or - for unified diff on stdin.")
    .option("--changed-scope <scope>", "Changed-region scope: symbol or hunk.", "symbol")
    .option("--history-file <path>", "Append score trend history to this JSON file.")
    .option("--baseline [path]", "Suppress findings that match a gruff baseline JSON file.")
    .option("--generate-baseline [path]", "Write current findings to a gruff baseline JSON file.")
    .option("--no-baseline", "Skip auto-applying the default baseline file for this run.")
    .action(async (paths: string[], rawOptions: Record<string, unknown>, command: Command) => {
      await runWithConfigErrorHandling(async () => {
        const baseOptions = normalizeOptions(paths, rawOptions, { shouldAllowBaselineFlag: true });
        const options = applyMinimumSeverityPrecedence(baseOptions, "analyse", command);
        await maybePromptInitConfig(program, process.cwd(), promptOptionsFromAnalysis(options));
        const report = runAnalyse(options);
        writeCommandOutput(program, renderReport(report, options.format));
        process.exitCode = exitFor(report, options.failOn);
      });
    });
}

// Reports whether gruff would exclude each path from analysis, with the matching ignore source and
// pattern, using the exact engine `analyse` uses (no second glob implementation) and performing no
// analysis. Built for coding-agent hooks: gate the changed-file list before scanning. Exit codes
// mirror `git check-ignore` (0 = at least one ignored, 1 = none); a config error surfaces as 2 via
// `runWithConfigErrorHandling`.
function registerCheckIgnoreCommand(program: Command): void {
  program
    .command("check-ignore")
    .description("Report whether gruff would ignore each path (config, gitignore, or default), with the matching source and pattern. Runs no analysis.")
    .argument("<paths...>", "Paths to check against the ignore rules.")
    .option("--config <path>", "Path to a gruff YAML config file.")
    .option("--no-config", "Skip auto-applying the default .gruff-ts.yaml file for this run.")
    .option("--format <format>", "Output format: text or json.", parseSummaryFormat, "text")
    .action(async (paths: string[], rawOptions: Record<string, unknown>) => {
      await runWithConfigErrorHandling(() => {
        const results = checkIgnore(paths, checkIgnoreOptions(paths, rawOptions));
        const format: CheckIgnoreFormat = rawOptions.format === "json" ? "json" : "text";
        writeCommandOutput(program, renderCheckIgnore(results, format));
        process.exitCode = checkIgnoreExitCode(results);
      });
    });
}

// Minimal AnalysisOptions for `check-ignore`: only the fields `loadConfig` and the ignore engine
// read. `--config` / `--no-config` resolve identically to `analyse`; `shouldIncludeIgnored` is false
// so default and gitignore matches are reported (config `paths.ignore` is reported regardless).
function checkIgnoreOptions(paths: string[], rawOptions: Record<string, unknown>): AnalysisOptions {
  return {
    paths,
    ...configOption(rawOptions),
    shouldSkipConfig: rawOptions.config === false || rawOptions.noConfig === true,
    format: "json",
    failOn: "none",
    shouldIncludeIgnored: false,
    changedScope: "symbol",
    shouldSkipBaseline: true,
  };
}

// Emits the static completion script for the requested shell. Does not touch the filesystem or
// run a scan - callers pipe the output into their shell config themselves.
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
    .action(async (rawOptions: Record<string, unknown>) => {
      const projectRoot = resolve(String(rawOptions.projectRoot ?? "."));
      await maybePromptInitConfig(program, projectRoot, { shouldSkipConfig: false, hasExplicitConfig: false });
      startDashboard(String(rawOptions.host ?? "127.0.0.1"), Number(rawOptions.port ?? 8767), projectRoot, runAnalyse, !outputSuppressed(program));
    });
}

// Writes the default `.gruff-ts.yaml` to the current working directory. Refuses to clobber an
// existing config unless `--force` is passed; sets process.exitCode=1 in that case so scripted
// callers can detect the refusal without parsing stdout.
function registerInitCommand(program: Command): void {
  program
    .command("init")
    .description("Write the default .gruff-ts.yaml to the current directory.")
    .option("--force", "Write .gruff-ts.yaml even when another supported config (.gruff.yaml/.yml/.json) is present; overwrites .gruff-ts.yaml if it exists.")
    .action((rawOptions: Record<string, unknown>) => {
      const result = writeDefaultConfig(process.cwd(), rawOptions.force === true);
      if (result.status === "exists") {
        process.stderr.write(`Refusing to overwrite existing config: ${result.path}. Re-run with --force to replace it.\n`);
        process.exitCode = 1;
        return;
      }
      const verb = result.status === "overwritten" ? "Overwrote" : "Wrote";
      writeCommandOutput(program, initSuccessMessage(verb, result.path));
    });
}

// Keeps `init` as a config-only write while pointing existing projects at the adoption flow.
function initSuccessMessage(verb: "Wrote" | "Overwrote", configPath: string): string {
  return [
    `${verb} ${configPath}`,
    "",
    "Next: generate an adoption baseline with:",
    "  gruff-ts analyse . --generate-baseline gruff-baseline.json --fail-on=none",
    "Then gate new findings with:",
    "  gruff-ts analyse . --baseline gruff-baseline.json --fail-on=advisory",
  ].join("\n");
}

// Mirrors the bare-root help output. Exists so users coming from Symfony's console conventions
// can run `gruff-ts list` the way they expect.
function registerListCommand(program: Command): void {
  program
    .command("list")
    .description("List commands")
    .action(() => {
      writeCommandOutput(program, renderConsoleList(ansiEnabled(program)));
    });
}

// Read-only catalogue dump. JSON is the canonical form consumed by docs builds; text is for humans.
// `--format` is validated by `parseSummaryFormat`; unsupported values fail fast as a usage error.
// Optional `<ruleId>` positional switches to single-rule detail mode (M08): no-arg behaviour stays
// byte-identical to the prior version.
function registerListRulesCommand(program: Command): void {
  program
    .command("list-rules")
    .description("List gruff rule metadata. Pass a rule id to print details for one rule.")
    .argument("[ruleId]", "Optional rule id to print details for.")
    .option("--format <format>", "Output format: text or json.", parseSummaryFormat, "text")
    .action((ruleId: string | undefined, rawOptions: Record<string, unknown>) => {
      const format: RuleListFormat = rawOptions.format === "json" ? "json" : "text";
      if (ruleId === undefined) {
        writeCommandOutput(program, renderRuleList(format));
        return;
      }
      const descriptor = getRuleDescriptor(ruleId);
      if (!descriptor) {
        program.error(`unknown rule "${ruleId}". Run \`gruff-ts list-rules\` to see all rules.`, { exitCode: 2 });
        return;
      }
      writeCommandOutput(program, renderRuleDetail(descriptor, format));
    });
}

// `report` differs from `analyse` in two ways: default format is `html`, and baseline suppression is
// disallowed (`shouldAllowBaselineFlag: false`) because reports are meant to capture the raw scan, not a
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
    .action(async (paths: string[], rawOptions: Record<string, unknown>, command: Command) => {
      await runWithConfigErrorHandling(async () => {
        const format = rawOptions.format === "json" ? "json" : "html";
        const baseOptions = normalizeOptions(paths, { ...rawOptions, format }, { shouldAllowBaselineFlag: false });
        const options = applyMinimumSeverityPrecedence(baseOptions, "report", command);
        await maybePromptInitConfig(program, process.cwd(), promptOptionsFromAnalysis(options));
        const report = runAnalyse(options);
        const rendered = renderReport(report, format);
        if (typeof rawOptions.output === "string") {
          writeFileSync(rawOptions.output, rendered);
        } else {
          writeCommandOutput(program, rendered);
        }
        process.exitCode = exitFor(report, options.failOn);
      });
    });
}

// Same analyser run as `analyse` but renders only the pillar/rule/offender digest.
function registerSummaryCommand(program: Command, runAnalyse: AnalyseRunner): void {
  program
    .command("summary")
    .description(
      "Print a compact digest of a scan: per-pillar finding counts, top rules, and top file offenders. Runs the analyser once and renders only the summary; no per-finding spam.",
    )
    .argument("[paths...]", "Files or directories to analyse.")
    .option("--config <path>", "Path to a gruff YAML config file.")
    .option("--no-config", "Skip auto-applying the default .gruff-ts.yaml file for this run.")
    .option("--format <format>", "Output format: text or json.", parseSummaryFormat, "text")
    .option("--top <n>", "How many top rules and file offenders to list.", parseNonNegativeInteger, 10)
    .option("--fail-on <severity>", "Finding severity that fails the run: advisory, warning, error, or none.", "advisory")
    .option("--include-ignored", "Include files under default and Git ignored paths; config ignores still apply.")
    .option("--diff [mode]", "Filter findings to changed files. Use working-tree, staged, unstaged, or a base ref.")
    .option("--history-file <path>", "Append score trend history to this JSON file.")
    .option("--baseline [path]", "Suppress findings that match a gruff baseline JSON file.")
    .option("--generate-baseline [path]", "Write current findings to a gruff baseline JSON file.")
    .option("--no-baseline", "Skip auto-applying the default baseline file for this run.")
    .action(async (paths: string[], rawOptions: Record<string, unknown>, command: Command) => {
      await runWithConfigErrorHandling(async () => {
        const baseOptions = normalizeOptions(paths, { ...rawOptions, format: "text" }, { shouldAllowBaselineFlag: true });
        const options = applyMinimumSeverityPrecedence(baseOptions, "summary", command);
        const summaryFormat = rawOptions.format === "json" ? "json" : "text";
        const top = typeof rawOptions.top === "number" ? rawOptions.top : 10;
        await maybePromptInitConfig(program, process.cwd(), promptOptionsFromAnalysis(options));
        const startedAt = performance.now();
        const report = runAnalyse(options);
        const elapsedMs = performance.now() - startedAt;
        const pathLabel = summaryPathLabel(options.paths, report.run.projectRoot);
        const rendered = summaryFormat === "json"
          ? renderSummaryJson(report, elapsedMs, pathLabel, top)
          : renderSummary(report, elapsedMs, pathLabel, top);
        writeCommandOutput(program, rendered);
        process.exitCode = exitFor(report, options.failOn);
      });
    });
}

/*
 * Commander `--format` argParser for the summary command. Throws `InvalidArgumentError` when the
 * input is neither `text` nor `json`; commander reports that as a usage error and exits non-zero
 * before the command body runs.
 */
function parseSummaryFormat(rawFormat: string): "text" | "json" {
  if (rawFormat === "text" || rawFormat === "json") {
    return rawFormat;
  }
  throw new InvalidArgumentError("must be text or json");
}

/*
 * Commander argParser for `--top`-style numeric flags. Throws `InvalidArgumentError` on non-integer
 * or negative input so commander reports a usage error and exits non-zero before the command runs.
 */
function parseNonNegativeInteger(rawCount: string): number {
  const parsed = Number(rawCount);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new InvalidArgumentError("must be a non-negative integer");
  }
  return parsed;
}

// Summary output should name the scanned operand, not merely the process cwd used to run gruff-ts.
function summaryPathLabel(paths: string[], projectRoot: string): string {
  if (paths.length === 0) {
    return projectRoot;
  }
  return paths.map((path) => resolve(path)).join(", ");
}

// Single source of truth for translating Commander's loose option bag into the strict
// `AnalysisOptions` shape that drives baseline matching. The fingerprint contract is the invariant:
// two CLI invocations producing identical AnalysisOptions must produce identical, stable findings -
// adding new fields here without folding them into that hash is a deterministic-output regression.
function normalizeOptions(paths: string[], rawOptions: Record<string, unknown>, context: NormalizeContext): AnalysisOptions {
  const format = stringChoice(rawOptions.format, ["text", "json", "html", "markdown", "github", "hotspot", "sarif"], "text");
  const failOn = stringChoice(rawOptions.failOn, ["none", "advisory", "warning", "error"], "advisory");
  const diffInput = diffOption(paths, rawOptions);
  const baselineValue = rawOptions.baseline;
  const shouldSkipBaseline =
    !context.shouldAllowBaselineFlag ||
    baselineValue === false ||
    rawOptions.noBaseline === true;
  return {
    paths: diffInput.paths,
    ...configOption(rawOptions),
    shouldSkipConfig:
      rawOptions.config === false ||
      rawOptions.noConfig === true,
    format,
    failOn,
    shouldIncludeIgnored: rawOptions.includeIgnored === true,
    changedScope: stringChoice(rawOptions.changedScope, ["symbol", "hunk"], "symbol"),
    ...diffInput.options,
    ...changedRangesOption(rawOptions),
    ...sinceOption(rawOptions),
    ...historyFileOption(rawOptions),
    ...baselineOption(baselineValue, context),
    ...generateBaselineOption(rawOptions),
    shouldSkipBaseline,
  };
}

// Conditional spreads (not `config: undefined`) because `AnalysisOptions` runs under
// `exactOptionalPropertyTypes` - the absent and `undefined` cases are not interchangeable.
function configOption(rawOptions: Record<string, unknown>): Partial<Pick<AnalysisOptions, "config">> {
  return typeof rawOptions.config === "string" ? { config: rawOptions.config } : {};
}

// `--diff` without an argument means "working-tree". `--diff -` is accepted even when Commander
// treats `-` as a positional path, so stdin-diff callers can use the documented spacing form.
function diffOption(paths: string[], rawOptions: Record<string, unknown>): { paths: string[]; options: Partial<Pick<AnalysisOptions, "diff" | "diffPatch">> } {
  if (typeof rawOptions.diff === "string") {
    return rawOptions.diff === "-"
      ? { paths, options: { diff: "-", diffPatch: readFileSync(0, "utf8") } }
      : { paths, options: { diff: rawOptions.diff } };
  }
  if (rawOptions.diff === true && paths[0] === "-") {
    return { paths: paths.slice(1), options: { diff: "-", diffPatch: readFileSync(0, "utf8") } };
  }
  return rawOptions.diff === true ? { paths, options: { diff: "working-tree" } } : { paths, options: {} };
}

// Preserves absence for `changedRanges`; setting it to undefined would change exact optional typing.
function changedRangesOption(rawOptions: Record<string, unknown>): Partial<Pick<AnalysisOptions, "changedRanges">> {
  return typeof rawOptions.changedRanges === "string" ? { changedRanges: rawOptions.changedRanges } : {};
}

// Preserves absence for `since` so direct callers can distinguish no ref from an explicit ref.
function sinceOption(rawOptions: Record<string, unknown>): Partial<Pick<AnalysisOptions, "since">> {
  return typeof rawOptions.since === "string" ? { since: rawOptions.since } : {};
}

// Conditional spread keeps `historyFile` absent rather than `undefined` under exactOptionalPropertyTypes.
function historyFileOption(rawOptions: Record<string, unknown>): Partial<Pick<AnalysisOptions, "historyFile">> {
  return typeof rawOptions.historyFile === "string" ? { historyFile: rawOptions.historyFile } : {};
}

// `--baseline` with no value implies the conventional default file (`gruff-baseline.json`); commands
// that disallow baseline input (e.g., `report`) short-circuit so the option is never set. The fingerprint
// contract requires that two scans with the same baseline file produce identical suppression behaviour.
function baselineOption(baselineValue: unknown, context: NormalizeContext): Partial<Pick<AnalysisOptions, "baseline">> {
  if (!context.shouldAllowBaselineFlag) {
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

/*
 * Precedence wiring for `--fail-on`: when the user did NOT pass `--fail-on` explicitly, the
 * `.gruff-ts.yaml` `minimumSeverity.<cmd>` value wins over the binary default. CLI flag always
 * wins when explicitly set. Commander's `getOptionValueSource("failOn")` returns `"cli"` for
 * explicit invocations and `"default"` otherwise, so the source check drives the precedence
 * chain. Throws `ConfigLoadError` on malformed config; CLI action handlers catch and format that
 * cleanly via `runWithConfigErrorHandling`.
 */
function applyMinimumSeverityPrecedence(options: AnalysisOptions, command: MinimumSeverityCommand, commanderCommand: Command): AnalysisOptions {
  if (commanderCommand.getOptionValueSource("failOn") === "cli") {
    return options;
  }
  const config = loadConfig(cwd(), options);
  const configuredFailOn = minimumSeverityFor(config, command);
  return configuredFailOn === undefined ? options : { ...options, failOn: configuredFailOn };
}

/*
 * Wraps an async command action so a malformed `.gruff-ts.yaml` surfaces as a clean stderr message
 * and exit code 2, not a raw Node stack trace. Catches `ConfigLoadError` (user-actionable config
 * bug) and reports it via formatted stderr; rethrows every other exception so an analyser/code
 * bug still surfaces its stack for debugging. The exit code matches the existing diagnostic
 * convention in `exitFor` so CI scripts that already handle exit 2 keep working.
 */
async function runWithConfigErrorHandling(action: () => Promise<void> | void): Promise<void> {
  try {
    await action();
  } catch (error) {
    if (error instanceof ConfigLoadError) {
      process.stderr.write(`gruff-ts: config error\n  ${error.message}\n\nSuggested fix:\n  ${error.suggestion}\n`);
      process.exitCode = 2;
      return;
    }
    throw error;
  }
}
