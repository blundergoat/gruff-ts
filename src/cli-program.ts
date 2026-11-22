// Connects the user's command and flags to analysis, output, and exit status.
//
// Use analyse for individual findings, summary for overall patterns, and report for an artifact to share.
// Machine-readable output carries the same run status that automation receives from the process.
import { Command, Help, InvalidArgumentError } from "commander";
import { readFileSync, writeFileSync } from "node:fs";
import { extname, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { cwd } from "node:process";
import { CONFIG_ERROR_DIAGNOSTIC_TYPE, failedRunReport, projectRootFromTargets, TARGET_ERROR_DIAGNOSTIC_TYPE, targetOutsideLaunchDirectory } from "./analyser.ts";
import { DEFAULT_BASELINE } from "./baseline.ts";
import { checkIgnore, checkIgnoreExitCode, renderCheckIgnore, type CheckIgnoreFormat } from "./check-ignore.ts";
import { CHANGED_REGION_DIAGNOSTIC_TYPE, ChangedRegionError } from "./changed-regions.ts";
import { ConfigLoadError } from "./config-load-error.ts";
import { loadConfig, minimumSeverityFor } from "./config.ts";
import { VERSION } from "./constants.ts";
import { startDashboard } from "./dashboard.ts";
import { hookExitCode, renderHookCapabilities, renderHookConfigError, renderHookFatal, renderHookReport, type HookExitGate } from "./hook-contract.ts";
import { promptYesNo, shouldPromptForInit, writeDefaultConfig } from "./init-config.ts";
import { migrateConfigText } from "./migrate-config.ts";
import { renderReport, renderSummary, renderSummaryJson } from "./report-renderers.ts";
import { completionShell, getRuleDescriptor, renderCompletionScript, renderConsoleList, renderProfileList, renderRuleDetail, renderRuleList, type RuleListFormat } from "./rule-list.ts";
import { exitFor, summarize } from "./scoring.ts";
import { applyDisplaySelectors, type DisplaySelectors } from "./selectors.ts";
import type { AnalysisOptions, AnalysisReport, Confidence, DeepScanBudgetOverride, ExecutionSelectors, MinimumSeverityCommand, Severity } from "./types.ts";

type HookAnalysisViews = { currentReport: AnalysisReport; scopedReport: AnalysisReport };
type AnalyseRunner = ((options: AnalysisOptions) => AnalysisReport) & {
  hookViews?: (currentOptions: AnalysisOptions, scopedOptions: AnalysisOptions, hasChangedRegion: boolean) => HookAnalysisViews;
};

// The `report` command intentionally rejects `--baseline` because its output is meant to reflect
// raw findings; this flag lets `normalizeOptions` enforce that without per-command branching.
interface NormalizeContext {
  shouldAllowBaselineFlag: boolean;
}

/*
 * What a command reports when the user's invocation could not be understood: an unknown flag, a stray operand, a
 * value outside a documented set. Distinct from 1, which means the scan ran and something reached the gate.
 */
const USAGE_EXIT_CODE = 2;

// Help for the flag every port accepts and no port implements, so `--help` says so rather than implying it works.
const SCAN_TIMEOUT_DESCRIPTION = "Parsed and accepted for cross-port compatibility; gruff-ts enforces no scan deadline on analyse.";

// Shared `--profile` flag help for analyse/report/summary/dashboard. The value is a built-in profile
// name or a profile file path; it overrides any config-file `profile:` block (CLI wins, per ADR-010).
const PROFILE_OPTION_DESCRIPTION = "Apply a built-in profile (gruff.minimal, gruff.recommended, gruff.strict) or a profile file path. Overrides a config-file profile:.";

// Writes output to stdout unless program's silent or quiet flags suppress it; ensures a trailing newline and returns nothing.
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

// Offer to create a missing default config at projectRoot when program's output and interaction flags, options' config flags and TTYs permit.
// Resolves without a value. On acceptance, attempts a filesystem write with overwrite disabled and reports a newly written file on stderr.
// Call before analysis so loadConfig can use the new file during the same invocation.
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

// Return init-prompt settings from options, preserving config opt-out and marking a string config path as an explicit selection.
function promptOptionsFromAnalysis(options: AnalysisOptions): InitPromptOptions {
  return { shouldSkipConfig: options.shouldSkipConfig, hasExplicitConfig: typeof options.config === "string" };
}

// Return whether to use colour: program supplies explicit ANSI flags; otherwise only a TTY stdout enables it.
// Disabling automatic colour for redirected output keeps escape codes out of files and CI logs.
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
// dependency graph; see `.goat-flow/learning-loop/lessons/verification.md` on the original cli.ts ↔ cli-program.ts cycle.
export function buildProgram(runAnalyse: AnalyseRunner): Command {
  const program = new Command();
  configureRootProgram(program);
  registerAnalyseCommand(program, runAnalyse);
  registerCheckIgnoreCommand(program);
  registerCompletionCommand(program);
  registerDashboardCommand(program, runAnalyse);
  registerHookCommand(program, runAnalyse);
  registerInitCommand(program);
  registerMigrateConfigCommand(program);
  registerListCommand(program);
  registerListProfilesCommand(program);
  registerListRulesCommand(program);
  registerReportCommand(program, runAnalyse);
  registerSummaryCommand(program, runAnalyse);
  return program;
}

// Configures program with global flags and shows the command catalogue for bare invocations and root help. Returns nothing.
// The exit override preserves successful help and version exits and maps nonzero Commander exit codes to status 2.
function configureRootProgram(program: Command): void {
  program
    .name("gruff-ts")
    .usage("command [options] [arguments]")
    .helpOption("-h, --help", "Display help for the given command. When no command is given display help for the list command")
    .version(`gruff-ts ${VERSION}`, "-V, --version", "Display this application version")
    .option("--silent", "Do not output any message")
    .option("-q, --quiet", "Only errors are displayed. All other output is suppressed")
    .option("--ansi", "Force ANSI output")
    .option("--no-ansi", "Disable ANSI output")
    .option("-n, --no-interaction", "Do not ask any interactive question")
    .option("-v, --verbose", "Increase the verbosity of messages: 1 for normal output, 2 for more verbose output and 3 for debug", (_value, previous: number) => previous + 1, 0)
    .addHelpCommand("help [command]", "Display help for a command")
    .showHelpAfterError()
    // Set before the subcommands are registered, because each one copies the root's exit behaviour as it is built.
    .exitOverride((error) => {
      // Help and version are successful output, so they keep the zero commander already chose for them.
      process.exit(error.exitCode === 0 ? 0 : USAGE_EXIT_CODE);
    })
    .configureHelp({

      // Return help for command using helper's layout settings and the captured root program.
      // Root help lists the command catalogue; subcommands use Commander's formatter with global options visible.
      formatHelp(command, helper) {
        return rootHelpText(program, command, helper);
      },
    })
    .action(() => {
      writeCommandOutput(program, renderConsoleList(ansiEnabled(program)));
    });
}

// Returns the catalogue for root help, or Commander's subcommand help with global options.
// program identifies the root and supplies ANSI settings; command is the help target; helper supplies optional wrap widths.
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

/**
 * Register the CLI command that upgrades a 0.5 configuration to the current schema.
 *
 * @param program - parent CLI command that receives the migration subcommand
 * @returns Nothing. Adds the subcommand, its input, output and dry-run options, and the migration action to the program.
 */
function registerMigrateConfigCommand(program: Command): void {
  program
    .command("migrate-config")
    .description("Rewrite a 0.5 config for the current schema, writing the result to a different file.")
    .requiredOption("--config <path>", "The 0.5 config to read. It is never modified.")
    .option("--output <path>", "New file for the migrated config. Required unless --dry-run.")
    .option("--dry-run", "Print what would change and write nothing.")
    .action((rawOptions: Record<string, unknown>) => runWithConfigErrorHandling(() => runMigrateConfig(program, rawOptions)));
}

/*
 * Previews or writes the migrated config requested by `migrate-config`.
 *
 * Side effects: writes one new file when the user supplies --output.
 * @throws {ConfigLoadError} when the input, format, or destination prevents migration.
 */
function runMigrateConfig(program: Command, rawOptions: Record<string, unknown>): void {
  const inputPath = resolve(String(rawOptions.config));
  const inputFormat = migrationConfigFormat(inputPath);
  let source: string;
  try {
    source = readFileSync(inputPath, "utf8");
  } catch (error) {
    // A user may pass `--config old.yaml` from a directory that has no such file.
    throw new ConfigLoadError(`Cannot read migration input ${inputPath}: ${(error as NodeJS.ErrnoException).code ?? "read failed"}.`, "Pass a readable config file to --config.");
  }
  const migration = migrateConfigText(source, inputFormat);
  // An empty change list tells the user their configuration settings are already current.
  const summary = migration.changes.length === 0
    ? `${inputPath} is already current; no changes.`
    : ["Migration changes:", ...migration.changes.map((change) => `  - line ${change.line}: ${change.description}`)].join("\n");

  // A dry run shows what to expect before the user chooses a destination.
  if (rawOptions.dryRun === true) {
    writeCommandOutput(program, summary);
    writeCommandOutput(program, `Dry run: nothing written.`);
    return;
  }

  const outputPath = typeof rawOptions.output === "string" ? resolve(rawOptions.output) : "";

  // With no destination, show how to supply a path or preview the changes.
  if (outputPath.length === 0) {
    process.stderr.write("gruff-ts: migrate-config needs --output <path>, or --dry-run to print the changes.\n");
    process.exitCode = USAGE_EXIT_CODE;
    return;
  }
  // A user upgrading old.yaml needs a YAML destination so its existing syntax still loads.
  if (migrationConfigFormat(outputPath) !== inputFormat) {
    throw new ConfigLoadError("The migration output must use the input config's format.", "Choose a new output path with a matching YAML or JSON extension.");
  }
  try {
    // Exclusive creation refuses every existing directory entry, including aliases of the input.
    writeFileSync(outputPath, migration.text, { flag: "wx" });
  } catch (error) {
    // For example, a user may select the same destination twice or choose a read-only directory.
    throw new ConfigLoadError(`Cannot create migration output ${outputPath}: ${(error as NodeJS.ErrnoException).code ?? "write failed"}.`, "Choose a new output file in a writable directory.");
  }
  writeCommandOutput(program, summary);
  writeCommandOutput(program, `Wrote ${outputPath}.`);
}

// Selects the migration encoding from a supported config extension.
// @throws {ConfigLoadError} for an unsupported extension.
function migrationConfigFormat(path: string): "yaml" | "json" {
  const extension = extname(path).toLowerCase();
  // Both common YAML suffixes are valid when the user names a source or destination.
  if (extension === ".yaml" || extension === ".yml") {
    return "yaml";
  }
  // A project with a JSON config can review the migration in the same format.
  if (extension === ".json") {
    return "json";
  }
  throw new ConfigLoadError(`Unsupported migration config extension: ${extension || "(none)"}.`, "Use a .yaml, .yml, or .json config file.");
}

// Registers analyse for users who want individual findings in the terminal or a machine-readable report.
//
// The default gate fails on advisory or higher. Users can set `--fail-on=error` or configure `failOn.analyse`.
function registerAnalyseCommand(program: Command, runAnalyse: AnalyseRunner): void {
  program
    .command("analyse")
    .description("Run gruff analysis.")
    .argument("[paths...]", "Files or directories to analyse.")
    .option("--config <path>", "Path to a gruff YAML config file.")
    .option("--no-config", "Skip auto-applying the default .gruff-ts.yaml file for this run.")
    .option("--profile <spec>", PROFILE_OPTION_DESCRIPTION)
    .option("--deep-scan-budget <lines:bytes|off>", "Override both deep-scan bounds as LINES:BYTES, or disable the budget with off.", parseDeepScanBudget)
    .option("--format <format>", "Output format: text, json, html, markdown, github, hotspot, or sarif.", parseAnalyseFormat, "text")
    .option("--fail-on <severity>", "Finding severity that fails the run: advisory, warning, error, or none.", parseFailOn, "advisory")
    .option("--min-confidence <confidence>", "Lowest analyser confidence that may fail the run: low, medium, or high. Filters nothing.", parseConfidence, "low")
    .option("--min-severity <severity>", "Hide findings below this severity from the report. The score and the exit code are unchanged.", parseMinSeverity)
    .option("--include-rule <ids>", "Run only these rules, so the score reflects them alone. Repeatable, or comma-separated.", collectSelectorList, [])
    .option("--exclude-rule <ids>", "Do not run these rules, so they cannot affect the score. Repeatable, or comma-separated.", collectSelectorList, [])
    .option("--include-pillar <names>", "Run only these pillars, so the score reflects them alone. Repeatable, or comma-separated.", collectSelectorList, [])
    .option("--exclude-pillar <names>", "Do not run these pillars, so they cannot affect the score. Repeatable, or comma-separated.", collectSelectorList, [])
    .option("--show-rule <ids>", "Show only these rules in the report. Every rule still runs and still scores. Repeatable, or comma-separated.", collectSelectorList, [])
    .option("--hide-rule <ids>", "Hide these rules from the report. They still run and still score. Repeatable, or comma-separated.", collectSelectorList, [])
    .option("--show-pillar <names>", "Show only these pillars in the report. Every pillar still runs and still scores. Repeatable, or comma-separated.", collectSelectorList, [])
    .option("--hide-pillar <names>", "Hide these pillars from the report. They still run and still score. Repeatable, or comma-separated.", collectSelectorList, [])
    .option("--scan-timeout <duration>", SCAN_TIMEOUT_DESCRIPTION)
    .option("--include-ignored", "Include files under default and Git ignored paths; config ignores still apply.")
    .option("--changed-ranges <ranges>", "Filter findings to changed regions, for example 3-3,8-10.")
    .option("--since <ref>", "Filter findings to regions changed against a git base ref.")
    .option("--diff [mode]", "Filter findings to changed regions. Use working-tree, staged, unstaged, a base ref, or - for unified diff on stdin.")
    .option("--diff-base <ref>", "The ref a diff is taken against. Equivalent to passing the ref to --diff, and it wins when both are given.")
    .option("--changed-scope <scope>", "Changed-region scope: hunk, symbol, or file.", parseChangedScope, "symbol")
    .option("--history-file <path>", "Append score trend history to this JSON file (full scans only; incompatible with --diff, --since, and --changed-ranges).")
    .option("--baseline [path]", "Suppress findings that match a gruff baseline JSON file.")
    .option("--generate-baseline [path]", "Write current findings to a gruff baseline JSON file.")
    .option("--migrate-baseline <path>", "Carry a 0.5 baseline's reviews into --generate-baseline; the original file is left untouched.")
    .option("--force", "Overwrite a 0.5 baseline at the default path; without it a generate that would destroy the retreat path is refused.")
    .option("--no-baseline", "Skip auto-applying the default baseline file for this run.")
    .option("--fail-on-new", "Exit 1 when the applied baseline leaves any finding the user has not reviewed, whatever its severity.")
    .action(async (paths: string[], rawOptions: Record<string, unknown>, command: Command) => {
      const outsideTarget = targetOutsideLaunchDirectory(paths);
      // A multi-target run with any outside target exits 2 before scanning. JSON and SARIF callers get a refusal envelope when stdout is enabled.
      if (outsideTarget !== null) {
        refuseTargetsOutsideLaunchDirectory(program, rawOptions.format, outsideTarget);
        return;
      }
      await runWithConfigErrorHandling(async () => {
        const baseOptions = normalizeOptions(paths, rawOptions, { shouldAllowBaselineFlag: true });
        const configured = configuredSeverities(baseOptions, "analyse", command);
        const options = configured.options;
        await maybePromptInitConfig(program, projectRootFromTargets(options.paths), promptOptionsFromAnalysis(options));
        const report = runAnalyse(options);
        const findingExit = exitFor(report, options.failOn, confidenceFloor(rawOptions));
        // A failed scan keeps exit 2. A successful scan can still fail either the severity gate or the new-finding gate.
        const status = findingExit === 2 ? findingExit : Math.max(findingExit, newDebtExitCode(report, rawOptions));
        process.exitCode = status;
        writeChangedRegionFailure(report, options.format);
        // A user can narrow the visible findings while CI keeps the exit status calculated from the full evaluated set.
        filterReportForDisplay(report, rawOptions, configured.displayFloor);
        writeCommandOutput(program, renderReport(report, options.format, status));
      }, (error) => writeFailedRunEnvelope(program, rawOptions.format, error));
    });
}

// Returns nothing. Registers check-ignore on program to classify paths with analyse's ignore rules.
// When output is enabled, JSON reports every path and text lists only ignored paths with their match details.
// The action sets process.exitCode to 0 if any path is ignored, 1 if none are ignored or 2 on config errors.
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

// Registers hook for coding agents to review an edit and apply a project gate using the findings in the JSON response.
//
// Invariant: a refused input or missing required baseline produces an envelope and exit 2.
// Config failures include a suggested next step inside the response.
// @throws from the registered action when the caught failure is not an Error.
function registerHookCommand(program: Command, runAnalyse: AnalyseRunner): void {
  program
    .command("hook")
    .description("Run the gruff agent-hook contract and emit gruff.hook.v2 JSON.")
    .argument("[paths...]", "Files or directories to analyse.")
    .option("--format <format>", "Output format: json.", parseHookFormat, "json")
    .option("--capabilities", "Print gruff.hook.v2 capability metadata and exit.")
    .option("--fail-on <severity>", "Finding severity that blocks the edit: advisory, warning, error, or none. The hook default of none keeps findings advisory.", parseFailOn, "none")
    .option("--min-confidence <confidence>", "Lowest analyser confidence that may block the edit: low, medium, or high.", parseConfidence, "low")
    .option("--fail-on-new", "Block the edit when a finding the applied baseline calls new is published.")
    .option("--config <path>", "Path to a gruff YAML config file.")
    .option("--no-config", "Skip auto-applying the default .gruff-ts.yaml file for this run.")
    .option("--profile <spec>", PROFILE_OPTION_DESCRIPTION)
    .option("--deep-scan-budget <lines:bytes|off>", "Override both deep-scan bounds as LINES:BYTES, or disable the budget with off.", parseDeepScanBudget)
    .option("--include-ignored", "Include files under default and Git ignored paths; config ignores still apply.")
    .option("--changed-ranges <ranges>", "Filter hook findings to changed regions, for example 3-3,8-10.")
    .option("--since <ref>", "Filter hook findings to regions changed against a git base ref and compare against that ref.")
    .option("--diff [mode]", "Filter hook findings to changed regions. Use working-tree, staged, unstaged, a base ref, or - for unified diff on stdin.")
    .option("--baseline <path>", "Compare hook findings against a gruff baseline JSON file using stableIdentity.")
    .option("--fail-on-diagnostics", "Exit 1 when parse/read diagnostics affect the analysed change; the default reports them in-band with exit 0.")
    .action((paths: string[], rawOptions: Record<string, unknown>) => {
      // An integration can discover supported options before sending any files to scan.
      if (rawOptions.capabilities === true) {
        writeCommandOutput(program, renderHookCapabilities());
        process.exitCode = 0;
        return;
      }
      try {
        const scopedOptions = hookScopedOptions(paths, rawOptions);
        const outsideTarget = targetOutsideLaunchDirectory(scopedOptions.paths);
        // A request naming several files must be launched from a directory containing them all.
        if (outsideTarget !== null) {
          writeCommandOutput(program, renderHookFatal(TARGET_ERROR_DIAGNOSTIC_TYPE, outsideTargetMessage(outsideTarget)));
          process.exitCode = USAGE_EXIT_CODE;
          return;
        }
        const baseline = hookBaselinePath(rawOptions);
        // A user needs to choose a review file before the hook can gate on findings they have yet to review.
        if (rawOptions.failOnNew === true && baseline.baselinePath === undefined) {
          writeCommandOutput(program, renderHookFatal("baseline-error", "--fail-on-new requires --baseline <path>."));
          process.exitCode = USAGE_EXIT_CODE;
          return;
        }
        const currentOptions = hookCurrentOptions(scopedOptions);
        const rendered = renderHookReport(runAnalyse, {
          currentOptions,
          scopedOptions,
          ...baseline,
          ...hookDiffBase(scopedOptions),
          hasChangedRegion: hasHookChangedRegion(scopedOptions),
        });
        writeCommandOutput(program, rendered);
        // Read findings and diagnostics from the rendered payload so the gate uses the same results as the report.
        process.exitCode = hookExitCode(rendered, hookGateFrom(rawOptions));
      } catch (error) {
        // A project may still use an older config schema. Give the integration the loader's instructions.
        if (error instanceof ConfigLoadError) {
          writeCommandOutput(program, renderHookConfigError(error.message, error.suggestion));
          process.exitCode = USAGE_EXIT_CODE;
          return;
        }
        // A missing review file, for example, is a fatal diagnostic in the hook's standard response.
        if (error instanceof Error) {
          // Render a fatal diagnostic under the gruff.hook.v2 schema so consumers can read the failure when stdout is enabled.
          writeCommandOutput(program, renderHookFatal(hookFatalType(error, rawOptions), error.message));
          process.stderr.write(`gruff-ts: ${error.message}\n`);
          process.exitCode = USAGE_EXIT_CODE;
          return;
        }
        throw error;
      }
    });
}

// Build AnalysisOptions for checking paths against ignore rules, using rawOptions to select or skip config.
// Config selection matches analyse. Git and fallback ignore checks stay enabled for eligible paths. Existing explicit files bypass them.
// The ignore-check contract reports paths.ignore matches from loaded config and skips analysis baselines.
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

// Register completion on program; its action emits the selected shell's completion script, defaulting to bash.
// Registration returns nothing. The action writes to stdout when enabled, leaving callers to choose where to save the script.
function registerCompletionCommand(program: Command): void {
  program
    .command("completion")
    .description("Dump the shell completion script")
    .argument("[shell]", "Shell to generate completion for: bash, zsh, or fish.", "bash")
    .action((shell: string) => {
      writeCommandOutput(program, renderCompletionScript(completionShell(shell)));
    });
}

// Register dashboard on program, passing runAnalyse to the server for requested scans.
// Default to 127.0.0.1:8767 because the unauthenticated dashboard accepts a caller-selected projectRoot.
// The action may write config after an interactive prompt before it starts serving. Registration returns nothing.
function registerDashboardCommand(program: Command, runAnalyse: AnalyseRunner): void {
  program
    .command("dashboard")
    .description("Serve the local gruff dashboard.")
    .option("--host <host>", "Host to bind.", "127.0.0.1")
    .option("--port <port>", "Port to bind.", "8767")
    .option("--project-root <path>", "Default project root.", ".")
    .option("--profile <spec>", PROFILE_OPTION_DESCRIPTION)
    .option("--deep-scan-budget <lines:bytes|off>", "Override both deep-scan bounds as LINES:BYTES, or disable the budget with off.", parseDeepScanBudget)
    .option("--scan-timeout <seconds>", "Accepted for cross-port compatibility; not implemented in gruff-ts.")
    .action(async (rawOptions: Record<string, unknown>) => {
      const projectRoot = resolve(String(rawOptions.projectRoot ?? "."));
      await maybePromptInitConfig(program, projectRoot, { shouldSkipConfig: false, hasExplicitConfig: false });
      const profile = typeof rawOptions.profile === "string" ? rawOptions.profile : undefined;
      const deepScanBudget = deepScanBudgetOption(rawOptions).deepScanBudget;
      startDashboard(String(rawOptions.host ?? "127.0.0.1"), Number(rawOptions.port ?? 8767), projectRoot, runAnalyse, !outputSuppressed(program), profile, deepScanBudget);
    });
}

// Register init on program and return nothing. Its action writes the default config in the current directory.
// On success the action prints adoption guidance when stdout is enabled.
// Without --force, an existing supported config is preserved and the action writes a refusal to stderr and sets process.exitCode to 1.
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

// Return init's success and adoption guidance, using verb to distinguish creation from overwrite and configPath to name the file.
// The gate command must use the same baseline file the generation command creates.
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

// Register list on program to mirror bare-root help, using the program's ANSI setting.
// Users following Symfony console conventions can request the command catalogue explicitly. Registration returns nothing.
function registerListCommand(program: Command): void {
  program
    .command("list")
    .description("List commands")
    .action(() => {
      writeCommandOutput(program, renderConsoleList(ansiEnabled(program)));
    });
}

// Returns nothing. Registers list-profiles on program to print the built-in profile catalogue as text or JSON when stdout is enabled.
// parseSummaryFormat rejects unsupported formats as usage errors. See footguns/schema-and-cli.md for the format validation contract.
function registerListProfilesCommand(program: Command): void {
  program
    .command("list-profiles")
    .description("List the built-in gruff profiles with their rule-count summary.")
    .option("--format <format>", "Output format: text or json.", parseSummaryFormat, "text")
    .action((rawOptions: Record<string, unknown>) => {
      const format: RuleListFormat = rawOptions.format === "json" ? "json" : "text";
      writeCommandOutput(program, renderProfileList(format));
    });
}

// Registers list-rules on program; without a rule id it prints the catalogue, otherwise one rule's details.
// The action prints text or JSON through program's output flags and reports unknown rules or formats as usage errors. Returns nothing.
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

// Registers report for users who want an HTML or JSON artifact of all findings, including reviewed baseline debt.
//
// Side effects: the action writes to --output or stdout, and can write project config after the user approves initialization.
function registerReportCommand(program: Command, runAnalyse: AnalyseRunner): void {
  program
    .command("report")
    .description("Render a gruff report to stdout or a file.")
    .argument("[paths...]", "Files or directories to analyse.")
    .option("--format <format>", "Report format: html or json.", parseReportFormat, "html")
    .option("--output <path>", "Write report to a file.")
    .option("--config <path>", "Path to a gruff YAML config file.")
    .option("--no-config", "Skip auto-applying the default .gruff-ts.yaml file for this run.")
    .option("--profile <spec>", PROFILE_OPTION_DESCRIPTION)
    .option("--deep-scan-budget <lines:bytes|off>", "Override both deep-scan bounds as LINES:BYTES, or disable the budget with off.", parseDeepScanBudget)
    .option("--fail-on <severity>", "Finding severity that fails the run: advisory, warning, error, or none.", parseFailOn, "none")
    .option("--include-ignored", "Include files under default and Git ignored paths; config ignores still apply.")
    .action(async (paths: string[], rawOptions: Record<string, unknown>, command: Command) => {
      const outsideTarget = targetOutsideLaunchDirectory(paths);
      // Refuse a mixed-project target list before trying to render or write a report.
      if (outsideTarget !== null) {
        refuseTargetsOutsideLaunchDirectory(program, rawOptions.format, outsideTarget);
        return;
      }
      await runWithConfigErrorHandling(async () => {
        const format = rawOptions.format === "json" ? "json" : "html";
        const baseOptions = normalizeOptions(paths, { ...rawOptions, format }, { shouldAllowBaselineFlag: false });
        const { options, displayFloor } = configuredSeverities(baseOptions, "report", command);
        await maybePromptInitConfig(program, projectRootFromTargets(options.paths), promptOptionsFromAnalysis(options));
        const report = runAnalyse(options);
        const status = exitFor(report, options.failOn);
        filterReportForDisplay(report, rawOptions, displayFloor);
        const rendered = renderReport(report, format, status);
        // A user can save report.html for a browser. With no file selected, use stdout.
        if (typeof rawOptions.output === "string") {
          writeFileSync(rawOptions.output, rendered);
        } else {
          writeCommandOutput(program, rendered);
        }
        process.exitCode = status;
      }, (error) => writeFailedRunEnvelope(program, rawOptions.format, error));
    });
}

// Registers summary for users who want pillar counts and top rules or files without opening a per-finding report.
//
// Side effects: the action writes the digest to stdout and can save config, a baseline, or score history when requested.
function registerSummaryCommand(program: Command, runAnalyse: AnalyseRunner): void {
  program
    .command("summary")
    .description(
      "Print a compact digest of a scan: per-pillar finding counts, top rules, and top file offenders. Runs the analyser once and renders only the summary; no per-finding spam.",
    )
    .argument("[paths...]", "Files or directories to analyse.")
    .option("--config <path>", "Path to a gruff YAML config file.")
    .option("--no-config", "Skip auto-applying the default .gruff-ts.yaml file for this run.")
    .option("--profile <spec>", PROFILE_OPTION_DESCRIPTION)
    .option("--deep-scan-budget <lines:bytes|off>", "Override both deep-scan bounds as LINES:BYTES, or disable the budget with off.", parseDeepScanBudget)
    .option("--format <format>", "Output format: text or json.", parseSummaryFormat, "text")
    .option("--top <n>", "How many top rules and file offenders to list.", parseNonNegativeInteger, 10)
    // The default gate lets findings pass unless config supplies a threshold. Run-invalidating diagnostics still give exit code 2.
    .option("--fail-on <severity>", "Finding severity that fails the run: advisory, warning, error, or none.", parseFailOn, "none")
    .option("--include-ignored", "Include files under default and Git ignored paths; config ignores still apply.")
    .option("--diff [mode]", "Filter findings to changed files. Use working-tree, staged, unstaged, or a base ref.")
    .option("--history-file <path>", "Append score trend history to this JSON file (full scans only; incompatible with --diff).")
    .option("--baseline [path]", "Suppress findings that match a gruff baseline JSON file.")
    .option("--generate-baseline [path]", "Write current findings to a gruff baseline JSON file.")
    .option("--migrate-baseline <path>", "Carry a 0.5 baseline's reviews into --generate-baseline; the original file is left untouched.")
    .option("--force", "Overwrite a 0.5 baseline at the default path; without it a generate that would destroy the retreat path is refused.")
    .option("--no-baseline", "Skip auto-applying the default baseline file for this run.")
    .action(async (paths: string[], rawOptions: Record<string, unknown>, command: Command) => {
      const outsideTarget = targetOutsideLaunchDirectory(paths);
      // Use one launch directory to keep paths and totals comparable within the digest.
      if (outsideTarget !== null) {
        refuseTargetsOutsideLaunchDirectory(program, rawOptions.format, outsideTarget);
        return;
      }
      await runWithConfigErrorHandling(async () => {
        const summaryFormat = rawOptions.format === "json" ? "json" : "text";
        const baseOptions = normalizeOptions(paths, { ...rawOptions, format: summaryFormat }, { shouldAllowBaselineFlag: true });
        const { options, displayFloor } = configuredSeverities(baseOptions, "summary", command);
        const top = typeof rawOptions.top === "number" ? rawOptions.top : 10;
        await maybePromptInitConfig(program, projectRootFromTargets(options.paths), promptOptionsFromAnalysis(options));
        const startedAt = performance.now();
        const report = runAnalyse(options);
        const elapsedMs = performance.now() - startedAt;
        const pathLabel = summaryPathLabel(options.paths, report.run.projectRoot);
        const status = exitFor(report, options.failOn);
        // Keep the decision from the full scan when the user hides lower-severity entries from the digest.
        filterReportForDisplay(report, rawOptions, displayFloor);
        const rendered = summaryFormat === "json"
          ? renderSummaryJson(report, status)
          : renderSummary(report, elapsedMs, pathLabel, top);
        writeCommandOutput(program, rendered);
        process.exitCode = status;
      }, (error) => writeFailedRunEnvelope(program, rawOptions.format, error));
    });
}

/**
 * Validate the requested output encoding before Commander runs the command.
 *
 * @param rawFormat - format value supplied on the command line
 * @returns the accepted encoding, text or json
 * @throws {InvalidArgumentError} - when the format is neither text nor json, so Commander reports a usage error
 */
function parseSummaryFormat(rawFormat: string): "text" | "json" {
  if (rawFormat === "text" || rawFormat === "json") {
    return rawFormat;
  }
  throw new InvalidArgumentError("must be text or json");
}

// Validate rawFormat for the hook's JSON-only output contract and return json when accepted.
// @throws {InvalidArgumentError} when rawFormat is anything other than json.
function parseHookFormat(rawFormat: string): "json" {
  if (rawFormat === "json") {
    return rawFormat;
  }
  throw new InvalidArgumentError("must be json");
}

/**
 * Build a Commander argument parser that rejects unsupported values before analysis because a silent fallback could change a CI gate.
 *
 * @param choices - allowed CLI values. An empty list makes the parser reject every value.
 * @returns a parser that returns an allowed input unchanged
 * @throws {InvalidArgumentError} - the returned parser throws for values outside choices
 */
function parseChoiceOf(choices: readonly string[]): (rawValue: string) => string {
  return (rawValue: string): string => {
    if (choices.includes(rawValue)) {
      return rawValue;
    }
    throw new InvalidArgumentError(`must be one of: ${choices.join(", ")}`);
  };
}

const parseAnalyseFormat = parseChoiceOf(["text", "json", "html", "markdown", "github", "hotspot", "sarif"]);
const parseReportFormat = parseChoiceOf(["html", "json"]);
const parseFailOn = parseChoiceOf(["none", "advisory", "warning", "error"]);
const parseChangedScope = parseChoiceOf(["symbol", "hunk", "file"]);
const parseConfidence = parseChoiceOf(["low", "medium", "high"]);
const parseMinSeverity = parseChoiceOf(["advisory", "warning", "error"]);

/**
 * Accumulate selectors across repeated CLI flags without changing the earlier list.
 *
 * @param rawValue - comma-separated selectors from the next flag value. Blank entries add nothing.
 * @param previous - selectors already collected, carried forward unchanged
 * @returns a new list with the trimmed nonempty entries appended to the earlier selectors
 */
function collectSelectorList(rawValue: string, previous: string[]): string[] {
  return [...previous, ...rawValue.split(",").map((entry) => entry.trim()).filter((entry) => entry.length > 0)];
}

// Build execution selectors from rawOptions; they determine which rules run and which findings contribute to scores.
// Keep only string entries from selector arrays; absent or non-array selectors become empty lists.
function executionSelectorsFrom(rawOptions: Record<string, unknown>): ExecutionSelectors {
  return {
    includeRules: selectorList(rawOptions.includeRule),
    excludeRules: selectorList(rawOptions.excludeRule),
    includePillars: selectorList(rawOptions.includePillar),
    excludePillars: selectorList(rawOptions.excludePillar),
  };
}

// Build report-only selectors from rawOptions; these settings affect visibility without changing execution, scores, or exit status.
// Keep only string list entries; absent or non-array selectors become empty lists and invalid minSeverity is omitted.
function displaySelectorsFrom(rawOptions: Record<string, unknown>): DisplaySelectors {
  const minSeverity = rawOptions.minSeverity;
  return {
    ...(minSeverity === "advisory" || minSeverity === "warning" || minSeverity === "error" ? { minSeverity } : {}),
    showRules: selectorList(rawOptions.showRule),
    hideRules: selectorList(rawOptions.hideRule),
    showPillars: selectorList(rawOptions.showPillar),
    hidePillars: selectorList(rawOptions.hidePillar),
  };
}

// Projects display findings and counts. The already computed exit status and score must stay stable across display filters.
function filterReportForDisplay(report: AnalysisReport, rawOptions: Record<string, unknown>, displayFloor: Severity | undefined): void {
  report.findings = applyDisplaySelectors(report.findings, displaySelectorsFrom(rawOptions), displayFloor);
  report.summary = summarize(report.findings);
}

// Returns string entries from rawValue, a collected selector flag; a non-array or an array without strings means no selectors.
function selectorList(rawValue: unknown): string[] {
  return Array.isArray(rawValue) ? rawValue.filter((entry): entry is string => typeof entry === "string") : [];
}

// Reads the confidence floor the gate applies; an unset flag admits every finding, which is the documented default.
function confidenceFloor(rawOptions: Record<string, unknown>): Confidence {
  const configured = rawOptions.minConfidence;
  return configured === "medium" || configured === "high" ? configured : "low";
}

// Returns the blocking policy from the parsed CLI options. The confidence floor defaults to low.
// The hook applies it after handling payload output, including when output is suppressed.
function hookGateFrom(rawOptions: Record<string, unknown>): HookExitGate {
  const failOn = rawOptions.failOn;
  return {
    // An unset severity threshold disables severity gating. The other blocking flags apply independently.
    failOn: failOn === "advisory" || failOn === "warning" || failOn === "error" ? failOn : "none",
    minConfidence: confidenceFloor(rawOptions),
    shouldFailOnNew: rawOptions.failOnNew === true,
    shouldFailOnDiagnostics: rawOptions.failOnDiagnostics === true,
  };
}

// Writes one gruff-ts: <message> line per changed-region diagnostic from report to stderr.
// The format argument limits these writes to text. The report carries the same diagnostic for machine readers.
// Returns nothing. The stderr line is the stable text-mode contract for reporting the unreadable scope.
function writeChangedRegionFailure(report: AnalysisReport, format: AnalysisOptions["format"]): void {
  if (format !== "text") {
    return;
  }
  for (const diagnostic of report.diagnostics) {
    if (diagnostic.diagnosticType === CHANGED_REGION_DIAGNOSTIC_TYPE) {
      process.stderr.write(`gruff-ts: ${diagnostic.message}\n`);
    }
  }
}

// Returns the changed-region diagnostic type for a ChangedRegionError under the hook's stable diagnostic contract.
// For other errors, returns baseline if the parsed options carry a baseline path string, or run otherwise. Message wording has no effect.
function hookFatalType(error: Error, rawOptions: Record<string, unknown>): string {
  if (error instanceof ChangedRegionError) {
    return CHANGED_REGION_DIAGNOSTIC_TYPE;
  }
  return typeof rawOptions.baseline === "string" ? "baseline" : "run";
}

// Parse rawBudget into an enabled override with line and byte limits, or a disabled override for off.
// Keeping both numeric limits in one value prevents a half-updated budget for the current invocation.
// @throws {InvalidArgumentError} when the value is not off and not LINES:BYTES with two positive safe integers.
function parseDeepScanBudget(rawBudget: string): DeepScanBudgetOverride {
  if (rawBudget === "off") {
    return { enabled: false };
  }
  const match = rawBudget.match(/^(\d+):(\d+)$/);
  const maxLines = match ? Number(match[1]) : Number.NaN;
  const maxBytes = match ? Number(match[2]) : Number.NaN;
  if (!Number.isSafeInteger(maxLines) || maxLines <= 0 || !Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
    throw new InvalidArgumentError("must be two positive integers as LINES:BYTES, or off");
  }
  return { enabled: true, maxLines, maxBytes };
}

/**
 * Validate a CLI count before the command runs, using Number conversion.
 *
 * @param rawCount - count supplied as a CLI value. Empty or whitespace-only input means zero.
 * @returns the converted non-negative integer
 * @throws {InvalidArgumentError} - when conversion produces a noninteger or negative value, so Commander reports a usage error
 */
function parseNonNegativeInteger(rawCount: string): number {
  const parsed = Number(rawCount);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new InvalidArgumentError("must be a non-negative integer");
  }
  return parsed;
}

// Returns a summary label by resolving paths against the current directory and joining them; an empty paths list returns projectRoot.
function summaryPathLabel(paths: string[], projectRoot: string): string {
  if (paths.length === 0) {
    return projectRoot;
  }
  return paths.map((path) => resolve(path)).join(", ");
}

/**
 * Converts a parsed CLI request into analysis options and enforces the baseline option contract for the command.
 * Reads the patch from stdin when selected so that analysis receives the patch text with its options.
 *
 * @param paths - positional scan targets, including the stdin marker for --diff. No targets defaults to the project.
 * @param rawOptions - parsed Commander flags used to select analysis settings and defaults
 * @param context - command policy that controls whether baseline input is allowed
 * @returns Normalized analysis options, including the resolved scan targets and diff, history and baseline settings.
 * @throws {ConfigLoadError} for incompatible history or baseline flags, or an invalid deep-scan budget override.
 */
function normalizeOptions(paths: string[], rawOptions: Record<string, unknown>, context: NormalizeContext): AnalysisOptions {
  assertFullScanHistoryOptions(rawOptions);
  const generation = generateBaselineOption(rawOptions);
  // The source tells migration which reviews to keep. The generation flag tells it where to put them.
  if (typeof rawOptions.migrateBaseline === "string" && !generation.generateBaseline) {
    throw new ConfigLoadError("--migrate-baseline requires --generate-baseline.", "Pass --generate-baseline <output path>.", false);
  }
  // A generation starts a review. A new-debt gate needs a review that already exists.
  if (rawOptions.failOnNew === true && generation.generateBaseline) {
    throw new ConfigLoadError("--fail-on-new requires an applied baseline.", "Generate the baseline first, then run with --baseline <path>.", false);
  }
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
    ...profileOption(rawOptions),
    ...deepScanBudgetOption(rawOptions),
    shouldSkipConfig:
      rawOptions.config === false ||
      rawOptions.noConfig === true,
    format,
    failOn,
    shouldIncludeIgnored: rawOptions.includeIgnored === true,
    changedScope: stringChoice(rawOptions.changedScope, ["symbol", "hunk", "file"], "symbol"),
    ...diffInput.options,
    ...changedRangesOption(rawOptions),
    ...sinceOption(rawOptions),
    ...historyFileOption(rawOptions),
    ...baselineOption(baselineValue, context),
    ...generation,
    ...migrateBaselineOption(rawOptions),
    ...(rawOptions.force === true ? { shouldForceBaselineOverwrite: true } : {}),
    shouldSkipBaseline,
    execution: executionSelectorsFrom(rawOptions),
  };
}

/**
 * Rejects a history write for a filtered scan so the user's score trend compares full scans.
 * The command reports the conflicting flags and exits 2 before rendering or writing history.
 *
 * @param rawOptions - parsed CLI options checked for a history path and changed-region flags
 * @returns Nothing. Lets the command proceed when the supplied options are compatible.
 * @throws {ConfigLoadError} when --history-file is combined with --diff, --diff-base, --since, or --changed-ranges.
 */
function assertFullScanHistoryOptions(rawOptions: Record<string, unknown>): void {
  const hasChangedRegionSelector = rawOptions.diff === true
    || typeof rawOptions.diff === "string"
    || typeof rawOptions.diffBase === "string"
    || typeof rawOptions.since === "string"
    || typeof rawOptions.changedRanges === "string";
  // A filtered request would mix partial scores into the full-project trend users review.
  if (typeof rawOptions.historyFile === "string" && hasChangedRegionSelector) {
    throw new ConfigLoadError(
      "`--history-file` requires a full scan and cannot be combined with `--diff`, `--diff-base`, `--since`, or `--changed-ranges`.",
      "Remove the changed-region option, or omit `--history-file` for this filtered scan.",
      false,
    );
  }
}

// Build hook analysis options from positional paths and parsed flags in rawOptions. Without a region selector, the scan is unscoped.
// The hook comparison contract uses JSON and symbol scope, with no severity gate or baseline suppression.
function hookScopedOptions(paths: string[], rawOptions: Record<string, unknown>): AnalysisOptions {
  return normalizeOptions(
    paths,
    { ...rawOptions, format: "json", failOn: "none", changedScope: "symbol", noBaseline: true },
    { shouldAllowBaselineFlag: false },
  );
}

// Return a copy of options with changed-region selectors removed so the hook can find full-file and project findings.
// The hook comparison contract keeps baseline suppression off so this pass sees the full set of findings.
function hookCurrentOptions(options: AnalysisOptions): AnalysisOptions {
  const { changedRanges: _changedRanges, diff: _diff, diffPatch: _diffPatch, since: _since, ...rest } = options;
  return { ...rest, shouldSkipBaseline: true };
}

// True when any changed-region selector (ranges, diff, since, stdin patch) is active for the run.
// `changedRanges` is tested for presence rather than truthiness, matching changedRegionScope: an empty value
// asks to scope the run and names no range, which the parser refuses instead of widening the scan.
function hasHookChangedRegion(options: AnalysisOptions): boolean {
  return options.changedRanges !== undefined || Boolean(options.diff || options.since || options.diffPatch);
}

// Returns baselinePath from the hook's parsed --baseline option to preserve the stable baseline contract for new-only filtering.
// Returns an empty object when the option is absent or its value is anything other than a path string.
function hookBaselinePath(rawOptions: Record<string, unknown>): Partial<{ baselinePath: string }> {
  return typeof rawOptions.baseline === "string" ? { baselinePath: rawOptions.baseline } : {};
}

// Return the hook's new-only comparison setting from options.diff, falling back to options.since; neither means an empty object.
function hookDiffBase(options: AnalysisOptions): Partial<{ diffBase: string }> {
  return options.diff ? { diffBase: options.diff } : options.since ? { diffBase: options.since } : {};
}

// Return a config option from rawOptions.config when it is a string; otherwise return an empty object.
// Omitting the key preserves exactOptionalPropertyTypes instead of assigning undefined.
function configOption(rawOptions: Record<string, unknown>): Partial<Pick<AnalysisOptions, "config">> {
  return typeof rawOptions.config === "string" ? { config: rawOptions.config } : {};
}

// Return rawOptions.profile as an analysis option when it is a string, or an empty object so config-file selection can supply it.
function profileOption(rawOptions: Record<string, unknown>): Partial<Pick<AnalysisOptions, "profile">> {
  return typeof rawOptions.profile === "string" ? { profile: rawOptions.profile } : {};
}

// Normalize rawOptions.deepScanBudget into an analysis override, or return an empty object for null, non-objects, or no enabled key.
// Return a disabled override for enabled=false, or a bounded override for enabled=true with both positive safe-integer limits.
// @throws {ConfigLoadError} when an object has enabled but is neither disabled nor validly bounded.
function deepScanBudgetOption(rawOptions: Record<string, unknown>): Partial<Pick<AnalysisOptions, "deepScanBudget">> {
  const budgetOverride = rawOptions.deepScanBudget;
  if (typeof budgetOverride !== "object" || budgetOverride === null || !("enabled" in budgetOverride)) {
    return {};
  }
  if (budgetOverride.enabled === false) {
    return { deepScanBudget: { enabled: false } };
  }
  if (budgetOverride.enabled === true && "maxLines" in budgetOverride && "maxBytes" in budgetOverride
    && typeof budgetOverride.maxLines === "number" && Number.isSafeInteger(budgetOverride.maxLines) && budgetOverride.maxLines > 0
    && typeof budgetOverride.maxBytes === "number" && Number.isSafeInteger(budgetOverride.maxBytes) && budgetOverride.maxBytes > 0) {
    return { deepScanBudget: { enabled: true, maxLines: budgetOverride.maxLines, maxBytes: budgetOverride.maxBytes } };
  }
  throw new ConfigLoadError("Invalid deep-scan budget override.", "Pass `--deep-scan-budget LINES:BYTES` with positive integers, or `--deep-scan-budget off`.", false);
}

/**
 * Decides whether --fail-on-new should block the run on findings an applied baseline leaves unreviewed.
 * The caller takes the maximum with the severity exit code to preserve the stable gate contract.
 *
 * @param report - analysis result carrying the baseline status and new finding count
 * @param rawOptions - parsed CLI options whose failOnNew flag enables the check
 * @returns 0 when disabled. With an applied baseline, returns 1 for a positive new finding count or 0 for an absent or nonpositive count.
 * @throws {ConfigLoadError} - when --fail-on-new is set but the run applied no baseline or only generated one.
 */
function newDebtExitCode(report: AnalysisReport, rawOptions: Record<string, unknown>): number {
  // When the new-debt gate is off, the command can proceed without applying a baseline.
  if (rawOptions.failOnNew !== true) {
    return 0;
  }

  const baseline = report.baseline;

  // A generate run writes a baseline rather than applying one, so it has nothing to call new either.
  if (baseline === undefined || baseline.generated === true) {
    throw new ConfigLoadError(
      "`--fail-on-new` needs an applied baseline to compare against, and this run applied none.",
      "Pass `--baseline <path>`, or generate one first with `--generate-baseline <path>`.",
      false,
    );
  }

  return (baseline.newFindings ?? 0) > 0 ? 1 : 0;
}

// Resolve diff settings from rawOptions and return them with paths; a nonempty diffBase overrides diff, and bare diff means working-tree.
// For diff='-', read stdin into diffPatch. With bare diff and a leading '-' in paths, consume that path in the returned list.
// Return unchanged paths and no diff settings when no selector applies.
function diffOption(paths: string[], rawOptions: Record<string, unknown>): { paths: string[]; options: Partial<Pick<AnalysisOptions, "diff" | "diffPatch">> } {
  const diffBase = rawOptions.diffBase;

  // The canonical spelling names the ref outright, so it wins over whatever mode --diff carried.
  if (typeof diffBase === "string" && diffBase.length > 0) {
    return { paths, options: { diff: diffBase } };
  }
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

// Return a changedRanges option for the string in rawOptions. Analysis rejects an explicitly empty range string.
// Return an empty object for other values so the explicit line-range filter stays unset.
function changedRangesOption(rawOptions: Record<string, unknown>): Partial<Pick<AnalysisOptions, "changedRanges">> {
  return typeof rawOptions.changedRanges === "string" ? { changedRanges: rawOptions.changedRanges } : {};
}

// Return a since option for a string in rawOptions, or an empty object otherwise. An empty string is preserved and selects no comparison ref.
function sinceOption(rawOptions: Record<string, unknown>): Partial<Pick<AnalysisOptions, "since">> {
  return typeof rawOptions.since === "string" ? { since: rawOptions.since } : {};
}

// Return a historyFile option from a string rawOptions.historyFile, or an empty object to preserve exactOptionalPropertyTypes.
function historyFileOption(rawOptions: Record<string, unknown>): Partial<Pick<AnalysisOptions, "historyFile">> {
  return typeof rawOptions.historyFile === "string" ? { historyFile: rawOptions.historyFile } : {};
}

// Normalize baselineValue from --baseline when context permits the command to use a baseline.
// The result holds the path string, even if empty, or gruff-baseline.json for a bare flag. An empty object leaves the option unset.
// Baseline selection is stable for calls with the same flag value and command policy.
function baselineOption(baselineValue: unknown, context: NormalizeContext): Partial<Pick<AnalysisOptions, "baseline">> {
  if (!context.shouldAllowBaselineFlag) {
    return {};
  }
  if (typeof baselineValue === "string") {
    return { baseline: baselineValue };
  }
  return baselineValue === true ? { baseline: DEFAULT_BASELINE } : {};
}

// Return a generateBaseline option from rawOptions when it is a string path; true selects DEFAULT_BASELINE.
// Other values return an empty object because baseline generation must be requested.
function generateBaselineOption(rawOptions: Record<string, unknown>): Partial<Pick<AnalysisOptions, "generateBaseline">> {
  if (typeof rawOptions.generateBaseline === "string") {
    return { generateBaseline: rawOptions.generateBaseline };
  }
  return rawOptions.generateBaseline === true ? { generateBaseline: DEFAULT_BASELINE } : {};
}

/*
 * Returns a migrateBaseline option from the parsed CLI flags, using the 0.5 baseline path to carry reviews into a new baseline.
 * A missing or non-string flag value yields an empty options object.
 */
function migrateBaselineOption(rawOptions: Record<string, unknown>): Partial<Pick<AnalysisOptions, "migrateBaseline">> {
  return typeof rawOptions.migrateBaseline === "string" ? { migrateBaseline: rawOptions.migrateBaseline } : {};
}

// Normalizes a programmatic option against choices; returns rawValue when it is a listed string, otherwise fallback.
function stringChoice<T extends string>(rawValue: unknown, choices: readonly T[], fallback: T): T {
  return typeof rawValue === "string" && choices.includes(rawValue as T) ? (rawValue as T) : fallback;
}

/*
 * What the project's config file says about one run's gate and its display floor, read in one pass.
 *
 * The two are deliberately separate keys: `failOn:` decides the exit code, `minimumSeverity:` decides what the
 * report shows. Keeping them in one result means the command reads the config once and cannot apply a stale half
 * of it (FAMILY-CONTRACT.md, search: `## 7. CLI surface`).
 */
interface ConfiguredSeverities {
  options: AnalysisOptions;
  displayFloor?: Severity;
}

/**
 * Uses failOn.<cmd> from configuration when the caller leaves --fail-on at its default. An explicit CLI value takes precedence.
 *
 * @param options - normalized analysis options used to select configuration and supply the existing fail-on value
 * @param command - command key used to look up the configured severity threshold
 * @param commanderCommand - parsed command used to detect an explicit CLI value
 * @returns Analysis options with any configured threshold applied, and a display floor only when one is configured.
 * @throws {ConfigLoadError} - if configuration loading fails, for runWithConfigErrorHandling to report.
 */
function configuredSeverities(options: AnalysisOptions, command: MinimumSeverityCommand, commanderCommand: Command): ConfiguredSeverities {
  // A scan of a sibling project should use that project's settings even if launched elsewhere.
  const config = loadConfig(projectRootFromTargets(options.paths), options);
  // An explicit --fail-on wins. If neither source sets a gate, keep this command's default.
  const configuredFailOn = commanderCommand.getOptionValueSource("failOn") === "cli" ? undefined : minimumSeverityFor(config, command);
  return {
    options: configuredFailOn === undefined ? options : { ...options, failOn: configuredFailOn },
    ...(config.displayFloor === undefined ? {} : { displayFloor: config.displayFloor }),
  };
}

/**
 * Writes a machine-readable failure envelope for a configuration load failure.
 *
 * @param program - command whose output flags govern stdout
 * @param requestedFormat - JSON or SARIF encoding. Other formats produce no envelope.
 * @param error - refusal to report when it represents a configuration load failure
 * @returns nothing. It publishes the envelope when the failure, format, and output flags allow it.
 */
function writeFailedRunEnvelope(program: Command, requestedFormat: unknown, error: ConfigLoadError): void {
  if (!error.isConfigLoadFailure || (requestedFormat !== "json" && requestedFormat !== "sarif")) {
    return;
  }
  writeCommandOutput(program, renderReport(failedRunReport(cwd(), requestedFormat, CONFIG_ERROR_DIAGNOSTIC_TYPE, error.message), requestedFormat));
}

/**
 * Report a target outside the launch directory and publish the refusal in machine-readable form when requested.
 *
 * @param program - command whose output flags govern the stdout envelope
 * @param requestedFormat - JSON or SARIF selects a failure envelope. Other formats skip it.
 * @param target - path outside the launch directory to identify in the refusal
 * @returns nothing. It writes the reason to stderr and sets process.exitCode to 2.
 */
function refuseTargetsOutsideLaunchDirectory(program: Command, requestedFormat: unknown, target: string): void {
  const message = outsideTargetMessage(target);
  process.stderr.write(`gruff-ts: ${message}\n`);
  // Automation reading JSON or SARIF receives the same refusal in its chosen format.
  if (requestedFormat === "json" || requestedFormat === "sarif") {
    writeCommandOutput(program, renderReport(failedRunReport(cwd(), requestedFormat, TARGET_ERROR_DIAGNOSTIC_TYPE, message), requestedFormat));
  }
  process.exitCode = 2;
}

// Describes why a multi-target scan cannot be anchored at its launch directory.
function outsideTargetMessage(target: string): string {
  return `target "${target}" is outside the launch directory; gruff-ts analyses several targets only from a directory that contains them all`;
}

/**
 * Awaits action; a ConfigLoadError writes stderr, optionally calls publishRefusal and sets process.exitCode to 2.
 * Other errors propagate unchanged; publisher errors propagate before the exit code is assigned.
 *
 * @param action - command work to run and await
 * @param publishRefusal - optional publisher for a handled refusal; omission leaves only stderr reporting
 * @returns a promise that resolves without a value after successful work or a handled refusal
 * @throws {unknown} - errors from action other than ConfigLoadError, or errors thrown by publishRefusal
 */
async function runWithConfigErrorHandling(action: () => Promise<void> | void, publishRefusal?: (error: ConfigLoadError) => void): Promise<void> {
  try {
    await action();
  } catch (error) {
    if (error instanceof ConfigLoadError) {
      process.stderr.write(`gruff-ts: config error\n  ${error.message}\n\nSuggested fix:\n  ${error.suggestion}\n`);
      publishRefusal?.(error);
      process.exitCode = 2;
      return;
    }
    throw error;
  }
}
