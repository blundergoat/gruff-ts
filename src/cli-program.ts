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

/**
 * Writes output to stdout unless suppressed by the program's flags, ensuring a trailing newline.
 *
 * @param program - root command whose silent and quiet flags govern whether stdout is written
 * @param output - text to write to stdout with a trailing newline appended when missing
 * @returns Nothing. Writes to stdout when output is enabled.
 */
function writeCommandOutput(program: Command, output: string): void {
  if (outputSuppressed(program)) {
    return;
  }
  process.stdout.write(output.endsWith("\n") ? output : `${output}\n`);
}

/**
 * Checks whether non-error stdout is suppressed. `--silent` and `--quiet` are intentionally treated
 * the same here because Commander exposes them as independent flags but the CLI's contract is uniform.
 *
 * @param program - root command providing the parsed quiet and silent flags
 * @returns True when either quiet or silent is enabled; otherwise false.
 */
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

/**
 * Offers to create a missing default config at the target root when interaction flags, config flags, and TTYs permit.
 * On acceptance, attempts a filesystem write with overwrite disabled and reports a newly written file on stderr;
 * call before analysis so loadConfig can use the new file during the same invocation.
 *
 * @param program - root command supplying interaction and output-suppression flags
 * @param projectRoot - directory checked for an existing config and used as the write target
 * @param options - per-command config-loading flags controlling whether prompting is skipped
 * @returns A promise that resolves without a value after checking, prompting, or writing the config.
 */
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

/**
 * Derives init-prompt settings from analysis options, preserving config opt-out and marking a string config path as explicit.
 *
 * @param options - normalized analysis options carrying config opt-out and path selection
 * @returns Prompt settings indicating whether config loading is skipped and whether a config path was explicitly supplied.
 */
function promptOptionsFromAnalysis(options: AnalysisOptions): InitPromptOptions {
  return { shouldSkipConfig: options.shouldSkipConfig, hasExplicitConfig: typeof options.config === "string" };
}

/**
 * Determines whether ANSI colour output is enabled, favouring explicit flags over TTY detection.
 * Disabling automatic colour for redirected output keeps escape codes out of files and CI logs.
 *
 * @param program - root command providing explicit `--ansi` or `--no-ansi` flag state
 * @returns True when ANSI is explicitly enabled or stdout is a TTY without `--no-ansi`; otherwise false.
 */
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

/**
 * Builds the root CLI program and registers every gruff-ts subcommand. The runner is injected rather than
 * imported to keep `cli-program.ts` off the analyser's dependency graph (see `.goat-flow/learning-loop/lessons/verification.md`).
 *
 * @param runAnalyse - analysis runner callback invoked by commands that execute scans or serve the dashboard
 * @returns The configured root Commander program with all subcommands registered.
 */
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

/**
 * Configures global CLI flags, help formatting, and the bare-invocation command catalogue action.
 * The exit override preserves successful help and version exits and maps nonzero Commander exit codes to status 2.
 *
 * @param program - root Commander instance to configure with global options and exit behaviour
 * @returns Nothing. Mutates the root program in place before subcommands are registered.
 */
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

      /**
       * Formats help text using the helper's layout settings and the captured root program.
       * Root help lists the command catalogue; subcommands use Commander's formatter with global options visible.
       *
       * @param command - command whose help text is being rendered
       * @param helper - Commander help formatter supplying wrap width settings
       * @returns The formatted help output for either the root catalogue or a subcommand.
       */
      formatHelp(command, helper) {
        return rootHelpText(program, command, helper);
      },
    })
    .action(() => {
      writeCommandOutput(program, renderConsoleList(ansiEnabled(program)));
    });
}

/**
 * Returns the command catalogue for root help, or Commander's subcommand help with global options visible.
 *
 * @param program - root command used to detect root help and supply ANSI colour settings
 * @param command - help target command being formatted
 * @param helper - Commander help instance supplying optional wrap width settings
 * @returns Rendered command catalogue for the root command, or formatted help text for a subcommand.
 */
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

/**
 * Previews or writes the migrated config requested by `migrate-config`.
 * Side effects: reads the input config, writes stdout, and writes one new file on the filesystem when `--output` is supplied.
 *
 * @param program - root command whose output flags govern stdout printing
 * @param rawOptions - parsed flags providing `--config`, `--output`, and `--dry-run`
 * @returns Nothing. Prints migration details, sets exit code 2 when `--output` is missing without `--dry-run`, or writes the migrated file.
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

/**
 * Selects the migration encoding from a supported config extension.
 *
 * @param path - filesystem path to the source or destination configuration file
 * @returns `"yaml"` for `.yaml`/`.yml` paths or `"json"` for `.json` paths.
 * @throws {ConfigLoadError} for an unsupported extension.
 */
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

/**
 * Registers the `analyse` subcommand for users who want individual findings in the terminal or a machine-readable report.
 * The default gate fails on advisory or higher; users can set `--fail-on=error` or configure `failOn.analyse`.
 *
 * @param program - root command that receives the `analyse` subcommand
 * @param runAnalyse - analysis runner invoked to scan the requested targets
 * @returns Nothing. Registers options and the action handler on the root program.
 */
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

/**
 * Registers `check-ignore` to classify paths with `analyse`'s ignore rules and set exit status 0, 1, or 2.
 * When output is enabled, JSON reports every path and text lists only ignored paths with their match details.
 *
 * @param program - root command that receives the `check-ignore` subcommand
 * @returns Nothing. Attaches the subcommand, its config/format flags, and the ignore-check action to the program.
 */
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

/**
 * Registers `hook` for coding agents to review an edit and apply a project gate using the JSON response.
 * Invariant: a refused input or missing required baseline produces an envelope and exit 2; config failures include a suggested next step.
 *
 * @param program - root command that receives the `hook` subcommand
 * @param runAnalyse - analysis runner used to evaluate current and scoped views for the hook payload
 * @returns Nothing. Registers the hook subcommand and its action handler.
 * @throws {unknown} - from the registered action when the caught failure is not an Error.
 */
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

/**
 * Builds analysis options for checking paths against ignore rules, matching `analyse` config selection and skipping baselines.
 * Git and fallback ignore checks stay enabled for eligible paths while existing explicit files bypass them.
 *
 * @param paths - target paths supplied to `check-ignore`
 * @param rawOptions - parsed CLI flags used to select or skip configuration loading
 * @returns Analysis options configured for the ignore-check contract with baselines disabled.
 */
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

/**
 * Registers `completion` to emit the selected shell's completion script to stdout, defaulting to bash.
 *
 * @param program - root command that receives the `completion` subcommand
 * @returns Nothing. Adds the subcommand whose action writes the completion script when stdout is enabled.
 */
function registerCompletionCommand(program: Command): void {
  program
    .command("completion")
    .description("Dump the shell completion script")
    .argument("[shell]", "Shell to generate completion for: bash, zsh, or fish.", "bash")
    .action((shell: string) => {
      writeCommandOutput(program, renderCompletionScript(completionShell(shell)));
    });
}

/**
 * Registers `dashboard`, defaulting to `127.0.0.1:8767` because the unauthenticated dashboard accepts a caller-selected projectRoot.
 * The action may write config after an interactive prompt before starting the server.
 *
 * @param program - root command that receives the `dashboard` subcommand
 * @param runAnalyse - analysis runner passed to the dashboard server for requested scans
 * @returns Nothing. Registers the dashboard subcommand and its startup action.
 */
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

/**
 * Registers `init` to write the default config in the current directory and print adoption guidance when stdout is enabled.
 * Without `--force`, an existing supported config is preserved, a refusal is written to stderr, and `process.exitCode` is set to 1.
 *
 * @param program - root command that receives the `init` subcommand
 * @returns Nothing. Adds the subcommand and its config-initialization action.
 */
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

/**
 * Builds the `init` success message and adoption guidance; the gate command must use the same baseline file that generation creates.
 *
 * @param verb - action label distinguishing newly created (`Wrote`) from replaced (`Overwrote`) config files
 * @param configPath - path to the written configuration file shown in the message
 * @returns Multi-line guidance naming the written config path and matching baseline generation and gating commands.
 */
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

/**
 * Registers `list` to mirror bare-root help so users following Symfony console conventions can request the command catalogue explicitly.
 *
 * @param program - root command that receives the `list` subcommand and supplies ANSI settings
 * @returns Nothing. Adds the `list` subcommand to the program.
 */
function registerListCommand(program: Command): void {
  program
    .command("list")
    .description("List commands")
    .action(() => {
      writeCommandOutput(program, renderConsoleList(ansiEnabled(program)));
    });
}

/**
 * Registers `list-profiles` to print the built-in profile catalogue as text or JSON when stdout is enabled.
 * `parseSummaryFormat` rejects unsupported formats as usage errors (see `footguns/schema-and-cli.md` for the format validation contract).
 *
 * @param program - root command that receives the `list-profiles` subcommand
 * @returns Nothing. Adds the subcommand and format option to the program.
 */
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

/**
 * Registers `list-rules` to print either the rule catalogue or one rule's details as text or JSON through the program's output flags.
 * Unknown rules or unsupported formats are reported as usage errors.
 *
 * @param program - root command that receives the `list-rules` subcommand
 * @returns Nothing. Adds the subcommand, optional rule argument, and output action.
 */
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

/**
 * Registers `report` for users who want an HTML or JSON artifact of all findings, including reviewed baseline debt.
 * Side effects: the action writes to `--output` or stdout, and can write project config on the filesystem after user approval.
 *
 * @param program - root command that receives the `report` subcommand
 * @param runAnalyse - analysis runner invoked to produce the report findings
 * @returns Nothing. Registers the subcommand, its report options, and its action handler.
 */
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

/**
 * Registers `summary` for users who want pillar counts and top rules or files without opening a per-finding report.
 * Side effects: the action writes the digest to stdout and can save config, a baseline, or score history when requested.
 *
 * @param program - root command that receives the `summary` subcommand
 * @param runAnalyse - analysis runner invoked to scan the target paths
 * @returns Nothing. Registers the summary subcommand and its action handler.
 */
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

/**
 * Validates the requested hook output format against the hook's JSON-only output contract.
 *
 * @param rawFormat - format string supplied to `--format` on the `hook` command
 * @returns `"json"` when accepted.
 * @throws {InvalidArgumentError} when `rawFormat` is anything other than `json`.
 */
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

/**
 * Builds execution selectors that determine which rules run and which findings contribute to scores.
 * Keeps only string entries from selector arrays; absent or non-array selectors become empty lists.
 *
 * @param rawOptions - parsed CLI options containing include and exclude rule or pillar lists
 * @returns Execution selector lists for rules and pillars.
 */
function executionSelectorsFrom(rawOptions: Record<string, unknown>): ExecutionSelectors {
  return {
    includeRules: selectorList(rawOptions.includeRule),
    excludeRules: selectorList(rawOptions.excludeRule),
    includePillars: selectorList(rawOptions.includePillar),
    excludePillars: selectorList(rawOptions.excludePillar),
  };
}

/**
 * Builds report-only display selectors that affect visibility without changing execution, scores, or exit status.
 * Keeps only string list entries; absent or non-array selectors become empty lists and invalid `minSeverity` is omitted.
 *
 * @param rawOptions - parsed CLI options containing show/hide selectors and optional minimum display severity
 * @returns Display selector filters for post-analysis report rendering.
 */
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

/**
 * Filters displayed findings and updates summary counts while keeping the already computed exit status and score stable.
 *
 * @param report - analysis report whose `findings` and `summary` are mutated for display
 * @param rawOptions - parsed CLI options supplying show/hide rules, pillars, and `--min-severity`
 * @param displayFloor - optional severity floor from configuration applied alongside CLI selectors
 * @returns Nothing. Mutates `report.findings` and `report.summary` in place.
 */
function filterReportForDisplay(report: AnalysisReport, rawOptions: Record<string, unknown>, displayFloor: Severity | undefined): void {
  report.findings = applyDisplaySelectors(report.findings, displaySelectorsFrom(rawOptions), displayFloor);
  report.summary = summarize(report.findings);
}

/**
 * Extracts string entries from a collected selector flag value.
 *
 * @param rawValue - candidate flag value expected to hold collected selector strings
 * @returns String entries from `rawValue`, or an empty list for a non-array or an array without strings.
 */
function selectorList(rawValue: unknown): string[] {
  return Array.isArray(rawValue) ? rawValue.filter((entry): entry is string => typeof entry === "string") : [];
}

/**
 * Reads the confidence floor the gate applies; an unset flag admits every finding, which is the documented default.
 *
 * @param rawOptions - parsed CLI options providing an optional `minConfidence` setting
 * @returns `"medium"` or `"high"` when explicitly configured, or `"low"` by default.
 */
function confidenceFloor(rawOptions: Record<string, unknown>): Confidence {
  const configured = rawOptions.minConfidence;
  return configured === "medium" || configured === "high" ? configured : "low";
}

/**
 * Builds the hook blocking policy applied after handling payload output, including when output is suppressed.
 *
 * @param rawOptions - parsed hook CLI flags supplying severity, confidence, new-finding, and diagnostic gates
 * @returns Hook gate policy with `failOn`, `minConfidence` (defaulting to `low`), and boolean blocking flags.
 */
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

/**
 * Writes one `gruff-ts: <message>` line per changed-region diagnostic to stderr under the stable text-mode contract.
 * Machine readers receive the same diagnostic inside the report payload instead.
 *
 * @param report - analysis report containing diagnostics from the run
 * @param format - requested output format; only `"text"` writes diagnostics to stderr
 * @returns Nothing. Writes matching changed-region diagnostic lines to stderr in text mode.
 */
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

/**
 * Maps a hook error to its diagnostic type under the hook's stable diagnostic contract without inspecting message wording.
 *
 * @param error - thrown error instance caught by the hook command
 * @param rawOptions - parsed CLI options checked for a string `--baseline` path
 * @returns The changed-region diagnostic type for `ChangedRegionError`, `"baseline"` when a baseline path string is present, or `"run"`.
 */
function hookFatalType(error: Error, rawOptions: Record<string, unknown>): string {
  if (error instanceof ChangedRegionError) {
    return CHANGED_REGION_DIAGNOSTIC_TYPE;
  }
  return typeof rawOptions.baseline === "string" ? "baseline" : "run";
}

/**
 * Parses a deep-scan budget override, keeping both numeric limits in one value to prevent a half-updated budget.
 *
 * @param rawBudget - CLI argument string, either `"off"` or `"LINES:BYTES"`
 * @returns An enabled override with positive `maxLines` and `maxBytes`, or `{ enabled: false }` for `"off"`.
 * @throws {InvalidArgumentError} when the value is not `"off"` and not `LINES:BYTES` with two positive safe integers.
 */
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

/**
 * Formats the path label shown in the summary header by resolving target paths against the current directory.
 *
 * @param paths - target paths supplied to the summary command
 * @param projectRoot - fallback project root returned when `paths` is empty
 * @returns Comma-joined resolved paths, or `projectRoot` when no paths were provided.
 */
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

/**
 * Builds hook analysis options under the hook comparison contract (JSON, symbol scope, no severity gate or baseline suppression).
 * Without a region selector, the scan remains unscoped.
 *
 * @param paths - positional paths passed to the hook command
 * @param rawOptions - parsed CLI flags merged with hook contract defaults
 * @returns Normalized analysis options for the scoped hook pass.
 */
function hookScopedOptions(paths: string[], rawOptions: Record<string, unknown>): AnalysisOptions {
  return normalizeOptions(
    paths,
    { ...rawOptions, format: "json", failOn: "none", changedScope: "symbol", noBaseline: true },
    { shouldAllowBaselineFlag: false },
  );
}

/**
 * Strips changed-region selectors from hook options so the current pass captures full-file and project findings.
 * Keeps baseline suppression off per the hook comparison contract so this pass sees the full set of findings.
 *
 * @param options - scoped hook analysis options to widen
 * @returns Copy of `options` with changed-region fields omitted and `shouldSkipBaseline` set to true.
 */
function hookCurrentOptions(options: AnalysisOptions): AnalysisOptions {
  const { changedRanges: _changedRanges, diff: _diff, diffPatch: _diffPatch, since: _since, ...rest } = options;
  return { ...rest, shouldSkipBaseline: true };
}

/**
 * Reports whether any changed-region selector (ranges, diff, since, or stdin patch) is active for the run.
 * `changedRanges` is tested for presence rather than truthiness, matching `changedRegionScope`: an empty value
 * asks to scope the run without naming a range, which the parser refuses instead of widening the scan.
 *
 * @param options - normalized analysis options to inspect for region selectors
 * @returns True when any changed-region selector is active; otherwise false.
 */
function hasHookChangedRegion(options: AnalysisOptions): boolean {
  return options.changedRanges !== undefined || Boolean(options.diff || options.since || options.diffPatch);
}

/**
 * Extracts `baselinePath` from `--baseline` to preserve the stable baseline contract for hook new-only filtering.
 *
 * @param rawOptions - parsed hook CLI flags
 * @returns `{ baselinePath }` when `--baseline` is a string, or an empty object when absent or non-string.
 */
function hookBaselinePath(rawOptions: Record<string, unknown>): Partial<{ baselinePath: string }> {
  return typeof rawOptions.baseline === "string" ? { baselinePath: rawOptions.baseline } : {};
}

/**
 * Selects the hook's new-only comparison ref from `diff`, falling back to `since`.
 *
 * @param options - normalized hook analysis options
 * @returns `{ diffBase }` from `options.diff` or `options.since`, or an empty object when neither is set.
 */
function hookDiffBase(options: AnalysisOptions): Partial<{ diffBase: string }> {
  return options.diff ? { diffBase: options.diff } : options.since ? { diffBase: options.since } : {};
}

/**
 * Extracts a string config path option while omitting the key to preserve `exactOptionalPropertyTypes` instead of assigning undefined.
 *
 * @param rawOptions - parsed CLI flags checked for a string `config` value
 * @returns `{ config }` when `rawOptions.config` is a string, or an empty object otherwise.
 */
function configOption(rawOptions: Record<string, unknown>): Partial<Pick<AnalysisOptions, "config">> {
  return typeof rawOptions.config === "string" ? { config: rawOptions.config } : {};
}

/**
 * Extracts a string profile specifier, omitting the key when absent so config-file selection can supply it.
 *
 * @param rawOptions - parsed CLI flags checked for a string `profile` value
 * @returns `{ profile }` when `rawOptions.profile` is a string, or an empty object otherwise.
 */
function profileOption(rawOptions: Record<string, unknown>): Partial<Pick<AnalysisOptions, "profile">> {
  return typeof rawOptions.profile === "string" ? { profile: rawOptions.profile } : {};
}

/**
 * Normalizes `rawOptions.deepScanBudget` into a disabled or bounded analysis override.
 *
 * @param rawOptions - parsed CLI flags containing an optional `deepScanBudget` override object
 * @returns `{ deepScanBudget }` for valid overrides, or an empty object for null, non-objects, or missing `enabled`.
 * @throws {ConfigLoadError} when an object has `enabled` but is neither disabled nor validly bounded.
 */
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

/**
 * Resolves `--diff` and `--diff-base` settings, reading stdin into `diffPatch` when `-` is given.
 * A nonempty `diffBase` overrides `diff`, bare `--diff` means `working-tree`, and a leading `-` in `paths` with bare `--diff` is consumed.
 *
 * @param paths - positional scan targets, which may begin with `-` for a stdin patch
 * @param rawOptions - parsed CLI flags providing `diff` and `diffBase`
 * @returns Updated `paths` and partial diff options, or unchanged `paths` with empty options when no selector applies.
 */
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

/**
 * Extracts a string `changedRanges` option so analysis can enforce or reject an explicitly empty range string.
 *
 * @param rawOptions - parsed CLI flags checked for a string `changedRanges` value
 * @returns `{ changedRanges }` when a string is present, or an empty object so the filter stays unset.
 */
function changedRangesOption(rawOptions: Record<string, unknown>): Partial<Pick<AnalysisOptions, "changedRanges">> {
  return typeof rawOptions.changedRanges === "string" ? { changedRanges: rawOptions.changedRanges } : {};
}

/**
 * Extracts a string `since` base ref option, preserving an empty string (which selects no comparison ref).
 *
 * @param rawOptions - parsed CLI flags checked for a string `since` value
 * @returns `{ since }` when `rawOptions.since` is a string, or an empty object otherwise.
 */
function sinceOption(rawOptions: Record<string, unknown>): Partial<Pick<AnalysisOptions, "since">> {
  return typeof rawOptions.since === "string" ? { since: rawOptions.since } : {};
}

/**
 * Extracts a string `historyFile` path while omitting absent values to preserve `exactOptionalPropertyTypes`.
 *
 * @param rawOptions - parsed CLI flags checked for a string `historyFile` value
 * @returns `{ historyFile }` when `rawOptions.historyFile` is a string, or an empty object otherwise.
 */
function historyFileOption(rawOptions: Record<string, unknown>): Partial<Pick<AnalysisOptions, "historyFile">> {
  return typeof rawOptions.historyFile === "string" ? { historyFile: rawOptions.historyFile } : {};
}

/**
 * Normalizes `--baseline` when the command policy permits baseline input; selection is stable for identical inputs.
 *
 * @param baselineValue - raw `--baseline` value (path string, `true` for a bare flag, or unset)
 * @param context - command policy controlling whether `--baseline` is permitted
 * @returns `{ baseline }` holding the path string (even if empty) or `DEFAULT_BASELINE` for `true`, or `{}` when disallowed.
 */
function baselineOption(baselineValue: unknown, context: NormalizeContext): Partial<Pick<AnalysisOptions, "baseline">> {
  if (!context.shouldAllowBaselineFlag) {
    return {};
  }
  if (typeof baselineValue === "string") {
    return { baseline: baselineValue };
  }
  return baselineValue === true ? { baseline: DEFAULT_BASELINE } : {};
}

/**
 * Resolves `--generate-baseline` into an output path, returning `{}` otherwise because baseline generation must be requested.
 *
 * @param rawOptions - parsed CLI flags checked for a string path or boolean `true` on `generateBaseline`
 * @returns `{ generateBaseline }` with the given string path or `DEFAULT_BASELINE` for `true`, or an empty object otherwise.
 */
function generateBaselineOption(rawOptions: Record<string, unknown>): Partial<Pick<AnalysisOptions, "generateBaseline">> {
  if (typeof rawOptions.generateBaseline === "string") {
    return { generateBaseline: rawOptions.generateBaseline };
  }
  return rawOptions.generateBaseline === true ? { generateBaseline: DEFAULT_BASELINE } : {};
}

/**
 * Extracts the 0.5 baseline path from parsed CLI flags to carry reviews into a new baseline.
 *
 * @param rawOptions - parsed CLI flags checked for a string `migrateBaseline` path
 * @returns `{ migrateBaseline }` when a string path is supplied, or an empty object for missing or non-string values.
 */
function migrateBaselineOption(rawOptions: Record<string, unknown>): Partial<Pick<AnalysisOptions, "migrateBaseline">> {
  return typeof rawOptions.migrateBaseline === "string" ? { migrateBaseline: rawOptions.migrateBaseline } : {};
}

/**
 * Normalizes a programmatic option against a list of allowed string values.
 *
 * @param rawValue - candidate option value to validate
 * @param choices - allowed string values accepted for the option
 * @param fallback - default value returned when `rawValue` is not a listed string
 * @returns `rawValue` when it is a string included in `choices`; otherwise `fallback`.
 */
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

/**
 * Formats the refusal reason explaining why a multi-target scan cannot be anchored at its launch directory.
 *
 * @param target - target path located outside the current launch directory
 * @returns Human-readable refusal message naming `target`.
 */
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
