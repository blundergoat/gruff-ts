// Formats the CLI command catalogue, shell completion scripts (`bash`/`zsh`/`fish`), and `list-rules`/`list-profiles` output.
//
// Projects internal rule descriptors into the public cross-port listing shape used by CLI text and JSON consumers.
// Keeps command discovery, tab completion, and rule documentation backed by one source of truth.
import { VERSION } from "./constants.ts";
import { profileSummaries, type ProfileSummary } from "./profiles.ts";
import { ruleDescriptors } from "./rules.ts";
import type { RuleDescriptor, Severity } from "./types.ts";

type RuleListFormat = "text" | "json";
type CompletionShell = "bash" | "fish" | "zsh";

// Pre-formatted token strings, not arrays - the shell-specific renderers paste them straight into
// completion scripts (bash `$commands`, zsh `_describe`, etc.) so the formatting must already be shell-safe.
interface CompletionContext {
  commands: string;
  options: string;
}

const ANSI_GREEN = "\x1b[32m";
const ANSI_YELLOW = "\x1b[33m";
const ANSI_RESET_FG = "\x1b[39m";

const CONSOLE_COMMANDS = [
  { name: "analyse", description: "Run gruff analysis." },
  { name: "check-ignore", description: "Report whether gruff would ignore each path, with the matching source and pattern. Runs no analysis." },
  { name: "completion", description: "Dump the shell completion script" },
  { name: "dashboard", description: "Serve the local gruff dashboard." },
  { name: "help", description: "Display help for a command" },
  { name: "hook", description: "Run the gruff agent-hook contract." },
  { name: "init", description: "Write the default .gruff-ts.yaml to the current directory." },
  { name: "list", description: "List commands" },
  { name: "list-profiles", description: "List the built-in gruff profiles." },
  { name: "list-rules", description: "List gruff rule metadata." },
  { name: "migrate-config", description: "Rewrite a 0.5 config for the current schema, writing the result to a different file." },
  { name: "report", description: "Render a gruff report to stdout or a file." },
  {
    name: "summary",
    description:
      "Print a compact digest of a scan: per-pillar finding counts, top rules, and top file offenders. Runs the analyser once and renders only the summary; no per-finding spam.",
  },
] as const;

// Cross-port threshold knob names for single-threshold rules (ratified M09 listing contract).
// Any rule without a family knob name publishes `{"threshold": N}` so no new permanent identifier is invented.
const LISTING_THRESHOLD_KNOB_NAMES: Readonly<Record<string, string>> = {
  "complexity.cyclomatic": "maxComplexity",
  "size.file-length": "maxLines",
  "size.function-length": "maxLines",
  "size.parameter-count": "maxParameters",
};

// Public JSON projection emitted by `list-rules` (`id`, `defaultSeverity`, `defaultEnabled`, and named `thresholds`).
// Internal descriptors keep their native field names for reports, hooks, and config validation.
type ListedRule = Omit<RuleDescriptor, "ruleId" | "severity" | "isEnabledByDefault" | "threshold"> & {
  id: string;
  defaultSeverity: Severity;
  defaultEnabled: boolean;
  thresholds?: Record<string, number>;
};

/**
 * Project one internal rule descriptor into a public listed record with deliberate field order:
 * identity and scoring first, then defaultEnabled, an optional named threshold map, and remaining fields.
 *
 * @param descriptor - Internal rule descriptor whose fields are projected into the public record.
 * @returns Public listed record with `defaultEnabled` defaulted to true when absent and `thresholds` omitted when no numeric threshold is set.
 */
function listedRule(descriptor: RuleDescriptor): ListedRule {
  const { ruleId, pillar, severity, confidence, isEnabledByDefault, threshold, ...rest } = descriptor;
  const knob = LISTING_THRESHOLD_KNOB_NAMES[ruleId] ?? "threshold";
  return {
    id: ruleId,
    pillar,
    defaultSeverity: severity,
    confidence,
    // Every record publishes the family field, so a rule that is on by default says so rather than leaving it absent.
    defaultEnabled: isEnabledByDefault !== false,
    ...(typeof threshold === "number" ? { thresholds: { [knob]: threshold } } : {}),
    ...rest,
  };
}

/**
 * Render the full rule catalogue. JSON is the integration surface for docs and audits; text stays
 * plain because it is only for terminal inspection and should not become another schema.
 *
 * @param format - Output format selecting either JSON with tool metadata and projected rules or plain text lines.
 * @returns Newline-terminated rule catalogue string in the requested format.
 */
function renderRuleList(format: RuleListFormat): string {
  const descriptors = ruleDescriptors();
  if (format === "json") {
    return `${JSON.stringify({ tool: { name: "gruff-ts", version: VERSION }, rules: descriptors.map(listedRule) }, null, 2)}\n`;
  }
  const lines = ["gruff-ts " + VERSION + ` rules (${descriptors.length})`, ""];
  for (const descriptor of descriptors) {
    const threshold = typeof descriptor.threshold === "number" ? ` | threshold: ${descriptor.threshold}` : "";
    const options = descriptor.optionKeys && descriptor.optionKeys.length > 0 ? ` | options: ${descriptor.optionKeys.join(",")}` : "";
    lines.push(`${descriptor.ruleId} | ${descriptor.pillar} | ${descriptor.severity} | ${descriptor.confidence} | ${descriptor.description}${threshold}${options}`);
  }
  return `${lines.join("\n")}\n`;
}

/**
 * Render the built-in profile catalogue. Mirrors renderRuleList: JSON is the integration surface for docs
 * and audits, while text stays plain because it is only for terminal inspection and should not become a second schema.
 *
 * @param format - Output format selecting either JSON with tool metadata and profile summaries or plain text rows via profileListRow.
 * @returns Newline-terminated profile catalogue string in the requested format.
 */
function renderProfileList(format: RuleListFormat): string {
  const summaries = profileSummaries();
  if (format === "json") {
    return `${JSON.stringify({ tool: { name: "gruff-ts", version: VERSION }, profiles: summaries }, null, 2)}\n`;
  }
  const header = ["gruff-ts " + VERSION + ` profiles (${summaries.length})`, ""];
  return `${[...header, ...summaries.map(profileListRow)].join("\n")}\n`;
}

/**
 * Format one plain-text row for a profile with name, enabled/total rule count, pillar count,
 * optional tightened-threshold count, and description. The tightened-threshold segment only appears for presets that set one.
 *
 * @param summary - Profile summary supplying counts, enabled pillars, and description text.
 * @returns Single formatted text line for the profile.
 */
function profileListRow(summary: ProfileSummary): string {
  const tightened = summary.tightenedThresholdCount > 0 ? ` | tightened thresholds: ${summary.tightenedThresholdCount}` : "";
  return `${summary.name} | ${summary.enabledRuleCount}/${summary.totalRuleCount} rules | ${summary.enabledPillars.length} pillars${tightened} | ${summary.description}`;
}

/**
 * Look up a registered rule by its exact, case-sensitive public ID for explain-mode rendering.
 *
 * @param ruleId - complete public rule ID to match
 * @returns matching descriptor, or undefined when the ID is not registered
 */
function getRuleDescriptor(ruleId: string): RuleDescriptor | undefined {
  return ruleDescriptors().find((descriptor) => descriptor.ruleId === ruleId);
}

/**
 * Show supported overrides because operators looking up a rule should be able to find its keys without opening src/config.ts.
 *
 * @param descriptor - Catalogue entry supplying the rule details and supported configuration and allowlist keys.
 * @param format - Selects the labelled text card or the catalogue record with config keys and tool metadata in JSON.
 * @returns The selected single-rule detail with a trailing newline. The threshold override appears only for a numeric threshold.
 */
function renderRuleDetail(descriptor: RuleDescriptor, format: RuleListFormat): string {
  if (format === "json") {
    return `${JSON.stringify({ tool: { name: "gruff-ts", version: VERSION }, rule: { ...listedRule(descriptor), configKeys: ruleConfigKeys(descriptor) } }, null, 2)}\n`;
  }
  const lines = [
    `Rule:        ${descriptor.ruleId}`,
    `Pillar:      ${descriptor.pillar}`,
    `Severity:    ${descriptor.severity}`,
    `Confidence:  ${descriptor.confidence}`,
    // The family's detail-card wording; a rule that ships off (ADR-021) runs only when a config enables it.
    `Enabled by default: ${descriptor.isEnabledByDefault === false ? "no" : "yes"}`,
    ...(typeof descriptor.threshold === "number" ? [`Threshold:   ${descriptor.threshold}`] : []),
    "",
    `Description: ${descriptor.description}`,
    "",
    `Remediation: ${descriptor.remediation}`,
    "",
    ...ruleConfigKeyLines(descriptor),
    ...(descriptor.optionKeys && descriptor.optionKeys.length > 0 ? ["", "Options:", ...descriptor.optionKeys.map((key) => `  rules.${descriptor.ruleId}.options.${key}`)] : []),
    ...(descriptor.allowlistKeys && descriptor.allowlistKeys.length > 0 ? ["", "Allowlists:", ...descriptor.allowlistKeys.map((key) => `  allowlists.${key}`)] : []),
    ...(descriptor.falsePositiveShapes && descriptor.falsePositiveShapes.length > 0
      ? ["", "Known false positives:", ...descriptor.falsePositiveShapes.flatMap(({ shape, mitigation }) => [`  ${shape}`, `    -> ${mitigation}`])]
      : []),
  ];
  return `${lines.join("\n")}\n`;
}

/**
 * Build config-key text lines for a rule's enable and severity settings, plus a threshold line when
 * numeric. Options and allowlists are rendered separately by renderRuleDetail.
 *
 * @param descriptor - Rule descriptor supplying the rule id and optional default numeric threshold.
 * @returns Lines starting with a "Config keys:" heading followed by each applicable key and value type.
 */
function ruleConfigKeyLines(descriptor: RuleDescriptor): string[] {
  return [
    "Config keys:",
    `  rules.${descriptor.ruleId}.enabled   (bool)`,
    `  rules.${descriptor.ruleId}.severity  (advisory|warning|error)`,
    ...(typeof descriptor.threshold === "number" ? [`  rules.${descriptor.ruleId}.threshold (int, default: ${descriptor.threshold})`] : []),
  ];
}

/**
 * Build structured config-key entries for JSON consumers. An omitted enablement flag defaults to true,
 * and a threshold entry appears only for a numeric threshold.
 *
 * @param descriptor - Rule descriptor supplying the rule id, enabled state, severity, and optional threshold.
 * @returns Config-key descriptors naming each key, its type, and any applicable default or enum values.
 */
function ruleConfigKeys(descriptor: RuleDescriptor): Array<{ key: string; type: string; values?: readonly string[]; default?: number | boolean | string }> {
  return [
    { key: `rules.${descriptor.ruleId}.enabled`, type: "bool", default: descriptor.isEnabledByDefault !== false },
    { key: `rules.${descriptor.ruleId}.severity`, type: "enum", values: ["advisory", "warning", "error"] as const, default: descriptor.severity },
    ...(typeof descriptor.threshold === "number" ? [{ key: `rules.${descriptor.ruleId}.threshold`, type: "int", default: descriptor.threshold }] : []),
  ];
}

/**
 * Render the command catalogue shown for gruff-ts, gruff-ts list, and gruff-ts help.
 * CLI callers supply their ANSI policy rather than detecting terminal capabilities in this renderer.
 *
 * @param shouldUseAnsi - Whether to colorize labels and headings with ANSI escapes; defaults to false for plain text.
 * @returns Newline-terminated command usage, global options, and available commands listing.
 */
function renderConsoleList(shouldUseAnsi = false): string {
  const listCommand = ansiWrap("list", ANSI_GREEN, shouldUseAnsi);
  return [
    "gruff-ts " + ansiWrap(VERSION, ANSI_GREEN, shouldUseAnsi),
    "",
    ansiWrap("Usage:", ANSI_YELLOW, shouldUseAnsi),
    "  command [options] [arguments]",
    "",
    ansiWrap("Options:", ANSI_YELLOW, shouldUseAnsi),
    formatConsoleRow("-h, --help", `Display help for the given command. When no command is given display help for the ${listCommand} command`, 22, shouldUseAnsi),
    formatConsoleRow("    --silent", "Do not output any message", 22, shouldUseAnsi),
    formatConsoleRow("-q, --quiet", "Only errors are displayed. All other output is suppressed", 22, shouldUseAnsi),
    formatConsoleRow("-V, --version", "Display this application version", 22, shouldUseAnsi),
    formatConsoleRow("    --ansi|--no-ansi", "Force (or disable --no-ansi) ANSI output", 22, shouldUseAnsi),
    formatConsoleRow("-n, --no-interaction", "Do not ask any interactive question", 22, shouldUseAnsi),
    formatConsoleRow("-v|vv|vvv, --verbose", "Increase the verbosity of messages: 1 for normal output, 2 for more verbose output and 3 for debug", 22, shouldUseAnsi),
    "",
    ansiWrap("Available commands:", ANSI_YELLOW, shouldUseAnsi),
    ...CONSOLE_COMMANDS.map((command) => formatConsoleRow(command.name, command.description, 15, shouldUseAnsi)),
  ].join("\n") + "\n";
}

/**
 * Format an indented console listing row with padding computed from the uncolored label length.
 *
 * @param label - Command or option label displayed at the start of the row.
 * @param description - Explanatory text appended after the separating padding.
 * @param width - Minimum column width toward which the label is padded before the description.
 * @param shouldUseAnsi - Whether to wrap the label in green ANSI foreground escapes.
 * @returns Indented row with the label, at least one separating space, and the description.
 */
function formatConsoleRow(label: string, description: string, width: number, shouldUseAnsi: boolean): string {
  const paddedLabel = ansiWrap(label, ANSI_GREEN, shouldUseAnsi);
  const padding = " ".repeat(Math.max(1, width - label.length));
  const rowDescription = description;
  return `  ${paddedLabel}${padding}${rowDescription}`;
}

/**
 * Conditionally wrap text in an ANSI foreground color prefix and reset suffix.
 * The caller supplies the color prefix and decides whether its output destination supports ANSI escapes.
 *
 * @param text - Plain text content to wrap or pass through unchanged.
 * @param color - ANSI escape sequence prefix applied before the text when enabled.
 * @param shouldUseAnsi - Whether to emit ANSI color escapes around the text.
 * @returns Colored text with a foreground reset sequence when enabled, or the original text unchanged.
 */
function ansiWrap(text: string, color: string, shouldUseAnsi: boolean): string {
  if (!shouldUseAnsi) {
    return text;
  }
  const ansiColor = color;
  return `${ansiColor}${text}${ANSI_RESET_FG}`;
}

/**
 * Generate a shell completion script for the requested shell, routing fish and zsh to dedicated
 * renderers and defaulting all other values to Bash.
 *
 * @param shell - Target shell selector determining which completion renderer to invoke.
 * @returns Rendered completion script text for the selected shell.
 */
function renderCompletionScript(shell: CompletionShell): string {
  const context = completionContext();
  if (shell === "fish") {
    return renderFishCompletion(context);
  }
  if (shell === "zsh") {
    return renderZshCompletion(context);
  }
  return renderBashCompletion(context);
}

/**
 * Assemble space-separated command names and global options for shell completion renderers.
 * Help is excluded because Commander handles it implicitly; offering it here would put it alongside analyse.
 *
 * @returns Completion context containing space-joined subcommands and global CLI option flags.
 */
function completionContext(): CompletionContext {
  return {
    commands: CONSOLE_COMMANDS.filter((command) => command.name !== "help").map((command) => command.name).join(" "),
    options: "-h --help --silent -q --quiet -V --version --ansi --no-ansi -n --no-interaction -v -vv -vvv --verbose",
  };
}

/**
 * Render a Fish completion script with file completion disabled so candidates come from the
 * supplied command and option lists.
 *
 * @param context - Completion context holding space-separated subcommands and global option flags.
 * @returns Newline-terminated Fish completion script registering subcommands and options for gruff-ts.
 */
function renderFishCompletion(context: CompletionContext): string {
  return [
    "complete -c gruff-ts -f",
    ...context.commands.split(" ").map((command) => `complete -c gruff-ts -n '__fish_use_subcommand' -a '${command}'`),
    ...context.options.split(" ").map((option) => `complete -c gruff-ts -a '${option}'`),
    "",
  ].join("\n");
}

/**
 * Render a Zsh completion script with a leading `#compdef` tag for completion discovery and
 * `_arguments` state routing between subcommands and options.
 *
 * @param context - Completion context holding space-separated subcommands and global option flags.
 * @returns Newline-terminated Zsh completion script defining `_gruff_ts`.
 */
function renderZshCompletion(context: CompletionContext): string {
  return [
    "#compdef gruff-ts",
    "_gruff_ts() {",
    "  local -a commands",
    `  commands=(${context.commands})`,
    "  _arguments '1:command:->commands' '*::arg:->args'",
    "  case $state in",
    "    commands) _describe 'command' commands ;;",
    "    args) _values 'option' " + context.options.split(" ").map((option) => `'${option}'`).join(" ") + " ;;",
    "  esac",
    "}",
    "_gruff_ts \"$@\"",
    "",
  ].join("\n");
}

/**
 * Render a Bash completion script registered with `complete -F`. The embedded `--format` and
 * `--fail-on` value lists let the emitted script offer those values without loading the analyser.
 *
 * @returns Newline-terminated Bash completion script defining `_gruff_ts_completion`.
 */
function renderBashCompletion({ commands, options }: CompletionContext): string {
  const commandsLine = `  commands=\"${commands}\"`;
  const optionsLine = `  options=\"${options}\"`;
  return [
    "_gruff_ts_completion() {",
    "  local current previous commands options",
    "  COMPREPLY=()",
    "  current=\"${COMP_WORDS[COMP_CWORD]}\"",
    "  previous=\"${COMP_WORDS[COMP_CWORD-1]}\"",
    commandsLine,
    optionsLine,
    "  if [ \"$COMP_CWORD\" -eq 1 ]; then",
    "    COMPREPLY=( $(compgen -W \"$commands $options\" -- \"$current\") )",
    "  else",
    "    case \"$previous\" in",
    "      --format) COMPREPLY=( $(compgen -W \"text json html markdown github hotspot sarif\" -- \"$current\") ) ;;",
    "      --fail-on) COMPREPLY=( $(compgen -W \"none advisory warning error\" -- \"$current\") ) ;;",
    "      *) COMPREPLY=( $(compgen -W \"$options\" -- \"$current\") ) ;;",
    "    esac",
    "  fi",
    "}",
    "complete -F _gruff_ts_completion gruff-ts",
    "",
  ].join("\n");
}

/**
 * Normalize a shell name to a supported completion target, selecting `"bash"` for any value
 * other than exact `"fish"` or `"zsh"`.
 *
 * @param shellName - Raw shell name input to match against supported completion shells.
 * @returns `"fish"` or `"zsh"` on an exact match, or `"bash"` otherwise.
 */
function completionShell(shellName: unknown): CompletionShell {
  return shellName === "fish" || shellName === "zsh" ? shellName : "bash";
}

export type { RuleListFormat, CompletionShell };
export { renderRuleList, renderProfileList, renderRuleDetail, getRuleDescriptor, renderConsoleList, renderCompletionScript, completionShell };
