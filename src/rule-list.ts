import { VERSION } from "./constants.ts";
import { ruleDescriptors } from "./rules.ts";

type RuleListFormat = "text" | "json";
type CompletionShell = "bash" | "fish" | "zsh";

interface CompletionContext {
  commands: string;
  options: string;
}

const ANSI_GREEN = "[32m";
const ANSI_YELLOW = "[33m";
const ANSI_RESET_FG = "[39m";

const CONSOLE_COMMANDS = [
  { name: "analyse", description: "Run gruff analysis." },
  { name: "completion", description: "Dump the shell completion script" },
  { name: "dashboard", description: "Serve the local gruff dashboard." },
  { name: "help", description: "Display help for a command" },
  { name: "list", description: "List commands" },
  { name: "list-rules", description: "List gruff rule metadata." },
  { name: "report", description: "Render a gruff report to stdout or a file." },
  {
    name: "summary",
    description:
      "Print a compact digest of a scan: per-pillar finding counts, top rules, and top file offenders. Runs the analyser once and renders only the summary; no per-finding spam.",
  },
] as const;

function renderRuleList(format: RuleListFormat): string {
  const descriptors = ruleDescriptors();
  if (format === "json") {
    return `${JSON.stringify({ tool: { name: "gruff-ts", version: VERSION }, rules: descriptors }, null, 2)}\n`;
  }
  const lines = ["gruff-ts " + VERSION + ` rules (${descriptors.length})`, ""];
  for (const descriptor of descriptors) {
    const thresholds = descriptor.thresholdKeys && descriptor.thresholdKeys.length > 0 ? ` | thresholds: ${descriptor.thresholdKeys.join(",")}` : "";
    lines.push(`${descriptor.ruleId} | ${descriptor.pillar} | ${descriptor.severity} | ${descriptor.confidence} | ${descriptor.description}${thresholds}`);
  }
  return `${lines.join("\n")}\n`;
}

function renderConsoleList(useAnsi = false): string {
  const listCommand = ansiWrap("list", ANSI_GREEN, useAnsi);
  return [
    "gruff-ts " + ansiWrap(VERSION, ANSI_GREEN, useAnsi),
    "",
    ansiWrap("Usage:", ANSI_YELLOW, useAnsi),
    "  command [options] [arguments]",
    "",
    ansiWrap("Options:", ANSI_YELLOW, useAnsi),
    formatConsoleRow("-h, --help", `Display help for the given command. When no command is given display help for the ${listCommand} command`, 22, useAnsi),
    formatConsoleRow("    --silent", "Do not output any message", 22, useAnsi),
    formatConsoleRow("-q, --quiet", "Only errors are displayed. All other output is suppressed", 22, useAnsi),
    formatConsoleRow("-V, --version", "Display this application version", 22, useAnsi),
    formatConsoleRow("    --ansi|--no-ansi", "Force (or disable --no-ansi) ANSI output", 22, useAnsi),
    formatConsoleRow("-n, --no-interaction", "Do not ask any interactive question", 22, useAnsi),
    formatConsoleRow("-v|vv|vvv, --verbose", "Increase the verbosity of messages: 1 for normal output, 2 for more verbose output and 3 for debug", 22, useAnsi),
    "",
    ansiWrap("Available commands:", ANSI_YELLOW, useAnsi),
    ...CONSOLE_COMMANDS.map((command) => formatConsoleRow(command.name, command.description, 12, useAnsi)),
  ].join("\n") + "\n";
}

function formatConsoleRow(label: string, description: string, width: number, useAnsi: boolean): string {
  const paddedLabel = ansiWrap(label, ANSI_GREEN, useAnsi);
  const padding = " ".repeat(Math.max(1, width - label.length));
  const rowDescription = description;
  return `  ${paddedLabel}${padding}${rowDescription}`;
}

function ansiWrap(value: string, color: string, useAnsi: boolean): string {
  if (!useAnsi) {
    return value;
  }
  const ansiColor = color;
  return `${ansiColor}${value}${ANSI_RESET_FG}`;
}

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

function completionContext(): CompletionContext {
  return {
    commands: CONSOLE_COMMANDS.filter((command) => command.name !== "help").map((command) => command.name).join(" "),
    options: "-h --help --silent -q --quiet -V --version --ansi --no-ansi -n --no-interaction -v -vv -vvv --verbose",
  };
}

function renderFishCompletion(context: CompletionContext): string {
  return [
    "complete -c gruff-ts -f",
    ...context.commands.split(" ").map((command) => `complete -c gruff-ts -n '__fish_use_subcommand' -a '${command}'`),
    ...context.options.split(" ").map((option) => `complete -c gruff-ts -a '${option}'`),
    "",
  ].join("\n");
}

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

function completionShell(value: unknown): CompletionShell {
  return value === "fish" || value === "zsh" ? value : "bash";
}

export type { RuleListFormat, CompletionShell };
export { renderRuleList, renderConsoleList, renderCompletionScript, completionShell };
