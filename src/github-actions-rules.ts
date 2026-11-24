// Audits committed GitHub Actions workflow YAML files for supply-chain and pull-request security risks.
//
// Path-gated to `.github/workflows/*.yml` and `.yaml` so regular YAML config files never emit CI findings.
// Checks unpinned third-party actions, remote-shell pipes, unsafe `pull_request_target` checkouts, and secret exposure on PR triggers.
import type { SourceFile } from "./discovery.ts";
import { unreachableWorkflowSecretLines } from "./github-actions-event-guards.ts";
import { makeFinding } from "./findings.ts";
import type { Finding } from "./types.ts";

// Normalized workflow line used by indentation-aware YAML heuristics.
interface WorkflowLine {
  raw: string;
  text: string;
  trimmed: string;
  lineNumber: number;
  indent: number;
}

// Common finding payload before the module applies shared security defaults.
interface WorkflowFindingInput {
  ruleId: string;
  message: string;
  line: number;
  symbol?: string;
  remediation: string;
  metadata: Record<string, unknown>;
}

// Active `run: |` / `run: >` block scalar. The start line is the finding anchor, while `lines`
// holds the shell body after YAML indentation has been stripped by `workflowLines`.
interface RunBlockState {
  indent?: number;
  startLine?: WorkflowLine;
  lines: string[];
}

// Shell command candidate extracted from a workflow `run` step with the line used for reporting.
interface WorkflowCommand {
  command: string;
  line: WorkflowLine;
}

// GitHub's 2026-07-12 workflow table defines the current write-capable keys below.
// `repository-projects` remains so users scanning legacy Enterprise workflows still see the risk.
const WRITE_PERMISSION_SCOPES = new Set([
  "actions",
  "artifact-metadata",
  "attestations",
  "checks",
  "code-quality",
  "contents",
  "deployments",
  "discussions",
  "id-token",
  "issues",
  "packages",
  "pages",
  "pull-requests",
  "repository-projects",
  "security-events",
  "statuses",
]);

/**
 * Checks YAML workflow source when `file` has a GitHub workflow display path, keeping example YAML outside workflows exempt.
 * Under the stable rule contract, non-workflow paths leave `findings` unchanged.
 *
 * @param file - Source file descriptor whose `displayPath` gates analysis.
 * @param source - Raw YAML file contents to inspect for workflow security findings.
 * @param findings - Findings array that receives appended workflow security warnings.
 * @returns Nothing. Appends any workflow findings to `findings` and leaves other paths unchanged.
 */
function analyseGithubActionsRules(file: SourceFile, source: string, findings: Finding[]): void {
  if (!isGithubWorkflowPath(file.displayPath)) {
    return;
  }
  const lines = workflowLines(source);
  analysePullRequestTarget(file, lines, findings);
  analyseUnpinnedActions(file, lines, findings);
  analyseRemoteShell(file, lines, findings);
  analyseSecretsInPullRequest(file, lines, findings);
}

/**
 * Checks whether a display path names a YAML file directly under the root `.github/workflows` directory, ignoring case.
 *
 * @param displayPath - Relative repository path to test against the workflow directory pattern.
 * @returns `true` when `displayPath` is a `.yml` or `.yaml` file directly inside `.github/workflows`.
 */
function isGithubWorkflowPath(displayPath: string): boolean {
  return /^\.github\/workflows\/[^/]+\.ya?ml$/i.test(displayPath);
}

/**
 * Normalizes raw YAML lines into structured records while preserving leading-space indentation for block-state scans.
 *
 * @param source - Raw YAML workflow text split on LF or CRLF line endings.
 * @returns Normalized line records with stripped inline comments, trimmed text, 1-based line numbers, and space indentation.
 */
function workflowLines(source: string): WorkflowLine[] {
  return source.split(/\r?\n/).map((raw, index) => {
    const text = stripInlineComment(raw);
    const trimmed = text.trim();
    return { raw, text, trimmed, lineNumber: index + 1, indent: leadingSpaceCount(raw) };
  });
}

/**
 * Removes common YAML inline comments starting at `" #"` without attempting to parse quoted scalars.
 *
 * @param line - Single raw YAML line to strip.
 * @returns Substring before the first `" #"`, or `line` unchanged when none is present.
 */
function stripInlineComment(line: string): string {
  const comment = line.indexOf(" #");
  return comment === -1 ? line : line.slice(0, comment);
}

/**
 * Counts leading ASCII spaces on a line because workflow YAML should only use spaces, never tabs, for indentation.
 *
 * @param line - Raw YAML line whose leading indentation is measured.
 * @returns Number of leading space characters at the start of `line`.
 */
function leadingSpaceCount(line: string): number {
  const match = line.match(/^ */);
  return match?.[0].length ?? 0;
}

/**
 * Checks workflow lines for a `pull_request_target` event paired with a trusted-context risk signal anywhere in the workflow.
 * Uses `file` and the first matching event line to emit a stable finding anchor.
 *
 * @param file - Workflow source file descriptor used for the finding path.
 * @param lines - Normalized workflow lines to scan for the event and risk signals.
 * @param findings - Findings array that receives the warning when both conditions match.
 * @returns Nothing. Appends a `pull_request_target` warning to `findings` when both exist.
 */
function analysePullRequestTarget(file: SourceFile, lines: readonly WorkflowLine[], findings: Finding[]): void {
  const eventLine = lines.find((line) => hasPullRequestTargetEvent(line));
  if (!eventLine || !hasPullRequestTargetRiskContext(lines)) {
    return;
  }
  findings.push(
    workflowFinding(file, {
      ruleId: "security.github-actions-pull-request-target",
      message: "`pull_request_target` is paired with workflow behavior that can execute or expose trusted context.",
      line: eventLine.lineNumber,
      symbol: "pull_request_target",
      remediation: "Use `pull_request` for untrusted code, or isolate checkout, secrets, and write permissions behind explicit trust checks.",
      metadata: { event: "pull_request_target", riskContext: pullRequestTargetRiskContext(lines) },
    }),
  );
}

/**
 * Checks whether a nonblank, noncomment workflow line contains the whole `pull_request_target` token using the line's text alone.
 *
 * @param line - Normalized workflow line to inspect.
 * @returns `true` when `line` is not blank or a comment and matches the `pull_request_target` word token.
 */
function hasPullRequestTargetEvent(line: WorkflowLine): boolean {
  return !isCommentOrBlank(line) && /\bpull_request_target\b/.test(line.trimmed);
}

/**
 * Checks whether workflow lines contain any recognized risk signal so an event-only workflow produces no `pull_request_target` warning.
 *
 * @param lines - Normalized workflow lines to scan for risk indicators.
 * @returns `true` when at least one risk context label is detected in `lines`.
 */
function hasPullRequestTargetRiskContext(lines: readonly WorkflowLine[]): boolean {
  return pullRequestTargetRiskContext(lines).length > 0;
}

/**
 * Scans workflow lines for checkout steps, `run` steps, secret references, and broad write permissions.
 * Produces unique risk labels in stable sorted order for finding metadata.
 *
 * @param lines - Normalized workflow lines to inspect.
 * @returns Sorted unique risk context labels; an empty array means no risk signal was recognized.
 */
function pullRequestTargetRiskContext(lines: readonly WorkflowLine[]): string[] {
  const contexts = new Set<string>();
  for (const line of lines) {
    if (isCommentOrBlank(line)) {
      continue;
    }
    if (/^(?:-\s*)?uses:\s*["']?actions\/checkout@/i.test(line.trimmed)) {
      contexts.add("checkout");
    }
    if (/^(?:-\s*)?run:\s*/i.test(line.trimmed)) {
      contexts.add("run");
    }
    if (/\bsecrets\./.test(line.trimmed)) {
      contexts.add("secrets");
    }
    if (broadPermissionSignal(line)) {
      contexts.add("write-permissions");
    }
  }
  return [...contexts].sort();
}

/**
 * Checks whether a line signals `write-all` permissions or a `write` grant for a recognized scope in the `pull_request_target` risk check.
 *
 * @param line - Normalized workflow line whose trimmed text is matched against permission rules.
 * @returns `true` when `line` declares `permissions: write-all` or `<scope>: write` for a known write scope.
 */
function broadPermissionSignal(line: WorkflowLine): boolean {
  if (/^permissions:\s*write-all\b/i.test(line.trimmed)) {
    return true;
  }
  const scoped = line.trimmed.match(/^([a-z-]+):\s*write\b/i);
  return WRITE_PERMISSION_SCOPES.has(scoped?.[1] ?? "");
}

/**
 * Scans workflow lines for third-party action references whose refs fall outside the stable pinning contract of 40 hexadecimal characters.
 *
 * @param file - Workflow source file descriptor used for warning paths.
 * @param lines - Normalized workflow lines to inspect for `uses:` entries.
 * @param findings - Findings array that receives a warning for each unpinned third-party action.
 * @returns Nothing. Appends warnings to `findings` for refs not pinned to a 40-character hexadecimal SHA.
 */
function analyseUnpinnedActions(file: SourceFile, lines: readonly WorkflowLine[], findings: Finding[]): void {
  for (const line of lines) {
    const action = thirdPartyActionUse(line);
    if (!action || isPinnedToFullSha(action.ref)) {
      continue;
    }
    findings.push(
      workflowFinding(file, {
        ruleId: "security.github-actions-unpinned-action",
        message: `Third-party action \`${action.action}\` is not pinned to a full commit SHA.`,
        line: line.lineNumber,
        symbol: action.action,
        remediation: "Pin third-party actions to a reviewed 40-character commit SHA and update them deliberately.",
        metadata: { action: action.action, owner: action.owner, ref: action.ref },
      }),
    );
  }
}

/**
 * Extracts the action path, owner, and ref from a recognized external `uses:` entry.
 * Local paths and owners `actions` or `github` are skipped because they are exempt from third-party pin checks.
 *
 * @param line - Normalized workflow line to parse for an external action reference.
 * @returns Parsed `{ action, owner, ref }` object, or `undefined` when absent, unsupported, local, or exempt.
 */
function thirdPartyActionUse(line: WorkflowLine): { action: string; owner: string; ref: string } | undefined {
  if (isCommentOrBlank(line)) {
    return undefined;
  }
  const match = line.trimmed.match(/^(?:-\s*)?uses:\s*["']?([^@\s"'#]+)@([^ \t"'#]+)/i);
  const action = match?.[1] ?? "";
  const ref = match?.[2] ?? "";
  if (!action.includes("/") || action.startsWith("./")) {
    return undefined;
  }
  const owner = action.split("/")[0] ?? "";
  if (owner === "actions" || owner === "github") {
    return undefined;
  }
  return { action, owner, ref };
}

/**
 * Checks whether an action ref is exactly 40 hexadecimal characters, the required commit-pin form for third-party actions.
 *
 * @param ref - Action version, branch, tag, or commit SHA string after `@`.
 * @returns `true` when `ref` consists of exactly 40 hexadecimal characters.
 */
function isPinnedToFullSha(ref: string): boolean {
  return /^[0-9a-f]{40}$/i.test(ref);
}

/**
 * Checks `run` commands extracted from workflow lines for a remote download piped to a shell.
 * YAML block parsing preserves a stable source anchor for each command.
 *
 * @param file - Workflow source file descriptor used for the report path.
 * @param lines - Normalized workflow lines to extract `run` commands from.
 * @param findings - Findings array that receives a warning for each matching remote-shell command.
 * @returns Nothing. Appends matching remote-shell warnings to `findings`.
 */
function analyseRemoteShell(file: SourceFile, lines: readonly WorkflowLine[], findings: Finding[]): void {
  for (const command of runCommands(lines)) {
    if (isRemoteShellCommand(command.command)) {
      pushRemoteShellFinding(file, findings, command.line);
    }
  }
}

/**
 * Appends a workflow remote-shell warning for a matched `run` command using a stable source anchor.
 *
 * @param file - Workflow source file descriptor used for the finding path.
 * @param findings - Findings array that receives the new warning.
 * @param line - Workflow line anchoring the matched `run` step in the report.
 * @returns Nothing. Appends one remote-shell finding to `findings`.
 */
function pushRemoteShellFinding(file: SourceFile, findings: Finding[], line: WorkflowLine): void {
  findings.push(
    workflowFinding(file, {
      ruleId: "security.github-actions-remote-shell",
      message: "Workflow downloads remote content and pipes it to a shell.",
      line: line.lineNumber,
      symbol: "run",
      remediation: "Vendor the installer, pin an audited action, or verify downloaded content before execution.",
      metadata: { command: "remote-shell" },
    }),
  );
}

/**
 * Collects inline and block-scalar `run` commands with their source lines in workflow source order.
 * Block bodies use trimmed lines so remote-shell findings stay deterministic.
 *
 * @param lines - Normalized workflow lines to scan for `run:` entries and block bodies.
 * @returns Extracted `run` commands paired with their anchor lines, or an empty list if none are recognized.
 */
function runCommands(lines: readonly WorkflowLine[]): WorkflowCommand[] {
  const commands: WorkflowCommand[] = [];
  const state: RunBlockState = { lines: [] };
  for (const line of lines) {
    flushClosedRunBlock(line, state, commands);
    if (runBlockLine(line, state)) {
      continue;
    }
    startOrPushRunCommand(line, state, commands);
  }
  flushRunBlock(state, commands);
  return commands;
}

/**
 * Flushes an active `run` block when indentation drops to or below the block header level, allowing the caller to inspect `line` next.
 * Leaves `state` and `commands` unchanged when no block is closed.
 *
 * @param line - Current workflow line whose indentation may close the active block.
 * @param state - Mutable run-block accumulator cleared when the active block closes.
 * @param commands - Command list that receives the flushed block command when a start line is present.
 * @returns Nothing. Appends any closed block command to `commands` and resets `state`.
 */
function flushClosedRunBlock(line: WorkflowLine, state: RunBlockState, commands: WorkflowCommand[]): void {
  if (state.indent !== undefined && line.indent <= state.indent) {
    flushRunBlock(state, commands);
  }
}

/**
 * Appends a line's trimmed text to `state.lines` when indented deeper than the active `run` key, leaving `state` unchanged otherwise.
 * The remote-shell check uses this normalized text, which can omit content after a space and hash.
 *
 * @param line - Normalized workflow line to test against the active run-block indentation.
 * @param state - Mutable run-block state holding the active `indent` and accumulated `lines`.
 * @returns `true` when `line` belongs to the active block and was captured; `false` otherwise.
 */
function runBlockLine(line: WorkflowLine, state: RunBlockState): boolean {
  if (state.indent === undefined || line.indent <= state.indent) {
    return false;
  }
  state.lines.push(line.trimmed);
  return true;
}

/**
 * Parses a line as a `run` entry, either initializing block-scalar collection in `state` or appending an inline command to `commands`.
 * Blank, comment-only, and non-`run` lines leave `state` and `commands` unchanged.
 *
 * @param line - Normalized workflow line to inspect for a `run:` prefix.
 * @param state - Mutable run-block state reset when `line` starts a block scalar.
 * @param commands - Command list that receives inline `run` commands.
 * @returns Nothing. Mutates `state` for block scalars or appends inline commands to `commands`.
 */
function startOrPushRunCommand(line: WorkflowLine, state: RunBlockState, commands: WorkflowCommand[]): void {
  if (isCommentOrBlank(line)) {
    return;
  }
  const run = line.trimmed.match(/^(?:-\s*)?run:\s*(.*)$/i);
  if (run?.[1] === undefined) {
    return;
  }
  if (isRunBlockScalar(run[1])) {
    state.indent = line.indent;
    state.startLine = line;
    state.lines = [];
  } else {
    commands.push({ command: run[1], line });
  }
}

/**
 * Emits any pending `run` block command from `state` to `commands` and clears `state`.
 * Missing `indent` or `startLine` skips command emission while still resetting `state`.
 *
 * @param state - Mutable run-block state whose pending lines, `indent`, and `startLine` are cleared.
 * @param commands - Command list that receives the joined block command when active.
 * @returns Nothing. Appends the pending block command to `commands` when complete and resets `state`.
 */
function flushRunBlock(state: RunBlockState, commands: WorkflowCommand[]): void {
  if (state.indent !== undefined && state.startLine) {
    commands.push({ command: state.lines.join("\n"), line: state.startLine });
  }
  delete state.indent;
  delete state.startLine;
  state.lines = [];
}

/**
 * Checks whether a `run` value matches a YAML block scalar header pattern, including forms such as `|-`, `>2`, or `|+4`.
 *
 * @param command - Inline string following `run:` on the header line.
 * @returns `true` when `command` is a block scalar indicator (`|` or `>`) with optional chomping or indent modifiers.
 */
function isRunBlockScalar(command: string): boolean {
  return /^[|>](?:[+-]?\d*|\d*[+-]?)?\s*$/.test(command);
}

/**
 * Checks whether command text matches a `curl` or `wget` HTTP(S) download piped to `sh`, `bash`, or `zsh`, with optional `sudo`.
 *
 * @param command - Shell command text extracted from an inline or block-scalar `run` step.
 * @returns `true` when `command` pipes an HTTP or HTTPS `curl` or `wget` fetch into a shell.
 */
function isRemoteShellCommand(command: string): boolean {
  return /\b(?:curl|wget)\b[^|]*https?:\/\/[^|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b/i.test(command);
}

/**
 * Checks workflow lines for named secret references only when the workflow declares `pull_request_target`.
 * Under the stable rule contract, skips `GITHUB_TOKEN` and lines identified as unreachable for this event.
 *
 * @param file - Workflow source file descriptor used for finding paths.
 * @param lines - Normalized workflow lines to check for triggers and secret references.
 * @param findings - Findings array that receives at most one secret warning per line.
 * @returns Nothing. Appends matching secret findings to `findings`.
 */
function analyseSecretsInPullRequest(file: SourceFile, lines: readonly WorkflowLine[], findings: Finding[]): void {
  if (!declaredWorkflowEvents(lines).has("pull_request_target")) {
    return;
  }
  const unreachable = unreachableWorkflowSecretLines(lines.map((line) => line.raw).join("\n"), ["pull_request_target"]);
  for (const line of lines) {
    const secretName = secretReference(line);
    if (!secretName || unreachable.has(line.lineNumber)) {
      continue;
    }
    findings.push(
      workflowFinding(file, {
        ruleId: "security.github-actions-secrets-in-pr",
        message: `pull_request_target workflow references secret \`${secretName}\`.`,
        line: line.lineNumber,
        symbol: secretName,
        remediation: "Avoid exposing secrets to pull request workflows unless the code path is trusted and tightly gated.",
        metadata: { event: "pull_request_target", secretName },
      }),
    );
  }
}

/**
 * Reads recognized event names from the top-level `on` key so `pull_request_target` secret checks only fire on workflows that declare that trigger.
 * Supports scalar, inline/multiline flow, and indented/indentless block sequences because YAML allows all four forms for `on:`.
 *
 * @param lines - Normalized workflow lines to scan for top-level `on` declarations.
 * @returns Set of recognized trigger event names, or an empty set when none are declared so the `pull_request_target` secret check is skipped.
 */
function declaredWorkflowEvents(lines: readonly WorkflowLine[]): Set<string> {
  const events = new Set<string>();
  const state: OnBlockState = { inOnBlock: false, eventIndent: undefined, flowDepth: 0 };
  for (const line of lines) {
    if (!isCommentOrBlank(line)) {
      consumeWorkflowEventLine(line, events, state);
    }
  }
  return events;
}

// Mutable parser state tracked while walking lines under a workflow's top-level `on:` trigger declaration.
interface OnBlockState {
  inOnBlock: boolean;
  eventIndent: number | undefined;
  flowDepth: number;
}

/**
 * Updates trigger-event state from one non-blank workflow line because YAML allows multiline flow arrays and indentless sequence items under `on:`.
 *
 * @param line - Normalized non-comment workflow line being scanned.
 * @param events - Mutable trigger-event set updated in place.
 * @param state - Mutable `on:` block tracking state updated in place.
 * @returns Nothing. Adds any recognized event names from `line` into `events`.
 */
function consumeWorkflowEventLine(line: WorkflowLine, events: Set<string>, state: OnBlockState): void {
  // Multiline flow declarations like `on: [\n  pull_request_target,\n  issues\n]` keep collecting until outer flow depth returns to zero.
  if (state.flowDepth > 0) {
    const cleaned = stripInlineComment(line.trimmed).trim();
    addFlowEvents(events, cleaned);
    state.flowDepth = Math.max(0, state.flowDepth + flowDelimiterDelta(cleaned));
    return;
  }
  // Indentless block sequence items (`on:\n- pull_request_target`) sit at indent 0 and belong to the active `on:` block.
  if (line.indent === 0 && !(state.inOnBlock && line.trimmed.startsWith("-"))) {
    const onKey = line.trimmed.match(/^["']?on["']?\s*:\s*(.*)$/);
    const inlineValue = onKey ? stripInlineComment(onKey[1] ?? "").trim() : "";
    state.inOnBlock = onKey !== null && inlineValue === "";
    state.eventIndent = undefined;
    if (onKey && !state.inOnBlock) {
      addFlowEvents(events, inlineValue);
      state.flowDepth = inlineValue.startsWith("[") || inlineValue.startsWith("{")
        ? Math.max(0, flowDelimiterDelta(inlineValue))
        : 0;
    }
    return;
  }
  if (!state.inOnBlock) {
    return;
  }
  // The first nested line fixes the event level; deeper lines configure one event, such as its branches.
  state.eventIndent ??= line.indent;
  if (line.indent === state.eventIndent) {
    const event = line.trimmed.match(/^(?:-\s*)?["']?([A-Za-z_]+)["']?\s*(?::|$)/)?.[1];
    if (event) {
      events.add(event);
    }
  }
}

/**
 * Counts net flow-collection bracket nesting (`[`/`{` minus `]`/`}`) on one YAML line so nested flow maps do not close `on:` early.
 *
 * @param text - Trimmed YAML flow text with inline comments already stripped.
 * @returns Positive count for unclosed openers, zero for balanced delimiters, or negative when closers exceed openers.
 */
function flowDelimiterDelta(text: string): number {
  let delta = 0;
  for (const character of text) {
    if (character === "[" || character === "{") {
      delta += 1;
    } else if (character === "]" || character === "}") {
      delta -= 1;
    }
  }
  return delta;
}

/**
 * Parses event names from a scalar or simple flow sequence or mapping declaration and adds non-empty names to `events`.
 *
 * @param events - Mutable event set that receives parsed trigger names.
 * @param declaration - Inline value following top-level `on:` after stripping inline comments.
 * @returns Nothing. Adds recognized non-empty event names to `events`.
 */
function addFlowEvents(events: Set<string>, declaration: string): void {
  for (const flowEntry of declaration.replace(/^[[{]/, "").replace(/[\]}]$/, "").split(",")) {
    const event = (flowEntry.split(":")[0] ?? "").trim().replace(/^["']|["']$/g, "");
    if (event) {
      events.add(event);
    }
  }
}

/**
 * Extracts the first case-sensitive `secrets.NAME` identifier on a line while excluding `GITHUB_TOKEN`.
 * Returning the name alone keeps the raw expression out of finding metadata.
 *
 * @param line - Normalized workflow line whose trimmed text is scanned for secret expressions.
 * @returns First non-`GITHUB_TOKEN` secret name, or `undefined` for blank, comment-only, or unmatched lines.
 */
function secretReference(line: WorkflowLine): string | undefined {
  if (isCommentOrBlank(line)) {
    return undefined;
  }
  // Excluding GITHUB_TOKEN does not end the search because a later reference on the same line can name another secret.
  for (const match of line.trimmed.matchAll(/\bsecrets\.([A-Za-z_][A-Za-z0-9_]*)\b/g)) {
    if (match[1] !== "GITHUB_TOKEN") {
      return match[1];
    }
  }
  return undefined;
}

/**
 * Checks whether a line's trimmed YAML text is empty or comment-only so callers can skip it during text heuristics.
 *
 * @param line - Normalized workflow line to test.
 * @returns `true` when `line.trimmed` is empty or starts with `#`.
 */
function isCommentOrBlank(line: WorkflowLine): boolean {
  return line.trimmed.length === 0 || line.trimmed.startsWith("#");
}

/**
 * Builds a workflow security warning using a stable finding contract across workflow rules.
 * Omits `symbol` when `input` supplies none or an empty string.
 *
 * @param file - Workflow source file descriptor providing `displayPath` for the report path.
 * @param input - Rule identifier, message, source line, optional symbol, remediation, and metadata payload.
 * @returns Constructed security warning `Finding` ready to append to results.
 */
function workflowFinding(file: SourceFile, input: WorkflowFindingInput): Finding {
  return makeFinding({
    ruleId: input.ruleId,
    message: input.message,
    filePath: file.displayPath,
    line: input.line,
    severity: "warning",
    pillar: "security",
    confidence: "medium",
    ...(input.symbol ? { symbol: input.symbol } : {}),
    remediation: input.remediation,
    metadata: input.metadata,
  });
}

export { analyseGithubActionsRules };
