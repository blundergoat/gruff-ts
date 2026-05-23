// GitHub Actions workflow security heuristics, path-gated to committed workflow files.
import type { SourceFile } from "./discovery.ts";
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

// Shared indentation state for YAML block scans; deleting `indent` exits the current block.
interface IndentedBlockState {
  indent?: number;
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

const WRITE_PERMISSION_SCOPES = new Set([
  "actions",
  "checks",
  "contents",
  "deployments",
  "issues",
  "packages",
  "pull-requests",
  "repository-projects",
  "security-events",
  "statuses",
]);

// Stable rule contract: workflow-only checks ignore non-workflow YAML so example docs avoid findings.
function analyseGithubActionsRules(file: SourceFile, source: string, findings: Finding[]): void {
  if (!isGithubWorkflowPath(file.displayPath)) {
    return;
  }
  const lines = workflowLines(source);
  analysePullRequestTarget(file, lines, findings);
  analyseBroadPermissions(file, lines, findings);
  analyseUnpinnedActions(file, lines, findings);
  analyseRemoteShell(file, lines, findings);
  analyseSecretsInPullRequest(file, lines, findings);
}

// Matches committed GitHub Actions workflow locations and nothing under docs or examples.
function isGithubWorkflowPath(displayPath: string): boolean {
  return /^\.github\/workflows\/[^/]+\.ya?ml$/i.test(displayPath);
}

// Normalizes raw YAML lines into a small record while preserving indentation for block-state scans.
function workflowLines(source: string): WorkflowLine[] {
  return source.split(/\r?\n/).map((raw, index) => {
    const text = stripInlineComment(raw);
    const trimmed = text.trim();
    return { raw, text, trimmed, lineNumber: index + 1, indent: leadingSpaceCount(raw) };
  });
}

// Removes common YAML inline comments without attempting to parse quoted scalars.
function stripInlineComment(line: string): string {
  const comment = line.indexOf(" #");
  return comment === -1 ? line : line.slice(0, comment);
}

// Counts spaces only; workflow YAML should not rely on tabs for indentation.
function leadingSpaceCount(line: string): number {
  const match = line.match(/^ */);
  return match?.[0].length ?? 0;
}

// Stable finding contract: reports pull_request_target only when trusted-context risk is visible nearby.
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

// Detects the event token in compact or expanded YAML event forms.
function hasPullRequestTargetEvent(line: WorkflowLine): boolean {
  return !isCommentOrBlank(line) && /\bpull_request_target\b/.test(line.trimmed);
}

// Separates the boolean gate from metadata collection so the event-alone case stays quiet.
function hasPullRequestTargetRiskContext(lines: readonly WorkflowLine[]): boolean {
  return pullRequestTargetRiskContext(lines).length > 0;
}

// Collects stable risk labels used in metadata and tests.
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

// Stable permissions contract: helpers keep YAML block state explicit because nested scopes affect anchors.
function analyseBroadPermissions(file: SourceFile, lines: readonly WorkflowLine[], findings: Finding[]): void {
  const state: IndentedBlockState = {};
  for (const line of lines) {
    const scope = broadPermissionScope(line, state);
    if (scope) {
      pushBroadPermissionFinding(file, findings, line, scope);
    }
  }
}

// Reports one finding per broad permission scope; stable scope symbols keep remediation targeted.
function pushBroadPermissionFinding(file: SourceFile, findings: Finding[], line: WorkflowLine, scope: string): void {
  findings.push(
    workflowFinding(file, {
      ruleId: "security.github-actions-broad-permissions",
      message: `Workflow grants broad write permission \`${scope}\`.`,
      line: line.lineNumber,
      symbol: scope,
      remediation: "Reduce workflow permissions to read-only by default and grant write scopes only to trusted jobs.",
      metadata: { permission: scope },
    }),
  );
}

// Returns the broad permission scope for either inline permissions or an active permissions block.
function broadPermissionScope(line: WorkflowLine, state: IndentedBlockState): string | undefined {
  if (isCommentOrBlank(line)) {
    return undefined;
  }
  closeBlockWhenOutdented(state, line);
  const inline = line.trimmed.match(/^permissions:\s*(write-all)\b/i);
  if (inline?.[1]) {
    return "write-all";
  }
  if (/^permissions:\s*$/i.test(line.trimmed)) {
    state.indent = line.indent;
    return undefined;
  }
  if (state.indent === undefined || line.indent <= state.indent) {
    return undefined;
  }
  return scopedWritePermission(line);
}

// Clears YAML block state once the scanner reaches a sibling or parent indentation level.
function closeBlockWhenOutdented(state: IndentedBlockState, line: WorkflowLine): void {
  if (state.indent !== undefined && line.indent <= state.indent) {
    delete state.indent;
  }
}

// Extracts selected write scopes that are broad enough to matter for workflow security.
function scopedWritePermission(line: WorkflowLine): string | undefined {
  const scoped = line.trimmed.match(/^([a-z-]+):\s*write\b/i);
  const scope = scoped?.[1] ?? "";
  return WRITE_PERMISSION_SCOPES.has(scope) ? scope : undefined;
}

// Lightweight permission signal used by the pull_request_target risk-context gate.
function broadPermissionSignal(line: WorkflowLine): boolean {
  if (/^permissions:\s*write-all\b/i.test(line.trimmed)) {
    return true;
  }
  const scoped = line.trimmed.match(/^([a-z-]+):\s*write\b/i);
  return WRITE_PERMISSION_SCOPES.has(scoped?.[1] ?? "");
}

// Stable supply-chain contract: reports third-party action refs unless pinned to a full commit SHA.
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

// Parses `uses:` entries while exempting GitHub-owned and local reusable actions.
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

// Full 40-character SHAs are the stable pinning target for third-party actions.
function isPinnedToFullSha(ref: string): boolean {
  return /^[0-9a-f]{40}$/i.test(ref);
}

// Stable run-step contract: helpers separate YAML block state from shell matching to preserve anchors.
function analyseRemoteShell(file: SourceFile, lines: readonly WorkflowLine[], findings: Finding[]): void {
  for (const command of runCommands(lines)) {
    if (isRemoteShellCommand(command.command)) {
      pushRemoteShellFinding(file, findings, command.line);
    }
  }
}

// Reports workflow-specific remote-shell findings at the risky command line for stable anchors.
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

// Extracts both inline `run: command` values and multiline block-scalar bodies. The returned order
// follows workflow source order so multiple remote-shell findings remain deterministic.
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

// Ends a block scalar when YAML indentation returns to the parent/sibling level. The current line
// is then processed again by the caller as a possible next command.
function flushClosedRunBlock(line: WorkflowLine, state: RunBlockState, commands: WorkflowCommand[]): void {
  if (state.indent !== undefined && line.indent <= state.indent) {
    flushRunBlock(state, commands);
  }
}

// Captures a line belonging to the active run block. The normalized trimmed text is enough for the
// remote-shell heuristic because it only needs command tokens and pipe placement.
function runBlockLine(line: WorkflowLine, state: RunBlockState): boolean {
  if (state.indent === undefined || line.indent <= state.indent) {
    return false;
  }
  state.lines.push(line.trimmed);
  return true;
}

// Starts a new `run` block or records an inline command. Blank and comment-only lines are ignored
// here because they cannot carry a workflow step key.
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

// Emits the pending block-scalar command and clears all mutable state. Missing `startLine` is
// treated as empty state so partially initialized blocks cannot throw.
function flushRunBlock(state: RunBlockState, commands: WorkflowCommand[]): void {
  if (state.indent !== undefined && state.startLine) {
    commands.push({ command: state.lines.join("\n"), line: state.startLine });
  }
  delete state.indent;
  delete state.startLine;
  state.lines = [];
}

// Recognizes YAML block scalar headers including chomping/indent indicators such as `|-`, `>2`, or `|+4`.
function isRunBlockScalar(command: string): boolean {
  return /^[|>](?:[+-]?\d*|\d*[+-]?)?\s*$/.test(command);
}

// Mirrors package script remote-installer semantics for curl/wget piped to a shell.
function isRemoteShellCommand(command: string): boolean {
  return /\b(?:curl|wget)\b[^|]*https?:\/\/[^|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b/i.test(command);
}

// Stable secret-exposure contract: reports secrets.NAME only when the workflow is pull-request triggered.
function analyseSecretsInPullRequest(file: SourceFile, lines: readonly WorkflowLine[], findings: Finding[]): void {
  if (!hasPullRequestStyleEvent(lines)) {
    return;
  }
  for (const line of lines) {
    const secretName = secretReference(line);
    if (!secretName) {
      continue;
    }
    findings.push(
      workflowFinding(file, {
        ruleId: "security.github-actions-secrets-in-pr",
        message: `Pull request workflow references secret \`${secretName}\`.`,
        line: line.lineNumber,
        symbol: secretName,
        remediation: "Avoid exposing secrets to pull request workflows unless the code path is trusted and tightly gated.",
        metadata: { event: "pull_request", secretName },
      }),
    );
  }
}

// Treats pull_request and pull_request_target as PR-style contexts for secret exposure checks.
function hasPullRequestStyleEvent(lines: readonly WorkflowLine[]): boolean {
  return lines.some((line) => !isCommentOrBlank(line) && /\bpull_request(?:_target)?\b/.test(line.trimmed));
}

// Extracts the secret symbol while keeping the raw expression out of finding metadata.
function secretReference(line: WorkflowLine): string | undefined {
  if (isCommentOrBlank(line)) {
    return undefined;
  }
  const match = line.trimmed.match(/\bsecrets\.([A-Za-z_][A-Za-z0-9_]*)\b/);
  return match?.[1];
}

// Skips blank/comment-only YAML lines before applying simple text heuristics.
function isCommentOrBlank(line: WorkflowLine): boolean {
  return line.trimmed.length === 0 || line.trimmed.startsWith("#");
}

// Centralizes workflow finding metadata so every rule emits the same pillar/severity contract.
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
