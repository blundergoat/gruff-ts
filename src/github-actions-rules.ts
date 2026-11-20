// GitHub Actions workflow security heuristics, path-gated to committed workflow files.
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

// Use the file's display path to decide whether to check its YAML source, so example YAML outside workflows stays exempt.
// The stable rule contract leaves the caller's findings unchanged for other paths. The function returns nothing and appends any workflow findings.
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

// Returns whether displayPath names a YAML file directly under the root .github/workflows directory, ignoring case.
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

// Checks workflow lines for a pull_request_target match and a trusted-context risk signal anywhere in the workflow.
// Returns nothing and appends a warning to findings when both exist. Uses file and the first matching event line for a stable anchor.
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

// Returns true when a nonblank, noncomment workflow line contains the whole pull_request_target token, using the line's text alone.
function hasPullRequestTargetEvent(line: WorkflowLine): boolean {
  return !isCommentOrBlank(line) && /\bpull_request_target\b/.test(line.trimmed);
}

// Returns whether workflow lines contain any recognized risk signal, so an event-only workflow produces no pull_request_target warning.
function hasPullRequestTargetRiskContext(lines: readonly WorkflowLine[]): boolean {
  return pullRequestTargetRiskContext(lines).length > 0;
}

// Scans workflow lines for checkout, run steps, secret references and broad write permissions.
// Returns unique risk labels in stable sorted order for finding metadata. An empty list means no risk signal was recognised.
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

// Returns whether line signals write-all permissions or a write grant for a recognized scope, for the pull_request_target risk check.
function broadPermissionSignal(line: WorkflowLine): boolean {
  if (/^permissions:\s*write-all\b/i.test(line.trimmed)) {
    return true;
  }
  const scoped = line.trimmed.match(/^([a-z-]+):\s*write\b/i);
  return WRITE_PERMISSION_SCOPES.has(scoped?.[1] ?? "");
}

// Scans workflow lines for third-party action references and uses file for warning paths.
// Returns nothing and appends warnings to findings for refs outside the stable pinning contract of 40 hexadecimal characters.
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

// Returns the action path, owner, and ref from line's recognized external uses entry, or undefined when it is absent or unsupported.
// Local paths and owners actions or github return undefined because they are exempt from third-party pin checks.
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

// Returns whether action ref is exactly 40 hexadecimal characters, the required commit-pin form for third-party actions.
function isPinnedToFullSha(ref: string): boolean {
  return /^[0-9a-f]{40}$/i.test(ref);
}

// Checks run commands extracted from lines for a download piped to a shell. Uses file for the workflow's report path.
// Returns nothing and appends matching warnings to findings. YAML block parsing preserves a stable source anchor for each command.
function analyseRemoteShell(file: SourceFile, lines: readonly WorkflowLine[], findings: Finding[]): void {
  for (const command of runCommands(lines)) {
    if (isRemoteShellCommand(command.command)) {
      pushRemoteShellFinding(file, findings, command.line);
    }
  }
}

// Returns nothing and appends a workflow remote-shell warning to findings for a matched run command.
// Uses file for the report path and the supplied command line for a stable source anchor.
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

// Returns inline and block-scalar run commands with their source lines, or an empty list if none are recognized.
// Block bodies use trimmed lines, and workflow source order keeps remote-shell findings deterministic.
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

// Returns nothing. When line closes an active run block by indentation, appends its command if it has a start line and clears state.
// Otherwise leaves state and commands unchanged; after a flush, the caller considers line as a possible next command.
function flushClosedRunBlock(line: WorkflowLine, state: RunBlockState, commands: WorkflowCommand[]): void {
  if (state.indent !== undefined && line.indent <= state.indent) {
    flushRunBlock(state, commands);
  }
}

// Appends line's trimmed text to state.lines when it is deeper than the active run key; returns true if captured, false otherwise.
// False leaves state unchanged. The remote-shell check uses this normalized text, which can omit content after a space and hash.
function runBlockLine(line: WorkflowLine, state: RunBlockState): boolean {
  if (state.indent === undefined || line.indent <= state.indent) {
    return false;
  }
  state.lines.push(line.trimmed);
  return true;
}

// Returns nothing. Reads line as a run entry, resetting state for a block scalar or appending the inline value and line to commands.
// Blank, comment-only, and non-run lines leave state and commands unchanged.
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

// Appends state's pending block text and start line to commands, then removes its indentation and start line and clears its lines.
// Returns nothing. Missing indentation or startLine skips command emission and still clears state.
function flushRunBlock(state: RunBlockState, commands: WorkflowCommand[]): void {
  if (state.indent !== undefined && state.startLine) {
    commands.push({ command: state.lines.join("\n"), line: state.startLine });
  }
  delete state.indent;
  delete state.startLine;
  state.lines = [];
}

// Returns whether the run value in command matches the block scalar header pattern, including forms such as |-, >2, or |+4.
function isRunBlockScalar(command: string): boolean {
  return /^[|>](?:[+-]?\d*|\d*[+-]?)?\s*$/.test(command);
}

// Returns whether command text matches a curl or wget HTTP(S) download piped to sh, bash, or zsh, with optional sudo.
function isRemoteShellCommand(command: string): boolean {
  return /\b(?:curl|wget)\b[^|]*https?:\/\/[^|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b/i.test(command);
}

// Checks lines for named secret references only when the workflow declares pull_request_target. Uses file for finding paths.
// Returns nothing and appends at most one match per line to findings under the stable rule contract.
// Skips GITHUB_TOKEN and lines identified as unreachable for this event.
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

// Returns recognized event names from the top-level on key in the workflow lines.
// Reads scalar and simple flow declarations, plus indented block sequences and mappings. Event names elsewhere do not count as triggers.
// Returns an empty set when no event is recognized, so that the pull_request_target secret check is skipped.
function declaredWorkflowEvents(lines: readonly WorkflowLine[]): Set<string> {
  const events = new Set<string>();
  let eventIndent: number | undefined;
  let inOnBlock = false;
  for (const line of lines) {
    if (isCommentOrBlank(line)) {
      continue;
    }
    if (line.indent === 0) {
      const onKey = line.trimmed.match(/^["']?on["']?\s*:\s*(.*)$/);
      inOnBlock = onKey !== null && stripInlineComment(onKey[1] ?? "").trim() === "";
      eventIndent = undefined;
      if (onKey && !inOnBlock) {
        addFlowEvents(events, stripInlineComment(onKey[1] ?? "").trim());
      }
      continue;
    }
    if (!inOnBlock) {
      continue;
    }
    // The first nested line fixes the event level; deeper lines configure one event, such as its branches.
    eventIndent ??= line.indent;
    if (line.indent === eventIndent) {
      const event = line.trimmed.match(/^(?:-\s*)?["']?([A-Za-z_]+)["']?\s*(?::|$)/)?.[1];
      if (event) {
        events.add(event);
      }
    }
  }
  return events;
}

// Returns nothing and adds event names from declaration to events, skipping empty entries in the scalar or simple flow sequence or mapping.
function addFlowEvents(events: Set<string>, declaration: string): void {
  for (const flowEntry of declaration.replace(/^[[{]/, "").replace(/[\]}]$/, "").split(",")) {
    const event = (flowEntry.split(":")[0] ?? "").trim().replace(/^["']|["']$/g, "");
    if (event) {
      events.add(event);
    }
  }
}

// Returns the first name from a case-sensitive secrets.NAME match in trimmed line text, excluding GITHUB_TOKEN.
// Returning the name alone keeps the raw expression out of finding metadata.
// Returns undefined for blank or comment-only lines, no matching reference, or references only to GITHUB_TOKEN.
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

// Returns whether line's trimmed YAML text is empty or comment-only, allowing callers to skip it during text heuristics.
function isCommentOrBlank(line: WorkflowLine): boolean {
  return line.trimmed.length === 0 || line.trimmed.startsWith("#");
}

// Returns a workflow finding using file for the report path and input for the rule, line, message and evidence.
// Uses a stable security warning contract across workflow rules and omits the symbol when input supplies none or an empty string.
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
