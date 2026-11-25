// Saves reviewed findings for `analyse --generate-baseline` and loads those reviews for `analyse --baseline`.
//
// Moving code leaves a review in place. An extra occurrence beyond the reviewed count appears as new.
// Sensitive findings contribute counts only. Users upgrading a 0.5 file can carry their reviews forward with `--migrate-baseline`.
import { lstatSync, mkdtempSync, readFileSync, realpathSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { type DeclarationPositionResolver, findingIdentities, isBaselineEligible, TOOL_LANGUAGE, type FindingIdentity } from "./baseline-identity.ts";
import type { Finding } from "./types.ts";

// The family baseline this port writes and reads; a file naming anything else is refused rather than guessed at.
export const BASELINE_SCHEMA_VERSION = "gruff.baseline.v3";

// The one baseline name every port writes and auto-discovers, and therefore the one a generate must protect.
export const DEFAULT_BASELINE_FILENAME = "gruff-baseline.json";

// The 0.5 baseline a migration accepts as input; reading one for suppression fails closed and names the command.
export const LEGACY_BASELINE_SCHEMA_VERSION = "gruff.baseline.v1";

// Keys a v3 row may never carry; each one is a way a stored baseline could expire on an edit or leak a finding's text.
const FORBIDDEN_OCCURRENCE_KEYS = ["line", "endLine", "column", "message", "severity", "confidence"];

// Why a generated baseline stores no sensitive occurrence, written into the file so a reader meets the rule there.
const SENSITIVE_INELIGIBILITY_REASON =
  "Sensitive findings are never baselinable; they are counted here and stay visible until fixed or excluded with a reason.";

// Where a finding with no line sorts when a reviewed count is spent, so an unlocated occurrence is always spent last.
const UNLOCATED_SPEND_LINE = Number.MAX_SAFE_INTEGER;

// The three keys the five 0.5 writers used for their row list: go and py wrote findings, php wrote groups, and rs and
// ts wrote entries. A file naming two of them cannot be read the same way twice, so a migration refuses it.
const LEGACY_ROW_CONTAINERS = ["findings", "groups", "entries"] as const;

// The family ports a baseline may name as its writer (gruff-spec `contracts/core/baseline.v3.json`, search: `toolLanguage`).
const FAMILY_TOOL_LANGUAGES: ReadonlySet<string> = new Set(["go", "php", "py", "rs", "ts"]);

/*
 * One reviewed row: a line-free identity and how many occurrences of it the team signed off.
 * Matching reads the identity and the count and nothing else; the rule, path, and subject exist so a reviewer can
 * read the file.
 */
export interface BaselineEntry {
  identity: string;
  count: number;
  ruleId?: string;
  path?: string;
  subject?: string;
}

// One identity that covers two declarations, so neither of them can be hidden and the run names both subjects.
export interface BaselineCollision {
  identity: string;
  ruleId: string;
  path: string;
  subjects: string[];
}

/*
 * How one run met the baseline: what stays hidden, what the user must still act on, and what could not be told apart.
 * `absent` counts the reviewed occurrences that are gone, which is debt the user has since fixed.
 */
export interface BaselineCounts {
  new: number;
  unchanged: number;
  absent: number;
  collision: number;
  notEligible: number;
}

// The gated findings plus the accounting behind them; every collision becomes one diagnostic the user reads.
// Stable contract: `findings` is the gated set the user must act on, and every collision here suppressed nothing.
export interface BaselineApplication {
  findings: Finding[];
  /** What the baseline made of each finding handed in, in that order, so a caller can report a status per finding. */
  statuses: string[];
  counts: BaselineCounts;
  collisions: BaselineCollision[];
  resolved: BaselineEntry[];
  entries: number;
}

// What a migration wrote, so the command can tell the user what carried across from their 0.5 file.
export interface BaselineMigration {
  entries: number;
  accepted: number;
  sensitiveCounted: number;
}

// The whole baseline document, as written and as read back on the next run.
// Stable contract: this is the `gruff.baseline.v3` schema on disk; adding a positional field to a row would break every stored review.
interface BaselineDocument {
  schemaVersion: string;
  toolLanguage: string;
  generatedAt: string;
  occurrences: BaselineEntry[];
  sensitive: { eligible: false; reason: string; counts: { total: number; byRule: Record<string, number> } };
}

/**
 * Writes a timestamped baseline of the run's reviewed debt with one row per identity in stable ascending identity order.
 * Sensitive findings contribute to a count without an occurrence row.
 *
 * @param path - destination file to write or replace
 * @param findings - current findings to aggregate into baseline rows
 * @param declarationPosition - optional resolver for declaration positions. Omit it to rank by finding line.
 * @returns The number of occurrence rows written, or zero when no finding has an identity.
 * @throws {BaselineFileError} when the temporary write or replacement fails.
 */
export function writeBaseline(path: string, findings: Finding[], declarationPosition?: DeclarationPositionResolver): number {
  const document = baselineDocument(findings, declarationPosition);
  try {
    // Stage the replacement beside the destination so an interrupted write leaves the user's earlier baseline intact.
    const temporaryDirectory = mkdtempSync(join(dirname(path), ".gruff-baseline-"));
    try {
      const temporaryPath = join(temporaryDirectory, "baseline.json");
      writeFileSync(temporaryPath, `${JSON.stringify(document, null, 2)}\n`);
      renameSync(temporaryPath, path);
    } finally {
      rmSync(temporaryDirectory, { recursive: true, force: true });
    }
  } catch (error) {
    // A user may choose a baseline destination in a read-only checkout.
    throw new BaselineFileError(`baseline ${path} cannot be written: ${unreadableReason(error)}`);
  }
  return document.occurrences.length;
}

/**
 * Counts the secrets a generated baseline recorded without storing, so the run can report what it set aside.
 * Stable contract: the count is derived from the same document a write would produce, so the two can never disagree.
 *
 * @param findings - current findings to inspect for sensitive occurrences
 * @param declarationPosition - optional resolver for declaration positions; omit it to rank by finding line
 * @returns Total number of sensitive findings counted across all rules.
 */
export function sensitiveCountOf(findings: Finding[], declarationPosition?: DeclarationPositionResolver): number {
  return baselineDocument(findings, declarationPosition).sensitive.counts.total;
}

/**
 * Apply reviewed counts in stable location order so matching hides the same occurrences for identical inputs.
 * Hide unchanged occurrences only. Collisions and ineligible findings remain visible.
 *
 * @param path - baseline file to read and validate
 * @param findings - current findings to classify against reviewed counts
 * @param declarationPosition - optional resolver for declaration positions. Omit it to rank by finding line.
 * @returns Visible findings, per-input statuses, counts, collisions, resolved review rows and the baseline entry total.
 * @throws {BaselineFileError} - the baseline cannot be read or validated for this run.
 */
export function applyBaseline(path: string, findings: Finding[], declarationPosition?: DeclarationPositionResolver): BaselineApplication {
  const document = readBaselineDocument(path);
  const reviewed = new Map(document.occurrences.map((entry) => [entry.identity, entry]));
  const identities = findingIdentities(findings, declarationPosition);
  const groups = groupByIdentity(findings, identities);
  const statuses = classify(findings, identities, groups, reviewed);
  const resolved = resolvedSurplus(document.occurrences, groups, statuses);

  return {
    findings: findings.filter((_, index) => statuses[index] !== "unchanged"),
    statuses,
    counts: {
      new: statuses.filter((status) => status === "new").length,
      unchanged: statuses.filter((status) => status === "unchanged").length,
      absent: resolved.reduce((total, entry) => total + entry.count, 0),
      collision: statuses.filter((status) => status === "collision").length,
      notEligible: statuses.filter((status) => status === "notEligible").length,
    },
    collisions: collidedIdentities(groups),
    resolved,
    entries: document.occurrences.length,
  };
}

/**
 * Matches the legacy input's reviews against the current findings and writes their v3 identities to a separate output path.
 * The input is opened only for reading, and its contents are verified unchanged after writing.
 *
 * @param inputPath - legacy 0.5 baseline file to read without modifying
 * @param outputPath - separate destination path to write the migrated v3 baseline
 * @param findings - current findings eligible to inherit legacy reviews
 * @param declarationPosition - optional resolver for declaration positions; omit it to default to finding lines
 * @returns Counts of written occurrence rows, matched findings, and findings tallied in the sensitive summary.
 * @throws {BaselineFileError} - the paths name the same file or the legacy schema or row container is invalid
 * @throws {Error} - a file operation fails or the input bytes differ after the write
 */
export function migrateBaseline(inputPath: string, outputPath: string, findings: Finding[], declarationPosition?: DeclarationPositionResolver): BaselineMigration {
  requireDistinctPaths(inputPath, outputPath);
  let original: Buffer;
  try {
    original = readFileSync(inputPath);
  } catch (error) {
    // For example, `--migrate-baseline old.json` points to a file omitted from this checkout.
    throw new BaselineFileError(`migration input ${inputPath} cannot be read: ${unreadableReason(error)}`);
  }
  const accepted = acceptedByLegacy(legacyRows(inputPath, original), findings);
  const entries = writeBaseline(outputPath, accepted, declarationPosition);

  // The 0.5 file is the user's way back, so the migration proves it survived rather than assuming it did.
  if (!readFileSync(inputPath).equals(original)) {
    throw new Error(`migration changed its own input: ${inputPath}`);
  }

  return { entries, accepted: accepted.length, sensitiveCounted: sensitiveCountOf(accepted, declarationPosition) };
}

/**
 * Guard the shared default filename because regenerating after an upgrade could overwrite the legacy baseline needed for rollback.
 * Generation proceeds for an absent path or a baseline that can be read by this analyzer.
 *
 * @param outputPath - proposed baseline destination, checked only when it uses the shared default filename
 * @param shouldForce - explicit user permission to bypass the overwrite guard
 * @returns Nothing. Allows the caller to continue when the overwrite guard passes.
 * @throws {BaselineFileError} - force is off and the existing default path cannot be read as a current regular baseline file.
 */
export function requireOverwritableDefaultPath(outputPath: string, shouldForce: boolean): void {
  // An explicit force flag or a different filename bypasses the shared-default safeguard; compare case-insensitively for macOS/Windows paths.
  if (shouldForce || basename(outputPath).toLowerCase() !== DEFAULT_BASELINE_FILENAME) {
    return;
  }
  try {
    // A directory or symlink at the default filename needs an explicit overwrite decision from the user.
    if (!lstatSync(outputPath).isFile()) {
      throw new BaselineFileError(`baseline ${outputPath} is not a regular file`);
    }
    readBaselineDocument(outputPath);
  } catch (error) {
    // A project generating its first baseline has no previous review file to protect.
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return;
    }
    throw new BaselineFileError(`${unreadableReason(error)}; generating over it would destroy the retreat path. Pass --force to overwrite it or choose a different output path.`);
  }
}

/**
 * Builds a timestamped baseline document from the scan findings, with one row per identity in stable order.
 *
 * @param findings - scan findings to aggregate into baseline rows and sensitive counts
 * @param declarationPosition - optional resolver for declaration positions; without it, finding lines are used
 * @returns Timestamped baseline document with sorted occurrence rows and sensitive rule totals.
 */
function baselineDocument(findings: Finding[], declarationPosition?: DeclarationPositionResolver): BaselineDocument {
  const identities = findingIdentities(findings, declarationPosition);
  const rows = new Map<string, BaselineEntry>();
  const sensitiveByRule: Record<string, number> = {};

  // A review covers one occurrence for each eligible finding in the scan snapshot.
  findings.forEach((finding, index) => {
    const named = identities[index];
    // An absent identity leaves this finding visible on later runs.
    if (named === undefined) {
      // Sensitive findings still contribute to the category totals. The first finding for a rule starts at zero.
      if (!isBaselineEligible(finding)) {
        sensitiveByRule[finding.ruleId] = (sensitiveByRule[finding.ruleId] ?? 0) + 1;
      }
      return;
    }
    // The first occurrence creates a row. Later matches extend the same review count.
    const existing = rows.get(named.identity);
    rows.set(named.identity, {
      identity: named.identity,
      count: (existing?.count ?? 0) + 1,
      ruleId: finding.ruleId,
      path: finding.filePath,
      subject: named.subject,
    });
  });

  const total = Object.values(sensitiveByRule).reduce((sum, count) => sum + count, 0);
  return {
    schemaVersion: BASELINE_SCHEMA_VERSION,
    toolLanguage: TOOL_LANGUAGE,
    generatedAt: new Date().toISOString(),
    occurrences: [...rows.values()].sort((left, right) => left.identity.localeCompare(right.identity)),
    sensitive: {
      eligible: false,
      reason: SENSITIVE_INELIGIBILITY_REASON,
      counts: { total, byRule: Object.fromEntries(Object.entries(sensitiveByRule).sort(([left], [right]) => left.localeCompare(right))) },
    },
  };
}

/**
 * Signals a baseline that cannot be safely applied or written.
 *
 * For example, `analyse --baseline review.json` reports `baseline-error` and exits 2 if that review file contains broken JSON.
 * The CLI can then surface a file or migration error without applying any of its review rows.
 */
export class BaselineFileError extends Error {}

/**
 * Reads and validates the v3 baseline at path for this tool language, including every occurrence row.
 *
 * @param path - baseline file path to read and validate
 * @returns Validated baseline document with checked occurrence rows.
 * @throws {BaselineFileError} - the file is unreadable, malformed, from an unsupported schema or port, or contains an invalid row
 */
function readBaselineDocument(path: string): BaselineDocument {
  const parsed = parsedBaselineFile(path);
  // A 0.5 file fails closed and names the command that carries its reviews forward, so nothing is silently dropped.
  if (parsed.schemaVersion === LEGACY_BASELINE_SCHEMA_VERSION) {
    throw new BaselineFileError(
      `baseline ${path} is a 0.5 baseline; migrate it to a separate file with \`gruff-ts analyse --migrate-baseline ${path} --generate-baseline <new path>\`, the original is preserved`,
    );
  }
  // Reject files whose review format this version cannot interpret.
  if (parsed.schemaVersion !== BASELINE_SCHEMA_VERSION) {
    throw new BaselineFileError(`unsupported baseline schema in ${path}`);
  }
  // A baseline names its writer, so another port's file is refused instead of reporting every row resolved.
  if (parsed.toolLanguage !== TOOL_LANGUAGE) {
    throw new BaselineFileError(`baseline ${path} was written by ${writerName(parsed.toolLanguage)} and this run is ${TOOL_LANGUAGE}; baselines are not shared across languages`);
  }
  // A review with no entries can use an empty list. An omitted list cannot establish what was reviewed.
  if (!parsed.occurrences) {
    throw new BaselineFileError(`baseline ${path} occurrences must be a list`);
  }
  const occurrences = parsed.occurrences.map((row, index) => validatedRow(path, row, index));
  // A hand-edited duplicate would make the reviewed count for that finding ambiguous.
  if (new Set(occurrences.map((entry) => entry.identity)).size !== occurrences.length) {
    throw new BaselineFileError(`baseline ${path} contains a duplicate occurrence identity`);
  }
  return { ...(parsed as BaselineDocument), occurrences };
}

// A baseline file as parsed, before its rows are validated: every field may be missing and a row may be anything.
type ParsedBaselineFile = Omit<Partial<BaselineDocument>, "occurrences"> & { occurrences?: unknown[] };

/**
 * Reads and parses the baseline file at path as a JSON object, checking that its occurrence list is an array when present.
 * The caller still checks the schema, writer language, and individual rows before applying any review.
 *
 * @param path - baseline file path to read from disk and parse as JSON
 * @returns Parsed baseline object with unvalidated fields and optional occurrences list.
 * @throws {BaselineFileError} - reading or parsing fails, the root is not an object, or occurrences is present without an array
 */
function parsedBaselineFile(path: string): ParsedBaselineFile {
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    throw new BaselineFileError(`baseline ${path} cannot be read: ${unreadableReason(error)}`);
  }
  // `null`, a list or a bare value has no schema to read, so the file is refused before any field is.
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new BaselineFileError(`baseline ${path} must be a JSON object`);
  }
  const occurrences = (parsed as { occurrences?: unknown }).occurrences;
  // Rows are validated one by one, which needs a list to walk.
  if (occurrences !== undefined && !Array.isArray(occurrences)) {
    throw new BaselineFileError(`baseline ${path} occurrences must be a list`);
  }
  return parsed as ParsedBaselineFile;
}

/**
 * Turns a baseline read or parse error into diagnostic text, with a fixed reason for a missing file.
 * Replaces JSON syntax errors with a fixed reason because parser messages can quote file contents. Other error messages pass through.
 *
 * @param error - caught filesystem or JSON parse error to describe
 * @returns Sanitized diagnostic reason string for the failure.
 */
function unreadableReason(error: unknown): string {
  if ((error as { code?: unknown }).code === "ENOENT") {
    return "the file does not exist";
  }
  if (error instanceof SyntaxError) {
    return "the file is not valid JSON";
  }
  return error instanceof Error ? error.message : String(error);
}

/**
 * Names the port that wrote a refused baseline without quoting arbitrary file input.
 *
 * @param toolLanguage - raw toolLanguage field read from the baseline document
 * @returns Family port language name when recognized, or "an unrecognised port" otherwise.
 */
function writerName(toolLanguage: unknown): string {
  return typeof toolLanguage === "string" && FAMILY_TOOL_LANGUAGES.has(toolLanguage) ? toolLanguage : "an unrecognised port";
}

/**
 * Validates a candidate baseline row and returns the reviewed entry, copying only nonempty text for optional descriptions.
 *
 * @param path - baseline file path used to locate an invalid entry in diagnostics
 * @param candidate - raw parsed row value to validate
 * @param index - zero-based index of the candidate in occurrences for error reporting
 * @returns Normalized baseline entry containing identity, count, and any nonempty optional fields.
 * @throws {BaselineFileError} - the candidate is not an object row, its identity or count is invalid, or a forbidden key is present
 */
function validatedRow(path: string, candidate: unknown, index: number): BaselineEntry {
  // A row that is not an object has no identity to match, so the file is refused as written.
  if (typeof candidate !== "object" || candidate === null || Array.isArray(candidate)) {
    throw new BaselineFileError(`baseline ${path} occurrences[${index}] must be an object`);
  }
  const row = candidate as Record<string, unknown>;
  const identity = row.identity;
  // The baseline schema requires 16 lowercase hex characters so that reviewed rows share one digest format.
  if (typeof identity !== "string" || !/^[0-9a-f]{16}$/u.test(identity)) {
    throw new BaselineFileError(`baseline ${path} occurrences[${index}].identity must be 16 lowercase hex characters`);
  }
  const count = row.count;
  // A reviewed row needs a positive whole count to give it a usable suppression budget.
  if (typeof count !== "number" || !Number.isInteger(count) || count < 1) {
    throw new BaselineFileError(`baseline ${path} occurrences[${index}].count must be a positive integer`);
  }
  for (const forbidden of FORBIDDEN_OCCURRENCE_KEYS) {
    // Refuse positional and diagnostic fields to keep line numbers and raw diagnostic details out of the reviewed row.
    if (forbidden in row) {
      throw new BaselineFileError(`baseline ${path} occurrences[${index}] carries forbidden key "${forbidden}"`);
    }
  }
  return { identity, count, ...optionalText(row, "ruleId"), ...optionalText(row, "path"), ...optionalText(row, "subject") };
}

/**
 * Extracts an optional string field from a baseline row only when it contains nonempty text.
 *
 * @param row - parsed baseline row object to inspect
 * @param key - property name to read from the row
 * @returns Single-entry object with the field value, or an empty object so absent or empty fields are omitted.
 */
function optionalText(row: Record<string, unknown>, key: string): Record<string, string> {
  const storedText = row[key];
  return typeof storedText === "string" && storedText.length > 0 ? { [key]: storedText } : {};
}

// Every occurrence of one identity in this run, plus what it takes to judge them together.
interface IdentityGroup {
  indexes: number[];
  declarations: Set<string>;
  subjects: string[];
  ruleId: string;
  path: string;
}

/**
 * Groups current findings by stable baseline identity for matching and collision reporting.
 * Each group retains finding indexes, declaration keys, and distinct subjects.
 *
 * @param findings - current findings in scan order
 * @param identities - computed identity per finding in matching array order, or undefined when ineligible
 * @returns Map keyed by stable baseline identity containing each group's indexes, declarations, subjects, ruleId, and path.
 */
function groupByIdentity(findings: Finding[], identities: Array<FindingIdentity | undefined>): Map<string, IdentityGroup> {
  const groups = new Map<string, IdentityGroup>();
  findings.forEach((finding, index) => {
    const named = identities[index];
    // Findings without an identity stay outside the groups, so baseline review rows cannot hide them.
    if (named === undefined) {
      return;
    }
    const group = groups.get(named.identity) ?? { indexes: [], declarations: new Set<string>(), subjects: [], ruleId: finding.ruleId, path: finding.filePath };
    group.indexes.push(index);
    group.declarations.add(named.declarationKey);
    if (!group.subjects.includes(named.subject)) {
      group.subjects.push(named.subject);
    }
    groups.set(named.identity, group);
  });
  return groups;
}

/**
 * Spend reviewed counts in stable line and column order so that identical inputs cover the same occurrences.
 *
 * @param findings - current findings whose locations determine spend order
 * @param identities - identity per finding in input order, with undefined marking an ineligible occurrence
 * @param groups - identity groups used to detect claims spanning multiple declarations
 * @param reviewed - baseline counts by identity, with missing entries providing no allowance
 * @returns One status per finding in input order. Unchanged marks a covered occurrence, and other statuses keep it visible.
 */
function classify(findings: Finding[], identities: Array<FindingIdentity | undefined>, groups: Map<string, IdentityGroup>, reviewed: Map<string, BaselineEntry>): string[] {
  const statuses = findings.map(() => "new");
  const spentPerIdentity = new Map<string, number>();

  for (const index of spendOrder(findings)) {
    const named = identities[index];
    // A finding without an identity is ineligible, so a reviewed row cannot hide it.
    if (named === undefined) {
      statuses[index] = "notEligible";
      continue;
    }
    // An identity spanning multiple declarations is ambiguous, so every occurrence with that identity stays visible.
    if ((groups.get(named.identity)?.declarations.size ?? 0) > 1) {
      statuses[index] = "collision";
      continue;
    }
    const spent = spentPerIdentity.get(named.identity) ?? 0;
    statuses[index] = spent < (reviewed.get(named.identity)?.count ?? 0) ? "unchanged" : "new";
    spentPerIdentity.set(named.identity, spent + 1);
  }
  return statuses;
}

/**
 * Computes finding indexes in stable reviewed-count spend order, sorted by line then column.
 * A missing line uses the last-line sentinel, and a missing column sorts as zero.
 *
 * @param findings - current findings whose locations determine spend order
 * @returns Array of zero-based indexes into findings in deterministic spend order.
 */
function spendOrder(findings: Finding[]): number[] {
  return findings
    .map((_, index) => index)
    .sort((left, right) => {
      const leftFinding = findings[left];
      const rightFinding = findings[right];
      return (leftFinding?.line ?? UNLOCATED_SPEND_LINE) - (rightFinding?.line ?? UNLOCATED_SPEND_LINE) || (leftFinding?.column ?? 0) - (rightFinding?.column ?? 0);
    });
}

/**
 * Computes reviewed rows whose counts exceed current group sizes, with each count set to the number absent from this scan.
 * Collided identities are excluded; when an identity has no current group, its full reviewed count is resolved.
 *
 * @param entries - baseline entries from the stored review file
 * @param groups - current scan findings grouped by baseline identity
 * @param statuses - per-finding classification statuses used to detect collisions
 * @returns Copies of resolved baseline entries with counts reduced to the absent surplus.
 */
function resolvedSurplus(entries: BaselineEntry[], groups: Map<string, IdentityGroup>, statuses: string[]): BaselineEntry[] {
  return entries.flatMap((entry) => {
    const group = groups.get(entry.identity);
    // A collided identity is accounted for by its collision; counting it resolved would double-report it.
    if (group !== undefined && statuses[group.indexes[0] ?? 0] === "collision") {
      return [];
    }
    const surplus = entry.count - (group?.indexes.length ?? 0);
    return surplus > 0 ? [{ ...entry, count: surplus }] : [];
  });
}

/**
 * Builds diagnostic collision records for every identity group that spans multiple declarations.
 *
 * @param groups - current scan findings grouped by baseline identity
 * @returns Collision records containing each ambiguous identity's rule, path, and known subjects.
 */
function collidedIdentities(groups: Map<string, IdentityGroup>): BaselineCollision[] {
  return [...groups.entries()]
    .filter(([, group]) => group.declarations.size > 1)
    .map(([identity, group]) => ({ identity, ruleId: group.ruleId, path: group.path, subjects: group.subjects }));
}

/**
 * Protects the original baseline by verifying that the migration input and output paths refer to distinct files.
 * A new destination can pass the path check without an inode comparison.
 *
 * @param inputPath - existing legacy baseline file path
 * @param outputPath - proposed destination path for the migrated baseline
 * @returns Nothing. Allows migration to proceed when the paths are distinct.
 * @throws {BaselineFileError} - the input and output paths compare equal after resolution or have matching device and inode numbers.
 */
function requireDistinctPaths(inputPath: string, outputPath: string): void {
  const resolvedInput = resolvedFilePath(inputPath);
  // A symlink or a hard link would make the "different" output the same bytes, destroying the retreat path.
  if (resolvedInput === resolvedFilePath(outputPath) || sameInode(inputPath, outputPath)) {
    throw new BaselineFileError(`migration output must be a different file from its input: ${inputPath}`);
  }
}

/**
 * Resolves a migration path to its canonical filesystem location, falling back to the supplied spelling on failure.
 *
 * @param path - file path to canonicalize via the filesystem
 * @returns Canonical real path, or the original path when filesystem resolution fails.
 */
function resolvedFilePath(path: string): string {
  try {
    return realpathSync(path);
  } catch {
    // A new output may have no target yet, so the caller can still compare its spelling and check inode identity separately.
    return path;
  }
}

/**
 * Checks whether two paths refer to the same underlying file on disk, including via a hard link.
 *
 * @param inputPath - first file path to stat
 * @param outputPath - second file path to stat
 * @returns True when both paths share a device and inode, or false if either stat fails.
 */
function sameInode(inputPath: string, outputPath: string): boolean {
  try {
    const input = statSync(inputPath);
    const output = statSync(outputPath);
    return input.dev === output.dev && input.ino === output.ino;
  } catch {
    // A new output normally has no inode yet, leaving the caller's resolved-path comparison as the other alias check.
    return false;
  }
}

/**
 * Reads and validates the 0.5 review rows for `analyse --migrate-baseline`. An empty list carries forward zero reviews.
 * Invariant: a file with conflicting row lists leaves the user's previous reviews ambiguous, so migration requires exactly one list.
 *
 * @param path - legacy baseline file path used in error diagnostics
 * @param contents - raw file bytes already read from the legacy baseline
 * @returns Validated legacy row objects from the single row container.
 * @throws {BaselineFileError} when the input is not a valid 0.5 baseline with exactly one row container.
 */
function legacyRows(path: string, contents: Buffer): Array<Record<string, unknown>> {
  let parsed: Record<string, unknown> | null;
  try {
    parsed = JSON.parse(contents.toString("utf8")) as Record<string, unknown> | null;
  } catch (error) {
    // A legacy JSON file can contain a merge-conflict marker after a branch merge.
    throw new BaselineFileError(`migration input ${path} cannot be read: ${unreadableReason(error)}`);
  }
  // A null object or a newer file does not provide the 0.5 review format migration expects.
  if (parsed?.schemaVersion !== LEGACY_BASELINE_SCHEMA_VERSION) {
    throw new BaselineFileError(`migration input ${path} is not a 0.5 baseline`);
  }
  const present = LEGACY_ROW_CONTAINERS.filter((container) => Array.isArray(parsed[container]));
  // When two valid lists exist, the user must choose which list represents the reviews they want to keep.
  if (present.length > 1) {
    throw new BaselineFileError(`migration input ${path} carries more than one row container (${present.join(", ")}); a migration input must name exactly one`);
  }
  const rows = present.length === 1 ? parsed[present[0] as string] : undefined;
  // Missing review lists usually mean the wrong input file was supplied.
  if (!Array.isArray(rows)) {
    throw new BaselineFileError(`migration input ${path} must carry an "entries" or "findings" list`);
  }
  return rows.map((row: unknown, index) => {
    // Each review needs named fields. A blank list item cannot be matched to a finding.
    if (typeof row !== "object" || row === null || Array.isArray(row)) {
      throw new BaselineFileError(`migration input ${path} row ${index} must be an object`);
    }
    const entry = row as Record<string, unknown>;
    // Check both legacy path names and the optional details used to match a review.
    for (const key of ["ruleId", "filePath", "file", "symbol", "message"]) {
      // An omitted detail is valid. A number or null can accidentally broaden which current findings match.
      if (entry[key] !== undefined && typeof entry[key] !== "string") {
        throw new BaselineFileError(`migration input ${path} row ${index}.${key} must be a string`);
      }
    }
    return entry;
  });
}

// The fields of one 0.5 baseline row that decide which current finding inherits its review.
interface LegacyRowCriteria {
  ruleId: string;
  path: string;
  symbol: string;
  message: string;
  line?: number;
}

/**
 * Carries reviews forward from a 0.5 baseline: each old row can cover one current finding with the same rule and file.
 *
 * A row must also agree on any symbol and message it stored, and a row on the finding's own line is preferred.
 * Matching runs per file so the most findings keep a review, even when one row stored only a symbol and another only a message.
 *
 * @param rows - legacy occurrence rows that supply one unit of acceptance each
 * @param findings - current findings eligible to consume that acceptance
 * @returns Current findings covered by the legacy rows in stable spend order, or an empty list when none match.
 */
function acceptedByLegacy(rows: Array<Record<string, unknown>>, findings: Finding[]): Finding[] {
  const rowsByGroup = new Map<string, LegacyRowCriteria[]>();
  for (const row of rows) {
    const criteria = legacyRowCriteria(row);
    const groupKey = `${criteria.ruleId}\0${criteria.path}`;
    const group = rowsByGroup.get(groupKey) ?? [];
    group.push(criteria);
    rowsByGroup.set(groupKey, group);
  }
  const orderedIndices = spendOrder(findings);
  const findingsByGroup = new Map<string, number[]>();
  // Group current findings by rule and file in spend order, so each group is matched only against old rows for that same file.
  for (const findingIndex of orderedIndices) {
    const finding = findings[findingIndex];
    // spendOrder only returns positions inside the list; this guard satisfies the type checker.
    if (finding === undefined) {
      continue;
    }
    const groupKey = `${finding.ruleId}\0${finding.filePath}`;
    // A finding with no 0.5 row for its rule and file has no old review to inherit, so it stays new.
    if (!rowsByGroup.has(groupKey)) {
      continue;
    }
    const group = findingsByGroup.get(groupKey) ?? [];
    group.push(findingIndex);
    findingsByGroup.set(groupKey, group);
  }
  const matchedIndices = new Set<number>();
  // Match each rule-and-file group on its own, so one file's old reviews never cover another file's findings.
  for (const [groupKey, groupFindingIndices] of findingsByGroup) {
    const groupRows = rowsByGroup.get(groupKey) ?? [];
    // Collect every finding in this group that inherited a 0.5 review.
    for (const matched of matchLegacyGroup(groupFindingIndices, groupRows, findings)) {
      matchedIndices.add(matched);
    }
  }
  // Return matched findings in stable line/column spend order.
  return orderedIndices
    .filter((index) => matchedIndices.has(index))
    .map((index) => findings[index])
    .filter((finding): finding is Finding => finding !== undefined);
}

/**
 * Pairs findings with old 0.5 rows for one rule and file, giving each row to at most one finding, the same way on every run.
 *
 * First, findings still on their old row's line claim those rows.
 * Then the rest take any compatible row, moving earlier picks when that lets more findings keep a review without dropping any.
 *
 * @param findingIndices - finding indexes in stable spend order sharing one `(ruleId, path)` group
 * @param groupRows - legacy 0.5 rows sharing the same `(ruleId, path)` group
 * @param findings - full findings array indexed by `findingIndices`
 * @returns Finding indexes matched to distinct legacy rows in this group.
 */
function matchLegacyGroup(findingIndices: readonly number[], groupRows: readonly LegacyRowCriteria[], findings: readonly Finding[]): number[] {
  const exactLineRowsByFinding = findingIndices.map((findingIndex) => compatibleLegacyRows(findings[findingIndex], groupRows, true));
  const compatibleRowsByFinding = findingIndices.map((findingIndex) => compatibleLegacyRows(findings[findingIndex], groupRows, false));
  const rowOwner = new Array<number>(groupRows.length).fill(-1);
  const matchedFindingSlots = new Set<number>();

  // Pass 1: claim exact-line matches first so unchanged occurrences keep their own reviewed rows.
  for (let slot = 0; slot < findingIndices.length && matchedFindingSlots.size < groupRows.length; slot += 1) {
    // A finding still on its old row's line claims that row before any looser match can take it.
    if ((exactLineRowsByFinding[slot]?.length ?? 0) > 0
      && tryAugmentLegacyMatch(slot, exactLineRowsByFinding, rowOwner, new Uint8Array(groupRows.length))) {
      matchedFindingSlots.add(slot);
    }
  }
  // Pass 2: match remaining findings (rearranging earlier picks when needed) so the most findings keep a review.
  // Both passes stop once every old row has an owner, so surplus findings in a large file never start a search that cannot succeed.
  for (let slot = 0; slot < findingIndices.length && matchedFindingSlots.size < groupRows.length; slot += 1) {
    // A finding without an exact-line row takes any compatible row; earlier picks may move to other rows so more findings fit.
    if (!matchedFindingSlots.has(slot) && tryAugmentLegacyMatch(slot, compatibleRowsByFinding, rowOwner, new Uint8Array(groupRows.length))) {
      matchedFindingSlots.add(slot);
    }
  }
  return [...matchedFindingSlots].flatMap((slot) => {
    const findingIndex = findingIndices[slot];
    return findingIndex === undefined ? [] : [findingIndex];
  });
}

/**
 * Tries to give one finding an old row, moving other findings to their own spare rows when that frees one up.
 * Updates `rowOwner` and `visitedRows` in place.
 *
 * @param slot - finding slot index in the current `(ruleId, path)` group
 * @param compatibleRowsBySlot - ordered compatible legacy-row indexes for each finding slot; an empty list leaves the finding unmatched
 * @param rowOwner - mutable mapping from legacy-row index to owning finding slot (or `-1` if free)
 * @param visitedRows - per-attempt visited flags preventing cycles in the augmenting search
 * @returns True if a compatible row was assigned (directly or by moving earlier picks); otherwise false.
 */
function tryAugmentLegacyMatch(
  slot: number,
  compatibleRowsBySlot: ReadonlyArray<readonly number[]>,
  rowOwner: number[],
  visitedRows: Uint8Array,
): boolean {
  // A free compatible row is taken straight away, so a large group of interchangeable rows never needs a deep search.
  for (const rowIndex of compatibleRowsBySlot[slot] ?? []) {
    // Claim the first unvisited compatible row that no other finding owns yet.
    if (visitedRows[rowIndex] !== 1 && (rowOwner[rowIndex] ?? -1) === -1) {
      visitedRows[rowIndex] = 1;
      rowOwner[rowIndex] = slot;
      return true;
    }
  }
  // Try the finding's compatible old rows, most specific first.
  for (const rowIndex of compatibleRowsBySlot[slot] ?? []) {
    // Each row is tried once per search, which stops two findings from swapping the same row forever.
    if (visitedRows[rowIndex] === 1) {
      continue;
    }
    visitedRows[rowIndex] = 1;
    const owner = rowOwner[rowIndex] ?? -1;
    // Take a free row, or move the row's current finding to another row it fits, so both findings keep a review.
    if (owner === -1 || tryAugmentLegacyMatch(owner, compatibleRowsBySlot, rowOwner, visitedRows)) {
      rowOwner[rowIndex] = slot;
      return true;
    }
  }
  return false;
}

/**
 * Lists legacy row indexes compatible with `finding` in stable deterministic order (descending specificity score, then declaration order).
 *
 * @param finding - current finding to compare against group legacy rows; `undefined` matches no rows
 * @param groupRows - legacy rows in the same `(ruleId, path)` group; an empty list returns no matches
 * @param requireExactLine - when true, keeps only rows whose stored numeric `line` equals `finding.line`
 * @returns Compatible row indexes sorted by descending specificity score, tie-broken by declaration order, or an empty list when none match.
 */
function compatibleLegacyRows(finding: Finding | undefined, groupRows: readonly LegacyRowCriteria[], requireExactLine: boolean): number[] {
  // A position without a finding matches no rows.
  if (finding === undefined) {
    return [];
  }
  const scored: Array<{ rowIndex: number; score: number }> = [];
  // Score every old row for this rule and file against the finding.
  for (const [rowIndex, row] of groupRows.entries()) {
    const score = legacyMatchScore(row, finding, requireExactLine);
    // Keep only rows whose stored symbol, message and line agree with this finding.
    if (score !== undefined) {
      scored.push({ rowIndex, score });
    }
  }
  return scored.sort((left, right) => right.score - left.score || left.rowIndex - right.rowIndex).map((entry) => entry.rowIndex);
}

/**
 * Computes a deterministic compatibility score for one legacy row against a finding, or undefined when incompatible.
 * Stable ordering: `symbol+message` (6) > `symbol` (4) > `message` (2) > `rule+path` (0), with `+1` for an exact line match.
 *
 * @param row - parsed 0.5 legacy row criteria
 * @param finding - current finding being tested for compatibility
 * @param requireExactLine - when true, rejects rows without an exact line match to `finding.line`
 * @returns Non-negative specificity score when compatible, or undefined when symbol, message, or required line differs.
 */
function legacyMatchScore(row: LegacyRowCriteria, finding: Finding, requireExactLine: boolean): number | undefined {
  const symbol = finding.symbol ?? "";
  // An old row that stored a symbol only covers findings in that same symbol.
  if (row.symbol.length > 0 && row.symbol !== symbol) {
    return undefined;
  }
  // An old row that stored a message only covers findings with exactly that message.
  if (row.message.length > 0 && row.message !== finding.message) {
    return undefined;
  }
  const isExactLine = row.line !== undefined && finding.line === row.line;
  // In the exact-line pass, a row stored for another line is left for the second pass.
  if (requireExactLine && !isExactLine) {
    return undefined;
  }
  const baseScore = (row.symbol.length > 0 ? 4 : 0) + (row.message.length > 0 ? 2 : 0);
  return baseScore + (isExactLine ? 1 : 0);
}

/**
 * Extracts normalized matching criteria from one validated 0.5 legacy row, retaining positive integer `line` when present.
 *
 * @param row - validated raw 0.5 row object
 * @returns Normalized criteria carrying ruleId, path, symbol, message, and optional positive integer line.
 */
function legacyRowCriteria(row: Record<string, unknown>): LegacyRowCriteria {
  const rawLine = row.line;
  return {
    ruleId: rowText(row, "ruleId"),
    path: rowText(row, "filePath") || rowText(row, "file"),
    symbol: rowText(row, "symbol"),
    message: rowText(row, "message"),
    ...(typeof rawLine === "number" && Number.isInteger(rawLine) && rawLine > 0 ? { line: rawLine } : {}),
  };
}

/**
 * Reads an optional string field from a legacy baseline row with an empty-string fallback.
 *
 * @param row - legacy baseline row object to inspect
 * @param key - property name to read from the row
 * @returns String value of the field, or empty string when absent or non-string.
 */
function rowText(row: Record<string, unknown>, key: string): string {
  const storedText = row[key];
  return typeof storedText === "string" ? storedText : "";
}
