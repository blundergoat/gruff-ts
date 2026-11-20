// Reads and writes `gruff-baseline.json`, and reconciles a fresh scan against the debt a user already reviewed.
//
// A baseline row stores one line-free identity and a count and nothing positional, so everyday reformatting never
// re-flags accepted debt, while a second occurrence beyond the reviewed count is still reported as new.
//
// Sensitive-data findings are counted here and never stored: withholding their identity is what stops a durable
// review from hiding a secret. A 0.5 baseline is refused with the command that carries its reviews forward.
import { readFileSync, realpathSync, statSync, writeFileSync } from "node:fs";
import { basename } from "node:path";
import { type DeclarationPositionResolver, findingIdentities, TOOL_LANGUAGE, type FindingIdentity } from "./baseline-identity.ts";
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
 */
export function writeBaseline(path: string, findings: Finding[], declarationPosition?: DeclarationPositionResolver): number {
  const document = baselineDocument(findings, declarationPosition);
  writeFileSync(path, `${JSON.stringify(document, null, 2)}\n`);
  return document.occurrences.length;
}

// Counts the secrets a generated baseline recorded without storing, so the run can report what it set aside.
// Stable contract: the count is derived from the same document a write would produce, so the two can never disagree.
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

/*
 * Matches the legacy input's reviews against the current findings and writes their v3 identities to a separate output path.
 * The input is opened only for reading. The optional resolver supplies declaration positions and defaults to finding lines.
 * Returns counts of written rows, matched findings, and findings tallied in the sensitive summary.
 *
 * @throws {BaselineFileError} - the paths name the same file or the legacy schema or row container is invalid
 * @throws {SyntaxError} - the input is malformed JSON
 * @throws {Error} - a file operation fails or the input bytes differ after the write
 */
export function migrateBaseline(inputPath: string, outputPath: string, findings: Finding[], declarationPosition?: DeclarationPositionResolver): BaselineMigration {
  requireDistinctPaths(inputPath, outputPath);
  const original = readFileSync(inputPath);
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
 * Stable contract: generation proceeds here when the file declares the current schema or the guard finds no schema string.
 *
 * @param outputPath - proposed baseline destination, checked only when it uses the shared default filename
 * @param shouldForce - explicit user permission to bypass the overwrite guard
 * @returns Nothing. Allows the caller to continue when the overwrite guard passes.
 * @throws {BaselineFileError} - force is off and the default-named output declares a different schema version.
 */
export function requireOverwritableDefaultPath(outputPath: string, shouldForce: boolean): void {
  // An explicit force flag or a different filename bypasses the shared-default safeguard.
  if (shouldForce || basename(outputPath) !== DEFAULT_BASELINE_FILENAME) {
    return;
  }
  const schemaVersion = existingSchemaVersion(outputPath);
  if (schemaVersion === undefined || schemaVersion === BASELINE_SCHEMA_VERSION) {
    return;
  }
  throw new BaselineFileError(
    `${outputPath} is a "${schemaVersion}" baseline, not "${BASELINE_SCHEMA_VERSION}"; generating over it would destroy the retreat path. ` +
      `Migrate it with \`gruff-ts analyse --migrate-baseline ${outputPath} --generate-baseline <new path>\`, or pass --force to overwrite it`,
  );
}

/*
 * Reads the schema string of whatever already sits at a path.
 * Nothing there, or nothing this can classify, reads as undefined: that is the ordinary first-generate case, and a
 * file gruff cannot parse is left alone rather than destroyed on a guess. The fallback recovers from a read or
 * parse failure rather than throwing, because a missing file is the normal state, not an error.
 */
function existingSchemaVersion(outputPath: string): string | undefined {
  try {
    const existing = JSON.parse(readFileSync(outputPath, "utf8")) as { schemaVersion?: unknown };
    return typeof existing.schemaVersion === "string" ? existing.schemaVersion : undefined;
  } catch {
    // The fallback is the ordinary case: a first generate has no file to protect.
    return undefined;
  }
}

// Builds a timestamped baseline document from the scan findings, with one row per identity in stable order.
// The optional resolver supplies declaration positions for identity. Without it, finding lines are used.
function baselineDocument(findings: Finding[], declarationPosition?: DeclarationPositionResolver): BaselineDocument {
  const identities = findingIdentities(findings, declarationPosition);
  const rows = new Map<string, BaselineEntry>();
  const sensitiveByRule: Record<string, number> = {};

  findings.forEach((finding, index) => {
    const named = identities[index];
    // A finding without an identity contributes to the sensitive tally by rule and gets no row that could hide it.
    if (named === undefined) {
      sensitiveByRule[finding.ruleId] = (sensitiveByRule[finding.ruleId] ?? 0) + 1;
      return;
    }
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
 * A baseline file that cannot be applied as written: missing, unreadable, malformed, a 0.5 layout, another port's file,
 * or a row that could expire or leak. A direct analysis reports it as a fatal `baseline-error` diagnostic and exits 2;
 * any other error from applying a baseline is a defect and keeps its stack.
 */
export class BaselineFileError extends Error {}

// Returns the v3 baseline at path for this tool language after validating its occurrence rows.
// A missing occurrence list becomes an empty review, so the baseline covers no findings.
// @throws {BaselineFileError} - the file is unreadable, malformed, from an unsupported schema or port, or contains an invalid row
function readBaselineDocument(path: string): BaselineDocument {
  const parsed = parsedBaselineFile(path);
  // A 0.5 file fails closed and names the command that carries its reviews forward, so nothing is silently dropped.
  if (parsed.schemaVersion === LEGACY_BASELINE_SCHEMA_VERSION) {
    throw new BaselineFileError(
      `baseline ${path} is a 0.5 baseline; migrate it to a separate file with \`gruff-ts analyse --migrate-baseline ${path} --generate-baseline <new path>\`, the original is preserved`,
    );
  }
  if (parsed.schemaVersion !== BASELINE_SCHEMA_VERSION) {
    throw new BaselineFileError(`unsupported baseline schema in ${path}`);
  }
  // A baseline names its writer, so another port's file is refused instead of reporting every row resolved.
  if (parsed.toolLanguage !== TOOL_LANGUAGE) {
    throw new BaselineFileError(`baseline ${path} was written by ${writerName(parsed.toolLanguage)} and this run is ${TOOL_LANGUAGE}; baselines are not shared across languages`);
  }
  return { ...(parsed as BaselineDocument), occurrences: (parsed.occurrences ?? []).map((row, index) => validatedRow(path, row, index)) };
}

// A baseline file as parsed, before its rows are validated: every field may be missing and a row may be anything.
type ParsedBaselineFile = Omit<Partial<BaselineDocument>, "occurrences"> & { occurrences?: unknown[] };

// Returns the baseline file at path as a JSON object, checking that its occurrence list is an array when present.
// The caller still checks the schema, writer language, and individual rows before applying any review.
// @throws {BaselineFileError} - reading or parsing fails, the root is not an object, or occurrences is present without an array
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

// Turns a baseline read or parse error into diagnostic text, with a fixed reason for a missing file.
// Replaces JSON syntax errors with a fixed reason because parser messages can quote file contents. Other error messages pass through.
function unreadableReason(error: unknown): string {
  if ((error as { code?: unknown }).code === "ENOENT") {
    return "the file does not exist";
  }
  if (error instanceof SyntaxError) {
    return "the file is not valid JSON";
  }
  return error instanceof Error ? error.message : String(error);
}

// Names the port that wrote a refused baseline without quoting the file: a family port by its language, and any other
// value, or none, as an unrecognised port.
function writerName(toolLanguage: unknown): string {
  return typeof toolLanguage === "string" && FAMILY_TOOL_LANGUAGES.has(toolLanguage) ? toolLanguage : "an unrecognised port";
}

// Returns the reviewed entry for a candidate row, copying only nonempty text for its optional descriptions.
// The baseline path and row index locate an invalid entry in the diagnostic.
// @throws {BaselineFileError} - the candidate is not an object row, its identity or count is invalid, or a forbidden key is present
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

// Returns the requested row field for copying when it contains nonempty text, or an empty object so it is omitted.
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

// Takes current findings and their identities in matching array order and returns groups keyed by stable baseline identity.
// Each group retains finding indexes, declaration keys and distinct subjects for matching and collision reporting.
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

// Returns indexes into the findings in stable reviewed-count order, by line then column.
// A missing line uses the last-line sentinel, and a missing column sorts as zero.
function spendOrder(findings: Finding[]): number[] {
  return findings
    .map((_, index) => index)
    .sort((left, right) => {
      const leftFinding = findings[left];
      const rightFinding = findings[right];
      return (leftFinding?.line ?? UNLOCATED_SPEND_LINE) - (rightFinding?.line ?? UNLOCATED_SPEND_LINE) || (leftFinding?.column ?? 0) - (rightFinding?.column ?? 0);
    });
}

// Returns copies of reviewed rows whose counts exceed the current group sizes, with each count set to the number absent from this scan.
// The current finding statuses identify collisions, whose reviewed rows are excluded. With no current group, the full reviewed count is resolved.
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

// Returns a diagnostic record for each identity group covering multiple declarations, with the rule, path, and known subjects.
function collidedIdentities(groups: Map<string, IdentityGroup>): BaselineCollision[] {
  return [...groups.entries()]
    .filter(([, group]) => group.declarations.size > 1)
    .map(([identity, group]) => ({ identity, ruleId: group.ruleId, path: group.path, subjects: group.subjects }));
}

// Protects the original baseline by checking the migration input path against the proposed output path.
// Returns nothing when the check passes. A new destination can pass the path check without an inode comparison.
// @throws {BaselineFileError} - the input and output paths compare equal after resolution or have matching device and inode numbers.
function requireDistinctPaths(inputPath: string, outputPath: string): void {
  const resolvedInput = resolvedFilePath(inputPath);
  // A symlink or a hard link would make the "different" output the same bytes, destroying the retreat path.
  if (resolvedInput === resolvedFilePath(outputPath) || sameInode(inputPath, outputPath)) {
    throw new BaselineFileError(`migration output must be a different file from its input: ${inputPath}`);
  }
}

// Returns the canonical migration path, or the supplied spelling when the filesystem cannot resolve it.
function resolvedFilePath(path: string): string {
  try {
    return realpathSync(path);
  } catch {
    // A new output may have no target yet, so the caller can still compare its spelling and check inode identity separately.
    return path;
  }
}

// Returns true if the input and output share a device and inode, including through a hard link, or false if either stat fails.
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

// Reads the rows of a 0.5 baseline, the only shape a migration accepts as its input.
// Throws when the input is not a 0.5 baseline, names more than one row container, or carries no row list at all.
// Stable contract: exactly one of the three 0.5 containers is accepted, because a file naming two of them migrates
// differently in different ports.
// @throws {BaselineFileError} when the parsed input is not a 0.5 baseline or has no row container or more than one, or {SyntaxError} when the input is not JSON.
function legacyRows(path: string, contents: Buffer): Array<Record<string, unknown>> {
  const parsed = JSON.parse(contents.toString("utf8")) as Record<string, unknown>;
  if (parsed.schemaVersion !== LEGACY_BASELINE_SCHEMA_VERSION) {
    throw new BaselineFileError(`migration input ${path} is not a 0.5 baseline`);
  }
  const present = LEGACY_ROW_CONTAINERS.filter((container) => Array.isArray(parsed[container]));
  if (present.length > 1) {
    throw new BaselineFileError(`migration input ${path} carries more than one row container (${present.join(", ")}); a migration input must name exactly one`);
  }
  const rows = present.length === 1 ? parsed[present[0] as string] : undefined;
  if (!Array.isArray(rows)) {
    throw new BaselineFileError(`migration input ${path} must carry an "entries" or "findings" list`);
  }
  return rows.filter((row): row is Record<string, unknown> => typeof row === "object" && row !== null);
}

/**
 * Carry reviews forward from a 0.5 baseline. Match by rule and path, using symbol and message when the old row stored them.
 *
 * @param rows - legacy occurrence rows that supply one unit of acceptance each
 * @param findings - current findings eligible to consume that acceptance
 * @returns Current findings covered by the legacy counts in stable spend order, or an empty list when none match.
 */
function acceptedByLegacy(rows: Array<Record<string, unknown>>, findings: Finding[]): Finding[] {
  const budget = new Map<string, number>();
  for (const row of rows) {
    const key = acceptanceKey(rowText(row, "ruleId"), rowText(row, "filePath") || rowText(row, "file"), rowText(row, "symbol"), rowText(row, "message"));
    budget.set(key, (budget.get(key) ?? 0) + 1);
  }
  // Spend limited counts by line then column so a partially covered set resolves to the same occurrences for the same inputs.
  return spendOrder(findings)
    .map((index) => findings[index])
    .filter((finding): finding is Finding => finding !== undefined && canSpendLegacyBudget(budget, finding));
}

// Reports whether one 0.5 row still covers this finding, spending it when it does.
// Stable contract: the most specific stored shape is spent first, so a sparser 0.5 row never steals a narrower row's budget.
function canSpendLegacyBudget(budget: Map<string, number>, finding: Finding): boolean {
  const symbol = finding.symbol ?? "";
  // If both single-field shapes can cover this finding, spend the symbol match and leave the message match available.
  for (const candidate of [
    acceptanceKey(finding.ruleId, finding.filePath, symbol, finding.message),
    acceptanceKey(finding.ruleId, finding.filePath, symbol, ""),
    acceptanceKey(finding.ruleId, finding.filePath, "", finding.message),
    acceptanceKey(finding.ruleId, finding.filePath, "", ""),
  ]) {
    const remaining = budget.get(candidate) ?? 0;
    if (remaining > 0) {
      budget.set(candidate, remaining - 1);
      return true;
    }
  }
  return false;
}

// Returns a legacy match key from the rule and file path, with an empty symbol or message leaving that part of the match unrestricted.
function acceptanceKey(ruleId: string, path: string, symbol: string, message: string): string {
  return [ruleId, path, symbol, message].join("\0");
}

// Returns the requested legacy row field as text, using an empty string for a missing or non-text value so matching can use its fallback.
function rowText(row: Record<string, unknown>, key: string): string {
  const storedText = row[key];
  return typeof storedText === "string" ? storedText : "";
}
