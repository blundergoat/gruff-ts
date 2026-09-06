// Reads and writes `gruff-baseline.json`, and reconciles a fresh scan against the debt a user already reviewed.
//
// A baseline row stores one line-free identity and a count and nothing positional, so everyday reformatting never
// re-flags accepted debt, while a second occurrence beyond the reviewed count is still reported as new.
//
// Sensitive-data findings are counted here and never stored: withholding their identity is what stops a durable
// review from hiding a secret. A 0.5 baseline is refused with the command that carries its reviews forward.
import { readFileSync, realpathSync, statSync, writeFileSync } from "node:fs";
import { basename } from "node:path";
import { findingIdentities, TOOL_LANGUAGE, type FindingIdentity } from "./baseline-identity.ts";
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

/*
 * Writes the reviewed debt of this run: one row per identity, with sensitive findings counted and never stored.
 * Returns how many rows the file holds, which is what the report shows the user after a generate run.
 * Stable contract: rows are written in ascending identity order, so two identical runs produce one identical file.
 */
export function writeBaseline(path: string, findings: Finding[], declarationPosition?: (finding: Finding) => number): number {
  const document = baselineDocument(findings, declarationPosition);
  writeFileSync(path, `${JSON.stringify(document, null, 2)}\n`);
  return document.occurrences.length;
}

// Counts the secrets a generated baseline recorded without storing, so the run can report what it set aside.
// Stable contract: the count is derived from the same document a write would produce, so the two can never disagree.
export function sensitiveCountOf(findings: Finding[], declarationPosition?: (finding: Finding) => number): number {
  return baselineDocument(findings, declarationPosition).sensitive.counts.total;
}

/*
 * Applies a baseline to this run: hides the reviewed occurrences, keeps everything else, and says what moved.
 *
 * Findings are classified in the ratified order: a sensitive finding is never eligible, an identity over two
 * declarations is a collision that hides nothing, occurrences within the reviewed count are unchanged, and the
 * rest are new. The reviewed count is spent lowest line first, so two ports hide the same occurrences.
 * Stable contract: only an unchanged finding is hidden; a collision, a secret, and every new occurrence still fail the run.
 */
export function applyBaseline(path: string, findings: Finding[], declarationPosition?: (finding: Finding) => number): BaselineApplication {
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
 * Carries a 0.5 baseline's reviews into a new v3 file, leaving the original byte-identical.
 *
 * The reviews are re-identified from the current scan rather than translated, because a 0.5 digest names a line
 * and this one does not. A finding the 0.5 file never accepted stays visible.
 *
 * Stable contract: the input is only ever read, so a migration the user regrets leaves their 0.5 file to fall back to.
 * Throws when the input is missing, is not a 0.5 baseline, or resolves to the same file as the output, so the retreat path is never overwritten.
 */
export function migrateBaseline(inputPath: string, outputPath: string, findings: Finding[], declarationPosition?: (finding: Finding) => number): BaselineMigration {
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

/*
 * Refuses to write a baseline over a 0.5 file at the shared default path.
 *
 * All five ports write and auto-discover the same filename, so without this an ordinary upgrade-then-generate
 * destroys the 0.5 baseline that is the user's documented retreat path, before they know they need it.
 * Regenerating v3 over v3 is not destructive, because v3 is what the tool now reads.
 *
 * Throws when the default path already holds a file this version would not read and the user passed no `--force`.
 * Stable contract: only the shared default filename is protected, and only a file this version cannot read.
 */
export function requireOverwritableDefaultPath(outputPath: string, shouldForce: boolean): void {
  // Any other destination is the user's own choice of file, and any v3 file is what this version already reads.
  if (shouldForce || basename(outputPath) !== DEFAULT_BASELINE_FILENAME) {
    return;
  }
  const schemaVersion = existingSchemaVersion(outputPath);
  if (schemaVersion === undefined || schemaVersion === BASELINE_SCHEMA_VERSION) {
    return;
  }
  throw new Error(
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

// Builds the document a generated baseline writes, ordered so two identical runs produce one identical file.
// Stable contract: one row per identity, deterministic order, and no stored identity for any sensitive finding.
function baselineDocument(findings: Finding[], declarationPosition?: (finding: Finding) => number): BaselineDocument {
  const identities = findingIdentities(findings, declarationPosition);
  const rows = new Map<string, BaselineEntry>();
  const sensitiveByRule: Record<string, number> = {};

  findings.forEach((finding, index) => {
    const named = identities[index];
    // A sensitive finding is counted by rule and stored nowhere, so no row can ever hide a secret.
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

// Reads one v3 baseline, refusing a 0.5 layout, another port's file, and any row that could expire or leak.
// Throws on a 0.5 layout, an unknown schema, another port's file, or a row that could expire or leak, so a bad baseline fails closed.
function readBaselineDocument(path: string): BaselineDocument {
  const parsed = JSON.parse(readFileSync(path, "utf8")) as Partial<BaselineDocument> & { occurrences?: Array<Record<string, unknown>> };
  // A 0.5 file fails closed and names the command that carries its reviews forward, so nothing is silently dropped.
  if (parsed.schemaVersion === LEGACY_BASELINE_SCHEMA_VERSION) {
    throw new Error(
      `baseline ${path} is a 0.5 baseline; migrate it to a separate file with \`gruff-ts analyse --migrate-baseline ${path} --generate-baseline <new path>\`, the original is preserved`,
    );
  }
  if (parsed.schemaVersion !== BASELINE_SCHEMA_VERSION) {
    throw new Error(`unsupported baseline schema in ${path}`);
  }
  // A baseline names its writer, so another port's file is refused instead of reporting every row resolved.
  if (parsed.toolLanguage !== TOOL_LANGUAGE) {
    throw new Error(`baseline ${path} was written by ${parsed.toolLanguage ?? "an unnamed port"} and this run is ${TOOL_LANGUAGE}; baselines are not shared across languages`);
  }
  return { ...(parsed as BaselineDocument), occurrences: (parsed.occurrences ?? []).map(validatedRow) };
}

// Rebuilds one reviewed row, refusing anything that could expire on an edit or leak a finding's text.
// Throws when the identity is not the ratified digest shape, the count is below one, or a positional key is present.
function validatedRow(row: Record<string, unknown>, index: number): BaselineEntry {
  const identity = row.identity;
  // An identity that is not the ratified digest shape cannot have come from a generator, so the row is refused.
  if (typeof identity !== "string" || !/^[0-9a-f]{16}$/u.test(identity)) {
    throw new Error(`baseline occurrences[${index}].identity must be 16 lowercase hex characters`);
  }
  const count = row.count;
  // A count below one would mean a reviewed identity that suppresses nothing, which is a hand edit gone wrong.
  if (typeof count !== "number" || !Number.isInteger(count) || count < 1) {
    throw new Error(`baseline occurrences[${index}].count must be a positive integer`);
  }
  for (const forbidden of FORBIDDEN_OCCURRENCE_KEYS) {
    // A positional field is how a 0.5 baseline expired on every edit, so its presence fails the file.
    if (forbidden in row) {
      throw new Error(`baseline occurrences[${index}] carries forbidden key "${forbidden}"`);
    }
  }
  return { identity, count, ...optionalText(row, "ruleId"), ...optionalText(row, "path"), ...optionalText(row, "subject") };
}

// Reads one optional descriptive field, leaving it out entirely when the row never stored it.
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

// Buckets every eligible finding by identity, remembering the declarations and subjects each one covers.
// Stable contract: a sensitive finding joins no group, so no reviewed row can ever reach it.
function groupByIdentity(findings: Finding[], identities: Array<FindingIdentity | undefined>): Map<string, IdentityGroup> {
  const groups = new Map<string, IdentityGroup>();
  findings.forEach((finding, index) => {
    const named = identities[index];
    // A sensitive finding has no identity, so it joins no group and no reviewed row can ever reach it.
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

/*
 * Labels every finding, spending each identity's reviewed count on its lowest lines first.
 * The run is walked once in file order, so two ports hide the same occurrences for identical input rather than
 * merely the same number of them.
 * Stable contract: the run is walked in the ratified spend order, so two ports hide the same occurrences for identical input.
 */
function classify(findings: Finding[], identities: Array<FindingIdentity | undefined>, groups: Map<string, IdentityGroup>, reviewed: Map<string, BaselineEntry>): string[] {
  const statuses = findings.map(() => "new");
  const spentPerIdentity = new Map<string, number>();

  for (const index of spendOrder(findings)) {
    const named = identities[index];
    // Sensitive findings are labelled before any lookup, so no reviewed row can reach a secret.
    if (named === undefined) {
      statuses[index] = "notEligible";
      continue;
    }
    // One identity over two declarations cannot separate them, so neither is hidden and the run names both.
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

// Orders this run's findings by line then column, which is the ratified order a reviewed count is spent in.
// Stable contract: line then column, with an unlocated finding last, is the ratified order a reviewed count is spent in.
function spendOrder(findings: Finding[]): number[] {
  return findings
    .map((_, index) => index)
    .sort((left, right) => {
      const leftFinding = findings[left];
      const rightFinding = findings[right];
      return (leftFinding?.line ?? UNLOCATED_SPEND_LINE) - (rightFinding?.line ?? UNLOCATED_SPEND_LINE) || (leftFinding?.column ?? 0) - (rightFinding?.column ?? 0);
    });
}

// Finds every reviewed identity with fewer live occurrences than reviewed, which is debt the user has since fixed.
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

// Lists the identities that covered two declarations, so the run can name each one for the user.
function collidedIdentities(groups: Map<string, IdentityGroup>): BaselineCollision[] {
  return [...groups.entries()]
    .filter(([, group]) => group.declarations.size > 1)
    .map(([identity, group]) => ({ identity, ruleId: group.ruleId, path: group.path, subjects: group.subjects }));
}

// Refuses an output that is the input by spelling, resolved link target, or inode.
// Throws when the two paths are one file by spelling, symlink, or inode, which is what keeps the 0.5 input intact.
function requireDistinctPaths(inputPath: string, outputPath: string): void {
  const resolvedInput = resolvedFilePath(inputPath);
  // A symlink or a hard link would make the "different" output the same bytes, destroying the retreat path.
  if (resolvedInput === resolvedFilePath(outputPath) || sameInode(inputPath, outputPath)) {
    throw new Error(`migration output must be a different file from its input: ${inputPath}`);
  }
}

// Resolves a path through any symlink, falling back to the literal path when the file does not exist yet.
// The fallback is the ordinary case, not an error: a migration output normally does not exist until it is written.
function resolvedFilePath(path: string): string {
  try {
    return realpathSync(path);
  } catch {
    // The output usually does not exist yet, which is the ordinary case and not a failure.
    return path;
  }
}

// Reports whether two paths are one file on disk, which a hard link makes true even with different names.
function sameInode(inputPath: string, outputPath: string): boolean {
  try {
    const input = statSync(inputPath);
    const output = statSync(outputPath);
    return input.dev === output.dev && input.ino === output.ino;
  } catch {
    // A missing output is the ordinary case: nothing to collide with yet.
    return false;
  }
}

// Reads the rows of a 0.5 baseline, the only shape a migration accepts as its input.
// Throws when the input is not a 0.5 baseline, names more than one row container, or carries no row list at all.
// Stable contract: exactly one of the three 0.5 containers is accepted, because a file naming two of them migrates
// differently in different ports.
function legacyRows(path: string, contents: Buffer): Array<Record<string, unknown>> {
  const parsed = JSON.parse(contents.toString("utf8")) as Record<string, unknown>;
  if (parsed.schemaVersion !== LEGACY_BASELINE_SCHEMA_VERSION) {
    throw new Error(`migration input ${path} is not a 0.5 baseline`);
  }
  const present = LEGACY_ROW_CONTAINERS.filter((container) => Array.isArray(parsed[container]));
  if (present.length > 1) {
    throw new Error(`migration input ${path} carries more than one row container (${present.join(", ")}); a migration input must name exactly one`);
  }
  const rows = present.length === 1 ? parsed[present[0] as string] : undefined;
  if (!Array.isArray(rows)) {
    throw new Error(`migration input ${path} must carry an "entries" or "findings" list`);
  }
  return rows.filter((row): row is Record<string, unknown> => typeof row === "object" && row !== null);
}

/*
 * Keeps the current findings a 0.5 baseline had already accepted, matching only on fields that file stored.
 * A row is matched on its rule and path, narrowed by its symbol and message when it recorded them, and it accepts
 * as many occurrences as the file held. A finding the old baseline never covered stays visible.
 * Stable contract: acceptance is spent in the same deterministic order as a reviewed count, so every port carries the same reviews across.
 */
function acceptedByLegacy(rows: Array<Record<string, unknown>>, findings: Finding[]): Finding[] {
  const budget = new Map<string, number>();
  for (const row of rows) {
    const key = acceptanceKey(rowText(row, "ruleId"), rowText(row, "filePath") || rowText(row, "file"), rowText(row, "symbol"), rowText(row, "message"));
    budget.set(key, (budget.get(key) ?? 0) + 1);
  }
  // Lowest line first, so a row covering fewer occurrences than exist today accepts the same ones on every port.
  return spendOrder(findings)
    .map((index) => findings[index])
    .filter((finding): finding is Finding => finding !== undefined && canSpendLegacyBudget(budget, finding));
}

// Reports whether one 0.5 row still covers this finding, spending it when it does.
// Stable contract: the most specific stored shape is spent first, so a sparser 0.5 row never steals a narrower row's budget.
function canSpendLegacyBudget(budget: Map<string, number>, finding: Finding): boolean {
  const symbol = finding.symbol ?? "";
  // Try the most specific stored shape first, then the shapes a sparser 0.5 writer produced, so no debt is lost.
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

// Joins the fields a 0.5 row could narrow on into one key, so a row and a finding compare as whole shapes.
function acceptanceKey(ruleId: string, path: string, symbol: string, message: string): string {
  return [ruleId, path, symbol, message].join("\0");
}

// Reads one stored 0.5 field, treating an absent or non-text value as a field that row never narrowed on.
function rowText(row: Record<string, unknown>, key: string): string {
  const storedText = row[key];
  return typeof storedText === "string" ? storedText : "";
}
