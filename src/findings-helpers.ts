// Shared low-level finding factories and string utilities used across every rule pass. Kept as
// a leaf module (no rule-specific imports) so block/line/comment/project rule modules can depend
// on it without forming a cycle.
import { execFileSync } from "node:child_process";
import { basename } from "node:path";
import type { SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import type { Finding, Pillar, Severity } from "./types.ts";

// Input bundle for `finding()` — the lowest-cost finding factory. Captures everything the caller
// must supply for a line-anchored Finding; shared defaults (confidence "high", empty metadata)
// are added inside the builder so callers don't repeat them at every rule site.
export interface LineFindingArgs {
  ruleId: string;
  message: string;
  file: SourceFile;
  line: number;
  severity: Severity;
  pillar: Pillar;
}

// Cheapest finding factory: line-anchored, no symbol, confidence "high". Produces the
// (ruleId, filePath, line) tuple that every per-line emission relies on — this tuple is the
// stable fingerprint that drives baseline matching and report determinism.
export function finding(args: LineFindingArgs): Finding {
  return makeFinding({ ruleId: args.ruleId, message: args.message, filePath: args.file.displayPath, line: args.line, severity: args.severity, pillar: args.pillar, confidence: "high" });
}

// Diff-aware discovery: uses `execFileSync` (not `execSync`) so the `mode` value is passed as
// an argv entry and a malicious value cannot inject shell metacharacters. Spawns `git diff`,
// reads the output, and normalises path separators to `/` for clean display-path joins.
export function changedFiles(mode: string): Set<string> {
  const args = ["diff", "--name-only"];
  if (mode === "staged") {
    args.push("--cached");
  } else if (mode !== "working-tree" && mode !== "unstaged") {
    args.push(mode);
  }
  return new Set(execFileSync("git", args, { encoding: "utf8" }).split(/\r?\n/).filter(Boolean).map((line) => line.replaceAll("\\", "/")));
}

// Strips directory and trailing extension. Used by `naming.class-file-mismatch` so the exported
// symbol name and the file stem normalise to the same shape — both sides must agree on this
// canonical form for the deterministic comparison to be meaningful.
export function fileBaseName(path: string): string {
  return basename(path).replace(/\.[^.]+$/, "");
}

// Lowercase-and-strip-separators canonical form. Treats `FooBar`, `foo_bar`, and `foo-bar` as
// the same key so naming rules can compare across case styles without baking the convention in.
export function normalizedIdentifier(identifier: string): string {
  return identifier.replace(/[^A-Za-z0-9]/g, "").toLowerCase();
}

// Inserts a space at every camelCase boundary, then splits on any non-alphanumeric run. Acronym
// runs (`HTTPServer`) stay intact because the inserted boundary is `lower → Upper`, not
// `Upper → Upper` — callers comparing word lists rely on this to keep tokens aligned.
export function splitIdentifierWords(identifier: string): string[] {
  return identifier
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .split(/[^A-Za-z0-9]+/)
    .map((word) => word.toLowerCase())
    .filter(Boolean);
}

// Counts newlines before the offset to get a 0-based line number. `Math.max(0, …)` guards against
// negative input — callers occasionally pass `match.index` which is typed as optional.
export function lineOffset(source: string, index: number): number {
  return source.slice(0, Math.max(0, index)).split("\n").length - 1;
}

// Two-stage detector for `waste.commented-out-code`: first checks for a leading code keyword
// (`const`, `function`, `if`, etc.), then falls back to a `foo()` / `foo.bar()` call shape.
// The keyword list is intentionally conservative to avoid flagging prose that starts with `if`.
export function isCommentedOutCode(line: string): boolean {
  const trimmed = line.trim();
  if (!trimmed.startsWith("//")) {
    return false;
  }
  const uncommented = trimmed.replace(/^\/\/+\s?/, "");
  if (/^(const|let|var|function|class|interface|type|enum|import|export|if|for|while|switch|return|throw|await)\b/.test(uncommented)) {
    return true;
  }
  return /^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)?\s*\([^)]*\);?$/.test(uncommented);
}

// Lowercase membership test against the configured banned-names set. Drives the
// `naming.identifier-quality` predicate so the rule stays a single Set lookup per identifier.
export function isGenericName(name: string, bannedNames: Set<string>): boolean {
  return bannedNames.has(name.toLowerCase());
}

// Escapes the standard regex metacharacters so user-supplied strings (rule IDs, identifiers,
// paths) can be embedded in dynamic patterns without altering their meaning. Hot path —
// used by every rule that builds a per-source RegExp.
export function escapeRegex(source: string): string {
  return source.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
