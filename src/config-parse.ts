// Config parsing layer: the zero-dependency YAML-subset parser, the file reader, the shared
// user-facing suggestion strings, and the value-narrowing helpers. Split out of `config.ts` so the
// config semantics module (defaults, validation, profile resolution) stays under the size budget and
// so both `config.ts` and the profile resolver can read files without a circular import. This module
// depends only on Node IO and `ConfigLoadError`; it never imports `config.ts` or `profiles.ts`.
import { readFileSync } from "node:fs";
import { extname } from "node:path";
import { ConfigLoadError } from "./config-load-error.ts";

// Two common suggestion strings reused across the validators. Hoisted out so a future doc-link
// or wording tweak lands in one place instead of N throw sites.
const SUGGEST_INIT_FORCE = "Run `gruff-ts init --force` to regenerate the config from current defaults (preserves your `paths.ignore` and `minimumSeverity:` entries).";
const SUGGEST_EDIT_CONFIG = "Edit `.gruff-ts.yaml` to use a valid value, or run `gruff-ts init --force` to regenerate from defaults.";

const YAML_KEYWORD_SCALARS = new Map<string, boolean | null>([
  ["true", true],
  ["false", false],
  ["null", null],
  ["~", null],
]);
const YAML_NUMBER_SCALAR = /^-?(?:0|[1-9]\d*)(?:\.\d+)?$/;

// Result of one scalar parser attempt. `isMatched: false` lets the dispatcher fall through to the
// next parser instead of mistaking `undefined` for a successfully parsed null value.
interface ParsedYamlScalar {
  isMatched: boolean;
  value: unknown;
}

const UNMATCHED_YAML_SCALAR: ParsedYamlScalar = { isMatched: false, value: undefined };

/*
 * Reads YAML or JSON config and rejects unknown extensions. Raw IO failures (e.g. `--config <path>`
 * pointing at a missing file) and JSON parse failures are rewrapped as ConfigLoadError so the CLI
 * surface stays uniform - a bare ENOENT or SyntaxError would otherwise bypass the formatted
 * "gruff-ts: config error" stderr path in `runWithConfigErrorHandling`.
 *
 * Throws ConfigLoadError when: the file is missing (ENOENT), the contents are not valid JSON, the
 * YAML subset rejects the file (see parseYamlConfig), or the top-level value is not a mapping.
 */
function parseConfigFile(path: string): Record<string, unknown> {
  const source = readConfigSource(path);
  const extension = extname(path).toLowerCase();
  const parsed = parseConfigSource(source, extension, path);
  const config = objectValue(parsed);
  if (!config) {
    throw new ConfigLoadError(`Config file must contain an object with .yaml, .yml, or .json extension: ${path}`, SUGGEST_INIT_FORCE);
  }
  return config;
}

/*
 * Reads the raw config bytes. Explicit `--config <path>` skips the `defaultConfigPath` existence
 * check, so a typo here would otherwise dump a raw Node stack. Throws ConfigLoadError on ENOENT
 * with a user-actionable suggestion; rethrows every other filesystem error unchanged so an
 * unexpected IO failure still surfaces its native stack for debugging.
 */
function readConfigSource(path: string): string {
  try {
    return readFileSync(path, "utf8").replace(/^\uFEFF/, "");
  } catch (error) {
    if ((error as NodeJS.ErrnoException | null)?.code === "ENOENT") {
      throw new ConfigLoadError(`Config file not found: ${path}.`, "Pass --config with an existing path, or omit the flag to use the default lookup.");
    }
    throw error;
  }
}

// Routes to the YAML subset parser or the native JSON parser. Wraps `JSON.parse`'s SyntaxError so
// a malformed `.gruff.json` surfaces through the same ConfigLoadError channel as YAML failures
// (parseYamlConfig already throws ConfigLoadError on its own malformed inputs).
function parseConfigSource(source: string, extension: string, path: string): unknown {
  if (extension === ".yaml" || extension === ".yml") {
    return parseYamlConfig(source);
  }
  if (extension !== ".json") {
    return undefined;
  }
  try {
    return JSON.parse(source) as unknown;
  } catch (error) {
    if (error instanceof SyntaxError) {
      throw new ConfigLoadError(`Config file is not valid JSON: ${error.message} (${path}).`, SUGGEST_EDIT_CONFIG);
    }
    throw error;
  }
}

// One non-blank, comment-stripped YAML line. `indent` is the column count (spaces only - tabs are
// rejected upstream) and is the sole signal used to nest blocks. `content` is whitespace-trimmed.
interface YamlLine {
  indent: number;
  content: string;
}

// Mutable cursor through `lines`. Stored on the heap so recursive `parseYamlBlock` calls share
// position state instead of threading an index argument.
interface YamlParser {
  lines: YamlLine[];
  index: number;
}

/*
 * Custom YAML parser that intentionally supports only a documented subset (mappings, arrays,
 * scalars, inline `[]`/`{}`) - keeps gruff free of a yaml dependency. Throws on malformed input
 * because silently misparsing config would produce wrong findings and a stable but broken baseline.
 */
function parseYamlConfig(source: string): Record<string, unknown> {
  const parser = { lines: yamlLines(source), index: 0 };
  const parsedDocument = parser.lines.length === 0 ? {} : parseYamlBlock(parser, parser.lines[0]?.indent ?? 0);
  const config = objectValue(parsedDocument);
  if (!config) {
    throw new ConfigLoadError("Config YAML must contain a mapping object.", SUGGEST_INIT_FORCE);
  }
  return config;
}

// Dispatch entry for a block. Empty (no lines at this indent) returns `{}`; sequence lines lead
// into the array parser; everything else is an object/mapping.
function parseYamlBlock(parser: YamlParser, indent: number): unknown {
  const line = parser.lines[parser.index];
  if (!line || line.indent < indent) {
    return {};
  }
  return isYamlArrayLine(line) ? parseYamlArray(parser, line.indent) : parseYamlObject(parser, line.indent);
}

// Walks mapping entries at one indent level, stopping when the next line dedents or switches to
// sequence form. Throws on unexpected indent so a missed key isn't silently swallowed.
function parseYamlObject(parser: YamlParser, indent: number): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  while (parser.index < parser.lines.length) {
    const line = parser.lines[parser.index];
    if (!line || line.indent < indent || isYamlArrayLine(line)) {
      break;
    }
    assertYamlIndent(line, indent);
    addYamlObjectEntry(parser, indent, line, result);
  }
  return result;
}

// Inline scalar after the colon → leaf value; bare key → recurse into nested block. Keys are
// unquoted so `"foo"` and `foo` produce the same result key.
function addYamlObjectEntry(parser: YamlParser, indent: number, line: YamlLine, result: Record<string, unknown>): void {
  const [rawKey, rawValue] = yamlKeyValuePair(line.content);
  const scalarText = rawValue.trim();
  parser.index += 1;
  result[unquoteYaml(rawKey.trim())] = scalarText.length > 0 ? parseYamlScalar(scalarText) : parseNestedYamlValue(parser, indent, {});
}

// Block-style YAML sequence. Inline `[...]` arrays are handled by `parseYamlCollectionScalar`;
// this walks the `- item` lines and recurses into nested values for empty `-` openers.
function parseYamlArray(parser: YamlParser, indent: number): unknown[] {
  const result: unknown[] = [];
  while (parser.index < parser.lines.length) {
    const line = parser.lines[parser.index];
    if (!line || line.indent < indent || !isYamlArrayLine(line)) {
      break;
    }
    assertYamlIndent(line, indent);
    result.push(parseYamlArrayItem(parser, indent, line));
  }
  return result;
}

// Three branches: bare `-` (recurse for nested), `- key: value` (mapping item), `- scalar`.
// Bare-dash items return null when the nested block is empty so the array entry isn't elided.
function parseYamlArrayItem(parser: YamlParser, indent: number, line: YamlLine): unknown {
  const itemText = line.content === "-" ? "" : line.content.slice(2).trim();
  parser.index += 1;
  if (itemText.length === 0) {
    return parseNestedYamlValue(parser, indent, null);
  }

  const pair = splitYamlKeyValue(itemText);
  return pair ? parseYamlArrayMappingItem(parser, indent, pair) : parseYamlScalar(itemText);
}

// `- key: value` form: the first key is on the dash line, subsequent keys live as a nested object.
// Mirrors the inline-vs-nested split of `addYamlObjectEntry`.
function parseYamlArrayMappingItem(parser: YamlParser, indent: number, pair: [string, string]): Record<string, unknown> {
  const [rawKey, rawValue] = pair;
  const scalarText = rawValue.trim();
  return {
    [unquoteYaml(rawKey.trim())]: scalarText.length > 0 ? parseYamlScalar(scalarText) : parseNestedYamlValue(parser, indent, {}),
  };
}

// Returns the nested block if the next line indents further, otherwise the caller's `fallback`.
// `fallback` is `{}` for mappings (empty value → empty object) and `null` for sequences.
function parseNestedYamlValue(parser: YamlParser, indent: number, fallback: unknown): unknown {
  const nestedIndent = parser.lines[parser.index]?.indent;
  return nestedIndent !== undefined && nestedIndent > indent ? parseYamlBlock(parser, nestedIndent) : fallback;
}

/*
 * Throws when a mapping line has no `:` separator - the parser cannot recover, and a silent skip
 * would hide a real config typo from the user.
 */
function yamlKeyValuePair(content: string): [string, string] {
  const pair = splitYamlKeyValue(content);
  if (!pair) {
    throw new ConfigLoadError(`Invalid YAML mapping line: "${content}".`, SUGGEST_INIT_FORCE);
  }
  return pair;
}

// `- ` or bare `-` only - two-dash openers and ambiguous variants are not sequence entries.
function isYamlArrayLine(line: YamlLine): boolean {
  return line.content.startsWith("- ") || line.content === "-";
}

/*
 * Throws when a line is indented more than expected at this scope. Without this guard, a stray
 * indent would silently produce a sub-mapping and the user's config would mean something different.
 */
function assertYamlIndent(line: YamlLine, indent: number): void {
  if (line.indent > indent) {
    throw new ConfigLoadError(`Invalid YAML indentation near "${line.content}".`, SUGGEST_INIT_FORCE);
  }
}

/*
 * Pre-pass that drops blank/comment lines and rejects tab-indented input. Tabs are forbidden
 * because mixing them with spaces is the canonical YAML footgun, so the parser throws rather than
 * guess at the user's intent.
 */
function yamlLines(source: string): YamlLine[] {
  const lines: YamlLine[] = [];
  for (const rawLine of source.replace(/\r\n/g, "\n").split("\n")) {
    const withoutComment = stripYamlComment(rawLine).trimEnd();
    if (withoutComment.trim().length === 0) {
      continue;
    }
    const indentText = withoutComment.match(/^\s*/)?.[0] ?? "";
    if (indentText.includes("\t")) {
      throw new ConfigLoadError("Tabs are not supported in gruff YAML config indentation.", SUGGEST_INIT_FORCE);
    }
    lines.push({ indent: indentText.length, content: withoutComment.trimStart() });
  }
  return lines;
}

// Drops `# comment` text but only when the `#` is not inside quotes - `foo: "a # b"` keeps the
// comment-like substring as part of the string value, matching YAML semantics.
function stripYamlComment(line: string): string {
  const commentIndex = firstUnquotedIndex(line, (character, index) => character === "#" && (index === 0 || /\s/.test(line[index - 1] ?? "")));
  return commentIndex === undefined ? line : line.slice(0, commentIndex);
}

// Finds the first `:<space>` outside quotes. Required because a quoted value can legitimately
// contain `:` (`url: "https://..."`) and the parser must not split at the first occurrence.
function splitYamlKeyValue(mappingText: string): [string, string] | undefined {
  const separatorIndex = firstUnquotedIndex(mappingText, (character, index) => {
    const next = mappingText[index + 1];
    return character === ":" && (!next || /\s/.test(next));
  });
  return separatorIndex === undefined ? undefined : [mappingText.slice(0, separatorIndex), mappingText.slice(separatorIndex + 1)];
}

// Tries each scalar parser in order; the first to claim a match wins. Bare strings are the
// fallback so callers never end up with `undefined` for a non-empty scalar.
function parseYamlScalar(scalarText: string): unknown {
  const trimmed = scalarText.trim();
  for (const parser of [parseYamlCollectionScalar, parseYamlQuotedScalar, parseYamlKeywordScalar, parseYamlNumberScalar]) {
    const parsedScalar = parser(trimmed);
    if (parsedScalar.isMatched) {
      return parsedScalar.value;
    }
  }
  return trimmed;
}

// Parses YAML collection scalar from source text.
function parseYamlCollectionScalar(trimmed: string): ParsedYamlScalar {
  if (trimmed === "[]") {
    return matchedYamlScalar([]);
  }
  if (trimmed === "{}") {
    return matchedYamlScalar({});
  }
  if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
    return matchedYamlScalar(parseYamlInlineArray(trimmed));
  }
  return UNMATCHED_YAML_SCALAR;
}

// `"..."` or `'...'` wrapped. Calls `unquoteYaml` so the resulting value matches what a real YAML
// engine would produce; matched-state flag separates "empty quoted string" from "not a quoted scalar".
function parseYamlQuotedScalar(trimmed: string): ParsedYamlScalar {
  if (isQuotedYaml(trimmed)) {
    return matchedYamlScalar(unquoteYaml(trimmed));
  }
  return UNMATCHED_YAML_SCALAR;
}

// Recognises `true`/`false`/`null`/`~` (case-insensitive). The keyword table is shared so the
// parser produces consistent JS values (`null` instead of the string "null").
function parseYamlKeywordScalar(trimmed: string): ParsedYamlScalar {
  const normalized = trimmed.toLowerCase();
  if (YAML_KEYWORD_SCALARS.has(normalized)) {
    return matchedYamlScalar(YAML_KEYWORD_SCALARS.get(normalized) ?? null);
  }
  return UNMATCHED_YAML_SCALAR;
}

// Strict numeric pattern - no octals, no special floats. Numbers that don't fit fall through to
// bare-string handling, so `0xFF` or `1e10` stay as strings rather than producing surprising values.
function parseYamlNumberScalar(trimmed: string): ParsedYamlScalar {
  if (YAML_NUMBER_SCALAR.test(trimmed)) {
    return matchedYamlScalar(Number(trimmed));
  }
  return UNMATCHED_YAML_SCALAR;
}

// Returns a "matched" result with the parsed value, distinguishing real matches from the shared
// `UNMATCHED_YAML_SCALAR` sentinel used by every parser that failed.
function matchedYamlScalar(scalarValue: unknown): ParsedYamlScalar {
  return { isMatched: true, value: scalarValue };
}

// Inline `[a, b, c]` arrays. Items are split on unquoted commas and each item recurses through
// `parseYamlScalar` so nested types resolve correctly.
function parseYamlInlineArray(arrayText: string): unknown[] {
  const inner = arrayText.slice(1, -1).trim();
  if (inner.length === 0) {
    return [];
  }
  return splitYamlInlineItems(inner).map((item) => parseYamlScalar(item));
}

// Quote-aware split on commas. Treating a quoted comma as a separator would corrupt entries like
// `["a, b", "c"]` - same reason `splitYamlKeyValue` is also quote-aware.
function splitYamlInlineItems(itemsText: string): string[] {
  const items: string[] = [];
  let start = 0;
  for (const index of unquotedIndexes(itemsText, ",")) {
    items.push(itemsText.slice(start, index).trim());
    start = index + 1;
  }
  items.push(itemsText.slice(start).trim());
  return items;
}

// Lexer state for the YAML quote walkers. `isEscaped` only matters inside `"..."` quotes because
// single-quoted YAML strings use `''` doubling rather than backslash escapes.
interface QuoteScanState {
  quote: string | undefined;
  isEscaped: boolean;
}

// Walks `value` calling `predicate` only at quote-free positions. Used by both the comment
// stripper and the colon splitter to keep quoted text inert.
function firstUnquotedIndex(sourceText: string, predicate: (character: string, index: number) => boolean): number | undefined {
  for (const index of unquotedIndexes(sourceText)) {
    const character = sourceText[index] ?? "";
    if (predicate(character, index)) {
      return index;
    }
  }
  return undefined;
}

// All quote-free positions in `value`, optionally filtered by a specific character. The two-mode
// shape lets the same lexer feed both `firstUnquotedIndex` and the inline-array splitter.
function unquotedIndexes(sourceText: string, expectedCharacter?: string): number[] {
  const indexes: number[] = [];
  const state: QuoteScanState = { quote: undefined, isEscaped: false };
  for (let index = 0; index < sourceText.length; index += 1) {
    const character = sourceText[index] ?? "";
    if (consumeQuotedCharacter(character, state)) {
      continue;
    }
    if (isYamlQuote(character)) {
      state.quote = character;
      continue;
    }
    if (!expectedCharacter || character === expectedCharacter) {
      indexes.push(index);
    }
  }
  return indexes;
}

// Returns true and mutates `state` when the character was inside a quoted region. The escape
// handling is double-quote-only because YAML single-quote strings have no `\` escapes.
function consumeQuotedCharacter(character: string, state: QuoteScanState): boolean {
  if (!state.quote) {
    return false;
  }
  if (state.quote === "\"" && character === "\\" && !state.isEscaped) {
    state.isEscaped = true;
    return true;
  }
  if (character === state.quote && !state.isEscaped) {
    state.quote = undefined;
  }
  state.isEscaped = false;
  return true;
}

// Single and double quotes only - YAML allows backticks elsewhere but they're not part of the
// supported subset here, and the parser would have to reject them anyway.
function isYamlQuote(character: string): boolean {
  return character === "\"" || character === "'";
}

// Both endpoints must use the same quote character; mismatched openers/closers are treated as
// plain text rather than a parse error so a single stray quote in user prose doesn't fail the config.
function isQuotedYaml(scalarText: string): boolean {
  return scalarText.length >= 2 && ((scalarText.startsWith("\"") && scalarText.endsWith("\"")) || (scalarText.startsWith("'") && scalarText.endsWith("'")));
}

// Removes quotes and decodes the supported escapes: `''` doubling for single quotes, and `\n`,
// `\r`, `\t`, `\"`, `\\` for double quotes. Anything else passes through unchanged so the parser
// reports the user's exact intent rather than mangling unknown escape sequences.
function unquoteYaml(scalarText: string): string {
  if (!isQuotedYaml(scalarText)) {
    return scalarText;
  }
  const quote = scalarText[0];
  const body = scalarText.slice(1, -1);
  if (quote === "'") {
    return body.replace(/''/g, "'");
  }
  return body.replace(/\\(["\\nrt])/g, (_match, escaped: string) => {
    if (escaped === "n") {
      return "\n";
    }
    if (escaped === "r") {
      return "\r";
    }
    if (escaped === "t") {
      return "\t";
    }
    return escaped;
  });
}

// Type narrowing for `Record<string, unknown>`. Returns undefined (not null) for non-objects so
// the caller can use the standard optional-chaining pattern through the rest of the config layer.
function objectValue(configValue: unknown): Record<string, unknown> | undefined {
  return typeof configValue === "object" && configValue !== null && !Array.isArray(configValue) ? (configValue as Record<string, unknown>) : undefined;
}

// Returns the array or an empty array - never undefined - so callers can iterate without a guard.
function arrayValue(configValue: unknown): unknown[] {
  return Array.isArray(configValue) ? configValue : [];
}

// String type narrowing. Exported so other modules can share a single string-test that matches
// the config-side semantics (rejects non-string truthy values like numbers).
function isString(configValue: unknown): configValue is string {
  return typeof configValue === "string";
}

export { arrayValue, isString, objectValue, parseConfigFile, SUGGEST_EDIT_CONFIG, SUGGEST_INIT_FORCE };
