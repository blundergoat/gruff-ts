// Reads the JSON and supported YAML syntax used by project settings and profiles.
//
// When a user passes `--config`, this layer turns the file into values the settings loader can validate.
// Syntax errors tell the user which part of the file to edit before trying the command again.
import { readFileSync } from "node:fs";
import { extname } from "node:path";
import { ConfigLoadError } from "./config-load-error.ts";

// Two common suggestion strings reused across the validators. Hoisted out so a future doc-link
// or wording tweak lands in one place instead of N throw sites.
const SUGGEST_INIT_FORCE = "Run `gruff-ts init --force` to regenerate the config from current defaults (preserves your `paths.ignore` and `failOn:` entries).";
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

/**
 * Reads YAML or JSON config so that runWithConfigErrorHandling can present missing or malformed configs as CLI usage errors.
 *
 * @param path - File selected by --config <path> or default lookup. Its extension determines the parser.
 * @param shownPath - Name used in diagnostics and error envelopes. Defaults to path.
 * @returns The parsed top-level configuration mapping.
 * @throws {ConfigLoadError} - The file is missing, has an unsupported extension, fails parsing, or does not contain a mapping.
 * @throws {Error} - Other filesystem read errors propagate unchanged.
 */
function parseConfigFile(path: string, shownPath: string = path): Record<string, unknown> {
  const source = readConfigSource(path, shownPath);
  const extension = extname(path).toLowerCase();
  const parsed = parseConfigSource(source, extension, shownPath);
  const config = objectValue(parsed);
  if (!config) {
    throw new ConfigLoadError(`Config file must contain an object with .yaml, .yml, or .json extension: ${shownPath}`, SUGGEST_INIT_FORCE);
  }
  return config;
}

/**
 * Reads config text and gives users a path-selection hint if the file is missing.
 *
 * @param path - Filesystem path to read.
 * @param shownPath - Path label to display if the file is missing.
 * @returns Decoded UTF-8 config text with any leading byte order mark removed.
 * @throws {ConfigLoadError} - When the file does not exist.
 * @throws {Error} - Propagates other filesystem read failures unchanged.
 */
function readConfigSource(path: string, shownPath: string): string {
  try {
    return readFileSync(path, "utf8").replace(/^\uFEFF/, "");
  } catch (error) {
    if ((error as NodeJS.ErrnoException | null)?.code === "ENOENT") {
      throw new ConfigLoadError(`Config file not found: ${shownPath}.`, "Pass --config with an existing path, or omit the flag to use the default lookup.");
    }
    throw error;
  }
}

// Parses config text as YAML or JSON according to its file extension and returns the parsed value.
// An unsupported extension yields undefined so the caller can reject the file.
// The display path identifies the file in invalid JSON errors, which use the same CLI error channel as YAML errors.
// @throws {ConfigLoadError} - For invalid JSON syntax or input rejected by the YAML parser.
// @throws {Error} - Propagates other JSON parser errors unchanged.
function parseConfigSource(source: string, extension: string, shownPath: string): unknown {
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
      throw new ConfigLoadError(`Config file is not valid JSON: ${error.message} (${shownPath}).`, SUGGEST_EDIT_CONFIG);
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

/**
 * Parses the supported YAML configuration subset of mappings, sequences and scalar values.
 *
 * @param source - Config text to split into YAML lines and parse.
 * @returns The top-level mapping. Blank or comment-only input yields an empty mapping.
 * @throws {ConfigLoadError} - For a non-mapping root, a missing mapping separator, excess indentation or tabs in retained line indentation.
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

// Returns an empty mapping when the YAML cursor has no next line or its indent is below the supplied minimum.
// Otherwise the next line sets the block indent and selects a sequence or mapping, advancing the cursor through that block.
function parseYamlBlock(parser: YamlParser, indent: number): unknown {
  const line = parser.lines[parser.index];
  if (!line || line.indent < indent) {
    return {};
  }
  return isYamlArrayLine(line) ? parseYamlArray(parser, line.indent) : parseYamlObject(parser, line.indent);
}

// Returns the mapping at the supplied indent and advances the YAML cursor through its entries and values.
// A dedent or sequence line ends the mapping. If no entry was consumed, the result is an empty object.
// An over-indented mapping line raises ConfigLoadError so a misaligned entry cannot be read at this level.
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

// Reads one key and its value so the settings loader can validate a user's YAML mapping.
//
// An empty value with no indented settings represents an empty mapping. Quoting a key keeps the same meaning.
// @throws {ConfigLoadError} when the mapping contains an invalid or duplicate key.
function addYamlObjectEntry(parser: YamlParser, indent: number, line: YamlLine, result: Record<string, unknown>): void {
  const [rawKey, rawValue] = yamlKeyValuePair(line.content);
  const key = unquoteYaml(rawKey.trim());
  // Two copies of `failOn` could come from a config merge. Ask the user to reconcile them before scanning.
  if (Object.hasOwn(result, key)) {
    throw new ConfigLoadError(`Duplicate configuration key ${JSON.stringify(key)}.`, SUGGEST_EDIT_CONFIG);
  }
  const scalarText = rawValue.trim();
  parser.index += 1;
  // A key followed by an indented block, such as `failOn:`, gets its settings from those lines.
  Object.defineProperty(result, key, {
    value: scalarText.length > 0 ? parseYamlScalar(scalarText) : parseNestedYamlValue(parser, indent, {}),
    enumerable: true,
    configurable: true,
    writable: true,
  });
}

// Returns the block sequence at the supplied indent and advances the YAML cursor through its items and nested values.
// A dedent or non-sequence line ends the block. If no item was consumed, the result is an empty array.
// An over-indented sequence item raises ConfigLoadError. Inline arrays are handled by parseYamlCollectionScalar.
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

// Parses the YAML sequence item on line, using indent as the dash column to distinguish a nested value.
// Advances parser past the current line and any continuation lines it consumes.
// Returns a nested value, a mapping for - key: value, or a scalar. A bare dash with no deeper block returns null so that its slot is kept.
function parseYamlArrayItem(parser: YamlParser, indent: number, line: YamlLine): unknown {
  const itemText = line.content === "-" ? "" : line.content.slice(2).trim();
  parser.index += 1;
  if (itemText.length === 0) {
    return parseNestedYamlValue(parser, indent, null);
  }

  const pair = splitYamlKeyValue(itemText);
  return pair ? parseYamlArrayMappingItem(parser, indent, pair) : parseYamlScalar(itemText);
}

// Returns the sequence item's mapping, starting from the key and value pair on its dash line.
// Uses the dash indent to find nested values and sibling keys, advancing the YAML cursor through those lines.
// A blank first value with no deeper block becomes an empty object.
function parseYamlArrayMappingItem(parser: YamlParser, indent: number, pair: [string, string]): Record<string, unknown> {
  const [rawKey, rawValue] = pair;
  const scalarText = rawValue.trim();
  const mappingItem: Record<string, unknown> = {
    [unquoteYaml(rawKey.trim())]: scalarText.length > 0 ? parseYamlScalar(scalarText) : parseNestedYamlValue(parser, indent, {}),
  };
  addYamlArrayItemSiblingKeys(parser, indent, mappingItem);
  return mappingItem;
}

/**
 * Reads sibling keys at the first continuation's indentation so that YAML entries such as sensitiveExclusions: can span lines.
 *
 * @param parser - YAML cursor positioned after the item's first entry
 * @param indent - indentation of the item's dash line, which continuations must exceed
 * @param mappingItem - mapping that receives the sibling entries
 * @returns - nothing. Adds the sibling entries and advances the cursor past them, if present.
 */
function addYamlArrayItemSiblingKeys(parser: YamlParser, indent: number, mappingItem: Record<string, unknown>): void {
  const keyIndent = parser.lines[parser.index]?.indent;
  // Nothing deeper than the dash line means the item ended with its first key.
  if (keyIndent === undefined || keyIndent <= indent) {
    return;
  }
  while (parser.index < parser.lines.length) {
    const line = parser.lines[parser.index];
    // A change in indentation or the start of the next sequence item ends this item's key list.
    if (!line || line.indent !== keyIndent || isYamlArrayLine(line)) {
      break;
    }
    addYamlObjectEntry(parser, keyIndent, line, mappingItem);
  }
}

// If the next line is deeper than the parent indent, advances the YAML cursor through the nested block and returns its value.
// Otherwise returns the supplied fallback, an empty object for a bare mapping value or null for a bare sequence item.
function parseNestedYamlValue(parser: YamlParser, indent: number, fallback: unknown): unknown {
  const nestedIndent = parser.lines[parser.index]?.indent;
  return nestedIndent !== undefined && nestedIndent > indent ? parseYamlBlock(parser, nestedIndent) : fallback;
}

/**
 * Requires a valid mapping separator so a malformed entry produces a config error.
 *
 * @param content - YAML mapping line to split into a key and value.
 * @returns Raw key and value slices on either side of the separator.
 * @throws {ConfigLoadError} - When no unquoted colon is followed by whitespace or the end of the line.
 */
function yamlKeyValuePair(content: string): [string, string] {
  const pair = splitYamlKeyValue(content);
  if (!pair) {
    throw new ConfigLoadError(`Invalid YAML mapping line: "${content}".`, SUGGEST_INIT_FORCE);
  }
  return pair;
}

// Treats a YAML line as a sequence entry when it starts with a dash followed by a space or consists of a single dash.
function isYamlArrayLine(line: YamlLine): boolean {
  return line.content.startsWith("- ") || line.content === "-";
}

/**
 * Rejects excess indentation before a misaligned entry can be consumed at the current block level.
 *
 * @param line - Candidate entry in the current YAML block.
 * @param indent - Expected indentation for entries at this block level.
 * @returns Nothing. Lets the caller continue parsing when the line is within the indentation limit.
 * @throws {ConfigLoadError} - When the line is indented deeper than the current block level.
 */
function assertYamlIndent(line: YamlLine, indent: number): void {
  if (line.indent > indent) {
    throw new ConfigLoadError(`Invalid YAML indentation near "${line.content}".`, SUGGEST_INIT_FORCE);
  }
}

/**
 * Prepares meaningful YAML lines for indentation-based parsing by stripping comments and skipping blank lines.
 *
 * @param source - YAML document text to split into lines.
 * @returns Retained lines with their indentation width and trimmed content, or an empty array if none remain.
 * @throws {ConfigLoadError} - When a retained line contains a tab in its leading whitespace.
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

// Returns the YAML line before its first unquoted hash at the start of the line or after whitespace.
// With no such hash, returns the full line so hashes inside quotes or unquoted words remain part of the value.
function stripYamlComment(line: string): string {
  const commentIndex = firstUnquotedIndex(line, (character, index) => character === "#" && (index === 0 || /\s/.test(line[index - 1] ?? "")));
  return commentIndex === undefined ? line : line.slice(0, commentIndex);
}

// Splits candidate mapping text at the first unquoted colon followed by whitespace or the end of the text.
// Returns the raw key and value slices, or undefined when there is no mapping separator.
function splitYamlKeyValue(mappingText: string): [string, string] | undefined {
  const separatorIndex = firstUnquotedIndex(mappingText, (character, index) => {
    const next = mappingText[index + 1];
    return character === ":" && (!next || /\s/.test(next));
  });
  return separatorIndex === undefined ? undefined : [mappingText.slice(0, separatorIndex), mappingText.slice(separatorIndex + 1)];
}

// Trims the supplied YAML scalar text and returns the first matching parser's value.
// When no parser matches, returns the trimmed text. A blank scalar therefore becomes an empty string.
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

// Returns a match for trimmed YAML text in square brackets or for an empty mapping written as a pair of braces.
// Empty collections are valid matches. Other text returns the unmatched-scalar sentinel so another parser can try it.
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

// Returns a matched string for trimmed YAML text with matching outer quotes, decoding the supported escapes.
// Empty quoted text is a successful match. Text without matching quotes returns the unmatched-scalar sentinel.
function parseYamlQuotedScalar(trimmed: string): ParsedYamlScalar {
  if (isQuotedYaml(trimmed)) {
    return matchedYamlScalar(unquoteYaml(trimmed));
  }
  return UNMATCHED_YAML_SCALAR;
}

// Matches trimmed YAML text for true, false, null and tilde case-insensitively, returning a Boolean or null in a matched result.
// Other text returns the unmatched-scalar sentinel so number parsing or the plain-text fallback can handle it.
function parseYamlKeywordScalar(trimmed: string): ParsedYamlScalar {
  const normalized = trimmed.toLowerCase();
  if (YAML_KEYWORD_SCALARS.has(normalized)) {
    return matchedYamlScalar(YAML_KEYWORD_SCALARS.get(normalized) ?? null);
  }
  return UNMATCHED_YAML_SCALAR;
}

// Returns a matched number when the trimmed YAML scalar fits the supported decimal syntax.
// Other text returns the unmatched-scalar sentinel. Hexadecimal and exponent forms fall through as strings.
function parseYamlNumberScalar(trimmed: string): ParsedYamlScalar {
  if (YAML_NUMBER_SCALAR.test(trimmed)) {
    return matchedYamlScalar(Number(trimmed));
  }
  return UNMATCHED_YAML_SCALAR;
}

// Returns a "matched" result with the parsed value, distinguishing real matches from the shared
// UNMATCHED_YAML_SCALAR sentinel used by every parser that failed.
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

// Splits the contents of an inline array into trimmed item strings, keeping quoted commas inside their items.
// Returns empty fields as empty strings so their array positions are preserved.
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

// Searches the source text outside quotes, passing eligible characters and their indexes to the supplied predicate until it accepts one.
// Returns the first accepted index, or undefined when no unquoted position matches.
function firstUnquotedIndex(sourceText: string, predicate: (character: string, index: number) => boolean): number | undefined {
  for (const index of unquotedIndexes(sourceText)) {
    const character = sourceText[index] ?? "";
    if (predicate(character, index)) {
      return index;
    }
  }
  return undefined;
}

// Returns indexes outside quoted regions in the supplied text, excluding the quote delimiters themselves.
// An omitted or empty character filter keeps every eligible index. If none qualify, the result is an empty array.
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

// Returns true for a character consumed by the active quoted region and updates the supplied quote and escape state.
// Backslash escapes apply inside double quotes. With no active quote, returns false so the caller can handle the character.
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

// Recognizes a character as a YAML quote delimiter when it is a single or double quote. Backticks remain ordinary text.
function isYamlQuote(character: string): boolean {
  return character === "\"" || character === "'";
}

// Both endpoints must use the same quote character; mismatched openers/closers are treated as
// plain text rather than a parse error so a single stray quote in user prose doesn't fail the config.
function isQuotedYaml(scalarText: string): boolean {
  return scalarText.length >= 2 && ((scalarText.startsWith("\"") && scalarText.endsWith("\"")) || (scalarText.startsWith("'") && scalarText.endsWith("'")));
}

// Removes matching outer quotes from a YAML scalar and decodes doubled apostrophes in single-quoted text.
// In double quotes, decodes backslash escapes for newline, carriage return, tab, double quote and backslash.
// Returns unquoted input unchanged and preserves unrecognized escapes inside quoted text.
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

// Returns the supplied config value when it is a non-null, non-array object so callers can read named options.
// Null, arrays and primitive values yield undefined so callers can use optional chaining for an absent mapping.
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

export { arrayValue, isString, objectValue, parseConfigFile, parseYamlConfig, stripYamlComment, SUGGEST_EDIT_CONFIG, SUGGEST_INIT_FORCE };
