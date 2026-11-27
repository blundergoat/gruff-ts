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

/**
 * Parses config text as YAML or JSON according to its file extension so the caller can validate or reject unsupported formats.
 *
 * @param source - Decoded config file contents to parse.
 * @param extension - Lowercase file extension selecting YAML (`.yaml`, `.yml`) or JSON (`.json`) parsing.
 * @param shownPath - Display path included in invalid JSON errors on the shared CLI error channel.
 * @returns The parsed config value, or `undefined` when the extension is unsupported.
 * @throws {ConfigLoadError} - For invalid JSON syntax or input rejected by the YAML parser.
 * @throws {Error} - Propagates other JSON parser errors unchanged.
 */
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

/**
 * Parses the next YAML sequence or mapping block at or beyond the minimum indentation, advancing the cursor through it.
 *
 * @param parser - Mutable YAML line cursor positioned at the start of the candidate block.
 * @param indent - Minimum column indentation required to continue into a nested block.
 * @returns The parsed sequence or mapping, or an empty object when no line remains at or above `indent`.
 */
function parseYamlBlock(parser: YamlParser, indent: number): unknown {
  const line = parser.lines[parser.index];
  if (!line || line.indent < indent) {
    return {};
  }
  return isYamlArrayLine(line) ? parseYamlArray(parser, line.indent) : parseYamlObject(parser, line.indent);
}

/**
 * Parses a YAML mapping block at the supplied indentation until a dedent, sequence item, or end of input stops it.
 *
 * @param parser - Mutable YAML line cursor positioned at the first entry of the mapping.
 * @param indent - Expected indentation column for entries belonging to this mapping.
 * @returns The parsed key-value mapping, or an empty object if no entry was consumed.
 * @throws {ConfigLoadError} - When an entry is over-indented (so a misaligned entry cannot be read here) or has a duplicate/invalid key.
 */
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

/**
 * Reads one YAML key-value entry and records it on the target mapping so the settings loader can validate it.
 * An empty value with no indented block represents an empty mapping, and quoting a key keeps the same meaning.
 *
 * @param parser - Mutable YAML line cursor positioned on `line`; advances past the entry and any nested block.
 * @param indent - Indentation column of the enclosing mapping, used to detect nested blocks.
 * @param line - Current YAML mapping line to split and unquote into a key and value.
 * @param result - Mapping object mutated with the parsed property via `Object.defineProperty`.
 * @returns Nothing. Mutates `result` with the parsed entry and advances `parser`.
 * @throws {ConfigLoadError} - When the mapping contains an invalid or duplicate key.
 */
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

/**
 * Parses a block YAML sequence at the supplied indentation until a dedent, non-sequence line, or end of input stops it.
 * Inline arrays are handled separately by `parseYamlCollectionScalar`.
 *
 * @param parser - Mutable YAML line cursor positioned at the first sequence item.
 * @param indent - Expected dash indentation column for items in this sequence.
 * @returns The parsed sequence items, or an empty array if no item was consumed.
 * @throws {ConfigLoadError} - When a sequence item is over-indented or a nested mapping entry is invalid.
 */
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

/**
 * Parses one YAML sequence item on `line` and advances `parser` past the item and any continuation lines it consumes.
 *
 * @param parser - Mutable YAML line cursor positioned at `line`.
 * @param indent - Dash indentation column used to distinguish nested blocks from outer or sibling lines.
 * @param line - Current sequence entry beginning with `-` or `- `.
 * @returns A nested value, a mapping for `- key: value`, a scalar, or `null` for a bare dash with no deeper block so that its slot is kept.
 */
function parseYamlArrayItem(parser: YamlParser, indent: number, line: YamlLine): unknown {
  const itemText = line.content === "-" ? "" : line.content.slice(2).trim();
  parser.index += 1;
  if (itemText.length === 0) {
    return parseNestedYamlValue(parser, indent, null);
  }

  const pair = splitYamlKeyValue(itemText);
  return pair ? parseYamlArrayMappingItem(parser, indent, pair) : parseYamlScalar(itemText);
}

/**
 * Builds a sequence item mapping from the key-value pair on its dash line and consumes any nested values or sibling keys.
 *
 * @param parser - Mutable YAML line cursor positioned immediately after the dash line.
 * @param indent - Dash indentation column used to locate nested values and sibling keys.
 * @param pair - Raw key and value slices split from the dash line after `- `.
 * @returns The sequence item mapping, using an empty object when the first value is blank and has no deeper block.
 */
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

/**
 * Parses a deeper nested YAML block if present, or returns the supplied fallback when no nested lines follow.
 *
 * @param parser - Mutable YAML line cursor positioned at the candidate nested block.
 * @param indent - Parent indentation column that a nested block must strictly exceed.
 * @param fallback - Value returned when no deeper line follows, such as `{}` for a bare mapping value or `null` for a bare sequence item.
 * @returns The parsed nested block value, or `fallback` when the next line is absent or not indented deeper.
 */
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

/**
 * Checks whether a YAML line starts a block sequence entry (`- ` or a single `-`).
 *
 * @param line - Comment-stripped YAML line to inspect.
 * @returns `true` when `line.content` starts with `"- "` or equals `"-"`; otherwise `false`.
 */
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

/**
 * Strips any trailing YAML comment starting at an unquoted `#` at line start or after whitespace.
 * Hashes inside quotes or unquoted words remain part of the value.
 *
 * @param line - Raw YAML line text to trim of comments.
 * @returns Substring before the comment `#`, or the full `line` when no comment marker is present.
 */
function stripYamlComment(line: string): string {
  const commentIndex = firstUnquotedIndex(line, (character, index) => character === "#" && (index === 0 || /\s/.test(line[index - 1] ?? "")));
  return commentIndex === undefined ? line : line.slice(0, commentIndex);
}

/**
 * Splits candidate YAML mapping text at the first unquoted colon followed by whitespace or the end of the text.
 *
 * @param mappingText - Candidate YAML mapping content to split.
 * @returns Raw `[key, value]` slices on either side of the separator, or `undefined` when no mapping separator exists.
 */
function splitYamlKeyValue(mappingText: string): [string, string] | undefined {
  const separatorIndex = firstUnquotedIndex(mappingText, (character, index) => {
    const next = mappingText[index + 1];
    return character === ":" && (!next || /\s/.test(next));
  });
  return separatorIndex === undefined ? undefined : [mappingText.slice(0, separatorIndex), mappingText.slice(separatorIndex + 1)];
}

/**
 * Trims a YAML scalar and decodes it with the first matching collection, quoted, keyword, or number parser.
 * When no parser matches, returns the trimmed text (so a blank scalar becomes an empty string).
 *
 * @param scalarText - Raw scalar slice to trim and decode.
 * @returns The decoded JS value from the first matching parser, or the trimmed string fallback.
 */
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

/**
 * Parses trimmed YAML text in square brackets or an empty brace mapping (`{}`) into a matched scalar result.
 *
 * @param trimmed - Pre-trimmed YAML scalar text to test for inline collection syntax.
 * @returns A matched result for an inline array or `{}`, or `UNMATCHED_YAML_SCALAR` so another parser can try it.
 */
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

/**
 * Parses trimmed YAML text enclosed in matching outer single or double quotes and decodes supported escapes.
 *
 * @param trimmed - Pre-trimmed YAML scalar text to test for matching outer quotes.
 * @returns A matched string (including empty quoted text `""`), or `UNMATCHED_YAML_SCALAR` without matching quotes.
 */
function parseYamlQuotedScalar(trimmed: string): ParsedYamlScalar {
  if (isQuotedYaml(trimmed)) {
    return matchedYamlScalar(unquoteYaml(trimmed));
  }
  return UNMATCHED_YAML_SCALAR;
}

/**
 * Matches YAML boolean and null keywords (`true`, `false`, `null`, `~`) case-insensitively.
 *
 * @param trimmed - Pre-trimmed YAML scalar text to look up in `YAML_KEYWORD_SCALARS`.
 * @returns A matched result holding a boolean or `null`, or `UNMATCHED_YAML_SCALAR` so number or plain-text parsing can handle it.
 */
function parseYamlKeywordScalar(trimmed: string): ParsedYamlScalar {
  const normalized = trimmed.toLowerCase();
  if (YAML_KEYWORD_SCALARS.has(normalized)) {
    return matchedYamlScalar(YAML_KEYWORD_SCALARS.get(normalized) ?? null);
  }
  return UNMATCHED_YAML_SCALAR;
}

/**
 * Parses decimal numbers matching `YAML_NUMBER_SCALAR`; hexadecimal and exponent forms fall through as strings.
 *
 * @param trimmed - Pre-trimmed YAML scalar text to test against decimal number syntax.
 * @returns A matched result containing the `Number` value, or `UNMATCHED_YAML_SCALAR` for non-decimal text.
 */
function parseYamlNumberScalar(trimmed: string): ParsedYamlScalar {
  if (YAML_NUMBER_SCALAR.test(trimmed)) {
    return matchedYamlScalar(Number(trimmed));
  }
  return UNMATCHED_YAML_SCALAR;
}

/**
 * Wraps a parsed scalar value as matched to distinguish real `null` or empty matches from `UNMATCHED_YAML_SCALAR`.
 *
 * @param scalarValue - Decoded scalar or inline collection value produced by a scalar parser.
 * @returns A `ParsedYamlScalar` with `isMatched: true` and `value` set to `scalarValue`.
 */
function matchedYamlScalar(scalarValue: unknown): ParsedYamlScalar {
  return { isMatched: true, value: scalarValue };
}

/**
 * Parses an inline `[a, b, c]` YAML array, splitting on unquoted commas and recursing through `parseYamlScalar` so nested types resolve correctly.
 *
 * @param arrayText - Bracket-delimited inline YAML array text.
 * @returns Array of decoded item values, or an empty array when only whitespace sits inside the brackets.
 */
function parseYamlInlineArray(arrayText: string): unknown[] {
  const inner = arrayText.slice(1, -1).trim();
  if (inner.length === 0) {
    return [];
  }
  return splitYamlInlineItems(inner).map((item) => parseYamlScalar(item));
}

/**
 * Splits inline array body text on unquoted commas into trimmed item strings while keeping quoted commas inside their items.
 * Empty fields are returned as empty strings so their array positions are preserved.
 *
 * @param itemsText - Inner text of an inline YAML array with outer brackets removed.
 * @returns Array of trimmed item strings in positional order.
 */
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

/**
 * Searches `sourceText` outside quotes, passing unquoted characters and indexes to `predicate` until one is accepted.
 *
 * @param sourceText - Text to scan while skipping single- and double-quoted regions.
 * @param predicate - Test invoked with each unquoted character and its string index.
 * @returns The first accepted unquoted index, or `undefined` when no unquoted position matches.
 */
function firstUnquotedIndex(sourceText: string, predicate: (character: string, index: number) => boolean): number | undefined {
  for (const index of unquotedIndexes(sourceText)) {
    const character = sourceText[index] ?? "";
    if (predicate(character, index)) {
      return index;
    }
  }
  return undefined;
}

/**
 * Collects character indexes outside quoted regions in `sourceText`, excluding the quote delimiters themselves.
 *
 * @param sourceText - Text to walk with the YAML quote state machine.
 * @param expectedCharacter - Optional single-character filter; an omitted or empty filter keeps every eligible index.
 * @returns Array of qualifying indexes in ascending order, or an empty array if none qualify.
 */
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

/**
 * Consumes one character inside an active quoted region and updates the quote and escape state in place.
 * Backslash escapes apply only inside double quotes.
 *
 * @param character - Current character being scanned.
 * @param state - Mutable quote and escape state updated when a quote closes or an escape begins.
 * @returns `true` if `character` was consumed by an active quote; `false` with no active quote so the caller can handle the character.
 */
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

/**
 * Recognizes a character as a YAML quote delimiter when it is a single or double quote; backticks remain ordinary text.
 *
 * @param character - Single character from the source scan to test.
 * @returns `true` for `"` or `'`; otherwise `false`.
 */
function isYamlQuote(character: string): boolean {
  return character === "\"" || character === "'";
}

/**
 * Checks whether `scalarText` is enclosed in matching outer quotes; both endpoints must use the same quote character.
 * Mismatched openers/closers are treated as plain text rather than a parse error so a stray quote in prose does not fail the config.
 *
 * @param scalarText - Trimmed YAML scalar text to inspect.
 * @returns `true` when `scalarText` has length >= 2 and matching outer `"` or `'` quotes; otherwise `false`.
 */
function isQuotedYaml(scalarText: string): boolean {
  return scalarText.length >= 2 && ((scalarText.startsWith("\"") && scalarText.endsWith("\"")) || (scalarText.startsWith("'") && scalarText.endsWith("'")));
}

/**
 * Removes matching outer quotes from a YAML scalar and decodes `''` in single quotes or `\"`, `\\`, `\n`, `\r`, `\t` in double quotes.
 * Unquoted input returns unchanged and unrecognized escapes inside quoted text are preserved.
 *
 * @param scalarText - Scalar or key text to unquote if enclosed in matching outer quotes.
 * @returns The unquoted and unescaped string, or `scalarText` unchanged if not validly quoted.
 */
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

/**
 * Narrows a config value to a non-null, non-array object so callers can read named options with optional chaining for absent mappings.
 *
 * @param configValue - Parsed JSON or YAML value to check.
 * @returns `configValue` cast as a record when it is a non-null, non-array object; `undefined` for null, arrays, and primitives.
 */
function objectValue(configValue: unknown): Record<string, unknown> | undefined {
  return typeof configValue === "object" && configValue !== null && !Array.isArray(configValue) ? (configValue as Record<string, unknown>) : undefined;
}

/**
 * Returns the array or an empty array (never `undefined`) so callers can iterate without a guard.
 *
 * @param configValue - Parsed JSON or YAML value to normalize to an array.
 * @returns `configValue` if it is an array; otherwise `[]`.
 */
function arrayValue(configValue: unknown): unknown[] {
  return Array.isArray(configValue) ? configValue : [];
}

/**
 * Narrows a value to `string`, exported so other modules share a single string-test matching config semantics (rejects truthy numbers).
 *
 * @param configValue - Unknown value from parsed configuration to test.
 * @returns `true` when `typeof configValue === "string"`; otherwise `false`.
 */
function isString(configValue: unknown): configValue is string {
  return typeof configValue === "string";
}

export { arrayValue, isString, objectValue, parseConfigFile, parseYamlConfig, stripYamlComment, SUGGEST_EDIT_CONFIG, SUGGEST_INIT_FORCE };
