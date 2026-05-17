import { existsSync, readFileSync } from "node:fs";
import { extname, isAbsolute, join } from "node:path";
import type { AnalysisOptions, Config } from "./types.ts";

const DEFAULT_CONFIG_FILES = [".gruff.json", ".gruff.yaml", ".gruff.yml"] as const;

function defaultConfig(): Config {
  return {
    ignoredPaths: [],
    acceptedAbbreviations: new Set(["id", "db", "io", "ui", "tx", "rx"]),
    secretPreviews: new Set(),
    rules: new Map(),
  };
}

function absolutize(projectRoot: string, path: string): string {
  return isAbsolute(path) ? path : join(projectRoot, path);
}

function loadConfig(projectRoot: string, options: AnalysisOptions): Config {
  const config = defaultConfig();
  if (options.noConfig) {
    return config;
  }
  const path = selectedConfigPath(projectRoot, options);
  if (!path) {
    return config;
  }

  applyConfigValues(config, parseConfigFile(path));
  return config;
}

function selectedConfigPath(projectRoot: string, options: AnalysisOptions): string | undefined {
  return options.config ? absolutize(projectRoot, options.config) : defaultConfigPath(projectRoot);
}

function applyConfigValues(config: Config, raw: Record<string, unknown>): void {
  applyPathConfig(config, raw);
  applyAllowlistConfig(config, raw);
  applyRuleConfig(config, raw);
}

function applyPathConfig(config: Config, raw: Record<string, unknown>): void {
  const paths = objectValue(raw.paths);
  config.ignoredPaths = arrayValue(paths?.ignore).filter(isString);
}

function applyAllowlistConfig(config: Config, raw: Record<string, unknown>): void {
  const allowlists = objectValue(raw.allowlists);
  const abbreviations = arrayValue(allowlists?.acceptedAbbreviations).filter(isString);
  if (abbreviations.length > 0) {
    config.acceptedAbbreviations = new Set(abbreviations.map((value) => value.toLowerCase()));
  }
  config.secretPreviews = new Set(arrayValue(allowlists?.secretPreviews).filter(isString));
}

function applyRuleConfig(config: Config, raw: Record<string, unknown>): void {
  const rules = objectValue(raw.rules);
  if (!rules) {
    return;
  }
  for (const [ruleId, value] of Object.entries(rules)) {
    const rule = objectValue(value);
    if (!rule) {
      continue;
    }
    config.rules.set(ruleId, ruleConfigValue(rule));
  }
}

function ruleConfigValue(rule: Record<string, unknown>): { enabled?: boolean; thresholds: Map<string, number> } {
  return {
    ...(typeof rule.enabled === "boolean" ? { enabled: rule.enabled } : {}),
    thresholds: thresholdConfigValue(rule.thresholds),
  };
}

function thresholdConfigValue(value: unknown): Map<string, number> {
  const thresholds = new Map<string, number>();
  const rawThresholds = objectValue(value);
  if (!rawThresholds) {
    return thresholds;
  }
  for (const [name, threshold] of Object.entries(rawThresholds)) {
    if (typeof threshold === "number") {
      thresholds.set(name, threshold);
    }
  }
  return thresholds;
}

function defaultConfigPath(projectRoot: string): string | undefined {
  for (const fileName of DEFAULT_CONFIG_FILES) {
    const candidate = join(projectRoot, fileName);
    if (existsSync(candidate)) {
      return candidate;
    }
  }
  return undefined;
}

function parseConfigFile(path: string): Record<string, unknown> {
  const source = readFileSync(path, "utf8");
  const extension = extname(path).toLowerCase();
  const parsed = extension === ".yaml" || extension === ".yml" ? parseYamlConfig(source) : (JSON.parse(source) as unknown);
  const config = objectValue(parsed);
  if (!config) {
    throw new Error(`Config file must contain an object: ${path}`);
  }
  return config;
}

interface YamlLine {
  indent: number;
  content: string;
}

interface YamlParser {
  lines: YamlLine[];
  index: number;
}

function parseYamlConfig(source: string): Record<string, unknown> {
  const parser = { lines: yamlLines(source), index: 0 };
  const parsed = parser.lines.length === 0 ? {} : parseYamlBlock(parser, parser.lines[0]?.indent ?? 0);
  const config = objectValue(parsed);
  if (!config) {
    throw new Error("Config YAML must contain a mapping object.");
  }
  return config;
}

function parseYamlBlock(parser: YamlParser, indent: number): unknown {
  const line = parser.lines[parser.index];
  if (!line || line.indent < indent) {
    return {};
  }
  return isYamlArrayLine(line) ? parseYamlArray(parser, line.indent) : parseYamlObject(parser, line.indent);
}

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

function addYamlObjectEntry(parser: YamlParser, indent: number, line: YamlLine, result: Record<string, unknown>): void {
  const [rawKey, rawValue] = yamlKeyValuePair(line.content);
  const scalarText = rawValue.trim();
  parser.index += 1;
  result[unquoteYaml(rawKey.trim())] = scalarText.length > 0 ? parseYamlScalar(scalarText) : parseNestedYamlValue(parser, indent, {});
}

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

function parseYamlArrayItem(parser: YamlParser, indent: number, line: YamlLine): unknown {
  const itemText = line.content === "-" ? "" : line.content.slice(2).trim();
  parser.index += 1;
  if (itemText.length === 0) {
    return parseNestedYamlValue(parser, indent, null);
  }

  const pair = splitYamlKeyValue(itemText);
  return pair ? parseYamlArrayMappingItem(parser, indent, pair) : parseYamlScalar(itemText);
}

function parseYamlArrayMappingItem(parser: YamlParser, indent: number, pair: [string, string]): Record<string, unknown> {
  const [rawKey, rawValue] = pair;
  const scalarText = rawValue.trim();
  return {
    [unquoteYaml(rawKey.trim())]: scalarText.length > 0 ? parseYamlScalar(scalarText) : parseNestedYamlValue(parser, indent, {}),
  };
}

function parseNestedYamlValue(parser: YamlParser, indent: number, fallback: unknown): unknown {
  const nestedIndent = parser.lines[parser.index]?.indent;
  return nestedIndent !== undefined && nestedIndent > indent ? parseYamlBlock(parser, nestedIndent) : fallback;
}

function yamlKeyValuePair(content: string): [string, string] {
  const pair = splitYamlKeyValue(content);
  if (!pair) {
    throw new Error(`Invalid YAML mapping line: "${content}".`);
  }
  return pair;
}

function isYamlArrayLine(line: YamlLine): boolean {
  return line.content.startsWith("- ") || line.content === "-";
}

function assertYamlIndent(line: YamlLine, indent: number): void {
  if (line.indent > indent) {
    throw new Error(`Invalid YAML indentation near "${line.content}".`);
  }
}

function yamlLines(source: string): YamlLine[] {
  const lines: YamlLine[] = [];
  for (const rawLine of source.replace(/\r\n/g, "\n").split("\n")) {
    const withoutComment = stripYamlComment(rawLine).trimEnd();
    if (withoutComment.trim().length === 0) {
      continue;
    }
    const indentText = withoutComment.match(/^\s*/)?.[0] ?? "";
    if (indentText.includes("\t")) {
      throw new Error("Tabs are not supported in gruff YAML config indentation.");
    }
    lines.push({ indent: indentText.length, content: withoutComment.trimStart() });
  }
  return lines;
}

function stripYamlComment(line: string): string {
  const commentIndex = firstUnquotedIndex(line, (character) => character === "#");
  return commentIndex === undefined ? line : line.slice(0, commentIndex);
}

function splitYamlKeyValue(value: string): [string, string] | undefined {
  const separatorIndex = firstUnquotedIndex(value, (character, index) => {
    const next = value[index + 1];
    return character === ":" && (!next || /\s/.test(next));
  });
  return separatorIndex === undefined ? undefined : [value.slice(0, separatorIndex), value.slice(separatorIndex + 1)];
}

function parseYamlScalar(value: string): unknown {
  const trimmed = value.trim();
  if (trimmed === "[]") {
    return [];
  }
  if (trimmed === "{}") {
    return {};
  }
  if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
    return parseYamlInlineArray(trimmed);
  }
  if (isQuotedYaml(trimmed)) {
    return unquoteYaml(trimmed);
  }
  if (/^(?:true|false)$/i.test(trimmed)) {
    return trimmed.toLowerCase() === "true";
  }
  if (/^(?:null|~)$/i.test(trimmed)) {
    return null;
  }
  if (/^-?(?:0|[1-9]\d*)(?:\.\d+)?$/.test(trimmed)) {
    return Number(trimmed);
  }
  return trimmed;
}

function parseYamlInlineArray(value: string): unknown[] {
  const inner = value.slice(1, -1).trim();
  if (inner.length === 0) {
    return [];
  }
  return splitYamlInlineItems(inner).map((item) => parseYamlScalar(item));
}

function splitYamlInlineItems(value: string): string[] {
  const items: string[] = [];
  let start = 0;
  for (const index of unquotedIndexes(value, ",")) {
    items.push(value.slice(start, index).trim());
    start = index + 1;
  }
  items.push(value.slice(start).trim());
  return items;
}

interface QuoteScanState {
  quote: string | undefined;
  isEscaped: boolean;
}

function firstUnquotedIndex(value: string, predicate: (character: string, index: number) => boolean): number | undefined {
  for (const index of unquotedIndexes(value)) {
    const character = value[index] ?? "";
    if (predicate(character, index)) {
      return index;
    }
  }
  return undefined;
}

function unquotedIndexes(value: string, expectedCharacter?: string): number[] {
  const indexes: number[] = [];
  const state: QuoteScanState = { quote: undefined, isEscaped: false };
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index] ?? "";
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

function isYamlQuote(character: string): boolean {
  return character === "\"" || character === "'";
}

function isQuotedYaml(value: string): boolean {
  return value.length >= 2 && ((value.startsWith("\"") && value.endsWith("\"")) || (value.startsWith("'") && value.endsWith("'")));
}

function unquoteYaml(value: string): string {
  if (!isQuotedYaml(value)) {
    return value;
  }
  const quote = value[0];
  const body = value.slice(1, -1);
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

function ruleEnabled(config: Config, ruleId: string): boolean {
  return config.rules.get(ruleId)?.enabled ?? true;
}

function threshold(config: Config, ruleId: string, name: string, defaultValue: number): number {
  return config.rules.get(ruleId)?.thresholds.get(name) ?? defaultValue;
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;
}

function arrayValue(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function isString(value: unknown): value is string {
  return typeof value === "string";
}

export { isString, loadConfig, objectValue, ruleEnabled, threshold };
