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
  const path = options.config ? absolutize(projectRoot, options.config) : defaultConfigPath(projectRoot);
  if (!path) {
    return config;
  }

  const raw = parseConfigFile(path);
  const paths = objectValue(raw.paths);
  config.ignoredPaths = arrayValue(paths?.ignore).filter(isString);

  const allowlists = objectValue(raw.allowlists);
  const abbreviations = arrayValue(allowlists?.acceptedAbbreviations).filter(isString);
  if (abbreviations.length > 0) {
    config.acceptedAbbreviations = new Set(abbreviations.map((value) => value.toLowerCase()));
  }
  config.secretPreviews = new Set(arrayValue(allowlists?.secretPreviews).filter(isString));

  const rules = objectValue(raw.rules);
  if (rules) {
    for (const [ruleId, value] of Object.entries(rules)) {
      const rule = objectValue(value);
      if (!rule) {
        continue;
      }
      const thresholds = new Map<string, number>();
      const rawThresholds = objectValue(rule.thresholds);
      if (rawThresholds) {
        for (const [name, threshold] of Object.entries(rawThresholds)) {
          if (typeof threshold === "number") {
            thresholds.set(name, threshold);
          }
        }
      }
      config.rules.set(ruleId, {
        ...(typeof rule.enabled === "boolean" ? { enabled: rule.enabled } : {}),
        thresholds,
      });
    }
  }

  return config;
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

function parseYamlConfig(source: string): Record<string, unknown> {
  const lines = yamlLines(source);
  let index = 0;

  function parseBlock(indent: number): unknown {
    const line = lines[index];
    if (!line || line.indent < indent) {
      return {};
    }
    return line.content.startsWith("- ") || line.content === "-" ? parseYamlArray(line.indent) : parseYamlObject(line.indent);
  }

  function parseYamlObject(indent: number): Record<string, unknown> {
    const result: Record<string, unknown> = {};
    while (index < lines.length) {
      const line = lines[index];
      if (!line || line.indent < indent) {
        break;
      }
      if (line.indent > indent) {
        throw new Error(`Invalid YAML indentation near "${line.content}".`);
      }
      if (line.content.startsWith("- ") || line.content === "-") {
        break;
      }

      const pair = splitYamlKeyValue(line.content);
      if (!pair) {
        throw new Error(`Invalid YAML mapping line: "${line.content}".`);
      }
      const [rawKey, rawValue] = pair;
      const key = unquoteYaml(rawKey.trim());
      const scalarText = rawValue.trim();
      index += 1;

      if (scalarText.length > 0) {
        result[key] = parseYamlScalar(scalarText);
        continue;
      }

      const nestedIndent = lines[index]?.indent;
      result[key] = nestedIndent !== undefined && nestedIndent > indent ? parseBlock(nestedIndent) : {};
    }
    return result;
  }

  function parseYamlArray(indent: number): unknown[] {
    const result: unknown[] = [];
    while (index < lines.length) {
      const line = lines[index];
      if (!line || line.indent < indent) {
        break;
      }
      if (line.indent > indent) {
        throw new Error(`Invalid YAML indentation near "${line.content}".`);
      }
      if (!line.content.startsWith("- ") && line.content !== "-") {
        break;
      }

      const itemText = line.content === "-" ? "" : line.content.slice(2).trim();
      index += 1;
      if (itemText.length === 0) {
        const nestedIndent = lines[index]?.indent;
        result.push(nestedIndent !== undefined && nestedIndent > indent ? parseBlock(nestedIndent) : null);
        continue;
      }

      const pair = splitYamlKeyValue(itemText);
      if (pair) {
        const [rawKey, rawValue] = pair;
        const scalarText = rawValue.trim();
        const entry: Record<string, unknown> = {};
        const nestedIndent = lines[index]?.indent;
        entry[unquoteYaml(rawKey.trim())] = scalarText.length > 0 ? parseYamlScalar(scalarText) : nestedIndent !== undefined && nestedIndent > indent ? parseBlock(nestedIndent) : {};
        result.push(entry);
        continue;
      }

      result.push(parseYamlScalar(itemText));
    }
    return result;
  }

  const parsed = lines.length === 0 ? {} : parseBlock(lines[0]?.indent ?? 0);
  const config = objectValue(parsed);
  if (!config) {
    throw new Error("Config YAML must contain a mapping object.");
  }
  return config;
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
  let quote: string | undefined;
  let isEscaped = false;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if (!character) {
      continue;
    }
    if (quote) {
      if (quote === "\"" && character === "\\" && !isEscaped) {
        isEscaped = true;
        continue;
      }
      if (character === quote && !isEscaped) {
        quote = undefined;
      }
      isEscaped = false;
      continue;
    }
    if (character === "\"" || character === "'") {
      quote = character;
      continue;
    }
    if (character === "#") {
      return line.slice(0, index);
    }
  }
  return line;
}

function splitYamlKeyValue(value: string): [string, string] | undefined {
  let quote: string | undefined;
  let isEscaped = false;
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (!character) {
      continue;
    }
    if (quote) {
      if (quote === "\"" && character === "\\" && !isEscaped) {
        isEscaped = true;
        continue;
      }
      if (character === quote && !isEscaped) {
        quote = undefined;
      }
      isEscaped = false;
      continue;
    }
    if (character === "\"" || character === "'") {
      quote = character;
      continue;
    }
    const next = value[index + 1];
    if (character === ":" && (!next || /\s/.test(next))) {
      return [value.slice(0, index), value.slice(index + 1)];
    }
  }
  return undefined;
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
  let quote: string | undefined;
  let isEscaped = false;
  let start = 0;
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (!character) {
      continue;
    }
    if (quote) {
      if (quote === "\"" && character === "\\" && !isEscaped) {
        isEscaped = true;
        continue;
      }
      if (character === quote && !isEscaped) {
        quote = undefined;
      }
      isEscaped = false;
      continue;
    }
    if (character === "\"" || character === "'") {
      quote = character;
      continue;
    }
    if (character === ",") {
      items.push(value.slice(start, index).trim());
      start = index + 1;
    }
  }
  items.push(value.slice(start).trim());
  return items;
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
