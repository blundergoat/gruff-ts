// Shared test harness utilities and synthetic secret/source fixtures for isolated project analyses.
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer as createNetServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { chdir, cwd } from "node:process";
import { analyse } from "./cli.ts";
import type { AnalysisReport, ChangedScopeMode, DeepScanBudgetOverride, Finding } from "./types.ts";

export const REPO_ROOT = cwd();
export const HIGH_ENTROPY_FIXTURE_VALUE = ["Zx7pQ9vLm3N8sT2r", "Y6wK1dF4gH5jC0bR2"].join("");
export const API_TOKEN_FIXTURE_VALUE = ["rN7pQ4sV9xY2zA5b", "C8dG9hK2mN5pQ8sR1"].join("");
export const DATABASE_URL_FIXTURE_VALUE = ["postgres://app:superSecret", "Password@db.internal/app"].join("");
export const URL_CREDENTIAL_FIXTURE_VALUE = ["https://agent:", "clientSecret42", "@example.test/api"].join("");
export const OPENAI_KEY_FIXTURE_VALUE = ["sk-proj-AbCdEfGhIjKl", "MnOpQrStUvWxYz1234567890"].join("");
export const GOOGLE_API_KEY_FIXTURE_VALUE = ["AIzaSyD3moKeyValue", "1234567890AbCdEf"].join("");
export const SLACK_WEBHOOK_FIXTURE_VALUE = ["https://hooks.slack.com/services/T00000000", "B00000000", "abcdefghijklmnopqrstuvwx"].join("/");
export const DISCORD_WEBHOOK_FIXTURE_VALUE = [
  "https://discord.com/api/webhooks/123456789012345678",
  ["abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"].join(""),
].join("/");
export const NPM_AUTH_TOKEN_FIXTURE_VALUE = ["npmAuthToken", "AbCdEfGhIjKlMnOp", "QrStUvWxYz123456"].join("");
export const SSN_FIXTURE_VALUE = ["123", "45", "6789"].join("-");
export const CREDIT_CARD_FIXTURE_VALUE = ["4539", "5787", "6362", "1486"].join(" ");
export const INVALID_CREDIT_CARD_FIXTURE_VALUE = ["4539", "5787", "6362", "1487"].join(" ");
export const MBI_FIXTURE_VALUE = ["1EG4", "TE5", "MK73"].join("");
export const MRN_FIXTURE_VALUE = "00489912";
export const GCP_PRIVATE_KEY_ID_FIXTURE_VALUE = ["a1b2c3d4e5f6a7b8c9d0", "e1f2a3b4c5d6e7f8a9b0"].join("");
export const AWS_ACCESS_KEY_FIXTURE_VALUE = ["AKIAABCDEFGH", "IJKLMNOP"].join("");
export const PRIVATE_KEY_HEADER_FIXTURE_VALUE = ["-----BEGIN ", "PRIVATE KEY-----"].join("");
export const POSTGRES_URL_FIXTURE_VALUE = ["postgres://user:sec", "ret@example.test/db"].join("");
export const JWT_FIXTURE_VALUE = ["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjMifQ", "signature"].join(".");
export const TS_IGNORE_DIRECTIVE = ["@ts", "-ignore"].join("");
export const COMMENTED_OUT_SECRET_LOAD = ["const", " legacyPassword = loadSecret();"].join("");
export const COMMENTED_OUT_CACHE_LOAD = ["const", " disabledCache = loadCache();"].join("");
export const COMMENTED_OUT_LEGACY_CALL = ["const", " disabledLegacy = runLegacyPath();"].join("");

// Configures temporary project scans used by tests.
export interface AnalyseProjectOptions {
  config?: Record<string, unknown>;
  configPath?: string;
  profile?: string;
  executableFiles?: string[];
  shouldIncludeIgnored?: boolean;
  shouldSkipConfig?: boolean;
  paths?: string[];
  diff?: string;
  diffPatch?: string;
  since?: string;
  changedRanges?: string;
  changedScope?: ChangedScopeMode;
  deepScanBudget?: DeepScanBudgetOverride;
}

// Adds a fixture filename override for single-source test scans.
export interface AnalyseFixtureOptions extends AnalyseProjectOptions {
  fileName?: string;
}

// Rules precision-floor M02 turned off by default whose detectors the native suites still exercise.
export const M02_DEFAULT_OFF_RULE_IDS = [
  "security.inner-html",
  "security.path-traversal-candidate",
  "security.unsafe-deserialization",
  "sensitive-data.aws-access-key",
  "sensitive-data.database-url-password",
  "waste.useless-return",
] as const;

// The same switch as a `.gruff-ts.yaml` document, for tests that drive the CLI.
export const M02_DEFAULT_OFF_RULES_ON_YAML = [
  "schemaVersion: gruff-ts.config.v0.1",
  "rules:",
  ...M02_DEFAULT_OFF_RULE_IDS.flatMap((ruleId) => [`  ${ruleId}:`, "    enabled: true"]),
].join("\n") + "\n";

// Returns a copy of options with the rules in M02_DEFAULT_OFF_RULE_IDS enabled; explicit rule settings win.
// Other settings stay unchanged; omitted options start from an empty configuration.
export function withDefaultOffRulesOn<T extends AnalyseFixtureOptions>(options: T = {} as T): T {
  const config = options.config ?? {};
  const rules = (config["rules"] ?? {}) as Record<string, Record<string, unknown>>;
  const switchedOn = Object.fromEntries(M02_DEFAULT_OFF_RULE_IDS.map((ruleId) => [ruleId, { enabled: true, ...rules[ruleId] }]));
  return { ...options, config: { ...config, rules: { ...rules, ...switchedOn } } };
}

// Return an analysis report for source, using options.fileName or bad.ts and forwarding only config, configPath and shouldSkipConfig.
// The delegated scan writes a temporary project and changes into it before restoring the working directory and removing the project.
export function analyseFixture(source: string, options: AnalyseFixtureOptions = {}) {
  return analyseProject(
    { [options.fileName ?? "bad.ts"]: source },
    {
      ...(options.config ? { config: options.config } : {}),
      ...(typeof options.configPath === "string" ? { configPath: options.configPath } : {}),
      ...(typeof options.shouldSkipConfig === "boolean" ? { shouldSkipConfig: options.shouldSkipConfig } : {}),
    },
  );
}

// Writes the supplied path-to-content map into a temporary project and returns its analysis report.
// options controls executable files, fixture config, and scan settings. Omit it to scan the project root with config loading disabled.
// Changes the process working directory for the scan, then restores it and removes the fixture tree in cleanup.
export function analyseProject(files: Record<string, string>, options: AnalyseProjectOptions = {}) {
  const dir = mkdtempSync(join(tmpdir(), "gruff-ts-"));
  const previous = cwd();
  try {
    setupAnalyseProjectDirectory(dir, files, options);
    chdir(dir);
    return analyseProjectInCurrentDirectory(options);
  } finally {
    chdir(previous);
    rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * Writes fixture files, executability bits, and optional config for project tests.
 *
 * @param dir - Temporary project root to populate.
 * @param files - Project-relative file paths and source text to write.
 * @param options - Selects executable files and supplies config for .gruff-ts.yaml when present.
 * @returns Nothing. Populates the project on disk for the fixture scan.
 */
export function setupAnalyseProjectDirectory(dir: string, files: Record<string, string>, options: AnalyseProjectOptions): void {
  writeFixtureFiles(dir, files);
  for (const fileName of options.executableFiles ?? []) {
    chmodSync(join(dir, fileName), 0o755);
  }
  if (options.config) {
    writeFileSync(join(dir, ".gruff-ts.yaml"), yamlConfigFixture(options.config));
  }
}

/**
 * Runs analyse after the fixture helper has switched into the temp project root, returning a stable report.
 * The explicit option assembly preserves exact optional property types because absent and undefined differ.
 * Skips baselines so reviewed findings stay visible. By default, config is enabled only with config or a nonempty configPath.
 *
 * @param options - selects scan settings. Omitted paths scan the working directory. shouldSkipConfig can override the config default.
 * @returns The analysis report produced from the current temporary project.
 */
export function analyseProjectInCurrentDirectory(options: AnalyseProjectOptions): AnalysisReport {
  return analyse({
    paths: options.paths ?? ["."],
    shouldSkipConfig: options.shouldSkipConfig ?? !(options.config || options.configPath),
    format: "json",
    failOn: "none",
    shouldIncludeIgnored: options.shouldIncludeIgnored ?? false,
    changedScope: options.changedScope ?? "symbol",
    shouldSkipBaseline: true,
    ...optionalFixtureScanFields(options),
  });
}

// Returns optional analyse arguments from fixture options, mapping configPath to config.
// Absent values are omitted to preserve exactOptionalPropertyTypes.
function optionalFixtureScanFields(options: AnalyseProjectOptions): Partial<Pick<Parameters<typeof analyse>[0], "config" | "profile" | "diff" | "diffPatch" | "since" | "changedRanges" | "deepScanBudget">> {
  return {
    ...(typeof options.configPath === "string" ? { config: options.configPath } : {}),
    ...(typeof options.profile === "string" ? { profile: options.profile } : {}),
    ...(typeof options.diff === "string" ? { diff: options.diff } : {}),
    ...(typeof options.diffPatch === "string" ? { diffPatch: options.diffPatch } : {}),
    ...(typeof options.since === "string" ? { since: options.since } : {}),
    ...(typeof options.changedRanges === "string" ? { changedRanges: options.changedRanges } : {}),
    ...(options.deepScanBudget !== undefined ? { deepScanBudget: options.deepScanBudget } : {}),
  };
}

/*
 * Serializes a test YAML config object from the root indentation level. Every fixture YAML is
 * stamped with the required `schemaVersion: gruff-ts.config.v0.1` field at the top (per ADR-004)
 * because the config loader throws when it's missing. The schema invariant is preserved by
 * spreading the input object AFTER schemaVersion so callers can't accidentally override it; tests
 * that need to assert against a missing schemaVersion must write the YAML by hand instead.
 */
export function yamlConfigFixture(configObject: Record<string, unknown>): string {
  return yamlConfigObject({ schemaVersion: "gruff-ts.config.v0.1", ...configObject }, 0);
}

// Returns fixture YAML for configObject's entries using indent leading spaces; an empty object returns an empty string.
export function yamlConfigObject(configObject: Record<string, unknown>, indent: number): string {
  return Object.entries(configObject)
    .map(([key, nested]) => yamlConfigEntry(key, nested, indent))
    .join("");
}

// Returns a fixture YAML entry for key and nestedValue, prefixed with indent spaces and ending with a newline.
// Non-null, non-array objects use nested entries. An object with no entries emits just the key and colon. Other values use the scalar serializer.
export function yamlConfigEntry(key: string, nestedValue: unknown, indent: number): string {
  const prefix = " ".repeat(indent);
  if (isYamlConfigObject(nestedValue)) {
    return prefix + key + ":\n" + yamlConfigObject(nestedValue, indent + 2);
  }
  return prefix + key + ": " + yamlConfigScalar(nestedValue) + "\n";
}

// Returns fixture YAML for scalarValue, including nested arrays, quoted strings, numbers and booleans.
// Null, undefined and all other values become the empty mapping {}.
export function yamlConfigScalar(scalarValue: unknown): string {
  if (Array.isArray(scalarValue)) {
    return `[${scalarValue.map(yamlConfigScalar).join(", ")}]`;
  }
  if (typeof scalarValue === "string") {
    return JSON.stringify(scalarValue);
  }
  if (typeof scalarValue === "number" || typeof scalarValue === "boolean") {
    return String(scalarValue);
  }
  return "{}";
}

// Returns whether configValue is a non-null, non-array object that the fixture serializer will treat as a mapping.
export function isYamlConfigObject(configValue: unknown): configValue is Record<string, unknown> {
  return typeof configValue === "object" && configValue !== null && !Array.isArray(configValue);
}

// Writes each relative path and its source text from files under fixture root dir, creating parent directories as needed.
// Returns nothing after populating the fixture directory on disk.
export function writeFixtureFiles(dir: string, files: Record<string, string>): void {
  for (const [fileName, source] of Object.entries(files)) {
    const path = join(dir, fileName);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, source);
  }
}

// Returns declaration lines named with prefix and an index, enough to cross the fixture-purpose line threshold.
export function largeFixtureSourceLines(prefix: string): string[] {
  return Array.from({ length: 13 }, (_, index) => "const " + prefix + index + " = " + index + ";");
}

// Returns the distinct file paths in the report with a security.eval-call finding, using the analyzer's stable rule ID for test assertions.
export function evalFindingFiles(report: AnalysisReport): Set<string> {
  return new Set(report.findings.filter((finding) => finding.ruleId === "security.eval-call").map((finding) => finding.filePath));
}

// Spawns git --version and returns true on success. A launch or command failure returns false so Git-dependent tests can skip.
// The probe stays quiet because an unusable Git command is an expected skip condition for these tests.
export function gitAvailable(): boolean {
  try {
    execFileSync("git", ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

// Spawns git check-ignore from projectRoot to check path. Returns true if Git reports the path ignored and false if it reports no match.
// @throws {Error} when `git check-ignore` cannot run or exits with a status other than 0 (ignored) or 1 (not ignored).
export function isGitIgnoredByGit(projectRoot: string, path: string): boolean {
  try {
    execFileSync("git", ["check-ignore", "--quiet", path], { cwd: projectRoot });
    return true;
  } catch (error) {
    const status = typeof error === "object" && error !== null && "status" in error ? (error as { status?: unknown }).status : undefined;
    if (status === 1) {
      return false;
    }
    throw error;
  }
}

// Starts a dashboard for the supplied project root and passes its base URL to the test callback after the health check.
// Resolves with no value after the callback and cleanup. Cleanup requests shutdown and waits up to one second for exit, even on failure.
export async function withDashboard(projectRoot: string, run: (endpoint: string) => Promise<void>): Promise<void> {
  const port = await freePort();
  const child = spawn("./bin/gruff-ts", ["dashboard", "--host", "127.0.0.1", "--port", String(port), "--project-root", projectRoot], {
    cwd: REPO_ROOT,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => {
    output += chunk;
  });
  child.stderr.on("data", (chunk: string) => {
    output += chunk;
  });
  const baseEndpoint = `http://127.0.0.1:${port}`;
  try {
    await waitForEndpoint(`${baseEndpoint}/health`, output);
    await run(baseEndpoint);
  } finally {
    child.kill();
    await new Promise<void>((resolve) => {
      if (child.exitCode !== null || child.signalCode !== null) {
        resolve();
        return;
      }
      child.once("exit", () => resolve());
      setTimeout(resolve, 1000);
    });
  }
}

// Starts a temporary loopback listener to obtain a port for dashboard tests. The promise resolves with the port after closing the listener.
// The caller receives an unreserved port. The promise rejects on a listener error or if no TCP address is available.
export async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createNetServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (typeof address !== "object" || address === null) {
        server.close();
        reject(new Error("unable to allocate dashboard test port"));
        return;
      }
      const { port } = address;
      server.close(() => resolve(port));
    });
  });
}

// Polls the dashboard URL in endpoint. It saves the latest failure for the final diagnostic so that transient failures stay quiet.
// The promise resolves with nothing on an OK response. output supplies the captured server text for a failure.
// @throws {Error} - after the five-second retry window without an OK response. An in-flight fetch can finish after that window.
export async function waitForEndpoint(endpoint: string, output: string): Promise<void> {
  const deadline = Date.now() + 5000;
  const processOutput = output;
  let lastError: unknown;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(endpoint);
      if (response.ok) {
        return;
      }
      lastError = new Error(`HTTP ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`timed out waiting for ${endpoint}: ${String(lastError)}\n${processOutput}`);
}

// Returns the response body from endpoint for test assertions; a non-OK status fails with the endpoint, status and body.
export async function fetchText(endpoint: string): Promise<string> {
  const response = await fetch(endpoint);
  const text = await response.text();
  assert.equal(response.ok, true, `${endpoint} returned ${response.status}: ${text}`);
  return text;
}

// Writes a broad temporary catalogue fixture because one scan must cover many rule families. Returns the distinct rule IDs the scan emits.
export function ruleCatalogueCoverageRuleIds(): Set<string> {
  return new Set(ruleCatalogueCoverageFindings().map((finding) => finding.ruleId));
}

// Returns every finding from the broad catalogue fixture in stable sorted report order for assertions about finding fields.
// Writes a temporary fixture project, changes into it for the scan, then restores the working directory and removes the project.
export function ruleCatalogueCoverageFindings(): Finding[] {
  return analyseProject(catalogueCoverageFiles(), catalogueCoverageOptions()).findings;
}

// Return project-relative paths and file contents for the catalogue fixture, including source, tests, credentials and configuration.
function catalogueCoverageFiles(): Record<string, string> {
  return {
      "src/catalogue.ts": catalogueRuntimeCoverageSource(),
      "src/dep.ts": `export const usedThing = "used";
`,
      "src/helpers.ts": `/** Handles payment requests in the catalogue coverage project. */
export class PaymentController {}
`,
      "src/catalogue.test.ts": catalogueTestCoverageSource(),
      "src/app/feature/controller.ts": `import { sharedHelper } from "../../../shared/helper";

// Exercises a deep relative import from a controller fixture.
export function renderController(): string {
  return sharedHelper();
}
`,
      "src/cycle/a.ts": `import { fromB } from "./b";

// Creates one side of the circular-import fixture.
export function fromA(): string {
  return fromB();
}
`,
      "src/cycle/b.ts": `import { fromA } from "./a";

// Creates the other side of the circular-import fixture.
export function fromB(): string {
  return fromA();
}
`,
      "src/shared/helper.ts": `export function sharedHelper(): string {
  return "shared";
}
`,
      "src/untested.ts": `export function untestedValue(): string {
  return "untested";
}
`,
      ".env": `AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_FIXTURE_VALUE}
PRIVATE_KEY=${PRIVATE_KEY_HEADER_FIXTURE_VALUE}
DATABASE_URL=${POSTGRES_URL_FIXTURE_VALUE}
JWT_TOKEN=${JWT_FIXTURE_VALUE}
OPENAI_API_KEY=${OPENAI_KEY_FIXTURE_VALUE}
PATIENT_SSN=${SSN_FIXTURE_VALUE}
PATIENT_MBI=${MBI_FIXTURE_VALUE}
API_TOKEN=${API_TOKEN_FIXTURE_VALUE}
`,
      "credentials/service-account.json": JSON.stringify({
        type: "service_account",
        private_key_id: GCP_PRIVATE_KEY_ID_FIXTURE_VALUE,
        private_key: `${PRIVATE_KEY_HEADER_FIXTURE_VALUE}\nMIIfake\n-----END PRIVATE KEY-----\n`,
        client_email: "svc@project.iam.gserviceaccount.com",
      }),
      "package.json": JSON.stringify({
        scripts: {
          postinstall: "node scripts/setup.js",
          prepare: "curl https://example.test/install.sh | sh",
        },
        bin: {
          "missing-cli": "./bin/missing.js",
          "bad-cli": "./bin/bad.js",
        },
        dependencies: {
          "wide-open": "*",
          "remote-tool": "git+https://github.com/example/remote-tool.git",
        },
      }),
      ".github/workflows/risky.yml": githubActionsCoverageWorkflowSource(),
      "bin/bad.js": "#!/usr/bin/env node\nconsole.log('ok');\n",
      "tsconfig.json": JSON.stringify({
        compilerOptions: {
          strict: false,
          noUncheckedIndexedAccess: false,
          exactOptionalPropertyTypes: false,
        },
      }),
    };
}

// Returns GitHub Actions YAML with risky settings and steps for workflow-security catalogue coverage.
function githubActionsCoverageWorkflowSource(): string {
  return `on:
  pull_request_target:
permissions: write-all
jobs:
  risky:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: vendor/deploy-action@v1
      - run: curl -fsSL https://example.test/install.sh | bash
      - run: echo "\${{ secrets.DEPLOY_TOKEN }}"
`;
}

// Returns synthetic module text for catalogue coverage of runtime, naming, schema documentation, security, and waste rules.
function catalogueRuntimeCoverageSource(): string {
  return `import { createHash } from "node:crypto";
import { exec, spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { unusedThing } from "./dep";

// TODO: collapse this coverage fixture when generated rule docs exist.
// See \`src/missing-catalogue.ts\` before updating catalogue fixtures.
// prettier-ignore
// ${COMMENTED_OUT_LEGACY_CALL}
const data1 = "placeholder";
const strName = "Ada";
const active = true;
const xx = 1;
const ctx = { request: 1 };
const disableCache = true;
const rawURL = "/health";
const databaseUrl = "/healthz";
const project_path = "src";
const projectPath = "src/index.ts";
const unsafeAny: any = {};
const embeddedToken = "${HIGH_ENTROPY_FIXTURE_VALUE}";
const maxRetryLimit = 12;
const maybeUser = { name: strName };
const optionalName = maybeUser && maybeUser.name;
const fallbackName = maybeUser.name || "anonymous";
var legacyName = fallbackName;

export function expandHelpers(data: unknown, options: unknown, target: unknown): unknown {
  return [data, options, target];
}

interface MissingCommentShape {
  name: string;
}

/** Carries payload details. */
interface ReportPayload {
  schemaVersion: string;
  fingerprint: string;
}

export type PublicAny = any;

export class WrongName {
  public status = "ready";
  private count: number;

  public constructor() {
    this.count = xx;
  }

  private hidden(): void {
    console.log(this.count);
  }
}

/** Handles process input. */
export function process(flag: boolean, userInput: string, userId: string, userIds: string[], unusedFlag: boolean, req: any, res: any): string {
  eval(userInput);
  new Function(userInput)();
  setTimeout("alert(1)", 10);
  window.setInterval("alert(1)", 10);
  exec(userInput);
  spawn(userInput, []);
  readFileSync(req.query.file, "utf8");
  fetch(req.body.url);
  res.redirect(req.query.next);
  new RegExp(process.argv[2]);
  const serializedPayload = req.body.serialized;
  nodeSerialize.unserialize(serializedPayload);
  const xmlPayload = req.body.xml;
  libxmljs.parseXml(xmlPayload, { noent: true });
  Math.random();
  document.write(userInput);
  element.innerHTML = userInput;
  element.dangerouslySetInnerHTML = { __html: userInput };
  element.__proto__ = {};
  createHash("md5").update(userInput);
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  const insecureAgent = { rejectUnauthorized: false, minVersion: "TLSv1" };
  location.href = "javascript:alert(1)";
  db.query("SELECT * FROM users WHERE id = " + userId);
  const timestamp = new Date().getTime();
  const copy = Object.assign({}, { userId });
  if (!!userId) {
    observe(copy);
  }
  if (userId == "legacy") {
    observe(timestamp);
  }
  userIds.forEach(async (id) => {
    await sendEmailAsync(id);
  });
  sendEmailAsync(userIds[0]);
  try {
    riskyWork();
  } catch (error) {
    throw error;
  }
  try {
    riskyWork();
  } catch (error) {
    // FIXME
  }
  if (flag) {
    if (userId) {
      return optionalName;
    }
  } else if (legacyName) {
    return legacyName;
  }
  if (userId === "a") {
    return "a";
  }
  if (userId === "b") {
    return "b";
  }
  if (userId === "c") {
    return "c";
  }
  if (userId === "d") {
    return "d";
  }
  if (userId === "e") {
    return "e";
  }
  if (userId === "f") {
    return "f";
  }
  if (userId === "g") {
    return "g";
  }
  if (userId === "h") {
    return "h";
  }
  if (userId === "i") {
    return "i";
  }
  void insecureAgent;
  throw "dynamic failure";
  console.log(unsafeAny);
}

function finish(): void {
  doWork();
  return;
}

function emptyWork(): void {}

function redundantResult(): string {
  const calculated = fallbackName;
  return calculated;
}

/**
 * score amount
 * @param stale Removed parameter.
 */
export function scoreAmount(amount: number): number {
  return amount + redundantResult().length;
}

export function unsafePublicApi(input: any): any {
  // ${TS_IGNORE_DIRECTIVE}
  const user = input as unknown as { name?: string };
  return user!.name;
}
`;
}

// Provides generated test source, including deliberate environment mutation coverage.
function catalogueTestCoverageSource(): string {
  return `import assert from "node:assert/strict";

// These independently named cases provide positive coverage for the opt-in group detector.
${"test"}("first conversion", () => { const input = 1; const result = convert(input); assert.equal(result, 2); });
${"test"}("second conversion", () => { const input = 2; const result = convert(input); assert.equal(result, 3); });
${"test"}("third conversion", () => { const input = 3; const result = convert(input); assert.equal(result, 4); });

const fixturePurposeReport = analyseFixture(${"`"}
${largeFixtureSourceLines("catalogueFixtureValue").join("\n")}
${"`"});
void fixturePurposeReport;

// Provides a named fixture callable used by render-related rule coverage.
function renderCatalogue(): string {
  return "catalogue";
}

${"test"}("no assertion", () => {
  const catalogueOutput = renderCatalogue();
});

${"test"}("trivial assertion", () => {
  assert.equal(1, 1);
});

${"test"}("snapshot only", () => {
  expect(renderCatalogue()).toMatchSnapshot();
});

${"test"}("no throw only", () => {
  assert.doesNotThrow(() => renderCatalogue());
});

${"test"}("magic assertion", () => {
  const total = 7;
  expect(total).toBe(42);
});

${"test"}("static shape assertion", () => {
  assert.equal(typeof renderCatalogue, "function");
});

${"test"}("unused mock", () => {
  const unusedMock = jest.fn();
  assert.ok(true);
});

${"test"}("mock only", () => {
  const serviceMock = vi.fn();
  serviceMock();
  expect(serviceMock).toHaveBeenCalled();
});

${"test"}("exception type only", () => {
  expect(() => fail()).toThrow(Error);
});

${"test"}("global mutation", () => {
  process.env.NODE_ENV = "test";
  assert.equal(process.env.NODE_ENV, "test");
});

${"test"}("setup bloat and control flow", () => {
  const one = buildOne();
  const two = buildTwo();
  const three = buildThree();
  if (one) {
    for (const setupEntry of [one, two, three]) {
      if (setupEntry) {
        sleep(setupEntry);
        assert.ok(setupEntry);
      }
    }
  }
  setTimeout(() => undefined, 1);
  ${"test"}.only("nested focus marker", () => undefined);
  assert.equal(one, one);
});
`;
}

// Return scan options that enable optional catalogue checks and lower thresholds for the synthetic fixture's positive cases.
function catalogueCoverageOptions(): AnalyseProjectOptions {
  return {
      config: {
        rules: {
          // Pin duplicate-body detection on so the repeated conversion cases stay covered if the catalogue default changes.
          "test-quality.duplicate-test-body": { enabled: true },
          // Off by default; the coverage project switches it on for a positive case.
          "complexity.cyclomatic": { enabled: true, threshold: 2, severity: "warning" },
          "design.large-module-concentration": { threshold: 35, severity: "advisory", options: { minFiles: 4, minLines: 8 } },
          "size.file-length": { threshold: 8, severity: "warning" },
          "size.function-length": { threshold: 8, severity: "warning" },
          "size.parameter-count": { threshold: 3, severity: "warning" },
          // ADR-021 keeps the open-redirect and JWT checks opt-in. Enable both here to exercise their positive fixture cases.
          "security.open-redirect-candidate": { enabled: true },
          "sensitive-data.jwt-token": { enabled: true },
          // Off by default: their keyword lists cannot accept a comment written in other words.
          "docs.missing-side-effect-doc": { enabled: true },
          "docs.missing-invariant-doc": { enabled: true },
          // Exercise the fixture's empty catch block with swallowed-catch detection enabled.
          "waste.swallowed-catch": { enabled: true },
          "security.inner-html": { enabled: true },
          "security.path-traversal-candidate": { enabled: true },
          "sensitive-data.aws-access-key": { enabled: true },
          "sensitive-data.database-url-password": { enabled: true },
          "waste.useless-return": { enabled: true },
          "security.unsafe-deserialization": { enabled: true },
        },
      },
    };
}
