#!/usr/bin/env node
// CLI shell: thin entrypoint that wires the analyser into the commander-based CLI program. The
// analyse pipeline itself lives in `./analyser.ts`; this file is just bootstrap plus re-exports.
import { argv } from "node:process";
import { pathToFileURL } from "node:url";
import { analyse } from "./analyser.ts";
import { buildProgram as buildCliProgram } from "./cli-program.ts";
import { absolutize, displayPath } from "./discovery.ts";
import { renderReport } from "./report-renderers.ts";
import { ruleDescriptors } from "./rules.ts";
export type { AnalysisReport, Finding, OutputFormat, Pillar, RuleDescriptor, Severity } from "./types.ts";

const buildProgram = (): ReturnType<typeof buildCliProgram> => buildCliProgram(analyse);

if (import.meta.url === pathToFileURL(argv[1] ?? "").href) {
  buildProgram().parse(argv);
}

export { absolutize, analyse, buildProgram, displayPath, renderReport, ruleDescriptors };
