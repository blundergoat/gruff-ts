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
  // Action handlers in cli-program.ts are async (await maybePromptInitConfig). parseAsync is
  // required so rejections after the first await surface through Commander's error path instead
  // of escaping as unhandled promise rejections.
  await buildProgram().parseAsync(argv);
}

export { absolutize, analyse, buildProgram, displayPath, renderReport, ruleDescriptors };
