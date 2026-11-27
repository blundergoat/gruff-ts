#!/usr/bin/env node
// Thin CLI entrypoint invoked by `bin/gruff-ts` and programmatic imports of the analyzer surface.
//
// Wires `analyse` and `analyseHookReports` into the Commander CLI program defined in `cli-program.ts`.
// Re-exports core types and functions so library consumers and tests can invoke scans without spawning a process.
import { argv } from "node:process";
import { pathToFileURL } from "node:url";
import { analyse, analyseHookReports } from "./analyser.ts";
import { buildProgram as buildCliProgram } from "./cli-program.ts";
import { absolutize, displayPath } from "./discovery.ts";
import { renderReport } from "./report-renderers.ts";
import { ruleDescriptors } from "./rules.ts";
export type { AnalysisReport, Finding, OutputFormat, Pillar, RuleDescriptor, Severity } from "./types.ts";

const analyseRunner = Object.assign(analyse, { hookViews: analyseHookReports });
/**
 * Builds the commander program with the optimized hook-view runner already attached.
 *
 * @returns Configured commander program wired with `analyseRunner`.
 */
const buildProgram = (): ReturnType<typeof buildCliProgram> => buildCliProgram(analyseRunner);

if (import.meta.url === pathToFileURL(argv[1] ?? "").href) {
  // Action handlers in cli-program.ts are async (await maybePromptInitConfig). parseAsync is
  // required so rejections after the first await surface through Commander's error path instead
  // of escaping as unhandled promise rejections.
  await buildProgram().parseAsync(argv);
}

export { absolutize, analyse, buildProgram, displayPath, renderReport, ruleDescriptors };
