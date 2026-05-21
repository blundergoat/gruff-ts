// Smoke coverage for cli-program; behavioural coverage lives in cli-surfaces.test.ts.
import assert from "node:assert/strict";
import test from "node:test";
import * as cliProgram from "./cli-program.ts";

test("cli-program module loads its public surface", () => {
  assert.equal(typeof cliProgram.buildProgram, "function");
});
