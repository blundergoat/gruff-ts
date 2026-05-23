// Smoke coverage for the type-only module. The behavioural tests live in their respective rule
// suites; here we only confirm the unions stay assignable to their canonical members.
import assert from "node:assert/strict";
import test from "node:test";
import type { Pillar, Severity } from "./types.ts";

test("types module exposes the documented union members", () => {
  const severity: Severity = "advisory";
  const pillar: Pillar = "design";
  assert.equal(severity, "advisory");
  assert.equal(pillar, "design");
});
