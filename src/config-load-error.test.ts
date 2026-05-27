// Tests for the ConfigLoadError data wrapper used by the CLI's graceful config-error formatter.
import assert from "node:assert/strict";
import test from "node:test";
import { ConfigLoadError } from "./config-load-error.ts";

test("ConfigLoadError stores message and suggestion verbatim", () => {
  // Fixture covers the construction contract: message reaches `error.message`; suggestion is
  // accessible as a readonly field that the CLI's stderr formatter renders alongside the message.
  const error = new ConfigLoadError("missing schemaVersion field", "run init --force");
  assert.equal(error.message, "missing schemaVersion field");
  assert.equal(error.suggestion, "run init --force");
  assert.equal(error.name, "ConfigLoadError");
  assert.equal(error instanceof Error, true);
});
