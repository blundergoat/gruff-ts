// Behavioural coverage for shared finding helper predicates.
import { strict as assert } from "node:assert";
import test from "node:test";

import { isCommentedOutCode } from "./findings-helpers.ts";

test("commented-out-code accepts parseable disabled source", () => {
  assert.equal(isCommentedOutCode("// const disabledLegacy = runLegacyPath();"), true);
  assert.equal(isCommentedOutCode("// if (ready) { return run(); }"), true);
  assert.equal(isCommentedOutCode("// runLegacyPath();"), true);
  assert.equal(isCommentedOutCode("// service.reset()"), true);
});

test("commented-out-code ignores prose anchors and section labels", () => {
  assert.equal(isCommentedOutCode("// type: 'both'"), false);
  assert.equal(isCommentedOutCode("// import cycle remains documented here"), false);
  assert.equal(isCommentedOutCode("// for deeply nested files - skip shorthand"), false);
  assert.equal(isCommentedOutCode("// ---------------------------------------------------------------------------"), false);
  assert.equal(isCommentedOutCode("// scanSectionAgainstSnapshot (claim patterns)"), false);
});

// M22 hunt shapes: axios `lib/adapters/http.js`, angular `cookie-popup`, express `lib/application.js` and angular
// `component-tree.ts`, each beside the disabled source the rule exists to report.
test("commented-out-code reads prose after control words, wrapped comments and API labels as prose", () => {
  assert.equal(isCommentedOutCode("        // return the last request in case of redirects"), false);
  assert.equal(isCommentedOutCode("    // throw when using `localStorage` in private mode.", "    // Needs to be in a try/catch, because some browsers will"), false);
  assert.equal(isCommentedOutCode("    // dependency (2)", "    // the import path from the providing injector to the feature module that provided the"), false);
  assert.equal(isCommentedOutCode("// fetch(url, ...)"), false);
  assert.equal(isCommentedOutCode("// console.log(\"this isn't closed)"), false);
});

test("commented-out-code still reports disabled statements, including blocks and spreads", () => {
  assert.equal(isCommentedOutCode("// ZodStringFormat.init(inst, def);"), true);
  assert.equal(isCommentedOutCode("// return this.settings[setting];"), true);
  assert.equal(isCommentedOutCode("// throw new Error(\"bad input\")"), true);
  assert.equal(isCommentedOutCode("// await server.close()"), true);
  assert.equal(isCommentedOutCode("// return value"), true);
  assert.equal(isCommentedOutCode("// const next = 2;", "// const previous = 1;"), true);
  assert.equal(isCommentedOutCode("// if (ready) {", "// Disabled until the flag ships."), true);
  assert.equal(isCommentedOutCode("// assert(!this.isDirty);", "// TODO: when assert gets supported"), true);
  assert.equal(isCommentedOutCode("// console.log(err)"), true);
  assert.equal(isCommentedOutCode("// app.get(setting)"), true);
  assert.equal(isCommentedOutCode("// runMigration(db);", "//"), true);
  assert.equal(isCommentedOutCode("// merge(...sources);"), true);
  assert.equal(isCommentedOutCode("// const emailRegex = /^[a-z'`]+@example$/i;", "// old version: too slow"), true);
  assert.equal(isCommentedOutCode("// const originalErrorMap = z.getErrorMap(); // might not exist, but let's keep it"), true);
});
