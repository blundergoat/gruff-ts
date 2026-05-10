# Commit guidance

Use concise conventional commits (`feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `test:`). Subject under 70 characters; body for the *why*.

Project-specific rules:

- **Run `npm run check` before every commit.** It is the only validation gate (`tsc --noEmit && npm test`); a green run is the precondition for committing changes to `src/cli.ts` or `src/cli.test.ts`.
- **Do not bump schema version strings (`gruff.analysis.v1`, `gruff.baseline.v1`, `gruff.hotspot.v1`) in a commit unless the message explicitly calls out the breaking change** — these are public output contracts and downstream baseline files match them exactly.
- **Do not commit `gruff-baseline.json` or `.gruff-history.json` from this repo's own runs.** Both are gitignored; if you regenerate them for testing, leave them out of the commit.
- Never commit `.claude/settings.local.json`, `node_modules/`, or `.idea/`.

This repo has no enforced commit hook; the rules above are review-time conventions.
