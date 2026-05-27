/*
 * Error class for user-facing config-load failures. CLI action handlers catch this specifically so
 * a malformed `.gruff-ts.yaml` produces a clean stderr message and exit code 2, instead of a raw
 * Node stack trace. The `suggestion` field carries the user-actionable next step (run init --force,
 * edit a specific value, etc.) so the CLI layer can format it consistently across all throw sites.
 * Reports a tagged error that the CLI layer recognises via `instanceof`.
 */
export class ConfigLoadError extends Error {
  readonly suggestion: string;

  // Stores the suggested fix alongside the message so the CLI formatter can render both without
  // re-deriving the suggestion from the error text. Throws nothing; this is a plain data wrapper.
  constructor(message: string, suggestion: string) {
    super(message);
    this.name = "ConfigLoadError";
    this.suggestion = suggestion;
  }
}
