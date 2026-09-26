/*
 * Error class for user-facing config-load failures. CLI action handlers catch this specifically so
 * a malformed `.gruff-ts.yaml` produces a clean stderr message and exit code 2, instead of a raw
 * Node stack trace. The `suggestion` field carries the user-actionable next step (run init --force,
 * edit a specific value, etc.) so the CLI layer can format it consistently across all throw sites.
 * Reports a tagged error that the CLI layer recognises via `instanceof`.
 */
export class ConfigLoadError extends Error {
  readonly suggestion: string;

  /*
   * True when the configuration itself could not be loaded, which is what a machine caller reads as a
   * `config-error` diagnostic.
   *
   * False marks a refusal the caller asked for by combining flags. Nothing failed to load there, so there is no
   * run-invalidating diagnostic to publish, and a report the run did produce must not be replaced by an empty one.
   */
  readonly isConfigLoadFailure: boolean;

  // Stores the suggested fix alongside the message so the CLI formatter can render both without
  // re-deriving the suggestion from the error text. Throws nothing; this is a plain data wrapper.
  constructor(message: string, suggestion: string, isConfigLoadFailure = true) {
    super(message);
    this.name = "ConfigLoadError";
    this.suggestion = suggestion;
    this.isConfigLoadFailure = isConfigLoadFailure;
  }
}
