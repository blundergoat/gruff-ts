/*
 * User-facing configuration and flag-conflict error caught by CLI command handlers to exit 2 cleanly.
 *
 * Carries a structured `suggestion` alongside the message so broken `.gruff-ts.yaml` files or invalid selectors print actionable guidance
 * instead of a raw Node stack trace, and lets machine consumers distinguish load failures from CLI flag refusals via `isConfigLoadFailure`.
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

  // Creates the CLI error from the display message and suggested next step.
  // The failure flag defaults to true. Pass false for a flag-related refusal that should omit the config-error diagnostic.
  constructor(message: string, suggestion: string, isConfigLoadFailure = true) {
    super(message);
    this.name = "ConfigLoadError";
    this.suggestion = suggestion;
    this.isConfigLoadFailure = isConfigLoadFailure;
  }
}
