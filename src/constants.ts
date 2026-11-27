// Shared release constants that keep CLI version output, JSON envelopes, and text report hints aligned.
//
// `VERSION` must match `package.json`; `OUTPUT_VOLUME_HINT_THRESHOLD` controls when `analyse` suggests `gruff-ts summary`.
const VERSION = "0.6.0";

/*
 * Finding count at which `analyse --format text` appends a one-line pointer to `gruff-ts summary`.
 *
 * Below 50 findings a flat terminal list stays easy to scan; above 50 the per-rule digest avoids scroll fatigue.
 */
const OUTPUT_VOLUME_HINT_THRESHOLD = 50;

export { OUTPUT_VOLUME_HINT_THRESHOLD, VERSION };
