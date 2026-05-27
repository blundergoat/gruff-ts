// Shared release constants that keep CLI, reports, and rule catalogue output in sync.
const VERSION = "0.2.0";

/*
 * Threshold at which the `analyse` text renderer appends a one-line pointer to `gruff-ts summary`.
 * Below 50 a flat list is still browsable; above 50 the operator hits scroll fatigue and needs the
 * per-rule digest. Calibrated against the gruff-ts self-scan (~8 findings) and the goat-flow scan
 * in 2026-05-25 feedback (1643 findings) - the threshold earns its keep at the cross-over.
 */
const OUTPUT_VOLUME_HINT_THRESHOLD = 50;

export { OUTPUT_VOLUME_HINT_THRESHOLD, VERSION };
