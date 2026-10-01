/**
 * Keeps recognizable public constants out of a user's entropy warnings.
 *
 * The detector calls these checks before scoring a complete literal.
 * A public-looking prefix or field name cannot hide an unrelated opaque value.
 */
const PUBLIC_ALPHABETS: ReadonlySet<string> = new Set([
  "abcdefghijklmnopqrstuvwxyz0123456789",
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
  "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_",
  "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
  "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_",
  "abcdefghijklmnopqrstuvwxyz0123456789-_",
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
  "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRTUVWXY23456789",
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
]);

// Only the complete portal route and fixed navigation flags establish public application metadata.
const ENTRA_APPLICATION_URL = /^https:\/\/entra\.microsoft\.com\/#view\/Microsoft_AAD_RegisteredApps\/ApplicationMenuBlade\/~\/Credentials\/appId\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/isMSAApp~\/false\?Microsoft_AAD_IAM_legacyAADRedirect=true$(?![\s\S])/;
// These nine complete service IDs identify signature implementations; extra text cannot inherit their exception.
const SIGNATURE_SERVICE_ID = /^security\.access_token_handler\.oidc\.signature\.(?:ES|RS|PS)(?:256|384|512)$(?![\s\S])/;
const GITHUB_COMMIT_URL = /^https:\/\/github\.com\/[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\/[A-Za-z0-9][A-Za-z0-9._-]{0,99}\/commit\/[0-9a-f]{40}$(?![\s\S])/;
const PUBLIC_FORMAT = /^(?:[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com|soljson-v[0-9]+\.[0-9]+\.[0-9]+\+commit\.[0-9a-f]{8}\.js)$/;

/**
 * Checks whether a complete literal matches a public format before the scanner raises an entropy warning.
 *
 * @param candidate - Complete literal content; empty content matches no exception.
 * @returns Whether the value may skip entropy scoring; this heuristic does not prove a value is public.
 */
export function isPublicEntropyShape(candidate: string): boolean {
  return ENTRA_APPLICATION_URL.test(candidate) || SIGNATURE_SERVICE_ID.test(candidate) || GITHUB_COMMIT_URL.test(candidate) || PUBLIC_ALPHABETS.has(candidate) || PUBLIC_FORMAT.test(candidate) || isBoundedPublicFormat(candidate) || isStructuredName(candidate);
}


/**
 * Keeps established help routes and clinical codes quiet only when every word fits their complete public format.
 *
 * @param candidate - Complete value from the scanned source; partial matches grant no exception.
 * @returns Whether the full format and its words pass; false leaves the value eligible for a warning.
 */
function isBoundedPublicFormat(candidate: string): boolean {
  const article = /^\/hc\/[a-z]{2}-[a-z]{2}\/articles\/[0-9]{12,13}-([A-Za-z]+(?:-[A-Za-z]+)*)$(?![\s\S])/.exec(candidate);
  const wordCase = /^(?:[A-Z]*[a-z]+|[A-Z]+|(?:[a-z]{3,}|[A-Z]{3,}|[A-Z][a-z]{2,})(?:[A-Z][a-z]{2,}|[A-Z]{3,})+)$/;
  // A stored relative help link uses its own title grammar after the complete route matches.
  if (article?.[1] !== undefined) {
    return article[1].split("-").every((word) => word === "a" || word === "to" || word === "in" || (word.length >= 3 && word.length <= 32 && wordCase.test(word)));
  }
  const formats = [
    /^\/hc\/[a-z]{2}-[a-z]{2}\/(?:sections|categories)\/[0-9]{12}-([A-Za-z]+(?:-[A-Za-z]+)*)$/,
    /^(?:PH|PHVS)_([A-Za-z]+)_HL7_V[0-9]{1,4}$/,
  ];
  return formats.some((pattern) => {
    // An unmatched format has no captured label, so the value gets no exemption from this route.
    const words = pattern.exec(candidate)?.[1];
    return words !== undefined && words.split("-").every((word) => word.length >= 3 && word.length <= 32 && wordCase.test(word));
  });
}

/**
 * Recognizes readable names and repository paths without allowing their words to hide an opaque tail.
 *
 * @param candidate - Whole source value; empty or malformed names remain eligible for entropy scoring.
 * @returns Whether every segment passes and at least two word segments supply a strict letter majority.
 */
function isStructuredName(candidate: string): boolean {
  // A committed path may start with two parent components or one rooted, hidden or current-directory prefix.
  const normalized = candidate.replace(/^(?:(?:\.\.\/){1,2}|\.\/|[/.])/, "");
  // Missing segments or other punctuation leave the value eligible for a warning.
  if (!/^[A-Za-z0-9]+(?:[/._-]+[A-Za-z0-9]+)+$/.test(normalized)) {
    return false;
  }
  let alphanumericCount = 0;
  let wordLetterCount = 0;
  let wordSegmentCount = 0;
  // Every part must qualify; readable directories cannot vouch for a random-looking filename.
  for (const segment of normalized.split(/[/._-]+/)) {
    const segmentWordLetterCount = countSegmentWordLetters(segment);
    // A rejected segment prevents the whole value from receiving the public-name exception.
    if (segmentWordLetterCount === null) {
      return false;
    }
    alphanumericCount += segment.length;
    wordLetterCount += segmentWordLetterCount;
    wordSegmentCount += Number(segmentWordLetterCount > 0);
  }
  return wordSegmentCount >= 2 && wordLetterCount * 2 > alphanumericCount;
}

/**
 * Counts word letters in one name segment so random-looking suffixes cannot inherit a readable prefix's exemption.
 *
 * @param segment - Populated ASCII alphanumeric segment supplied by the whole-name check.
 * @returns Word-letter count; zero contributes no word evidence, and null rejects the entire name.
 */
function countSegmentWordLetters(segment: string): number | null {
  // Long undivided segments can hold opaque values, so they remain eligible for a warning.
  if (segment.length > 32) {
    return null;
  }
  // Model codes and timestamps may appear in public paths, but they contribute no readable-word evidence.
  if (/^(?:[vVxXrR][0-9]{1,4}|[0-9]{1,4}[bBeE]|[aA][0-9]{1,4}[bB]|FP[0-9]{1,4}|i18n|ec2|[mMtT][0-9]{2,3}|[0-9]{8}T[0-9]{4}(?:[0-9]{2})?Z)$/.test(segment)) {
    return 0;
  }
  // No matched runs means this segment contributes none of that character class to the name decision.
  const letterRuns = segment.match(/[A-Za-z]+/g) ?? [];
  const digitRuns = segment.match(/[0-9]+/g) ?? [];
  const maxDigits = letterRuns.length === 0 ? 6 : 4;
  // Repeated or long number runs keep opaque identifiers eligible for a warning.
  if (digitRuns.length > 2 || digitRuns.some((run) => run.length > maxDigits)) {
    return null;
  }
  const minLetters = digitRuns.length > 0 ? 3 : 1;
  const wordCase = /^(?:[A-Z]*[a-z]+|[A-Z]+|(?:[a-z]{3,}|[A-Z]{3,}|[A-Z][a-z]{2,})(?:[A-Z][a-z]{2,}|[A-Z]{3,})+)$/;
  // Short interleaved letters or arbitrary case changes are insufficient evidence of a readable public name.
  if (letterRuns.some((run) => run.length < minLetters || !wordCase.test(run))) {
    return null;
  }
  return letterRuns.reduce((count, run) => count + (run.length >= 3 ? run.length : 0), 0);
}
