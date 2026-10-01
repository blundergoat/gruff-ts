// Checks the entropy warnings users receive for public-looking values and related opaque text.
//
// Source projections reproduce adjudicated cases through the actual JSON scan.
// Authored mutations prove that a public prefix or field name cannot hide an unrelated opaque suffix.
import assert from "node:assert/strict";
import test from "node:test";
import { analyseProject } from "./test-fixtures.ts";
import { isPublicEntropyShape } from "./entropy-public-shapes.ts";

const SHARED_CASES: ReadonlyArray<readonly [string, string, boolean]> = [
  ["review5-4-article-route", "/hc/en-au/articles/1234567890123-Guide-to-fax-messages-in-Halaxy", false],
  ["article-twelve-digit-id", "/hc/en-au/articles/123456789012-Guide-to-fax-messages-in-Halaxy", false],
  ["article-approved-a", "/hc/en-au/articles/1234567890123-Deactivate-a-user-from-your-group", false],
  ["article-complete-url", "https://support.halaxy.com/hc/en-au/articles/1234567890123-Guide-to-fax-messages-in-Halaxy", false],
  ["article-wrong-prefix", "/support/en-au/articles/1234567890123-Guide-to-fax-messages-in-Halaxy", true],
  ["article-eleven-digit-id", "/hc/en-au/articles/12345678901-Guide-to-fax-messages-in-Halaxy", true],
  ["article-fourteen-digit-id", "/hc/en-au/articles/12345678901234-Guide-to-fax-messages-in-Halaxy", true],
  ["article-unapproved-short-word", "/hc/en-au/articles/1234567890123-Guide-by-fax-messages", true],
  ["article-uppercase-joiner", "/hc/en-au/articles/1234567890123-Guide-TO-fax-messages", true],
  ["article-opaque-prefix", "q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0/hc/en-au/articles/1234567890123-Guide-to-fax-messages-in-Halaxy", true],
  ["article-opaque-tail", "/hc/en-au/articles/1234567890123-Guide-to-fax-messages-in-Halaxyq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true],
  ["article-split-opaque-tail", "/hc/en-au/articles/1234567890123-Guide-to-fax-messages-in-Halaxy-q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true],
  ["article-joiner-not-section", "/hc/en-au/sections/123456789012-Guide-to-fax-messages-in-Halaxy", true],
  ["review5-24-lowercase-digit-alphabet", "abcdefghijklmnopqrstuvwxyz0123456789", false],
  ["lowercase-digit-permutation", "bacdefghijklmnopqrstuvwxyz0123456789", true],
  ["lowercase-digit-duplicate", "abcdefghijklmnopqrstuvwxyz01234567899", true],
  ["lowercase-digit-opaque-prefix", "q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0abcdefghijklmnopqrstuvwxyz0123456789", true],
  ["lowercase-digit-opaque-tail", "abcdefghijklmnopqrstuvwxyz0123456789q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true],
  ["review4-24-base62-alphabet", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", false],
  ["base62-permutation", "BACDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", true],
  ["base62-duplicate", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567899", true],
  ["base62-opaque-prefix", "q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", true],
  ["base62-opaque-tail", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true],
  ["review4-signature-ES256", "security.access_token_handler.oidc.signature.ES256", false],
  ["review4-signature-ES384", "security.access_token_handler.oidc.signature.ES384", false],
  ["review4-signature-ES512", "security.access_token_handler.oidc.signature.ES512", false],
  ["review4-signature-RS256", "security.access_token_handler.oidc.signature.RS256", false],
  ["review4-signature-RS384", "security.access_token_handler.oidc.signature.RS384", false],
  ["review4-signature-RS512", "security.access_token_handler.oidc.signature.RS512", false],
  ["review4-signature-PS256", "security.access_token_handler.oidc.signature.PS256", false],
  ["review4-signature-PS384", "security.access_token_handler.oidc.signature.PS384", false],
  ["review4-signature-PS512", "security.access_token_handler.oidc.signature.PS512", false],
  ["signature-unknown-code", "security.access_token_handler.oidc.signature.HS512", true],
  ["signature-wrong-size", "security.access_token_handler.oidc.signature.PS513", true],
  ["signature-wrong-case", "security.access_token_handler.oidc.signature.ps512", true],
  ["signature-wrong-prefix", "other.security.access_token_handler.oidc.signature.PS512", true],
  ["signature-opaque-tail", "security.access_token_handler.oidc.signature.PS512q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true],
  ["signature-opaque-prefix", "q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0security.access_token_handler.oidc.signature.PS512", true],
  ["review4-18-entra-route", "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true", false],
  ["review3-24-uuid-alphabet", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", false],
  ["uuid-alphabet-permutation", "1023456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", true],
  ["uuid-alphabet-opaque-prefix", "q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z00123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", true],
  ["uuid-alphabet-opaque-tail", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true],
  ["review3-18-commit-url", "https://github.com/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e", false],
  ["recaptchaSiteKey", "q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true],
  ["review2-4-category", "/hc/en-au/categories/360002157933-Schedule", false],
  ["review2-34-article", "https://support.halaxy.com/hc/en-au/articles/6033481017999-Customise-your-reminder-templates", false],
  ["review2-45-base64-decoder", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=", false],
  ["decoder-extra-padding", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/==", true],
  ["decoder-permutation", "BACDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=", true],
  ["decoder-opaque-prefix", "q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=", true],
  ["decoder-opaque-tail", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true],
  ["category-opaque-tail", "/hc/en-au/categories/360002157933-Scheduleq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true],
  ["category-unapproved-prefix", "public/hc/en-au/categories/360002157933-Schedule", true],
  ["category-short-word", "/hc/en-au/categories/360002157933-Schedule-Ab", true],
  ["category-mixed-case", "/hc/en-au/categories/360002157933-ScHeDuLe", true],
  ["category-overlong-word", "/hc/en-au/categories/360002157933-Schedule-AlphabeticRepresentationReference", true],
  ["category-numeric-label", "/hc/en-au/categories/360002157933-Schedule-123", true],
  ["category-long-id", "/hc/en-au/categories/3600021579337-Schedule", true],
  ["review-1-ec2", "github.com/aws/aws-sdk-go-v2/feature/ec2/imds", false],
  ["review-43-parent-path", "../../examples/tutorial_derive/03_02_option_mult.md", false],
  ["review-46-hashids-alphabet", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890", false],
  ["ec2-opaque-tail", "github.com/aws/aws-sdk-go-v2/feature/ec2/imdsq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true],
  ["parent-path-opaque-tail", "../../manuals/tutorial_derive/03_02_option_mult.mdq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true],
  ["hashids-alphabet-opaque-tail", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true],
  ["three-parent-path", "../../../manuals/tutorial_derive/03_02_option_mult.md/DeveloperGuide", true],
  ["unknown-ec2-code", "github.com/aws/aws-sdk-go-v2/feature/ec23/imds", true],
  ["unknown-alphabet-permutation", "bcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890a", true],
  ["review-5-complete-help-url", "https://support.halaxy.com/hc/en-au/articles/360044495693-Deactivate-a-user-from-your-group", false],
  ["review-34-complete-sqs-url", "https://sqs.ap-southeast-2.amazonaws.com/123456789012/media-concat-processing-queue?auto_setup=false", false],
  ["case-50", "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRTUVWXY23456789", false],
  ["case-149", "ComposerAutoloaderInit386a05f6676643b8b2eb49288e20d079", true],
  ["case-243", "Cryptography_HAS_TLSv1_3_HS_FUNCTIONS", false],
  ["case-244", "chacha20poly1305_bad_tag_second_chunk_full", false],
  ["case-245", "Cryptography_STACK_OF_X509_OBJECT *X509_STORE_get0_objects(X509_STORE *);", false],
  ["case-247", "int sk_X509_OBJECT_num(Cryptography_STACK_OF_X509_OBJECT *);", false],
  ["case-249", "Cryptography_HAS_TLSv1_3_FUNCTIONS", false],
  ["case-250", "cryptography-manylinux2014_aarch64", false],
  ["case-252", "aes256gcm_bad_tag_empty_final_chunk", false],
  ["case-254", "static const long Cryptography_HAS_TLSv1_3_HS_FUNCTIONS = 0;", false],
  ["case-256", "chacha20poly1305_bad_tag_first_chunk", false],
  ["case-434", "soljson-v0.8.21+commit.d9974bed.js", false],
  ["case-435", "./node_modules/core-js/internals/v8-prototype-define-bug.js", false],
  ["case-443", "SNYK-JS-EXPRESSFILEUPLOAD-473997", false],
  ["case-444", "1005568560502-6hm16lef8oh46hr2d98vf2ohlnj4nfhq.apps.googleusercontent.com", false],
  ["opaque", "q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true],
  ["alphabet-tail", "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRTUVWXY23456789q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true],
  ["opaque-prefix-alphabet", "q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRTUVWXY23456789", true],
  ["structured-tail", "public_metadata_q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true],
  ["misleading-word-prefix", "public_metadata_alphaq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true],
  ["split-opaque-tail", "public_metadata_q7W9e2R4t6Y8u1I3o5P0_a9S7d5F3g1H8j6K4l2Z0", true],
  ["path", "q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true],
  ["ruleId", "q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true],
  ["clientId", "q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true],
  ["public-format-tail", "1005568560502-6hm16lef8oh46hr2d98vf2ohlnj4nfhq.apps.googleusercontent.comq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true],
  ["alphabet-0", "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", false],
  ["alphabet-1", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", false],
  ["alphabet-2", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_", false],
  ["alphabet-3", "abcdefghijklmnopqrstuvwxyz0123456789-_", false],
  ["alphabet-4", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", false],
  ["alphabet-5", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", false],
  ["alphabet-6", "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRTUVWXY23456789", false],
  ["alphabet-7", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_", false],
  ["legacy-0", "Com.Example2.Services.Authentication.TokenProvider", false],
  ["legacy-1", "docs/decisions/ADR-020-DeferCorpusScoringParity2.md", false],
  ["legacy-2", "deepseek-ai/DeepSeek-R1-Distill-Qwen-32B", false],
  ["legacy-3", "Qwen/Qwen2.5-Coder-32B-Instruct-AWQ", false],
  ["hidden-path", ".goat-flow/tasks/0.1/M38-css-metrics-and-todo-density-calibration.md", false],
  ["rooted-path", "/repo/.goat-flow/tasks/1.7.0/M00-side-menu-navigation.md", false],
  ["hidden-path-opaque-tail", ".goat-flow/tasks/0.1/M38-css-metrics-and-todo-density-calibration.mdq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true],
  ["rooted-path-opaque-tail", "/repo/.goat-flow/tasks/1.7.0/M00-side-menu-navigation.mdq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true],
  ["repeated-leading-dot", "..goat-flow/tasks/0.1/M38-css-metrics-and-todo-density-calibration.md", true],
  ["repeated-leading-slash", "//repo/.goat-flow/tasks/1.7.0/M00-side-menu-navigation.md", true],
  ["i18n", "Automattic/i18n-check-webpack-plugin", false],
  ["timestamp-minute", "var/quality/full-corpus-20260710T2328Z/primock57-day2-consultation09-i-cant-move-my-left-arm/live-history.json", false],
  ["timestamp-second", "var/quality/0.5.0-harness-20260717T011802Z/t02.9-holdout-registration.tsv", false],
  ["help-appointments", "/hc/en-au/sections/360005188513-Appointments", false],
  ["help-report", "/hc/en-au/sections/360005149694-Communication-Report", false],
  ["clinical-code", "PH_ObservationInterpretation_HL7_V3", false],
  ["clinical-value-set", "PHVS_ObservationInterpretation_HL7_V3", false],
  ["i18n-opaque-tail", "Automattic/i18n-check-webpack-pluginq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true],
  ["timestamp-minute-opaque-tail", "var/quality/full-corpus-20260710T2328Z/primock57-day2-consultation09-i-cant-move-my-left-arm/live-history.jsonq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true],
  ["timestamp-second-opaque-tail", "var/quality/0.5.0-harness-20260717T011802Z/t02.9-holdout-registration.tsvq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true],
  ["help-appointments-opaque-tail", "/hc/en-au/sections/360005188513-Appointmentsq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true],
  ["help-report-opaque-tail", "/hc/en-au/sections/360005149694-Communication-Reportq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true],
  ["clinical-code-opaque-tail", "PH_ObservationInterpretation_HL7_V3q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true],
  ["clinical-value-set-opaque-tail", "PHVS_ObservationInterpretation_HL7_V3q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true],
  ["help-appointments-opaque-prefix", "q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0/hc/en-au/sections/360005188513-Appointments", true],
  ["clinical-code-opaque-prefix", "q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0PH_ObservationInterpretation_HL7_V3", true],
];


// Checks the shared URL guard directly because native entropy extraction excludes full URLs.
// Guard rejection supplies no claim that a URL reached the native detector.
test("commit URL policy requires a complete public reference", () => {
  assert.equal(isPublicEntropyShape("https://github.com/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e"), true);
  const invalidReferences = [
    "https://github.com/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e\n",
    "http://github.com/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e",
    "https://reader:@github.com/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e",
    "https://github.com:443/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e",
    "https://github.com.invalid/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e",
    "https://github.com/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e?mode=debug",
    "https://github.com/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e#details",
    "https://github.com/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e/details",
    "https://github.com/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10",
    "https://github.com/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e0",
    "https://github.com/python/cpython/commit/6E8DCDAAA49D4313BF9FAB9F9923CA5828FBB10E",
    "https://github.com/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10eq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0",
    "https://github.com/-python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e",
    "https://github.com/python-/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e",
    "https://github.com/python/.cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e",
    "https://github.com/python//commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e",
  ];
  // Each extra or malformed component must prevent the complete-value exception.
  invalidReferences.forEach((reference) => assert.equal(isPublicEntropyShape(reference), false, reference));
});


// Checks full portal routes directly because the native scanner excludes colon-bearing URL values.
// The synthetic UUID identifies no account; malformed components must prevent the exception.
test("portal route policy rejects extra components", () => {
  assert.equal(isPublicEntropyShape("https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true"), true);
  const invalidReferences = [
    "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true\n",
    "http://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true",
    "https://reader:@entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true",
    "https://entra.microsoft.com:443/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true",
    "https://entra.microsoft.com.invalid/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true",
    "https://entra.microsoft.com/?mode=debug#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true",
    "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/01234567-89ab-cdef-0123-456789abcde/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true",
    "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/01234567-89AB-CDEF-0123-456789ABCDEF/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true",
    "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Overview/appId/01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true",
    "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/true?Microsoft_AAD_IAM_legacyAADRedirect=true",
    "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=false",
    "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true&mode=debug",
    "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true#details",
    "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=trueq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0",
    "prefix https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true suffix",
    "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z001234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true",
  ];
  // Each malformed route must remain eligible; the assertion identifies the particular authored control that failed.
  invalidReferences.forEach((reference) => assert.equal(isPublicEntropyShape(reference), false, reference));
});

// Checks stored help links directly so native token boundaries cannot hide a malformed title.
test("article route policy rejects extra components", () => {
 assert.equal(isPublicEntropyShape("/hc/en-au/articles/1234567890123-Guide-to-fax-messages-in-Halaxy"), true);
 const invalidRoutes = [
    "/hc/en-au/articles/1234567890123-Guide-to-fax-messages-in-Halaxy\n",
    "/hc/en-au/articles/1234567890123-Guide-to-fax-messages-in-Halaxy?mode=debug",
    "/hc/en-au/articles/1234567890123-Guide-to-fax-messages-in-Halaxy#details",
    "/hc/en-au/articles/1234567890123-Guide-to-fax-messages-in-Halaxy/details",
    "prefix /hc/en-au/articles/1234567890123-Guide-to-fax-messages-in-Halaxy suffix",
    "/hc/en-au/articles/1234567890123--to-fax-messages-in-Halaxy",
    "/hc/en-au/articles/1234567890123-gUiDe-to-fax-messages-in-Halaxy",
    "/hc/en-au/articles/1234567890123-AlphabeticRepresentationReference-to-fax-messages-in-Halaxy",
    "/hc/en-au/articles/1234567890123-Guide2-to-fax-messages-in-Halaxy",
    "/hc/en-au/articles/1234567890123-Guide-to-fax-messages-IN-Halaxy",
 ];
 // Extra components or malformed title words cannot inherit the readable article's exception.
 invalidRoutes.forEach((route) => assert.equal(isPublicEntropyShape(route), false, route));
});

// Invariant: public whole values stay quiet and opaque tails or misleading keys still report.
// Controls use production-class paths because discovery exclusions cannot prove a predicate's precision.
test("shared entropy policy preserves complete public shapes and reports opaque mutations", () => {
  // Each input gets its own report, making every unexpected warning or lost warning visible to the test.
  for (const [name, candidate, shouldReport] of SHARED_CASES) {
    const report = analyseProject({ "src/entropy.json": JSON.stringify({ [name]: candidate }) });
    const findings = report.findings.filter((finding) => finding.ruleId === "sensitive-data.high-entropy-string");
    assert.equal(findings.length, shouldReport ? 1 : 0, name);
  }
});
