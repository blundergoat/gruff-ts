// GitHub Actions permission fixtures keep the scanner aligned with GitHub's dated scope table.
// Maintainers reach these tests when a workflow permission gains or loses write access.
// The matrix protects specific report messages while keeping read-only workflow settings quiet.
import assert from "node:assert/strict";
import test from "node:test";
import { analyseProject } from "./test-fixtures.ts";

const REVIEWED_WRITE_PERMISSION_SCOPES = [
  { scope: "actions", documentation: "current", reviewedOn: "2026-07-12" },
  { scope: "artifact-metadata", documentation: "current", reviewedOn: "2026-07-12" },
  { scope: "checks", documentation: "current", reviewedOn: "2026-07-12" },
  { scope: "code-quality", documentation: "current", reviewedOn: "2026-07-12" },
  { scope: "contents", documentation: "current", reviewedOn: "2026-07-12" },
  { scope: "deployments", documentation: "current", reviewedOn: "2026-07-12" },
  { scope: "discussions", documentation: "current", reviewedOn: "2026-07-12" },
  { scope: "issues", documentation: "current", reviewedOn: "2026-07-12" },
  { scope: "packages", documentation: "current", reviewedOn: "2026-07-12" },
  { scope: "pages", documentation: "current", reviewedOn: "2026-07-12" },
  { scope: "pull-requests", documentation: "current", reviewedOn: "2026-07-12" },
  { scope: "security-events", documentation: "current", reviewedOn: "2026-07-12" },
  { scope: "statuses", documentation: "current", reviewedOn: "2026-07-12" },
  { scope: "repository-projects", documentation: "legacy-enterprise", reviewedOn: "2026-07-12" },
] as const;

const READ_ONLY_PERMISSION_SCOPES = ["models", "vulnerability-alerts"] as const;

// Write-capable in GitHub's table, but they mint a token or an attestation rather than granting a
// repository resource. Requesting them is GitHub's recommended alternative to storing long-lived
// credentials, so the broad-permission rule stays quiet on them.
const CAPABILITY_PERMISSION_SCOPES = ["attestations", "id-token"] as const;

test("explicit workflow writes report every reviewed write-capable permission", () => {
  const permissionsYaml = REVIEWED_WRITE_PERMISSION_SCOPES
    .map(({ scope }) => `  ${scope}: write`)
    .join("\n");
  const report = analyseProject({
    ".github/workflows/permissions.yml": `permissions:\n${permissionsYaml}\n`,
  });
  const permissionFindings = report.findings.filter(
    (finding) => finding.ruleId === "security.github-actions-broad-permissions",
  );

  assert.deepEqual(
    permissionFindings.map((finding) => ({
      scope: finding.symbol,
      message: finding.message,
      metadataPermission: finding.metadata.permission,
    })),
    REVIEWED_WRITE_PERMISSION_SCOPES.map(({ scope }) => ({
      scope,
      message: `Workflow grants broad write permission \`${scope}\`.`,
      metadataPermission: scope,
    })),
  );
});

test("capability scopes stay quiet so keyless auth is not reported as over-permissioned", () => {
  const permissionsYaml = CAPABILITY_PERMISSION_SCOPES
    .map((scope) => `  ${scope}: write`)
    .join("\n");
  const report = analyseProject({
    ".github/workflows/oidc.yml": `permissions:\n${permissionsYaml}\n  contents: read\n`,
  });

  assert.deepEqual(
    report.findings.filter((finding) => finding.ruleId === "security.github-actions-broad-permissions"),
    [],
  );
});

test("write-all keeps its specific broad-permission report", () => {
  const report = analyseProject({
    ".github/workflows/write-all.yml": "permissions: write-all\n",
  });
  const permissionFindings = report.findings.filter(
    (finding) => finding.ruleId === "security.github-actions-broad-permissions",
  );

  assert.deepEqual(
    permissionFindings.map((finding) => ({
      scope: finding.symbol,
      message: finding.message,
      metadataPermission: finding.metadata.permission,
    })),
    [{
      scope: "write-all",
      message: "Workflow grants broad write permission `write-all`.",
      metadataPermission: "write-all",
    }],
  );
});

test("read permissions and read-only scope names stay quiet", () => {
  const reviewedReadPermissions = REVIEWED_WRITE_PERMISSION_SCOPES
    .map(({ scope }) => `  ${scope}: read`);
  const readOnlyPermissions = READ_ONLY_PERMISSION_SCOPES
    .flatMap((scope) => [`  ${scope}: read`, `  ${scope}: write`]);
  const report = analyseProject({
    ".github/workflows/read-only.yml": `permissions:\n${[...reviewedReadPermissions, ...readOnlyPermissions].join("\n")}\n`,
  });

  assert.deepEqual(
    report.findings.filter((finding) => finding.ruleId === "security.github-actions-broad-permissions"),
    [],
  );
});
