import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  assessExternalAssuranceEvidence,
  createExternalAssuranceTemplate,
  externalAssuranceKinds,
  validateExternalAssuranceEvidence,
  type ExternalAssuranceEvidence,
  type ExternalAssuranceKind,
} from "../src/assurance/external-evidence.js";
import {
  assuranceOperatorExitCode,
  assuranceOperatorRecommendations,
  createAssuranceOperatorReport,
} from "../src/assurance/operator.js";

const digest = "a".repeat(64);

const measurements: Record<ExternalAssuranceKind, Record<string, string | number | boolean>> = {
  passkey_real_device: { browserFamily: "Chromium", browserVersion: "stable", operatingSystem: "Windows", authenticatorClass: "platform", registrationPassed: true, authenticationPassed: true, userVerification: "required", discoverableCredential: true },
  notification_provider_delivery: { provider: "controlled-provider", providerResponseAccepted: true, deliveryConfirmed: true, idempotencyConfirmed: true, deliveryTargetHash: digest },
  key_rotation_exercise: { dryRunPassed: true, applyPassed: true, rollbackPlanValidated: true, rowsRotated: 4 },
  alert_delivery: { channel: "controlled-channel", alertRule: "identity-degraded", deliveryConfirmed: true, acknowledgmentSeconds: 30 },
  recovery_drill: { backupDigest: digest, restorePassed: true, integrityPassed: true, rtoSeconds: 120, rpoSeconds: 30 },
  incident_response_exercise: { scenario: "identity-abuse", detectionSeconds: 60, containmentSeconds: 300, communicationsTested: true, postmortemReference: "IR-2026-001" },
  privacy_legal_review: { jurisdictions: "approved-scope", dataMapReviewed: true, retentionReviewed: true, processorContractsReviewed: true, decision: "approved" },
  penetration_test: { testingOrganization: "independent-lab", methodology: "ASVS-based", criticalOpen: 0, highOpen: 0, reportDigest: digest, retestRequired: false },
};

function qualifyingEnvironment(kind: ExternalAssuranceKind): ExternalAssuranceEvidence["environment"] {
  if (kind === "recovery_drill") return "recovery";
  if (kind === "privacy_legal_review" || kind === "penetration_test") return "external";
  return "staging";
}

function passed(kind: ExternalAssuranceKind): ExternalAssuranceEvidence {
  const template = createExternalAssuranceTemplate(kind, new Date("2026-07-23T00:00:00.000Z"));
  return validateExternalAssuranceEvidence({
    ...template,
    environment: qualifyingEnvironment(kind),
    status: "passed",
    controls: ["ID2-037"],
    measurements: measurements[kind],
    artifacts: [{
      name: `${kind}-redacted.json`,
      sha256: digest,
      mediaType: "application/json",
      redacted: true,
      reference: `vault://phoenix/${kind}`,
    }],
    approvals: [{
      role: "independent-reviewer",
      decision: "approved",
      at: "2026-07-23T01:00:00.000Z",
      reference: `APPROVAL-${kind}`,
    }],
  });
}

test("operator report is complete for eight qualifying passed records", () => {
  const records = externalAssuranceKinds.map(passed);
  const assessment = assessExternalAssuranceEvidence(records);
  const report = createAssuranceOperatorReport(
    "C:/approved/evidence",
    records,
    assessment,
    new Date("2026-07-23T02:00:00.000Z"),
  );

  assert.equal(report.complete, true);
  assert.equal(report.records.length, 8);
  assert.equal(report.evidenceDirectoryDigest.length, 64);
  assert.deepEqual(report.recommendations, [
    "external assurance evidence is complete and eligible for governed bundling",
  ]);
  assert.equal(assuranceOperatorExitCode(assessment, true), 0);
});

test("operator reports missing and non-passed evidence without claiming completion", () => {
  const blocked = createExternalAssuranceTemplate(
    "passkey_real_device",
    new Date("2026-07-23T00:00:00.000Z"),
  );
  const assessment = assessExternalAssuranceEvidence([blocked]);
  const recommendations = assuranceOperatorRecommendations(assessment);

  assert.equal(assessment.complete, false);
  assert.equal(assuranceOperatorExitCode(assessment, true), 2);
  assert.ok(recommendations.some((item) => item.startsWith("collect missing evidence:")));
  assert.ok(recommendations.some((item) => item.includes("resolve non-passed evidence")));
});


test("CLI creates sanitized reports without logging local paths", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "phoenix-operator-test-"));
  const evidenceDirectory = path.join(root, "evidence");
  const reportDirectory = path.join(root, "report");
  fs.mkdirSync(evidenceDirectory);

  const blocked = createExternalAssuranceTemplate(
    "passkey_real_device",
    new Date("2026-07-23T00:00:00.000Z"),
  );
  fs.writeFileSync(
    path.join(evidenceDirectory, "passkey_real_device.json"),
    JSON.stringify(blocked),
    "utf8",
  );

  try {
    const result = spawnSync(
      process.execPath,
      [
        "--import",
        "tsx",
        "scripts/assurance-operator.ts",
        evidenceDirectory,
        reportDirectory,
      ],
      {
        cwd: process.cwd(),
        encoding: "utf8",
      },
    );

    assert.equal(result.status, 0, result.stderr);
    assert.equal(fs.existsSync(path.join(reportDirectory, "operator-report.json")), true);
    assert.equal(fs.existsSync(path.join(reportDirectory, "operator-summary.txt")), true);
    assert.equal(result.stdout.includes(evidenceDirectory), false);
    assert.equal(result.stdout.includes(reportDirectory), false);

    const event = JSON.parse(result.stdout.trim()) as {
      event: string;
      evidenceDirectoryDigest: string;
      complete: boolean;
    };
    assert.equal(event.event, "assurance_operator.report_created");
    assert.equal(event.evidenceDirectoryDigest.length, 64);
    assert.equal(event.complete, false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("CLI rejects non-regular JSON evidence entries", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "phoenix-operator-entry-test-"));
  const evidenceDirectory = path.join(root, "evidence");
  const reportDirectory = path.join(root, "report");
  fs.mkdirSync(evidenceDirectory);
  fs.mkdirSync(path.join(evidenceDirectory, "not-a-file.json"));

  try {
    const result = spawnSync(
      process.execPath,
      [
        "--import",
        "tsx",
        "scripts/assurance-operator.ts",
        evidenceDirectory,
        reportDirectory,
      ],
      {
        cwd: process.cwd(),
        encoding: "utf8",
      },
    );

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /evidence entry must be a regular file/);
    assert.equal(fs.existsSync(reportDirectory), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
