import test from "node:test";
import assert from "node:assert/strict";
import { assessExternalAssuranceEvidence, createExternalAssuranceTemplate, externalAssuranceKinds, validateExternalAssuranceEvidence, type ExternalAssuranceEvidence } from "../src/assurance/external-evidence.js";

const digest = "a".repeat(64);
const passedMeasurements: Record<string, Record<string, string | number | boolean>> = {
  passkey_real_device: { browserFamily: "Chromium", browserVersion: "stable", operatingSystem: "desktop", authenticatorClass: "platform", registrationPassed: true, authenticationPassed: true, userVerification: "required", discoverableCredential: true },
  notification_provider_delivery: { provider: "controlled-provider", providerResponseAccepted: true, deliveryConfirmed: true, idempotencyConfirmed: true, deliveryTargetHash: digest },
  key_rotation_exercise: { dryRunPassed: true, applyPassed: true, rollbackPlanValidated: true, rowsRotated: 4 },
  alert_delivery: { channel: "controlled-channel", alertRule: "identity-degraded", deliveryConfirmed: true, acknowledgmentSeconds: 30 },
  recovery_drill: { backupDigest: digest, restorePassed: true, integrityPassed: true, rtoSeconds: 120, rpoSeconds: 30 },
  incident_response_exercise: { scenario: "identity-abuse", detectionSeconds: 60, containmentSeconds: 300, communicationsTested: true, postmortemReference: "IR-2026-001" },
  privacy_legal_review: { jurisdictions: "approved-scope", dataMapReviewed: true, retentionReviewed: true, processorContractsReviewed: true, decision: "approved" },
  penetration_test: { testingOrganization: "independent-lab", methodology: "ASVS-based", criticalOpen: 0, highOpen: 0, reportDigest: digest, retestRequired: false },
};

function passed(kind: (typeof externalAssuranceKinds)[number]): ExternalAssuranceEvidence {
  const template = createExternalAssuranceTemplate(kind, new Date("2026-07-14T00:00:00.000Z"));
  return validateExternalAssuranceEvidence({ ...template, status: "passed", controls: ["ID2-037"], measurements: passedMeasurements[kind], artifacts: [{ name: `${kind}-redacted.json`, sha256: digest, mediaType: "application/json", redacted: true, reference: `vault://phoenix/${kind}` }], approvals: [{ role: "independent-reviewer", decision: "approved", at: "2026-07-14T01:00:00.000Z", reference: `APPROVAL-${kind}` }] });
}

test("all blocked templates validate without claiming completion", () => {
  const records = externalAssuranceKinds.map(kind => validateExternalAssuranceEvidence(createExternalAssuranceTemplate(kind, new Date("2026-07-14T00:00:00.000Z"))));
  const assessment = assessExternalAssuranceEvidence(records);
  assert.equal(assessment.complete, false);
  assert.deepEqual(assessment.missingKinds, []);
  assert.equal(assessment.notPassedKinds.length, externalAssuranceKinds.length);
});

test("a unique passed record for every required kind closes the evidence set", () => {
  const assessment = assessExternalAssuranceEvidence(externalAssuranceKinds.map(passed));
  assert.equal(assessment.complete, true);
  assert.deepEqual(assessment.missingKinds, []);
  assert.deepEqual(assessment.duplicateKinds, []);
  assert.deepEqual(assessment.notPassedKinds, []);
});

test("sensitive fields and direct identifiers are rejected", () => {
  const record = createExternalAssuranceTemplate("alert_delivery", new Date("2026-07-14T00:00:00.000Z"));
  assert.throws(() => validateExternalAssuranceEvidence({ ...record, token: "not-allowed" }), /forbidden sensitive field/u);
  assert.throws(() => validateExternalAssuranceEvidence({ ...record, notes: ["send to person@example.com"] }), /potential sensitive value/u);
});

test("passed penetration evidence requires zero open critical and high findings", () => {
  const record = passed("penetration_test");
  assert.throws(() => validateExternalAssuranceEvidence({ ...record, measurements: { ...record.measurements, highOpen: 1 } }), /Critical and high/u);
});
