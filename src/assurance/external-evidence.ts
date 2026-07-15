import { createHash, randomUUID } from "node:crypto";

export const externalAssuranceKinds = [
  "passkey_real_device",
  "notification_provider_delivery",
  "key_rotation_exercise",
  "alert_delivery",
  "recovery_drill",
  "incident_response_exercise",
  "privacy_legal_review",
  "penetration_test",
] as const;

export type ExternalAssuranceKind = (typeof externalAssuranceKinds)[number];
export type ExternalAssuranceStatus = "passed" | "failed" | "blocked";
export type ExternalAssuranceEnvironment = "local" | "staging" | "production" | "recovery" | "external";
export type EvidenceMeasurement = string | number | boolean;

export type EvidenceArtifact = Readonly<{
  name: string;
  sha256: string;
  mediaType: string;
  redacted: boolean;
  reference: string;
}>;

export type EvidenceApproval = Readonly<{
  role: string;
  decision: "approved" | "rejected";
  at: string;
  reference: string;
}>;

export type ExternalAssuranceEvidence = Readonly<{
  schema: "phoenix.external-assurance-evidence.v1";
  id: string;
  kind: ExternalAssuranceKind;
  status: ExternalAssuranceStatus;
  environment: ExternalAssuranceEnvironment;
  startedAt: string;
  completedAt: string;
  operatorRole: string;
  changeReference: string;
  summary: string;
  controls: readonly string[];
  measurements: Readonly<Record<string, EvidenceMeasurement>>;
  artifacts: readonly EvidenceArtifact[];
  approvals: readonly EvidenceApproval[];
  notes: readonly string[];
}>;

export type ExternalAssuranceAssessment = Readonly<{
  schema: "phoenix.external-assurance-assessment.v1";
  complete: boolean;
  requiredKinds: readonly ExternalAssuranceKind[];
  presentKinds: readonly ExternalAssuranceKind[];
  missingKinds: readonly ExternalAssuranceKind[];
  duplicateKinds: readonly ExternalAssuranceKind[];
  notPassedKinds: readonly ExternalAssuranceKind[];
  nonQualifyingKinds: readonly ExternalAssuranceKind[];
  evidenceCount: number;
}>;


const closureEnvironments: Readonly<Record<ExternalAssuranceKind, readonly ExternalAssuranceEnvironment[]>> = {
  passkey_real_device: ["staging", "production"],
  notification_provider_delivery: ["staging", "production"],
  key_rotation_exercise: ["staging", "production"],
  alert_delivery: ["staging", "production"],
  recovery_drill: ["recovery"],
  incident_response_exercise: ["staging", "production", "recovery"],
  privacy_legal_review: ["external"],
  penetration_test: ["external"],
};

const requiredMeasurements: Readonly<Record<ExternalAssuranceKind, readonly string[]>> = {
  passkey_real_device: ["browserFamily", "browserVersion", "operatingSystem", "authenticatorClass", "registrationPassed", "authenticationPassed", "userVerification", "discoverableCredential"],
  notification_provider_delivery: ["provider", "providerResponseAccepted", "deliveryConfirmed", "idempotencyConfirmed", "deliveryTargetHash"],
  key_rotation_exercise: ["dryRunPassed", "applyPassed", "rollbackPlanValidated", "rowsRotated"],
  alert_delivery: ["channel", "alertRule", "deliveryConfirmed", "acknowledgmentSeconds"],
  recovery_drill: ["backupDigest", "restorePassed", "integrityPassed", "rtoSeconds", "rpoSeconds"],
  incident_response_exercise: ["scenario", "detectionSeconds", "containmentSeconds", "communicationsTested", "postmortemReference"],
  privacy_legal_review: ["jurisdictions", "dataMapReviewed", "retentionReviewed", "processorContractsReviewed", "decision"],
  penetration_test: ["testingOrganization", "methodology", "criticalOpen", "highOpen", "reportDigest", "retestRequired"],
};

const forbiddenKey = /(password|secret|authorization|cookie|token|private.?key|recovery.?code|totp.?seed|credential.?id|user.?id|email|api.?key)/iu;
const emailValue = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/iu;
const privateKeyValue = /-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/u;
const bearerValue = /\bBearer\s+[A-Za-z0-9._~+\/-]+=*/iu;
const jwtValue = /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/u;
const opaqueCredentialValue = /^(?![a-f0-9]{64}$)[A-Za-z0-9_-]{40,}$/u;
const sha256 = /^[a-f0-9]{64}$/u;
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const controlId = /^ID2-\d{3}$/u;
const safeReference = /^[A-Za-z0-9._:/#-]{1,256}$/u;

function objectValue(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as Record<string, unknown>;
}
function stringValue(value: unknown, label: string, minimum = 1, maximum = 500): string {
  if (typeof value !== "string") throw new Error(`${label} must be a string`);
  const normalized = value.trim();
  if (normalized.length < minimum || normalized.length > maximum) throw new Error(`${label} length is invalid`);
  return normalized;
}
function booleanValue(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") throw new Error(`${label} must be a boolean`);
  return value;
}
function numberValue(value: unknown, label: string, minimum = 0): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < minimum) throw new Error(`${label} must be a finite number >= ${minimum}`);
  return value;
}
function isoValue(value: unknown, label: string): string {
  const text = stringValue(value, label, 20, 40);
  const parsed = Date.parse(text);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== text) throw new Error(`${label} must be canonical ISO-8601 UTC`);
  return text;
}
function rejectSensitiveContent(value: unknown, path = "evidence"): void {
  if (Array.isArray(value)) {
    value.forEach((item, index) => rejectSensitiveContent(item, `${path}[${index}]`));
    return;
  }
  if (typeof value === "object" && value !== null) {
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      if (forbiddenKey.test(key)) throw new Error(`forbidden sensitive field at ${path}.${key}`);
      rejectSensitiveContent(child, `${path}.${key}`);
    }
    return;
  }
  if (typeof value === "string") {
    if (emailValue.test(value) || privateKeyValue.test(value) || bearerValue.test(value) || jwtValue.test(value) || opaqueCredentialValue.test(value)) {
      throw new Error(`potential sensitive value at ${path}`);
    }
  }
}
function measurementString(measurements: Readonly<Record<string, EvidenceMeasurement>>, key: string): string {
  return stringValue(measurements[key], `measurements.${key}`, 1, 256);
}
function measurementBoolean(measurements: Readonly<Record<string, EvidenceMeasurement>>, key: string): boolean {
  return booleanValue(measurements[key], `measurements.${key}`);
}
function measurementNumber(measurements: Readonly<Record<string, EvidenceMeasurement>>, key: string): number {
  return numberValue(measurements[key], `measurements.${key}`);
}
function assertPassedSemantics(kind: ExternalAssuranceKind, measurements: Readonly<Record<string, EvidenceMeasurement>>): void {
  switch (kind) {
    case "passkey_real_device":
      if (!measurementBoolean(measurements, "registrationPassed") || !measurementBoolean(measurements, "authenticationPassed") || !measurementBoolean(measurements, "discoverableCredential")) throw new Error("Passkey evidence must prove registration, authentication, and discoverable credentials");
      if (measurementString(measurements, "userVerification") !== "required") throw new Error("Passkey evidence must require user verification");
      break;
    case "notification_provider_delivery":
      for (const key of ["providerResponseAccepted", "deliveryConfirmed", "idempotencyConfirmed"] as const) if (!measurementBoolean(measurements, key)) throw new Error(`Notification evidence requires ${key}`);
      if (!sha256.test(measurementString(measurements, "deliveryTargetHash"))) throw new Error("deliveryTargetHash must be SHA-256");
      break;
    case "key_rotation_exercise":
      for (const key of ["dryRunPassed", "applyPassed", "rollbackPlanValidated"] as const) if (!measurementBoolean(measurements, key)) throw new Error(`Key-rotation evidence requires ${key}`);
      if (!Number.isInteger(measurementNumber(measurements, "rowsRotated")) || measurementNumber(measurements, "rowsRotated") < 1) throw new Error("Key rotation must cover at least one row");
      break;
    case "alert_delivery":
      if (!measurementBoolean(measurements, "deliveryConfirmed")) throw new Error("Alert delivery must be confirmed");
      if (measurementNumber(measurements, "acknowledgmentSeconds") > 3600) throw new Error("Alert acknowledgment exceeded one hour");
      break;
    case "recovery_drill":
      if (!measurementBoolean(measurements, "restorePassed") || !measurementBoolean(measurements, "integrityPassed")) throw new Error("Recovery evidence must prove restore and integrity");
      if (!sha256.test(measurementString(measurements, "backupDigest"))) throw new Error("backupDigest must be SHA-256");
      measurementNumber(measurements, "rtoSeconds"); measurementNumber(measurements, "rpoSeconds");
      break;
    case "incident_response_exercise":
      if (!measurementBoolean(measurements, "communicationsTested")) throw new Error("Incident communications must be tested");
      measurementNumber(measurements, "detectionSeconds"); measurementNumber(measurements, "containmentSeconds");
      break;
    case "privacy_legal_review":
      for (const key of ["dataMapReviewed", "retentionReviewed", "processorContractsReviewed"] as const) if (!measurementBoolean(measurements, key)) throw new Error(`Privacy/legal evidence requires ${key}`);
      if (measurementString(measurements, "decision") !== "approved") throw new Error("Privacy/legal decision must be approved");
      break;
    case "penetration_test":
      if (measurementNumber(measurements, "criticalOpen") !== 0 || measurementNumber(measurements, "highOpen") !== 0) throw new Error("Critical and high penetration-test findings must be closed");
      if (!sha256.test(measurementString(measurements, "reportDigest"))) throw new Error("reportDigest must be SHA-256");
      break;
  }
}

export function validateExternalAssuranceEvidence(input: unknown): ExternalAssuranceEvidence {
  rejectSensitiveContent(input);
  const value = objectValue(input, "evidence");
  if (value.schema !== "phoenix.external-assurance-evidence.v1") throw new Error("unsupported evidence schema");
  const id = stringValue(value.id, "id", 36, 36);
  if (!uuid.test(id)) throw new Error("id must be a UUID");
  const kind = stringValue(value.kind, "kind") as ExternalAssuranceKind;
  if (!externalAssuranceKinds.includes(kind)) throw new Error("unsupported evidence kind");
  const status = stringValue(value.status, "status") as ExternalAssuranceStatus;
  if (!["passed", "failed", "blocked"].includes(status)) throw new Error("invalid evidence status");
  const environment = stringValue(value.environment, "environment") as ExternalAssuranceEnvironment;
  if (!["local", "staging", "production", "recovery", "external"].includes(environment)) throw new Error("invalid evidence environment");
  const startedAt = isoValue(value.startedAt, "startedAt");
  const completedAt = isoValue(value.completedAt, "completedAt");
  if (Date.parse(completedAt) < Date.parse(startedAt)) throw new Error("completedAt must not precede startedAt");
  const operatorRole = stringValue(value.operatorRole, "operatorRole", 3, 80);
  const changeReference = stringValue(value.changeReference, "changeReference", 3, 128);
  if (!safeReference.test(changeReference)) throw new Error("changeReference contains unsafe characters");
  const summary = stringValue(value.summary, "summary", 3, 500);

  if (!Array.isArray(value.controls) || value.controls.length < 1 || value.controls.length > 20) throw new Error("controls must contain 1-20 items");
  const controls = [...new Set(value.controls.map((item, index) => stringValue(item, `controls[${index}]`, 7, 7)))];
  if (controls.length !== value.controls.length || controls.some(item => !controlId.test(item))) throw new Error("controls must be unique ID2 identifiers");

  const rawMeasurements = objectValue(value.measurements, "measurements");
  const measurements: Record<string, EvidenceMeasurement> = {};
  for (const [key, item] of Object.entries(rawMeasurements)) {
    if (!/^[A-Za-z][A-Za-z0-9]{1,63}$/u.test(key)) throw new Error(`invalid measurement key: ${key}`);
    if (!["string", "number", "boolean"].includes(typeof item)) throw new Error(`measurement ${key} must be primitive`);
    if (typeof item === "number" && !Number.isFinite(item)) throw new Error(`measurement ${key} must be finite`);
    if (typeof item === "string") measurements[key] = stringValue(item, `measurements.${key}`, 1, 256);
    else measurements[key] = item as number | boolean;
  }
  if (status === "passed") {
    for (const key of requiredMeasurements[kind]) if (!(key in measurements)) throw new Error(`missing required measurement: ${key}`);
    assertPassedSemantics(kind, measurements);
  }

  if (!Array.isArray(value.artifacts) || value.artifacts.length > 20) throw new Error("artifacts must be an array with at most 20 items");
  const artifacts = value.artifacts.map((item, index): EvidenceArtifact => {
    const artifact = objectValue(item, `artifacts[${index}]`);
    const digest = stringValue(artifact.sha256, `artifacts[${index}].sha256`, 64, 64);
    if (!sha256.test(digest)) throw new Error(`artifacts[${index}].sha256 must be SHA-256`);
    const reference = stringValue(artifact.reference, `artifacts[${index}].reference`, 3, 256);
    if (!safeReference.test(reference)) throw new Error(`artifacts[${index}].reference contains unsafe characters`);
    return Object.freeze({
      name: stringValue(artifact.name, `artifacts[${index}].name`, 1, 120),
      sha256: digest,
      mediaType: stringValue(artifact.mediaType, `artifacts[${index}].mediaType`, 3, 100),
      redacted: booleanValue(artifact.redacted, `artifacts[${index}].redacted`),
      reference,
    });
  });

  if (!Array.isArray(value.approvals) || value.approvals.length > 10) throw new Error("approvals must be an array with at most 10 items");
  const approvals = value.approvals.map((item, index): EvidenceApproval => {
    const approval = objectValue(item, `approvals[${index}]`);
    const decision = stringValue(approval.decision, `approvals[${index}].decision`) as EvidenceApproval["decision"];
    if (!["approved", "rejected"].includes(decision)) throw new Error(`invalid approval decision at ${index}`);
    const reference = stringValue(approval.reference, `approvals[${index}].reference`, 3, 256);
    if (!safeReference.test(reference)) throw new Error(`approvals[${index}].reference contains unsafe characters`);
    return Object.freeze({ role: stringValue(approval.role, `approvals[${index}].role`, 3, 80), decision, at: isoValue(approval.at, `approvals[${index}].at`), reference });
  });
  if (status === "passed" && !approvals.some(item => item.decision === "approved")) throw new Error("passed evidence requires an approval");
  if (status === "passed" && artifacts.length < 1) throw new Error("passed evidence requires at least one redacted artifact");

  if (!Array.isArray(value.notes) || value.notes.length > 10) throw new Error("notes must be an array with at most 10 items");
  const notes = value.notes.map((item, index) => stringValue(item, `notes[${index}]`, 1, 500));

  return Object.freeze({ schema: "phoenix.external-assurance-evidence.v1", id, kind, status, environment, startedAt, completedAt, operatorRole, changeReference, summary, controls: Object.freeze(controls), measurements: Object.freeze(measurements), artifacts: Object.freeze(artifacts), approvals: Object.freeze(approvals), notes: Object.freeze(notes) });
}

export function assessExternalAssuranceEvidence(records: readonly ExternalAssuranceEvidence[]): ExternalAssuranceAssessment {
  const counts = new Map<ExternalAssuranceKind, number>();
  for (const record of records) counts.set(record.kind, (counts.get(record.kind) ?? 0) + 1);
  const presentKinds = externalAssuranceKinds.filter(kind => counts.has(kind));
  const missingKinds = externalAssuranceKinds.filter(kind => !counts.has(kind));
  const duplicateKinds = externalAssuranceKinds.filter(kind => (counts.get(kind) ?? 0) > 1);
  const notPassedKinds = externalAssuranceKinds.filter(kind => records.filter(record => record.kind === kind).some(record => record.status !== "passed") || !counts.has(kind));
  const nonQualifyingKinds = externalAssuranceKinds.filter(kind => {
    const matching = records.filter(record => record.kind === kind && record.status === "passed");
    return matching.length > 0 && matching.some(record => !closureEnvironments[kind].includes(record.environment));
  });
  return Object.freeze({
    schema: "phoenix.external-assurance-assessment.v1",
    complete: missingKinds.length === 0 && duplicateKinds.length === 0 && notPassedKinds.length === 0 && nonQualifyingKinds.length === 0 && records.length === externalAssuranceKinds.length,
    requiredKinds: externalAssuranceKinds,
    presentKinds,
    missingKinds,
    duplicateKinds,
    notPassedKinds,
    nonQualifyingKinds,
    evidenceCount: records.length,
  });
}

const templateMeasurements: Readonly<Record<ExternalAssuranceKind, Readonly<Record<string, EvidenceMeasurement>>>> = {
  passkey_real_device: { browserFamily: "replace", browserVersion: "replace", operatingSystem: "replace", authenticatorClass: "replace", registrationPassed: false, authenticationPassed: false, userVerification: "required", discoverableCredential: false },
  notification_provider_delivery: { provider: "replace", providerResponseAccepted: false, deliveryConfirmed: false, idempotencyConfirmed: false, deliveryTargetHash: "replace" },
  key_rotation_exercise: { dryRunPassed: false, applyPassed: false, rollbackPlanValidated: false, rowsRotated: 0 },
  alert_delivery: { channel: "replace", alertRule: "replace", deliveryConfirmed: false, acknowledgmentSeconds: 0 },
  recovery_drill: { backupDigest: "replace", restorePassed: false, integrityPassed: false, rtoSeconds: 0, rpoSeconds: 0 },
  incident_response_exercise: { scenario: "replace", detectionSeconds: 0, containmentSeconds: 0, communicationsTested: false, postmortemReference: "replace" },
  privacy_legal_review: { jurisdictions: "replace", dataMapReviewed: false, retentionReviewed: false, processorContractsReviewed: false, decision: "blocked" },
  penetration_test: { testingOrganization: "replace", methodology: "replace", criticalOpen: 0, highOpen: 0, reportDigest: "replace", retestRequired: true },
};

export function createExternalAssuranceTemplate(kind: ExternalAssuranceKind, now = new Date()): ExternalAssuranceEvidence {
  const timestamp = now.toISOString();
  return Object.freeze({ schema: "phoenix.external-assurance-evidence.v1", id: randomUUID(), kind, status: "blocked", environment: kind === "penetration_test" || kind === "privacy_legal_review" ? "external" : kind === "recovery_drill" ? "recovery" : "staging", startedAt: timestamp, completedAt: timestamp, operatorRole: "replace-role", changeReference: "CHANGE-REFERENCE", summary: "Replace this blocked template with sanitized evidence after the controlled exercise.", controls: Object.freeze(["ID2-034"]), measurements: templateMeasurements[kind], artifacts: Object.freeze([]), approvals: Object.freeze([]), notes: Object.freeze(["Do not include names, email addresses, tokens, credentials, or unredacted reports."]) });
}

export function canonicalJson(value: unknown): string {
  const normalize = (item: unknown): unknown => {
    if (Array.isArray(item)) return item.map(normalize);
    if (typeof item === "object" && item !== null) return Object.fromEntries(Object.entries(item as Record<string, unknown>).sort(([left], [right]) => left.localeCompare(right)).map(([key, child]) => [key, normalize(child)]));
    return item;
  };
  return `${JSON.stringify(normalize(value), null, 2)}\n`;
}

export function sha256Text(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}
