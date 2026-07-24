import { createHash } from "node:crypto";
import type {
  ExternalAssuranceAssessment,
  ExternalAssuranceEvidence,
  ExternalAssuranceKind,
} from "./external-evidence.js";

export type AssuranceOperatorRecordSummary = Readonly<{
  id: string;
  kind: ExternalAssuranceKind;
  status: ExternalAssuranceEvidence["status"];
  environment: ExternalAssuranceEvidence["environment"];
  changeReference: string;
  artifactCount: number;
  approvalCount: number;
}>;

export type AssuranceOperatorReport = Readonly<{
  schema: "phoenix.assurance-operator-report.v1";
  generatedAt: string;
  evidenceDirectoryDigest: string;
  complete: boolean;
  assessment: ExternalAssuranceAssessment;
  records: readonly AssuranceOperatorRecordSummary[];
  recommendations: readonly string[];
}>;

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function sortedUnique(values: readonly string[]): readonly string[] {
  return Object.freeze([...new Set(values)].sort());
}

export function assuranceOperatorRecommendations(
  assessment: ExternalAssuranceAssessment,
): readonly string[] {
  const recommendations: string[] = [];

  if (assessment.missingKinds.length > 0) {
    recommendations.push(`collect missing evidence: ${assessment.missingKinds.join(", ")}`);
  }
  if (assessment.duplicateKinds.length > 0) {
    recommendations.push(`reconcile duplicate evidence: ${assessment.duplicateKinds.join(", ")}`);
  }
  if (assessment.notPassedKinds.length > 0) {
    recommendations.push(`resolve non-passed evidence: ${assessment.notPassedKinds.join(", ")}`);
  }
  if (assessment.nonQualifyingKinds.length > 0) {
    recommendations.push(
      `repeat evidence in qualifying environments: ${assessment.nonQualifyingKinds.join(", ")}`,
    );
  }
  if (assessment.complete) {
    recommendations.push("external assurance evidence is complete and eligible for governed bundling");
  }

  return sortedUnique(recommendations);
}

export function createAssuranceOperatorReport(
  evidenceDirectory: string,
  records: readonly ExternalAssuranceEvidence[],
  assessment: ExternalAssuranceAssessment,
  now = new Date(),
): AssuranceOperatorReport {
  const recordSummaries = records
    .map((record): AssuranceOperatorRecordSummary =>
      Object.freeze({
        id: record.id,
        kind: record.kind,
        status: record.status,
        environment: record.environment,
        changeReference: record.changeReference,
        artifactCount: record.artifacts.length,
        approvalCount: record.approvals.length,
      }),
    )
    .sort((left, right) => left.kind.localeCompare(right.kind));

  return Object.freeze({
    schema: "phoenix.assurance-operator-report.v1",
    generatedAt: now.toISOString(),
    evidenceDirectoryDigest: sha256(evidenceDirectory),
    complete: assessment.complete,
    assessment,
    records: Object.freeze(recordSummaries),
    recommendations: assuranceOperatorRecommendations(assessment),
  });
}

export function assuranceOperatorExitCode(
  assessment: ExternalAssuranceAssessment,
  requireComplete: boolean,
): 0 | 2 {
  return requireComplete && !assessment.complete ? 2 : 0;
}
