import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import {
  assessExternalAssuranceEvidence,
  canonicalJson,
  validateExternalAssuranceEvidence,
  type ExternalAssuranceEvidence,
} from "../src/assurance/external-evidence.js";
import {
  assuranceOperatorExitCode,
  createAssuranceOperatorReport,
} from "../src/assurance/operator.js";

function usage(): never {
  throw new Error(
    "usage: assurance-operator <evidence-directory> <report-directory> [--require-complete]",
  );
}

function absolute(value: string | undefined): string {
  if (!value) usage();
  return path.resolve(value);
}

const repositoryRoot = fs.realpathSync.native(process.cwd());

function insideRepository(target: string): boolean {
  const relative = path.relative(repositoryRoot, target);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function assertExternalPath(target: string, label: string): void {
  if (insideRepository(target)) {
    throw new Error(`${label} must be outside the governed repository`);
  }
}

function existingExternalDirectory(value: string | undefined, label: string): string {
  const resolved = absolute(value);
  if (!fs.existsSync(resolved) || !fs.statSync(resolved).isDirectory()) {
    throw new Error(`${label} not found: ${resolved}`);
  }
  const canonical = fs.realpathSync.native(resolved);
  assertExternalPath(canonical, label);
  return canonical;
}

function newExternalDirectory(value: string | undefined, label: string): string {
  const resolved = absolute(value);
  if (fs.existsSync(resolved)) {
    throw new Error(`${label} already exists`);
  }
  const parent = path.dirname(resolved);
  if (!fs.existsSync(parent) || !fs.statSync(parent).isDirectory()) {
    throw new Error(`${label} parent directory not found: ${parent}`);
  }
  const canonicalParent = fs.realpathSync.native(parent);
  const canonicalTarget = path.join(canonicalParent, path.basename(resolved));
  assertExternalPath(canonicalTarget, label);
  return canonicalTarget;
}

function secureDirectory(directory: string): void {
  fs.mkdirSync(directory, { recursive: false, mode: 0o700 });
  fs.chmodSync(directory, 0o700);
}

function writeSecure(file: string, content: string): void {
  fs.writeFileSync(file, content, { encoding: "utf8", mode: 0o600, flag: "wx" });
  fs.chmodSync(file, 0o600);
}

function readEvidence(directory: string): readonly ExternalAssuranceEvidence[] {
  if (!fs.existsSync(directory) || !fs.statSync(directory).isDirectory()) {
    throw new Error(`evidence directory not found: ${directory}`);
  }

  return Object.freeze(
    fs
      .readdirSync(directory)
      .filter(
        (name) =>
          name.endsWith(".json") &&
          !["evidence-summary.json", "evidence-manifest.json", "operator-report.json"].includes(name),
      )
      .sort()
      .map((name) => {
        const evidenceFile = path.join(directory, name);
        const entry = fs.lstatSync(evidenceFile);
        if (!entry.isFile() || entry.isSymbolicLink()) {
          throw new Error(`evidence entry must be a regular file: ${name}`);
        }
        const raw = fs.readFileSync(evidenceFile, "utf8");
        return validateExternalAssuranceEvidence(JSON.parse(raw) as unknown);
      }),
  );
}

const evidenceDirectory = existingExternalDirectory(process.argv[2], "evidence directory");
const reportDirectory = newExternalDirectory(process.argv[3], "report directory");
const requireComplete = process.argv.includes("--require-complete");

const records = readEvidence(evidenceDirectory);
const assessment = assessExternalAssuranceEvidence(records);
const report = createAssuranceOperatorReport(evidenceDirectory, records, assessment);

secureDirectory(reportDirectory);
writeSecure(path.join(reportDirectory, "operator-report.json"), canonicalJson(report));

const summary = [
  "PHOENIX ASSURANCE OPERATOR",
  `complete=${report.complete}`,
  `evidence_count=${report.assessment.evidenceCount}`,
  `missing=${report.assessment.missingKinds.join(",") || "none"}`,
  `duplicates=${report.assessment.duplicateKinds.join(",") || "none"}`,
  `not_passed=${report.assessment.notPassedKinds.join(",") || "none"}`,
  `non_qualifying=${report.assessment.nonQualifyingKinds.join(",") || "none"}`,
  ...report.recommendations.map((item) => `recommendation=${item}`),
  "",
].join("\n");

writeSecure(path.join(reportDirectory, "operator-summary.txt"), summary);

console.log(
  JSON.stringify({
    event: "assurance_operator.report_created",
    evidenceDirectoryDigest: report.evidenceDirectoryDigest,
    complete: report.complete,
    evidenceCount: report.assessment.evidenceCount,
  }),
);

process.exitCode = assuranceOperatorExitCode(assessment, requireComplete);
