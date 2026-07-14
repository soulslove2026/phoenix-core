import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { assessExternalAssuranceEvidence, canonicalJson, createExternalAssuranceTemplate, externalAssuranceKinds, sha256Text, validateExternalAssuranceEvidence, type ExternalAssuranceEvidence } from "../src/assurance/external-evidence.js";

function usage(): never {
  throw new Error("usage: external-assurance-evidence <init|validate|bundle|status> <evidence-directory> [output-directory] [--require-complete]");
}
function absolute(value: string | undefined): string { if (!value) usage(); return path.resolve(value); }
function insideRepository(target: string): boolean {
  const relative = path.relative(process.cwd(), target);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}
function assertExternalPath(target: string, label: string): void {
  if (insideRepository(target)) throw new Error(`${label} must be outside the governed repository`);
}
function jsonFiles(directory: string): string[] {
  if (!fs.existsSync(directory) || !fs.statSync(directory).isDirectory()) throw new Error(`evidence directory not found: ${directory}`);
  return fs.readdirSync(directory).filter(name => name.endsWith(".json") && !["evidence-summary.json", "evidence-manifest.json"].includes(name)).sort();
}
function readEvidence(directory: string): Readonly<{ file: string; record: ExternalAssuranceEvidence; canonical: string }[]> {
  return jsonFiles(directory).map(file => {
    const raw = fs.readFileSync(path.join(directory, file), "utf8");
    const record = validateExternalAssuranceEvidence(JSON.parse(raw) as unknown);
    return Object.freeze({ file, record, canonical: canonicalJson(record) });
  });
}
function secureDirectory(directory: string): void {
  fs.mkdirSync(directory, { recursive: false, mode: 0o700 });
  fs.chmodSync(directory, 0o700);
}
function writeSecure(file: string, content: string): void {
  fs.writeFileSync(file, content, { encoding: "utf8", mode: 0o600, flag: "wx" });
  fs.chmodSync(file, 0o600);
}

const command = process.argv[2];
const evidenceDirectory = absolute(process.argv[3]);
const requireComplete = process.argv.includes("--require-complete");

if (command === "init") {
  assertExternalPath(evidenceDirectory, "evidence directory");
  if (fs.existsSync(evidenceDirectory)) throw new Error("evidence directory already exists");
  secureDirectory(evidenceDirectory);
  const fixedTime = new Date();
  for (const kind of externalAssuranceKinds) writeSecure(path.join(evidenceDirectory, `${kind}.json`), canonicalJson(createExternalAssuranceTemplate(kind, fixedTime)));
  console.log(JSON.stringify({ event: "external_assurance.templates_initialized", directory: evidenceDirectory, count: externalAssuranceKinds.length }));
} else if (command === "validate" || command === "status") {
  const evidence = readEvidence(evidenceDirectory);
  const assessment = assessExternalAssuranceEvidence(evidence.map(item => item.record));
  console.log(canonicalJson(assessment).trim());
  if (requireComplete && !assessment.complete) process.exitCode = 2;
} else if (command === "bundle") {
  assertExternalPath(evidenceDirectory, "evidence directory");
  const outputDirectory = absolute(process.argv[4]);
  assertExternalPath(outputDirectory, "output directory");
  if (fs.existsSync(outputDirectory)) throw new Error("output directory already exists");
  const evidence = readEvidence(evidenceDirectory);
  const assessment = assessExternalAssuranceEvidence(evidence.map(item => item.record));
  if (!assessment.complete) throw new Error("external assurance evidence is incomplete or not fully passed");
  secureDirectory(outputDirectory);
  const manifestEntries = evidence.map(item => ({ file: item.file, kind: item.record.kind, id: item.record.id, status: item.record.status, sha256: sha256Text(item.canonical) }));
  for (const item of evidence) writeSecure(path.join(outputDirectory, item.file), item.canonical);
  writeSecure(path.join(outputDirectory, "evidence-summary.json"), canonicalJson(assessment));
  writeSecure(path.join(outputDirectory, "evidence-manifest.json"), canonicalJson({ schema: "phoenix.external-assurance-manifest.v1", createdAt: new Date().toISOString(), entries: manifestEntries }));
  writeSecure(path.join(outputDirectory, "SHA256SUMS"), manifestEntries.map(item => `${item.sha256}  ${item.file}`).join("\n") + "\n");
  console.log(JSON.stringify({ event: "external_assurance.bundle_created", directory: outputDirectory, evidenceCount: evidence.length, complete: true }));
} else {
  usage();
}
