import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const fail = (message) => { console.error(message); process.exitCode = 1; };
const read = (name) => fs.readFileSync(name, "utf8");
const parse = (name) => JSON.parse(read(name));
const required = [
  "package.json", "package-lock.json", "tsconfig.json", "tsconfig.check.json",
  "src/app.ts", "src/main.ts", "src/config.ts",
  "src/identity/email.ts", "src/identity/password.ts", "src/identity/password-breach.ts",
  "src/identity/token-crypto.ts", "src/identity/totp.ts", "src/identity/passkeys.ts",
  "src/identity/distributed-rate-limit.ts", "src/identity/repository.ts",
  "src/identity/phase-b-repository.ts", "src/identity/phase-b-types.ts",
  "src/identity/notification-delivery.ts", "src/identity/routes.ts", "src/identity/service.ts",
  "migrations/001_identity.sql", "migrations/002_identity_hardening.sql",
  "migrations/003_identity_slice2.sql", "migrations/004_identity_phase_b.sql",
  "scripts/migrate.ts", "scripts/notification-worker.ts", "scripts/security-check.mjs",
  "scripts/dependency-governance-check.mjs", "Dockerfile", "compose.yaml", ".env.example",
  "VERSION.json", "README.md", "SECURITY.md", "ARCHITECTURE.md",
  "docs/IDENTITY_SLICE2_PHASE_B.md", "docs/PASSKEYS_AND_MFA.md",
  "docs/PASSWORD_BREACH_SCREENING.md", "docs/NOTIFICATION_DELIVERY.md",
  "FILE_MANIFEST.json", "CHECKSUMS.sha256", ".github/workflows/ci.yml",
  ".github/workflows/codeql.yml", ".github/workflows/dependency-review.yml", ".github/dependabot.yml"
];
for (const file of required) if (!fs.existsSync(file)) fail(`Missing required file: ${file}`);
if (process.exitCode) process.exit();

const pkg = parse("package.json");
const lock = parse("package-lock.json");
const version = parse("VERSION.json");
const manifest = parse("FILE_MANIFEST.json");
const readme = read("README.md");
const security = read("SECURITY.md");
const system = read("src/routes/system.ts");

if (pkg.version !== version.version) fail("package.json and VERSION.json versions differ");
if (lock.version !== version.version || lock.packages?.[""]?.version !== version.version) fail("package-lock version differs");
if (manifest.repository_version !== version.version) fail("manifest version differs");
if (!readme.includes("3.5.0") || !readme.includes("Phase B")) fail("README authority is stale");
for (const requiredControl of ["Passkeys", "TOTP", "breached-password", "notification-delivery worker"]) {
  if (!security.includes(requiredControl)) fail(`SECURITY missing Phase B control: ${requiredControl}`);
}
if (!system.includes("app.config.version") || /version:\s*["']3\./.test(system)) fail("system route version is hard-coded");
if (version.production_ready !== false || version.status !== "candidate") fail("release state is unsafe");
if (pkg.dependencies?.["@simplewebauthn/server"] !== "13.3.2") fail("SimpleWebAuthn version is not exactly ratified");

const ignored = new Set([".git", "node_modules", "dist"]);
function walk(directory = ".") {
  const output = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory() && ignored.has(entry.name)) continue;
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) output.push(...walk(full));
    else if (entry.isFile()) output.push(full.replace(/^\.\//, "").replaceAll("\\", "/"));
  }
  return output;
}
const actual = walk().filter((file) => file !== "CHECKSUMS.sha256").sort();
const listed = [...manifest.files].sort();
if (JSON.stringify(actual) !== JSON.stringify(listed)) {
  const actualSet = new Set(actual); const listedSet = new Set(listed);
  const extra = actual.filter((file) => !listedSet.has(file));
  const missing = listed.filter((file) => !actualSet.has(file));
  if (extra.length) console.error(`Unmanaged files:\n- ${extra.join("\n- ")}`);
  if (missing.length) console.error(`Missing files:\n- ${missing.join("\n- ")}`);
  fail("FILE_MANIFEST does not exactly match repository files");
}
if (manifest.file_count !== listed.length) fail("manifest count incorrect");
for (const line of read("CHECKSUMS.sha256").trim().split("\n")) {
  if (!line) continue;
  const match = /^([a-f0-9]{64})  (.+)$/.exec(line);
  if (!match) { fail(`Invalid checksum: ${line}`); continue; }
  const [, expected, file] = match;
  if (!fs.existsSync(file)) { fail(`Checksum missing file: ${file}`); continue; }
  const actualHash = createHash("sha256").update(fs.readFileSync(file)).digest("hex");
  if (actualHash !== expected) fail(`Checksum mismatch: ${file}`);
}
const lockText = read("package-lock.json");
if (lockText.includes("internal.api.openai.org") || lockText.includes("applied-caas-gateway")) fail("private registry URL found");
if (!process.exitCode) console.log("Repository constitutional consistency checks passed.");
