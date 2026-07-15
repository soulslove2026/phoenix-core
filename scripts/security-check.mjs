import fs from "node:fs";
import path from "node:path";
const fail = (message) => { console.error(message); process.exitCode = 1; };
const ignored = new Set([".git", "node_modules", "dist"]);
function walk(directory = ".") {
  const files = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory() && ignored.has(entry.name)) continue;
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...walk(full));
    else if (entry.isFile()) files.push(full.replace(/^\.\//, "").replaceAll("\\", "/"));
  }
  return files;
}
for (const file of walk()) {
  if (/(^|\/)\.env($|\.)/.test(file) && ![".env.example", "deploy/staging/.env.staging.example"].includes(file)) fail(`Forbidden environment file: ${file}`);
  if (/\.(pem|key|p12|pfx)$/i.test(file)) fail(`Forbidden key material: ${file}`);
  const text = fs.readFileSync(file, "utf8");
  if (/console\.(log|info|warn|error)\([^\n]*(password|sessionToken|transactionToken|tokenPepper|notificationKey|mfaKey|totp|recoveryCodes)/i.test(text)) fail(`Potential secret logging in ${file}`);
  if (/-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(text)) fail(`Private key material in ${file}`);
}
const ci = fs.readFileSync(".github/workflows/ci.yml", "utf8");
for (const required of [
  "npm ci --ignore-scripts", "npm audit --omit=dev --audit-level=high", "npm audit --audit-level=high",
  "npm sbom --sbom-format cyclonedx", "npm run security:check", "npm run migrate",
  "Verify Identity migration ledger", "npm run test:integration", "docker build",
  "PHOENIX_IDENTITY_MFA_KEY", "PHOENIX_IDENTITY_PASSWORD_BREACH_MODE: disabled"
]) if (!ci.includes(required)) fail(`CI security gate missing: ${required}`);

const passkeys = fs.readFileSync("src/identity/passkeys.ts", "utf8");
for (const required of ['residentKey: "required"', 'userVerification: "required"', 'requireUserVerification: true']) {
  if (!passkeys.includes(required)) fail(`Passkey security control missing: ${required}`);
}
const breach = fs.readFileSync("src/identity/password-breach.ts", "utf8");
for (const required of ['slice(0, 5)', '"add-padding": "true"', '"user-agent"', 'this.options.mode === "required"']) {
  if (!breach.includes(required)) fail(`Password breach control missing: ${required}`);
}
const totp = fs.readFileSync("src/identity/totp.ts", "utf8");
for (const required of ['createHmac("sha1"', 'periodSeconds ?? 30', 'window ?? 1', 'timingSafeEqual']) {
  if (!totp.includes(required)) fail(`TOTP control missing: ${required}`);
}
const repository = fs.readFileSync("src/identity/phase-b-repository.ts", "utf8");
if (!repository.includes("last_used_step<") || !repository.includes("initialStep")) fail("TOTP replay prevention is incomplete");
const delivery = fs.readFileSync("src/identity/notification-delivery.ts", "utf8");
for (const required of ["idempotency-key", 'redirect: "error"', "AbortSignal.timeout", "deadLetter"]) {
  if (!delivery.includes(required)) fail(`Notification delivery control missing: ${required}`);
}
const operations = fs.readFileSync("src/operations/routes.ts", "utf8");
for (const required of ["verifyOperationsBearer", "operations_unauthorized", "text/plain; version=0.0.4"]) if (!operations.includes(required)) fail(`Operations control missing: ${required}`);
const harness = fs.readFileSync("src/validation/passkey-harness.ts", "utf8");
for (const required of ["navigator.credentials.create", "navigator.credentials.get", "noindex, nofollow"]) if (!harness.includes(required)) fail(`Passkey validation control missing: ${required}`);
if (harness.includes("localStorage") || harness.includes("sessionStorage")) fail("Passkey validation harness must not persist session tokens");
const config = fs.readFileSync("src/config.ts", "utf8");
for (const required of [
  "Passkey validation harness is allowed only in local, local-compose, or staging",
  "PHOENIX_REQUIRE_TLS must be true in staging and production",
  "PHOENIX_OPERATIONS_ENABLED must be true in staging and production",
  "localhost WebAuthn RP ID is forbidden in staging and production",
  "password breach screening cannot be disabled in staging and production",
  "_FILE"
]) if (!config.includes(required)) fail(`Staging configuration control missing: ${required}`);
const rotation = fs.readFileSync("scripts/rotate-identity-keys.ts", "utf8");
const rotationLibrary = fs.readFileSync("src/identity/key-rotation.ts", "utf8");
for (const required of ["notification rotation key must change", "MFA rotation key must change", "notification and MFA rotation keys must remain independent"]) {
  if (!rotationLibrary.includes(required)) fail(`Key-rotation validation missing: ${required}`);
}
for (const required of ["validateIdentityEncryptionRotation", "pg_advisory_xact_lock", "ROTATE_IDENTITY_KEYS"]) {
  if (!rotation.includes(required)) fail(`Key-rotation control missing: ${required}`);
}
const assurance = fs.readFileSync(".github/workflows/assurance.yml", "utf8");
for (const required of ["actions/attest@v4", "pg_dump", "pg_restore", "incident:snapshot"]) if (!assurance.includes(required)) fail(`Assurance gate missing: ${required}`);


const stagingWorkflow = fs.readFileSync(".github/workflows/staging-foundation.yml", "utf8");
for (const required of ["Staging Foundation Validation", "npm run staging:preflight", "deploy/staging/compose.yaml", "Prove rendered Compose contains no secret values", "Verify governed repository stayed clean"]) {
  if (!stagingWorkflow.includes(required)) fail(`Staging foundation workflow control missing: ${required}`);
}
const stagingCompose = fs.readFileSync("deploy/staging/compose.yaml", "utf8");
for (const required of ["PHOENIX_ENV: staging", 'PHOENIX_REQUIRE_TLS: "true"', 'PHOENIX_TRUST_PROXY_HOPS: "1"', "PHOENIX_DATABASE_URL_FILE", "PHOENIX_OPERATIONS_TOKEN_FILE", "read_only: true", "cap_drop:"]) {
  if (!stagingCompose.includes(required)) fail(`Staging deployment control missing: ${required}`);
}

const externalEvidence = fs.readFileSync("src/assurance/external-evidence.ts", "utf8");
for (const required of ["passkey_real_device", "notification_provider_delivery", "key_rotation_exercise", "alert_delivery", "recovery_drill", "incident_response_exercise", "privacy_legal_review", "penetration_test", "forbidden sensitive field", "passed evidence requires an approval", "passed evidence requires at least one redacted artifact"]) {
  if (!externalEvidence.includes(required)) fail(`External assurance control missing: ${required}`);
}
const externalWorkflow = fs.readFileSync(".github/workflows/external-assurance-controls.yml", "utf8");
for (const required of ["Validate blocked committed templates", "Prove no real evidence is committed", "external-assurance-template-assessment.json", "Verify governed repository stayed clean"]) {
  if (!externalWorkflow.includes(required)) fail(`External assurance workflow control missing: ${required}`);
}
const evidenceIgnore = fs.readFileSync("assurance/evidence/.gitignore", "utf8");
if (!evidenceIgnore.includes("*") || !evidenceIgnore.includes("!README.md")) fail("Evidence quarantine ignore policy missing");

if (!fs.existsSync(".github/workflows/codeql.yml")) fail("CodeQL workflow is missing");
if (!fs.existsSync(".github/workflows/dependency-review.yml")) fail("Dependency Review workflow is missing");
if (!fs.existsSync(".github/dependabot.yml")) fail("Dependabot configuration is missing");
if (!process.exitCode) console.log("Security static checks passed.");
