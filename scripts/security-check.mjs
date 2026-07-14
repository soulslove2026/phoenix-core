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
  if (/(^|\/)\.env($|\.)/.test(file) && file !== ".env.example") fail(`Forbidden environment file: ${file}`);
  if (/\.(pem|key|p12|pfx)$/i.test(file)) fail(`Forbidden key material: ${file}`);
  const text = fs.readFileSync(file, "utf8");
  if (/console\.(log|info|warn|error)\([^\n]*(password|sessionToken|transactionToken|tokenPepper|notificationKey|mfaKey|totp|recoveryCodes)/i.test(text)) fail(`Potential secret logging in ${file}`);
  if (/-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(text)) fail(`Private key material in ${file}`);
}
const ci = fs.readFileSync(".github/workflows/ci.yml", "utf8");
for (const required of [
  "npm ci --ignore-scripts", "npm audit --omit=dev --audit-level=high", "npm audit --audit-level=high",
  "npm sbom --sbom-format cyclonedx", "npm run security:check", "npm run migrate",
  "Verify Phase B migration ledger", "npm run test:integration", "docker build",
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
if (!fs.existsSync(".github/workflows/codeql.yml")) fail("CodeQL workflow is missing");
if (!fs.existsSync(".github/workflows/dependency-review.yml")) fail("Dependency Review workflow is missing");
if (!fs.existsSync(".github/dependabot.yml")) fail("Dependabot configuration is missing");
if (!process.exitCode) console.log("Security static checks passed.");
