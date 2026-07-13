import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const fail = (message) => { console.error(message); process.exitCode = 1; };
const read = (name) => fs.readFileSync(name, "utf8");
const parse = (name) => JSON.parse(read(name));
const required = [
  "package.json", "package-lock.json", "tsconfig.json", "tsconfig.check.json",
  "src/app.ts", "src/main.ts", "src/identity/email.ts", "src/identity/rate-limit.ts",
  "migrations/001_identity.sql", "migrations/002_identity_hardening.sql",
  "scripts/migrate.ts", "Dockerfile", "VERSION.json", "README.md", "SECURITY.md",
  "FILE_MANIFEST.json", "CHECKSUMS.sha256", ".github/workflows/ci.yml"
];
for (const file of required) if (!fs.existsSync(file)) fail(`Missing required file: ${file}`);
if (process.exitCode) process.exit();

const pkg = parse("package.json");
const lock = parse("package-lock.json");
const version = parse("VERSION.json");
const manifest = parse("FILE_MANIFEST.json");
const readme = read("README.md");
const security = read("SECURITY.md");
const systemRoutes = read("src/routes/system.ts");

if (pkg.version !== version.version) fail("package.json and VERSION.json versions differ");
if (lock.version !== version.version || lock.packages?.[""]?.version !== version.version) {
  fail("package-lock.json version differs from VERSION.json");
}
if (manifest.repository_version !== version.version) fail("FILE_MANIFEST version differs from VERSION.json");
if (!readme.includes(version.version) || !readme.includes("Identity Slice 1")) fail("README does not state the current version and slice");
if (readme.includes("This release contains no Identity domain logic")) fail("README contains a stale pre-Identity statement");
if (security.includes("Authentication and authorization are not yet implemented")) fail("SECURITY contains a stale authentication statement");
if (!systemRoutes.includes("app.config.version") || /version:\s*["\']3\./.test(systemRoutes)) fail("System endpoints contain a hard-coded release version");
if (version.production_ready !== false) fail("This release must not claim production readiness");
if (pkg.scripts.test !== "tsx --test test/*.test.ts") fail("Unit-test script must include top-level tests explicitly");
if (pkg.scripts["test:integration"] !== "tsx --test test/integration/*.test.ts") fail("Integration-test script is not explicit");

const ignoredDirectories = new Set([".git", "node_modules", "dist"]);
function walk(directory = ".") {
  const result = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory() && ignoredDirectories.has(entry.name)) continue;
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) result.push(...walk(full));
    else if (entry.isFile()) result.push(full.replace(/^\.\//, "").replaceAll("\\", "/"));
  }
  return result;
}
const actualFiles = walk().filter((file) => file !== "CHECKSUMS.sha256").sort();
const listedFiles = [...manifest.files].sort();
if (JSON.stringify(actualFiles) !== JSON.stringify(listedFiles)) fail("FILE_MANIFEST does not exactly match repository files");
if (manifest.file_count !== listedFiles.length) fail("FILE_MANIFEST file_count is incorrect");

for (const line of read("CHECKSUMS.sha256").trim().split("\n")) {
  if (!line) continue;
  const match = /^([a-f0-9]{64})  (.+)$/.exec(line);
  if (!match) { fail(`Invalid checksum line: ${line}`); continue; }
  const [, expected, file] = match;
  if (!fs.existsSync(file)) { fail(`Checksum references missing file: ${file}`); continue; }
  const actual = createHash("sha256").update(fs.readFileSync(file)).digest("hex");
  if (actual !== expected) fail(`Checksum mismatch: ${file}`);
}

const lockText = read("package-lock.json");
if (lockText.includes("internal.api.openai.org") || lockText.includes("applied-caas-gateway")) {
  fail("package-lock.json contains a private registry URL");
}
for (const forbidden of [".env"]) if (fs.existsSync(forbidden)) fail(`Forbidden path: ${forbidden}`);

if (!process.exitCode) console.log("Repository constitutional consistency checks passed.");
