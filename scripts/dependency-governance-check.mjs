import fs from "node:fs";
import path from "node:path";

const fail = (message) => {
  console.error(message);
  process.exitCode = 1;
};

const directory = ".github/workflows";
const workflows = fs.readdirSync(directory)
  .filter((name) => name.endsWith(".yml") || name.endsWith(".yaml"))
  .map((name) => ({ name, text: fs.readFileSync(path.join(directory, name), "utf8") }));

const combined = workflows.map(({ text }) => text).join("\n");

for (const forbidden of [
  "actions/checkout@v4",
  "actions/checkout@v5",
  "actions/checkout@v7",
  "actions/setup-node@v4",
  "actions/setup-node@v5",
  "actions/upload-artifact@v4",
  "actions/upload-artifact@v5",
  "actions/upload-artifact@v6",
  "github/codeql-action/init@v3",
  "github/codeql-action/analyze@v3",
  "actions/dependency-review-action@v4",
  "pull_request_target:",
]) {
  if (combined.includes(forbidden)) {
    fail(`Forbidden or unreviewed workflow reference: ${forbidden}`);
  }
}

for (const required of [
  "actions/checkout@v6",
  "actions/setup-node@v6",
  "actions/upload-artifact@v7",
  "github/codeql-action/init@v4",
  "github/codeql-action/analyze@v4",
  "actions/dependency-review-action@v5",
]) {
  if (!combined.includes(required)) fail(`Approved workflow reference missing: ${required}`);
}

for (const { name, text } of workflows) {
  const checkoutCount = (text.match(/actions\/checkout@v6/g) ?? []).length;
  const safeCheckoutCount = (text.match(/persist-credentials:\s*false/g) ?? []).length;
  if (checkoutCount > safeCheckoutCount) {
    fail(`${name} must disable persisted checkout credentials`);
  }
}

const dependabot = fs.readFileSync(".github/dependabot.yml", "utf8");
if ((dependabot.match(/open-pull-requests-limit:\s*0/g) ?? []).length !== 2) {
  fail("Routine npm and GitHub Actions version updates must remain disabled");
}
for (const ecosystem of ['package-ecosystem: "npm"', 'package-ecosystem: "github-actions"']) {
  if (!dependabot.includes(ecosystem)) fail(`Dependabot security coverage missing: ${ecosystem}`);
}

const review = fs.readFileSync(".github/workflows/dependency-review.yml", "utf8");
for (const required of [
  "fail-on-severity: moderate",
  "fail-on-scopes: runtime, development, unknown",
  "pkg:githubactions/actions/checkout",
  "pkg:githubactions/actions/dependency-review-action",
]) {
  if (!review.includes(required)) fail(`Dependency Review policy missing: ${required}`);
}

if (!process.exitCode) console.log("Dependency governance checks passed.");
