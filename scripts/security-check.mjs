import fs from "node:fs";
import path from "node:path";
const fail=(message)=>{console.error(message);process.exitCode=1;};
const ignored=new Set([".git","node_modules","dist"]);
function walk(dir="."){const files=[];for(const entry of fs.readdirSync(dir,{withFileTypes:true})){if(entry.isDirectory()&&ignored.has(entry.name))continue;const full=path.join(dir,entry.name);if(entry.isDirectory())files.push(...walk(full));else if(entry.isFile())files.push(full.replace(/^\.\//,"").replaceAll("\\","/"));}return files;}
for(const file of walk()){
  if(/(^|\/)\.env($|\.)/.test(file)&&file!==".env.example")fail(`Forbidden environment file: ${file}`);
  if(/\.(pem|key|p12|pfx)$/i.test(file))fail(`Forbidden key material: ${file}`);
  const text=fs.readFileSync(file,"utf8");
  if(/console\.(log|info|warn|error)\([^\n]*(password|sessionToken|tokenPepper|notificationKey)/i.test(text))fail(`Potential secret logging in ${file}`);
  if(/-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(text))fail(`Private key material in ${file}`);
}
const ci=fs.readFileSync(".github/workflows/ci.yml","utf8");
for(const required of ["npm ci --ignore-scripts","npm audit --omit=dev --audit-level=high","npm audit --audit-level=high","npm sbom --sbom-format cyclonedx","npm run security:check","npm run migrate","npm run test:integration","docker build"]){if(!ci.includes(required))fail(`CI security gate missing: ${required}`);}
if(!fs.existsSync(".github/workflows/codeql.yml"))fail("CodeQL workflow is missing");
if(!fs.existsSync(".github/workflows/dependency-review.yml"))fail("Dependency Review workflow is missing");
if(!fs.existsSync(".github/dependabot.yml"))fail("Dependabot configuration is missing");
if(!process.exitCode)console.log("Security static checks passed.");
