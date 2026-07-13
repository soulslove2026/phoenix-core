import fs from "node:fs";
const required=["package.json","package-lock.json","tsconfig.json","src/app.ts","src/main.ts","Dockerfile","VERSION.json",".github/workflows/ci.yml"];
const missing=required.filter(x=>!fs.existsSync(x));
if(missing.length){console.error(`Missing: ${missing.join(", ")}`);process.exit(1)}
const pkg=JSON.parse(fs.readFileSync("package.json","utf8"));const ver=JSON.parse(fs.readFileSync("VERSION.json","utf8"));
if(pkg.version!==ver.version){console.error("Version mismatch");process.exit(1)}
for(const forbidden of ["dist",".env"]){if(fs.existsSync(forbidden)){console.error(`Forbidden path: ${forbidden}`);process.exit(1)}}
console.log("Repository checks passed.");
