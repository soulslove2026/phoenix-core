import { loadConfig } from "../src/config.js";
import { assessStagingConfig } from "../src/deployment/staging-assurance.js";

const report = assessStagingConfig(loadConfig());
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
