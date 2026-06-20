import { readFileSync } from "fs";
import { generateReport, parseWorkflow, scanWorkflows } from "./lib/scanner";

const files = process.argv.slice(2);
if (!files.length) {
  console.error("Usage: artifact-notary <workflow.yml> [...]");
  process.exit(1);
}

const workflows = files.map((f) => parseWorkflow(readFileSync(f, "utf8"), f));
const report = scanWorkflows(workflows);
console.log(generateReport(report));
process.exit(report.riskLevel === "critical" ? 1 : 0);