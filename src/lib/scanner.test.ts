import { readFileSync } from "fs";
import { join } from "path";
import { describe, expect, it } from "vitest";
import { generateReport, parseWorkflow, scanWorkflow, scanWorkflows } from "./scanner";

const fixture = readFileSync(join(import.meta.dirname, "../../fixtures/vulnerable.yml"), "utf8");

describe("parseWorkflow", () => {
  it("parses jobs and triggers", () => {
    const wf = parseWorkflow(fixture, "vulnerable.yml");
    expect(Object.keys(wf.jobs)).toContain("build-pr");
    expect(Object.keys(wf.jobs)).toContain("deploy");
  });
});

describe("scanWorkflow", () => {
  it("detects PR artifact upload", () => {
    const wf = parseWorkflow(fixture);
    const findings = scanWorkflow(wf);
    expect(findings.some((f) => f.type === "pr_artifact_upload")).toBe(true);
  });

  it("detects workflow_run download", () => {
    const findings = scanWorkflow(parseWorkflow(fixture));
    expect(findings.some((f) => f.type === "workflow_run_download")).toBe(true);
  });

  it("detects privileged execution", () => {
    const findings = scanWorkflow(parseWorkflow(fixture));
    expect(findings.some((f) => f.type === "privileged_execution")).toBe(true);
  });

  it("detects artifact execution", () => {
    const findings = scanWorkflow(parseWorkflow(fixture));
    expect(findings.some((f) => f.type === "artifact_executed")).toBe(true);
  });

  it("detects privilege crossing", () => {
    const findings = scanWorkflow(parseWorkflow(fixture));
    expect(findings.some((f) => f.type === "privilege_crossing")).toBe(true);
  });

  it("scores critical for vulnerable fixture", () => {
    const report = scanWorkflows([parseWorkflow(fixture)]);
    expect(report.riskLevel).toBe("critical");
  });

  it("generates markdown report", () => {
    const report = scanWorkflows([parseWorkflow(fixture)]);
    const md = generateReport(report);
    expect(md).toContain("Artifact Notary Report");
    expect(md).toContain("CRITICAL");
  });

  it("returns none for safe workflow", () => {
    const safe = `name: Safe\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test`;
    const report = scanWorkflows([parseWorkflow(safe)]);
    expect(report.riskLevel).toBe("none");
  });
});