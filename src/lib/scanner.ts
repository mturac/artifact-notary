import yaml from "js-yaml";

export type RiskLevel = "critical" | "high" | "medium" | "low" | "none";

export interface WorkflowJob {
  name: string;
  trigger: string;
  permissions: Record<string, string>;
  steps: { uses?: string; run?: string; with?: Record<string, string> }[];
  needs?: string[];
}

export interface Workflow {
  name: string;
  on: Record<string, unknown>;
  jobs: Record<string, WorkflowJob>;
  raw: string;
  file: string;
}

export interface Finding {
  id: string;
  type: string;
  risk: RiskLevel;
  message: string;
  source?: string;
  sink?: string;
  workflow: string;
  job?: string;
}

export interface ScanReport {
  findings: Finding[];
  crossings: PrivilegeCrossing[];
  riskLevel: RiskLevel;
  riskScore: number;
}

export interface PrivilegeCrossing {
  source: string;
  sink: string;
  artifact: string;
  privilege: string;
  risk: RiskLevel;
  message: string;
}

export function parseWorkflow(content: string, file = "workflow.yml"): Workflow {
  const parsed = yaml.load(content) as Record<string, unknown>;
  const on = (parsed.on ?? {}) as Record<string, unknown>;
  const jobsRaw = (parsed.jobs ?? {}) as Record<string, Record<string, unknown>>;

  const jobs: Record<string, WorkflowJob> = {};
  for (const [name, job] of Object.entries(jobsRaw)) {
    jobs[name] = {
      name,
      trigger: detectTrigger(on, job),
      permissions: (job.permissions as Record<string, string>) ?? {},
      steps: (job.steps as WorkflowJob["steps"]) ?? [],
      needs: job.needs as string[] | undefined,
    };
  }

  return {
    name: String(parsed.name ?? file),
    on,
    jobs,
    raw: content,
    file,
  };
}

function detectTrigger(on: Record<string, unknown>, job: Record<string, unknown>): string {
  if (on.pull_request) return "pull_request";
  if (on.workflow_run) return "workflow_run";
  if (on.push) return "push";
  if (job["if"] && String(job["if"]).includes("pull_request")) return "pull_request";
  return "other";
}

const PRIVILEGED = new Set(["write", "admin"]);
const ARTIFACT_UPLOAD = /actions\/upload-artifact/;
const ARTIFACT_DOWNLOAD = /actions\/download-artifact/;
const EXEC_PATTERNS = [
  /unzip/i, /\.sh\b/, /chmod \+x/, /npm (run|exec)/, /node /, /python /, /bash /,
  /source /, /eval /, /docker run/, /make /,
];

export function scanWorkflow(wf: Workflow): Finding[] {
  const findings: Finding[] = [];
  let uploadJobs: { job: string; artifact: string; trigger: string }[] = [];

  for (const [jobName, job] of Object.entries(wf.jobs)) {
    const perms = job.permissions;
    const hasSecrets = perms.secrets === "write" || perms.contents === "write" || perms.id_token === "write";

    for (const step of job.steps) {
      const uses = step.uses ?? "";
      const run = step.run ?? "";
      const with_ = step.with ?? {};

      if (ARTIFACT_UPLOAD.test(uses)) {
        const artifact = with_.name ?? with_["artifact-name"] ?? "unnamed";
        uploadJobs.push({ job: jobName, artifact: String(artifact), trigger: job.trigger });
        if (job.trigger === "pull_request") {
          findings.push({
            id: `${wf.file}:${jobName}:pr-upload`,
            type: "pr_artifact_upload",
            risk: "high",
            message: `Artifact "${artifact}" uploaded from pull_request context`,
            source: `${jobName} (${job.trigger})`,
            workflow: wf.file,
            job: jobName,
          });
        }
      }

      if (ARTIFACT_DOWNLOAD.test(uses)) {
        const artifact = with_.name ?? with_["artifact-name"] ?? "unnamed";
        if (job.trigger === "workflow_run" || wf.on.workflow_run) {
          findings.push({
            id: `${wf.file}:${jobName}:wf-run-download`,
            type: "workflow_run_download",
            risk: "high",
            message: `Artifact "${artifact}" downloaded in privileged workflow_run context`,
            sink: jobName,
            workflow: wf.file,
            job: jobName,
          });
        }
      }

      if (hasSecrets && (ARTIFACT_DOWNLOAD.test(uses) || EXEC_PATTERNS.some((p) => p.test(run)))) {
        findings.push({
          id: `${wf.file}:${jobName}:privileged-exec`,
          type: "privileged_execution",
          risk: "critical",
          message: `Job "${jobName}" has write permissions and executes/downloads artifacts`,
          sink: jobName,
          workflow: wf.file,
          job: jobName,
        });
      }

      const jobRuns = job.steps.map((s) => s.run ?? "").join("\n");
      if (ARTIFACT_DOWNLOAD.test(uses) && EXEC_PATTERNS.some((p) => p.test(jobRuns))) {
        findings.push({
          id: `${wf.file}:${jobName}:artifact-exec`,
          type: "artifact_executed",
          risk: "critical",
          message: `Downloaded artifact may be executed in job "${jobName}"`,
          workflow: wf.file,
          job: jobName,
        });
      }
    }
  }

  // Cross-workflow pattern within same file
  const prUploads = uploadJobs.filter((u) => u.trigger === "pull_request");
  const wfRunJobs = Object.entries(wf.jobs).filter(([, j]) => j.trigger === "workflow_run" || wf.on.workflow_run);
  for (const up of prUploads) {
    for (const [sinkName] of wfRunJobs) {
      findings.push({
        id: `${wf.file}:cross:${up.job}->${sinkName}`,
        type: "privilege_crossing",
        risk: "critical",
        message: "Untrusted artifact may cross privilege boundary",
        source: `pull_request / ${up.job} / ${up.artifact}`,
        sink: `workflow_run / ${sinkName}`,
        workflow: wf.file,
      });
    }
  }

  return dedupe(findings);
}

function dedupe(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    if (seen.has(f.id)) return false;
    seen.add(f.id);
    return true;
  });
}

export function detectPrivilegeCrossing(findings: Finding[]): PrivilegeCrossing[] {
  return findings
    .filter((f) => f.type === "privilege_crossing" || (f.source && f.sink))
    .map((f) => ({
      source: f.source ?? "unknown",
      sink: f.sink ?? "unknown",
      artifact: f.message.match(/"([^"]+)"/)?.[1] ?? "artifact",
      privilege: "secrets available + contents:write",
      risk: f.risk,
      message: f.message,
    }));
}

export function scanWorkflows(workflows: Workflow[]): ScanReport {
  const findings = workflows.flatMap(scanWorkflow);
  const crossings = detectPrivilegeCrossing(findings);
  const riskLevel = scoreRisk(findings);
  return {
    findings,
    crossings,
    riskLevel,
    riskScore: Math.min(100, findings.length * 25),
  };
}

export function scoreRisk(findings: Finding[]): RiskLevel {
  if (findings.some((f) => f.risk === "critical")) return "critical";
  if (findings.some((f) => f.risk === "high")) return "high";
  if (findings.some((f) => f.risk === "medium")) return "medium";
  if (findings.length > 0) return "low";
  return "none";
}

export function generateReport(report: ScanReport): string {
  const lines = [
    "# Artifact Notary Report",
    "",
    `**Risk:** ${report.riskLevel.toUpperCase()} (${report.riskScore}/100)`,
    "",
    "## Findings",
    "",
  ];
  for (const f of report.findings) {
    lines.push(`### [${f.risk.toUpperCase()}] ${f.type}`);
    lines.push(f.message);
    if (f.source) lines.push(`- Source: ${f.source}`);
    if (f.sink) lines.push(`- Sink: ${f.sink}`);
    lines.push("");
  }
  if (report.crossings.length) {
    lines.push("## Privilege Crossings");
    for (const c of report.crossings) {
      lines.push(`- ${c.message}`);
      lines.push(`  - ${c.source} → ${c.sink}`);
    }
  }
  return lines.join("\n");
}