"use client";

import { useMemo, useState } from "react";
import { generateReport, parseWorkflow, scanWorkflows } from "@/lib/scanner";

const SAMPLE = `name: CI Pipeline
on:
  pull_request:
    branches: [main]
  workflow_run:
    workflows: [CI Pipeline]
jobs:
  build-pr:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/upload-artifact@v4
        with:
          name: build-output
          path: dist/
  deploy:
    if: github.event_name == 'workflow_run'
    permissions:
      contents: write
      secrets: write
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: build-output
      - run: unzip build-output.zip && ./deploy.sh`;

const riskColors: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/40",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/40",
  medium: "bg-yellow-500/15 text-yellow-300 border-yellow-500/30",
  low: "bg-blue-500/15 text-blue-300 border-blue-500/30",
  none: "bg-cyan-500/15 text-cyan-400 border-cyan-500/30",
};

export default function Home() {
  const [yaml, setYaml] = useState(SAMPLE);
  const report = useMemo(() => {
    try {
      return scanWorkflows([parseWorkflow(yaml, "input.yml")]);
    } catch {
      return null;
    }
  }, [yaml]);

  return (
    <div className="min-h-screen" style={{ background: "linear-gradient(135deg,#060d18 0%,#0a1628 50%,#061018 100%)" }}>
      <header className="border-b border-cyan-900/50 bg-slate-950/60 backdrop-blur">
        <div className="max-w-6xl mx-auto px-6 py-5 flex justify-between items-center">
          <div>
            <h1 className="text-2xl font-bold text-cyan-100 tracking-tight">artifact-notary</h1>
            <p className="text-cyan-600/80 text-sm">GitHub Actions Artifact Integrity Scanner</p>
          </div>
          {report && (
            <span className={`px-4 py-2 rounded-full border text-sm font-bold ${riskColors[report.riskLevel]}`}>
              {report.riskLevel.toUpperCase()}
            </span>
          )}
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-6 py-8 grid lg:grid-cols-2 gap-8">
        <div className="rounded-2xl border border-cyan-800/40 bg-slate-900/50 overflow-hidden">
          <div className="px-4 py-3 border-b border-cyan-900/40 text-cyan-300 text-sm font-medium">Workflow YAML</div>
          <textarea
            value={yaml}
            onChange={(e) => setYaml(e.target.value)}
            className="w-full h-[480px] p-4 bg-transparent font-mono text-sm text-slate-300 resize-none focus:outline-none"
          />
        </div>

        <div className="space-y-4">
          {report && (
            <>
              <div className="flex gap-3">
                <PipelineNode label="PR Build" status="untrusted" />
                <div className="flex-1 flex items-center">
                  <div className="h-0.5 w-full bg-gradient-to-r from-orange-500 to-red-500 relative">
                    <span className="absolute -top-3 left-1/2 -translate-x-1/2 text-xs text-red-400">artifact →</span>
                  </div>
                </div>
                <PipelineNode label="Deploy" status="privileged" />
              </div>

              <button
                onClick={() => {
                  const blob = new Blob([generateReport(report)], { type: "text/markdown" });
                  const a = document.createElement("a");
                  a.href = URL.createObjectURL(blob);
                  a.download = "artifact-notary-report.md";
                  a.click();
                }}
                className="w-full py-3 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold transition"
              >
                Export Report
              </button>

              {report.findings.map((f) => (
                <div key={f.id} className="p-4 rounded-xl border border-slate-700/50 bg-slate-900/60">
                  <div className="flex justify-between mb-2">
                    <span className="font-mono text-xs text-cyan-500">{f.type}</span>
                    <span className={`px-2 py-0.5 rounded text-xs border ${riskColors[f.risk]}`}>{f.risk}</span>
                  </div>
                  <p className="text-sm text-slate-300">{f.message}</p>
                  {f.source && <p className="text-xs text-slate-500 mt-1">Source: {f.source}</p>}
                  {f.sink && <p className="text-xs text-slate-500">Sink: {f.sink}</p>}
                </div>
              ))}
            </>
          )}
        </div>
      </main>
    </div>
  );
}

function PipelineNode({ label, status }: { label: string; status: string }) {
  const color = status === "privileged" ? "border-red-500/50 bg-red-500/10" : "border-orange-500/50 bg-orange-500/10";
  return (
    <div className={`px-4 py-3 rounded-xl border ${color} text-center min-w-[100px]`}>
      <div className="text-sm font-semibold text-slate-200">{label}</div>
      <div className="text-xs text-slate-500 mt-1">{status}</div>
    </div>
  );
}