"use client";

import { useState, useEffect, useRef, useCallback } from "react";

const API = "http://localhost:8000";

// ─── Types ────────────────────────────────────────────────────────────────────

interface Log { ts: number; level: string; msg: string; }
interface TrieFinding { pattern: string; category: string; severity: string; cwe_id: string; confidence: number; }
interface ASTFinding { node_type: string; description: string; line: number; col: number; severity: string; suggestion?: string; }
interface ASTReport { cyclomatic_complexity: number; max_loop_depth: number; function_count: number; class_count: number; dangerous_calls: string[]; findings: ASTFinding[]; optimized_snippet?: string; original_snippet?: string; }
interface RAGResult { kb_ref: string; vulnerability_type: string; root_cause: string; historical_fix: string; optimized_example: string; similarity_score: number; owasp_category: string; cwe_id: string; }
interface AgentMsg { agent: string; role: string; content: string; timestamp: number; }
interface SwarmResult { dialogue: AgentMsg[]; final_patch: string; pr_description: string; risk_score: number; patched_risk_score: number; approved: boolean; }
interface StageInfo { status: string; detail: string; ts: number; }
interface PipelineState {
  status: string; run_id: string | null; repo: string | null; commit_sha: string | null;
  pusher: string | null; branch: string | null; stages: Record<string, StageInfo>;
  logs: Log[]; trie_findings: TrieFinding[]; ast_report: ASTReport; rag_context: RAGResult[];
  swarm_result: SwarmResult; ci_status: Record<string, unknown>; dag_topology: unknown[];
  pr_url: string | null; pr_body?: string; started_at: number | null; finished_at: number | null;
  platform: string | null;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const STAGES = ["ingest", "trie_scan", "ast_analysis", "rag_lookup", "sandbox", "optimizer", "auditor", "report"];
const STAGE_LABELS: Record<string, string> = {
  ingest: "Ingest", trie_scan: "Trie Scan", ast_analysis: "AST Analysis",
  rag_lookup: "RAG Lookup", sandbox: "Sandbox", optimizer: "Optimizer",
  auditor: "Auditor", report: "Report",
};
const SEV_COLOR: Record<string, string> = {
  critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e", info: "#3b82f6",
};

// ─── Hooks ────────────────────────────────────────────────────────────────────

function usePipelineState() {
  const [state, setState] = useState<PipelineState | null>(null);
  const [connected, setConnected] = useState(false);
  const intervalRef = useRef<NodeJS.Timeout | null>(null);

  const poll = useCallback(async () => {
    try {
      const r = await fetch(`${API}/api/pipeline/state`);
      if (!r.ok) throw new Error();
      const data = await r.json();
      setState(data);
      setConnected(true);
    } catch {
      setConnected(false);
    }
  }, []);

  useEffect(() => {
    poll();
    intervalRef.current = setInterval(poll, 1500);
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [poll]);

  return { state, connected };
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function StatusDot({ status }: { status: string }) {
  const colors: Record<string, string> = {
    complete: "#22c55e", running: "#3b82f6", failed: "#ef4444",
    pending: "#6b7280", idle: "#6b7280", error: "#ef4444",
  };
  const isRunning = status === "running";
  return (
    <span style={{
      display: "inline-block", width: 8, height: 8, borderRadius: "50%",
      background: colors[status] || "#6b7280", marginRight: 6,
      boxShadow: isRunning ? `0 0 0 3px ${colors.running}33` : "none",
      animation: isRunning ? "pulse 1.5s ease-in-out infinite" : "none",
    }} />
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const color = SEV_COLOR[severity] || "#6b7280";
  return (
    <span style={{
      fontSize: 10, fontWeight: 600, letterSpacing: "0.05em",
      textTransform: "uppercase", padding: "2px 7px", borderRadius: 4,
      border: `1px solid ${color}44`, color, background: `${color}15`,
    }}>
      {severity}
    </span>
  );
}

function Card({ children, style }: { children: React.ReactNode; style?: React.CSSProperties }) {
  return (
    <div style={{
      background: "var(--card-bg)", border: "1px solid var(--border)", borderRadius: 12,
      padding: "20px 24px", ...style,
    }}>
      {children}
    </div>
  );
}

function MetricCard({ label, value, sub, accent }: { label: string; value: string | number; sub?: string; accent?: string }) {
  return (
    <div style={{
      background: "var(--metric-bg)", borderRadius: 10, padding: "16px 20px",
      border: "1px solid var(--border)", flex: 1, minWidth: 120,
    }}>
      <div style={{ fontSize: 11, color: "var(--text-muted)", letterSpacing: "0.06em", textTransform: "uppercase", marginBottom: 6 }}>{label}</div>
      <div style={{ fontSize: 26, fontWeight: 700, color: accent || "var(--text-primary)", lineHeight: 1 }}>{value}</div>
      {sub && <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 4 }}>{sub}</div>}
    </div>
  );
}

function PipelineDAGVisual({ stages }: { stages: Record<string, StageInfo> }) {
  const nodes = STAGES.map(s => ({
    id: s, label: STAGE_LABELS[s], status: stages[s]?.status || "pending",
  }));

  const getColor = (status: string) => ({
    complete: "#22c55e", running: "#3b82f6", failed: "#ef4444", pending: "#374151",
  }[status] || "#374151");

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 0, flexWrap: "nowrap", overflowX: "auto", paddingBottom: 4 }}>
      {nodes.map((node, i) => (
        <div key={node.id} style={{ display: "flex", alignItems: "center" }}>
          <div style={{
            display: "flex", flexDirection: "column", alignItems: "center", gap: 4, minWidth: 72,
          }}>
            <div style={{
              width: 36, height: 36, borderRadius: "50%", background: getColor(node.status),
              display: "flex", alignItems: "center", justifyContent: "center",
              boxShadow: node.status === "running" ? `0 0 0 4px ${getColor("running")}33` : "none",
              transition: "all 0.3s",
              fontSize: 14,
            }}>
              {node.status === "complete" ? "✓" : node.status === "failed" ? "✗" : node.status === "running" ? "⟳" : "·"}
            </div>
            <span style={{ fontSize: 10, color: "var(--text-muted)", textAlign: "center", lineHeight: 1.2 }}>
              {node.label}
            </span>
          </div>
          {i < nodes.length - 1 && (
            <div style={{ width: 20, height: 2, background: stages[node.id]?.status === "complete" ? "#22c55e" : "var(--border)", margin: "0 2px", marginBottom: 16 }} />
          )}
        </div>
      ))}
    </div>
  );
}

function LogStream({ logs }: { logs: Log[] }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => { if (ref.current) ref.current.scrollTop = ref.current.scrollHeight; }, [logs]);

  const levelColor: Record<string, string> = {
    info: "#3b82f6", warn: "#f59e0b", error: "#ef4444", debug: "#8b5cf6",
  };

  return (
    <div ref={ref} style={{
      fontFamily: "'JetBrains Mono', 'Fira Code', monospace", fontSize: 12,
      lineHeight: 1.7, height: 300, overflowY: "auto", padding: "12px 16px",
      background: "var(--terminal-bg)", borderRadius: 8, border: "1px solid var(--border)",
    }}>
      {logs.length === 0 && (
        <span style={{ color: "var(--text-muted)" }}>Waiting for pipeline events…</span>
      )}
      {logs.map((log, i) => (
        <div key={i} style={{ display: "flex", gap: 12, marginBottom: 2 }}>
          <span style={{ color: "var(--text-muted)", minWidth: 80, flexShrink: 0 }}>
            {new Date(log.ts).toISOString().slice(11, 19)}
          </span>
          <span style={{ color: levelColor[log.level] || "#94a3b8", minWidth: 40, flexShrink: 0 }}>
            [{log.level?.toUpperCase()}]
          </span>
          <span style={{ color: "var(--terminal-text)" }}>{log.msg}</span>
        </div>
      ))}
    </div>
  );
}

function TrieTab({ findings }: { findings: TrieFinding[] }) {
  if (!findings.length) return <EmptyState icon="🔍" text="No threats detected yet. Run a simulation to trigger a scan." />;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      {findings.map((f, i) => (
        <div key={i} style={{
          background: "var(--card-bg)", border: `1px solid ${SEV_COLOR[f.severity] || "#374151"}44`,
          borderLeft: `3px solid ${SEV_COLOR[f.severity] || "#374151"}`,
          borderRadius: 8, padding: "12px 16px",
        }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
            <code style={{ fontSize: 13, color: "#f472b6", background: "var(--code-bg)", padding: "2px 8px", borderRadius: 4 }}>{f.pattern}</code>
            <SeverityBadge severity={f.severity} />
          </div>
          <div style={{ fontSize: 13, color: "var(--text-primary)", marginBottom: 4 }}>{f.category}</div>
          <div style={{ display: "flex", gap: 16 }}>
            <span style={{ fontSize: 12, color: "var(--text-muted)" }}>{f.cwe_id}</span>
            <span style={{ fontSize: 12, color: "var(--text-muted)" }}>Confidence: {(f.confidence * 100).toFixed(0)}%</span>
          </div>
        </div>
      ))}
    </div>
  );
}

function ASTTab({ report }: { report: ASTReport | undefined }) {
  if (!report?.findings) return <EmptyState icon="🌳" text="AST analysis pending. Run a simulation to analyse code structure." />;
  const cc = report.cyclomatic_complexity;
  const ccColor = cc > 15 ? "#ef4444" : cc > 8 ? "#f97316" : "#22c55e";

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
        <MetricCard label="Complexity" value={cc} sub="Cyclomatic" accent={ccColor} />
        <MetricCard label="Loop Depth" value={report.max_loop_depth} sub="Max nesting" accent={report.max_loop_depth >= 2 ? "#ef4444" : "#22c55e"} />
        <MetricCard label="Functions" value={report.function_count} />
        <MetricCard label="Classes" value={report.class_count} />
      </div>

      {report.dangerous_calls?.length > 0 && (
        <Card>
          <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 8, textTransform: "uppercase", letterSpacing: "0.06em" }}>Dangerous Calls</div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {report.dangerous_calls.map((c, i) => (
              <code key={i} style={{ fontSize: 12, color: "#f472b6", background: "var(--code-bg)", padding: "3px 10px", borderRadius: 4 }}>{c}</code>
            ))}
          </div>
        </Card>
      )}

      {report.findings?.length > 0 && (
        <div>
          <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 10, textTransform: "uppercase", letterSpacing: "0.06em" }}>Structural Findings</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {report.findings.map((f, i) => (
              <div key={i} style={{
                background: "var(--card-bg)", border: "1px solid var(--border)",
                borderLeft: `3px solid ${SEV_COLOR[f.severity] || "#6b7280"}`,
                borderRadius: 8, padding: "10px 14px",
              }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                  <span style={{ fontSize: 12, color: "var(--text-muted)" }}>Line {f.line}:{f.col} · {f.node_type}</span>
                  <SeverityBadge severity={f.severity} />
                </div>
                <div style={{ fontSize: 13, color: "var(--text-primary)", marginBottom: f.suggestion ? 4 : 0 }}>{f.description}</div>
                {f.suggestion && <div style={{ fontSize: 12, color: "#3b82f6" }}>💡 {f.suggestion}</div>}
              </div>
            ))}
          </div>
        </div>
      )}

      {report.optimized_snippet && (
        <Card>
          <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 8, textTransform: "uppercase", letterSpacing: "0.06em" }}>Suggested Refactor</div>
          <pre style={{ margin: 0, fontSize: 12, color: "#86efac", background: "var(--terminal-bg)", padding: 12, borderRadius: 6, overflow: "auto" }}>
            {report.optimized_snippet}
          </pre>
        </Card>
      )}
    </div>
  );
}

function RAGTab({ context }: { context: RAGResult[] }) {
  if (!context?.length) return <EmptyState icon="🧠" text="RAG retrieval pending. The knowledge base will be queried when a simulation runs." />;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {context.map((r, i) => (
        <Card key={i} style={{ borderLeft: "3px solid #8b5cf6" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 12 }}>
            <div>
              <code style={{ fontSize: 11, color: "#8b5cf6", background: "var(--code-bg)", padding: "2px 8px", borderRadius: 4 }}>{r.kb_ref}</code>
              <div style={{ fontSize: 14, fontWeight: 600, color: "var(--text-primary)", marginTop: 6 }}>{r.vulnerability_type}</div>
            </div>
            <div style={{ textAlign: "right" }}>
              <div style={{ fontSize: 11, color: "var(--text-muted)" }}>Similarity</div>
              <div style={{ fontSize: 18, fontWeight: 700, color: r.similarity_score > 0.7 ? "#22c55e" : "#f59e0b" }}>
                {(r.similarity_score * 100).toFixed(0)}%
              </div>
            </div>
          </div>

          <div style={{ marginBottom: 12 }}>
            <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.05em" }}>Root Cause</div>
            <div style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.6 }}>{r.root_cause}</div>
          </div>

          <div style={{ marginBottom: 12 }}>
            <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.05em" }}>Historical Fix</div>
            <div style={{ fontSize: 13, color: "var(--text-primary)", lineHeight: 1.6 }}>{r.historical_fix}</div>
          </div>

          <div style={{ marginBottom: 10 }}>
            <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.05em" }}>Optimized Example</div>
            <pre style={{ margin: 0, fontSize: 12, color: "#86efac", background: "var(--terminal-bg)", padding: 10, borderRadius: 6, overflow: "auto" }}>
              {r.optimized_example}
            </pre>
          </div>

          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            <span style={{ fontSize: 11, color: "#f59e0b", background: "#f59e0b15", border: "1px solid #f59e0b44", padding: "2px 8px", borderRadius: 4 }}>{r.owasp_category}</span>
            <span style={{ fontSize: 11, color: "#3b82f6", background: "#3b82f615", border: "1px solid #3b82f644", padding: "2px 8px", borderRadius: 4 }}>{r.cwe_id}</span>
          </div>
        </Card>
      ))}
    </div>
  );
}

function AgentTab({ swarm, originalCode }: { swarm: SwarmResult | undefined; originalCode?: string }) {
  if (!swarm?.dialogue?.length) return <EmptyState icon="🤖" text="Agent swarm idle. Trigger a simulation to launch the multi-agent review." />;

  const roleColor: Record<string, string> = { auditor: "#ef4444", optimizer: "#3b82f6", synthesizer: "#8b5cf6" };
  const roleIcon: Record<string, string> = { auditor: "🔒", optimizer: "⚡", synthesizer: "🔀" };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
        <MetricCard label="Original Risk" value={swarm.risk_score != null ? `${swarm.risk_score}/100` : "—"} accent={swarm.risk_score > 70 ? "#ef4444" : swarm.risk_score > 40 ? "#f97316" : "#22c55e"} />
        <MetricCard label="Mitigated Risk" value={swarm.patched_risk_score != null ? `${swarm.patched_risk_score}/100` : "—"} accent={swarm.patched_risk_score > 70 ? "#ef4444" : swarm.patched_risk_score > 40 ? "#f97316" : "#22c55e"} />
        <MetricCard label="Decision" value={swarm.approved ? "APPROVE" : "REQUEST CHANGES"} accent={swarm.approved ? "#22c55e" : "#ef4444"} />
        <MetricCard label="Agents" value={swarm.dialogue.length} sub="messages" />
      </div>

      <div>
        <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 10, textTransform: "uppercase", letterSpacing: "0.06em" }}>Agent Dialogue</div>
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {swarm.dialogue.map((msg, i) => (
            <div key={i} style={{
              background: "var(--card-bg)", border: `1px solid ${roleColor[msg.role] || "#374151"}44`,
              borderLeft: `3px solid ${roleColor[msg.role] || "#374151"}`,
              borderRadius: 8, padding: "12px 16px",
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                <span>{roleIcon[msg.role] || "🤖"}</span>
                <span style={{ fontSize: 13, fontWeight: 600, color: roleColor[msg.role] || "var(--text-primary)" }}>{msg.agent}</span>
                <span style={{ fontSize: 11, color: "var(--text-muted)", marginLeft: "auto" }}>
                  {new Date(msg.timestamp * 1000).toLocaleTimeString()}
                </span>
              </div>
              <div style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.7, whiteSpace: "pre-wrap" }}>
                {msg.content.slice(0, 600)}{msg.content.length > 600 ? "…" : ""}
              </div>
            </div>
          ))}
        </div>
      </div>

      {swarm.final_patch && (
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          <div style={{ fontSize: 12, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.06em" }}>Remediation Patch Comparison</div>
          <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
            {/* Original Code */}
            <div style={{ flex: 1, minWidth: 320 }}>
              <div style={{ fontSize: 11, color: "#ef4444", marginBottom: 6, display: "flex", alignItems: "center", gap: 6, fontWeight: 600 }}>
                <span style={{ width: 6, height: 6, borderRadius: "50%", background: "#ef4444" }} />
                Original Vulnerable Code
              </div>
              <pre style={{ margin: 0, fontSize: 12, color: "#f87171", background: "#1a1113", border: "1px solid #7f1d1d44", padding: 14, borderRadius: 6, overflow: "auto", maxHeight: 400, fontFamily: "monospace", lineHeight: 1.6 }}>
                {originalCode || "# Original code snippet unavailable"}
              </pre>
            </div>
            
            {/* Patched Code */}
            <div style={{ flex: 1, minWidth: 320 }}>
              <div style={{ fontSize: 11, color: "#22c55e", marginBottom: 6, display: "flex", alignItems: "center", gap: 6, fontWeight: 600 }}>
                <span style={{ width: 6, height: 6, borderRadius: "50%", background: "#22c55e" }} />
                Optimized & Secured Patch
              </div>
              <pre style={{ margin: 0, fontSize: 12, color: "#86efac", background: "#0c1712", border: "1px solid #064e3b44", padding: 14, borderRadius: 6, overflow: "auto", maxHeight: 400, fontFamily: "monospace", lineHeight: 1.6 }}>
                {swarm.final_patch}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function PRTab({ state }: { state: PipelineState }) {
  const { pr_url, pr_body, platform } = state;
  const platformName = platform === "gitlab" ? "GitLab" : platform === "azure-devops" ? "Azure DevOps" : "GitHub";
  const prLabel = platform === "gitlab" ? "Merge Request" : "Pull Request";

  if (!pr_body && !pr_url) return <EmptyState icon="📝" text="PR/MR report will appear here after the pipeline completes." />;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {pr_url && (
        <div style={{ background: "#22c55e15", border: "1px solid #22c55e44", borderRadius: 8, padding: "12px 16px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span style={{ fontSize: 14, color: "#22c55e" }}>✅ {platformName} {prLabel} created successfully</span>
          <a href={pr_url} target="_blank" rel="noreferrer" style={{ fontSize: 12, color: "#3b82f6" }}>{pr_url}</a>
        </div>
      )}
      {!pr_url && (
        <div style={{ background: "#f59e0b15", border: "1px solid #f59e0b44", borderRadius: 8, padding: "12px 16px" }}>
          <span style={{ fontSize: 13, color: "#f59e0b" }}>⚠️ Set {platform === "gitlab" ? "GITLAB_TOKEN" : platform === "azure-devops" ? "AZURE_DEVOPS_TOKEN" : "GITHUB_TOKEN"} in .env to auto-create real {prLabel}s. {prLabel} body preview below.</span>
        </div>
      )}
      {pr_body && (
        <Card>
          <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 10, textTransform: "uppercase", letterSpacing: "0.06em" }}>{prLabel} Markdown Preview</div>
          <pre style={{ margin: 0, fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.7, background: "var(--terminal-bg)", padding: 14, borderRadius: 6, overflow: "auto", maxHeight: 600, whiteSpace: "pre-wrap" }}>
            {pr_body}
          </pre>
        </Card>
      )}
    </div>
  );
}

function EmptyState({ icon, text }: { icon: string; text: string }) {
  return (
    <div style={{ textAlign: "center", padding: "48px 24px", color: "var(--text-muted)" }}>
      <div style={{ fontSize: 36, marginBottom: 12 }}>{icon}</div>
      <div style={{ fontSize: 14, lineHeight: 1.6, maxWidth: 360, margin: "0 auto" }}>{text}</div>
    </div>
  );
}

function ArchitectureTab() {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
      <Card style={{ padding: "24px 32px" }}>
        <div style={{ fontSize: 16, fontWeight: 700, color: "#e6edf3", marginBottom: 6 }}>Microsoft Azure Ecosystem Architecture</div>
        <div style={{ fontSize: 13, color: "var(--text-secondary)", marginBottom: 20, lineHeight: 1.6 }}>
          SentinelForge is designed to integrate natively into the Microsoft developer cloud, combining enterprise identity/secrets, vector search intelligence, and large language models for compliance-driven auto-patch generation.
        </div>
        
        {/* SVG Diagram */}
        <div style={{ background: "#0b0d12", borderRadius: 8, padding: "20px 0", border: "1px solid var(--border)", display: "flex", justifyContent: "center", marginBottom: 20 }}>
          <svg viewBox="0 0 800 320" width="100%" height="280" style={{ maxWidth: 700, fontFamily: "system-ui, sans-serif" }}>
            {/* Defs */}
            <defs>
              <marker id="arrow" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 1 L 10 5 L 0 9 z" fill="#4b5563" />
              </marker>
              <linearGradient id="azureGlow" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#0078d4" />
                <stop offset="100%" stopColor="#50e4ff" />
              </linearGradient>
            </defs>

            {/* GitHub Block */}
            <rect x="20" y="120" width="120" height="80" rx="10" fill="#24292f" stroke="#30363d" strokeWidth="2" />
            <text x="80" y="155" textAnchor="middle" fill="#ffffff" fontWeight="700" fontSize="13">GitHub Repository</text>
            <text x="80" y="175" textAnchor="middle" fill="#8b949e" fontSize="11">Webhook (Push / PR)</text>

            {/* Flow line GitHub to API */}
            <path d="M 140 160 L 220 160" fill="none" stroke="#4b5563" strokeWidth="2" markerEnd="url(#arrow)" />

            {/* FastAPI Gateway Block */}
            <rect x="230" y="110" width="160" height="100" rx="10" fill="#002244" stroke="url(#azureGlow)" strokeWidth="2" />
            <text x="310" y="145" textAnchor="middle" fill="#ffffff" fontWeight="700" fontSize="13">SentinelForge Engine</text>
            <text x="310" y="165" textAnchor="middle" fill="#50e4ff" fontSize="11">FastAPI Backend</text>
            <text x="310" y="185" textAnchor="middle" fill="#a5b4fc" fontSize="10">sentinelforge-v2</text>

            {/* Lines from API Gateway to Services */}
            {/* Line to Azure Key Vault */}
            <path d="M 310 110 L 310 50 L 480 50" fill="none" stroke="#4b5563" strokeWidth="2" markerEnd="url(#arrow)" />
            {/* Line to Azure AI Search */}
            <path d="M 390 160 L 480 160" fill="none" stroke="#4b5563" strokeWidth="2" markerEnd="url(#arrow)" />
            {/* Line to Azure OpenAI / GitHub Models */}
            <path d="M 310 210 L 310 270 L 480 270" fill="none" stroke="#4b5563" strokeWidth="2" markerEnd="url(#arrow)" />

            {/* Key Vault Block */}
            <rect x="490" y="20" width="160" height="60" rx="8" fill="#161b22" stroke="#0078d4" strokeWidth="1.5" />
            <text x="570" y="45" textAnchor="middle" fill="#ffffff" fontWeight="600" fontSize="12">🔑 Azure Key Vault</text>
            <text x="570" y="62" textAnchor="middle" fill="#8b949e" fontSize="10">Secrets & Token Storage</text>

            {/* AI Search Block */}
            <rect x="490" y="130" width="160" height="60" rx="8" fill="#161b22" stroke="#0078d4" strokeWidth="1.5" />
            <text x="570" y="155" textAnchor="middle" fill="#ffffff" fontWeight="600" fontSize="12">🧠 Azure AI Search</text>
            <text x="570" y="172" textAnchor="middle" fill="#8b949e" fontSize="10">Vector Semantic RAG</text>

            {/* Models Block */}
            <rect x="490" y="240" width="160" height="60" rx="8" fill="#161b22" stroke="#50e4ff" strokeWidth="1.5" />
            <text x="570" y="265" textAnchor="middle" fill="#ffffff" fontWeight="600" fontSize="12">🤖 GitHub Models</text>
            <text x="570" y="282" textAnchor="middle" fill="#a5b4fc" fontSize="10">Azure-Hosted GPT-4o (Free)</text>
          </svg>
        </div>

        {/* Detailed Description Cards */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 14 }}>
          <div style={{ background: "var(--metric-bg)", borderRadius: 8, padding: 16, border: "1px solid var(--border)" }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: "#3b82f6", marginBottom: 6 }}>1. Azure Key Vault</div>
            <div style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.5 }}>
              Securely retrieves `GITHUB_TOKEN` and webhook credentials at runtime. Prevents credential leaks in repository history, maintaining enterprise-grade safety.
            </div>
          </div>
          <div style={{ background: "var(--metric-bg)", borderRadius: 8, padding: 16, border: "1px solid var(--border)" }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: "#a855f7", marginBottom: 6 }}>2. Azure AI Search</div>
            <div style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.5 }}>
              Serves as our Vector Database (RAG) containing secure coding guidelines, OWASP recommendations, and historic patch fixes to guide LLM synthesis.
            </div>
          </div>
          <div style={{ background: "var(--metric-bg)", borderRadius: 8, padding: 16, border: "1px solid var(--border)" }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: "#10b981", marginBottom: 6 }}>3. GitHub Models API</div>
            <div style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.5 }}>
              Accesses Azure-hosted **GPT-4o** inference models free of charge. Provides premium multi-agent auditing, optimization, and synthesis without token cost.
            </div>
          </div>
        </div>
      </Card>
    </div>
  );
}

// ─── Main Dashboard ───────────────────────────────────────────────────────────

export default function SentinelForgeDashboard() {
  const { state, connected } = usePipelineState();
  const [tab, setTab] = useState("logs");
  const [simulating, setSimulating] = useState(false);
  const [showInput, setShowInput] = useState(false);
  const [repo, setRepo] = useState("my-org/my-project");
  const [filename, setFilename] = useState("solution.py");
  const [platform, setPlatform] = useState("github");
  const [code, setCode] = useState(`# Paste your code here (Python, JS, Java, C++, YAML, etc.)
def two_sum(nums, target):
    for i in range(len(nums)):
        for j in range(len(nums)):
            if i != j and nums[i] + nums[j] == target:
                return [i, j]
`);

  const handleSimulate = async () => {
    setSimulating(true);
    setShowInput(false);
    try {
      await fetch(`${API}/api/analyze-custom`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo, filename, code, platform }),
      });
      setTab("logs");
    } catch {
      alert("Cannot reach backend. Make sure uvicorn is running on port 8000.");
    } finally {
      setTimeout(() => setSimulating(false), 2000);
    }
  };

  const handleSimulatePush = async () => {
    setSimulating(true);
    try {
      const r = await fetch(`${API}/api/pipeline/simulate`, {
        method: "POST",
      });
      if (r.ok) {
        setTab("logs");
      } else {
        alert("Failed to trigger simulation.");
      }
    } catch {
      alert("Cannot reach backend. Make sure uvicorn is running on port 8000.");
    } finally {
      setTimeout(() => setSimulating(false), 1000);
    }
  };

  const running = state?.status === "running";
  const complete = state?.status === "complete";
  const dur = state?.started_at && state?.finished_at
    ? `${(state.finished_at - state.started_at).toFixed(1)}s`
    : null;

  const tabs = [
    { id: "logs", label: "Pipeline Logs", count: state?.logs?.length },
    { id: "trie", label: "Trie Scan", count: state?.trie_findings?.length },
    { id: "ast", label: "AST Analysis", count: state?.ast_report?.findings?.length },
    { id: "rag", label: "RAG Context", count: state?.rag_context?.length },
    { id: "agents", label: "Agent Swarm", count: state?.swarm_result?.dialogue?.length },
    { id: "pr", label: state?.platform === "gitlab" ? "MR Report" : "PR Report", count: state?.pr_url ? 1 : 0 },
    { id: "architecture", label: "Azure Topology" },
  ];

  return (
    <>
      <style>{`
        :root {
          --card-bg: #0f1117;
          --metric-bg: #161b22;
          --border: #21262d;
          --text-primary: #e6edf3;
          --text-secondary: #8b949e;
          --text-muted: #484f58;
          --terminal-bg: #010409;
          --terminal-text: #7ee787;
          --code-bg: #161b22;
        }
        @media (prefers-color-scheme: light) {
          :root {
            --card-bg: #ffffff;
            --metric-bg: #f6f8fa;
            --border: #d0d7de;
            --text-primary: #1f2328;
            --text-secondary: #57606a;
            --text-muted: #8c959f;
            --terminal-bg: #1b1f24;
            --terminal-text: #7ee787;
            --code-bg: #f6f8fa;
          }
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: #010409; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; }
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        .tab-btn:hover { background: var(--metric-bg) !important; }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: #30363d; border-radius: 3px; }
      `}</style>

      <div style={{ minHeight: "100vh", background: "#010409", color: "var(--text-primary)", fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif" }}>

        {/* ── Header ─────────────────────────────────────────────────────── */}
        <div style={{ borderBottom: "1px solid #21262d", padding: "0 32px" }}>
          <div style={{ maxWidth: 1200, margin: "0 auto", padding: "16px 0", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
              <div style={{
                width: 36, height: 36, borderRadius: 8, background: "linear-gradient(135deg, #3b82f6, #8b5cf6)",
                display: "flex", alignItems: "center", justifyContent: "center", fontSize: 18,
              }}>🛡️</div>
              <div>
                <div style={{ fontSize: 18, fontWeight: 700, letterSpacing: "-0.02em", color: "#e6edf3" }}>SentinelForge</div>
                <div style={{ fontSize: 11, color: "#484f58", letterSpacing: "0.04em", textTransform: "uppercase" }}>AI Code Security Pipeline</div>
              </div>
            </div>

            <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
              {/* Connection status */}
              <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12 }}>
                <span style={{ width: 7, height: 7, borderRadius: "50%", background: connected ? "#22c55e" : "#ef4444", display: "inline-block" }} />
                <span style={{ color: "var(--text-muted)" }}>{connected ? "API Connected" : "API Offline"}</span>
              </div>

              {/* Run info */}
              {state?.repo && (
                <div style={{ fontSize: 12, color: "var(--text-muted)", display: "flex", alignItems: "center", gap: 6 }}>
                  <span>{state.platform === "gitlab" ? "🦊" : state.platform === "azure-devops" ? "☁️" : "🐙"}</span>
                  <span style={{ color: "#3b82f6" }}>{state.repo}</span>
                  {state.commit_sha && <span> · {state.commit_sha.slice(0, 8)}</span>}
                </div>
              )}

              {/* Simulate GitHub Push button */}
              <button
                onClick={handleSimulatePush}
                disabled={simulating || running}
                style={{
                  padding: "9px 16px", background: running || simulating ? "#1c2128" : "transparent",
                  border: "1px solid var(--border)", borderRadius: 8, color: running || simulating ? "#484f58" : "var(--text-secondary)",
                  fontSize: 13, fontWeight: 600, cursor: running || simulating ? "not-allowed" : "pointer",
                  display: "flex", alignItems: "center", gap: 6, transition: "all 0.2s", marginRight: 8,
                }}
                className="tab-btn"
              >
                <span>🚀</span> Simulate Push
              </button>

              {/* Analyse button */}
              <button
                onClick={() => setShowInput(v => !v)}
                disabled={simulating || running}
                style={{
                  padding: "9px 20px", background: running || simulating ? "#1c2128" : "linear-gradient(135deg, #238636, #2ea043)",
                  border: "1px solid #2ea04366", borderRadius: 8, color: running || simulating ? "#484f58" : "#fff",
                  fontSize: 13, fontWeight: 600, cursor: running || simulating ? "not-allowed" : "pointer",
                  display: "flex", alignItems: "center", gap: 8, transition: "all 0.2s",
                }}
              >
                {running ? (
                  <><span style={{ animation: "spin 1s linear infinite", display: "inline-block" }}>⟳</span> Running…</>
                ) : simulating ? "Starting…" : "▶ Analyse Code"}
              </button>
            </div>
          </div>
        </div>

        <div style={{ maxWidth: 1200, margin: "0 auto", padding: "28px 32px" }}>

          {/* ── Code Input Panel ─────────────────────────────────────────── */}
          {showInput && (
            <div style={{ background: "#0f1117", border: "1px solid #21262d", borderRadius: 12, padding: 24, marginBottom: 24 }}>
              <div style={{ fontSize: 15, fontWeight: 600, color: "#e6edf3", marginBottom: 16 }}>🔍 Analyse Your Code</div>
              <div style={{ display: "flex", gap: 12, marginBottom: 14, flexWrap: "wrap" }}>
                <div style={{ flex: 1, minWidth: 200 }}>
                  <div style={{ fontSize: 11, color: "#484f58", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.05em" }}>Repository Name</div>
                  <input
                    value={repo}
                    onChange={e => setRepo(e.target.value)}
                    placeholder="e.g. john/my-project"
                    style={{ width: "100%", padding: "9px 12px", background: "#161b22", border: "1px solid #30363d", borderRadius: 7, color: "#e6edf3", fontSize: 13, outline: "none" }}
                  />
                </div>
                <div style={{ flex: 1, minWidth: 160 }}>
                  <div style={{ fontSize: 11, color: "#484f58", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.05em" }}>Filename</div>
                  <input
                    value={filename}
                    onChange={e => setFilename(e.target.value)}
                    placeholder="e.g. solution.py"
                    style={{ width: "100%", padding: "9px 12px", background: "#161b22", border: "1px solid #30363d", borderRadius: 7, color: "#e6edf3", fontSize: 13, outline: "none" }}
                  />
                </div>
                <div style={{ flex: 1, minWidth: 160 }}>
                  <div style={{ fontSize: 11, color: "#484f58", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.05em" }}>CI Platform</div>
                  <select
                    value={platform}
                    onChange={e => setPlatform(e.target.value)}
                    style={{ width: "100%", padding: "9px 12px", background: "#161b22", border: "1px solid #30363d", borderRadius: 7, color: "#e6edf3", fontSize: 13, outline: "none" }}
                  >
                    <option value="github">GitHub</option>
                    <option value="gitlab">GitLab</option>
                    <option value="azure-devops">Azure DevOps</option>
                  </select>
                </div>
              </div>
              <div style={{ fontSize: 11, color: "#484f58", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.05em" }}>Paste Your Code</div>
              <textarea
                value={code}
                onChange={e => setCode(e.target.value)}
                rows={12}
                style={{ width: "100%", padding: "12px", background: "#010409", border: "1px solid #30363d", borderRadius: 7, color: "#7ee787", fontSize: 12, fontFamily: "monospace", outline: "none", resize: "vertical", lineHeight: 1.6 }}
              />
              <div style={{ display: "flex", gap: 10, marginTop: 14 }}>
                <button
                  onClick={handleSimulate}
                  disabled={simulating || running || !code.trim()}
                  style={{ padding: "10px 24px", background: "linear-gradient(135deg, #238636, #2ea043)", border: "none", borderRadius: 8, color: "#fff", fontSize: 13, fontWeight: 600, cursor: "pointer" }}
                >
                  {simulating ? "Running…" : "▶ Run Analysis"}
                </button>
                <button
                  onClick={() => setShowInput(false)}
                  style={{ padding: "10px 20px", background: "transparent", border: "1px solid #30363d", borderRadius: 8, color: "#8b949e", fontSize: 13, cursor: "pointer" }}
                >
                  Cancel
                </button>
              </div>
            </div>
          )}

          {/* ── Pipeline Stage DAG ────────────────────────────────────────── */}
          <Card style={{ marginBottom: 24 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <StatusDot status={state?.status || "idle"} />
                <span style={{ fontSize: 14, fontWeight: 600, textTransform: "capitalize" }}>{state?.status || "idle"}</span>
                {dur && <span style={{ fontSize: 12, color: "#22c55e" }}>· {dur}</span>}
              </div>
              <div style={{ display: "flex", gap: 20 }}>
                {[
                  { label: "Threats", value: state?.trie_findings?.length ?? 0, color: state?.trie_findings?.length ? "#ef4444" : "#22c55e" },
                  { label: "AST Issues", value: state?.ast_report?.findings?.length ?? 0, color: state?.ast_report?.findings?.length ? "#f97316" : "#22c55e" },
                  { label: "Original Risk", value: state?.swarm_result?.risk_score != null ? `${state.swarm_result.risk_score}/100` : "—", color: (state?.swarm_result?.risk_score ?? 0) > 40 ? "#ef4444" : "#22c55e" },
                  { label: "Mitigated Risk", value: state?.swarm_result?.patched_risk_score != null ? `${state.swarm_result.patched_risk_score}/100` : "—", color: (state?.swarm_result?.patched_risk_score ?? 0) > 40 ? "#ef4444" : "#22c55e" },
                ].map(m => (
                  <div key={m.label} style={{ textAlign: "right" }}>
                    <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.05em" }}>{m.label}</div>
                    <div style={{ fontSize: 16, fontWeight: 700, color: m.color }}>{m.value}</div>
                  </div>
                ))}
              </div>
            </div>
            <PipelineDAGVisual stages={state?.stages || {}} />
          </Card>

          {/* ── Tabs ─────────────────────────────────────────────────────── */}
          <div style={{ display: "flex", gap: 2, marginBottom: 16, borderBottom: "1px solid #21262d", paddingBottom: 0 }}>
            {tabs.map(t => (
              <button
                key={t.id}
                className="tab-btn"
                onClick={() => setTab(t.id)}
                style={{
                  padding: "10px 18px", background: "transparent",
                  border: "none", borderBottom: tab === t.id ? "2px solid #3b82f6" : "2px solid transparent",
                  color: tab === t.id ? "#3b82f6" : "var(--text-muted)",
                  fontSize: 13, fontWeight: tab === t.id ? 600 : 400,
                  cursor: "pointer", display: "flex", alignItems: "center", gap: 7,
                  transition: "color 0.15s", borderRadius: "4px 4px 0 0",
                  marginBottom: -1,
                }}
              >
                {t.label}
                {t.count !== undefined && t.count !== null && t.count > 0 && (
                  <span style={{
                    fontSize: 10, background: tab === t.id ? "#3b82f6" : "#21262d",
                    color: tab === t.id ? "#fff" : "#8b949e",
                    padding: "1px 6px", borderRadius: 10, fontWeight: 600,
                  }}>{t.count}</span>
                )}
              </button>
            ))}
          </div>

          {/* ── Tab Content ──────────────────────────────────────────────── */}
          <div>
            {tab === "logs" && (
              <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
                <LogStream logs={state?.logs || []} />
                {state?.status === "idle" && (
                  <div style={{ background: "#161b22", border: "1px dashed #30363d", borderRadius: 8, padding: "32px", textAlign: "center", color: "#484f58", fontSize: 13 }}>
                    Click <strong style={{ color: "#2ea043" }}>▶ Simulate GitHub Push</strong> to trigger the full 8-stage AI pipeline
                  </div>
                )}
              </div>
            )}
            {tab === "trie" && <TrieTab findings={state?.trie_findings || []} />}
            {tab === "ast" && <ASTTab report={state?.ast_report} />}
            {tab === "rag" && <RAGTab context={state?.rag_context || []} />}
            {tab === "agents" && <AgentTab swarm={state?.swarm_result} originalCode={state?.ast_report?.original_snippet} />}
            {tab === "pr" && state && <PRTab state={state} />}
            {tab === "architecture" && <ArchitectureTab />}
          </div>
        </div>

        {/* ── Footer ───────────────────────────────────────────────────────── */}
        <div style={{ borderTop: "1px solid #21262d", padding: "16px 32px", textAlign: "center", fontSize: 11, color: "#484f58" }}>
          SentinelForge AI · Microsoft Build AI Hackathon 2025 · Powered by Azure OpenAI GPT-4o + AutoGen
        </div>
      </div>
    </>
  );
}
