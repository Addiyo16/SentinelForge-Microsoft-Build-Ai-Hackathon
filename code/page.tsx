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
interface SwarmResult { dialogue: AgentMsg[]; final_patch: string; pr_description: string; risk_score: number; approved: boolean; }
interface StageInfo { status: string; detail: string; ts: number; }
interface PipelineState {
  status: string; run_id: string | null; repo: string | null; commit_sha: string | null;
  pusher: string | null; branch: string | null; stages: Record<string, StageInfo>;
  logs: Log[]; trie_findings: TrieFinding[]; ast_report: ASTReport; rag_context: RAGResult[];
  swarm_result: SwarmResult; ci_status: Record<string, unknown>; dag_topology: unknown[];
  pr_url: string | null; pr_body?: string; started_at: number | null; finished_at: number | null;
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

function ASTTab({ report }: { report: ASTReport }) {
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

function AgentTab({ swarm }: { swarm: SwarmResult }) {
  if (!swarm?.dialogue?.length) return <EmptyState icon="🤖" text="Agent swarm idle. Trigger a simulation to launch the multi-agent review." />;

  const roleColor: Record<string, string> = { auditor: "#ef4444", optimizer: "#3b82f6", synthesizer: "#8b5cf6" };
  const roleIcon: Record<string, string> = { auditor: "🔒", optimizer: "⚡", synthesizer: "🔀" };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
        <MetricCard label="Risk Score" value={`${swarm.risk_score}/100`} accent={swarm.risk_score > 70 ? "#ef4444" : swarm.risk_score > 40 ? "#f97316" : "#22c55e"} />
        <MetricCard label="Decision" value={swarm.approved ? "APPROVE" : "CHANGES"} accent={swarm.approved ? "#22c55e" : "#f97316"} />
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
        <Card>
          <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 8, textTransform: "uppercase", letterSpacing: "0.06em" }}>Final Patch</div>
          <pre style={{ margin: 0, fontSize: 12, color: "#86efac", background: "var(--terminal-bg)", padding: 14, borderRadius: 6, overflow: "auto", maxHeight: 400 }}>
            {swarm.final_patch}
          </pre>
        </Card>
      )}
    </div>
  );
}

function PRTab({ state }: { state: PipelineState }) {
  const { pr_url, pr_body, repo, commit_sha, swarm_result } = state;

  if (!pr_body && !pr_url) return <EmptyState icon="📝" text="PR report will appear here after the pipeline completes." />;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {pr_url && (
        <div style={{ background: "#22c55e15", border: "1px solid #22c55e44", borderRadius: 8, padding: "12px 16px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span style={{ fontSize: 14, color: "#22c55e" }}>✅ Pull Request created successfully</span>
          <a href={pr_url} target="_blank" rel="noreferrer" style={{ fontSize: 12, color: "#3b82f6" }}>{pr_url}</a>
        </div>
      )}
      {!pr_url && (
        <div style={{ background: "#f59e0b15", border: "1px solid #f59e0b44", borderRadius: 8, padding: "12px 16px" }}>
          <span style={{ fontSize: 13, color: "#f59e0b" }}>⚠️ Set GITHUB_TOKEN in .env to auto-create real PRs. PR body preview below.</span>
        </div>
      )}
      {pr_body && (
        <Card>
          <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 10, textTransform: "uppercase", letterSpacing: "0.06em" }}>PR Markdown Preview</div>
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

// ─── Main Dashboard ───────────────────────────────────────────────────────────

export default function SentinelForgeDashboard() {
  const { state, connected } = usePipelineState();
  const [tab, setTab] = useState("logs");
  const [simulating, setSimulating] = useState(false);

  const handleSimulate = async () => {
    setSimulating(true);
    try {
      await fetch(`${API}/api/pipeline/simulate`, { method: "POST" });
      setTab("logs");
    } catch {
      alert("Cannot reach backend. Make sure uvicorn is running on port 8000.");
    } finally {
      setTimeout(() => setSimulating(false), 2000);
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
    { id: "pr", label: "PR Report", count: state?.pr_url ? 1 : 0 },
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
                <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
                  <span style={{ color: "#3b82f6" }}>{state.repo}</span>
                  {state.commit_sha && <span> · {state.commit_sha.slice(0, 8)}</span>}
                </div>
              )}

              {/* Simulate button */}
              <button
                onClick={handleSimulate}
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
                ) : simulating ? "Starting…" : "▶ Simulate GitHub Push"}
              </button>
            </div>
          </div>
        </div>

        <div style={{ maxWidth: 1200, margin: "0 auto", padding: "28px 32px" }}>

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
                  { label: "RAG Hits", value: state?.rag_context?.length ?? 0, color: "#8b5cf6" },
                  { label: "Risk", value: state?.swarm_result?.risk_score ? `${state.swarm_result.risk_score}/100` : "—", color: state?.swarm_result?.risk_score > 70 ? "#ef4444" : "#22c55e" },
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
            {tab === "agents" && <AgentTab swarm={state?.swarm_result} />}
            {tab === "pr" && state && <PRTab state={state} />}
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
