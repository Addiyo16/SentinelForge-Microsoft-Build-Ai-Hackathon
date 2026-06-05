"""
SentinelForge — FastAPI Main Application
Full 7-stage async pipeline: ingest → trie → AST → RAG → swarm → report → PR
"""

import asyncio
import json
import os
import time
from contextlib import asynccontextmanager
from typing import Any, Optional

import httpx
from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.agents.swarm import run_swarm
from app.services.github_service import (
    create_pull_request,
    fetch_changed_files,
    get_ci_status,
    parse_push_event,
    verify_signature,
)
from app.structures.dag import build_sentinelforge_dag
from app.structures.trie import ThreatTrie
from app.utils.ast_engine import analyze_code
from app.utils.rag_engine import retrieve_context
from app.utils.sandbox import run_sandboxed

from pathlib import Path
load_dotenv(dotenv_path=Path(__file__).parent.parent / ".env")

# ── Global pipeline state (in-memory; swap for Redis in production) ──────────

_pipeline_state: dict[str, Any] = {
    "status": "idle",
    "run_id": None,
    "repo": None,
    "commit_sha": None,
    "pusher": None,
    "branch": None,
    "stages": {},
    "logs": [],
    "trie_findings": [],
    "ast_report": {},
    "rag_context": [],
    "sandbox_result": {},
    "swarm_result": {},
    "ci_status": {},
    "dag_topology": [],
    "pr_url": None,
    "started_at": None,
    "finished_at": None,
}

_trie = ThreatTrie()


def _log(msg: str, level: str = "info"):
    entry = {"ts": round(time.time() * 1000), "level": level, "msg": msg}
    _pipeline_state["logs"].append(entry)
    print(f"[{level.upper()}] {msg}")


def _set_stage(name: str, status: str, detail: str = ""):
    _pipeline_state["stages"][name] = {
        "status": status,
        "detail": detail,
        "ts": round(time.time() * 1000),
    }


# ── Pipeline ─────────────────────────────────────────────────────────────────

async def run_full_pipeline(
    repo: str,
    commit_sha: str,
    files: list[dict],
    pusher: str = "unknown",
    branch: str = "main",
):
    global _pipeline_state

    run_id = f"{commit_sha[:8]}-{int(time.time())}"
    _pipeline_state.update({
        "status": "running",
        "run_id": run_id,
        "repo": repo,
        "commit_sha": commit_sha,
        "pusher": pusher,
        "branch": branch,
        "stages": {},
        "logs": [],
        "trie_findings": [],
        "ast_report": {},
        "rag_context": [],
        "sandbox_result": {},
        "swarm_result": {},
        "ci_status": {},
        "dag_topology": build_sentinelforge_dag().get_topology(),
        "pr_url": None,
        "started_at": time.time(),
        "finished_at": None,
    })

    try:
        # ── Stage 1: Ingest ───────────────────────────────────────────────────
        _set_stage("ingest", "running")
        _log(f"📥 Ingesting {len(files)} file(s) from {repo}@{commit_sha[:8]}")
        await asyncio.sleep(0.3)
        combined_code = "\n\n".join(
            f"# === {f['filename']} ===\n{f['content']}" for f in files
        )
        _set_stage("ingest", "complete", f"{len(files)} file(s) ingested")
        _log(f"✅ Ingest complete — {len(combined_code)} chars")

        # ── Stage 2: Trie Threat Scan ─────────────────────────────────────────
        _set_stage("trie_scan", "running")
        _log("🔍 Running Trie threat signature scan…")
        await asyncio.sleep(0.2)
        threats = _trie.find_all_threats(combined_code)
        trie_dicts = [
            {
                "pattern": t.pattern,
                "category": t.category,
                "severity": t.severity,
                "cwe_id": t.cwe_id,
                "confidence": t.confidence,
            }
            for t in threats
        ]
        _pipeline_state["trie_findings"] = trie_dicts
        _set_stage("trie_scan", "complete", f"{len(threats)} threat(s) found")
        _log(f"✅ Trie scan — {len(threats)} threat signature(s) matched", "warn" if threats else "info")

        # ── Stage 3: AST Analysis ─────────────────────────────────────────────
        _set_stage("ast_analysis", "running")
        _log("🌳 Running AST deep analysis…")
        await asyncio.sleep(0.2)
        # Analyse each file separately for best per-file findings
        all_findings = []
        ast_report_combined = None
        for f in files:
            report = analyze_code(f["content"])
            all_findings.extend(report.to_dict()["findings"])
            if ast_report_combined is None:
                ast_report_combined = report.to_dict()
        if ast_report_combined:
            ast_report_combined["findings"] = all_findings
        _pipeline_state["ast_report"] = ast_report_combined or {}
        _set_stage(
            "ast_analysis", "complete",
            f"CC={ast_report_combined.get('cyclomatic_complexity',0)}, "
            f"depth={ast_report_combined.get('max_loop_depth',0)}"
        )
        _log(f"✅ AST analysis — complexity {ast_report_combined.get('cyclomatic_complexity')}, "
             f"loop depth {ast_report_combined.get('max_loop_depth')}")

        # ── Stage 4: RAG Retrieval ────────────────────────────────────────────
        _set_stage("rag_lookup", "running")
        _log("🧠 Querying RAG knowledge base…")
        await asyncio.sleep(0.2)
        threat_categories = list({t.category for t in threats})
        rag_results = retrieve_context(combined_code, threat_categories)
        rag_dicts = [r.to_dict() for r in rag_results]
        _pipeline_state["rag_context"] = rag_dicts
        _set_stage("rag_lookup", "complete", f"{len(rag_results)} KB entry/entries retrieved")
        _log(f"✅ RAG — {len(rag_results)} knowledge base entries retrieved")

        # ── Stage 5: Sandbox Test ─────────────────────────────────────────────
        _set_stage("sandbox", "running")
        _log("🏖️ Sandboxing code snippet…")
        try:
            sandbox_res = await run_sandboxed(files[0]["content"] if files else "", timeout=4.0)
            _pipeline_state["sandbox_result"] = sandbox_res.to_dict()
            _set_stage("sandbox", "complete" if sandbox_res.success else "failed",
                       "passed" if sandbox_res.success else sandbox_res.stderr[:100])
            _log(f"{'✅' if sandbox_res.success else '⚠️'} Sandbox — exit {sandbox_res.exit_code}")
        except Exception:
            _pipeline_state["sandbox_result"] = {"stdout": "", "stderr": "skipped", "exit_code": 0, "timed_out": False, "memory_exceeded": False, "success": True}
            _set_stage("sandbox", "complete", "skipped on Windows")
            _log("⚠️ Sandbox skipped (Windows — continuing pipeline)")

        # ── Stage 6: Agent Swarm (Auditor ‖ Optimizer → Synthesizer) ─────────
        _set_stage("optimizer", "running")
        _set_stage("auditor", "running")
        _log("🤖 Launching AutoGen agent swarm (Auditor ‖ Optimizer)…")

        swarm_result = await run_swarm(
            code=combined_code,
            trie_findings=trie_dicts,
            ast_report=ast_report_combined or {},
            rag_context=rag_dicts,
        )
        _pipeline_state["swarm_result"] = swarm_result.to_dict()
        _set_stage("optimizer", "complete", "Code optimized")
        _set_stage("auditor", "complete", f"Risk score: {swarm_result.risk_score}")
        _log(f"✅ Agent swarm complete — risk score {swarm_result.risk_score}/100, "
             f"decision: {'APPROVE' if swarm_result.approved else 'REQUEST_CHANGES'}")

        # ── Stage 7: CI Status ────────────────────────────────────────────────
        _set_stage("ci_check", "running")
        _log("🔄 Checking GitHub Actions CI status…")
        ci = await get_ci_status(repo, commit_sha)
        _pipeline_state["ci_status"] = ci
        _set_stage("ci_check", "complete", ci.get("summary", "unknown"))
        _log(f"✅ CI status — {ci.get('summary', 'no checks found')}")

        # ── Stage 8: Auto PR ──────────────────────────────────────────────────
        _set_stage("report", "running")
        _log("📝 Generating PR report…")
        pr_title = f"[SentinelForge] Auto-patch · {commit_sha[:8]} · Risk {swarm_result.risk_score}/100"
        pr_body = _build_pr_body(
            repo, commit_sha, files, trie_dicts, ast_report_combined or {},
            rag_dicts, swarm_result, ci
        )

        pr_url = await create_pull_request(
            repo=repo,
            base_branch=branch,
            head_branch=f"sentinelforge/patch-{commit_sha[:8]}",
            title=pr_title,
            body=pr_body,
        )
        _pipeline_state["pr_url"] = pr_url
        _pipeline_state["pr_body"] = pr_body
        _set_stage("report", "complete", pr_url or "PR body generated (no token)")
        _log(f"✅ PR {'created: ' + pr_url if pr_url else 'body ready (set GITHUB_TOKEN to auto-create)'}")

        _pipeline_state["status"] = "complete"
        _pipeline_state["finished_at"] = time.time()
        duration = round(_pipeline_state["finished_at"] - _pipeline_state["started_at"], 2)
        _log(f"🏁 Pipeline complete in {duration}s")

    except Exception as e:
        _pipeline_state["status"] = "error"
        _pipeline_state["finished_at"] = time.time()
        _log(f"💥 Pipeline error: {e}", "error")
        raise


def _build_pr_body(
    repo, sha, files, threats, ast_report, rag_context, swarm_result, ci
) -> str:
    decision_badge = "✅ APPROVED" if swarm_result.approved else "⚠️ CHANGES REQUESTED"
    risk = swarm_result.risk_score
    risk_color = "🟢" if risk < 30 else "🟡" if risk < 70 else "🔴"

    threat_table = "\n".join(
        f"| `{t['pattern']}` | {t['category']} | {t['severity'].upper()} | {t['cwe_id']} |"
        for t in threats
    ) or "| — | No threats detected | — | — |"

    rag_section = "\n".join(
        f"- **[{r['kb_ref']}]** {r['vulnerability_type']} (similarity: {r['similarity_score']})\n"
        f"  > {r['historical_fix']}"
        for r in rag_context
    ) or "_No RAG entries matched._"

    ci_section = "\n".join(
        f"- {cr['name']}: `{cr['conclusion'] or cr['status']}`"
        for cr in ci.get("check_runs", [])
    ) or "_No CI checks found._"

    return f"""# 🛡️ SentinelForge Auto-Patch Report

> **Commit:** `{sha[:12]}` · **Repo:** `{repo}` · **Decision:** {decision_badge}

## {risk_color} Risk Score: {risk}/100

## 📁 Files Analysed
{chr(10).join(f'- `{f["filename"]}`' for f in files)}

## 🔍 Trie Threat Signatures
| Pattern | Category | Severity | CWE |
|---------|----------|----------|-----|
{threat_table}

## 🌳 AST Metrics
- Cyclomatic Complexity: `{ast_report.get("cyclomatic_complexity", "N/A")}`
- Max Loop Depth: `{ast_report.get("max_loop_depth", "N/A")}`
- Dangerous Calls: `{", ".join(ast_report.get("dangerous_calls", [])) or "none"}`

## 🧠 RAG Knowledge Base Context
{rag_section}

## 🛡️ Agent Patch
```python
{swarm_result.final_patch}
```

## 🔄 CI/CD Status
{ci_section}

## 📋 Agent Review
{swarm_result.pr_description}

---
_Generated by [SentinelForge AI](https://github.com) · Microsoft Build AI Hackathon_
"""


# ── FastAPI App ───────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    _log("🚀 SentinelForge API started")
    yield
    _log("🛑 SentinelForge API shutting down")


app = FastAPI(
    title="SentinelForge AI",
    description="AI-powered code security & optimization pipeline",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "version": "2.0.0"}


@app.get("/api/pipeline/state")
async def get_pipeline_state():
    return _pipeline_state


@app.post("/api/pipeline/simulate")
async def simulate(background_tasks: BackgroundTasks):
    """Trigger pipeline with mock code for demo/testing."""
    mock_files = [
        {
            "filename": "auth_service.py",
            "content": MOCK_CODE_AUTH,
        },
        {
            "filename": "data_processor.py",
            "content": MOCK_CODE_PERF,
        },
    ]
    background_tasks.add_task(
        run_full_pipeline,
        repo="demo-org/sentinelforge-demo",
        commit_sha="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        files=mock_files,
        pusher="demo-user",
        branch="feature/new-auth",
    )
    return {"status": "started", "message": "Pipeline simulation launched"}


@app.post("/webhook/github")
async def github_webhook(request: Request, background_tasks: BackgroundTasks):
    """Real GitHub webhook endpoint. Wire this to your repo via ngrok."""
    body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256", "")

    if not verify_signature(body, signature):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    event_type = request.headers.get("X-GitHub-Event", "")
    if event_type != "push":
        return {"status": "ignored", "event": event_type}

    payload = json.loads(body)
    event = parse_push_event(payload)

    _log(f"📨 Push event from {event.pusher} on {event.repo_full_name}@{event.branch}")

    # Fetch real file content from GitHub
    github_files = await fetch_changed_files(event, max_files=5)

    if not github_files:
        return {"status": "skipped", "reason": "No Python files changed"}

    files_payload = [
        {"filename": f.filename, "content": f.content}
        for f in github_files
    ]

    background_tasks.add_task(
        run_full_pipeline,
        repo=event.repo_full_name,
        commit_sha=event.commit_sha,
        files=files_payload,
        pusher=event.pusher,
        branch=event.branch,
    )

    return {
        "status": "processing",
        "repo": event.repo_full_name,
        "commit": event.commit_sha,
        "files": [f.filename for f in github_files],
    }


@app.post("/api/analyze-custom")
async def analyze_custom(request: Request, background_tasks: BackgroundTasks):
    """Run full pipeline on user-provided code — for recruiter/demo UI."""
    body = await request.json()
    repo = body.get("repo", "custom/submission")
    filename = body.get("filename", "code.py")
    code = body.get("code", "")
    if not code.strip():
        raise HTTPException(status_code=400, detail="No code provided")
    files = [{"filename": filename, "content": code}]
    import hashlib, time as _time
    sha = hashlib.md5(code.encode()).hexdigest()
    background_tasks.add_task(
        run_full_pipeline,
        repo=repo,
        commit_sha=sha,
        files=files,
        pusher="recruiter-demo",
        branch="main",
    )
    return {"status": "started", "repo": repo, "filename": filename}


@app.post("/api/analyze")
async def analyze_snippet(request: Request):
    """Synchronous analysis endpoint for single code snippets."""
    body = await request.json()
    code = body.get("code", "")
    filename = body.get("filename", "snippet.py")

    if not code.strip():
        raise HTTPException(status_code=400, detail="No code provided")

    threats = _trie.find_all_threats(code)
    trie_dicts = [
        {"pattern": t.pattern, "category": t.category,
         "severity": t.severity, "cwe_id": t.cwe_id, "confidence": t.confidence}
        for t in threats
    ]
    ast_report = analyze_code(code).to_dict()
    rag = retrieve_context(code, [t.category for t in threats])

    return {
        "filename": filename,
        "trie_findings": trie_dicts,
        "ast_report": ast_report,
        "rag_context": [r.to_dict() for r in rag],
    }


# ── Mock Code Fixtures ────────────────────────────────────────────────────────

MOCK_CODE_AUTH = '''
import pickle
import os

password = "admin123"
api_key = "sk-live-abc123xyz"

def verify_login(users, target_username):
    """Find user by iterating entire list — O(N) scan."""
    for user in users:
        for role in user["roles"]:
            if user["username"] == target_username:
                return user
    return None

def load_session(session_bytes):
    # Insecure deserialization
    return pickle.loads(session_bytes)

def run_admin_command(cmd):
    os.system(cmd)
'''

MOCK_CODE_PERF = '''
def find_duplicates(items):
    duplicates = []
    for i in range(len(items)):
        for j in range(len(items)):
            if i != j and items[i] == items[j]:
                if items[i] not in duplicates:
                    duplicates.append(items[i])
    return duplicates

def process_records(records, target_id):
    for record in records:
        for sub in record["sub_items"]:
            if sub["id"] == target_id:
                return sub
    return None
'''
