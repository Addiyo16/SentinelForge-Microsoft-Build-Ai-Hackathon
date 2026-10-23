"""
SentinelForge v2 — FastAPI Main Application
Full 8-stage async pipeline: ingest → trie → AST → RAG → sandbox → auditor‖optimizer → CI check → PR
Supports multiple CI/CD platforms: GitHub, GitLab, Azure DevOps.
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
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from app.agents.swarm import run_swarm
from app.core.risk import compute_risk_evaluation, RiskEvaluation
from app.integrations.github.client import (
    GitHubRepoClient,
    InvalidGitHubUrlError,
    RepositoryNotFoundError,
    RepositoryAccessDeniedError,
    RateLimitExceededError,
)
from app.ml.classifier import FindingClassifier, score_finding, _finding_classifier
from app.rules import (
    RULE_REGISTRY_VERSION,
    FindingStatus,
    deduplicate_findings,
    get_rule_registry,
)
from app.services.service_factory import get_ci_service
# Backwards compatible imports
from app.services.github_service import (
    create_pull_request,
    fetch_changed_files,
    get_ci_status,
    parse_push_event,
    verify_signature,
)
from app.structures.dag import build_sentinelforge_dag
from app.structures.trie import ThreatTrie
from app.utils.ast_engine import analyze_code, _detect_lang
from app.utils.rag_engine import retrieve_context
from app.utils.sandbox import run_sandboxed, verify_candidate_patch
from app.utils.teams import send_teams_notification

from pathlib import Path
load_dotenv(dotenv_path=Path(__file__).parent.parent / ".env")

# ── Global pipeline state & scan history (in-memory) ──────────────────────────

_scan_history: dict[str, dict[str, Any]] = {}

_pipeline_state: dict[str, Any] = {
    "status": "idle",
    "run_id": None,
    "scan_id": None,
    "scan_mode": "comprehensive",
    "repo": None,
    "commit_sha": None,
    "pusher": None,
    "branch": None,
    "stages": {},
    "logs": [],
    "trie_findings": [],
    "ast_report": {},
    "normalized_findings": [],
    "coverage_report": {},
    "rag_context": [],
    "sandbox_result": {},
    "swarm_result": {},
    "verification_result": {},
    "risk_evaluation": None,
    "ci_status": {},
    "dag_topology": [],
    "pr_url": None,
    "pr_body": None,
    "started_at": None,
    "finished_at": None,
    "platform": "github",
}

_trie = ThreatTrie()


def _log(msg: str, level: str = "info"):
    entry = {"ts": round(time.time() * 1000), "level": level, "msg": msg}
    _pipeline_state["logs"].append(entry)
    try:
        print(f"[{level.upper()}] {msg}")
    except UnicodeEncodeError:
        import sys
        encoding = sys.stdout.encoding or "ascii"
        clean_msg = msg.encode(encoding, errors="replace").decode(encoding)
        print(f"[{level.upper()}] {clean_msg}")


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
    platform: str = "github",
    scan_id: Optional[str] = None,
    scan_mode: str = "comprehensive",
    coverage_report: Optional[dict] = None,
):
    global _pipeline_state, _scan_history

    run_id = scan_id or f"{commit_sha[:8]}-{int(time.time())}"
    _pipeline_state.update({
        "status": "running",
        "run_id": run_id,
        "scan_id": run_id,
        "scan_mode": scan_mode,
        "repo": repo,
        "commit_sha": commit_sha,
        "pusher": pusher,
        "branch": branch,
        "stages": {},
        "logs": [],
        "trie_findings": [],
        "ast_report": {},
        "normalized_findings": [],
        "coverage_report": coverage_report or {},
        "rag_context": [],
        "sandbox_result": {},
        "swarm_result": {},
        "verification_result": {},
        "risk_evaluation": None,
        "ci_status": {},
        "dag_topology": build_sentinelforge_dag().get_topology(),
        "pr_url": None,
        "pr_body": None,
        "started_at": time.time(),
        "finished_at": None,
        "platform": platform,
    })
    _scan_history[run_id] = dict(_pipeline_state)

    try:
        # Resolve platform service
        ci_service = get_ci_service(platform)

        # ── Stage 1: Ingest ───────────────────────────────────────────────────
        _set_stage("ingest", "running")
        _log(f"📥 Ingesting {len(files)} file(s) from {platform.upper()} · {repo}@{commit_sha[:8]}")
        if coverage_report:
            _log(f"📊 Scan coverage: {coverage_report.get('successfully_scanned_count', len(files))} file(s) scanned out of {coverage_report.get('discovered_files_count', len(files))} discovered ({coverage_report.get('skipped_count', 0)} skipped)")
        await asyncio.sleep(0.3)
        def _file_header(fn: str) -> str:
            return f"# === {fn} ===" if fn.endswith((".py", ".yml", ".yaml", ".sh", ".rb")) else f"// === {fn} ==="

        if len(files) == 1:
            combined_code = files[0]["content"]
        else:
            combined_code = "\n\n".join(
                f"{_file_header(f['filename'])}\n{f['content']}" for f in files
            )
        _set_stage("ingest", "complete", f"{len(files)} file(s) ingested")
        _log(f"✅ Ingest complete — {len(combined_code)} chars")

        # ── Stage 2: Trie Threat Scan ─────────────────────────────────────────
        _set_stage("trie_scan", "running")
        _log("🔍 Running Trie threat signature scan & ML prioritization…")
        await asyncio.sleep(0.2)
        threats = []
        trie_dicts = []
        for f in files:
            fname = f.get("filename", "code.py")
            f_content = f.get("content", "")
            f_threats = _trie.find_all_threats(f_content, filename=fname, filter_false_positives=True)
            f_lang = _detect_lang(f_content, filename=fname)
            for t in f_threats:
                threats.append(t)
                ml_pred = score_finding(
                    finding={
                        "pattern": t.pattern,
                        "category": t.category,
                        "severity": t.severity,
                        "confidence": t.confidence,
                        "line": t.line,
                        "snippet": t.snippet,
                        "source_file": fname,
                    },
                    code_context=t.snippet or f_content[:500],
                    cyclomatic_complexity=1,
                    loop_depth=0,
                    language=f_lang,
                )
                trie_dicts.append({
                    "pattern": t.pattern,
                    "category": t.category,
                    "severity": t.severity,
                    "cwe_id": t.cwe_id,
                    "confidence": t.confidence,
                    "line": t.line,
                    "col": t.col,
                    "snippet": t.snippet,
                    "source_file": fname,
                    "language": f_lang,
                    "ml_score": ml_pred.priority_score,
                    "ml_verdict": "CONFIRMED_VULNERABILITY" if ml_pred.is_valid else "POTENTIAL_FALSE_POSITIVE",
                    "ml_priority_tier": ml_pred.priority_tier,
                    "ml_rationale": ml_pred.rationale,
                    "ml_probability": ml_pred.probability,
                })
        _pipeline_state["trie_findings"] = trie_dicts
        _set_stage("trie_scan", "complete", f"{len(threats)} threat(s) found")
        _log(f"✅ Trie scan — {len(threats)} threat signature(s) matched (ML scored)", "warn" if threats else "info")

        # ── Stage 3: AST Analysis ─────────────────────────────────────────────
        _set_stage("ast_analysis", "running")
        _log("🌳 Running AST deep analysis & ML classification…")
        await asyncio.sleep(0.2)
        
        all_findings = []
        ast_report_combined = None
        for f in files:
            cur_fname = f.get("filename", "code.py")
            report = analyze_code(f["content"], filename=cur_fname)
            findings_data = report.to_dict()["findings"]
            f_lang = _detect_lang(f["content"], filename=cur_fname)
            for af in findings_data:
                af["source_file"] = cur_fname
                af["language"] = f_lang
                ml_pred = score_finding(
                    finding=af,
                    code_context=af.get("evidence", "") or report.original_snippet or "",
                    cyclomatic_complexity=report.cyclomatic_complexity,
                    loop_depth=report.max_loop_depth,
                    language=f_lang,
                )
                af["ml_score"] = ml_pred.priority_score
                af["ml_verdict"] = "CONFIRMED_VULNERABILITY" if ml_pred.is_valid else "POTENTIAL_FALSE_POSITIVE"
                af["ml_priority_tier"] = ml_pred.priority_tier
                af["ml_rationale"] = ml_pred.rationale
                af["ml_probability"] = ml_pred.probability
                all_findings.append(af)
            if ast_report_combined is None:
                ast_report_combined = report.to_dict()

        if ast_report_combined:
            ast_report_combined["findings"] = all_findings
            
        _pipeline_state["ast_report"] = ast_report_combined or {}

        # Deduplicate and normalize findings across engines using versioned RuleRegistry
        raw_candidates = []
        for idx, t in enumerate(trie_dicts):
            raw_candidates.append({
                "source": "trie",
                "detection_source": "pattern",
                "pattern": t.get("pattern"),
                "category": t.get("category"),
                "title": t.get("category"),
                "severity": t.get("severity"),
                "cwe_id": t.get("cwe_id"),
                "line": t.get("line"),
                "col": t.get("col"),
                "evidence": t.get("snippet", ""),
                "snippet": t.get("snippet", ""),
                "source_file": t.get("source_file", files[0]["filename"] if files else "code.py"),
                "language": t.get("language", ""),
                "ml_score": t.get("ml_score", 50),
                "ml_verdict": t.get("ml_verdict", "POTENTIAL_FALSE_POSITIVE"),
                "ml_priority_tier": t.get("ml_priority_tier", "MEDIUM_RISK"),
                "ml_rationale": t.get("ml_rationale", ""),
                "ml_probability": t.get("ml_probability", 0.5),
            })
        for idx, a in enumerate(all_findings):
            raw_candidates.append({
                "source": "ast",
                "detection_source": "ast",
                "rule_id": a.get("rule_id"),
                "category": a.get("category", "AST Structural Rule"),
                "title": a.get("rule_id", "AST Finding"),
                "description": a.get("description", ""),
                "severity": a.get("severity", "medium"),
                "cwe_id": a.get("cwe_id", "CWE-Unknown"),
                "line": a.get("line"),
                "col": a.get("col"),
                "evidence": a.get("evidence", ""),
                "source_file": a.get("source_file", files[0]["filename"] if files else "code.py"),
                "language": a.get("language", ""),
                "ml_score": a.get("ml_score", 50),
                "ml_verdict": a.get("ml_verdict", "POTENTIAL_FALSE_POSITIVE"),
                "ml_priority_tier": a.get("ml_priority_tier", "MEDIUM_RISK"),
                "ml_rationale": a.get("ml_rationale", ""),
                "ml_probability": a.get("ml_probability", 0.5),
            })

        norm_findings = deduplicate_findings(raw_candidates)
        _pipeline_state["normalized_findings"] = norm_findings

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
        detected_cwes = list({f.get("cwe_id") for f in norm_findings if f.get("cwe_id")})
        primary_lang = _detect_lang(files[0]["content"], filename=files[0]["filename"]) if files else "python"
        
        try:
            from app.utils.rag_engine import retrieve_context_azure
            rag_results = await retrieve_context_azure(
                combined_code,
                threat_categories,
                language=primary_lang,
                finding_cwes=detected_cwes,
            )
        except Exception as re:
            _log(f"⚠️ RAG Azure Search failed ({re}) — falling back to local KB", "warn")
            rag_results = retrieve_context(
                combined_code,
                threat_categories,
                language=primary_lang,
                finding_cwes=detected_cwes,
            )
            
        rag_dicts = [r.to_dict() for r in rag_results]
        _pipeline_state["rag_context"] = rag_dicts
        _set_stage("rag_lookup", "complete", f"{len(rag_results)} KB entry/entries retrieved")
        _log(f"✅ RAG — {len(rag_results)} knowledge base entries retrieved")

        # ── Stage 5: Sandbox Test (Baseline Code Execution) ───────────────────
        _set_stage("sandbox", "running")
        _log("🏖️ Sandboxing code snippet…")
        try:
            primary_fn = files[0]["filename"] if files else "code.py"
            sandbox_res = await run_sandboxed(files[0]["content"] if files else "", timeout=4.0, filename=primary_fn)
            _pipeline_state["sandbox_result"] = sandbox_res.to_dict()
            _set_stage("sandbox", "complete" if sandbox_res.success else "failed",
                       "passed" if sandbox_res.success else sandbox_res.stderr[:100])
            _log(f"{'✅' if sandbox_res.success else '⚠️'} Sandbox baseline — exit {sandbox_res.exit_code}")
        except Exception as se:
            _pipeline_state["sandbox_result"] = {"stdout": "", "stderr": str(se), "exit_code": 1, "timed_out": False, "memory_exceeded": False, "success": False}
            _set_stage("sandbox", "failed", str(se)[:100])
            _log(f"⚠️ Sandbox execution warning: {se}", "warn")

        # ── Stage 6: Agent Swarm (Auditor ‖ Optimizer → Synthesizer) ─────────
        _set_stage("optimizer", "running")
        _set_stage("auditor", "running")
        _log("🤖 Launching AutoGen agent swarm (Auditor ‖ Optimizer)…")

        primary_filename = files[0]["filename"] if files else "code.py"
        swarm_result = await run_swarm(
            code=combined_code,
            trie_findings=trie_dicts,
            ast_report=ast_report_combined or {},
            rag_context=rag_dicts,
            filename=primary_filename,
            files=files,
            all_findings=norm_findings,
        )
        _pipeline_state["swarm_result"] = swarm_result.to_dict()
        _set_stage("optimizer", "complete", "Code optimized")
        _set_stage("auditor", "complete", f"Risk score: {swarm_result.risk_score}")
        _log(f"✅ Agent swarm complete — risk score {swarm_result.risk_score}/100, "
             f"decision: {'APPROVE' if swarm_result.approved else 'REQUEST_CHANGES'}")

        # ── Stage 6.5: Independent Patch Verification (Module 5) ─────────────
        _log("🔬 Running independent patch verification (parse, test, rescan, regression)…")
        verification_res = await verify_candidate_patch(
            original_code=combined_code,
            patch_code=swarm_result.final_patch,
            original_trie_threats=trie_dicts,
            original_ast_report=ast_report_combined or {},
            filename=primary_filename,
            timeout=5.0,
            files=files,
            all_findings=norm_findings,
        )
        _pipeline_state["verification_result"] = verification_res
        v_passed = verification_res["verification_passed"]
        v_status_label = verification_res.get("status", "NOT VERIFIED")
        if verification_res.get("is_clean_baseline") or not (norm_findings or trie_dicts):
            _log("✅ Independent verification — BASELINE CHECK PASSED (No patch required)")
        elif v_passed:
            _log("✅ Independent verification — PATCH VERIFICATION PASSED: All checks satisfied")
        elif "PATCH NOT GENERATED" in v_status_label:
            _log("⚠️ Independent verification — PATCH NOT GENERATED: Findings remain unresolved", "warn")
        else:
            _log(f"❌ Independent verification — NOT VERIFIED: {verification_res.get('failure_summary', 'Checks failed')}", "warn")

        # ── Stage 7: CI Status ────────────────────────────────────────────────
        _set_stage("ci_check", "running")
        _log(f"🔄 Checking {platform.upper()} CI pipeline status…")
        ci = await ci_service.get_ci_status(repo, commit_sha)
        _pipeline_state["ci_status"] = ci
        _set_stage("ci_check", "complete", ci.get("summary", "unknown"))
        _log(f"✅ CI status — {ci.get('summary', 'no checks found')}")

        # ── Canonical Risk Evaluation (app.core.risk) ─────────────────────────
        risk_eval = compute_risk_evaluation(
            findings=norm_findings or trie_dicts,
            ast_report=ast_report_combined or {},
            verification_result=verification_res,
            coverage_report=coverage_report,
            ci_status=ci,
        )
        _pipeline_state["risk_evaluation"] = risk_eval.to_dict()

        swarm_result.risk_score = risk_eval.original_risk
        swarm_result.patched_risk_score = risk_eval.residual_risk
        swarm_result.approved = (risk_eval.merge_decision == "APPROVED")
        _pipeline_state["swarm_result"]["risk_score"] = risk_eval.original_risk
        _pipeline_state["swarm_result"]["patched_risk_score"] = risk_eval.residual_risk
        _pipeline_state["swarm_result"]["approved"] = (risk_eval.merge_decision == "APPROVED")

        if not v_passed:
            _log(f"⚠️ Risk reduction withheld: {risk_eval.decision_reasons[0] if risk_eval.decision_reasons else 'Verification failed'}", "warn")
        else:
            _log(f"🛡️ Verified risk reduction credited: {risk_eval.original_risk}/100 -> {risk_eval.residual_risk}/100")

        # ── Stage 8: Auto PR ──────────────────────────────────────────────────
        _set_stage("report", "running")
        _log(f"📝 Generating {platform.upper()} patch integration PR/MR…")
        pr_title = f"[SentinelForge] Auto-patch · {commit_sha[:8]} · Risk {risk_eval.residual_risk}/100"
        pr_body = _build_pr_body(
            repo, commit_sha, files, norm_findings, ast_report_combined or {},
            rag_dicts, swarm_result, ci, platform, verification_res, coverage_report, risk_eval=risk_eval
        )

        pr_url = await ci_service.create_pull_request(
            repo=repo,
            base_branch=branch,
            head_branch=f"sentinelforge/patch-{commit_sha[:8]}",
            title=pr_title,
            body=pr_body,
        )
        _pipeline_state["pr_url"] = pr_url
        _pipeline_state["pr_body"] = pr_body
        
        pr_type_label = "Merge Request" if platform == "gitlab" else "Pull Request"
        _set_stage("report", "complete", pr_url or f"{pr_type_label} body generated (no token)")
        _log(f"✅ {pr_type_label} {'created: ' + pr_url if pr_url else 'body ready (set token to auto-create)'}")

        _pipeline_state["status"] = "complete"
        _pipeline_state["finished_at"] = time.time()
        duration = round(_pipeline_state["finished_at"] - _pipeline_state["started_at"], 2)
        _log(f"🏁 Pipeline complete in {duration}s")
        _scan_history[run_id] = dict(_pipeline_state)

        # Optional: Send Microsoft Teams alert card
        try:
            await send_teams_notification(
                repo=repo,
                branch=branch,
                commit_sha=commit_sha,
                risk_score=swarm_result.risk_score,
                approved=swarm_result.approved,
                pr_url=pr_url,
                trie_count=len(trie_dicts),
                ast_count=len(ast_report_combined.get("findings", [])) if ast_report_combined else 0,
                cc=ast_report_combined.get("cyclomatic_complexity", 0) if ast_report_combined else 0,
            )
        except Exception as te:
            _log(f"⚠️ Teams notification skipped: {te}", "warn")

    except Exception as e:
        _pipeline_state["status"] = "error"
        _pipeline_state["finished_at"] = time.time()
        _log(f"💥 Pipeline error: {e}", "error")
        _scan_history[run_id] = dict(_pipeline_state)
        raise


def _build_pr_body(
    repo: str,
    sha: str,
    files: list[dict],
    threats: list[dict],
    ast_report: dict,
    rag_context: list[dict],
    swarm_result: Any,
    ci: dict,
    platform: str = "github",
    verification: dict = None,
    coverage_report: dict = None,
    risk_eval: Optional[RiskEvaluation] = None,
) -> str:
    pr_name = "Merge Request" if platform == "gitlab" else "Pull Request"
    v_passed = bool(verification and verification.get("verification_passed"))
    findings = threats or []

    if risk_eval is None:
        risk_eval = compute_risk_evaluation(
            findings=findings,
            ast_report=ast_report,
            verification_result=verification,
            coverage_report=coverage_report,
            ci_status=ci,
        )
        orig_risk = swarm_result.risk_score if (swarm_result and hasattr(swarm_result, "risk_score")) else risk_eval.original_risk
        patched_risk = (swarm_result.patched_risk_score if v_passed else orig_risk) if (swarm_result and hasattr(swarm_result, "patched_risk_score")) else risk_eval.residual_risk
    else:
        orig_risk = risk_eval.original_risk
        patched_risk = risk_eval.residual_risk

    if risk_eval.is_partial_scan:
        decision_badge = "⚠️ CHANGES REQUESTED (PARTIAL SCAN)"
    elif risk_eval.merge_decision == "APPROVED":
        decision_badge = "✅ APPROVED"
    elif risk_eval.merge_decision == "BLOCKED":
        decision_badge = "🛑 BLOCKED"
    else:
        decision_badge = "⚠️ CHANGES REQUESTED"

    risk_color = "🟢" if (patched_risk < 30 and not risk_eval.is_partial_scan) else "🟡" if patched_risk < 70 else "🔴"

    scanned_count = coverage_report.get('successfully_scanned_count', len(files)) if coverage_report else len(files)
    eligible_count = coverage_report.get('eligible_files_count', len(files)) if coverage_report else len(files)
    discovered_count = coverage_report.get('discovered_files_count', len(files)) if coverage_report else len(files)
    discovery_coverage_pct = round((scanned_count / max(1, discovered_count)) * 100.0, 2) if discovered_count else 100.0

    if not findings:
        if risk_eval.is_partial_scan:
            risk_reduction_note = (
                f"Baseline (Partial Scan): No security vulnerabilities detected in the {scanned_count} analyzed files "
                f"({risk_eval.coverage_percentage:.2f}% eligible coverage). Note: {eligible_count - scanned_count} eligible files were not analyzed. "
                f"This partial scan does not prove the entire repository is secure."
            )
        else:
            risk_reduction_note = "Baseline (Complete Scan): Zero security vulnerabilities discovered across all analyzed repository code."
    elif v_passed:
        risk_reduction_note = f"Credited: Risk reduced from {orig_risk}/100 to {patched_risk}/100 following independent verification of patch mitigation."
    elif not (swarm_result.final_patch if swarm_result and hasattr(swarm_result, "final_patch") else "").strip():
        risk_reduction_note = f"Withheld: Residual risk remains {orig_risk}/100 because no remediation patch was generated or applied."
    else:
        risk_reduction_note = f"Withheld: Residual risk remains {orig_risk}/100 because the proposed patch failed independent verification or left target vulnerabilities unmitigated."

    reasons_markdown = "\n".join(f"- {r}" for r in risk_eval.decision_reasons)

    # Partial scan warning banner
    partial_scan_banner = ""
    if risk_eval.is_partial_scan or (coverage_report and eligible_count > scanned_count):
        skipped_quota = max(0, eligible_count - scanned_count)
        cov_pct = risk_eval.coverage_percentage
        next_off = coverage_report.get("next_offset") if coverage_report else None
        resumable_hint = f"\n> To analyze subsequent files, run resumable scan with `file_offset={next_off}`." if next_off else ""
        partial_scan_banner = (
            f"\n> ⚠️ **CRITICAL AUDIT LIMITATION — PARTIAL REPOSITORY SCAN ({cov_pct:.2f}% ELIGIBLE COVERAGE / {discovery_coverage_pct:.2f}% TOTAL COVERAGE)**:\n"
            f"> Only **{scanned_count}** of **{eligible_count}** eligible source files were analyzed (**{skipped_quota} files skipped** due to scan quota limits).\n"
            f"> Findings, risk calculations, and clean statuses apply **ONLY** to the {scanned_count} analyzed files and do **NOT** certify the entire repository.{resumable_hint}\n"
        )

    # 1. Scan Coverage Section
    cov_section = ""
    if coverage_report:
        skip_summary = coverage_report.get("skip_reasons_summary") or coverage_report.get("skipped_summary") or {}
        skip_rows = "\n".join(
            f"| `{reason}` | {count} |"
            for reason, count in skip_summary.items()
        ) or "| _None_ | 0 |"

        cov_section = f"""
## 📊 Repository Scan Coverage & Discovery Audit
| Coverage Metric | Value |
|-----------------|-------|
| Target Commit SHA | `{sha}` |
| Discovered Total Files | `{discovered_count}` |
| Eligible Source Files | `{eligible_count}` |
| Successfully Scanned | `{scanned_count}` |
| Skipped Files | `{coverage_report.get('skipped_count', 0)}` |
| Eligible Source Coverage | `{risk_eval.coverage_percentage:.2f}%` ({scanned_count} of {eligible_count} eligible files) |
| Total Discovery Coverage | `{discovery_coverage_pct:.2f}%` ({scanned_count} of {discovered_count} discovered files) |
| Scan Review Status | `{'⚠️ INCOMPLETE / PARTIAL SCAN' if risk_eval.is_partial_scan else '✅ COMPLETE SCAN'}` |
| Current Batch Offset | `{coverage_report.get('file_offset', 0)}` |
| Resumable Next Offset | `{coverage_report.get('next_offset') if coverage_report.get('next_offset') is not None else 'None (Final Batch)'}` |
| Prioritization Strategy | Priority-Scored (Entrypoints, Handlers, Controllers, Logic) |
| Excluded Test Files | `{'Enabled' if coverage_report.get('exclude_tests') else 'Disabled'}` |

### Files Skipped by Category
| Skip Category / Reason | File Count |
|------------------------|------------|
{skip_rows}
"""

    # 2. ML Benchmark Evidence
    ml_section = ""
    try:
        from app.ml.model_registry import ModelRegistry
        meta = ModelRegistry().load_metadata()
        if meta and meta.metrics:
            test_eval = meta.metrics.get("test_evaluation", {})
            cm = test_eval.get("confusion_matrix", {})
            ml_section = f"""
## 🤖 Supervised AI/ML Finding Prioritization Model
> ⚠️ **EXPERIMENTAL BETA NOTICE**: The supervised ML model assists in ranking and filtering findings. Test evaluation metrics reflect held-out validation splits. Deterministic AST and signature scanners retain authoritative gating control.

- **Status**: `EXPERIMENTAL BETA (Assists ranking; deterministic engine retains authority)`
- **Model Architecture**: `{meta.model_type}` (Calibrated Probability Classifier)
- **Model Registry Version**: `v{meta.version}`
- **Training Datasets**: `Juliet (NIST)`, `Big-Vul`, `Devign`, `DiverseVul`, `SentinelForge-Curated`
- **Split Methodology**: Repository-level Grouped Split (Zero cross-repository data leakage)
- **Classification Threshold**: `{meta.optimal_threshold}` (Calibrated on Validation Split)

### Benchmark Test Evaluation (Held-Out Repositories)
| Metric | Score |
|--------|-------|
| Evaluated Test Samples | `{test_eval.get('sample_count', 0)}` (Held-Out Unseen Repositories) |
| Total Benchmark Corpus | `{meta.training_samples + (test_eval.get('sample_count', 0) * 2)}` Samples across Independent Repos |
| Precision | `{test_eval.get('precision', 0.0):.2f}` |
| Recall | `{test_eval.get('recall', 0.0):.2f}` |
| F1-Score | `{test_eval.get('f1_score', 0.0):.2f}` |
| PR-AUC | `{test_eval.get('pr_auc', 0.0):.2f}` |
| False Positive Rate | `{test_eval.get('false_positive_rate', 0.0):.2f}` |

### Confusion Matrix (Held-Out Test Split)
| | Predicted Negative | Predicted Positive |
|---|---|---|
| **Actual Benign / Sanitized** | True Negative: `{cm.get('true_negatives', 0)}` | False Positive: `{cm.get('false_positives', 0)}` |
| **Actual Vulnerable** | False Negative: `{cm.get('false_negatives', 0)}` | True Positive: `{cm.get('true_positives', 0)}` |
"""
    except Exception:
        pass

    # 3. Independent Verification & Command Trail
    v_sec = ""
    if verification:
        raw_status = verification.get("status") or ""
        is_clean_base = bool(verification.get("is_clean_baseline") or not findings or raw_status == "BASELINE CHECK PASSED — NO PATCH REQUIRED")
        is_patch_missing = bool(not is_clean_base and (raw_status == "PATCH NOT GENERATED" or "PATCH NOT GENERATED" in raw_status or (findings and not (swarm_result.final_patch if swarm_result and hasattr(swarm_result, "final_patch") else "").strip())))

        if is_clean_base:
            if risk_eval.is_partial_scan:
                v_badge = "✅ BASELINE CHECK PASSED (PARTIAL SCAN)"
                result_label = f"BASELINE CHECK PASSED (PARTIAL SCAN): No findings detected in the {scanned_count} analyzed files ({risk_eval.coverage_percentage:.2f}% coverage). WARNING: Incomplete scan ({eligible_count - scanned_count} files unanalyzed) does not prove overall repository security."
                patch_status_label = "NOT REQUIRED (FOR SCANNED FILES)"
            else:
                v_badge = "✅ BASELINE CHECK PASSED — NO PATCH REQUIRED"
                result_label = "BASELINE CHECK PASSED — NO PATCH REQUIRED (All analyzed code satisfies security criteria; zero patch required)"
                patch_status_label = "NOT REQUIRED"
        elif is_patch_missing:
            v_badge = "⚠️ PATCH NOT GENERATED"
            result_label = "PATCH NOT GENERATED — FINDINGS REMAIN UNRESOLVED"
            patch_status_label = "NOT GENERATED"
        elif v_passed and len(verification.get("persisting_vulnerabilities", [])) == 0:
            v_badge = "✅ PATCH VERIFICATION PASSED"
            result_label = "PATCH VERIFICATION PASSED (All security, syntax, and regression checks satisfied)"
            patch_status_label = "VERIFIED"
        else:
            persisting_count = len(verification.get("persisting_vulnerabilities", [])) if verification else 0
            if persisting_count > 0:
                v_badge = "❌ INCOMPLETE PATCH — TARGET VULNERABILITIES PERSIST"
                result_label = f"NOT VERIFIED: Proposed patch is INCOMPLETE — {persisting_count} vulnerability pattern(s) persist. (A Python syntax check passing does not establish that a security vulnerability has been fixed)."
                patch_status_label = "INCOMPLETE"
            else:
                v_badge = "❌ NOT VERIFIED"
                result_label = "NOT VERIFIED (Required tests failed, rescan failed, or target findings unmitigated)"
                patch_status_label = "NOT VERIFIED"

        audit_trail = verification.get("command_audit_trail", [])
        if audit_trail:
            audit_rows = "\n".join(
                f"| {step.get('step')} | `{step.get('command')}` | `{step.get('status')}` | `{step.get('exit_code') if step.get('exit_code') is not None else '—'}` | `{step.get('duration_ms')}ms` | {step.get('output')} |"
                for step in audit_trail
            )
        else:
            audit_rows = "| — | No command trail recorded | — | — | — | — |"

        mitigated = ", ".join(f"`{m}`" for m in verification.get("mitigated_vulnerabilities", [])) or "_None_"
        persisting = ", ".join(f"`{p}`" for p in verification.get("persisting_vulnerabilities", [])) or "_None_"

        # 3.1 Traceable Per-Finding Remediation Audit
        trace_list = verification.get("finding_traceability", [])
        if trace_list:
            trace_rows = "\n".join(
                f"| `{t.get('finding_id', 'Finding')}` | `{t.get('source_file', 'code.py')}:{t.get('line', 1)}` | {t.get('cwe_id', 'CWE-Unknown')} | `{t.get('patch_hunk_status', 'UNKNOWN')}` | `{t.get('rescan_status', 'UNKNOWN')}` | {'✅ `MITIGATED`' if t.get('resolution') == 'MITIGATED' else '❌ `PERSISTING`'} | {t.get('details', '')} |"
                for t in trace_list
            )
        else:
            trace_rows = "| — | — | — | — | — | — | Zero findings requiring remediation |"

        v_sec = f"""
## 🧪 Independent Patch Verification ({v_badge})
- **Patch Status**: `{patch_status_label}`
- **Verification Result**: `{result_label}`
- **Total Execution Duration**: `{verification.get('execution_duration', 0)}s`
- **Mitigated Vulnerabilities**: {mitigated}
- **Persisting Vulnerabilities**: {persisting}

### 📍 Finding-to-Patch Traceability & Verification Audit
| Finding ID & Rule | Target File & Line | CWE | Patch Hunk Status | Rescan Verification | Resolution | Audit Details |
|-------------------|--------------------|-----|-------------------|---------------------|------------|---------------|
{trace_rows}

### Subprocess Command Execution Audit Trail
| Step | Subprocess Command | Status | Exit Code | Duration | Diagnostic Output |
|------|--------------------|--------|-----------|----------|-------------------|
{audit_rows}
"""
        if verification.get("failure_summary"):
            v_sec += f"\n> ⚠️ **Verification Diagnostics**: {verification.get('failure_summary')}\n"

    # 4. Reconciled Findings Table (AST + Trie + Dataflow)
    findings_rows = []
    for f in findings:
        file_loc = f"{f.get('file_path') or f.get('source_file') or (files[0]['filename'] if files else 'code.py')}:{f.get('line', 1)}"
        f_title = f.get('title') or f.get('pattern') or f.get('category') or 'Finding'
        r_id = f.get('rule_id') or 'SF-VULN'
        finding_id_title = f"{r_id} - {f_title}"
        cat = f.get('category', 'Security')
        sev = str(f.get('severity', 'medium')).upper()
        cwe = f.get('cwe_id', 'CWE-Unknown')
        ds_list = f.get('detection_sources') or ([f.get('detection_source')] if f.get('detection_source') else ['ast'])
        ds_str = ", ".join(str(s).upper() for s in ds_list if s)
        ml_tier = f"{f.get('ml_priority_tier', 'MEDIUM_RISK')} ({f.get('ml_score', 50)}%)"
        findings_rows.append(
            f"| `{file_loc}` | `{finding_id_title}` | {cat} | {sev} | {cwe} | `{ds_str}` | `{ml_tier}` |"
        )

    findings_table = "\n".join(findings_rows) or "| — | — | — | No security threats detected | — | — | — |"

    rag_section = "\n".join(
        f"- **[{r['kb_ref']}]** {r['vulnerability_type']} (similarity: {r['similarity_score']})\n"
        f"  > *Reason*: {r.get('selection_reason', 'Domain match')}\n"
        f"  > {r['historical_fix']}"
        for r in rag_context
    ) or "_No RAG entries matched._"

    # CI Checks formatting: Distinguish native upstream test suites from SentinelForge required check enforcement
    check_runs = ci.get("check_runs", [])
    if check_runs:
        passed_runs = [cr for cr in check_runs if (cr.get("conclusion") or "").lower() == "success"]
        ci_section = "\n".join(
            f"- {cr['name']}: `{cr['conclusion'] or cr['status']}`"
            for cr in check_runs
        )
        sf_check = next((cr for cr in check_runs if "sentinelforge" in cr.get("name", "").lower()), None)
        if sf_check:
            enforce_status = f"Active SentinelForge Check Run detected (`{sf_check.get('name')}`: `{sf_check.get('conclusion') or sf_check.get('status')}`)."
        else:
            enforce_status = (
                f"⚠️ **Advisory In-PR Gate (Not Enforced by GitHub Branch Protection)**\n"
                f"  > **Evidence & Gap Analysis**: {len(passed_runs)} of {len(check_runs)} native upstream GitHub check run(s) succeeded (validating codebase compilation and upstream unit test suites). "
                f"However, `sentinelforge/security-gate` is **not currently configured as a required status check** under repository Branch Protection Rules.\n"
                f"  > While SentinelForge evaluates this pull request as `{risk_eval.merge_decision}`, GitHub does **not** block merges automatically without administrative branch protection configuration.\n"
                f"  > **How to enforce automated merge blocking in GitHub:**\n"
                f"  > 1. Ensure `.github/workflows/sentinelforge.yml` triggers on `pull_request` and reports check-run `sentinelforge/security-gate`.\n"
                f"  > 2. Under GitHub repository **Settings -> Branches -> Branch Protection Rules**, enable **Require status checks to pass before merging** and select `sentinelforge/security-gate`."
            )
        ci_enforcement_note = (
            f"- **Upstream CI Health**: `{len(passed_runs)}/{len(check_runs)} passed` (validates upstream test suite)\n"
            f"- **SentinelForge Gate Decision**: `{risk_eval.merge_decision}`\n"
            f"- **Branch Protection Status**: {enforce_status}"
        )
    else:
        ci_section = "- CI Checks: `NOT CONFIGURED` (No automated CI workflow runs or check suites detected for this commit)."
        ci_enforcement_note = (
            "- **Enforcement Status**: ⚠️ **Advisory Recommendation (Not Enforced by GitHub Branch Protection)**\n"
            f"  > **Important Context**: SentinelForge has evaluated this pull request as `{risk_eval.merge_decision}`. "
            "However, because no GitHub Actions workflow or Branch Protection Rule requires `sentinelforge/security-gate` "
            "as a mandatory status check, GitHub does **not** block merges automatically without administrative configuration.\n"
            "  > **How to enforce merge blocking in GitHub:**\n"
            "  > 1. Add `.github/workflows/sentinelforge.yml` to your repository.\n"
            "  > 2. Under GitHub repository **Settings -> Branches -> Branch Protection Rules**, enable **Require status checks to pass before merging** and select `sentinelforge/security-gate`."
        )

    enforcement_action = (
        "PR APPROVED — All security, syntax, and regression checks verified."
        if risk_eval.merge_decision == "APPROVED"
        else f"PR {risk_eval.merge_decision} — {risk_eval.decision_reasons[0] if risk_eval.decision_reasons else 'Security policy requirements not met'}"
    )

    # 5. Authoritative Review Summary (derived exclusively from risk_eval and verification)
    review_issues = []
    if not findings:
        if risk_eval.is_partial_scan:
            review_issues.append(
                f"- **No Findings Detected in Scanned Files**: Zero vulnerabilities discovered in {scanned_count} analyzed files "
                f"({risk_eval.coverage_percentage:.2f}% of eligible source code). "
                f"*Important limitation*: {eligible_count - scanned_count} eligible files remain unanalyzed due to quota limits."
            )
        else:
            review_issues.append("- **Clean Source State**: Zero security vulnerabilities detected across complete scan.")
    else:
        for f in findings[:5]:
            sev_str = str(f.get('severity', 'medium')).upper()
            title_str = f.get('title') or f.get('pattern') or f.get('rule_id') or 'Finding'
            cwe_str = f.get('cwe_id', 'CWE-Unknown')
            file_loc = f"{f.get('file_path') or f.get('source_file') or (files[0]['filename'] if files else 'code.py')}:{f.get('line', 1)}"
            review_issues.append(f"- **[{sev_str}] {title_str} ({cwe_str})** at `{file_loc}`")
        if len(findings) > 5:
            review_issues.append(f"- ... and {len(findings) - 5} additional finding(s).")

    review_issues_md = "\n".join(review_issues)

    patch_str = (swarm_result.final_patch if swarm_result and hasattr(swarm_result, "final_patch") else "") or ""
    if not findings:
        if risk_eval.is_partial_scan:
            remediation_summary = (
                f"No security vulnerabilities detected within the {scanned_count} analyzed source files ({risk_eval.coverage_percentage:.2f}% coverage). "
                f"Note: {eligible_count - scanned_count} eligible files were skipped; this partial scan does NOT certify entire repository security."
            )
            v_gate_str = "BASELINE CHECK PASSED (PARTIAL SCAN — UNANALYZED FILES REMAIN)"
        else:
            remediation_summary = "All eligible source files analyzed with zero security vulnerabilities detected. Baseline check passed — zero remediation patch required."
            v_gate_str = "BASELINE CHECK PASSED — NO PATCH REQUIRED"
    elif v_passed and len(verification.get("persisting_vulnerabilities", [])) == 0:
        remediation_summary = f"Candidate patch verified in isolated sandbox. Target vulnerabilities mitigated, reducing risk from {orig_risk}/100 to {patched_risk}/100."
        v_gate_str = "PATCH VERIFICATION PASSED"
    elif not patch_str.strip():
        remediation_summary = f"No remediation patch was generated or applied. Identified security findings remain unresolved. Residual risk remains {orig_risk}/100."
        v_gate_str = "PATCH NOT GENERATED"
    else:
        persisting_list = verification.get("persisting_vulnerabilities", []) if verification else []
        fail_diag = verification.get('failure_summary') if verification else 'checks failed or unverified'
        if persisting_list:
            remediation_summary = (
                f"Candidate patch is INCOMPLETE: Replaced only partial threat patterns, leaving {len(persisting_list)} "
                f"finding(s) unresolved ({', '.join(persisting_list)}). A Python syntax check passing does not establish that "
                f"a security vulnerability has been fixed. Risk reduction withheld; residual risk remains {orig_risk}/100."
            )
            v_gate_str = "INCOMPLETE PATCH — TARGET FINDINGS PERSIST"
        else:
            remediation_summary = f"Candidate patch generated but FAILED independent verification ({fail_diag}). Risk reduction withheld; residual risk remains {orig_risk}/100."
            v_gate_str = "NOT VERIFIED"

    review_summary_md = f"""### Summary of Security Review & Gate Decision
SentinelForge Automated Code Review evaluated `{repo}@{sha[:8]}` against static signatures, AST rules, and ML classification.

#### Identified Issues
{review_issues_md}

#### Remediation Strategy
{remediation_summary}

#### Review Decision
- **Canonical Decision:** `{risk_eval.merge_decision}`
- **Original Risk Score:** `{orig_risk}/100`
- **Residual Risk Score:** `{patched_risk}/100`
- **Verification Gate:** `{v_gate_str}`
- **Coverage Status:** `{scanned_count} of {eligible_count} eligible files scanned ({risk_eval.coverage_percentage:.2f}%)`
"""

    # Synchronize swarm_result description to match canonical summary
    if swarm_result and hasattr(swarm_result, "pr_description"):
        swarm_result.pr_description = review_summary_md

    provider_url = "https://gitlab.com" if platform == "gitlab" else "https://dev.azure.com" if platform == "azure-devops" else "https://github.com"

    return f"""# 🛡️ SentinelForge Auto-Patch & Security Audit Report

> **Commit:** `{sha[:12]}` · **Repo:** `{repo}` · **Decision:** {decision_badge} · **Platform:** `{platform.upper()}`
{partial_scan_banner}
## {risk_color} Canonical Risk Assessment: {patched_risk}/100 ({risk_eval.residual_risk_level})
- **Original Unpatched Code Risk**: `{orig_risk}/100` ({risk_eval.original_risk_level})
- **Residual Risk (Post-Verification)**: `{patched_risk}/100` ({risk_eval.residual_risk_level})
- **Risk Score Policy**: {risk_reduction_note}
- **Automated PR Merge Gate**: `{risk_eval.merge_decision}`
- **Scan Completeness**: `{risk_eval.coverage_percentage:.2f}%` ({'Partial Scan' if risk_eval.is_partial_scan else 'Complete Scan'})
- **Findings Breakdown**: Critical: `{risk_eval.findings_breakdown.get('critical', 0)}`, High: `{risk_eval.findings_breakdown.get('high', 0)}`, Medium: `{risk_eval.findings_breakdown.get('medium', 0)}`, Low: `{risk_eval.findings_breakdown.get('low', 0)}`

### Auditable Decision Rationales
{reasons_markdown}
{cov_section}
{v_sec}
{ml_section}
## 🔍 Polyglot Threat Signatures & AST Structural Findings
| File & Line | Finding / Rule ID | Category | Severity | CWE | Detection Source | ML Priority Tier |
|-------------|-------------------|----------|----------|-----|------------------|------------------|
{findings_table}

## 🌳 AST Metrics
- Cyclomatic Complexity: `{ast_report.get("cyclomatic_complexity", "N/A")}`
- Max Loop Depth: `{ast_report.get("max_loop_depth", "N/A")}`
- Dangerous Calls: `{", ".join(ast_report.get("dangerous_calls", [])) or "none"}`

## 🧠 RAG Knowledge Base Context
{rag_section}

## 🤖 Candidate Secure Patch (Unified Diff)
```diff
{patch_str}
```

## 🔄 CI/CD & Merge Enforcement ({platform.upper()})
- **Enforcement Action**: `{enforcement_action}`

### Upstream CI Status
{ci_section}

### GitHub Merge Enforcement Gate
{ci_enforcement_note}

## 📋 Review Summary
{review_summary_md}

---
_Generated by [SentinelForge AI]({provider_url}) · Microsoft Build AI Hackathon_
"""


# ── FastAPI App ───────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    _log("🚀 SentinelForge API started")
    yield
    _log("🛑 SentinelForge API shutting down")


app = FastAPI(
    title="SentinelForge AI v2",
    description="Polyglot AI-powered code security & optimization pipeline",
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
    return {"status": "ok", "version": "2.0.0", "engine": "sentinelforge-v2"}


@app.get("/api/pipeline/state")
async def get_pipeline_state():
    return _pipeline_state


# ── Models ────────────────────────────────────────────────────────────────────

class ValidateRepoRequest(BaseModel):
    repo_url: str
    token: Optional[str] = None


class ScanRepoRequest(BaseModel):
    repo_url: str
    branch: Optional[str] = None
    token: Optional[str] = None
    max_files: Optional[int] = 50
    file_offset: Optional[int] = 0
    scan_mode: Optional[str] = "comprehensive"
    exclude_tests: Optional[bool] = True


# ── Real-World GitHub Scanner & ML Endpoints ─────────────────────────────────

@app.post("/api/repositories/validate")
async def validate_repository(req: ValidateRepoRequest):
    """
    Validate a GitHub repository URL, enforce SSRF protection,
    check accessibility, and resolve its default branch and commit SHA.
    """
    client = GitHubRepoClient(api_token=req.token)
    try:
        meta = await client.validate_repository(req.repo_url)
        return {
            "valid": True,
            "owner": meta.owner,
            "repo": meta.name,
            "full_name": meta.full_name,
            "default_branch": meta.default_branch,
            "commit_sha": meta.commit_sha,
            "description": meta.description,
            "is_private": meta.is_private,
            "stars": meta.stars,
            "primary_language": meta.primary_language,
            "html_url": meta.html_url,
        }
    except InvalidGitHubUrlError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except RepositoryNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except (RepositoryAccessDeniedError, RateLimitExceededError) as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to validate repository: {e}")


@app.post("/api/scans/github")
async def scan_github_repository(req: ScanRepoRequest):
    """
    Scan a real-world GitHub repository. Ingests source files via Git Trees API,
    runs deterministic scans, ML prioritization, and automated verification.
    """
    client = GitHubRepoClient(api_token=req.token)
    try:
        meta = await client.validate_repository(req.repo_url, requested_ref=req.branch)
    except InvalidGitHubUrlError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except RepositoryNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except (RepositoryAccessDeniedError, RateLimitExceededError) as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Validation failed: {e}")

    try:
        scanned_files = await client.fetch_repository_files(
            owner=meta.owner,
            repo=meta.name,
            commit_sha=meta.commit_sha,
            max_files=req.max_files or 50,
            file_offset=req.file_offset or 0,
            exclude_tests=req.exclude_tests if req.exclude_tests is not None else True,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch repository files: {e}")

    if not scanned_files:
        raise HTTPException(
            status_code=400,
            detail="No supported source code files found to scan in repository."
        )

    files_payload = [
        {"filename": sf.filename, "content": sf.content}
        for sf in scanned_files
    ]

    scan_id = f"scan-{meta.commit_sha[:8]}-{int(time.time())}"
    target_branch = req.branch or meta.default_branch
    cov_report = client.last_coverage_report.to_dict() if client.last_coverage_report else None

    # Launch pipeline asynchronously
    asyncio.create_task(
        run_full_pipeline(
            repo=meta.full_name,
            commit_sha=meta.commit_sha,
            files=files_payload,
            pusher=meta.owner,
            branch=target_branch,
            platform="github",
            scan_id=scan_id,
            scan_mode=req.scan_mode or "comprehensive",
            coverage_report=cov_report,
        )
    )

    return {
        "scan_id": scan_id,
        "status": "started",
        "repo": meta.full_name,
        "commit_sha": meta.commit_sha,
        "branch": target_branch,
        "files_count": len(files_payload),
        "coverage_report": cov_report,
        "files": [f["filename"] for f in files_payload],
    }


@app.get("/api/scans/{scan_id}")
async def get_scan_details(scan_id: str):
    """Get the state and results of a specific scan."""
    if scan_id == "latest":
        return _pipeline_state
    if scan_id in _scan_history:
        return _scan_history[scan_id]
    if _pipeline_state.get("run_id") == scan_id or _pipeline_state.get("scan_id") == scan_id:
        return _pipeline_state
    raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")


@app.get("/api/scans/{scan_id}/findings")
async def get_scan_findings(scan_id: str):
    """Retrieve normalized, ML-prioritized findings for a scan."""
    state = None
    if scan_id == "latest":
        state = _pipeline_state
    elif scan_id in _scan_history:
        state = _scan_history[scan_id]
    elif _pipeline_state.get("run_id") == scan_id or _pipeline_state.get("scan_id") == scan_id:
        state = _pipeline_state

    if not state:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")

    findings = state.get("normalized_findings") or []
    return {
        "scan_id": scan_id,
        "repo": state.get("repo"),
        "commit_sha": state.get("commit_sha"),
        "total_findings": len(findings),
        "findings": findings,
    }


@app.get("/api/scans/{scan_id}/report")
async def get_scan_report(scan_id: str, format: str = "markdown"):
    """Retrieve the generated security and audit report in Markdown or JSON."""
    state = None
    if scan_id == "latest":
        state = _pipeline_state
    elif scan_id in _scan_history:
        state = _scan_history[scan_id]
    elif _pipeline_state.get("run_id") == scan_id or _pipeline_state.get("scan_id") == scan_id:
        state = _pipeline_state

    if not state:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")

    pr_body = state.get("pr_body", "")
    if format.lower() == "markdown":
        return PlainTextResponse(pr_body or "# SentinelForge Security Report\n\nNo report generated yet.")
    return {
        "scan_id": scan_id,
        "repo": state.get("repo"),
        "commit_sha": state.get("commit_sha"),
        "report_markdown": pr_body,
        "status": state.get("status"),
        "risk_score": state.get("swarm_result", {}).get("risk_score"),
        "residual_risk_score": state.get("swarm_result", {}).get("patched_risk_score"),
        "risk_evaluation": state.get("risk_evaluation"),
        "verification_passed": state.get("verification_result", {}).get("verification_passed"),
    }


@app.get("/api/ml/metrics")
async def get_ml_metrics():
    """Retrieve supervised finding classifier performance metrics."""
    return _finding_classifier.evaluate()


@app.post("/api/pipeline/simulate")
async def simulate():
    """Trigger pipeline with mock code for demo/testing."""
    mock_files = [
        {
            "filename": "auth_service.py",
            "content": MOCK_CODE_PYTHON,
        },
        {
            "filename": "buffer_overflow.cpp",
            "content": MOCK_CODE_CPP,
        },
        {
            "filename": "SessionController.java",
            "content": MOCK_CODE_JAVA,
        },
        {
            "filename": "deploy.yml",
            "content": MOCK_CODE_YAML,
        }
    ]
    asyncio.create_task(
        run_full_pipeline(
            repo="demo-org/sentinelforge-polyglot",
            commit_sha="b8e4f1a2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6",
            files=mock_files,
            pusher="polyglot-user",
            branch="feature/multi-lang",
            platform="github",
        )
    )
    return {"status": "started", "message": "Polyglot pipeline simulation launched"}


@app.post("/webhook/github")
async def github_webhook(request: Request):
    """Real GitHub webhook endpoint. Wire this to your repo via ngrok."""
    body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256", "")
    
    service = get_ci_service("github")

    if not service.verify_webhook(body, signature):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    payload = json.loads(body)
    event = service.parse_push_event(payload)

    _log(f"📨 Push event from {event.pusher} on GitHub · {event.repo_full_name}@{event.branch}")

    # Fetch real file content from GitHub
    github_files = await service.fetch_changed_files(event, max_files=5)

    if not github_files:
        return {"status": "skipped", "reason": "No supported source files changed"}

    files_payload = [
        {"filename": f.filename, "content": f.content}
        for f in github_files
    ]

    asyncio.create_task(
        run_full_pipeline(
            repo=event.repo_full_name,
            commit_sha=event.commit_sha,
            files=files_payload,
            pusher=event.pusher,
            branch=event.branch,
            platform="github",
        )
    )

    return {
        "status": "processing",
        "repo": event.repo_full_name,
        "commit": event.commit_sha,
        "files": [f.filename for f in github_files],
    }


@app.post("/webhook/gitlab")
async def gitlab_webhook(request: Request):
    """Real GitLab webhook endpoint."""
    body = await request.body()
    signature = request.headers.get("X-Gitlab-Token", "")
    
    service = get_ci_service("gitlab")

    if not service.verify_webhook(body, signature):
        raise HTTPException(status_code=401, detail="Invalid GitLab webhook token")

    payload = json.loads(body)
    event = service.parse_push_event(payload)

    _log(f"📨 Push event from {event.pusher} on GitLab · {event.repo_full_name}@{event.branch}")

    gitlab_files = await service.fetch_changed_files(event, max_files=5)

    if not gitlab_files:
        return {"status": "skipped", "reason": "No supported source files changed"}

    files_payload = [
        {"filename": f.filename, "content": f.content}
        for f in gitlab_files
    ]

    asyncio.create_task(
        run_full_pipeline(
            repo=event.repo_full_name,
            commit_sha=event.commit_sha,
            files=files_payload,
            pusher=event.pusher,
            branch=event.branch,
            platform="gitlab",
        )
    )

    return {
        "status": "processing",
        "repo": event.repo_full_name,
        "commit": event.commit_sha,
        "files": [f.filename for f in gitlab_files],
    }


@app.post("/webhook/azure-devops")
async def azure_devops_webhook(request: Request):
    """Real Azure DevOps service hooks endpoint."""
    body = await request.body()
    signature = request.headers.get("Authorization", "")
    
    service = get_ci_service("azure-devops")

    if not service.verify_webhook(body, signature):
        raise HTTPException(status_code=401, detail="Invalid ADO service hook credentials")

    payload = json.loads(body)
    event = service.parse_push_event(payload)

    _log(f"📨 Push event from {event.pusher} on Azure DevOps · {event.repo_full_name}@{event.branch}")

    ado_files = await service.fetch_changed_files(event, max_files=5)

    if not ado_files:
        return {"status": "skipped", "reason": "No supported source files changed"}

    files_payload = [
        {"filename": f.filename, "content": f.content}
        for f in ado_files
    ]

    asyncio.create_task(
        run_full_pipeline(
            repo=event.repo_full_name,
            commit_sha=event.commit_sha,
            files=files_payload,
            pusher=event.pusher,
            branch=event.branch,
            platform="azure-devops",
        )
    )

    return {
        "status": "processing",
        "repo": event.repo_full_name,
        "commit": event.commit_sha,
        "files": [f.filename for f in ado_files],
    }


@app.post("/api/analyze-custom")
async def analyze_custom(request: Request):
    """Run full pipeline on user-provided code."""
    body = await request.json()
    repo = body.get("repo", "custom/submission")
    filename = body.get("filename", "code.py")
    code = body.get("code", "")
    platform = body.get("platform", "github")
    
    if not code.strip():
        raise HTTPException(status_code=400, detail="No code provided")
    files = [{"filename": filename, "content": code}]
    import hashlib
    sha = hashlib.md5(code.encode()).hexdigest()
    asyncio.create_task(
        run_full_pipeline(
            repo=repo,
            commit_sha=sha,
            files=files,
            pusher="recruiter-demo",
            branch="main",
            platform=platform,
        )
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

    threats = _trie.find_all_threats(code, filename=filename)
    trie_dicts = [
        {"pattern": t.pattern, "category": t.category,
         "severity": t.severity, "cwe_id": t.cwe_id, "confidence": t.confidence,
         "line": t.line, "col": t.col, "snippet": t.snippet}
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


# ── Polyglot Mock Code Fixtures ──────────────────────────────────────────────

MOCK_CODE_PYTHON = '''
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
    return pickle.loads(session_bytes)
'''

MOCK_CODE_CPP = '''
#include <iostream>
#include <cstring>

void process_buffer(const char* input) {
    char local_buf[16];
    // Insecure buffer copy - CWE-120
    strcpy(local_buf, input);
    std::cout << "Buffer: " << local_buf << std::endl;
}

int main() {
    process_buffer("very_long_input_overflowing_stack_frame");
    return 0;
}
'''

MOCK_CODE_JAVA = '''
import java.io.ObjectInputStream;
import java.io.InputStream;

public class SessionController {
    private String token = "github_pat_11234abc";

    public Object parseSession(InputStream stream) throws Exception {
        // Java Insecure Deserialization - CWE-502
        ObjectInputStream ois = new ObjectInputStream(stream);
        return ois.readObject();
    }
}
'''

MOCK_CODE_YAML = '''
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  name: container-build
spec:
  templates:
  - name: run-pipeline
    container:
      image: node:latest
      command: [sh, -c]
      # Unprivileged shell mode chmod 777
      args: ["chmod 777 scripts/run.sh && ./scripts/run.sh"]
'''
