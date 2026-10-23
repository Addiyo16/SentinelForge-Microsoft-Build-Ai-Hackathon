"""
Unit and integration tests for SentinelForge FastAPI API endpoints.
Tests health, state, repository validation, GitHub scan initiation, findings, and ML metrics.
"""

import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient

from app.main import app, _pipeline_state, _scan_history
from app.integrations.github.client import RepositoryMetadata, ScannedFile


@pytest.fixture
def client():
    return TestClient(app)


def test_health_endpoint(client):
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["version"] == "2.0.0"


def test_get_pipeline_state(client):
    res = client.get("/api/pipeline/state")
    assert res.status_code == 200
    data = res.json()
    assert "status" in data
    assert "logs" in data


def test_validate_repository_ssrf_rejection(client):
    res = client.post(
        "/api/repositories/validate",
        json={"repo_url": "https://evil.internal.corp/secret"},
    )
    assert res.status_code == 400
    assert "not a valid GitHub domain" in res.json()["detail"]


def test_validate_repository_empty_url(client):
    res = client.post("/api/repositories/validate", json={"repo_url": ""})
    assert res.status_code == 400


@patch("app.main.GitHubRepoClient.validate_repository")
def test_validate_repository_success(mock_validate, client):
    mock_validate.return_value = RepositoryMetadata(
        owner="test-owner",
        name="test-repo",
        full_name="test-owner/test-repo",
        default_branch="main",
        commit_sha="abcd1234efgh5678",
        description="A secure repository",
        is_private=False,
        stars=150,
        primary_language="Python",
        html_url="https://github.com/test-owner/test-repo",
    )

    res = client.post(
        "/api/repositories/validate",
        json={"repo_url": "https://github.com/test-owner/test-repo"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["valid"] is True
    assert data["full_name"] == "test-owner/test-repo"
    assert data["commit_sha"] == "abcd1234efgh5678"
    assert data["stars"] == 150


@patch("app.main.GitHubRepoClient.validate_repository")
@patch("app.main.GitHubRepoClient.fetch_repository_files")
@patch("app.main.run_full_pipeline")
def test_scan_github_repository_dispatch(mock_pipeline, mock_fetch, mock_validate, client):
    mock_validate.return_value = RepositoryMetadata(
        owner="pallets",
        name="flask",
        full_name="pallets/flask",
        default_branch="main",
        commit_sha="1234567890abcdef",
        html_url="https://github.com/pallets/flask",
    )
    mock_fetch.return_value = [
        ScannedFile(
            filename="app.py",
            content="import os\nprint('hello')",
            size_bytes=25,
            language="python",
        )
    ]
    mock_pipeline.return_value = None

    res = client.post(
        "/api/scans/github",
        json={"repo_url": "https://github.com/pallets/flask", "max_files": 5},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "started"
    assert data["repo"] == "pallets/flask"
    assert data["commit_sha"] == "1234567890abcdef"
    assert data["files_count"] == 1
    assert "app.py" in data["files"]


def test_get_scan_unknown(client):
    res = client.get("/api/scans/non-existent-scan-id")
    assert res.status_code == 404


def test_get_scan_latest(client):
    res = client.get("/api/scans/latest")
    assert res.status_code == 200
    assert "status" in res.json()


def test_get_scan_findings_latest(client):
    res = client.get("/api/scans/latest/findings")
    assert res.status_code == 200
    data = res.json()
    assert "findings" in data
    assert "total_findings" in data


def test_get_scan_report_markdown(client):
    res = client.get("/api/scans/latest/report?format=markdown")
    assert res.status_code == 200
    assert "text/plain" in res.headers["content-type"]


def test_get_scan_report_json(client):
    res = client.get("/api/scans/latest/report?format=json")
    assert res.status_code == 200
    data = res.json()
    assert "report_markdown" in data


def test_get_ml_metrics(client):
    res = client.get("/api/ml/metrics")
    assert res.status_code == 200
    data = res.json()
    assert "precision" in data
    assert "recall" in data
    assert "f1_score" in data
    assert "confusion_matrix" in data
    assert data["f1_score"] >= 0.50


def test_build_pr_body_comprehensive_audit_and_ml_sections():
    from app.main import _build_pr_body
    from app.agents.swarm import SwarmResult

    swarm_res = SwarmResult(
        dialogue=[],
        final_patch="--- a/code.py\n+++ b/code.py\n@@ -1,1 +1,1 @@\n-eval(x)\n+int(x)",
        pr_description="Remediated eval call",
        risk_score=75,
        patched_risk_score=15,
        approved=True,
    )

    verification_data = {
        "status": "VERIFIED",
        "verification_passed": True,
        "execution_duration": 0.42,
        "mitigated_vulnerabilities": ["eval("],
        "persisting_vulnerabilities": [],
        "command_audit_trail": [
            {
                "step": "Patch Application",
                "command": "git_apply_patch (unified_diff)",
                "status": "PASSED",
                "exit_code": 0,
                "duration_ms": 1.2,
                "output": "Clean hunk application",
            },
            {
                "step": "AST Syntax Validation",
                "command": "syntax_check_py",
                "status": "PASSED",
                "exit_code": 0,
                "duration_ms": 2.5,
                "output": "AST parsed cleanly",
            },
        ],
    }

    cov_report = {
        "discovered_files_count": 50,
        "eligible_files_count": 20,
        "successfully_scanned_count": 15,
        "skipped_count": 35,
        "exclude_tests": True,
        "skip_reasons_summary": {
            "unsupported_extension": 25,
            "excluded_directory": 8,
            "quota_limit_exceeded": 2,
        },
    }

    body = _build_pr_body(
        repo="testowner/testrepo",
        sha="abcdef1234567890",
        files=[{"filename": "code.py", "content": "eval(x)"}],
        threats=[{"pattern": "eval(", "category": "Code Injection", "severity": "critical", "cwe_id": "CWE-94", "source_file": "code.py", "line": 1, "ml_score": 90, "ml_priority_tier": "CRITICAL_RISK"}],
        ast_report={"cyclomatic_complexity": 2, "max_loop_depth": 0, "dangerous_calls": ["eval"]},
        rag_context=[],
        swarm_result=swarm_res,
        ci={"summary": "1 check passed", "check_runs": [{"name": "build", "conclusion": "success"}]},
        platform="github",
        verification=verification_data,
        coverage_report=cov_report,
    )

    # 1. Coverage audit table
    assert "Repository Scan Coverage & Discovery Audit" in body
    assert "Discovered Total Files" in body
    assert "`50`" in body
    assert "unsupported_extension" in body

    # 2. ML benchmark and metrics
    assert "Supervised AI/ML Finding Prioritization Model" in body
    assert "Confusion Matrix" in body

    # 3. Independent verification and subprocess command trail
    assert "Independent Patch Verification (✅ PATCH VERIFICATION PASSED)" in body
    assert "Subprocess Command Execution Audit Trail" in body
    assert "git_apply_patch (unified_diff)" in body

    # 4. Unified diff
    assert "Candidate Secure Patch (Unified Diff)" in body
    assert "```diff" in body
    assert "--- a/code.py" in body

    # 5. Risk reduction credited
    assert "Risk reduced from 75/100 to 15/100" in body
    assert "CHANGES REQUESTED (PARTIAL SCAN)" in body


@pytest.mark.asyncio
async def test_end_to_end_pipeline_vulnerable_fixture():
    from app.main import run_full_pipeline, _pipeline_state

    vuln_code = (
        "import pickle\n"
        "\n"
        "def process_payload(raw_bytes):\n"
        "    data = pickle.loads(raw_bytes)\n"
        "    return data\n"
    )

    await run_full_pipeline(
        repo="testowner/vuln-fixture",
        branch="main",
        commit_sha="a1b2c3d4e5f67890",
        files=[{"filename": "vuln.py", "content": vuln_code}],
        platform="github",
        coverage_report={
            "discovered_files_count": 1,
            "eligible_files_count": 1,
            "successfully_scanned_count": 1,
            "skipped_count": 0,
            "is_partial_scan": False,
        },
    )

    assert _pipeline_state["status"] == "complete"
    risk_eval = _pipeline_state["risk_evaluation"]
    orig_risk = risk_eval["original_risk"]
    res_risk = risk_eval["residual_risk"]
    assert orig_risk > 0
    # Patch verification succeeded
    assert _pipeline_state["verification_result"]["verification_passed"] is True
    # Risk reduction was verified and credited
    assert res_risk < orig_risk
    assert risk_eval["merge_decision"] == "APPROVED"

    pr_body = _pipeline_state["pr_body"]
    # Check findings table format
    assert "| File & Line | Finding / Rule ID | Category | Severity | CWE | Detection Source | ML Priority Tier |" in pr_body
    assert "vuln.py:4" in pr_body
    assert "CWE-502" in pr_body
    assert "CRITICAL" in pr_body
    # Check no contradiction in review summary vs canonical assessment
    assert f"Original Risk Score:** `{orig_risk}/100`" in pr_body
    assert f"Residual Risk Score:** `{res_risk}/100`" in pr_body
    assert "Canonical Decision:** `APPROVED`" in pr_body


@pytest.mark.asyncio
async def test_end_to_end_pipeline_clean_fixture():
    from app.main import run_full_pipeline, _pipeline_state

    clean_code = (
        "import json\n"
        "\n"
        "def process_payload(raw_text):\n"
        "    data = json.loads(raw_text)\n"
        "    return data\n"
    )

    await run_full_pipeline(
        repo="testowner/clean-fixture",
        branch="main",
        commit_sha="fedcba9876543210",
        files=[{"filename": "clean.py", "content": clean_code}],
        platform="github",
        coverage_report={
            "discovered_files_count": 1,
            "eligible_files_count": 1,
            "successfully_scanned_count": 1,
            "skipped_count": 0,
            "is_partial_scan": False,
        },
    )

    assert _pipeline_state["status"] == "complete"
    risk_eval = _pipeline_state["risk_evaluation"]
    assert risk_eval["original_risk"] == 0
    assert risk_eval["residual_risk"] == 0
    assert risk_eval["merge_decision"] == "APPROVED"
    assert _pipeline_state["swarm_result"]["final_patch"] == ""

    pr_body = _pipeline_state["pr_body"]
    assert "No security threats detected" in pr_body
    assert "Canonical Risk Assessment: 0/100 (LOW)" in pr_body
    assert "Clean Source State" in pr_body
    assert "Zero security vulnerabilities" in pr_body
    assert "Canonical Decision:** `APPROVED`" in pr_body
@pytest.mark.asyncio
async def test_ci_approval_claim_evidence_differentiation():
    """
    Validates Issue 4: CI approval claim evidence.
    When 30 upstream check runs succeed, the report must distinguish native upstream
    test suite health from SentinelForge's required check enforcement under GitHub branch protection.
    """
    from app.main import _build_pr_body
    from app.agents.swarm import SwarmResult
    from app.core.risk import compute_risk_evaluation

    ci_data = {
        "check_runs": [
            {"name": f"test-matrix-py3{i}", "conclusion": "success", "status": "completed"}
            for i in range(30)
        ],
        "summary": "30 checks passed",
    }
    risk_eval = compute_risk_evaluation(
        findings=[],
        ast_report={"dangerous_calls": [], "max_loop_depth": 0, "findings": []},
        ci_status=ci_data,
    )
    pr_body = _build_pr_body(
        repo="psf/requests",
        sha="611c6162cbc4ac2020a2f91c7cfa4f3abf9bbb60",
        files=[{"filename": "src/requests/api.py", "content": "def get(): pass"}],
        threats=[],
        ast_report={"dangerous_calls": [], "max_loop_depth": 0, "findings": []},
        rag_context=[],
        swarm_result=SwarmResult([], "", "", 0, 0, True),
        ci=ci_data,
        verification={"status": "BASELINE CHECK PASSED — NO PATCH REQUIRED", "verification_passed": True, "is_clean_baseline": True},
        risk_eval=risk_eval,
    )

    assert "30/30 passed" in pr_body or "30 of 30 native upstream GitHub check run(s) succeeded" in pr_body
    assert "Advisory In-PR Gate (Not Enforced by GitHub Branch Protection)" in pr_body
    assert "sentinelforge/security-gate" in pr_body
    assert "Settings -> Branches -> Branch Protection Rules" in pr_body

