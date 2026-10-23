"""
Unit tests for SentinelForge Canonical Risk Scoring Engine (app.core.risk).
Validates baseline scoring, AST penalties, verified-only risk reduction,
scan coverage factoring, and merge gate decisions.
"""

import pytest
from app.core.risk import (
    RiskEvaluation,
    RiskLevel,
    MergeDecision,
    VerificationStatus,
    compute_risk_evaluation,
)


class TestRiskEngine:
    def test_clean_code_zero_risk(self):
        eval_result = compute_risk_evaluation(
            findings=[],
            ast_report={"dangerous_calls": [], "max_loop_depth": 0, "cyclomatic_complexity": 1},
        )
        assert eval_result.original_risk == 0
        assert eval_result.residual_risk == 0
        assert eval_result.risk_level == RiskLevel.LOW.value
        assert eval_result.verification_status == VerificationStatus.BASELINE_PASSED.value
        assert eval_result.merge_decision == MergeDecision.APPROVED.value
        assert "Clean baseline" in eval_result.decision_reasons[0]

    def test_critical_finding_calculation(self):
        findings = [{"severity": "critical", "category": "Code Execution"}]
        eval_result = compute_risk_evaluation(
            findings=findings,
            ast_report={"dangerous_calls": ["os.system"], "max_loop_depth": 1, "cyclomatic_complexity": 2},
        )
        # 35 (critical) + 25 (dangerous call) = 60
        assert eval_result.original_risk == 60
        assert eval_result.risk_level == RiskLevel.HIGH.value
        assert eval_result.findings_breakdown["critical"] == 1
        # Without verification, residual risk remains 60
        assert eval_result.residual_risk == 60
        assert eval_result.merge_decision == MergeDecision.CHANGES_REQUESTED.value

    def test_verified_only_risk_reduction_policy(self):
        findings = [{"severity": "critical", "category": "Deserialization"}]
        # 1. Unverified or failed verification
        failed_verification = {
            "verification_passed": False,
            "failure_summary": "pickle.loads pattern persists in patched file",
            "persisting_vulnerabilities": ["pickle.loads("],
            "mitigated_vulnerabilities": [],
        }
        res_failed = compute_risk_evaluation(
            findings=findings,
            verification_result=failed_verification,
        )
        assert res_failed.residual_risk == res_failed.original_risk
        assert res_failed.verification_status == VerificationStatus.FAILED.value
        assert any("Risk reduction withheld" in r for r in res_failed.decision_reasons)
        assert res_failed.merge_decision in (MergeDecision.CHANGES_REQUESTED.value, MergeDecision.BLOCKED.value)

        # 2. Passed verification with full mitigation
        passed_verification = {
            "verification_passed": True,
            "failure_summary": "",
            "persisting_vulnerabilities": [],
            "mitigated_vulnerabilities": ["pickle.loads("],
        }
        res_passed = compute_risk_evaluation(
            findings=findings,
            verification_result=passed_verification,
        )
        assert res_passed.verification_status == VerificationStatus.PASSED.value
        assert res_passed.residual_risk < res_passed.original_risk
        assert res_passed.residual_risk <= 10
        assert res_passed.merge_decision == MergeDecision.APPROVED.value
        assert any("Verified mitigation credited" in r for r in res_passed.decision_reasons)

    def test_partial_scan_coverage_reporting(self):
        coverage = {
            "eligible_files_count": 100,
            "successfully_scanned_count": 25,
            "is_partial_scan": True,
            "is_truncated": False,
        }
        eval_result = compute_risk_evaluation(
            findings=[{"severity": "medium"}],
            coverage_report=coverage,
        )
        assert eval_result.is_partial_scan is True
        assert eval_result.scan_completeness == 0.25
        assert eval_result.coverage_percentage == 25.0
        assert any("Partial scan" in r for r in eval_result.decision_reasons)

    def test_ci_failure_blocks_merge(self):
        ci = {
            "check_runs": [
                {"name": "build-and-test", "conclusion": "failure"},
            ]
        }
        eval_result = compute_risk_evaluation(
            findings=[],
            ci_status=ci,
        )
        assert eval_result.merge_decision == MergeDecision.BLOCKED.value
        assert any("CI check failure" in r for r in eval_result.decision_reasons)

    def test_risk_evaluation_patch_not_generated_preserves_full_risk(self):
        findings = [{"severity": "critical", "category": "Code Execution"}]
        eval_result = compute_risk_evaluation(
            findings=findings,
            verification_result={"status": "PATCH NOT GENERATED — FINDINGS REMAIN UNRESOLVED", "verification_passed": False},
        )
        assert eval_result.verification_status == VerificationStatus.PATCH_NOT_GENERATED.value
        assert eval_result.residual_risk == eval_result.original_risk
        assert eval_result.merge_decision != MergeDecision.APPROVED.value
        assert any("Patch not generated" in r for r in eval_result.decision_reasons)

    def test_risk_evaluation_zero_mitigated_preserves_full_risk(self):
        findings = [{"severity": "high", "category": "SQLi"}]
        eval_result = compute_risk_evaluation(
            findings=findings,
            verification_result={
                "status": "NOT VERIFIED",
                "verification_passed": False,
                "mitigated_vulnerabilities": [],
                "persisting_vulnerabilities": ["DROP TABLE"],
                "failure_summary": "Rescan indicates 0 target vulnerability patterns were mitigated",
            },
        )
        assert eval_result.verification_status == VerificationStatus.NOT_VERIFIED.value
        assert eval_result.residual_risk == eval_result.original_risk
        assert any("Risk reduction withheld" in r for r in eval_result.decision_reasons)

    def test_exact_coverage_percentages_and_discovery_ratio(self):
        coverage = {
            "eligible_files_count": 598,
            "successfully_scanned_count": 15,
            "discovered_files_count": 1467,
            "is_partial_scan": True,
            "is_truncated": False,
        }
        eval_result = compute_risk_evaluation(
            findings=[],
            coverage_report=coverage,
        )
        # 15 / 598 = 2.50836...% -> 2.51%
        assert eval_result.coverage_percentage == 2.51
        # 15 / 1467 = 1.02249...% -> 1.02%
        assert eval_result.discovery_coverage_percentage == 1.02
        assert eval_result.is_partial_scan is True
        assert eval_result.scan_completeness == 0.0251

    def test_partial_scan_with_zero_findings_warns_and_requests_changes(self):
        coverage = {
            "eligible_files_count": 598,
            "successfully_scanned_count": 15,
            "discovered_files_count": 1467,
            "is_partial_scan": True,
            "is_truncated": False,
        }
        eval_result = compute_risk_evaluation(
            findings=[],
            coverage_report=coverage,
        )
        assert eval_result.original_risk == 0
        assert eval_result.residual_risk == 0
        assert eval_result.merge_decision == MergeDecision.CHANGES_REQUESTED.value
        assert any(
            "WARNING: Incomplete scan (583 eligible files unanalyzed) does not prove overall repository security" in r
            for r in eval_result.decision_reasons
        )
        assert any("2.51% coverage" in r for r in eval_result.decision_reasons)
    def test_reconciled_risk_level_matches_residual_score_not_contradictory(self):
        """
        Validates Issue 2: Reconciled Risk Assessment.
        When initial risk is critical (e.g. >= 70, CRITICAL) and verified patch reduces risk
        to 5/100, the residual risk level MUST be 'LOW' (not CRITICAL).
        The canonical assessment label must not contradict the numerical score.
        """
        findings = [
            {"severity": "critical", "category": "RCE"},
            {"severity": "critical", "category": "Deserialization"},
            {"severity": "high", "category": "Auth Bypass"},
        ]
        verification_passed = {
            "status": "PATCH VERIFICATION PASSED",
            "verification_passed": True,
            "mitigated_vulnerabilities": ["pickle.loads(", "eval("],
            "persisting_vulnerabilities": [],
        }
        eval_result = compute_risk_evaluation(
            findings=findings,
            verification_result=verification_passed,
        )
        assert eval_result.original_risk >= 70
        assert eval_result.original_risk_level == RiskLevel.CRITICAL.value
        assert eval_result.residual_risk == 5
        assert eval_result.residual_risk_level == RiskLevel.LOW.value
        assert eval_result.risk_level == RiskLevel.LOW.value  # Active assessment label matches residual score!
        assert eval_result.risk_level != RiskLevel.CRITICAL.value

