"""
SentinelForge — Canonical Deterministic Risk Scoring & Verification Policy Engine.
Governs original risk calculation, scan completeness adjustment, verified mitigation credit,
and automated merge gate decisions across API, Swarm, and PR reports.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class MergeDecision(str, Enum):
    APPROVED = "APPROVED"
    CHANGES_REQUESTED = "CHANGES_REQUESTED"
    BLOCKED = "BLOCKED"


class VerificationStatus(str, Enum):
    PASSED = "PATCH VERIFICATION PASSED"
    FAILED = "NOT VERIFIED"
    BASELINE_PASSED = "BASELINE CHECK PASSED — NO PATCH REQUIRED"
    PATCH_NOT_GENERATED = "PATCH NOT GENERATED — FINDINGS REMAIN UNRESOLVED"
    NOT_VERIFIED = "NOT VERIFIED"


SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 35,
    "high": 20,
    "medium": 10,
    "low": 5,
    "informational": 0,
}

APPROVED_RISK_THRESHOLD: int = 30
BLOCKED_RISK_THRESHOLD: int = 70


def get_risk_level_label(score: int) -> str:
    """Return canonical RiskLevel string based on numerical score."""
    if score >= BLOCKED_RISK_THRESHOLD:
        return RiskLevel.CRITICAL.value
    elif score >= 50:
        return RiskLevel.HIGH.value
    elif score >= 25:
        return RiskLevel.MEDIUM.value
    else:
        return RiskLevel.LOW.value


@dataclass
class RiskEvaluation:
    original_risk: int
    residual_risk: int
    risk_level: str
    scan_completeness: float
    verification_status: str
    merge_decision: str
    decision_reasons: list[str] = field(default_factory=list)
    findings_breakdown: dict[str, int] = field(default_factory=dict)
    mitigated_count: int = 0
    persisting_count: int = 0
    is_partial_scan: bool = False
    coverage_percentage: float = 100.0
    discovery_coverage_percentage: float = 100.0
    original_risk_level: str = "NONE"
    residual_risk_level: str = "NONE"

    def to_dict(self) -> dict[str, Any]:
        return {
            "original_risk": self.original_risk,
            "residual_risk": self.residual_risk,
            "risk_level": self.risk_level,
            "original_risk_level": self.original_risk_level,
            "residual_risk_level": self.residual_risk_level,
            "scan_completeness": self.scan_completeness,
            "verification_status": self.verification_status,
            "merge_decision": self.merge_decision,
            "decision_reasons": self.decision_reasons,
            "findings_breakdown": self.findings_breakdown,
            "mitigated_count": self.mitigated_count,
            "persisting_count": self.persisting_count,
            "is_partial_scan": self.is_partial_scan,
            "coverage_percentage": self.coverage_percentage,
            "discovery_coverage_percentage": self.discovery_coverage_percentage,
        }


def compute_risk_evaluation(
    findings: Optional[list[dict]] = None,
    ast_report: Optional[dict] = None,
    verification_result: Optional[dict] = None,
    coverage_report: Optional[dict] = None,
    ci_status: Optional[dict] = None,
) -> RiskEvaluation:
    """
    Deterministically calculate original risk, residual risk, and gate decisions.

    Guarantees:
    1. Zero unexplained risk reduction: residual_risk drops ONLY when verification_passed is True.
    2. Transparent coverage factoring: partial scan warnings appended to decision reasons.
    3. Proportionate scoring: non-critical findings cannot artificially trigger 100/100 risk.
    """
    findings = findings or []
    ast_report = ast_report or {}
    ci_status = ci_status or {}

    # 1. Tally findings severity breakdown directly from reconciled findings
    breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    raw_points = 0
    for f in findings:
        sev = str(f.get("severity", "medium")).lower()
        if sev not in breakdown:
            sev = "medium"
        breakdown[sev] += 1
        raw_points += SEVERITY_WEIGHTS.get(sev, 10)

    # 2. Standalone AST additions only if not already represented in findings
    ast_points = 0
    dangerous_calls = ast_report.get("dangerous_calls", [])
    has_dangerous_finding = any(
        "dangerous" in str(f.get("category", "")).lower() or
        any(dc in str(f.get("pattern", "") or f.get("evidence", "")) for dc in dangerous_calls)
        for f in findings
    )
    if dangerous_calls and not has_dangerous_finding:
        ast_points += 25
    if ast_report.get("max_loop_depth", 0) >= 2 and not any("complexity" in str(f.get("category", "")).lower() for f in findings):
        ast_points += 15

    total_flaws = len(findings) + (1 if ast_points > 0 else 0)
    if total_flaws == 0:
        base_risk = 0
    else:
        # Cap risk at 45 if no critical or high severity vulnerabilities are present
        calculated = raw_points + ast_points
        if breakdown["critical"] == 0 and breakdown["high"] == 0:
            base_risk = min(45, max(5, calculated))
        else:
            base_risk = min(100, max(15, calculated))

    original_risk = base_risk

    # 3. Scan Coverage & Completeness
    is_partial_scan = False
    coverage_percentage = 100.0
    discovery_coverage_percentage = 100.0
    scan_completeness = 1.0

    if coverage_report:
        eligible = coverage_report.get("eligible_files_count", 0)
        scanned = coverage_report.get("successfully_scanned_count", 0)
        discovered = coverage_report.get("discovered_files_count", 0)
        is_partial_scan = bool(
            coverage_report.get("is_partial_scan", False)
            or (eligible > 0 and scanned < eligible)
            or coverage_report.get("is_truncated", False)
        )
        if eligible > 0:
            scan_completeness = round(min(1.0, max(0.0, scanned / eligible)), 4)
            coverage_percentage = round((scanned / eligible) * 100.0, 2)
        if discovered > 0:
            discovery_coverage_percentage = round((scanned / discovered) * 100.0, 2)

    # 4. Independent Verification & Residual Risk
    decision_reasons: list[str] = []
    v_status = VerificationStatus.NOT_VERIFIED.value
    v_passed = False
    mitigated_count = 0
    persisting_count = 0

    if verification_result:
        v_passed = bool(verification_result.get("verification_passed", False))
        mitigated_list = verification_result.get("mitigated_vulnerabilities", [])
        persisting_list = verification_result.get("persisting_vulnerabilities", [])
        mitigated_count = len(mitigated_list)
        persisting_count = len(persisting_list)
        raw_status = verification_result.get("status") or ""

        if verification_result.get("is_clean_baseline") or raw_status == VerificationStatus.BASELINE_PASSED.value:
            v_status = VerificationStatus.BASELINE_PASSED.value
        elif raw_status == VerificationStatus.PATCH_NOT_GENERATED.value or "PATCH NOT GENERATED" in raw_status:
            v_status = VerificationStatus.PATCH_NOT_GENERATED.value
        elif v_passed and persisting_count == 0:
            v_status = VerificationStatus.PASSED.value
        else:
            v_status = VerificationStatus.NOT_VERIFIED.value
    elif original_risk == 0:
        v_status = VerificationStatus.BASELINE_PASSED.value
    else:
        v_status = VerificationStatus.PATCH_NOT_GENERATED.value

    if original_risk == 0:
        # Code was clean initially
        residual_risk = 0
        v_status = VerificationStatus.BASELINE_PASSED.value
        if is_partial_scan:
            decision_reasons.append(
                f"No security vulnerabilities detected in the {scanned} scanned files ({coverage_percentage:.2f}% eligible coverage). "
                f"WARNING: Incomplete scan ({eligible - scanned} eligible files unanalyzed) does not prove overall repository security."
            )
        else:
            decision_reasons.append("Clean baseline: Zero security vulnerabilities detected across complete scan. No patch required.")
    elif v_passed and v_status == VerificationStatus.PASSED.value and persisting_count == 0:
        # Full remediation verified
        residual_risk = 5 if original_risk > 15 else 0
        decision_reasons.append(
            f"Verified mitigation credited: Risk reduced from {original_risk}/100 to {residual_risk}/100 "
            f"after independent validation verified elimination of all target threat patterns."
        )
    else:
        # Verification failed, incomplete patch, not run, or patch not generated: ZERO risk reduction permitted
        residual_risk = original_risk
        if v_status == VerificationStatus.PATCH_NOT_GENERATED.value:
            decision_reasons.append(
                f"Patch not generated: Findings remain unresolved. Residual risk remains {original_risk}/100."
            )
        elif verification_result:
            if persisting_count > 0:
                persisting_str = ", ".join(persisting_list)
                decision_reasons.append(
                    f"Risk reduction withheld: Proposed patch is INCOMPLETE. Residual risk remains {original_risk}/100 "
                    f"because {persisting_count} target threat(s) persist ({persisting_str}). "
                    "A Python syntax check passing does not establish that a security vulnerability has been fixed."
                )
            else:
                failure_diag = verification_result.get("failure_summary") or "Vulnerability patterns persisted or checks failed."
                decision_reasons.append(
                    f"Risk reduction withheld: Proposed patch failed independent verification ({failure_diag}). "
                    f"Residual risk remains {original_risk}/100."
                )
        else:
            decision_reasons.append(
                f"Independent verification not executed. Residual risk remains {original_risk}/100."
            )

    # 5. CI Pipeline Status Check
    ci_failed = False
    if ci_status:
        check_runs = ci_status.get("check_runs", [])
        for cr in check_runs:
            conclusion = (cr.get("conclusion") or "").lower()
            if conclusion in ("failure", "timed_out", "action_required", "cancelled"):
                ci_failed = True
                decision_reasons.append(f"CI check failure: {cr.get('name', 'Job')} concluded with '{conclusion}'.")

    # 6. Automated Merge Decision Gate
    if ci_failed:
        merge_decision = MergeDecision.BLOCKED.value
        decision_reasons.append("PR Merge Gate: BLOCKED due to upstream CI check failure.")
    elif is_partial_scan:
        # A partial scan MUST NOT be treated as a complete security review and cannot approve merge
        merge_decision = MergeDecision.CHANGES_REQUESTED.value
        decision_reasons.append(
            f"PR Merge Gate: CHANGES_REQUESTED due to partial repository scan ({coverage_percentage:.2f}% coverage; "
            f"{scanned}/{eligible} eligible files scanned). Complete scan required before merge approval."
        )
    elif original_risk > 0 and not v_passed:
        if original_risk >= BLOCKED_RISK_THRESHOLD:
            merge_decision = MergeDecision.BLOCKED.value
            decision_reasons.append(
                f"PR Merge Gate: BLOCKED due to high/critical unverified security risk ({original_risk}/100)."
            )
        else:
            merge_decision = MergeDecision.CHANGES_REQUESTED.value
            decision_reasons.append(
                "PR Merge Gate: CHANGES_REQUESTED until candidate patch is verified."
            )
    elif v_passed and residual_risk <= APPROVED_RISK_THRESHOLD:
        merge_decision = MergeDecision.APPROVED.value
        decision_reasons.append(
            f"PR Merge Gate: APPROVED. Residual risk ({residual_risk}/100) satisfies security threshold (<= {APPROVED_RISK_THRESHOLD})."
        )
    elif v_passed and residual_risk > APPROVED_RISK_THRESHOLD:
        merge_decision = MergeDecision.CHANGES_REQUESTED.value
        decision_reasons.append(
            f"PR Merge Gate: CHANGES_REQUESTED. Residual risk ({residual_risk}/100) exceeds threshold (<= {APPROVED_RISK_THRESHOLD})."
        )
    elif original_risk == 0:
        merge_decision = MergeDecision.APPROVED.value
        decision_reasons.append("PR Merge Gate: APPROVED (Clean repository analysis).")
    else:
        merge_decision = MergeDecision.CHANGES_REQUESTED.value

    # 7. Coverage Transparency Note
    if is_partial_scan:
        decision_reasons.append(
            f"Coverage note: Partial scan ({coverage_percentage:.2f}% of eligible files scanned). "
            f"Residual risk reflects inspected files only."
        )

    # Determine original and residual risk levels
    original_risk_level = get_risk_level_label(original_risk)
    residual_risk_level = get_risk_level_label(residual_risk)
    # The active risk level reflects the post-verification state so that residual risk is not labeled with unmitigated severity
    risk_level = residual_risk_level

    return RiskEvaluation(
        original_risk=original_risk,
        residual_risk=residual_risk,
        risk_level=risk_level,
        original_risk_level=original_risk_level,
        residual_risk_level=residual_risk_level,
        scan_completeness=scan_completeness,
        verification_status=v_status,
        merge_decision=merge_decision,
        decision_reasons=decision_reasons,
        findings_breakdown=breakdown,
        mitigated_count=mitigated_count,
        persisting_count=persisting_count,
        is_partial_scan=is_partial_scan,
        coverage_percentage=coverage_percentage,
        discovery_coverage_percentage=discovery_coverage_percentage,
    )
