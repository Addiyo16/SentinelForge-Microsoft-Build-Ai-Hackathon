"""
Unit tests for Python AST Security & Complexity Scanner.
Tests rule triggers, loop depth, cyclomatic complexity, evidence extraction, and syntax resilience.
"""

import pytest
from app.utils.ast_engine import analyze_code
from app.utils.scanners.python_scanner import PythonScanner


class TestASTEngine:
    def test_benign_code_no_security_findings(self):
        code = """
def add(a: int, b: int) -> int:
    return a + b
"""
        report = analyze_code(code)
        assert len(report.findings) == 0
        assert report.cyclomatic_complexity >= 1
        assert report.max_loop_depth == 0

    def test_nested_loop_depth_and_complexity(self):
        code = """
def two_sum(nums, target):
    for i in range(len(nums)):
        for j in range(i + 1, len(nums)):
            if nums[i] + nums[j] == target:
                return [i, j]
    return []
"""
        report = analyze_code(code)
        assert report.max_loop_depth == 2
        assert len(report.findings) == 1
        f = report.findings[0]
        assert f.rule_id == "AST-PERF-001"
        assert f.cwe_id == "CWE-400"
        assert f.line == 4
        assert "for j in range" in f.evidence

    def test_single_loop_does_not_trigger_perf_warning(self):
        code = """
def sum_all(nums):
    total = 0
    for x in nums:
        total += x
    return total
"""
        report = analyze_code(code)
        assert report.max_loop_depth == 1
        assert len(report.findings) == 0

    def test_eval_code_injection(self):
        code = """
def run_user_input(payload):
    result = eval(payload)
    return result
"""
        report = analyze_code(code)
        assert any(f.rule_id == "AST-SEC-001" for f in report.findings)
        finding = next(f for f in report.findings if f.rule_id == "AST-SEC-001")
        assert finding.cwe_id == "CWE-94"
        assert finding.severity == "critical"
        assert "eval(payload)" in finding.evidence

    def test_exec_code_injection(self):
        code = """
def execute(cmd):
    exec(cmd)
"""
        report = analyze_code(code)
        assert any(f.rule_id == "AST-SEC-002" for f in report.findings)

    def test_os_system_command_injection(self):
        code = """
import os
def ping(host):
    os.system("ping " + host)
"""
        report = analyze_code(code)
        assert any(f.rule_id == "AST-SEC-003" for f in report.findings)
        f = next(f for f in report.findings if f.rule_id == "AST-SEC-003")
        assert f.cwe_id == "CWE-78"

    def test_pickle_insecure_deserialization(self):
        code = """
import pickle
def load_state(b):
    return pickle.loads(b)
"""
        report = analyze_code(code)
        assert any(f.rule_id == "AST-SEC-005" for f in report.findings)
        f = next(f for f in report.findings if f.rule_id == "AST-SEC-005")
        assert f.cwe_id == "CWE-502"

    def test_bare_except_suppression(self):
        code = """
def risky_operation():
    try:
        do_work()
    except:
        pass
"""
        report = analyze_code(code)
        assert any(f.rule_id == "AST-ERR-001" for f in report.findings)
        f = next(f for f in report.findings if f.rule_id == "AST-ERR-001")
        assert f.cwe_id == "CWE-391"

    def test_syntax_error_handled_gracefully(self):
        broken_code = "def invalid_syntax(:"
        report = analyze_code(broken_code)
        assert len(report.findings) == 1
        assert report.findings[0].rule_id == "AST-SYNTAX-ERR"
