"""
Focused regression tests for false-positive reduction and precision improvement (Section 3).
Covers:
  1. PSF Requests help.py:71 platform.system() (OS command injection false positive).
  2. Genuine OS command injection detection retention (True positive).
  3. PSF Requests models.py ordinary flattening loops vs AST-PERF-001 (CWE-400 false positive).
  4. Genuine quadratic O(N^2) Cartesian iteration detection retention (True positive).
  5. PSF Requests non-secret password references vs SF-SEC-002 (CWE-798 false positive).
  6. Genuine hardcoded secret detection retention (True positive).
"""

import pytest
from app.structures.trie import ThreatTrie, is_contextual_false_positive
from app.utils.ast_engine import analyze_code
from app.utils.scanners.python_scanner import PythonScanner


class TestFalsePositiveRegressions:
    @pytest.fixture
    def trie(self):
        return ThreatTrie()

    @pytest.fixture
    def scanner(self):
        return PythonScanner()

    # ── 1. requests/help.py:71 (platform.system()) ────────────────────────────
    def test_requests_help_platform_system_not_flagged(self, trie):
        """
        Verify that `src/requests/help.py:71` calling `platform.system()`
        to query OS information is recognized as benign and not flagged as OS command injection.
        """
        code = '''
def info():
    try:
        platform_info = {
            "system": platform.system(),
            "release": platform.release(),
        }
    except OSError:
        platform_info = {"system": "Unknown", "release": "Unknown"}
    return platform_info
'''
        # find_all_matches records the contextual FP analysis
        matches = trie.find_all_matches(code, filename="src/requests/help.py")
        sys_match = next((m for m in matches if m.pattern == "system("), None)
        assert sys_match is not None
        assert sys_match.is_false_positive is True
        assert "platform.system" in sys_match.false_positive_reason.lower()

        # find_all_threats filters out false positives
        actionable = trie.find_all_threats(code, filename="src/requests/help.py", filter_false_positives=True)
        assert len(actionable) == 0

    def test_genuine_os_command_injection_retained(self, trie, scanner):
        """
        Verify that real OS command injection vectors (e.g. `os.system("ping " + host)`)
        remain reliably flagged as critical CWE-78 findings.
        """
        code = '''
import os
def ping_service(host: str):
    return os.system("ping -c 1 " + host)
'''
        # ThreatTrie detection
        threats = trie.find_all_threats(code, filename="src/services/network.py", filter_false_positives=True)
        assert len(threats) >= 1
        assert any(t.pattern == "os.system(" and t.cwe_id == "CWE-78" for t in threats)

        # AST Scanner detection
        report = scanner.scan(code, filename="src/services/network.py")
        assert any(f.rule_id == "AST-SEC-003" and f.cwe_id == "CWE-78" for f in report.findings)

    # ── 2. requests/models.py loops vs AST-PERF-001 (CWE-400) ────────────────
    def test_requests_models_hierarchical_flattening_not_flagged(self, scanner):
        """
        Verify that ordinary sub-element / flatMap flattening loops in `src/requests/models.py`
        (lines 170 and 206) are recognized as linear O(N) traversals, NOT O(N^2) CWE-400 vulnerabilities.
        """
        code = '''
def _encode_params(data):
    result = []
    for k, vs in to_key_val_list(data):
        if isinstance(vs, str) or not hasattr(vs, "__iter__"):
            vs = [vs]
        for v in vs:
            if v is not None:
                result.append((k, v))
    return result

def _encode_files(files, data):
    new_fields = []
    fields = to_key_val_list(data or {})
    for field, val in fields:
        if isinstance(val, str) or not hasattr(val, "__iter__"):
            val = [val]
        for v in val:
            if v is not None:
                new_fields.append((field, v))
    return new_fields
'''
        report = scanner.scan(code, filename="src/requests/models.py")
        # Sub-element flattening must NOT emit AST-PERF-001
        perf_findings = [f for f in report.findings if f.rule_id == "AST-PERF-001"]
        assert len(perf_findings) == 0

    def test_genuine_quadratic_cartesian_iteration_retained(self, scanner):
        """
        Verify that genuine quadratic O(N^2) Cartesian product and pairwise comparisons
        continue to trigger AST-PERF-001 (CWE-400).
        """
        code = '''
def find_duplicates(items: list[int]) -> bool:
    for i in range(len(items)):
        for j in range(i + 1, len(items)):
            if items[i] == items[j]:
                return True
    return False
'''
        report = scanner.scan(code, filename="src/algorithms/search.py")
        perf_findings = [f for f in report.findings if f.rule_id == "AST-PERF-001"]
        assert len(perf_findings) == 1
        assert perf_findings[0].cwe_id == "CWE-400"
        assert perf_findings[0].severity == "high"

    def test_constant_bounded_inner_loop_not_flagged(self, scanner):
        """
        Verify that nested loops bounded by a small constant range (e.g. retry attempts <= 20)
        are recognized as bounded linear runtime O(N) and not flagged.
        """
        code = '''
def process_batches(records):
    for record in records:
        for attempt in range(3):
            if try_send(record):
                break
'''
        report = scanner.scan(code, filename="src/tasks.py")
        perf_findings = [f for f in report.findings if f.rule_id == "AST-PERF-001"]
        assert len(perf_findings) == 0

    # ── 3. requests password references vs SF-SEC-002 (CWE-798) ──────────────
    def test_requests_non_secret_password_references_not_flagged(self, trie):
        """
        Verify that tuple unpacking, parameter assignments, type conversions,
        and keyword arguments referencing password in `requests` are not flagged as hardcoded credentials.
        """
        snippets = [
            ("src/requests/adapters.py", "username, password = get_auth_from_url(proxy)"),
            ("src/requests/adapters.py", "auth = HTTPBasicAuth(username, password=password)"),
            ("src/requests/auth.py", "password = str(password)"),
            ("src/requests/auth.py", 'password = password.encode("latin1")'),
            ("src/requests/auth.py", "self.password = password"),
            ("src/requests/auth.py", 'self.password == getattr(other, "password", None),'),
            ("src/requests/sessions.py", "username, password = None, None"),
            ("src/requests/auth.py", "def __init__(self, username, password=None):"),
            ("src/requests/auth.py", "# password = user provided password string"),
        ]

        for filepath, line in snippets:
            threats = trie.find_all_threats(line, filename=filepath, filter_false_positives=True)
            assert len(threats) == 0, f"Expected 0 threats for benign pattern `{line}`, got: {threats}"

    def test_genuine_hardcoded_password_retained(self, trie):
        """
        Verify that genuine hardcoded production password literals remain reliably detected.
        """
        genuine_code = '''
# Application Database Configuration
DB_HOST = "db.internal.net"
password = "SuperSecretProductionDatabasePassword123!"
'''
        threats = trie.find_all_threats(genuine_code, filename="src/config/database.py", filter_false_positives=True)
        assert len(threats) == 1
        assert threats[0].pattern == "password ="
        assert threats[0].cwe_id == "CWE-798"
        assert threats[0].severity == "high"
        assert threats[0].is_false_positive is False
