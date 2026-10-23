"""
Unit tests for SentinelForge Isolated Patch Verification Engine.
Tests AST parsing validation, sandboxed test execution, vulnerability mitigation rescan, and regression checks.
"""

import pytest
import asyncio
from app.utils.sandbox import verify_candidate_patch, run_sandboxed


class TestPatchVerifier:
    @pytest.mark.asyncio
    async def test_valid_benign_patch_passes(self):
        original = "def foo():\n    return 42\n"
        patch = "def foo():\n    return 42\n"
        res = await verify_candidate_patch(
            original_code=original,
            patch_code=patch,
            original_trie_threats=[],
            original_ast_report={"dangerous_calls": [], "max_loop_depth": 0, "findings": []},
        )
        assert res["parse_result"] is True
        assert res["test_result"] is True
        assert res["rescan_result"] is True
        assert res["regression_result"] is True
        assert res["verification_passed"] is True

    @pytest.mark.asyncio
    async def test_syntax_error_patch_fails(self):
        original = "def foo():\n    return 42\n"
        broken_patch = "def foo(\n    broken syntax"
        res = await verify_candidate_patch(
            original_code=original,
            patch_code=broken_patch,
            original_trie_threats=[],
            original_ast_report={"dangerous_calls": [], "max_loop_depth": 0, "findings": []},
        )
        assert res["parse_result"] is False
        assert res["verification_passed"] is False
        assert "SyntaxError" in res["failure_summary"]

    @pytest.mark.asyncio
    async def test_vulnerability_mitigation_rescan(self):
        original = "import pickle\ndata = b'test'\nobj = pickle.loads(data)\n"
        safe_patch = "import json\ndata = '{\"key\": \"val\"}'\nobj = json.loads(data)\n"
        res = await verify_candidate_patch(
            original_code=original,
            patch_code=safe_patch,
            original_trie_threats=[{"pattern": "pickle.loads("}],
            original_ast_report={"dangerous_calls": ["pickle.loads"], "max_loop_depth": 0, "findings": [{}]},
        )
        assert res["rescan_result"] is True
        assert res["verification_passed"] is True

    @pytest.mark.asyncio
    async def test_unmitigated_vulnerability_fails_rescan(self):
        original = "import pickle\nobj = pickle.loads(data)\n"
        bad_patch = "import pickle\n# note: still dangerous\nobj = pickle.loads(data)\n"
        res = await verify_candidate_patch(
            original_code=original,
            patch_code=bad_patch,
            original_trie_threats=[{"pattern": "pickle.loads("}],
            original_ast_report={"dangerous_calls": ["pickle.loads"], "max_loop_depth": 0, "findings": [{}]},
        )
        assert res["rescan_result"] is False
        assert res["verification_passed"] is False
        assert "not eliminated" in res["failure_summary"]

    @pytest.mark.asyncio
    async def test_regression_detection(self):
        original = "def run():\n    pass\n"
        regressive_patch = "import os\ndef run():\n    os.system('rm -rf /')\n"
        res = await verify_candidate_patch(
            original_code=original,
            patch_code=regressive_patch,
            original_trie_threats=[],
            original_ast_report={"dangerous_calls": [], "max_loop_depth": 0, "findings": []},
        )
        assert res["regression_result"] is False
        assert res["verification_passed"] is False
        assert "introduced" in res["failure_summary"]

    @pytest.mark.asyncio
    async def test_sandbox_subprocess_execution(self):
        code = "print('SentinelForge Verified Sandbox Output')"
        run_res = await run_sandboxed(code, timeout=5)
        assert run_res.exit_code == 0
        assert "SentinelForge Verified Sandbox Output" in run_res.stdout

    @pytest.mark.asyncio
    async def test_unified_diff_application_and_verification_status(self):
        from app.utils.sandbox import PatchVerificationStatus
        original = "import pickle\ndata = b'test'\nobj = pickle.loads(data)\n"
        diff = """--- a/code.py
+++ b/code.py
@@ -1,3 +1,3 @@
-import pickle
-data = b'test'
-obj = pickle.loads(data)
+import json
+data = '{"test": 1}'
+obj = json.loads(data)
"""
        res = await verify_candidate_patch(
            original_code=original,
            patch_code=diff,
            original_trie_threats=[{"pattern": "pickle.loads("}],
            original_ast_report={"dangerous_calls": ["pickle.loads"], "max_loop_depth": 0, "findings": [{}]},
        )
        assert res["patch_applied"] is True
        assert res["verification_passed"] is True
        assert res["status"] == PatchVerificationStatus.VERIFIED.value
        assert "apply_unified_diff" in res["test_commands"]

    @pytest.mark.asyncio
    async def test_partially_verified_status_when_threat_persists(self):
        from app.utils.sandbox import PatchVerificationStatus
        original = "import pickle\ndata = pickle.dumps(123)\nobj = pickle.loads(data)\n"
        bad_diff = """--- a/code.py
+++ b/code.py
@@ -1,3 +1,4 @@
 import pickle
+# Still contains dangerous call
 data = pickle.dumps(123)
 obj = pickle.loads(data)
"""
        res = await verify_candidate_patch(
            original_code=original,
            patch_code=bad_diff,
            original_trie_threats=[{"pattern": "pickle.loads("}],
            original_ast_report={"dangerous_calls": ["pickle.loads"], "max_loop_depth": 0, "findings": [{}]},
        )
        assert res["patch_applied"] is True
        assert res["status"] == PatchVerificationStatus.PARTIALLY_VERIFIED.value
        assert res["verification_passed"] is False

    @pytest.mark.asyncio
    async def test_command_audit_trail_and_persisting_threats(self):
        original = "import pickle\ndata = b'test'\nobj = pickle.loads(data)\n"
        diff = """--- a/code.py
+++ b/code.py
@@ -1,3 +1,3 @@
-import pickle
-data = b'test'
-obj = pickle.loads(data)
+import json
+data = '{"test": 1}'
+obj = json.loads(data)
"""
        res = await verify_candidate_patch(
            original_code=original,
            patch_code=diff,
            original_trie_threats=[{"pattern": "pickle.loads("}],
            original_ast_report={"dangerous_calls": ["pickle.loads"], "max_loop_depth": 0, "findings": [{}]},
        )
        assert "command_audit_trail" in res
        trail = res["command_audit_trail"]
        assert len(trail) >= 4
        assert any(step["step"] == "Patch Application" and step["status"] == "PASSED" for step in trail)
        assert any(step["step"] == "AST Syntax Validation" and step["status"] == "PASSED" for step in trail)
        assert any(step["step"] == "Vulnerability Mitigation Rescan" and step["status"] == "PASSED" for step in trail)
        assert any(step["step"] == "Security Regression Check" and step["status"] == "PASSED" for step in trail)
        assert "pickle.loads(" in res["mitigated_vulnerabilities"]
        assert len(res["persisting_vulnerabilities"]) == 0
        assert res["verification_passed"] is True

    def test_apply_unified_diff_with_line_offset(self):
        from app.utils.sandbox import apply_unified_diff

        original = (
            "import os\n"
            "import sys\n"
            "\n"
            "def worker():\n"
            "    print('Starting')\n"
            "    data = pickle.loads(b'payload')\n"
            "    print('Done')\n"
            "    return data\n"
        )
        diff = (
            "--- a/worker.py\n"
            "+++ b/worker.py\n"
            "@@ -6,1 +6,1 @@\n"
            "-    data = pickle.loads(b'payload')\n"
            "+    data = json.loads('{\"safe\": true}')\n"
        )
        applied, patched = apply_unified_diff(original, diff)
        assert applied is True
        # Verify lines 1-5 are untouched
        assert patched.startswith("import os\nimport sys\n\ndef worker():\n    print('Starting')\n")
        # Verify line 6 was replaced
        assert "data = json.loads('{\"safe\": true}')\n" in patched
        assert "pickle.loads" not in patched
        # Verify line 7-8 remain untouched
        assert patched.endswith("    print('Done')\n    return data\n")

    def test_apply_unified_diff_rejects_noop_diff(self):
        from app.utils.sandbox import apply_unified_diff

        original = "app = Flask(__name__)\napp.cli.add_command(init_db_command)\n"
        # No-op diff where removed line equals added line
        noop_diff = (
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -2,1 +2,1 @@\n"
            "-app.cli.add_command(init_db_command)\n"
            "+app.cli.add_command(init_db_command)\n"
        )
        applied, patched = apply_unified_diff(original, noop_diff)
        assert applied is False
        assert patched == original

    def test_apply_unified_diff_multi_hunk(self):
        from app.utils.sandbox import apply_unified_diff

        original = (
            "import pickle\n"
            "header = 1\n"
            "line3 = 3\n"
            "line4 = 4\n"
            "line5 = 5\n"
            "line6 = 6\n"
            "line7 = 7\n"
            "os.system('id')\n"
            "footer = 9\n"
        )
        diff = (
            "--- a/multi.py\n"
            "+++ b/multi.py\n"
            "@@ -1,1 +1,1 @@\n"
            "-import pickle\n"
            "+import json\n"
            "@@ -8,1 +8,1 @@\n"
            "-os.system('id')\n"
            "+subprocess.run(['id'])\n"
        )
        applied, patched = apply_unified_diff(original, diff)
        assert applied is True
        assert patched.startswith("import json\nheader = 1\n")
        assert "subprocess.run(['id'])" in patched
        assert "os.system" not in patched
        assert "pickle" not in patched
        assert patched.endswith("footer = 9\n")

    @pytest.mark.asyncio
    async def test_empty_patch_for_vulnerable_code_marks_steps_not_run(self):
        original = "import pickle\ndata = pickle.loads(raw)\n"
        empty_patch = ""
        res = await verify_candidate_patch(
            original_code=original,
            patch_code=empty_patch,
            original_trie_threats=[{"pattern": "pickle.loads("}],
            original_ast_report={"dangerous_calls": ["pickle.loads"], "max_loop_depth": 0, "findings": []},
        )
        assert res["patch_applied"] is False
        assert res["verification_passed"] is False
        assert len(res["mitigated_vulnerabilities"]) == 0
        assert "pickle.loads(" in res["persisting_vulnerabilities"]
        assert res["execution_duration"] > 0

        trail = res["command_audit_trail"]
        # Step 0: Patch Application FAILED
        assert any(step["step"] == "Patch Application" and step["status"] == "FAILED" for step in trail)
        # Downstream steps must be NOT RUN, not PASSED!
        not_run_steps = [step["step"] for step in trail if step["status"] == "NOT RUN"]
        assert "AST Syntax Validation" in not_run_steps
        assert "Vulnerability Mitigation Rescan" in not_run_steps
        assert "Security Regression Check" in not_run_steps
        assert "Isolated Test Execution" in not_run_steps
        assert not any(step["status"] == "PASSED" for step in trail)

    @pytest.mark.asyncio
    async def test_scenario_1_clean_baseline_no_patch_required(self):
        """Scenario 1: Clean baseline without findings reports BASELINE CHECK PASSED — NO PATCH REQUIRED."""
        from app.utils.sandbox import PatchVerificationStatus
        code = "def add(a, b):\n    return a + b\n"
        res = await verify_candidate_patch(
            original_code=code,
            patch_code="",
            original_trie_threats=[],
            original_ast_report={"dangerous_calls": [], "max_loop_depth": 0, "findings": []},
        )
        assert res["status"] == PatchVerificationStatus.BASELINE_PASSED.value
        assert res["is_clean_baseline"] is True
        assert res["patch_applied"] is False
        assert len(res["mitigated_vulnerabilities"]) == 0
        assert len(res["persisting_vulnerabilities"]) == 0
        assert any(s["step"] == "Baseline Integrity Check" and s["status"] == "PASSED" for s in res["command_audit_trail"])

    @pytest.mark.asyncio
    async def test_scenario_2_findings_exist_patch_not_generated(self):
        """Scenario 2: Findings exist but patch empty reports PATCH NOT GENERATED — FINDINGS REMAIN UNRESOLVED."""
        from app.utils.sandbox import PatchVerificationStatus
        code = "import pickle\ndata = pickle.loads(raw)\n"
        res = await verify_candidate_patch(
            original_code=code,
            patch_code="",
            original_trie_threats=[{"pattern": "pickle.loads("}],
            original_ast_report={"dangerous_calls": ["pickle.loads"], "max_loop_depth": 0, "findings": []},
        )
        assert res["status"] == PatchVerificationStatus.PATCH_NOT_GENERATED.value
        assert res["patch_applied"] is False
        assert res["verification_passed"] is False
        assert len(res["mitigated_vulnerabilities"]) == 0
        assert "pickle.loads(" in res["persisting_vulnerabilities"]
        not_run = [s["step"] for s in res["command_audit_trail"] if s["status"] == "NOT RUN"]
        assert "AST Syntax Validation" in not_run
        assert "Vulnerability Mitigation Rescan" in not_run
        assert "Security Regression Check" in not_run
        assert "Isolated Test Execution" in not_run

    @pytest.mark.asyncio
    async def test_scenario_3_patch_applied_syntax_fails_not_verified(self):
        """Scenario 3: Patch applied with broken syntax reports NOT VERIFIED and skips rescan/regression."""
        from app.utils.sandbox import PatchVerificationStatus
        code = "import pickle\ndata = pickle.loads(raw)\n"
        broken_patch = "import json\ndata = json.loads(raw\n"  # missing closing paren
        res = await verify_candidate_patch(
            original_code=code,
            patch_code=broken_patch,
            original_trie_threats=[{"pattern": "pickle.loads("}],
            original_ast_report={"dangerous_calls": ["pickle.loads"], "max_loop_depth": 0, "findings": []},
        )
        assert res["status"] == PatchVerificationStatus.NOT_VERIFIED.value
        assert res["patch_applied"] is True
        assert res["parse_result"] is False
        assert res["verification_passed"] is False
        not_run = [s["step"] for s in res["command_audit_trail"] if s["status"] == "NOT RUN"]
        assert "Vulnerability Mitigation Rescan" in not_run
        assert "Security Regression Check" in not_run

    @pytest.mark.asyncio
    async def test_scenario_4_patch_applied_mitigates_zero_not_verified(self):
        """Scenario 4: Patch leaves vulnerability intact -> Rescan FAILED, 0 mitigated, NOT VERIFIED."""
        from app.utils.sandbox import PatchVerificationStatus
        code = "import pickle\ndata = pickle.loads(raw)\n"
        noop_patch = "# Comments added\nimport pickle\ndata = pickle.loads(raw)\n"
        res = await verify_candidate_patch(
            original_code=code,
            patch_code=noop_patch,
            original_trie_threats=[{"pattern": "pickle.loads("}],
            original_ast_report={"dangerous_calls": ["pickle.loads"], "max_loop_depth": 0, "findings": [{}]},
        )
        assert res["status"] == PatchVerificationStatus.NOT_VERIFIED.value
        assert res["rescan_result"] is False
        assert res["verification_passed"] is False
        assert len(res["mitigated_vulnerabilities"]) == 0
        rescan_step = next(s for s in res["command_audit_trail"] if s["step"] == "Vulnerability Mitigation Rescan")
        assert rescan_step["status"] == "FAILED"
        assert "Mitigated 0 target vulnerability pattern(s)" in rescan_step["output"]

    @pytest.mark.asyncio
    async def test_scenario_5_patch_applied_fully_verified(self):
        """Scenario 5: Real patch applied, clean syntax, flaws mitigated -> PATCH VERIFICATION PASSED."""
        from app.utils.sandbox import PatchVerificationStatus
        code = "import pickle\ndata = pickle.loads(raw)\n"
        good_patch = "import json\ndata = json.loads(raw)\n"
        res = await verify_candidate_patch(
            original_code=code,
            patch_code=good_patch,
            original_trie_threats=[{"pattern": "pickle.loads("}],
            original_ast_report={"dangerous_calls": ["pickle.loads"], "max_loop_depth": 0, "findings": []},
        )
        assert res["status"] == PatchVerificationStatus.VERIFIED.value
        assert res["patch_applied"] is True
        assert res["parse_result"] is True
        assert res["rescan_result"] is True
        assert res["regression_result"] is True
        assert res["verification_passed"] is True
        assert len(res["mitigated_vulnerabilities"]) > 0
        assert len(res["persisting_vulnerabilities"]) == 0

    @pytest.mark.asyncio
    async def test_incomplete_patch_fails_even_if_syntax_passes(self):
        """Validates that a passing Python syntax check does NOT establish vulnerability remediation."""
        from app.utils.sandbox import PatchVerificationStatus
        code = (
            "import pickle\n"
            "password = 'admin123'\n"
            "data = pickle.loads(raw)\n"
            "strcpy(dest, src)\n"
        )
        # Patch only fixes pickle.loads, leaving password and strcpy unresolved
        incomplete_patch = (
            "import json\n"
            "password = 'admin123'\n"
            "data = json.loads(raw)\n"
            "strcpy(dest, src)\n"
        )
        trie_threats = [
            {"pattern": "pickle.loads(", "category": "Deserialization", "severity": "critical", "cwe_id": "CWE-502"},
            {"pattern": "password =", "category": "Hardcoded Credential", "severity": "high", "cwe_id": "CWE-798"},
            {"pattern": "strcpy(", "category": "Buffer Overflow", "severity": "high", "cwe_id": "CWE-120"},
        ]
        res = await verify_candidate_patch(
            original_code=code,
            patch_code=incomplete_patch,
            original_trie_threats=trie_threats,
            original_ast_report={"dangerous_calls": ["pickle.loads"], "max_loop_depth": 0, "findings": []},
            filename="app.py",
        )
        assert res["parse_result"] is True  # Python syntax passes
        assert res["rescan_result"] is False  # Security rescan fails!
        assert res["verification_passed"] is False  # Overall verification blocked
        assert "password =" in res["persisting_vulnerabilities"]
        assert "strcpy(" in res["persisting_vulnerabilities"]
        assert "A Python syntax check passing does not establish that a security vulnerability has been fixed" in res["failure_summary"]

    @pytest.mark.asyncio
    async def test_comprehensive_patch_fixes_all_vulnerabilities_and_passes(self):
        """Validates that remediating all target vulnerabilities successfully passes verification."""
        from app.utils.sandbox import PatchVerificationStatus
        code = (
            "import pickle\n"
            "import os\n"
            "password = 'supersecretpassword123'\n"
            "data = b'test'\n"
            "obj = pickle.loads(data)\n"
            "os.chmod('/tmp/secret.txt', 0o777)\n"
            "strcpy(dest, src)\n"
        )
        # Comprehensive patch addressing all 4 findings
        complete_patch = (
            "import json\n"
            "import os\n"
            "password = os.environ.get('DB_PASSWORD', '')\n"
            "data = b'test'\n"
            "obj = json.loads(data)\n"
            "os.chmod('/tmp/secret.txt', 0o600)\n"
            "strncpy(dest, src, sizeof(dest) - 1)\n"
        )
        trie_threats = [
            {"pattern": "pickle.loads(", "category": "Deserialization", "severity": "critical", "cwe_id": "CWE-502"},
            {"pattern": "password =", "category": "Hardcoded Credential", "severity": "high", "cwe_id": "CWE-798"},
            {"pattern": "chmod 777", "category": "Overly Permissive File Permissions", "severity": "high", "cwe_id": "CWE-732"},
            {"pattern": "strcpy(", "category": "Buffer Overflow", "severity": "high", "cwe_id": "CWE-120"},
        ]
        res = await verify_candidate_patch(
            original_code=code,
            patch_code=complete_patch,
            original_trie_threats=trie_threats,
            original_ast_report={"dangerous_calls": ["pickle.loads"], "max_loop_depth": 0, "findings": []},
            filename="app.py",
        )
        assert res["parse_result"] is True
        assert res["rescan_result"] is True
        assert res["regression_result"] is True
        assert res["verification_passed"] is True
        assert len(res["persisting_vulnerabilities"]) == 0
        assert "pickle.loads(" in res["mitigated_vulnerabilities"]
        assert "password =" in res["mitigated_vulnerabilities"]
        assert "strcpy(" in res["mitigated_vulnerabilities"]

    @pytest.mark.asyncio
    async def test_ast_perf_and_import_injection_remediated_and_verified(self):
        """Validates that AST-PERF-001 (nested loop) and __import__( injection are both remediated and pass verification."""
        from app.agents.swarm import _generate_fallback_optimizer, create_unified_diff
        from app.structures.trie import ThreatTrie
        from app.utils.ast_engine import analyze_code

        sample_code = (
            "import os\n"
            "def check_pairs(nums, target):\n"
            "    mod = __import__('math')\n"
            "    for i in range(len(nums)):\n"
            "        for j in range(len(nums)):\n"
            "            if i != j and nums[i] + nums[j] == target:\n"
            "                return [i, j]\n"
            "    return []\n"
        )
        trie = ThreatTrie()
        trie_threats = [
            {"pattern": t.pattern, "category": t.category, "severity": t.severity, "cwe_id": t.cwe_id}
            for t in trie.find_all_threats(sample_code, filename="code.py")
        ]
        ast_rep = analyze_code(sample_code, filename="code.py").to_dict()

        # Both threats must be detected on original unpatched code
        assert any(t["pattern"] == "__import__(" for t in trie_threats)
        assert any(f["rule_id"] == "AST-PERF-001" for f in ast_rep["findings"])

        # Generate remediated patch using fallback optimizer
        patched_code = _generate_fallback_optimizer(sample_code, ast_rep, [], trie_findings=trie_threats)
        diff_patch = create_unified_diff(sample_code, patched_code, filename="code.py")

        assert diff_patch.strip() != "", "Unified diff patch must not be empty"

        # Verify candidate patch
        res = await verify_candidate_patch(
            original_code=sample_code,
            patch_code=diff_patch,
            original_trie_threats=trie_threats,
            original_ast_report=ast_rep,
            filename="code.py",
        )

        assert res["status"] == "PATCH VERIFICATION PASSED"
        assert res["verification_passed"] is True
        assert res["patch_applied"] is True
        assert res["parse_result"] is True
        assert res["rescan_result"] is True
        assert res["regression_result"] is True
        assert len(res["persisting_vulnerabilities"]) == 0
        assert "__import__(" in res["mitigated_vulnerabilities"]
        assert "AST-PERF-001" in res["mitigated_vulnerabilities"]
    @pytest.mark.asyncio
    async def test_multi_file_patch_traceability_incomplete_patch_fails(self):
        """
        Validates Issue 1: Multi-file patch traceability.
        When findings exist in packages.py, sessions.py, utils.py, and api.py,
        but the diff only patches api.py, verification MUST fail with persisting findings
        and explicit traceability showing missing hunks for the unpatched files.
        """
        files = [
            {
                "filename": "src/requests/packages.py",
                "content": "import sys\nmod = __import__('urllib3')\n",
            },
            {
                "filename": "src/requests/sessions.py",
                "content": "def find_cookie(cookies, target):\n    for c in cookies:\n        for item in c:\n            if item == target: return True\n    return False\n",
            },
            {
                "filename": "src/requests/utils.py",
                "content": "import os\nos.chmod('/tmp/cache', 0o777)\n",
            },
            {
                "filename": "src/requests/api.py",
                "content": "def request(method, url):\n    mod = __import__('urllib3')\n    return mod\n",
            },
        ]
        all_findings = [
            {"rule_id": "SF-SEC-008", "pattern": "__import__(", "source_file": "src/requests/packages.py", "line": 2, "cwe_id": "CWE-94"},
            {"rule_id": "AST-PERF-001", "pattern": None, "source_file": "src/requests/sessions.py", "line": 3, "cwe_id": "CWE-400"},
            {"rule_id": "SF-SEC-007", "pattern": "chmod 777", "source_file": "src/requests/utils.py", "line": 2, "cwe_id": "CWE-732"},
            {"rule_id": "SF-SEC-008", "pattern": "__import__(", "source_file": "src/requests/api.py", "line": 2, "cwe_id": "CWE-94"},
        ]

        # Incomplete patch: ONLY modifies src/requests/api.py!
        incomplete_diff = """--- a/src/requests/api.py
+++ b/src/requests/api.py
@@ -1,3 +1,4 @@
+import importlib
 def request(method, url):
-    mod = __import__('urllib3')
+    mod = importlib.import_module('urllib3')
     return mod
"""

        res = await verify_candidate_patch(
            original_code="",
            patch_code=incomplete_diff,
            original_trie_threats=[{"pattern": "__import__("}],
            original_ast_report={"dangerous_calls": [], "findings": []},
            filename="src/requests/api.py",
            files=files,
            all_findings=all_findings,
        )

        assert res["verification_passed"] is False
        assert res["status"] == "NOT VERIFIED"
        assert len(res["persisting_vulnerabilities"]) == 3
        assert "SF-SEC-008" in res["mitigated_vulnerabilities"]  # api.py mitigated

        trace = res["finding_traceability"]
        assert len(trace) == 4

        # Check that the 3 omitted files are flagged as MISSING_HUNK / PERSISTING
        packages_trace = next(t for t in trace if t["source_file"] == "src/requests/packages.py")
        assert packages_trace["patch_hunk_status"] == "MISSING_HUNK"
        assert packages_trace["resolution"] == "PERSISTING"

        sessions_trace = next(t for t in trace if t["source_file"] == "src/requests/sessions.py")
        assert sessions_trace["patch_hunk_status"] == "MISSING_HUNK"
        assert sessions_trace["resolution"] == "PERSISTING"

        utils_trace = next(t for t in trace if t["source_file"] == "src/requests/utils.py")
        assert utils_trace["patch_hunk_status"] == "MISSING_HUNK"
        assert utils_trace["resolution"] == "PERSISTING"

        api_trace = next(t for t in trace if t["source_file"] == "src/requests/api.py")
        assert api_trace["patch_hunk_status"] == "APPLIED"
        assert api_trace["resolution"] == "MITIGATED"

    @pytest.mark.asyncio
    async def test_multi_file_patch_traceability_complete_patch_passes(self):
        """
        Validates Issue 1: Multi-file complete patch passes when all findings have traceable hunks.
        """
        files = [
            {
                "filename": "src/requests/packages.py",
                "content": "import sys\nmod = __import__('urllib3')\n",
            },
            {
                "filename": "src/requests/utils.py",
                "content": "import os\nos.chmod('/tmp/cache', 0o777)\n",
            },
        ]
        all_findings = [
            {"rule_id": "SF-SEC-008", "pattern": "__import__(", "source_file": "src/requests/packages.py", "line": 2, "cwe_id": "CWE-94"},
            {"rule_id": "SF-SEC-007", "pattern": "chmod 777", "source_file": "src/requests/utils.py", "line": 2, "cwe_id": "CWE-732"},
        ]

        complete_diff = """--- a/src/requests/packages.py
+++ b/src/requests/packages.py
@@ -1,2 +1,3 @@
 import sys
+import importlib
-mod = __import__('urllib3')
+mod = importlib.import_module('urllib3')
--- a/src/requests/utils.py
+++ b/src/requests/utils.py
@@ -1,2 +1,2 @@
 import os
-os.chmod('/tmp/cache', 0o777)
+os.chmod('/tmp/cache', 0o600)
"""

        res = await verify_candidate_patch(
            original_code="",
            patch_code=complete_diff,
            original_trie_threats=[{"pattern": "__import__("}],
            original_ast_report={"dangerous_calls": [], "findings": []},
            filename="src/requests/packages.py",
            files=files,
            all_findings=all_findings,
        )

        assert res["verification_passed"] is True
        assert res["status"] == "PATCH VERIFICATION PASSED"
        assert len(res["persisting_vulnerabilities"]) == 0
        assert len(res["mitigated_vulnerabilities"]) == 2

        trace = res["finding_traceability"]
        assert len(trace) == 2
        for t in trace:
            assert t["patch_hunk_status"] == "APPLIED"
            assert t["resolution"] == "MITIGATED"

