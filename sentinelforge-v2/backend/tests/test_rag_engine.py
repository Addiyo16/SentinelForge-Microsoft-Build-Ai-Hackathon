"""
Unit tests for SentinelForge RAG Knowledge Base Engine.
Tests TF-IDF retrieval, threshold calibration, category boosting, and selection rationale.
"""

import pytest
from app.utils.rag_engine import retrieve_context, RAGResult, KNOWLEDGE_BASE


class TestRAGEngine:
    def test_benign_code_returns_zero_rag_entries(self):
        code = """
def calculate_discount(price: float, discount: float) -> float:
    return price * (1.0 - discount)
"""
        results = retrieve_context(code)
        assert len(results) == 0

    def test_nested_loop_retrieves_perf_guidance(self):
        code = """
def two_sum(nums, target):
    for i in range(len(nums)):
        for j in range(i + 1, len(nums)):
            if nums[i] + nums[j] == target:
                return [i, j]
    return []
"""
        results = retrieve_context(code)
        assert len(results) >= 1
        ref_ids = [r.kb_ref for r in results]
        assert "perf-001" in ref_ids
        # Verify selection reason is populated
        perf_result = next(r for r in results if r.kb_ref == "perf-001")
        assert perf_result.selection_reason != ""

    def test_no_insecure_deserialization_on_math_code(self):
        code = """
def matrix_mult(A, B):
    n = len(A)
    C = [[0] * n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            for k in range(n):
                C[i][j] += A[i][k] * B[k][j]
    return C
"""
        results = retrieve_context(code)
        ref_ids = [r.kb_ref for r in results]
        # Insecure deserialization (sec-002) should NEVER be returned for matrix multiplication
        assert "sec-002" not in ref_ids

    def test_threat_category_boosting(self):
        code = "data = load_data()"
        # Pass detected threat category from Trie
        results = retrieve_context(code, threat_categories=["Insecure Deserialization"])
        assert len(results) >= 1
        assert any(r.kb_ref == "sec-002" for r in results)
        res = next(r for r in results if r.kb_ref == "sec-002")
        assert "Matched detected threat category" in res.selection_reason

    def test_command_injection_retrieval(self):
        code = "import os\nos.system('echo ' + user_input)"
        results = retrieve_context(code, threat_categories=["OS Command Injection"])
        assert any(r.kb_ref == "sec-004" for r in results)
        res = next(r for r in results if r.kb_ref == "sec-004")
        assert res.cwe_id == "CWE-78"
    def test_python_code_with_requests_get_never_retrieves_c_gets_overflow(self):
        """
        Validates Issue 3: Python requests.get() or get() calls must NEVER retrieve
        C/C++ buffer-overflow advice about gets() or strcpy().
        """
        python_code = """
import requests

def fetch_data(url):
    response = requests.get(url, timeout=10)
    return response.json()

def process_widget():
    data = get_widget_config()
    return data
"""
        # 1. Without explicit language, regex word-boundary prevents matching 'gets' inside 'get' or 'widgets'
        results = retrieve_context(python_code)
        for r in results:
            assert r.kb_ref != "sec-005", f"C/C++ buffer overflow {r.kb_ref} incorrectly returned for Python code!"
            assert "gets" not in r.historical_fix.lower()

        # 2. With explicit language='python', sec-005 is strictly filtered out
        results_py = retrieve_context(python_code, language="python")
        for r in results_py:
            assert r.kb_ref != "sec-005"
            assert r.cwe_id != "CWE-120"

    def test_dynamic_import_injection_retrieves_python_importlib_advice(self):
        """
        Validates Issue 3: Python dynamic import __import__ correctly retrieves
        sec-008 (Dynamic Python Import Injection) with CWE-94 guidance.
        """
        code = "module = __import__(untrusted_input)"
        results = retrieve_context(code, language="python", finding_cwes=["CWE-94"])
        assert any(r.kb_ref == "sec-008" for r in results)
        res = next(r for r in results if r.kb_ref == "sec-008")
        assert res.cwe_id == "CWE-94"
        assert "importlib" in res.historical_fix

