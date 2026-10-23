"""
Regression and unit tests for Polyglot AST Scanners (C++, Java, Go, JS/TS, YAML).
Guarantees every ASTFinding has a required rule_id, CWE ID, evidence, and valid schema.
Prevents regression of incident: 'ASTFinding.__init__() missing 1 required positional argument: rule_id'.
"""

import pytest
from app.utils.ast_engine import analyze_code
from app.utils.scanners.generic_fallback import scan_generic_regex


class TestPolyglotScanners:
    def test_cpp_buffer_overflow_finding_schema(self):
        code = """
#include <cstring>
void process(const char* s) {
    char buf[16];
    strcpy(buf, s);
}
"""
        report = analyze_code(code, filename="buffer_overflow.cpp")
        assert len(report.findings) >= 1
        finding = next((f for f in report.findings if f.rule_id == "AST-SEC-C-001"), None)
        assert finding is not None
        assert finding.rule_id == "AST-SEC-C-001"
        assert finding.cwe_id == "CWE-120"
        assert finding.node_type == "DangerousCall"
        assert finding.source_file == "buffer_overflow.cpp"
        assert "strcpy" in finding.evidence
        assert finding.line > 0

    def test_java_insecure_deserialization_finding_schema(self):
        code = """
import java.io.ObjectInputStream;
import java.io.InputStream;
public class Handler {
    public Object read(InputStream is) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(is);
        return ois.readObject();
    }
}
"""
        report = analyze_code(code, filename="Handler.java")
        assert len(report.findings) >= 1
        finding = next((f for f in report.findings if f.rule_id == "AST-SEC-JAVA-002"), None)
        assert finding is not None
        assert finding.rule_id == "AST-SEC-JAVA-002"
        assert finding.cwe_id == "CWE-502"
        assert finding.node_type == "DangerousCall"
        assert finding.source_file == "Handler.java"
        assert "readObject" in finding.evidence

    def test_yaml_devops_permission_finding_schema(self):
        code = """
apiVersion: argoproj.io/v1alpha1
kind: Workflow
spec:
  templates:
  - name: step
    args: ["chmod 777 run.sh"]
"""
        report = analyze_code(code, filename="deploy.yml")
        assert len(report.findings) >= 1
        finding = next((f for f in report.findings if f.rule_id == "AST-SEC-OPS-001"), None)
        assert finding is not None
        assert finding.rule_id == "AST-SEC-OPS-001"
        assert finding.cwe_id == "CWE-732"
        assert finding.source_file == "deploy.yml"

    def test_go_unsafe_pointer_finding_schema(self):
        code = """
package main
import "unsafe"
func leak(p unsafe.Pointer) {}
"""
        report = analyze_code(code, filename="leak.go")
        assert len(report.findings) >= 1
        finding = next((f for f in report.findings if f.rule_id == "AST-SEC-GO-001"), None)
        assert finding is not None
        assert finding.rule_id == "AST-SEC-GO-001"
        assert finding.cwe_id == "CWE-119"

    def test_javascript_xss_and_eval_finding_schema(self):
        code = """
const Component = ({ data }) => {
    eval(data);
    return <div dangerouslySetInnerHTML={{ __html: data }} />;
};
"""
        report = analyze_code(code, filename="app.jsx")
        rule_ids = {f.rule_id for f in report.findings}
        assert "AST-SEC-JS-001" in rule_ids
        assert "AST-SEC-JS-003" in rule_ids

    def test_polyglot_nested_loop_finding_schema(self):
        js_nested = """
function process(matrix) {
    for (let i = 0; i < matrix.length; i++) {
        for (let j = 0; j < matrix[i].length; j++) {
            console.log(matrix[i][j]);
        }
    }
}
"""
        report = analyze_code(js_nested, filename="matrix.js")
        assert report.max_loop_depth == 2
        loop_finding = next((f for f in report.findings if f.rule_id == "AST-PERF-001"), None)
        assert loop_finding is not None
        assert loop_finding.cwe_id == "CWE-400"
        assert loop_finding.source_file == "matrix.js"

    def test_demo_polyglot_simulation_files_no_crashes(self):
        """Reproduce exact 4-file simulation from demo-org/sentinelforge-polyglot."""
        from app.main import MOCK_CODE_PYTHON, MOCK_CODE_CPP, MOCK_CODE_JAVA, MOCK_CODE_YAML

        files = [
            ("auth_service.py", MOCK_CODE_PYTHON),
            ("buffer_overflow.cpp", MOCK_CODE_CPP),
            ("SessionController.java", MOCK_CODE_JAVA),
            ("deploy.yml", MOCK_CODE_YAML),
        ]

        total_findings = 0
        for filename, content in files:
            report = analyze_code(content, filename=filename)
            assert report is not None
            for finding in report.findings:
                # Every finding must have non-empty required fields
                assert finding.rule_id != ""
                assert finding.node_type != ""
                assert finding.description != ""
                assert finding.line > 0
                assert finding.cwe_id.startswith("CWE-")
                assert finding.source_file == filename
                assert finding.evidence != ""
            total_findings += len(report.findings)

        # Confirm all 4 files generated valid findings without crashing
        assert total_findings >= 4

    def test_demo_polyglot_simulation_deduplication_rule_integrity(self):
        """Verify that simulation deduplication produces accurate, non-conflicting rule classifications."""
        from app.main import MOCK_CODE_PYTHON, MOCK_CODE_CPP, MOCK_CODE_JAVA, MOCK_CODE_YAML, _trie
        from app.rules.registry import deduplicate_findings

        files = [
            {"filename": "auth_service.py", "content": MOCK_CODE_PYTHON},
            {"filename": "buffer_overflow.cpp", "content": MOCK_CODE_CPP},
            {"filename": "SessionController.java", "content": MOCK_CODE_JAVA},
            {"filename": "deploy.yml", "content": MOCK_CODE_YAML},
        ]

        raw_candidates = []
        for f in files:
            report = analyze_code(f["content"], filename=f["filename"])
            for af in report.to_dict()["findings"]:
                item = dict(**af)
                item["source"] = "ast"
                item["source_file"] = f["filename"]
                raw_candidates.append(item)
            for tm in _trie.find_all_threats(f["content"], filename=f["filename"]):
                raw_candidates.append({
                    "source": "trie",
                    "source_file": f["filename"],
                    "pattern": tm.pattern,
                    "category": tm.category,
                    "severity": tm.severity,
                    "cwe_id": tm.cwe_id,
                    "line": tm.line,
                    "snippet": tm.snippet,
                })

        norm = deduplicate_findings(raw_candidates)

        # 1. SessionController.java must be mapped to Java rules, NOT Python pickle
        java_findings = [n for n in norm if n["file_path"] == "SessionController.java"]
        assert len(java_findings) >= 1
        for jf in java_findings:
            assert "pickle" not in jf["rule_id"].lower()
            assert "pickle" not in jf["title"].lower()
            assert not jf["rule_id"].startswith("SF-PY-")
        deser_finding = next((jf for jf in java_findings if jf["cwe_id"] == "CWE-502"), None)
        assert deser_finding is not None
        assert deser_finding["rule_id"] == "SF-JV-002"
        assert deser_finding["title"] == "Java Insecure Deserialization"

        # 2. deploy.yml must NOT be flagged with AST-PERF-001 or CWE-400
        yaml_findings = [n for n in norm if n["file_path"] == "deploy.yml"]
        assert not any(yf["rule_id"] == "AST-PERF-001" for yf in yaml_findings)
        assert not any(yf["cwe_id"] == "CWE-400" for yf in yaml_findings)

        # 3. auth_service.py nested loop must be AST-PERF-001 (CWE-400)
        py_loop = next((n for n in norm if n["file_path"] == "auth_service.py" and n["cwe_id"] == "CWE-400"), None)
        assert py_loop is not None
        assert py_loop["rule_id"] == "AST-PERF-001"
        assert py_loop["title"] == "Algorithmic Complexity Resource Exhaustion"

