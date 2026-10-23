"""
Unit tests for SentinelForge Versioned Rule Registry and Multi-Engine Finding Deduplication.
"""

import pytest
from app.rules.registry import (
    RULE_REGISTRY_VERSION,
    FindingStatus,
    RuleRegistry,
    get_rule_registry,
    deduplicate_findings,
)


class TestRuleRegistry:
    def test_version_and_loading(self):
        registry = get_rule_registry()
        assert RULE_REGISTRY_VERSION == "2.1.0"
        rules = registry.list_rules()
        assert len(rules) >= 15

    def test_get_rule_by_id(self):
        registry = get_rule_registry()
        py_rule = registry.get_rule("SF-PY-001")
        assert py_rule is not None
        assert py_rule.cwe_id == "CWE-502"
        assert py_rule.severity == "critical"
        assert "Pickle" in py_rule.name

        js_rule = registry.get_rule("SF-JS-001")
        assert js_rule is not None
        assert js_rule.cwe_id == "CWE-95"

    def test_find_rule_by_pattern_and_cwe(self):
        registry = get_rule_registry()
        rule = registry.find_rule_by_pattern_or_cwe(pattern="pickle.loads(", cwe_id="CWE-502")
        assert rule is not None
        assert rule.rule_id == "SF-PY-001"

    def test_list_rules_by_language(self):
        registry = get_rule_registry()
        py_rules = registry.list_rules("python")
        assert any(r.rule_id == "SF-PY-001" for r in py_rules)
        # Polyglot rules should be included in language listings
        assert any(r.rule_id == "SF-SEC-001" for r in py_rules)

    def test_deduplicate_findings_merges_ast_and_trie(self):
        raw_findings = [
            {
                "source": "trie",
                "detection_source": "pattern",
                "pattern": "pickle.loads(",
                "category": "Insecure Deserialization",
                "severity": "critical",
                "cwe_id": "CWE-502",
                "source_file": "app/service.py",
                "line": 15,
                "col": 4,
                "snippet": "obj = pickle.loads(data)",
                "ml_score": 75,
            },
            {
                "source": "ast",
                "detection_source": "ast",
                "rule_id": "AST-PY-001",
                "category": "Insecure Deserialization",
                "severity": "critical",
                "cwe_id": "CWE-502",
                "source_file": "app/service.py",
                "line": 15,
                "col": 4,
                "evidence": "pickle.loads(data)",
                "ml_score": 80,
            },
        ]

        deduped = deduplicate_findings(raw_findings)
        assert len(deduped) == 1
        merged = deduped[0]

        assert merged["file_path"] == "app/service.py"
        assert merged["line"] == 15
        assert merged["cwe_id"] == "CWE-502"
        assert "trie" in merged["detection_sources"]
        assert "ast" in merged["detection_sources"]
        assert merged["status"] == FindingStatus.CONFIRMED.value
        assert merged["rule_id"] == "SF-PY-001"
        assert "JSON" in merged["remediation"]

    def test_deduplicate_keeps_distinct_findings_separate(self):
        raw_findings = [
            {
                "source": "ast",
                "rule_id": "SF-PY-001",
                "cwe_id": "CWE-502",
                "source_file": "app/service.py",
                "line": 15,
                "severity": "critical",
            },
            {
                "source": "ast",
                "rule_id": "SF-PY-002",
                "cwe_id": "CWE-78",
                "source_file": "app/service.py",
                "line": 35,
                "severity": "high",
            },
        ]

        deduped = deduplicate_findings(raw_findings)
        assert len(deduped) == 2

    def test_java_session_controller_deserialization_maps_to_java_rule_never_pickle(self):
        """Ensure SessionController.java findings map to Java deserialization (SF-JV-002), never Python pickle (SF-PY-001)."""
        raw_findings = [
            {
                "source": "ast",
                "detection_source": "ast",
                "rule_id": "AST-SEC-JAVA-002",
                "category": "Insecure Deserialization",
                "severity": "critical",
                "cwe_id": "CWE-502",
                "source_file": "SessionController.java",
                "line": 9,
                "evidence": "return ois.readObject();",
                "ml_score": 85,
            },
            {
                "source": "trie",
                "detection_source": "pattern",
                "pattern": "readObject(",
                "category": "Java Insecure Deserialization",
                "severity": "critical",
                "cwe_id": "CWE-502",
                "source_file": "SessionController.java",
                "line": 9,
                "snippet": "return ois.readObject();",
                "ml_score": 88,
            },
        ]
        deduped = deduplicate_findings(raw_findings)
        assert len(deduped) == 1
        finding = deduped[0]

        assert finding["file_path"] == "SessionController.java"
        assert finding["rule_id"] == "SF-JV-002"
        assert finding["title"] == "Java Insecure Deserialization"
        assert "pickle" not in finding["rule_id"].lower()
        assert "pickle" not in finding["title"].lower()
        assert "pickle" not in finding["description"].lower()
        assert "ObjectInputStream" in finding["description"]
        assert finding["cwe_id"] == "CWE-502"
        assert finding["status"] == FindingStatus.CONFIRMED.value

    def test_declarative_yaml_rejects_ast_perf_001_and_loop_complexity(self):
        """Ensure YAML declarative files reject AST-PERF-001 loop findings and map permissions to YAML rules."""
        raw_findings = [
            {
                "source": "ast",
                "rule_id": "AST-PERF-001",
                "node_type": "NestedLoop",
                "description": "Nested loop depth 2",
                "severity": "high",
                "cwe_id": "CWE-400",
                "source_file": "deploy.yml",
                "line": 4,
            },
            {
                "source": "ast",
                "rule_id": "AST-SEC-OPS-001",
                "pattern": "chmod 777",
                "severity": "high",
                "cwe_id": "CWE-732",
                "source_file": "deploy.yml",
                "line": 12,
                "evidence": 'args: ["chmod 777 scripts/run.sh"]',
            },
        ]
        deduped = deduplicate_findings(raw_findings)
        # AST-PERF-001 must be discarded on deploy.yml
        assert not any(f["rule_id"] == "AST-PERF-001" for f in deduped)
        assert not any(f["cwe_id"] == "CWE-400" for f in deduped)

        # chmod 777 must map to YAML DevOps rule, never Python SF-PY-007
        ops_finding = next(f for f in deduped if f["cwe_id"] == "CWE-732")
        assert ops_finding["rule_id"] in ("AST-SEC-OPS-001", "SF-OPS-001")
        assert ops_finding["rule_id"] != "SF-PY-007"
        assert "Python" not in ops_finding["title"]

    def test_ast_perf_001_polyglot_registered_rule(self):
        """Verify AST-PERF-001 rule registry schema and metadata."""
        registry = get_rule_registry()
        rule = registry.get_rule("AST-PERF-001")
        assert rule is not None
        assert rule.rule_id == "AST-PERF-001"
        assert rule.cwe_id == "CWE-400"
        assert rule.severity == "high"
        assert rule.language == "polyglot"
        assert "Algorithmic Complexity" in rule.category

