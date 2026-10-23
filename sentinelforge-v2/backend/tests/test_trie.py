"""
Unit tests for SentinelForge Polyglot Aho-Corasick Threat Trie.
Tests state transitions, failure links, line/column tracking, overlapping signatures, and performance.
"""

import pytest
from app.structures.trie import ThreatTrie, ThreatMatch


class TestAhoCorasickTrie:
    @pytest.fixture
    def trie(self):
        return ThreatTrie()

    def test_benign_code_returns_zero_threats(self, trie):
        code = """
def calculate_total(prices: list[float], tax_rate: float) -> float:
    subtotal = sum(prices)
    return subtotal * (1 + tax_rate)
"""
        threats = trie.find_all_threats(code)
        assert len(threats) == 0

    def test_empty_string(self, trie):
        assert trie.find_all_threats("") == []
        assert trie.find_all_matches("") == []

    def test_single_threat_detection_with_locations(self, trie):
        code = "import pickle\n\ndata = pickle.loads(raw_data)\n"
        threats = trie.find_all_threats(code)
        assert len(threats) == 1
        m = threats[0]
        assert m.pattern == "pickle.loads("
        assert m.cwe_id == "CWE-502"
        assert m.severity == "critical"
        assert m.line == 3
        assert m.col == 8
        assert "pickle.loads(raw_data)" in m.snippet

    def test_overlapping_signatures_via_failure_links(self, trie):
        # 'os.system(' contains 'system(' as a suffix match
        code = "import os\n\nos.system('echo test')\n"
        threats = trie.find_all_threats(code)
        patterns = {t.pattern for t in threats}
        assert "os.system(" in patterns
        assert "system(" in patterns

    def test_all_occurrences_returned_by_find_all_matches(self, trie):
        code = "eval(a)\neval(b)\neval(c)\n"
        all_matches = trie.find_all_matches(code)
        assert len(all_matches) == 3
        assert [m.line for m in all_matches] == [1, 2, 3]

        # find_all_threats should deduplicate by pattern
        deduped = trie.find_all_threats(code)
        assert len(deduped) == 1
        assert deduped[0].pattern == "eval("

    def test_polyglot_signatures(self, trie):
        # JavaScript/React
        js_code = "const el = <div dangerouslySetInnerHTML={{ __html: raw }} />;"
        js_threats = trie.find_all_threats(js_code)
        assert any(t.pattern == "dangerouslySetInnerHTML" for t in js_threats)

        # Java
        java_code = "Runtime.getRuntime().exec(\"shutdown\");"
        java_threats = trie.find_all_threats(java_code)
        assert any(t.pattern == "Runtime.getRuntime().exec(" for t in java_threats)

        # C/C++
        c_code = "char buf[10];\nstrcpy(buf, input);"
        c_threats = trie.find_all_threats(c_code)
        assert any(t.pattern == "strcpy(" for t in c_threats)

        # SQL
        sql_code = "SELECT * FROM users WHERE id = 1 UNION SELECT password FROM admin;"
        sql_threats = trie.find_all_threats(sql_code)
        assert any(t.pattern == "UNION SELECT" for t in sql_threats)

    def test_custom_signatures(self):
        custom = [
            {"pattern": "SUPER_SECRET_TOKEN", "category": "Secret", "severity": "critical", "cwe": "CWE-798", "conf": 1.0},
        ]
        custom_trie = ThreatTrie(custom_signatures=custom)
        matches = custom_trie.find_all_threats("my_key = 'SUPER_SECRET_TOKEN'")
        assert len(matches) == 1
        assert matches[0].pattern == "SUPER_SECRET_TOKEN"

    def test_severity_sorting(self, trie):
        code = "chmod 777\nos.system('ls')\n"
        threats = trie.find_all_threats(code)
        # critical (os.system) should come before high (chmod 777)
        assert threats[0].severity == "critical"

    def test_contextual_false_positive_yaml_swagger(self, trie):
        code = "const swaggerDocument = yaml.load(fs.readFileSync('./swagger.yaml', 'utf8'))"
        matches = trie.find_all_matches(code, filename="server.ts")
        assert len(matches) == 1
        assert matches[0].is_false_positive is True
        assert "swagger" in matches[0].false_positive_reason.lower()
        # Filtered out from actionable threats
        threats = trie.find_all_threats(code, filename="server.ts", filter_false_positives=True)
        assert len(threats) == 0

    def test_contextual_false_positive_placeholder_password(self, trie):
        dummy_code = 'let password = ""\n'
        threats = trie.find_all_threats(dummy_code, filename="models/index.ts")
        assert len(threats) == 0

        real_secret_code = 'password = "SuperSecretProdLiveKey456!"\n'
        real_threats = trie.find_all_threats(real_secret_code, filename="config.py")
        assert len(real_threats) == 1
        assert real_threats[0].is_false_positive is False

    def test_contextual_false_positive_drop_table_if_exists(self, trie):
        migration_code = 'DROP TABLE IF EXISTS sessions;'
        threats = trie.find_all_threats(migration_code, filename="migration.sql")
        assert len(threats) == 0
