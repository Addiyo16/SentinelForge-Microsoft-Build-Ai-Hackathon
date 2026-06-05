"""
SentinelForge — Polyglot Trie-based Threat Signature Engine
Supports multi-language pattern matching with confidence and severity metrics.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class ThreatMatch:
    pattern: str
    category: str
    severity: str  # critical | high | medium | low
    cwe_id: str
    confidence: float


class TrieNode:
    def __init__(self):
        self.children: dict[str, "TrieNode"] = {}
        self.is_end: bool = False
        self.pattern: str = ""
        self.category: str = ""
        self.severity: str = ""
        self.cwe_id: str = ""
        self.confidence: float = 0.0


class ThreatTrie:
    """
    Aho-Corasick-inspired trie for fast multi-pattern threat detection.
    Supports overlapping matches and partial pattern scoring.
    """

    SIGNATURES: list[dict] = [
        # --- Python Vulnerabilities ---
        {"pattern": "eval(", "category": "Python Code Injection", "severity": "critical", "cwe": "CWE-94", "conf": 0.95},
        {"pattern": "exec(", "category": "Python Code Injection", "severity": "critical", "cwe": "CWE-94", "conf": 0.94},
        {"pattern": "os.system(", "category": "OS Command Injection", "severity": "critical", "cwe": "CWE-78", "conf": 0.98},
        {"pattern": "subprocess.call(", "category": "OS Command Injection", "severity": "high", "cwe": "CWE-78", "conf": 0.90},
        {"pattern": "pickle.loads(", "category": "Insecure Deserialization", "severity": "critical", "cwe": "CWE-502", "conf": 0.99},
        {"pattern": "yaml.load(", "category": "Insecure YAML Deserialization", "severity": "high", "cwe": "CWE-502", "conf": 0.95},
        
        # --- JavaScript / TypeScript Vulnerabilities ---
        {"pattern": "child_process.exec(", "category": "Node.js Command Injection", "severity": "critical", "cwe": "CWE-78", "conf": 0.96},
        {"pattern": "dangerouslySetInnerHTML", "category": "React XSS Risk", "severity": "high", "cwe": "CWE-79", "conf": 0.92},
        {"pattern": "eval(req.query", "category": "Dynamic RCE Vector", "severity": "critical", "cwe": "CWE-95", "conf": 0.99},

        # --- Java Vulnerabilities ---
        {"pattern": "Runtime.getRuntime().exec(", "category": "Java Command Injection", "severity": "critical", "cwe": "CWE-78", "conf": 0.97},
        {"pattern": "ProcessBuilder(", "category": "Java External Process Creation", "severity": "high", "cwe": "CWE-78", "conf": 0.88},
        {"pattern": "ObjectInputStream.readObject(", "category": "Java Insecure Deserialization", "severity": "critical", "cwe": "CWE-502", "conf": 0.96},

        # --- C/C++ Vulnerabilities ---
        {"pattern": "strcpy(", "category": "C Buffer Overflow Risk", "severity": "high", "cwe": "CWE-120", "conf": 0.85},
        {"pattern": "gets(", "category": "C Deprecated Vulnerable Call", "severity": "critical", "cwe": "CWE-242", "conf": 0.99},
        {"pattern": "sprintf(buf,", "category": "C Format String Vulnerability", "severity": "high", "cwe": "CWE-134", "conf": 0.80},
        {"pattern": "system(", "category": "C Command Execution", "severity": "critical", "cwe": "CWE-78", "conf": 0.90},

        # --- Go Vulnerabilities ---
        {"pattern": "unsafe.Pointer", "category": "Go Memory Safety Bypass", "severity": "medium", "cwe": "CWE-119", "conf": 0.70},
        {"pattern": "exec.Command(", "category": "Go OS Shell Execution", "severity": "high", "cwe": "CWE-78", "conf": 0.85},

        # --- SQL Injection (Generic) ---
        {"pattern": "' OR '1'='1", "category": "SQL Injection Pattern", "severity": "critical", "cwe": "CWE-89", "conf": 0.99},
        {"pattern": "DROP TABLE", "category": "SQL Destructive Query", "severity": "critical", "cwe": "CWE-89", "conf": 0.95},
        {"pattern": "UNION SELECT", "category": "SQL Data Exfiltration Query", "severity": "critical", "cwe": "CWE-89", "conf": 0.97},

        # --- Secrets & Hardcoded Credentials ---
        {"pattern": "password =", "category": "Potential Hardcoded Credential", "severity": "high", "cwe": "CWE-798", "conf": 0.82},
        {"pattern": "api_key =", "category": "Potential Hardcoded Secret", "severity": "critical", "cwe": "CWE-798", "conf": 0.88},
        {"pattern": "secret =", "category": "Potential Hardcoded Secret", "severity": "high", "cwe": "CWE-798", "conf": 0.80},
        {"pattern": "token =", "category": "Potential Hardcoded Token", "severity": "high", "cwe": "CWE-798", "conf": 0.78},

        # --- DevOps / CI/CD Workflow Vulnerabilities ---
        {"pattern": "chmod 777", "category": "Overly Permissive File Permissions", "severity": "high", "cwe": "CWE-732", "conf": 0.92},
        {"pattern": "run: |", "category": "DevOps Pipeline Execution Block", "severity": "info", "cwe": "CWE-1104", "conf": 0.40},
        {"pattern": "USER root", "category": "Container Root Execution Risk", "severity": "high", "cwe": "CWE-250", "conf": 0.90},
    ]

    def __init__(self):
        self.root = TrieNode()
        self._build()

    def _build(self):
        for sig in self.SIGNATURES:
            self._insert(
                sig["pattern"],
                sig["category"],
                sig["severity"],
                sig["cwe"],
                sig["conf"],
            )

    def _insert(self, pattern: str, category: str, severity: str, cwe: str, conf: float):
        node = self.root
        for ch in pattern:
            node = node.children.setdefault(ch, TrieNode())
        node.is_end = True
        node.pattern = pattern
        node.category = category
        node.severity = severity
        node.cwe_id = cwe
        node.confidence = conf

    def find_all_threats(self, code: str) -> list[ThreatMatch]:
        """Scan code for all threat patterns. Returns deduplicated matches."""
        seen: set[str] = set()
        results: list[ThreatMatch] = []

        for start in range(len(code)):
            node = self.root
            for i in range(start, len(code)):
                ch = code[i]
                if ch not in node.children:
                    break
                node = node.children[ch]
                if node.is_end and node.pattern not in seen:
                    seen.add(node.pattern)
                    results.append(
                        ThreatMatch(
                            pattern=node.pattern,
                            category=node.category,
                            severity=node.severity,
                            cwe_id=node.cwe_id,
                            confidence=node.confidence,
                        )
                    )

        # Sort by severity: critical > high > medium > low > info
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        results.sort(key=lambda m: severity_order.get(m.severity, 9))
        return results
