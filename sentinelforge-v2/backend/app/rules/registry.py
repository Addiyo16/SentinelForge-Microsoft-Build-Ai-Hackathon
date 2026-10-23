"""
SentinelForge — Versioned Security Rule Registry & Finding Lifecycle Engine
Version: 2.1.0

Features:
  - Versioned catalog of security rules with unique IDs, CWE mappings, severities, and remediation guidance.
  - Multi-engine finding deduplication (AST + Aho-Corasick Trie + Data-flow).
  - Explicit finding lifecycle tracking: CONFIRMED, SUSPECTED, FALSE_POSITIVE, FIXED, UNRESOLVED.
  - Evidence and code context traceability.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Any


RULE_REGISTRY_VERSION = "2.1.0"


class FindingStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    SUSPECTED = "SUSPECTED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    FIXED = "FIXED"
    UNRESOLVED = "UNRESOLVED"


@dataclass
class SecurityRule:
    rule_id: str
    name: str
    category: str
    severity: str           # critical | high | medium | low | info
    language: str           # python | javascript | java | c_cpp | go | yaml | polyglot
    cwe_id: str             # e.g. "CWE-502"
    description: str
    remediation: str
    pattern: Optional[str] = None
    detection_source: str = "ast"  # ast | pattern | dataflow
    confidence: float = 0.90

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "language": self.language,
            "cwe_id": self.cwe_id,
            "description": self.description,
            "remediation": self.remediation,
            "pattern": self.pattern,
            "detection_source": self.detection_source,
            "confidence": self.confidence,
        }


@dataclass
class UnifiedFinding:
    id: str
    rule_id: str
    title: str
    category: str
    severity: str
    cwe_id: str
    file_path: str
    line: int
    col: int
    evidence: str
    description: str
    remediation: str
    detection_sources: list[str] = field(default_factory=lambda: ["ast"])
    status: FindingStatus = FindingStatus.SUSPECTED
    ml_score: int = 50
    ml_verdict: str = "POTENTIAL_FALSE_POSITIVE"
    ml_priority_tier: str = "MEDIUM_RISK"
    ml_rationale: str = ""
    ml_probability: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "cwe_id": self.cwe_id,
            "file_path": self.file_path,
            "line": self.line,
            "col": self.col,
            "evidence": self.evidence,
            "description": self.description,
            "remediation": self.remediation,
            "detection_sources": self.detection_sources,
            "status": self.status.value if isinstance(self.status, FindingStatus) else str(self.status),
            "ml_score": self.ml_score,
            "ml_verdict": self.ml_verdict,
            "ml_priority_tier": self.ml_priority_tier,
            "ml_rationale": self.ml_rationale,
            "ml_probability": self.ml_probability,
        }


class RuleRegistry:
    """
    Central, versioned registry of security rules.
    """

    def __init__(self):
        self._rules: dict[str, SecurityRule] = {}
        self._load_default_rules()

    def _load_default_rules(self):
        default_rules = [
            # ── Python Rules ──
            SecurityRule(
                rule_id="SF-PY-001",
                name="Insecure Pickle Deserialization",
                category="Insecure Deserialization",
                severity="critical",
                language="python",
                cwe_id="CWE-502",
                description="Unpickling untrusted data can lead to arbitrary code execution via __reduce__ exploit payloads.",
                remediation="Use secure serialization formats like JSON, Protocol Buffers, or HMAC-signed payloads with strict schemas.",
                pattern="pickle.loads(",
                detection_source="ast+pattern",
                confidence=0.99,
            ),
            SecurityRule(
                rule_id="SF-PY-002",
                name="OS Command Injection",
                category="Command Injection",
                severity="critical",
                language="python",
                cwe_id="CWE-78",
                description="Executing shell commands with unescaped input allows attackers to execute arbitrary system commands.",
                remediation="Use subprocess.run() with shell=False and pass arguments as a structured list, or use shlex.quote().",
                pattern="os.system(",
                detection_source="ast+pattern",
                confidence=0.98,
            ),
            SecurityRule(
                rule_id="SF-PY-003",
                name="Dynamic Python Code Execution",
                category="Code Injection",
                severity="critical",
                language="python",
                cwe_id="CWE-94",
                description="The eval() or exec() builtins execute arbitrary Python code within current process scope.",
                remediation="Replace dynamic evaluation with ast.literal_eval() for data, or define an explicit parser.",
                pattern="eval(",
                detection_source="ast+pattern",
                confidence=0.95,
            ),
            SecurityRule(
                rule_id="SF-PY-004",
                name="Insecure YAML Deserialization",
                category="Insecure Deserialization",
                severity="high",
                language="python",
                cwe_id="CWE-502",
                description="Calling yaml.load() without SafeLoader allows instantiation of arbitrary Python objects.",
                remediation="Always use yaml.safe_load(data) or yaml.load(data, Loader=yaml.SafeLoader).",
                pattern="yaml.load(",
                detection_source="ast+pattern",
                confidence=0.95,
            ),
            SecurityRule(
                rule_id="SF-PY-005",
                name="Insecure Temporary File Creation",
                category="Insecure File Operations",
                severity="medium",
                language="python",
                cwe_id="CWE-377",
                description="tempfile.mktemp() is vulnerable to symlink race conditions between name generation and file creation.",
                remediation="Use tempfile.NamedTemporaryFile() or tempfile.TemporaryDirectory() with appropriate permission masks.",
                pattern="tempfile.mktemp(",
                detection_source="ast",
                confidence=0.88,
            ),
            SecurityRule(
                rule_id="SF-PY-006",
                name="Weak Cryptographic Hash",
                category="Cryptographic Weakness",
                severity="medium",
                language="python",
                cwe_id="CWE-328",
                description="MD5 and SHA-1 have known collision vulnerabilities and should not be used for security purposes.",
                remediation="Upgrade to SHA-256, SHA-3, or bcrypt/argon2 for password hashing.",
                pattern="hashlib.md5(",
                detection_source="ast",
                confidence=0.85,
            ),
            SecurityRule(
                rule_id="SF-PY-007",
                name="Insecure File Permissions",
                category="Insecure Permissions",
                severity="high",
                language="python",
                cwe_id="CWE-732",
                description="Setting file permissions to world-writable (0o777) allows any local process to modify sensitive files.",
                remediation="Restrict permissions to owner read/write (0o600) or owner read/write/execute (0o700).",
                pattern="chmod(0o777)",
                detection_source="ast",
                confidence=0.90,
            ),

            # ── JavaScript / TypeScript Rules ──
            SecurityRule(
                rule_id="SF-JS-001",
                name="Dynamic JavaScript Code Evaluation",
                category="Code Injection",
                severity="critical",
                language="javascript",
                cwe_id="CWE-95",
                description="eval() and Function() evaluate arbitrary code strings with elevated privileges.",
                remediation="Avoid eval(). Parse structured JSON using JSON.parse() and use explicit dispatch tables.",
                pattern="eval(",
                detection_source="ast+pattern",
                confidence=0.94,
            ),
            SecurityRule(
                rule_id="SF-JS-002",
                name="Node.js Command Injection",
                category="Command Injection",
                severity="critical",
                language="javascript",
                cwe_id="CWE-78",
                description="child_process.exec invokes a system shell, enabling command injection via shell metacharacters.",
                remediation="Use child_process.execFile() or child_process.spawn() with an argument array and shell: false.",
                pattern="child_process.exec(",
                detection_source="ast+pattern",
                confidence=0.96,
            ),
            SecurityRule(
                rule_id="SF-JS-003",
                name="React Cross-Site Scripting (XSS)",
                category="Cross-Site Scripting",
                severity="high",
                language="javascript",
                cwe_id="CWE-79",
                description="dangerouslySetInnerHTML injects unescaped HTML directly into DOM nodes.",
                remediation="Sanitize raw HTML using DOMPurify before rendering, or prefer native JSX element interpolation.",
                pattern="dangerouslySetInnerHTML",
                detection_source="ast+pattern",
                confidence=0.92,
            ),
            SecurityRule(
                rule_id="SF-JS-004",
                name="DOM-based Cross-Site Scripting",
                category="Cross-Site Scripting",
                severity="medium",
                language="javascript",
                cwe_id="CWE-79",
                description="Writing unescaped data via document.write() or innerHTML allows DOM-based XSS attacks.",
                remediation="Use textContent or innerText, or sanitize inputs with DOMPurify.",
                pattern="document.write(",
                detection_source="ast+pattern",
                confidence=0.85,
            ),

            # ── Java Rules ──
            SecurityRule(
                rule_id="SF-JV-001",
                name="Java Command Injection",
                category="Command Injection",
                severity="critical",
                language="java",
                cwe_id="CWE-78",
                description="Runtime.exec() executes system commands without parameterization.",
                remediation="Use ProcessBuilder with parameterized arguments and validate all inputs.",
                pattern="Runtime.getRuntime().exec(",
                detection_source="ast+pattern",
                confidence=0.96,
            ),
            SecurityRule(
                rule_id="SF-JV-002",
                name="Java Insecure Deserialization",
                category="Insecure Deserialization",
                severity="critical",
                language="java",
                cwe_id="CWE-502",
                description="ObjectInputStream.readObject() deserializes untrusted streams, allowing gadget chain execution.",
                remediation="Use look-ahead deserialization filters (ValidatingObjectInputStream) or JSON/Protobuf.",
                pattern="readObject(",
                detection_source="ast+pattern",
                confidence=0.97,
            ),
            SecurityRule(
                rule_id="AST-SEC-JAVA-002",
                name="Java Insecure Deserialization",
                category="Insecure Deserialization",
                severity="critical",
                language="java",
                cwe_id="CWE-502",
                description="ObjectInputStream.readObject() deserializes untrusted streams, allowing gadget chain execution.",
                remediation="Use look-ahead deserialization filters (ValidatingObjectInputStream) or JSON/Protobuf.",
                pattern="readObject(",
                detection_source="ast",
                confidence=0.97,
            ),

            # ── C / C++ Rules ──
            SecurityRule(
                rule_id="SF-CP-001",
                name="Unbounded Memory Copy",
                category="Buffer Overflow",
                severity="high",
                language="c_cpp",
                cwe_id="CWE-120",
                description="strcpy() does not check destination buffer boundaries, causing stack or heap buffer overflow.",
                remediation="Use strncpy() with bounded lengths or C11 safe alternatives like strcpy_s().",
                pattern="strcpy(",
                detection_source="pattern",
                confidence=0.88,
            ),
            SecurityRule(
                rule_id="SF-CP-002",
                name="Dangerous Deprecated Input Function",
                category="Buffer Overflow",
                severity="critical",
                language="c_cpp",
                cwe_id="CWE-242",
                description="gets() is inherently vulnerable to buffer overflows as it lacks length constraints.",
                remediation="Replace with fgets() specifying exact buffer capacity.",
                pattern="gets(",
                detection_source="pattern",
                confidence=0.99,
            ),

            # ── Go Rules ──
            SecurityRule(
                rule_id="SF-GO-001",
                name="Unsafe Pointer Memory Access",
                category="Memory Safety Bypass",
                severity="medium",
                language="go",
                cwe_id="CWE-119",
                description="unsafe.Pointer circumvents Go type safety and garbage collector protections.",
                remediation="Avoid unsafe.Pointer unless strictly necessary in low-level runtime code.",
                pattern="unsafe.Pointer",
                detection_source="pattern",
                confidence=0.75,
            ),

            # ── DevOps / YAML Workflow Rules ──
            SecurityRule(
                rule_id="SF-OPS-001",
                name="Overly Permissive File Permissions (YAML/DevOps)",
                category="Insecure Permissions",
                severity="high",
                language="yaml",
                cwe_id="CWE-732",
                description="chmod 777 grants world-writable permissions in deployment workflows or container initialization scripts.",
                remediation="Restrict permissions to least-privilege mode (chmod 600 or chmod 750).",
                pattern="chmod 777",
                detection_source="ast+pattern",
                confidence=0.92,
            ),
            SecurityRule(
                rule_id="AST-SEC-OPS-001",
                name="Overly Permissive File Permissions (YAML/DevOps)",
                category="Insecure Permissions",
                severity="high",
                language="yaml",
                cwe_id="CWE-732",
                description="chmod 777 configured in pipeline violates least privilege principles.",
                remediation="Restrict file permissions to specific required user/group (e.g. chmod 750 or 600).",
                pattern="chmod 777",
                detection_source="ast+pattern",
                confidence=0.92,
            ),
            SecurityRule(
                rule_id="SF-OPS-002",
                name="Privileged Container Execution",
                category="Privilege Management",
                severity="high",
                language="yaml",
                cwe_id="CWE-250",
                description="Container or workflow step configured to execute with elevated root privileges.",
                remediation="Execute pipeline steps under least-privilege non-root service accounts and set privileged: false.",
                pattern="USER root",
                detection_source="ast+pattern",
                confidence=0.90,
            ),

            # ── Algorithmic Complexity / Performance Rules ──
            SecurityRule(
                rule_id="AST-PERF-001",
                name="Algorithmic Complexity Resource Exhaustion",
                category="Algorithmic Complexity",
                severity="high",
                language="polyglot",
                cwe_id="CWE-400",
                description="Unconstrained nested loop iteration yields quadratic O(N^2) or worse execution complexity, creating an asymptotic CPU resource exhaustion vector.",
                remediation="Refactor nested iteration using hash maps, lookup dictionaries, or indexed sets to reduce time complexity to linear O(N).",
                pattern="",
                detection_source="ast",
                confidence=0.88,
            ),

            # ── Polyglot Secrets & SQLi ──
            SecurityRule(
                rule_id="SF-SEC-001",
                name="Hardcoded Secret or API Key",
                category="Hardcoded Secrets",
                severity="critical",
                language="polyglot",
                cwe_id="CWE-798",
                description="Hardcoded API keys, tokens, or private secrets committed to source repositories.",
                remediation="Extract credentials to environment variables or secret vaults (e.g. Azure Key Vault, HashiCorp Vault).",
                pattern="api_key =",
                detection_source="pattern",
                confidence=0.88,
            ),
            SecurityRule(
                rule_id="SF-SEC-002",
                name="Hardcoded Password",
                category="Hardcoded Secrets",
                severity="high",
                language="polyglot",
                cwe_id="CWE-798",
                description="Hardcoded plaintext passwords discovered in configuration or source code.",
                remediation="Use secrets managers and inject passwords via secure environment variables at runtime.",
                pattern="password =",
                detection_source="pattern",
                confidence=0.82,
            ),
            SecurityRule(
                rule_id="SF-SEC-003",
                name="SQL Injection Pattern",
                category="SQL Injection",
                severity="critical",
                language="polyglot",
                cwe_id="CWE-89",
                description="Dynamic query construction or unescaped SQL fragments allow database compromise.",
                remediation="Use parameterized queries, prepared statements, or an ORM with automatic query binding.",
                pattern="' OR '1'='1",
                detection_source="pattern",
                confidence=0.98,
            ),
        ]

        for rule in default_rules:
            self._rules[rule.rule_id] = rule

    def get_rule(self, rule_id: str) -> Optional[SecurityRule]:
        return self._rules.get(rule_id)

    def find_rule_by_pattern_or_cwe(self, pattern: str = "", cwe_id: str = "", language: str = "") -> Optional[SecurityRule]:
        """Find best matching rule in the registry enforcing strict language affinity."""
        p_clean = pattern.lower().strip()
        cwe_clean = cwe_id.upper().strip()
        lang_clean = language.lower().strip() if language else ""

        # Normalize language aliases
        if lang_clean in ("py", "python3"):
            lang_clean = "python"
        elif lang_clean in ("js", "ts", "typescript", "jsx", "tsx"):
            lang_clean = "javascript"
        elif lang_clean in ("c", "c++", "cpp"):
            lang_clean = "c_cpp"
        elif lang_clean in ("yml",):
            lang_clean = "yaml"

        # 1. Match direct rule_id if pattern is a registered rule_id
        if pattern in self._rules:
            r = self._rules[pattern]
            if not lang_clean or r.language in (lang_clean, "polyglot"):
                return r

        # 2. Match exact pattern within matching language
        if p_clean:
            if lang_clean:
                for rule in self._rules.values():
                    if rule.pattern and rule.pattern.lower().strip() in p_clean:
                        if rule.language == lang_clean:
                            return rule
            # Match pattern in polyglot rules
            for rule in self._rules.values():
                if rule.pattern and rule.pattern.lower().strip() in p_clean:
                    if rule.language == "polyglot" or not lang_clean:
                        return rule

        # 3. Match CWE + exact language first
        if cwe_clean and lang_clean:
            for rule in self._rules.values():
                if rule.cwe_id == cwe_clean and rule.language == lang_clean:
                    return rule

        # 4. Match CWE + polyglot
        if cwe_clean:
            for rule in self._rules.values():
                if rule.cwe_id == cwe_clean and rule.language == "polyglot":
                    return rule

        # 5. If language was unspecified, match any rule with the CWE
        if cwe_clean and not lang_clean:
            for rule in self._rules.values():
                if rule.cwe_id == cwe_clean:
                    return rule

        return None

    def list_rules(self, language: Optional[str] = None) -> list[SecurityRule]:
        if not language:
            return list(self._rules.values())
        return [r for r in self._rules.values() if r.language in (language, "polyglot")]


# Global registry instance
_registry = RuleRegistry()


def get_rule_registry() -> RuleRegistry:
    return _registry


def deduplicate_findings(
    raw_findings: list[dict],
    cwe_proximity_tolerance: int = 1,
) -> list[dict]:
    """
    Deduplicate security findings generated across multiple detection engines (AST, Trie, Regex).
    Merges duplicate findings occurring on the same file and line into a unified evidence finding.
    Boosts confidence and sets status to CONFIRMED when multiple independent engines detect the issue.
    """
    registry = get_rule_registry()
    groups: dict[tuple[str, int, str], list[dict]] = {}

    for f in raw_findings:
        file_path = f.get("source_file") or f.get("filename") or f.get("file_path") or "code.py"
        fp_lower = file_path.lower()
        r_id = str(f.get("rule_id") or "")
        cwe = str(f.get("cwe_id") or "CWE-Unknown").upper()
        desc = str(f.get("description") or "").lower()
        node_t = str(f.get("node_type") or "").lower()

        # Reject AST-PERF-001 / loop complexity findings on declarative configuration / markup files
        is_declarative_file = fp_lower.endswith((".yml", ".yaml", ".json", ".toml", ".xml", ".ini", ".cfg", ".md", ".txt"))
        if is_declarative_file:
            if r_id == "AST-PERF-001" or node_t == "nestedloop" or "nested loop" in desc or (cwe == "CWE-400" and "loop" in desc):
                continue

        line = int(f.get("line") or 1)
        # Canonical key: (file, line, cwe)
        key = (file_path, line, cwe)

        # Check for proximity tolerance (within +- 1 line) with identical CWE
        matched_key = None
        for (g_file, g_line, g_cwe) in groups.keys():
            if g_file == file_path and g_cwe == cwe and abs(g_line - line) <= cwe_proximity_tolerance:
                matched_key = (g_file, g_line, g_cwe)
                break

        if matched_key:
            groups[matched_key].append(f)
        else:
            groups[key] = [f]

    deduped: list[dict] = []
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    for (file_path, line, cwe), items in groups.items():
        sample_item = items[0]
        fp_lower = file_path.lower()

        # Infer language from item or file path
        item_lang = sample_item.get("language") or ""
        if not item_lang and file_path:
            if fp_lower.endswith(".java"):
                item_lang = "java"
            elif fp_lower.endswith((".py", ".pyw")):
                item_lang = "python"
            elif fp_lower.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs")):
                item_lang = "javascript"
            elif fp_lower.endswith((".c", ".cpp", ".cc", ".cxx", ".h", ".hpp")):
                item_lang = "c_cpp"
            elif fp_lower.endswith(".go"):
                item_lang = "go"
            elif fp_lower.endswith((".yml", ".yaml")):
                item_lang = "yaml"

        # Combine detection sources
        sources = list(dict.fromkeys(
            item.get("source") or item.get("detection_source") or "ast"
            for item in items
        ))

        # Highest severity among duplicates
        highest_sev = max(
            (item.get("severity", "medium").lower() for item in items),
            key=lambda s: sev_rank.get(s, 2)
        )

        # Find best rule from registry with strict language affinity
        pattern_str = sample_item.get("pattern") or sample_item.get("rule_id") or ""
        rule = registry.find_rule_by_pattern_or_cwe(
            pattern=pattern_str,
            cwe_id=cwe,
            language=item_lang,
        )

        # Disallow cross-language rule misattribution
        if rule and item_lang:
            if rule.language not in (item_lang, "polyglot"):
                rule = None

        # Special case: Java Insecure Deserialization (CWE-502) must NEVER map to Python pickle
        if fp_lower.endswith(".java") and cwe == "CWE-502":
            rule = registry.get_rule("SF-JV-002") or registry.get_rule("AST-SEC-JAVA-002") or rule

        rule_id = rule.rule_id if rule else (sample_item.get("rule_id") or f"SF-GEN-{cwe}")
        remediation = rule.remediation if rule else sample_item.get("suggestion", "Review code and apply secure coding best practices.")
        description = rule.description if rule else sample_item.get("description", "Security vulnerability detected.")
        title = rule.name if rule else sample_item.get("title", sample_item.get("category", "Security Finding"))
        category = rule.category if rule else sample_item.get("category", "General Security")

        # Best evidence string
        evidence = next(
            (item.get("evidence") or item.get("snippet") for item in items if item.get("evidence") or item.get("snippet")),
            ""
        )

        # Maximum ML score & priority
        max_ml_score = max(int(item.get("ml_score", 50)) for item in items)
        ml_verdict = "CONFIRMED_VULNERABILITY" if max_ml_score >= 50 else "POTENTIAL_FALSE_POSITIVE"
        ml_priority_tier = items[0].get("ml_priority_tier", "MEDIUM_RISK")
        ml_rationale = items[0].get("ml_rationale", "")
        ml_prob = max(float(item.get("ml_probability", 0.5)) for item in items)

        # Multi-engine consensus elevates status to CONFIRMED
        if len(sources) > 1 or max_ml_score >= 65:
            status = FindingStatus.CONFIRMED
        else:
            status = FindingStatus.SUSPECTED

        finding = UnifiedFinding(
            id=f"{rule_id}-{line}",
            rule_id=rule_id,
            title=title,
            category=rule.category if rule else sample_item.get("category", "General Security"),
            severity=highest_sev,
            cwe_id=cwe,
            file_path=file_path,
            line=line,
            col=int(sample_item.get("col", 1)),
            evidence=evidence,
            description=description,
            remediation=remediation,
            detection_sources=sources,
            status=status,
            ml_score=max_ml_score,
            ml_verdict=ml_verdict,
            ml_priority_tier=ml_priority_tier,
            ml_rationale=ml_rationale,
            ml_probability=ml_prob,
        )
        deduped.append(finding.to_dict())

    # Sort descending by priority score
    deduped.sort(key=lambda x: x.get("ml_score", 0), reverse=True)
    return deduped
