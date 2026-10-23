"""
SentinelForge — Polyglot Aho-Corasick Threat Signature Engine
Provides O(n + z) multi-pattern keyword scanning across polyglot source code.
Returns precise source locations (line, col, end_line, end_col), snippets, CWE IDs, and severities.
"""

from collections import deque
from dataclasses import dataclass, field
import bisect
from typing import Optional, List, Dict, Any


@dataclass
class ThreatMatch:
    pattern: str
    category: str
    severity: str  # critical | high | medium | low | info
    cwe_id: str
    confidence: float
    start_pos: int = 0
    end_pos: int = 0
    line: int = 1
    col: int = 1
    end_line: int = 1
    end_col: int = 1
    snippet: str = ""
    source_file: str = ""
    is_false_positive: bool = False
    false_positive_reason: str = ""


@dataclass
class SignatureMeta:
    pattern: str
    category: str
    severity: str
    cwe_id: str
    confidence: float


class TrieNode:
    __slots__ = ("children", "fail", "outputs")

    def __init__(self):
        self.children: dict[str, "TrieNode"] = {}
        self.fail: Optional["TrieNode"] = None
        self.outputs: list[SignatureMeta] = []


class ThreatTrie:
    """
    Aho-Corasick multi-pattern string matching automaton.
    Preprocesses signatures into a trie with failure and dictionary transitions.
    Complexity:
      - Build: O(M) where M is sum of pattern lengths.
      - Search: O(N + z) where N is text length and z is number of matches.
    """

    SIGNATURES: list[dict] = [
        # --- Python Vulnerabilities ---
        {"pattern": "eval(", "category": "Python Code Injection", "severity": "critical", "cwe": "CWE-94", "conf": 0.95},
        {"pattern": "exec(", "category": "Python Code Injection", "severity": "critical", "cwe": "CWE-94", "conf": 0.94},
        {"pattern": "os.system(", "category": "OS Command Injection", "severity": "critical", "cwe": "CWE-78", "conf": 0.98},
        {"pattern": "subprocess.call(", "category": "OS Command Injection", "severity": "high", "cwe": "CWE-78", "conf": 0.90},
        {"pattern": "subprocess.Popen(", "category": "OS Process Spawning", "severity": "high", "cwe": "CWE-78", "conf": 0.88},
        {"pattern": "pickle.loads(", "category": "Insecure Deserialization", "severity": "critical", "cwe": "CWE-502", "conf": 0.99},
        {"pattern": "pickle.load(", "category": "Insecure Deserialization", "severity": "critical", "cwe": "CWE-502", "conf": 0.99},
        {"pattern": "yaml.load(", "category": "Insecure YAML Deserialization", "severity": "high", "cwe": "CWE-502", "conf": 0.95},
        {"pattern": "__import__(", "category": "Dynamic Python Import Injection", "severity": "high", "cwe": "CWE-94", "conf": 0.90},
        
        # --- JavaScript / TypeScript Vulnerabilities ---
        {"pattern": "child_process.exec(", "category": "Node.js Command Injection", "severity": "critical", "cwe": "CWE-78", "conf": 0.96},
        {"pattern": "child_process.spawn(", "category": "Node.js Process Execution", "severity": "high", "cwe": "CWE-78", "conf": 0.85},
        {"pattern": "dangerouslySetInnerHTML", "category": "React XSS Risk", "severity": "high", "cwe": "CWE-79", "conf": 0.92},
        {"pattern": "eval(req.query", "category": "Dynamic RCE Vector", "severity": "critical", "cwe": "CWE-95", "conf": 0.99},
        {"pattern": "document.write(", "category": "DOM-based XSS Risk", "severity": "medium", "cwe": "CWE-79", "conf": 0.82},

        # --- Java Vulnerabilities ---
        {"pattern": "Runtime.getRuntime().exec(", "category": "Java Command Injection", "severity": "critical", "cwe": "CWE-78", "conf": 0.97},
        {"pattern": "ProcessBuilder(", "category": "Java External Process Creation", "severity": "high", "cwe": "CWE-78", "conf": 0.88},
        {"pattern": "ObjectInputStream.readObject(", "category": "Java Insecure Deserialization", "severity": "critical", "cwe": "CWE-502", "conf": 0.96},
        {"pattern": "readObject(", "category": "Java Insecure Deserialization", "severity": "critical", "cwe": "CWE-502", "conf": 0.96},
        {"pattern": "XMLDecoder.readObject(", "category": "Java XML Deserialization", "severity": "high", "cwe": "CWE-502", "conf": 0.90},

        # --- C/C++ Vulnerabilities ---
        {"pattern": "strcpy(", "category": "C Buffer Overflow Risk", "severity": "high", "cwe": "CWE-120", "conf": 0.85},
        {"pattern": "gets(", "category": "C Deprecated Vulnerable Call", "severity": "critical", "cwe": "CWE-242", "conf": 0.99},
        {"pattern": "sprintf(buf,", "category": "C Format String Vulnerability", "severity": "high", "cwe": "CWE-134", "conf": 0.80},
        {"pattern": "system(", "category": "C Command Execution", "severity": "critical", "cwe": "CWE-78", "conf": 0.90},
        {"pattern": "strcat(", "category": "C Buffer Overflow Risk", "severity": "high", "cwe": "CWE-120", "conf": 0.85},

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
        {"pattern": "-----BEGIN RSA PRIVATE KEY-----", "category": "Exposed Private Key", "severity": "critical", "cwe": "CWE-312", "conf": 0.99},

        # --- DevOps / CI/CD Workflow Vulnerabilities ---
        {"pattern": "chmod 777", "category": "Overly Permissive File Permissions", "severity": "high", "cwe": "CWE-732", "conf": 0.92},
        {"pattern": "run: |", "category": "DevOps Pipeline Execution Block", "severity": "info", "cwe": "CWE-1104", "conf": 0.40},
        {"pattern": "USER root", "category": "Container Root Execution Risk", "severity": "high", "cwe": "CWE-250", "conf": 0.90},
        {"pattern": "curl | bash", "category": "Insecure Remote Script Execution", "severity": "critical", "cwe": "CWE-494", "conf": 0.95},
    ]

    def __init__(self, custom_signatures: Optional[list[dict]] = None):
        self.root = TrieNode()
        self._signatures = custom_signatures if custom_signatures is not None else self.SIGNATURES
        self._build()

    def _build(self):
        """Construct the trie and build failure and output links via BFS."""
        for sig in self._signatures:
            self._insert(
                sig["pattern"],
                sig["category"],
                sig["severity"],
                sig["cwe"],
                sig["conf"],
            )
        self._build_automaton()

    def _insert(self, pattern: str, category: str, severity: str, cwe: str, conf: float):
        """Insert a single pattern into the keyword trie."""
        if not pattern:
            return
        node = self.root
        for ch in pattern:
            node = node.children.setdefault(ch, TrieNode())
        node.outputs.append(
            SignatureMeta(
                pattern=pattern,
                category=category,
                severity=severity,
                cwe_id=cwe,
                confidence=conf,
            )
        )

    def insert(
        self,
        pattern: str,
        category: str = "General",
        severity: str = "medium",
        cwe_id: str = "CWE-Unknown",
        conf: float = 0.9,
    ) -> None:
        """Insert a single pattern into the trie and rebuild automaton."""
        self._insert(pattern, category, severity, cwe_id, conf)
        self._build_automaton()

    def _build_automaton(self):
        """
        Build BFS failure links f(u) and dictionary links.
        Guarantees O(n + z) linear scan complexity.
        """
        queue: deque[TrieNode] = deque()

        # Direct children of root have failure link = root
        for child in self.root.children.values():
            child.fail = self.root
            queue.append(child)

        while queue:
            curr = queue.popleft()
            for ch, child in curr.children.items():
                # Follow failure transitions until matching child or root
                f = curr.fail
                while f is not None and ch not in f.children:
                    f = f.fail
                child.fail = f.children[ch] if f and ch in f.children else self.root

                # Output/dictionary link: inherit outputs from suffix state
                if child.fail and child.fail.outputs:
                    child.outputs.extend(child.fail.outputs)

                queue.append(child)

    def find_all_matches(self, code: str, filename: str = "") -> list[ThreatMatch]:
        """
        Scan code using Aho-Corasick automaton in O(n + z) time.
        Returns all threat matches including multiple occurrences across the file,
        each annotated with exact line, column, end_line, end_col, code snippet, and contextual FP analysis.
        """
        if not code:
            return []

        lines = code.splitlines(keepends=True)
        line_offsets: list[int] = []
        curr_offset = 0
        for l in lines:
            line_offsets.append(curr_offset)
            curr_offset += len(l)

        def get_pos(char_idx: int) -> tuple[int, int, str]:
            if not line_offsets:
                return (1, 1, "")
            line_idx = bisect.bisect_right(line_offsets, char_idx) - 1
            line_idx = max(0, min(line_idx, len(line_offsets) - 1))
            col = char_idx - line_offsets[line_idx] + 1
            raw_line = lines[line_idx].rstrip("\r\n")
            return (line_idx + 1, col, raw_line)

        curr = self.root
        raw_matches: list[ThreatMatch] = []

        for i, ch in enumerate(code):
            while curr is not self.root and ch not in curr.children:
                curr = curr.fail or self.root
            curr = curr.children.get(ch, self.root)

            for sig in curr.outputs:
                start_pos = i - len(sig.pattern) + 1
                end_pos = i + 1
                start_line, start_col, snippet = get_pos(start_pos)
                end_line, end_col, _ = get_pos(max(0, end_pos - 1))

                is_fp, fp_reason = is_contextual_false_positive(
                    pattern=sig.pattern,
                    snippet=snippet,
                    full_code=code,
                    filename=filename,
                )

                raw_matches.append(
                    ThreatMatch(
                        pattern=sig.pattern,
                        category=sig.category,
                        severity=sig.severity if not is_fp else "info",
                        cwe_id=sig.cwe_id,
                        confidence=sig.confidence if not is_fp else 0.1,
                        start_pos=start_pos,
                        end_pos=end_pos,
                        line=start_line,
                        col=start_col,
                        end_line=end_line,
                        end_col=end_col,
                        snippet=snippet,
                        source_file=filename,
                        is_false_positive=is_fp,
                        false_positive_reason=fp_reason,
                    )
                )

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        raw_matches.sort(key=lambda m: (severity_order.get(m.severity, 9), m.line, m.col))
        return raw_matches

    def find_all_threats(
        self,
        code: str,
        filename: str = "",
        filter_false_positives: bool = True,
    ) -> list[ThreatMatch]:
        """
        Scan code for all threat patterns.
        Returns matches deduplicated by pattern (first occurrence location and evidence),
        sorted by severity (critical > high > medium > low > info).
        If filter_false_positives is True, filters out contextual false positives.
        """
        all_matches = self.find_all_matches(code, filename=filename)
        seen: set[str] = set()
        deduped: list[ThreatMatch] = []
        for m in all_matches:
            if filter_false_positives and m.is_false_positive:
                continue
            if m.pattern not in seen:
                seen.add(m.pattern)
                deduped.append(m)
        return deduped


def is_contextual_false_positive(
    pattern: str,
    snippet: str,
    full_code: str = "",
    filename: str = "",
) -> tuple[bool, str]:
    """
    Contextual analysis to distinguish exploitable vulnerabilities from benign patterns
    and false positives (e.g., local Swagger docs, SQLite placeholder credentials, env vars).
    Returns (is_fp: bool, rationale: str).
    """
    s_clean = snippet.strip()
    s_lower = s_clean.lower()
    fn_lower = filename.lower()

    # 0. Cross-Language False Positive Filtering
    if fn_lower:
        # Java source files: Python-specific and C-specific patterns are invalid
        if fn_lower.endswith(".java"):
            py_specific = ("pickle.loads(", "pickle.load(", "__import__(", "os.system(", "subprocess.call(", "subprocess.Popen(")
            if any(p in pattern for p in py_specific):
                return True, f"Python-specific pattern `{pattern}` is non-executable and invalid in Java source `{filename}`"
            c_specific = ("strcpy(", "gets(", "strcat(", "sprintf(buf,")
            if any(p in pattern for p in c_specific):
                return True, f"C-specific pattern `{pattern}` is non-executable and invalid in Java source `{filename}`"

        # Python source files: Java-specific and JS-specific patterns are invalid
        elif fn_lower.endswith((".py", ".pyw")):
            jv_specific = ("Runtime.getRuntime().exec(", "ObjectInputStream.readObject(", "XMLDecoder.readObject(")
            if any(p in pattern for p in jv_specific):
                return True, f"Java-specific pattern `{pattern}` is non-executable and invalid in Python source `{filename}`"
            js_specific = ("child_process.exec(", "child_process.spawn(", "dangerouslySetInnerHTML", "document.write(")
            if any(p in pattern for p in js_specific):
                return True, f"JavaScript-specific pattern `{pattern}` is non-executable and invalid in Python source `{filename}`"

        # Declarative configuration files: reject imperative runtime call patterns
        elif fn_lower.endswith((".yml", ".yaml", ".json", ".toml", ".xml", ".ini", ".cfg", ".md", ".txt")):
            imperative_patterns = ("pickle.loads(", "pickle.load(", "os.system(", "Runtime.getRuntime().exec(", "strcpy(", "gets(")
            if any(p in pattern for p in imperative_patterns):
                return True, f"Imperative code pattern `{pattern}` is non-executable in declarative config `{filename}`"

    # 1. OS Command execution checks (system() / platform.system)
    if pattern == "system(":
        if "platform.system" in s_lower:
            return True, "platform.system() queries operating system metadata (platform module), not OS command execution"
        if fn_lower.endswith((".py", ".pyw")):
            if "os.system" not in s_lower and "os.system" not in full_code.lower():
                return True, "Bare system() is not a valid Python command execution function (requires os.system)"

    # 2. YAML Deserialization checks (yaml.load)
    if pattern.startswith("yaml.load"):
        # SafeLoader in Python
        if any(loader in s_lower for loader in ("safeloader", "yaml.safeloader", "safedump", "baseloader")):
            return True, "Safe YAML loader explicitly configured (SafeLoader/BaseLoader)"
        # Local static file read (e.g. Swagger spec or config)
        if any(ind in s_lower for ind in (
            "readfilesync", "swagger", "openapi", "path.join", "__dirname",
            "./config", ".yaml", ".yml", "spec", "schema"
        )):
            return True, "yaml.load processes a static local file schema/spec (e.g. swagger/config), not untrusted remote input"

    # 3. Hardcoded Secret / Credential checks (password =, api_key =, secret =, token =)
    if pattern in ("password =", "api_key =", "secret =", "token ="):
        # Comments, docstrings, and documentation references
        if s_clean.startswith(("#", "//", "/*", "*", "'''", '"""')):
            return True, "Documentation, comment, or docstring reference, not an active credential assignment"

        # Comparison operations
        if any(op in s_clean for op in ("==", "!=", "<=", ">=")):
            return True, "Equality or comparison operator, not variable assignment"

        # Function definition parameters (e.g. def login(username, password=None):)
        if s_clean.startswith(("def ", "async def ", "function ", "func ", "public ", "private ", "protected ")) and "(" in s_clean:
            return True, "Function parameter declaration, not hardcoded secret"

        if "=" not in s_clean:
            return True, "Non-assignment credential reference"

        parts = s_clean.split("=", 1)
        lhs = parts[0].strip()
        rhs = parts[1].strip() if len(parts) > 1 else ""
        rhs_clean = rhs.rstrip(";, )")

        # Tuple unpacking or multiple assignment (e.g., `username, password = ...`)
        if "," in lhs:
            return True, "Tuple unpacking assignment, not a hardcoded secret literal"

        # Function call keyword argument passing (e.g., password=password, or password=None))
        if s_clean.endswith(",") and not ('"' in s_clean or "'" in s_clean):
            return True, "Function call keyword argument or variable reference"

        # If RHS is not a string literal (does not start with quote or byte quote)
        if not (rhs_clean.startswith(('"', "'", 'b"', "b'"))):
            return True, f"Variable assignment, parameter binding, or function call: `{rhs_clean}`"

        # RHS is a quoted string literal: check dummy / placeholder values
        val_inside = rhs_clean.strip("\"'").lower()
        dummy_literals = {
            "", "password", "test", "admin", "sqlite", "default", "changeit",
            "your_password", "xxx", "todo", "root", "dummy", "sample", "example",
            "none", "null", "false", "true", "secret", "token", "api_key",
            "latin1", "utf-8", "ascii",
        }
        if val_inside in dummy_literals:
            return True, f"Dummy/placeholder credential value detected: `{rhs_clean}`"

        env_lookups = (
            "process.env", "os.environ", "os.getenv", "config.get", "system.getenv",
            "environment.get", "req.", "request.", "params.", "options.", "db_pass",
            "user.", "body."
        )
        if any(lookup in val_inside for lookup in env_lookups):
            return True, "Credential dynamically resolved from environment or request configuration"

        if any(db in s_lower or db in fn_lower for db in ("sqlite", ":memory:", "models/index")):
            return True, "Placeholder credential for local SQLite/in-memory database"

    # 4. Safe AST literal_eval checks
    if pattern == "eval(" and "literal_eval" in s_lower:
        return True, "Safe ast.literal_eval() execution, not arbitrary code evaluation"

    # 5. SQL Destructive Query (DROP TABLE)
    if pattern == "DROP TABLE" and "if exists" in s_lower:
        return True, "Database migration/cleanup command (DROP TABLE IF EXISTS), not SQL injection"

    return False, ""
