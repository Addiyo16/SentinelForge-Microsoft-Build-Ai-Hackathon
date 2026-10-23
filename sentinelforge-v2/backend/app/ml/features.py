"""
SentinelForge — ML Feature Engineering Pipeline
Extracts structured numerical and categorical features from code snippets and candidate findings
for machine learning-based vulnerability validation and priority ranking.
"""

import math
import re
from dataclasses import dataclass
from typing import Optional, Dict, Any, List


@dataclass
class FindingFeatures:
    rule_severity_score: float      # critical: 1.0, high: 0.75, medium: 0.5, low: 0.25
    scanner_confidence: float       # 0.0 to 1.0 from deterministic rule
    is_dangerous_api: int           # 1 if dangerous call identified, 0 otherwise
    has_sanitization: int           # 1 if input validation / escaping detected nearby
    has_auth_context: int           # 1 if credentials, tokens, or permissions involved
    cyclomatic_complexity: int      # Function/module CC
    loop_depth: int                 # Maximum iteration depth
    finding_line: int               # 1-indexed source line
    snippet_length: int             # Length in characters of evidence snippet
    evidence_entropy: float         # Shannon entropy of evidence string
    language_code: int              # 0: py, 1: js/ts, 2: java, 3: c/cpp, 4: go, 5: yaml, 6: other

    def to_vector(self) -> list[float]:
        return [
            self.rule_severity_score,
            self.scanner_confidence,
            float(self.is_dangerous_api),
            float(self.has_sanitization),
            float(self.has_auth_context),
            float(min(self.cyclomatic_complexity, 50)),
            float(min(self.loop_depth, 10)),
            float(min(self.finding_line, 1000)),
            float(min(self.snippet_length, 500)),
            self.evidence_entropy,
            float(self.language_code),
        ]

    @classmethod
    def feature_names(cls) -> list[str]:
        return [
            "rule_severity_score",
            "scanner_confidence",
            "is_dangerous_api",
            "has_sanitization",
            "has_auth_context",
            "cyclomatic_complexity",
            "loop_depth",
            "finding_line",
            "snippet_length",
            "evidence_entropy",
            "language_code",
        ]


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    return -sum(p * math.log2(p) for p in prob)


def extract_features(
    finding: dict,
    code_context: str = "",
    cyclomatic_complexity: int = 1,
    loop_depth: int = 0,
    language: str = "python",
) -> FindingFeatures:
    """
    Extract structured ML feature vector from a candidate security finding and surrounding code context.
    """
    # 1. Severity mapping
    sev_map = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25, "info": 0.1}
    raw_sev = str(finding.get("severity", "medium")).lower()
    rule_severity_score = sev_map.get(raw_sev, 0.5)

    # 2. Scanner confidence
    scanner_conf = float(finding.get("confidence", 0.8))

    # 3. Dangerous API check
    evidence = str(finding.get("evidence") or finding.get("description") or finding.get("snippet") or finding.get("pattern") or "").lower()
    surrounding_context = (code_context + " " + evidence).lower()
    dangerous_keywords = (
        "eval(", "exec(", "os.system", "os.popen", "subprocess.call", "subprocess.popen",
        "pickle.loads", "pickle.load", "yaml.load(", "strcpy(", "gets(", "system(",
        "readobject(", "unsafe.pointer", "dangerouslysetinnerhtml", "chmod 777",
        "union select", "drop table", "md5(", "des(", "' or '1'='1"
    )
    is_dangerous_api = 1 if any(k in surrounding_context for k in dangerous_keywords) else 0

    # 4. Sanitization and input validation check
    sanitization_patterns = (
        r"\b(isinstance|is_valid|validate|sanitize|escape|quote|int\(|float\(|re\.match|whitelist)\b",
        r"\b(param|preparedstatement|parameterized|shlex\.quote|check_call|safeloader)\b",
        r"\b(readfilesync|swagger|openapi|sqlite|process\.env|os\.getenv)\b",
        r"\b(json\.loads|json\.parse|yaml\.safe_load|dompurify|validatingobjectinputstream)\b",
        r"\b(subprocess\.run|execfile|compare_digest|aes|sha256|sha-256|snprintf|strncpy)\b",
    )
    has_sanitization = 1 if (any(re.search(p, surrounding_context) for p in sanitization_patterns) or finding.get("is_false_positive")) else 0

    # 5. Auth / Secret Context check
    auth_keywords = ("password", "api_key", "secret", "token", "auth", "bearer", "private_key")
    has_auth_context = 1 if any(k in surrounding_context for k in auth_keywords) else 0

    # 6. Snippet entropy
    snippet_entropy = round(_shannon_entropy(evidence[:120]), 3)

    # 7. Language code mapping
    lang_map = {
        "python": 0, "py": 0,
        "javascript": 1, "typescript": 1, "js": 1, "ts": 1,
        "java": 2,
        "c_cpp": 3, "c": 3, "cpp": 3,
        "go": 4,
        "yaml": 5, "yml": 5,
    }
    lang_code = lang_map.get(language.lower(), 6)

    return FindingFeatures(
        rule_severity_score=rule_severity_score,
        scanner_confidence=scanner_conf,
        is_dangerous_api=is_dangerous_api,
        has_sanitization=has_sanitization,
        has_auth_context=has_auth_context,
        cyclomatic_complexity=cyclomatic_complexity,
        loop_depth=loop_depth,
        finding_line=int(finding.get("line") or 1),
        snippet_length=len(evidence),
        evidence_entropy=snippet_entropy,
        language_code=lang_code,
    )
