"""
SentinelForge — RAG Engine
Vector similarity search over a security knowledge base.
Production: uses Azure AI Search. Dev: cosine sim over local embeddings.
"""

import math
import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class RAGResult:
    kb_ref: str
    vulnerability_type: str
    root_cause: str
    historical_fix: str
    optimized_example: str
    similarity_score: float
    owasp_category: str
    cwe_id: str

    def to_dict(self) -> dict:
        return self.__dict__


# ── Polyglot Local Knowledge Base ─────────────────────────────────────────────

KNOWLEDGE_BASE: list[dict] = [
    {
        "kb_ref": "perf-001",
        "vulnerability_type": "Asymptotic Exhaustion — O(N²) Linear Search",
        "root_cause": (
            "Nested iteration over collections scales quadratically. "
            "At large size, this performs N*N comparisons, locking threads "
            "and exposing endpoints to denial-of-service."
        ),
        "historical_fix": "Index inner loop elements into a hash map or Map. Reduces retrieval to O(1).",
        "optimized_example": "lookup = {u.id: u for u in users}\nresult = lookup.get(target_id)",
        "owasp": "A05:2021 – Security Misconfiguration",
        "cwe": "CWE-400",
        "keywords": ["nested loop", "for i in range", "linear search", "O(N²)", "performance", "Map", "Set"],
    },
    {
        "kb_ref": "sec-001",
        "vulnerability_type": "SQL Injection via String Concatenation",
        "root_cause": (
            "Unsanitized user inputs concatenated directly into SQL command strings. "
            "Enables attackers to hijack query logic and exfiltrate database records."
        ),
        "historical_fix": "Always use parameterized query bindings or a secure ORM layer.",
        "optimized_example": 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-89",
        "keywords": ["sql", "query", "DROP TABLE", "UNION SELECT", "concat", "injection"],
    },
    {
        "kb_ref": "sec-002",
        "vulnerability_type": "Insecure Deserialization — Binary RCE",
        "root_cause": (
            "Deserializing untrusted binary streams executes arbitrary constructor code in Python/Java. "
            "Allows attackers to inject malicious payloads triggering remote code execution (RCE)."
        ),
        "historical_fix": "Replace python pickle / Java ObjectInputStream with safe formats like JSON or Protocol Buffers.",
        "optimized_example": "import json\ndata = json.loads(raw_bytes)  # Python safe",
        "owasp": "A08:2021 – Software and Data Integrity Failures",
        "cwe": "CWE-502",
        "keywords": ["pickle", "deserialization", "marshal", "ObjectInputStream", "readObject", "RCE"],
    },
    {
        "kb_ref": "sec-003",
        "vulnerability_type": "Hardcoded Credentials in Source Code",
        "root_cause": (
            "Committing sensitive API tokens, keys, or passwords exposes credentials in git logs, "
            "facilitating immediate cloud account hijacking."
        ),
        "historical_fix": "Load secrets dynamically at runtime from environment variables or Azure Key Vault.",
        "optimized_example": "import os\nAPI_KEY = os.environ['MY_SERVICE_API_KEY']",
        "owasp": "A02:2021 – Cryptographic Failures",
        "cwe": "CWE-798",
        "keywords": ["password", "api_key", "secret", "token", "hardcoded", "credential"],
    },
    {
        "kb_ref": "sec-004",
        "vulnerability_type": "OS Command Injection via Shell Execution",
        "root_cause": (
            "Injecting user-provided strings into system shells enables attackers to chain shell "
            "commands (using ;, &&, |) to compromise the underlying operating system."
        ),
        "historical_fix": "Execute shell sub-commands with explicit argument lists (shell=False) and validate input.",
        "optimized_example": 'subprocess.run(["ls", "-la", path], check=True, capture_output=True)  # safe',
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-78",
        "keywords": ["os.system", "exec", "eval", "shell", "subprocess", "child_process", "command injection"],
    },
    {
        "kb_ref": "sec-005",
        "vulnerability_type": "C/C++ Memory Corruption — Unbounded Buffer Overflow",
        "root_cause": (
            "Legacy standard functions like strcpy() and gets() do not check destination boundary limits. "
            "Writing excess bytes overwrites call stacks, causing segmentation faults or payload execution."
        ),
        "historical_fix": "Replace strcpy() with strncpy() or bounds-checked functions and specify maximum size.",
        "optimized_example": "strncpy(dest, src, sizeof(dest) - 1);\ndest[sizeof(dest) - 1] = '\\0'; // safe C",
        "owasp": "A06:2021 – Vulnerable and Outdated Components",
        "cwe": "CWE-120",
        "keywords": ["strcpy", "gets", "sprintf", "buffer overflow", "C++", "memory corruption"],
    },
    {
        "kb_ref": "sec-006",
        "vulnerability_type": "React XSS injection via dangerouslySetInnerHTML",
        "root_cause": (
            "Rendering raw user inputs inside HTML elements bypasses React's automatic string sanitization. "
            "Enables attackers to run malicious scripts inside client browsers (Cross-Site Scripting)."
        ),
        "historical_fix": "Use DOMpurify to sanitize HTML payloads before injecting them, or rely on standard JSX braces.",
        "optimized_example": "const cleanHTML = DOMPurify.sanitize(userInput);\nreturn <div dangerouslySetInnerHTML={{__html: cleanHTML}} />;",
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-79",
        "keywords": ["dangerouslySetInnerHTML", "XSS", "React", "innerHTML", "script injection"],
    },
    {
        "kb_ref": "sec-007",
        "vulnerability_type": "Container Execution Privilege Escalation (Docker root)",
        "root_cause": (
            "Running docker container processes as root enables host machine compromises in the event "
            "of container escape bugs. Overly permissive DevOps YAML settings expose containers."
        ),
        "historical_fix": "Specify a non-privileged user (e.g., USER node or USER alpine) inside Dockerfiles.",
        "optimized_example": "RUN groupadd -r app && useradd -r -g app appuser\nUSER appuser  # Docker safe",
        "owasp": "A05:2021 – Security Misconfiguration",
        "cwe": "CWE-250",
        "keywords": ["USER root", "Docker", "chmod 777", "permissions", "container", "DevOps"],
    },
]


def _tokenize(text: str) -> set[str]:
    return set(text.lower().replace("(", " ").replace(")", " ").replace("/", " ").split())


def _cosine_similarity(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    intersection = len(a & b)
    return intersection / math.sqrt(len(a) * len(b))


def retrieve_context(code: str, threat_categories: list[str]) -> list[RAGResult]:
    """
    Retrieve top-k knowledge base entries relevant to the scanned code.
    Uses keyword-based cosine similarity over code tokens + threat labels.
    """
    query_tokens = _tokenize(code) | _tokenize(" ".join(threat_categories))
    scored: list[tuple[float, dict]] = []

    for entry in KNOWLEDGE_BASE:
        kb_tokens = _tokenize(
            " ".join(entry["keywords"]) + " " + entry["vulnerability_type"]
        )
        score = _cosine_similarity(query_tokens, kb_tokens)
        if score > 0.05:
            scored.append((score, entry))

    scored.sort(key=lambda x: x[0], reverse=True)
    top_k = scored[:3]

    results = []
    for score, entry in top_k:
        results.append(
            RAGResult(
                kb_ref=entry["kb_ref"],
                vulnerability_type=entry["vulnerability_type"],
                root_cause=entry["root_cause"],
                historical_fix=entry["historical_fix"],
                optimized_example=entry["optimized_example"],
                similarity_score=round(score, 4),
                owasp_category=entry["owasp"],
                cwe_id=entry["cwe"],
            )
        )

    return results


async def retrieve_context_azure(code: str, threat_categories: list[str]) -> list[RAGResult]:
    """
    Production path — Azure AI Search semantic retrieval.
    Requires: AZURE_SEARCH_ENDPOINT, AZURE_SEARCH_KEY, AZURE_SEARCH_INDEX in .env
    Falls back to local similarity if env vars not set.
    """
    endpoint = os.getenv("AZURE_SEARCH_ENDPOINT")
    key = os.getenv("AZURE_SEARCH_KEY")
    index = os.getenv("AZURE_SEARCH_INDEX", "sentinelforge-kb")

    if not endpoint or not key:
        return retrieve_context(code, threat_categories)

    try:
        from azure.search.documents import SearchClient
        from azure.core.credentials import AzureKeyCredential

        client = SearchClient(endpoint, index, AzureKeyCredential(key))
        query = code[:500] + " " + " ".join(threat_categories)
        raw = client.search(
            search_text=query,
            top=3,
            query_type="semantic",
            semantic_configuration_name="default",
        )
        results = []
        for r in raw:
            results.append(
                RAGResult(
                    kb_ref=r.get("kb_ref", "azure-kb"),
                    vulnerability_type=r.get("vulnerability_type", "Unknown"),
                    root_cause=r.get("root_cause", ""),
                    historical_fix=r.get("historical_fix", ""),
                    optimized_example=r.get("optimized_example", ""),
                    similarity_score=round(r.get("@search.score", 0.0), 4),
                    owasp_category=r.get("owasp_category", ""),
                    cwe_id=r.get("cwe_id", ""),
                )
            )
        return results
    except Exception:
        return retrieve_context(code, threat_categories)
