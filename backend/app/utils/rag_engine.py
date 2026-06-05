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


# ── Local Knowledge Base ─────────────────────────────────────────────────────

KNOWLEDGE_BASE: list[dict] = [
    {
        "kb_ref": "perf-001",
        "vulnerability_type": "Asymptotic Exhaustion — O(N²) Linear Search",
        "root_cause": (
            "Nested iteration over unsorted collections scales quadratically. "
            "At N=10,000 items this performs 100M comparisons, causing timeouts "
            "and enabling denial-of-service attacks via large payload injection."
        ),
        "historical_fix": "Replace inner loop with a pre-built hash map. Reduces lookup to O(1).",
        "optimized_example": "lookup = {u.id: u for u in users}\nresult = lookup.get(target_id)",
        "owasp": "A05:2021 – Security Misconfiguration",
        "cwe": "CWE-400",
        "keywords": ["nested loop", "for i in range", "linear search", "O(N²)", "performance"],
    },
    {
        "kb_ref": "sec-001",
        "vulnerability_type": "SQL Injection via String Concatenation",
        "root_cause": (
            "Unsanitized user input concatenated directly into SQL query strings. "
            "Allows attackers to alter query logic, exfiltrate data, or drop tables."
        ),
        "historical_fix": "Use parameterised queries or an ORM. Never concatenate user input into SQL.",
        "optimized_example": 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-89",
        "keywords": ["sql", "query", "DROP TABLE", "UNION SELECT", "string concat", "injection"],
    },
    {
        "kb_ref": "sec-002",
        "vulnerability_type": "Insecure Deserialization — Pickle RCE",
        "root_cause": (
            "Python pickle.loads() executes arbitrary bytecode during deserialization. "
            "Attacker-controlled pickle payloads achieve remote code execution with no other prerequisites."
        ),
        "historical_fix": "Replace pickle with json.loads() or msgpack. If pickle is required, use HMAC signature verification.",
        "optimized_example": "import json\ndata = json.loads(raw_bytes)  # safe, no code execution",
        "owasp": "A08:2021 – Software and Data Integrity Failures",
        "cwe": "CWE-502",
        "keywords": ["pickle", "deserialization", "marshal", "yaml.load", "RCE"],
    },
    {
        "kb_ref": "sec-003",
        "vulnerability_type": "Hardcoded Credentials in Source Code",
        "root_cause": (
            "API keys, passwords, or tokens committed to source code are exposed in git history "
            "and any checkout. Leaked credentials are the #1 cause of cloud account takeovers."
        ),
        "historical_fix": "Store secrets in environment variables or a secrets manager (Azure Key Vault, HashiCorp Vault).",
        "optimized_example": "import os\nAPI_KEY = os.environ['MY_SERVICE_API_KEY']",
        "owasp": "A02:2021 – Cryptographic Failures",
        "cwe": "CWE-798",
        "keywords": ["password", "api_key", "secret", "token", "hardcoded", "credential"],
    },
    {
        "kb_ref": "sec-004",
        "vulnerability_type": "OS Command Injection via os.system / subprocess",
        "root_cause": (
            "Passing unsanitized strings to shell commands allows attackers to append "
            "arbitrary shell operators (;, &&, |) and execute system commands."
        ),
        "historical_fix": "Use subprocess with a list of arguments (never shell=True) and validate all inputs.",
        "optimized_example": 'subprocess.run(["ls", "-la", path], check=True, capture_output=True)',
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-78",
        "keywords": ["os.system", "exec", "eval", "shell", "subprocess", "command injection"],
    },
    {
        "kb_ref": "perf-002",
        "vulnerability_type": "Unbounded Recursion — Stack Overflow Risk",
        "root_cause": (
            "Recursive functions without depth guards exhaust the call stack. "
            "In Python the default recursion limit is 1000 frames. Attacker-controlled "
            "depth triggers RecursionError or denial of service."
        ),
        "historical_fix": "Add a depth parameter with a hard limit, or convert recursion to an iterative stack.",
        "optimized_example": "def dfs(node, depth=0, max_depth=500):\n    if depth > max_depth: return\n    ...",
        "owasp": "A05:2021 – Security Misconfiguration",
        "cwe": "CWE-674",
        "keywords": ["recursion", "recursive", "stack overflow", "depth"],
    },
]


def _tokenize(text: str) -> set[str]:
    return set(text.lower().replace("(", " ").replace(")", " ").split())


def _cosine_similarity(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    intersection = len(a & b)
    return intersection / math.sqrt(len(a) * len(b))


def retrieve_context(code: str, threat_categories: list[str]) -> list[RAGResult]:
    """
    Retrieve top-k knowledge base entries relevant to the scanned code.
    Uses keyword-based cosine similarity over code tokens + threat labels.

    In production, swap this with Azure AI Search vector retrieval:
        client = SearchClient(endpoint, index_name, AzureKeyCredential(key))
        results = client.search(search_text=code, top=3, query_type="semantic")
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
        # Fall back to local KB
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
