"""
SentinelForge — RAG Engine
Vector similarity search over a security knowledge base.
Production: uses Azure AI Search (Hybrid + Semantic Ranker).
Dev/Fallback: uses TF-IDF vector space model with stopword filtering over local knowledge base.
"""

import math
import os
import re
from dataclasses import dataclass
from typing import Optional, List, Dict, Set


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
    selection_reason: str = ""

    def to_dict(self) -> dict:
        return self.__dict__


# ── Polyglot Local Knowledge Base ─────────────────────────────────────────────

KNOWLEDGE_BASE: List[dict] = [
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
        "languages": ["python", "javascript", "typescript", "java", "go", "c_cpp", "cpp", "c"],
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
        "languages": ["python", "javascript", "typescript", "java", "go", "c_cpp", "cpp", "c", "php"],
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
        "languages": ["python", "java", "yaml", "ruby"],
        "keywords": ["pickle", "deserialization", "marshal", "ObjectInputStream", "readObject", "RCE", "yaml.load"],
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
        "languages": ["python", "javascript", "typescript", "java", "go", "c_cpp", "cpp", "c", "yaml", "shell"],
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
        "languages": ["python", "javascript", "typescript", "java", "go", "c_cpp", "cpp", "c", "shell"],
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
        "languages": ["c_cpp", "cpp", "c"],
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
        "languages": ["javascript", "typescript", "js", "ts"],
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
        "languages": ["yaml", "yml", "docker", "dockerfile", "shell"],
        "keywords": ["USER root", "Docker", "chmod 777", "permissions", "container", "DevOps"],
    },
    {
        "kb_ref": "sec-008",
        "vulnerability_type": "Dynamic Python Import Injection",
        "root_cause": (
            "Invoking __import__() directly with dynamic or untrusted parameters enables attackers to load "
            "arbitrary executable Python modules and trigger unintended code execution."
        ),
        "historical_fix": "Validate module names against an explicit allowlist and import safely via importlib.import_module() or static imports.",
        "optimized_example": "import importlib\nALLOWED = {'math', 'json'}\nif mod in ALLOWED: importlib.import_module(mod)",
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-94",
        "languages": ["python"],
        "keywords": ["__import__", "importlib", "import injection", "dynamic import", "eval"],
    },
]

# Stopwords to clean programming noise and English filler words
STOPWORDS: Set[str] = {
    "a", "an", "the", "and", "or", "in", "on", "at", "to", "for", "with", "is", "of", "from", "by", "that", "this",
    "def", "class", "import", "return", "function", "const", "let", "var", "public", "private", "protected",
    "static", "void", "int", "double", "float", "char", "string", "new", "null", "true", "false", "if", "else",
    "for", "while", "do", "try", "catch", "include", "using", "namespace", "std", "main", "args", "self"
}


def _tokenize(text: str) -> List[str]:
    """Clean, lowercase, and tokenize code/text. Filters out standard stopwords."""
    cleaned = re.sub(r"[^a-zA-Z0-9_\-\u00a0-\uffff]", " ", text)
    tokens = cleaned.lower().split()
    return [t for t in tokens if t not in STOPWORDS and len(t) > 1]


# ── TF-IDF Model Precomputation ────────────────────────────────────────────────

_doc_frequencies: Dict[str, int] = {}
for entry in KNOWLEDGE_BASE:
    # Build text representation of KB document
    doc_text = (
        " ".join(entry["keywords"]) + " " + 
        entry["vulnerability_type"] + " " + 
        entry["cwe"] + " " + 
        entry["root_cause"]
    )
    doc_tokens = set(_tokenize(doc_text))
    for token in doc_tokens:
        _doc_frequencies[token] = _doc_frequencies.get(token, 0) + 1


def _get_tfidf_vector(tokens: List[str]) -> Dict[str, float]:
    """Calculate TF-IDF representation vector of token list."""
    vector = {}
    total = len(tokens)
    if total == 0:
        return vector

    # Calculate Term Frequency (TF)
    tf_counts = {}
    for t in tokens:
        tf_counts[t] = tf_counts.get(t, 0) + 1

    # Apply Inverse Document Frequency (IDF)
    N = len(KNOWLEDGE_BASE)
    for term, count in tf_counts.items():
        tf = count / total
        df = _doc_frequencies.get(term, 0)
        # Smoothing: idf = log((1 + N) / (1 + df)) + 1
        idf = math.log((1 + N) / (1 + df)) + 1
        vector[term] = tf * idf

    return vector


def _cosine_similarity_tfidf(vec1: Dict[str, float], vec2: Dict[str, float]) -> float:
    """Compute cosine similarity between two sparse TF-IDF vectors."""
    if not vec1 or not vec2:
        return 0.0

    dot_product = sum(val * vec2[term] for term, val in vec1.items() if term in vec2)
    norm1 = math.sqrt(sum(val * val for val in vec1.values()))
    norm2 = math.sqrt(sum(val * val for val in vec2.values()))

    if norm1 == 0.0 or norm2 == 0.0:
        return 0.0

    return dot_product / (norm1 * norm2)


# ── Retrieval ─────────────────────────────────────────────────────────────────

def retrieve_context(
    code: str,
    threat_categories: Optional[list[str]] = None,
    language: Optional[str] = None,
    finding_cwes: Optional[list[str]] = None,
) -> list[RAGResult]:
    """
    Retrieve top-3 knowledge base entries relevant to the scanned code.
    Uses TF-IDF Vector Space Model (VSM) cosine similarity over clean tokens.
    Filters by target language to avoid irrelevant advice (e.g. C gets() for Python).
    Enforces minimum relevance threshold (0.18) and records selection rationale.
    """
    if threat_categories is None:
        threat_categories = []
    if finding_cwes is None:
        finding_cwes = []

    # Normalize target language for polyglot filtering
    target_lang = None
    if language:
        l = language.lower().strip()
        if l in ("py", "python"):
            target_lang = "python"
        elif l in ("js", "javascript", "ts", "typescript", "jsx", "tsx"):
            target_lang = "javascript"
        elif l in ("java",):
            target_lang = "java"
        elif l in ("c", "cpp", "c_cpp", "c++"):
            target_lang = "c_cpp"
        elif l in ("go", "golang"):
            target_lang = "go"
        elif l in ("yaml", "yml"):
            target_lang = "yaml"
        elif l in ("shell", "sh", "bash"):
            target_lang = "shell"
        else:
            target_lang = l

    # Create query by combining code contents and matched threat labels
    query_text = code + " " + " ".join(threat_categories) + " " + " ".join(finding_cwes)
    query_tokens = _tokenize(query_text)
    query_vector = _get_tfidf_vector(query_tokens)

    scored: list[tuple[float, dict, str]] = []
    code_lower = code.lower()

    for entry in KNOWLEDGE_BASE:
        # 1. Target language filtering: strictly exclude advice meant for other languages
        entry_langs = entry.get("languages", [])
        if target_lang and entry_langs:
            lang_match = False
            if target_lang in entry_langs:
                lang_match = True
            elif target_lang in ("javascript", "typescript") and any(x in entry_langs for x in ("javascript", "typescript", "js", "ts")):
                lang_match = True
            elif target_lang in ("c", "cpp", "c_cpp") and any(x in entry_langs for x in ("c", "cpp", "c_cpp")):
                lang_match = True
            if not lang_match:
                continue  # Skip entries incompatible with target language

        kb_text = (
            " ".join(entry["keywords"]) + " " + 
            entry["vulnerability_type"] + " " + 
            entry["cwe"] + " " + 
            entry["root_cause"]
        )
        kb_tokens = _tokenize(kb_text)
        kb_vector = _get_tfidf_vector(kb_tokens)

        score = _cosine_similarity_tfidf(query_vector, kb_vector)
        
        # 2. Check direct keyword matches using regex word boundaries to prevent substring collisions
        # (e.g. 'gets' must not match inside 'requests.get' or 'widgets')
        matched_kws = []
        for kw in entry["keywords"]:
            kw_clean = kw.strip().lower()
            if not kw_clean:
                continue
            if re.search(r"\b" + re.escape(kw_clean) + r"\b", code_lower):
                matched_kws.append(kw)

        matched_cats = [
            cat for cat in threat_categories 
            if cat.lower() in entry["vulnerability_type"].lower() or cat.lower() in " ".join(entry["keywords"]).lower()
        ]

        matched_cwes = [
            cwe for cwe in finding_cwes
            if cwe.upper() == entry["cwe"].upper()
        ]

        selection_reason = ""
        if matched_cwes:
            score += 0.35  # High-confidence detected CWE match
            selection_reason = f"Matched detected vulnerability CWE: {', '.join(matched_cwes)}"
        elif matched_cats:
            score += 0.25  # High-confidence scanner category boost
            selection_reason = f"Matched detected threat category: {', '.join(matched_cats)}"
        elif matched_kws:
            score += 0.15  # Direct source code keyword match boost
            selection_reason = f"Source code matched domain keywords: {', '.join(matched_kws)}"
        elif score >= 0.22:
            selection_reason = f"TF-IDF semantic relevance (similarity: {score:.2f})"

        # Minimum relevance threshold: 0.18, AND requires either matched keywords/categories or strong TF-IDF score
        MIN_THRESHOLD = 0.18
        if score >= MIN_THRESHOLD and selection_reason:
            scored.append((score, entry, selection_reason))

    # Sort results by similarity score descending
    scored.sort(key=lambda x: x[0], reverse=True)
    top_k = scored[:3]

    results = []
    for score, entry, reason in top_k:
        results.append(
            RAGResult(
                kb_ref=entry["kb_ref"],
                vulnerability_type=entry["vulnerability_type"],
                root_cause=entry["root_cause"],
                historical_fix=entry["historical_fix"],
                optimized_example=entry["optimized_example"],
                # Clamp similarity score between 0.0 and 1.0
                similarity_score=round(min(max(score, 0.0), 1.0), 4),
                owasp_category=entry["owasp"],
                cwe_id=entry["cwe"],
                selection_reason=reason,
            )
        )

    return results


async def retrieve_context_azure(
    code: str,
    threat_categories: list[str],
    language: Optional[str] = None,
    finding_cwes: Optional[list[str]] = None,
) -> list[RAGResult]:
    """
    Production path — Azure AI Search semantic retrieval.
    Requires: AZURE_SEARCH_ENDPOINT, AZURE_SEARCH_KEY, AZURE_SEARCH_INDEX in .env
    Falls back to local TF-IDF similarity if Azure Search credentials are missing.
    """
    endpoint = os.getenv("AZURE_SEARCH_ENDPOINT")
    key = os.getenv("AZURE_SEARCH_KEY")
    index = os.getenv("AZURE_SEARCH_INDEX", "sentinelforge-kb")

    if not endpoint or not key:
        return retrieve_context(code, threat_categories, language=language, finding_cwes=finding_cwes)

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
        # Graceful fallback to local Vector Space Model
        return retrieve_context(code, threat_categories, language=language, finding_cwes=finding_cwes)
