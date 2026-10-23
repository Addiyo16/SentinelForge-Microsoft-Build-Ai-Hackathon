"""
SentinelForge — Polyglot AST Analysis Router
Routes raw code strings to language-specific scanner engines using a clean pluggable interface.
"""

from app.utils.scanners.base_scanner import ASTFinding, ASTReport
from app.utils.scanners.scanner_factory import get_scanner


def _detect_lang(code: str, filename: str = "") -> str:
    """Detect programming language based on file extension and code structure."""
    fn_lower = filename.lower()
    if fn_lower.endswith((".cpp", ".cc", ".cxx", ".c", ".h", ".hpp")):
        return "c_cpp"
    if fn_lower.endswith(".java"):
        return "java"
    if fn_lower.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs")):
        return "javascript"
    if fn_lower.endswith(".go"):
        return "go"
    if fn_lower.endswith((".yml", ".yaml")):
        return "yaml"
    if fn_lower.endswith((".sh", ".bash", ".zsh", ".bat", ".cmd", ".ps1")):
        return "shell"
    if fn_lower.endswith(".py"):
        return "python"

    c_lower = code.lower()
    if "import java." in code or "public class " in code or "system.out.println" in code:
        return "java"
    if "const " in code or "let " in code or "require(" in code or "import react" in c_lower or "function " in code:
        return "javascript"
    if "#include <" in code or "std::" in code or "void main(" in code or "printf(" in code:
        return "c_cpp"
    if "package main" in code or "func " in code:
        return "go"
    if "apiversion:" in c_lower or "jobs:" in c_lower or "steps:" in c_lower:
        return "yaml"
    return "python"


def analyze_code(code: str, filename: str = "code.py") -> ASTReport:
    """
    Parse and analyze code structure by routing to the appropriate pluggable language scanner.
    """
    lang = _detect_lang(code, filename=filename)
    scanner = get_scanner(lang)
    return scanner.scan(code, filename=filename)
