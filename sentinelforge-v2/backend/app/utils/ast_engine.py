"""
SentinelForge — Polyglot AST Analysis Router
Routes raw code strings to language-specific scanner engines using a clean pluggable interface.
"""

from app.utils.scanners.base_scanner import ASTFinding, ASTReport
from app.utils.scanners.scanner_factory import get_scanner


def _detect_lang(code: str) -> str:
    """Guess programming language based on keywords/structures."""
    c_lower = code.lower()
    if "import java." in code or "public class " in code or "system.out.println" in code:
        return "java"
    if "const " in code or "let " in code or "require(" in code or "import react" in c_lower or "function " in code:
        return "javascript"
    if "#include <" in code or "std::" in code or "void main(" in code or "printf(" in code:
        return "c_cpp"
    if "package main" in code or "func " in code:
        return "go"
    if "apiversion:" in code or "jobs:" in code or "steps:" in code:
        return "yaml"
    return "python"


def analyze_code(code: str) -> ASTReport:
    """
    Parse and analyze code structure by routing to the appropriate pluggable language scanner.
    """
    lang = _detect_lang(code)
    scanner = get_scanner(lang)
    return scanner.scan(code)
