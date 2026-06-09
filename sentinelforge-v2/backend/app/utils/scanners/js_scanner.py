"""
SentinelForge — JavaScript / TypeScript AST Scanner
"""

from app.utils.scanners.base_scanner import BaseScanner, ASTReport
from app.utils.scanners.generic_fallback import scan_generic_regex


class JavascriptScanner(BaseScanner):
    """JavaScript and TypeScript code scanner."""

    def scan(self, code: str) -> ASTReport:
        # Currently utilizes refined regex heuristics (can be extended with tree-sitter or esprima in prod)
        return scan_generic_regex(code, "javascript")
