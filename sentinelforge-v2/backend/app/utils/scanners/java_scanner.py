"""
SentinelForge — Java AST Scanner
"""

from app.utils.scanners.base_scanner import BaseScanner, ASTReport
from app.utils.scanners.generic_fallback import scan_generic_regex


class JavaScanner(BaseScanner):
    """Java source code scanner."""

    def scan(self, code: str) -> ASTReport:
        return scan_generic_regex(code, "java")
