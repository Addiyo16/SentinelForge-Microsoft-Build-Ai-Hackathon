"""
SentinelForge — Go AST Scanner
"""

from app.utils.scanners.base_scanner import BaseScanner, ASTReport
from app.utils.scanners.generic_fallback import scan_generic_regex


class GoScanner(BaseScanner):
    """Go source code scanner."""

    def scan(self, code: str) -> ASTReport:
        return scan_generic_regex(code, "go")
