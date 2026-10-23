"""
SentinelForge — JavaScript / TypeScript AST Scanner
"""

from app.utils.scanners.base_scanner import BaseScanner, ASTReport
from app.utils.scanners.generic_fallback import scan_generic_regex


class JavascriptScanner(BaseScanner):
    """JavaScript and TypeScript code scanner."""

    def scan(self, code: str, filename: str = "code.js") -> ASTReport:
        lang = "typescript" if filename.endswith((".ts", ".tsx")) else "javascript"
        return scan_generic_regex(code, lang, filename=filename)
