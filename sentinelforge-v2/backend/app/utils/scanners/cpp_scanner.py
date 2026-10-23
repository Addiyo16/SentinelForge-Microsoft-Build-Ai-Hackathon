"""
SentinelForge — C/C++ AST Scanner
"""

from app.utils.scanners.base_scanner import BaseScanner, ASTReport
from app.utils.scanners.generic_fallback import scan_generic_regex


class CppScanner(BaseScanner):
    """C and C++ source code scanner."""

    def scan(self, code: str, filename: str = "code.cpp") -> ASTReport:
        return scan_generic_regex(code, "c_cpp", filename=filename)
