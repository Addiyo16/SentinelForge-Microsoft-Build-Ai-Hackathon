"""
SentinelForge — Base AST Scanner Interface
Defines the standard data structures and interfaces for all language scanners.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, List


@dataclass
class ASTFinding:
    rule_id: str
    node_type: str
    description: str
    line: int
    col: int
    severity: str  # critical | high | medium | low | info
    cwe_id: str = "CWE-Unknown"
    source_file: str = "code.py"
    end_line: Optional[int] = None
    evidence: str = ""
    explanation: str = ""
    suggestion: Optional[str] = None

    def to_dict(self) -> dict:
        return self.__dict__


@dataclass
class ASTReport:
    cyclomatic_complexity: int
    max_loop_depth: int
    function_count: int
    class_count: int
    dangerous_calls: List[str]
    findings: List[ASTFinding]
    optimized_snippet: Optional[str] = None
    original_snippet: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "cyclomatic_complexity": self.cyclomatic_complexity,
            "max_loop_depth": self.max_loop_depth,
            "function_count": self.function_count,
            "class_count": self.class_count,
            "dangerous_calls": self.dangerous_calls,
            "findings": [f.to_dict() for f in self.findings],
            "optimized_snippet": self.optimized_snippet,
            "original_snippet": self.original_snippet,
        }


class BaseScanner(ABC):
    """
    Abstract Base Class for language-specific AST scanners.
    """

    @abstractmethod
    def scan(self, code: str, filename: str = "code.py") -> ASTReport:
        """Scan code content and return an ASTReport."""
        pass
