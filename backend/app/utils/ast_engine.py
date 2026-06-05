"""
SentinelForge — AST Analysis Engine
Deep structural analysis: loop nesting, complexity, dangerous call detection.
"""

import ast
import textwrap
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ASTFinding:
    node_type: str
    description: str
    line: int
    col: int
    severity: str  # critical | high | medium | low | info
    suggestion: Optional[str] = None


@dataclass
class ASTReport:
    cyclomatic_complexity: int
    max_loop_depth: int
    function_count: int
    class_count: int
    dangerous_calls: list[str]
    findings: list[ASTFinding]
    optimized_snippet: Optional[str] = None
    original_snippet: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "cyclomatic_complexity": self.cyclomatic_complexity,
            "max_loop_depth": self.max_loop_depth,
            "function_count": self.function_count,
            "class_count": self.class_count,
            "dangerous_calls": self.dangerous_calls,
            "findings": [
                {
                    "node_type": f.node_type,
                    "description": f.description,
                    "line": f.line,
                    "col": f.col,
                    "severity": f.severity,
                    "suggestion": f.suggestion,
                }
                for f in self.findings
            ],
            "optimized_snippet": self.optimized_snippet,
            "original_snippet": self.original_snippet,
        }


DANGEROUS_CALLS = {
    "eval": "Dynamic code evaluation — arbitrary code execution risk",
    "exec": "Dynamic code execution — arbitrary code execution risk",
    "compile": "Dynamic compilation — potential code injection",
    "os.system": "Shell command injection vector",
    "subprocess.call": "Shell command injection vector",
    "pickle.loads": "Insecure deserialization — RCE risk",
    "yaml.load": "Insecure YAML load — use yaml.safe_load()",
    "__import__": "Dynamic import — code injection risk",
}


class _ASTVisitor(ast.NodeVisitor):
    def __init__(self):
        self.findings: list[ASTFinding] = []
        self.dangerous_calls: list[str] = []
        self.cyclomatic_complexity: int = 1
        self.function_count: int = 0
        self.class_count: int = 0
        self._loop_depth: int = 0
        self.max_loop_depth: int = 0

    # ── Complexity counters ──────────────────────────────────────────────────

    def _enter_loop(self, node):
        self._loop_depth += 1
        self.max_loop_depth = max(self.max_loop_depth, self._loop_depth)
        if self._loop_depth >= 2:
            self.findings.append(
                ASTFinding(
                    node_type="NestedLoop",
                    description=f"Nested loop depth {self._loop_depth} — potential O(N^{self._loop_depth}) complexity",
                    line=node.lineno,
                    col=node.col_offset,
                    severity="high" if self._loop_depth == 2 else "critical",
                    suggestion="Consider flattening with a hash map / set lookup",
                )
            )
        self.cyclomatic_complexity += 1
        self.generic_visit(node)
        self._loop_depth -= 1

    def visit_For(self, node): self._enter_loop(node)
    def visit_While(self, node): self._enter_loop(node)

    def visit_If(self, node):
        self.cyclomatic_complexity += 1
        self.generic_visit(node)

    def visit_ExceptHandler(self, node):
        self.cyclomatic_complexity += 1
        if node.type is None:
            self.findings.append(
                ASTFinding(
                    node_type="BareExcept",
                    description="Bare `except:` swallows all exceptions including KeyboardInterrupt",
                    line=node.lineno,
                    col=node.col_offset,
                    severity="medium",
                    suggestion="Use `except Exception as e:` or be explicit about the exception type",
                )
            )
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        self.function_count += 1
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self.class_count += 1
        self.generic_visit(node)

    # ── Dangerous call detection ─────────────────────────────────────────────

    def visit_Call(self, node):
        call_name = self._get_call_name(node)
        if call_name and call_name in DANGEROUS_CALLS:
            self.dangerous_calls.append(call_name)
            self.findings.append(
                ASTFinding(
                    node_type="DangerousCall",
                    description=f"`{call_name}()` — {DANGEROUS_CALLS[call_name]}",
                    line=node.lineno,
                    col=node.col_offset,
                    severity="critical",
                    suggestion=f"Replace `{call_name}` with a safe alternative",
                )
            )
        self.generic_visit(node)

    def _get_call_name(self, node: ast.Call) -> Optional[str]:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            parts = []
            n = node.func
            while isinstance(n, ast.Attribute):
                parts.append(n.attr)
                n = n.value
            if isinstance(n, ast.Name):
                parts.append(n.id)
                return ".".join(reversed(parts))
        return None


def analyze_code(code: str) -> ASTReport:
    """Parse and analyze Python source code. Returns ASTReport."""
    try:
        tree = ast.parse(textwrap.dedent(code))
    except SyntaxError as e:
        return ASTReport(
            cyclomatic_complexity=0,
            max_loop_depth=0,
            function_count=0,
            class_count=0,
            dangerous_calls=[],
            findings=[
                ASTFinding(
                    node_type="SyntaxError",
                    description=str(e),
                    line=e.lineno or 0,
                    col=e.offset or 0,
                    severity="critical",
                )
            ],
        )

    visitor = _ASTVisitor()
    visitor.visit(tree)

    report = ASTReport(
        cyclomatic_complexity=visitor.cyclomatic_complexity,
        max_loop_depth=visitor.max_loop_depth,
        function_count=visitor.function_count,
        class_count=visitor.class_count,
        dangerous_calls=list(set(visitor.dangerous_calls)),
        findings=visitor.findings,
        original_snippet=code.strip(),
    )

    # Auto-generate simplified optimized snippet for O(N²) cases
    if visitor.max_loop_depth >= 2:
        report.optimized_snippet = _suggest_linear_refactor(code)

    return report


def _suggest_linear_refactor(code: str) -> str:
    """Generate a high-level refactor hint for nested loop patterns."""
    return (
        "# SentinelForge Suggestion — O(N) refactor\n"
        "# Replace nested loop with a hash-map lookup:\n\n"
        "lookup = {item.id: item for item in collection}  # O(N) build\n"
        "result = lookup.get(target_id)                   # O(1) access\n"
        "# Eliminates O(N²) scan entirely"
    )
