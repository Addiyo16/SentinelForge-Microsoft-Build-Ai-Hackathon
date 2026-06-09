"""
SentinelForge — Python AST Scanner
Utilizes Python's native 'ast' module for deep structural analysis.
"""

import ast
import textwrap
from typing import Optional

from app.utils.scanners.base_scanner import BaseScanner, ASTReport, ASTFinding


class _PythonASTVisitor(ast.NodeVisitor):
    def __init__(self):
        self.findings: list[ASTFinding] = []
        self.dangerous_calls: list[str] = []
        self.cyclomatic_complexity: int = 1
        self.function_count: int = 0
        self.class_count: int = 0
        self._loop_depth: int = 0
        self.max_loop_depth: int = 0

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
                    suggestion="Use `except Exception as e:` or explicit exception types",
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

    def visit_Call(self, node):
        call_name = self._get_call_name(node)
        dangerous = {
            "eval": "Dynamic code evaluation RCE risk",
            "exec": "Dynamic code execution RCE risk",
            "os.system": "OS Command injection vector",
            "subprocess.call": "OS Command execution",
            "pickle.loads": "Insecure serialization",
            "yaml.load": "Insecure YAML load",
        }
        if call_name in dangerous:
            self.dangerous_calls.append(call_name)
            self.findings.append(
                ASTFinding(
                    node_type="DangerousCall",
                    description=f"`{call_name}()` — {dangerous[call_name]}",
                    line=node.lineno,
                    col=node.col_offset,
                    severity="critical",
                    suggestion="Replace with a secure library alternative",
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


class PythonScanner(BaseScanner):
    """Python source code AST scanner."""

    def scan(self, code: str) -> ASTReport:
        try:
            tree = ast.parse(textwrap.dedent(code))
            visitor = _PythonASTVisitor()
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
            if visitor.max_loop_depth >= 2:
                report.optimized_snippet = (
                    "# SentinelForge Suggestion — O(N) refactor\n"
                    "lookup = {item.id: item for item in collection}  # O(N) map\n"
                    "result = lookup.get(target_id)                   # O(1) fetch"
                )
            return report
        except Exception:
            # If standard AST parsing fails (e.g. syntax error), fallback to generic regex scanning
            from app.utils.scanners.generic_fallback import scan_generic_regex
            return scan_generic_regex(code, "python")
