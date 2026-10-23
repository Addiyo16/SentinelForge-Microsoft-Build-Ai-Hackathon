"""
SentinelForge — Python AST Scanner
Utilizes Python's native 'ast' module for deep structural analysis.
"""

import ast
import textwrap
from typing import Optional

from app.utils.scanners.base_scanner import BaseScanner, ASTReport, ASTFinding


class _PythonASTVisitor(ast.NodeVisitor):
    def __init__(self, code: str = "", source_file: str = "code.py"):
        self.code_lines = code.splitlines() if code else []
        self.source_file = source_file
        self.findings: list[ASTFinding] = []
        self.dangerous_calls: list[str] = []
        self.cyclomatic_complexity: int = 1
        self.function_count: int = 0
        self.class_count: int = 0
        self._loop_depth: int = 0
        self.max_loop_depth: int = 0
        self._loop_stack: list[ast.AST] = []

    def _get_evidence(self, start_line: int, end_line: Optional[int] = None) -> str:
        if not self.code_lines or start_line <= 0:
            return ""
        s = max(0, start_line - 1)
        e = min(len(self.code_lines), end_line or start_line)
        return "\n".join(self.code_lines[s:e]).strip()

    def _collect_target_names(self, target: ast.AST) -> set[str]:
        names = set()
        if isinstance(target, ast.Name):
            names.add(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                names.update(self._collect_target_names(elt))
        return names

    def _is_hierarchical_or_bounded(self, inner_loop: ast.AST, outer_loop: ast.AST) -> bool:
        """
        Differentiate benign flatMap / hierarchical / bounded iterations from
        genuine O(N^2) Cartesian self-product algorithmic complexity vulnerabilities (CWE-400).
        """
        if isinstance(inner_loop, ast.For) and isinstance(outer_loop, ast.For):
            outer_targets = self._collect_target_names(outer_loop.target)
            # 1. Sub-element / value flattening: inner loop iterates over a variable unpacked in outer loop
            # e.g., for k, vs in data: for v in vs: (O(N) total work, not O(N^2))
            if isinstance(inner_loop.iter, ast.Name) and inner_loop.iter.id in outer_targets:
                return True
            if isinstance(inner_loop.iter, ast.Attribute) and isinstance(inner_loop.iter.value, ast.Name) and inner_loop.iter.value.id in outer_targets:
                return True

            # 2. Bounded constant range: inner loop iterates over a small constant range or tuple literal
            # e.g., for attempt in range(3):
            if isinstance(inner_loop.iter, ast.Call) and isinstance(inner_loop.iter.func, ast.Name) and inner_loop.iter.func.id == "range":
                args = inner_loop.iter.args
                if len(args) == 1 and isinstance(args[0], ast.Constant) and isinstance(args[0].value, int) and args[0].value <= 20:
                    return True
            if isinstance(inner_loop.iter, (ast.Tuple, ast.List)) and all(isinstance(elt, ast.Constant) for elt in inner_loop.iter.elts) and len(inner_loop.iter.elts) <= 20:
                return True

        return False

    def _enter_loop(self, node):
        self._loop_depth += 1
        self.max_loop_depth = max(self.max_loop_depth, self._loop_depth)

        is_benign = False
        if self._loop_stack:
            outer_node = self._loop_stack[-1]
            if self._is_hierarchical_or_bounded(node, outer_node):
                is_benign = True

        if self._loop_depth >= 2 and not is_benign:
            end_line = getattr(node, "end_lineno", node.lineno)
            evidence = self._get_evidence(node.lineno, end_line)
            self.findings.append(
                ASTFinding(
                    rule_id="AST-PERF-001",
                    node_type="NestedLoop",
                    description=f"Nested loop depth {self._loop_depth} — quadratic O(N^{self._loop_depth}) execution complexity",
                    line=node.lineno,
                    col=node.col_offset,
                    end_line=end_line,
                    severity="high" if self._loop_depth == 2 else "critical",
                    cwe_id="CWE-400",
                    source_file=self.source_file,
                    evidence=evidence,
                    explanation=(
                        f"A nested iteration loop was detected at depth {self._loop_depth}. "
                        "When processing unconstrained input collections, quadratic O(N^2) time complexity "
                        "can cause CPU resource exhaustion and excessive thread latency."
                    ),
                    suggestion="Refactor using a hash map, dictionary, or set lookup to achieve O(N) linear time.",
                )
            )
        self.cyclomatic_complexity += 1
        self._loop_stack.append(node)
        self.generic_visit(node)
        self._loop_stack.pop()
        self._loop_depth -= 1

    def visit_For(self, node): self._enter_loop(node)
    def visit_While(self, node): self._enter_loop(node)

    def visit_If(self, node):
        self.cyclomatic_complexity += 1
        self.generic_visit(node)

    def visit_ExceptHandler(self, node):
        self.cyclomatic_complexity += 1
        if node.type is None:
            end_line = getattr(node, "end_lineno", node.lineno)
            evidence = self._get_evidence(node.lineno, end_line)
            self.findings.append(
                ASTFinding(
                    rule_id="AST-ERR-001",
                    node_type="BareExcept",
                    description="Bare `except:` swallows all exceptions including SystemExit and KeyboardInterrupt",
                    line=node.lineno,
                    col=node.col_offset,
                    end_line=end_line,
                    severity="medium",
                    cwe_id="CWE-391",
                    source_file=self.source_file,
                    evidence=evidence,
                    explanation="Broad exception catching hides genuine bugs, syntax errors, and signal interrupts.",
                    suggestion="Use `except Exception as e:` or catch explicit exception types.",
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
            "eval": ("Dynamic code evaluation RCE risk", "CWE-94", "AST-SEC-001"),
            "exec": ("Dynamic code execution RCE risk", "CWE-94", "AST-SEC-002"),
            "os.system": ("OS Command injection vector", "CWE-78", "AST-SEC-003"),
            "subprocess.call": ("Unvalidated shell command execution", "CWE-78", "AST-SEC-004"),
            "pickle.loads": ("Insecure binary deserialization leading to RCE", "CWE-502", "AST-SEC-005"),
            "yaml.load": ("Insecure YAML load without safe loader", "CWE-502", "AST-SEC-006"),
        }
        if call_name in dangerous:
            if call_name == "yaml.load":
                has_safe_loader = any(
                    kw.arg == "Loader" and any(safe in ast.unparse(kw.value) for safe in ("SafeLoader", "BaseLoader"))
                    for kw in node.keywords
                )
                if has_safe_loader:
                    self.generic_visit(node)
                    return

            desc, cwe, rule = dangerous[call_name]
            end_line = getattr(node, "end_lineno", node.lineno)
            evidence = self._get_evidence(node.lineno, end_line)
            self.dangerous_calls.append(call_name)
            self.findings.append(
                ASTFinding(
                    rule_id=rule,
                    node_type="DangerousCall",
                    description=f"`{call_name}()` — {desc}",
                    line=node.lineno,
                    col=node.col_offset,
                    end_line=end_line,
                    severity="critical",
                    cwe_id=cwe,
                    source_file=self.source_file,
                    evidence=evidence,
                    explanation=f"Direct invocation of '{call_name}' permits attackers to execute arbitrary system commands or load malicious objects.",
                    suggestion="Replace with a secure library alternative (e.g. json.loads, subprocess.run).",
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

    def scan(self, code: str, filename: str = "code.py") -> ASTReport:
        try:
            tree = ast.parse(textwrap.dedent(code))
            visitor = _PythonASTVisitor(code=code, source_file=filename)
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
        except SyntaxError as e:
            line = e.lineno or 1
            col = e.offset or 0
            lines = code.splitlines()
            evidence = lines[line - 1].strip() if 0 < line <= len(lines) else code[:60]
            finding = ASTFinding(
                rule_id="AST-SYNTAX-ERR",
                node_type="SyntaxError",
                description=f"Python syntax error: {e.msg}",
                line=line,
                col=col,
                severity="critical",
                cwe_id="CWE-1107",
                source_file=filename,
                evidence=evidence,
                explanation=f"Python AST parser encountered invalid syntax at line {line}: {e.msg}.",
                suggestion="Correct the Python syntax error before running security verification.",
            )
            return ASTReport(
                cyclomatic_complexity=1,
                max_loop_depth=0,
                function_count=0,
                class_count=0,
                dangerous_calls=[],
                findings=[finding],
                original_snippet=code.strip(),
            )
        except Exception:
            # Fallback to generic regex scanning for other parsing exceptions
            from app.utils.scanners.generic_fallback import scan_generic_regex
            return scan_generic_regex(code, "python")

