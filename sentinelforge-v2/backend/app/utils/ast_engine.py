"""
SentinelForge — Polyglot AST Analysis Engine
Deep structural analysis supporting Python, JS/TS, Java, Go, C/C++, and YAML.
Uses Python ast for Python files, and custom regex pseudo-parsers for other languages.
"""

import ast
import re
import textwrap
from dataclasses import dataclass
from typing import Optional, Any


@dataclass
class ASTFinding:
    node_type: str
    description: str
    line: int
    col: int
    severity: str  # critical | high | medium | low | info
    suggestion: Optional[str] = None

    def to_dict(self) -> dict:
        return self.__dict__


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
            "findings": [f.to_dict() for f in self.findings],
            "optimized_snippet": self.optimized_snippet,
            "original_snippet": self.original_snippet,
        }


# --- Python AST Visitor ---

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


# --- Regex Pseudo-Parser for JS, Java, C/C++, Go ---

def _detect_lang(code: str) -> str:
    """Guess programming language based on keywords/structures."""
    if "import java." in code or "public class " in code or "System.out.println" in code:
        return "java"
    if "const " in code or "let " in code or "require(" in code or "import React" in code or "function " in code:
        return "javascript"
    if "#include <" in code or "std::" in code or "void main(" in code or "printf(" in code:
        return "c_cpp"
    if "package main" in code or "func " in code:
        return "go"
    if "apiVersion:" in code or "jobs:" in code or "steps:" in code:
        return "yaml"
    return "python"


def _analyze_generic(code: str, lang: str) -> ASTReport:
    """Run regex-based token complexity scan for non-python files."""
    findings = []
    dangerous_calls = []
    
    # Simple lines analysis
    lines = code.splitlines()
    cc = 1
    funcs = 0
    classes = 0
    
    # 1. Nesting Loop Depth Checker
    # Simple brace parsing to track max nesting loop depth
    loop_depth = 0
    max_loop_depth = 0
    brace_stack = []  # tracks loop braces

    # Loop keywords by language
    loop_pattern = re.compile(r"\b(for|while|foreach)\b")
    
    # dangerous calls patterns
    dangerous_patterns = {
        "javascript": [
            (r"\beval\s*\(", "eval", "Dynamic JavaScript code evaluation RCE risk"),
            (r"\bexec\s*\(", "exec", "Node.js child_process.exec command execution vector"),
            (r"\bdangerouslySetInnerHTML\b", "dangerouslySetInnerHTML", "React XSS injection risk"),
        ],
        "java": [
            (r"\.exec\s*\(", "Runtime.exec", "Java Process Command injection vector"),
            (r"\breadObject\s*\(", "readObject", "Java insecure deserialization RCE vulnerability"),
        ],
        "c_cpp": [
            (r"\bstrcpy\s*\(", "strcpy", "C string copy buffer overflow vector"),
            (r"\bgets\s*\(", "gets", "C deprecated insecure console read call"),
            (r"\bsystem\s*\(", "system", "C command shell execution vector"),
        ],
        "go": [
            (r"\bunsafe\.Pointer\b", "unsafe.Pointer", "Go memory safety bypass pattern"),
            (r"\bexec\.Command\s*\(", "exec.Command", "Go process command execution"),
        ],
        "yaml": [
            (r"\bchmod 777\b", "chmod 777", "Overly permissive DevOps execution mode"),
            (r"\bUSER root\b", "USER root", "Container building as root superuser"),
        ]
    }

    # Iterate lines
    for line_idx, line in enumerate(lines, 1):
        clean_line = line.strip()
        if not clean_line or clean_line.startswith("//") or clean_line.startswith("#") or clean_line.startswith("/*"):
            continue

        # Cyclomatic complexity tokens
        branches = len(re.findall(r"\b(if|else if|catch|case|&{2}|\|{2})\b", clean_line))
        cc += branches

        # Function declarations
        if lang == "javascript":
            if re.search(r"\b(function\s+\w+|const\s+\w+\s*=\s*\([^)]*\)\s*=>)", clean_line):
                funcs += 1
            if re.search(r"\bclass\s+\w+", clean_line):
                classes += 1
        elif lang == "java" or lang == "c_cpp":
            # Matching return_type function_name(args)
            if re.search(r"\b(public|private|protected|static|void|int|double|char|string|float) +[\w<>\\[\\]]+ +\w+\s*\([^)]*\)", clean_line):
                funcs += 1
            if re.search(r"\b(class|struct|interface)\s+\w+", clean_line):
                classes += 1
        elif lang == "go":
            if re.search(r"\bfunc\s+\w+\(", clean_line):
                funcs += 1
            if re.search(r"\btype\s+\w+\s+struct", clean_line):
                classes += 1

        # Check dangerous calls
        lang_checks = dangerous_patterns.get(lang, [])
        for pattern, call_name, desc in lang_checks:
            if re.search(pattern, clean_line):
                dangerous_calls.append(call_name)
                findings.append(
                    ASTFinding(
                        node_type="DangerousCall",
                        description=f"`{call_name}` — {desc}",
                        line=line_idx,
                        col=line.find(call_name) or 0,
                        severity="critical",
                        suggestion=f"Replace `{call_name}` with a safe library counterpart"
                    )
                )

        # Loop Nesting Tracker
        if loop_pattern.search(clean_line):
            loop_depth += 1
            max_loop_depth = max(max_loop_depth, loop_depth)
            if "{" in clean_line:
                brace_stack.append(loop_depth)
            if loop_depth >= 2:
                findings.append(
                    ASTFinding(
                        node_type="NestedLoop",
                        description=f"Nested loop depth {loop_depth} — potential complexity bottleneck",
                        line=line_idx,
                        col=0,
                        severity="high",
                        suggestion="Consider hash maps or sorting collections to reach O(N) linear runtime."
                    )
                )
        
        # Track closing braces to decrease loop depth
        if "}" in clean_line and brace_stack:
            # Simple closing heuristic
            loop_depth = max(0, loop_depth - 1)
            brace_stack.pop()

    report = ASTReport(
        cyclomatic_complexity=cc,
        max_loop_depth=max_loop_depth,
        function_count=funcs,
        class_count=classes,
        dangerous_calls=list(set(dangerous_calls)),
        findings=findings,
        original_snippet=code,
    )
    
    # Custom optimization recommendations based on language
    if max_loop_depth >= 2:
        if lang == "javascript":
            report.optimized_snippet = (
                "// SentinelForge ES6 Suggestion\n"
                "// Use Map/Set instead of nesting loops:\n"
                "const lookup = new Map(collection.map(item => [item.id, item]));\n"
                "const result = lookup.get(targetId); // O(1)"
            )
        elif lang == "java":
            report.optimized_snippet = (
                "// SentinelForge Java Suggestion\n"
                "// Use Map for O(1) hash resolution:\n"
                "Map<String, Item> lookup = collection.stream()\n"
                "    .collect(Collectors.toMap(Item::getId, Function.identity()));\n"
                "Item result = lookup.get(targetId);"
            )
        else:
            report.optimized_snippet = (
                "# SentinelForge Generic Suggestion\n"
                "# Index collections in hash maps to reduce complexity from O(N²) to O(N)."
            )

    return report


def analyze_code(code: str) -> ASTReport:
    """Parse and analyze Python source code, falling back to polyglot parser for other languages."""
    lang = _detect_lang(code)
    
    if lang == "python":
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
            # Fallback to regex parser if python ast parsing fails (e.g., malformed code)
            return _analyze_generic(code, "python")
    else:
        return _analyze_generic(code, lang)
