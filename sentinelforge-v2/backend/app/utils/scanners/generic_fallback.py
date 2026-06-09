"""
SentinelForge — Generic Regex Heuristic Scanner Fallback
Defines general regex scanning for non-Python languages and syntax error fallbacks.
"""

import re
from app.utils.scanners.base_scanner import ASTReport, ASTFinding


def scan_generic_regex(code: str, lang: str) -> ASTReport:
    """Run regex-based token complexity scan for a specific language."""
    findings = []
    dangerous_calls = []
    
    lines = code.splitlines()
    cc = 1
    funcs = 0
    classes = 0
    
    loop_depth = 0
    max_loop_depth = 0
    brace_stack = []  # tracks loop braces

    loop_pattern = re.compile(r"\b(for|while|foreach)\b")
    
    dangerous_patterns = {
        "javascript": [
            (r"\beval\s*\(", "eval", "Dynamic JavaScript code evaluation RCE risk"),
            (r"\bexec\s*\(", "exec", "Node.js child_process.exec command execution vector"),
            (r"\bdangerouslySetInnerHTML\b", "dangerouslySetInnerHTML", "React XSS injection risk"),
        ],
        "typescript": [
            (r"\beval\s*\(", "eval", "Dynamic JS/TS code evaluation RCE risk"),
            (r"\bexec\s*\(", "exec", "Node.js command execution vector"),
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

    for line_idx, line in enumerate(lines, 1):
        clean_line = line.strip()
        if not clean_line or clean_line.startswith("//") or clean_line.startswith("#") or clean_line.startswith("/*"):
            continue

        # Cyclomatic complexity tokens
        branches = len(re.findall(r"\b(if|else if|catch|case|&{2}|\|{2})\b", clean_line))
        cc += branches

        # Function declarations
        if lang in ("javascript", "typescript"):
            if re.search(r"\b(function\s+\w+|const\s+\w+\s*=\s*\([^)]*\)\s*=>)", clean_line):
                funcs += 1
            if re.search(r"\bclass\s+\w+", clean_line):
                classes += 1
        elif lang in ("java", "c_cpp", "cpp"):
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
        if lang in ("javascript", "typescript"):
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
