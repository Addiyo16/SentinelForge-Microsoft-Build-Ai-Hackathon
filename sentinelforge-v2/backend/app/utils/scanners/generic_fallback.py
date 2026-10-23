"""
SentinelForge — Generic Regex Heuristic Scanner Fallback
Defines general regex scanning for non-Python languages and syntax error fallbacks.
Enforces stable rule IDs, CWE identifiers, and evidence snippets for all findings.
"""

import re
from typing import Optional
from app.utils.scanners.base_scanner import ASTReport, ASTFinding


def scan_generic_regex(code: str, lang: str, filename: str = "code") -> ASTReport:
    """Run regex-based token complexity scan for a specific language."""
    findings: list[ASTFinding] = []
    dangerous_calls: list[str] = []

    lines = code.splitlines()
    cc = 1
    funcs = 0
    classes = 0

    max_loop_depth = 0
    total_braces = 0
    active_loops: list[tuple[int, str, int]] = []  # (line_num, line_str, brace_depth)

    fn_lower = filename.lower()
    is_declarative = (
        lang.lower() in ("yaml", "yml", "json", "toml", "xml", "markdown", "text", "config")
        or fn_lower.endswith((".yml", ".yaml", ".json", ".toml", ".xml", ".ini", ".cfg", ".md", ".txt"))
    )
    loop_pattern = re.compile(r"^\s*(for\s*\(|while\s*\(|for\s+\w+\s+in\s+|foreach\s*\()")

    # Mapping of language patterns: (regex, call_name, description, rule_id, cwe_id, severity)
    dangerous_patterns = {
        "javascript": [
            (r"\beval\s*\(", "eval", "Dynamic JavaScript code evaluation RCE risk", "AST-SEC-JS-001", "CWE-95", "critical"),
            (r"\bexec\s*\(", "exec", "Node.js child_process.exec command execution vector", "AST-SEC-JS-002", "CWE-78", "critical"),
            (r"\bdangerouslySetInnerHTML\b", "dangerouslySetInnerHTML", "React XSS injection risk", "AST-SEC-JS-003", "CWE-79", "high"),
        ],
        "typescript": [
            (r"\beval\s*\(", "eval", "Dynamic JS/TS code evaluation RCE risk", "AST-SEC-TS-001", "CWE-95", "critical"),
            (r"\bexec\s*\(", "exec", "Node.js command execution vector", "AST-SEC-TS-002", "CWE-78", "critical"),
            (r"\bdangerouslySetInnerHTML\b", "dangerouslySetInnerHTML", "React XSS injection risk", "AST-SEC-TS-003", "CWE-79", "high"),
        ],
        "java": [
            (r"\.exec\s*\(", "Runtime.exec", "Java Process Command injection vector", "AST-SEC-JAVA-001", "CWE-78", "critical"),
            (r"\breadObject\s*\(", "readObject", "Java insecure deserialization RCE vulnerability", "AST-SEC-JAVA-002", "CWE-502", "critical"),
        ],
        "c_cpp": [
            (r"\bstrcpy\s*\(", "strcpy", "C string copy buffer overflow vector", "AST-SEC-C-001", "CWE-120", "high"),
            (r"\bgets\s*\(", "gets", "C deprecated insecure console read call", "AST-SEC-C-002", "CWE-242", "critical"),
            (r"\bsystem\s*\(", "system", "C command shell execution vector", "AST-SEC-C-003", "CWE-78", "critical"),
        ],
        "cpp": [
            (r"\bstrcpy\s*\(", "strcpy", "C string copy buffer overflow vector", "AST-SEC-C-001", "CWE-120", "high"),
            (r"\bgets\s*\(", "gets", "C deprecated insecure console read call", "AST-SEC-C-002", "CWE-242", "critical"),
            (r"\bsystem\s*\(", "system", "C command shell execution vector", "AST-SEC-C-003", "CWE-78", "critical"),
        ],
        "go": [
            (r"\bunsafe\.Pointer\b", "unsafe.Pointer", "Go memory safety bypass pattern", "AST-SEC-GO-001", "CWE-119", "medium"),
            (r"\bexec\.Command\s*\(", "exec.Command", "Go process command execution", "AST-SEC-GO-002", "CWE-78", "high"),
        ],
        "yaml": [
            (r"\bchmod\s+(-R\s+)?(777|a\+rwx)\b", "chmod 777", "Overly permissive DevOps execution mode", "AST-SEC-OPS-001", "CWE-732", "high"),
            (r"\bUSER\s+root\b|\bprivileged:\s*true\b", "privileged execution", "Container building with elevated root privileges", "AST-SEC-OPS-002", "CWE-250", "high"),
        ],
    }

    for line_idx, line in enumerate(lines, 1):
        clean_line = line.strip()
        if not clean_line or clean_line.startswith("//") or clean_line.startswith("#") or clean_line.startswith("/*"):
            continue

        # Cyclomatic complexity tokens (imperative code only)
        if not is_declarative:
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
        for pattern, call_name, desc, rule_id, cwe_id, sev in lang_checks:
            if re.search(pattern, clean_line):
                dangerous_calls.append(call_name)
                findings.append(
                    ASTFinding(
                        rule_id=rule_id,
                        node_type="DangerousCall",
                        description=f"`{call_name}` — {desc}",
                        line=line_idx,
                        col=max(0, line.find(call_name)),
                        severity=sev,
                        cwe_id=cwe_id,
                        source_file=filename,
                        evidence=clean_line,
                        explanation=f"Detected potentially dangerous call `{call_name}` in {lang.upper()} source ({desc}).",
                        suggestion=f"Replace `{call_name}` with a safe library counterpart.",
                    )
                )

        # Loop Nesting Tracker (imperative code only)
        if not is_declarative:
            if "{" in clean_line:
                total_braces += clean_line.count("{")

            if loop_pattern.search(clean_line):
                active_loops.append((line_idx, clean_line, total_braces))
                curr_depth = len(active_loops)
                max_loop_depth = max(max_loop_depth, curr_depth)
                if curr_depth >= 2:
                    outer_line, outer_snippet, _ = active_loops[0]
                    evidence = f"Outer loop (Line {outer_line}): {outer_snippet}\nInner loop (Line {line_idx}): {clean_line}"
                    findings.append(
                        ASTFinding(
                            rule_id="AST-PERF-001",
                            node_type="NestedLoop",
                            description=f"Nested loop depth {curr_depth} — quadratic O(N^{curr_depth}) execution complexity",
                            line=line_idx,
                            col=0,
                            severity="high" if curr_depth == 2 else "critical",
                            cwe_id="CWE-400",
                            source_file=filename,
                            evidence=evidence,
                            explanation=(
                                f"A nested iteration loop was detected at depth {curr_depth} in {filename}. "
                                "When processing unconstrained collections, quadratic time complexity can cause CPU resource exhaustion."
                            ),
                            suggestion="Consider hash maps, indexing, or sorting collections to reach O(N) linear runtime.",
                        )
                    )

            if "}" in clean_line:
                total_braces = max(0, total_braces - clean_line.count("}"))
                active_loops = [loop for loop in active_loops if loop[2] <= total_braces and total_braces > 0]

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
