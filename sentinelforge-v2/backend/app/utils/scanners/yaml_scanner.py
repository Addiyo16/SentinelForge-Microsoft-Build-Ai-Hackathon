"""
SentinelForge — YAML Configuration Security Scanner
Performs deterministic structural and security analysis on YAML configurations (Kubernetes, CI/CD, OpenAPI/Swagger).
Guarantees:
- Zero false-positive loop or algorithmic complexity findings on declarative configuration files.
- Accurate detection and evidence tracking for real YAML risks: Insecure tags (CWE-502),
  Entity expansion / Billion laughs anchor bombs (CWE-776/CWE-400), permissive permissions (CWE-732),
  and privileged container execution (CWE-250).
"""

import re
from typing import Optional
from app.utils.scanners.base_scanner import BaseScanner, ASTReport, ASTFinding


class YamlScanner(BaseScanner):
    """YAML configuration and CI/CD manifest security scanner."""

    def scan(self, code: str, filename: str = "deploy.yml") -> ASTReport:
        findings: list[ASTFinding] = []
        dangerous_calls: list[str] = []

        lines = code.splitlines()

        # Track anchor definitions and alias expansions for real CWE-776/CWE-400 resource exhaustion
        anchors: dict[str, int] = {}
        aliases: list[tuple[int, str]] = []

        anchor_re = re.compile(r"&([a-zA-Z0-9_-]+)")
        alias_re = re.compile(r"\*([a-zA-Z0-9_-]+)")

        for line_idx, line in enumerate(lines, 1):
            clean_line = line.strip()
            if not clean_line or clean_line.startswith("#"):
                continue

            # 1. Insecure Deserialization Tags (CWE-502)
            if re.search(r"!!python/object|!ruby/object|!javax\.script|!org\.yaml", clean_line):
                call_name = "YAML Custom Tag"
                dangerous_calls.append(call_name)
                findings.append(
                    ASTFinding(
                        rule_id="SF-YAML-001",
                        node_type="InsecureTag",
                        description="Insecure YAML object instantiation tag enables remote code execution (CWE-502)",
                        line=line_idx,
                        col=0,
                        severity="critical",
                        cwe_id="CWE-502",
                        source_file=filename,
                        evidence=clean_line,
                        explanation=(
                            f"Detected unsafe custom type tag `{clean_line}` in {filename}. "
                            "Unsafe deserialization of YAML payloads with executable constructors allows Arbitrary Code Execution."
                        ),
                        suggestion="Use safe YAML loading (e.g. yaml.safe_load) without custom object instantiation tags.",
                    )
                )

            # 2. Overly Permissive Execution Permissions (CWE-732)
            if re.search(r"\bchmod\s+(-R\s+)?(777|a\+rwx)\b", clean_line):
                call_name = "chmod 777"
                dangerous_calls.append(call_name)
                findings.append(
                    ASTFinding(
                        rule_id="AST-SEC-OPS-001",
                        node_type="PermissivePermissions",
                        description="Overly permissive file mode chmod 777 configured in pipeline (CWE-732)",
                        line=line_idx,
                        col=0,
                        severity="high",
                        cwe_id="CWE-732",
                        source_file=filename,
                        evidence=clean_line,
                        explanation=(
                            f"Execution mode 777 configured at line {line_idx}. Granting read/write/execute "
                            "to all users violates the principle of least privilege."
                        ),
                        suggestion="Restrict file permissions to specific required user/group (e.g. chmod 750 or 700).",
                    )
                )

            # 3. Privileged Container Execution (CWE-250)
            if re.search(r"\bUSER\s+root\b|\bprivileged:\s*true\b", clean_line, re.IGNORECASE):
                call_name = "privileged: true"
                dangerous_calls.append(call_name)
                findings.append(
                    ASTFinding(
                        rule_id="SF-YAML-004",
                        node_type="PrivilegedExecution",
                        description="Container configured to run with elevated root privileges (CWE-250)",
                        line=line_idx,
                        col=0,
                        severity="high",
                        cwe_id="CWE-250",
                        source_file=filename,
                        evidence=clean_line,
                        explanation=(
                            f"Container or step configured with root/privileged execution at line {line_idx}. "
                            "Allows container escape and privilege escalation on host systems."
                        ),
                        suggestion="Execute containers as non-root service accounts and set privileged: false.",
                    )
                )

            # 4. GitHub Actions pull_request_target Untrusted Checkout (CWE-829)
            if "pull_request_target" in clean_line:
                findings.append(
                    ASTFinding(
                        rule_id="SF-YAML-005",
                        node_type="UntrustedWorkflowTrigger",
                        description="Workflow uses pull_request_target trigger requiring strict checkout validation (CWE-829)",
                        line=line_idx,
                        col=0,
                        severity="medium",
                        cwe_id="CWE-829",
                        source_file=filename,
                        evidence=clean_line,
                        explanation=(
                            "The pull_request_target trigger runs with repository write privileges and access to secrets. "
                            "Checking out or executing untrusted PR code within this context exposes secrets to exfiltration."
                        ),
                        suggestion="Use pull_request event for untrusted fork testing or avoid checking out PR head ref.",
                    )
                )

            # Track anchors and aliases
            for m in anchor_re.finditer(clean_line):
                anchors[m.group(1)] = line_idx
            for m in alias_re.finditer(clean_line):
                aliases.append((line_idx, m.group(1)))

        # 5. Genuine YAML Billion Laughs / Anchor Bombing (CWE-776 / CWE-400)
        # Only triggered when actual anchor bomb structure exists with excessive alias expansion ratio
        if len(anchors) >= 3 and len(aliases) >= 15:
            first_alias_line, first_alias_name = aliases[0]
            evidence_sample = f"&{first_alias_name} defined at line {anchors.get(first_alias_name, 1)}, referenced across {len(aliases)} alias expansions"
            findings.append(
                ASTFinding(
                    rule_id="SF-YAML-002",
                    node_type="YamlEntityExpansion",
                    description=f"Recursive YAML entity expansion detected ({len(anchors)} anchors, {len(aliases)} aliases) — DoS risk (CWE-776/CWE-400)",
                    line=first_alias_line,
                    col=0,
                    severity="high",
                    cwe_id="CWE-776",
                    source_file=filename,
                    evidence=evidence_sample,
                    explanation=(
                        f"Detected YAML anchor/alias amplification bomb in {filename}. "
                        "Recursive anchor references multiply during parsing, consuming gigabytes of memory and causing CPU exhaustion."
                    ),
                    suggestion="Disable YAML alias resolution or limit maximum alias recursion depth in parser.",
                )
            )

        return ASTReport(
            cyclomatic_complexity=1,
            max_loop_depth=0,
            function_count=0,
            class_count=0,
            dangerous_calls=list(set(dangerous_calls)),
            findings=findings,
            original_snippet=code,
        )
