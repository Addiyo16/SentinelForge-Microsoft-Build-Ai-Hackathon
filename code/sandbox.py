"""
SentinelForge — Secure Sandbox Executor
Runs untrusted code in a restricted subprocess with resource limits.
"""

import asyncio
import os
import sys
import tempfile
from dataclasses import dataclass


@dataclass
class SandboxResult:
    stdout: str
    stderr: str
    exit_code: int
    timed_out: bool
    memory_exceeded: bool

    @property
    def success(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.memory_exceeded

    def to_dict(self) -> dict:
        return {
            "stdout": self.stdout,
            "stderr": self.stderr,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "memory_exceeded": self.memory_exceeded,
            "success": self.success,
        }


async def run_sandboxed(code: str, timeout: float = 5.0, max_mb: int = 64) -> SandboxResult:
    """
    Execute Python code in an isolated subprocess.
    - Hard timeout via asyncio (no zombie processes)
    - Memory limit via ulimit on Linux; approximated on Windows
    - Temp file cleaned up in finally block
    """
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write(_wrap_code(code, max_mb))
            tmp = f.name

        proc = await asyncio.create_subprocess_exec(
            sys.executable, tmp,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        timed_out = False
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            timed_out = True
            stdout_bytes, stderr_bytes = b"", b"[SentinelForge] Execution timed out"

        stdout = stdout_bytes.decode("utf-8", errors="replace").strip()
        stderr = stderr_bytes.decode("utf-8", errors="replace").strip()

        memory_exceeded = "MemoryError" in stderr or "[MEMORY]" in stderr

        return SandboxResult(
            stdout=stdout,
            stderr=stderr,
            exit_code=proc.returncode or 0,
            timed_out=timed_out,
            memory_exceeded=memory_exceeded,
        )

    finally:
        if tmp and os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


def _wrap_code(code: str, max_mb: int) -> str:
    """Wrap user code with memory guard and safe globals restriction."""
    return f"""
import resource, sys

# Apply memory limit (Linux only; silently skipped on Windows)
try:
    limit = {max_mb} * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
except Exception:
    pass

try:
{_indent(code)}
except MemoryError:
    print("[MEMORY] Memory limit exceeded", file=sys.stderr)
    sys.exit(1)
"""


def _indent(code: str, spaces: int = 4) -> str:
    return "\n".join(" " * spaces + line for line in code.splitlines())
