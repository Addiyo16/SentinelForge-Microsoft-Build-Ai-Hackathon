"""
SentinelForge — AutoGen Multi-Agent Swarm
Three specialized agents collaborate on code review:
  • SecurityAuditor   — finds vulnerabilities
  • CodeOptimizer     — rewrites for performance
  • PatchSynthesizer  — merges findings into a final patch
"""

import asyncio
import os
from dataclasses import dataclass
from typing import Optional

import openai


@dataclass
class AgentMessage:
    agent: str
    role: str  # auditor | optimizer | synthesizer
    content: str
    timestamp: float


@dataclass
class SwarmResult:
    dialogue: list[AgentMessage]
    final_patch: str
    pr_description: str
    risk_score: int  # 0–100
    approved: bool

    def to_dict(self) -> dict:
        return {
            "dialogue": [
                {
                    "agent": m.agent,
                    "role": m.role,
                    "content": m.content,
                    "timestamp": m.timestamp,
                }
                for m in self.dialogue
            ],
            "final_patch": self.final_patch,
            "pr_description": self.pr_description,
            "risk_score": self.risk_score,
            "approved": self.approved,
        }


def _get_client() -> openai.AsyncAzureOpenAI:
    return openai.AsyncAzureOpenAI(
        api_key=os.environ["AZURE_OPENAI_API_KEY"],
        azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
        api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2024-05-01-preview"),
    )


async def _call_agent(
    client: openai.AsyncAzureOpenAI,
    deployment: str,
    system_prompt: str,
    user_message: str,
    max_tokens: int = 800,
) -> str:
    response = await client.chat.completions.create(
        model=deployment,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ],
        max_tokens=max_tokens,
        temperature=0.2,
    )
    return response.choices[0].message.content.strip()


async def run_swarm(
    code: str,
    trie_findings: list[dict],
    ast_report: dict,
    rag_context: list[dict],
) -> SwarmResult:
    """
    Run three agents in sequence, each building on prior context.
    Auditor and Optimizer run in parallel; Synthesizer merges them.
    """
    import time

    client = _get_client()
    optimizer_deploy = os.getenv("AZURE_OPTIMIZER_DEPLOYMENT", "gpt-4o")
    auditor_deploy = os.getenv("AZURE_AUDITOR_DEPLOYMENT", "gpt-4o-mini")

    rag_summary = "\n".join(
        f"- [{r['kb_ref']}] {r['vulnerability_type']}: {r['historical_fix']}"
        for r in rag_context
    )
    threat_summary = "\n".join(
        f"- {t.get('category','?')} ({t.get('severity','?')}): pattern `{t.get('pattern','?')}`"
        for t in trie_findings
    )
    ast_summary = (
        f"Cyclomatic complexity: {ast_report.get('cyclomatic_complexity')}, "
        f"Max loop depth: {ast_report.get('max_loop_depth')}, "
        f"Dangerous calls: {ast_report.get('dangerous_calls')}"
    )

    dialogue: list[AgentMessage] = []

    # ── Stage 1: Auditor & Optimizer run in parallel ──────────────────────────

    auditor_system = (
        "You are SecurityAuditor, an expert in OWASP Top 10 and CWE vulnerability analysis. "
        "Analyse the provided code for security issues. Be concise, technical, and specific. "
        "Format: 3-5 bullet points with severity labels."
    )
    auditor_prompt = (
        f"Code to audit:\n```python\n{code}\n```\n\n"
        f"Trie threat signatures found:\n{threat_summary}\n\n"
        f"RAG knowledge base context:\n{rag_summary}\n\n"
        f"AST metrics:\n{ast_summary}\n\n"
        "List all security vulnerabilities, their CWE references, and recommended fixes."
    )

    optimizer_system = (
        "You are CodeOptimizer, an expert in Python performance and clean code. "
        "Rewrite the code to be faster, safer, and more maintainable. "
        "Provide the full rewritten function with inline comments explaining each change."
    )
    optimizer_prompt = (
        f"Original code:\n```python\n{code}\n```\n\n"
        f"AST analysis:\n{ast_summary}\n\n"
        f"RAG-suggested optimizations:\n{rag_summary}\n\n"
        "Provide the optimized version of the code."
    )

    auditor_task = _call_agent(client, auditor_deploy, auditor_system, auditor_prompt)
    optimizer_task = _call_agent(client, optimizer_deploy, optimizer_system, optimizer_prompt)

    auditor_response, optimizer_response = await asyncio.gather(auditor_task, optimizer_task)
    now = time.time()

    dialogue.append(AgentMessage(agent="SecurityAuditor", role="auditor", content=auditor_response, timestamp=now))
    dialogue.append(AgentMessage(agent="CodeOptimizer", role="optimizer", content=optimizer_response, timestamp=now + 0.1))

    # ── Stage 2: Synthesizer merges both ─────────────────────────────────────

    synthesizer_system = (
        "You are PatchSynthesizer, the lead engineer reviewing code changes before merge. "
        "Given the security audit and the optimized code, produce:\n"
        "1. A final merged patch (the best version of the code)\n"
        "2. A GitHub PR description in Markdown with sections: Summary, Changes, Risk Score (0-100), Recommendation\n"
        "3. Whether you APPROVE or REQUEST_CHANGES\n\n"
        "Format your response as:\n"
        "PATCH:\n```python\n<code>\n```\n\n"
        "PR_DESCRIPTION:\n<markdown>\n\n"
        "RISK_SCORE: <number>\n"
        "DECISION: APPROVE or REQUEST_CHANGES"
    )
    synthesizer_prompt = (
        f"Security Audit:\n{auditor_response}\n\n"
        f"Optimized Code:\n{optimizer_response}\n\n"
        "Produce the final patch, PR description, risk score, and decision."
    )

    synth_response = await _call_agent(
        client, optimizer_deploy, synthesizer_system, synthesizer_prompt, max_tokens=1200
    )
    dialogue.append(AgentMessage(agent="PatchSynthesizer", role="synthesizer", content=synth_response, timestamp=time.time()))

    # ── Parse synthesizer output ──────────────────────────────────────────────

    final_patch = _extract_between(synth_response, "```python", "```") or optimizer_response
    pr_description = _extract_after(synth_response, "PR_DESCRIPTION:") or synth_response
    risk_score = _extract_int(synth_response, "RISK_SCORE:") or 50
    approved = "APPROVE" in synth_response and "REQUEST_CHANGES" not in synth_response

    return SwarmResult(
        dialogue=dialogue,
        final_patch=final_patch,
        pr_description=pr_description,
        risk_score=risk_score,
        approved=approved,
    )


def _extract_between(text: str, start: str, end: str) -> Optional[str]:
    try:
        s = text.index(start) + len(start)
        e = text.index(end, s)
        return text[s:e].strip()
    except ValueError:
        return None


def _extract_after(text: str, marker: str) -> Optional[str]:
    try:
        idx = text.index(marker) + len(marker)
        chunk = text[idx:].strip()
        # Stop at next section marker
        for stop in ["RISK_SCORE:", "DECISION:", "PATCH:"]:
            if stop in chunk:
                chunk = chunk[: chunk.index(stop)].strip()
        return chunk
    except ValueError:
        return None


def _extract_int(text: str, marker: str) -> Optional[int]:
    try:
        idx = text.index(marker) + len(marker)
        chunk = text[idx:idx+10].strip().split()[0]
        return int("".join(c for c in chunk if c.isdigit()))
    except (ValueError, IndexError):
        return None
