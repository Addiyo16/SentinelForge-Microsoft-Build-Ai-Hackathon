"""
SentinelForge — Microsoft Teams Webhook Integrator
Sends automated, rich security reports directly to a Microsoft Teams channel when patches are synthesized.
"""

import httpx
from typing import Optional
from app.utils.vault import get_secret


async def send_teams_notification(
    repo: str,
    branch: str,
    commit_sha: str,
    risk_score: int,
    approved: bool,
    pr_url: Optional[str] = None,
    trie_count: int = 0,
    ast_count: int = 0,
    cc: int = 0,
) -> bool:
    """
    Sends a rich MessageCard notification to Microsoft Teams.
    Returns True if successfully sent, False otherwise.
    """
    # Fetch Webhook URL securely via Key Vault or Local Env
    webhook_url = get_secret("TEAMS_WEBHOOK_URL")
    if not webhook_url:
        return False

    theme_color = "22C55E" if approved else "EF4444"
    status_text = "✅ APPROVED" if approved else "⚠️ CHANGES REQUESTED"
    pr_section = f"[View GitHub Pull Request]({pr_url})" if pr_url else "*(Local Run - No PR Created)*"

    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions/message-card.json",
        "themeColor": theme_color,
        "summary": f"SentinelForge Patch Generated for {repo}",
        "sections": [
            {
                "activityTitle": "🛡️ SentinelForge AI Security Pipeline",
                "activitySubtitle": f"Repository: **{repo}** · Branch: `{branch}`",
                "activityImage": "https://img.icons8.com/color/100/shield.png",
                "facts": [
                    {"name": "Commit SHA", "value": f"`{commit_sha[:8]}`"},
                    {"name": "Swarm Decision", "value": f"**{status_text}**"},
                    {"name": "Vulnerability Risk", "value": f"**{risk_score}/100**"},
                    {"name": "Trie Signatures", "value": f"{trie_count} matches"},
                    {"name": "AST Findings", "value": f"{ast_count} structural issues"},
                    {"name": "Cyclomatic Complexity", "value": f"{cc}"}
                ],
                "markdown": True
            },
            {
                "title": "🤖 Auto-Patch Generation Details",
                "text": (
                    f"SentinelForge has completed the 8-stage audit of the pushed commits. "
                    f"A patch has been generated to fix security issues (such as hardcoded credentials or O(N²) loop nesting).\n\n"
                    f"⚡ {pr_section}"
                ),
                "markdown": True
            }
        ]
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.post(webhook_url, json=payload)
            return r.status_code == 200
    except Exception as e:
        print(f"[TEAMS] Webhook error: {e}")
        return False
