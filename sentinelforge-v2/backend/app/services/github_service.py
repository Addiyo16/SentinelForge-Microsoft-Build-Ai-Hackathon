"""
SentinelForge — GitHub Integration Service
Handles webhook verification, diff fetching, and PR creation.
Now inherits from BaseCIService.
"""

import hashlib
import hmac
from typing import Optional, List

import httpx

from app.services.base_ci_service import BaseCIService, PushEvent, SourceFile
from app.utils.vault import get_secret

# For backwards compatibility
GitHubFile = SourceFile


class GitHubService(BaseCIService):
    """GitHub provider service implementation."""

    def verify_webhook(self, payload_bytes: bytes, signature: str) -> bool:
        """Verify GitHub webhook HMAC-SHA256 signature."""
        secret = get_secret("GITHUB_WEBHOOK_SECRET", "")
        if not secret:
            return True  # Skip verification in dev mode
        expected = "sha256=" + hmac.new(
            secret.encode(), payload_bytes, hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, signature or "")

    def parse_push_event(self, payload: dict) -> PushEvent:
        """Extract key fields from a GitHub push webhook payload."""
        repo = payload.get("repository", {})
        head_commit = payload.get("head_commit", {})
        commits = payload.get("commits", [{}])

        modified = []
        added = []
        for commit in commits:
            modified.extend(commit.get("modified", []))
            added.extend(commit.get("added", []))

        return PushEvent(
            repo_full_name=repo.get("full_name", ""),
            commit_sha=payload.get("after", ""),
            commit_message=head_commit.get("message", ""),
            pusher=payload.get("pusher", {}).get("name", "unknown"),
            branch=payload.get("ref", "").replace("refs/heads/", ""),
            files_modified=list(set(modified)),
            files_added=list(set(added)),
        )

    async def fetch_changed_files(self, event: PushEvent, max_files: int = 5) -> List[SourceFile]:
        """Fetch content of all changed polyglot source files from a push event."""
        token = get_secret("GITHUB_TOKEN")
        all_files = (event.files_modified + event.files_added)
        
        # Supported file extensions
        source_exts = (".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".c", ".cpp", ".h", ".go", ".yml", ".yaml")
        target_files = [f for f in all_files if f.lower().endswith(source_exts)][:max_files]

        results = []
        for filepath in target_files:
            file = await self._fetch_file_content(event.repo_full_name, event.commit_sha, filepath, token)
            if file:
                results.append(file)
        return results

    async def _fetch_file_content(
        self, repo: str, sha: str, filepath: str, token: Optional[str] = None
    ) -> Optional[SourceFile]:
        """Fetch raw file content from GitHub at a specific commit."""
        headers = {"Accept": "application/vnd.github.v3.raw"}
        if token:
            headers["Authorization"] = f"token {token}"

        url = f"https://raw.githubusercontent.com/{repo}/{sha}/{filepath}"
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                r = await client.get(url, headers=headers)
                if r.status_code != 200:
                    return None
                lang = self._detect_language(filepath)
                return SourceFile(
                    filename=filepath,
                    content=r.text,
                    sha=sha,
                    language=lang,
                )
            except httpx.RequestError:
                return None

    async def get_ci_status(self, repo: str, sha: str) -> dict:
        """Fetch CI/CD check run status for a commit."""
        token = get_secret("GITHUB_TOKEN")
        headers = {"Accept": "application/vnd.github.v3+json"}
        if token:
            headers["Authorization"] = f"token {token}"

        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(
                f"https://api.github.com/repos/{repo}/commits/{sha}/check-runs",
                headers=headers,
            )
            if r.status_code != 200:
                return {"total_count": 0, "check_runs": []}
            data = r.json()
            runs = [
                {
                    "name": cr["name"],
                    "status": cr["status"],
                    "conclusion": cr.get("conclusion"),
                    "url": cr.get("html_url"),
                }
                for cr in data.get("check_runs", [])
            ]
            return {
                "total_count": data.get("total_count", 0),
                "check_runs": runs,
                "summary": self._summarize_checks(runs),
            }

    async def create_pull_request(
        self,
        repo: str,
        base_branch: str,
        head_branch: str,
        title: str,
        body: str,
    ) -> Optional[str]:
        """Create a GitHub Pull Request. Returns the PR URL or None on failure."""
        token = get_secret("GITHUB_TOKEN")
        if not token:
            return None

        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.post(
                f"https://api.github.com/repos/{repo}/pulls",
                headers={
                    "Authorization": f"token {token}",
                    "Accept": "application/vnd.github.v3+json",
                },
                json={
                    "title": title,
                    "body": body,
                    "head": head_branch,
                    "base": base_branch,
                },
            )
            if r.status_code in (200, 201):
                return r.json().get("html_url")
            return None

    def _summarize_checks(self, runs: List[dict]) -> str:
        if not runs:
            return "no_checks"
        conclusions = [r.get("conclusion") for r in runs if r.get("conclusion")]
        if all(c == "success" for c in conclusions):
            return "all_passing"
        if any(c == "failure" for c in conclusions):
            return "failing"
        return "pending"

    def _detect_language(self, filepath: str) -> str:
        ext_map = {
            ".py": "python", ".js": "javascript", ".ts": "typescript",
            ".jsx": "javascript", ".tsx": "typescript",
            ".go": "go", ".java": "java", ".rb": "ruby", ".rs": "rust",
            ".c": "c", ".cpp": "c++", ".h": "c/c++ header",
            ".yml": "yaml", ".yaml": "yaml"
        }
        for ext, lang in ext_map.items():
            if filepath.endswith(ext):
                return lang
        return "unknown"


# For backwards compatibility with direct function imports
_service = GitHubService()
verify_signature = _service.verify_webhook
parse_push_event = _service.parse_push_event
fetch_changed_files = _service.fetch_changed_files
get_ci_status = _service.get_ci_status
create_pull_request = _service.create_pull_request
