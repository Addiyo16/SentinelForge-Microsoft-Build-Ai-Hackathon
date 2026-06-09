"""
SentinelForge — GitLab Integration Service
Handles GitLab webhook verification, project files ingestion, pipeline status, and Merge Request creation.
Inherits from BaseCIService.
"""

import urllib.parse
from typing import Optional, List

import httpx

from app.services.base_ci_service import BaseCIService, PushEvent, SourceFile
from app.utils.vault import get_secret


class GitLabService(BaseCIService):
    """GitLab CI/CD provider service implementation."""

    def verify_webhook(self, payload_bytes: bytes, signature: str) -> bool:
        """Verify GitLab webhook token match (X-Gitlab-Token)."""
        secret = get_secret("GITLAB_WEBHOOK_SECRET", "")
        if not secret:
            return True  # Skip verification in dev mode
        return secret == signature

    def parse_push_event(self, payload: dict) -> PushEvent:
        """Extract key fields from a GitLab push webhook payload."""
        project = payload.get("project", {})
        repo_name = project.get("path_with_namespace", "")
        
        # GitLab commits list
        commits = payload.get("commits", [])
        modified = []
        added = []
        for commit in commits:
            modified.extend(commit.get("modified", []))
            added.extend(commit.get("added", []))

        # GitLab push ref is refs/heads/branch
        ref = payload.get("ref", "")
        branch = ref.replace("refs/heads/", "") if "refs/heads/" in ref else ref

        return PushEvent(
            repo_full_name=repo_name,
            commit_sha=payload.get("checkout_sha", payload.get("after", "")),
            commit_message=commits[0].get("message", "") if commits else "",
            pusher=payload.get("user_username", "unknown"),
            branch=branch,
            files_modified=list(set(modified)),
            files_added=list(set(added)),
        )

    async def fetch_changed_files(self, event: PushEvent, max_files: int = 5) -> List[SourceFile]:
        """Fetch content of changed source files using the GitLab Projects API."""
        token = get_secret("GITLAB_TOKEN")
        all_files = (event.files_modified + event.files_added)
        
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
        """Fetch raw file content from GitLab Repository Files API."""
        # URL encode project path (e.g. group/repo -> group%2Frepo)
        encoded_repo = urllib.parse.quote_plus(repo)
        encoded_filepath = urllib.parse.quote_plus(filepath)
        
        headers = {}
        if token:
            headers["PRIVATE-TOKEN"] = token

        # GitLab raw files endpoint
        url = f"https://gitlab.com/api/v4/projects/{encoded_repo}/repository/files/{encoded_filepath}/raw?ref={sha}"
        
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
        """Fetch pipeline status for a commit from GitLab Projects Pipelines API."""
        token = get_secret("GITLAB_TOKEN")
        encoded_repo = urllib.parse.quote_plus(repo)
        
        headers = {}
        if token:
            headers["PRIVATE-TOKEN"] = token

        # GitLab Pipelines for specific SHA
        url = f"https://gitlab.com/api/v4/projects/{encoded_repo}/pipelines?sha={sha}"
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                r = await client.get(url, headers=headers)
                if r.status_code != 200 or not r.json():
                    return {"total_count": 0, "check_runs": [], "summary": "no_checks"}
                
                pipelines = r.json()
                latest_pipeline = pipelines[0]
                status = latest_pipeline.get("status", "unknown")
                
                run = {
                    "name": f"GitLab Pipeline #{latest_pipeline.get('id')}",
                    "status": status,
                    "conclusion": "success" if status == "success" else "failure" if status in ("failed", "canceled") else "pending",
                    "url": latest_pipeline.get("web_url"),
                }
                
                return {
                    "total_count": len(pipelines),
                    "check_runs": [run],
                    "summary": "all_passing" if status == "success" else "failing" if status in ("failed", "canceled") else "pending",
                }
            except (httpx.RequestError, IndexError, KeyError):
                return {"total_count": 0, "check_runs": [], "summary": "no_checks"}

    async def create_pull_request(
        self,
        repo: str,
        base_branch: str,
        head_branch: str,
        title: str,
        body: str,
    ) -> Optional[str]:
        """Create a GitLab Merge Request. Returns MR URL or None on failure."""
        token = get_secret("GITLAB_TOKEN")
        if not token:
            return None

        encoded_repo = urllib.parse.quote_plus(repo)
        url = f"https://gitlab.com/api/v4/projects/{encoded_repo}/merge_requests"

        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                r = await client.post(
                    url,
                    headers={"PRIVATE-TOKEN": token},
                    json={
                        "source_branch": head_branch,
                        "target_branch": base_branch,
                        "title": title,
                        "description": body,
                    },
                )
                if r.status_code in (200, 201):
                    return r.json().get("web_url")
                return None
            except httpx.RequestError:
                return None

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
