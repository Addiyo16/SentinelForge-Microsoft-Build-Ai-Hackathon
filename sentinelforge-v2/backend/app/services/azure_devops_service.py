"""
SentinelForge — Azure DevOps Integration Service
Handles Azure DevOps push service hooks, item fetching, build status, and Pull Request creation.
Inherits from BaseCIService.
"""

import base64
from typing import Optional, List

import httpx

from app.services.base_ci_service import BaseCIService, PushEvent, SourceFile
from app.utils.vault import get_secret


class AzureDevOpsService(BaseCIService):
    """Azure DevOps provider service implementation."""

    def verify_webhook(self, payload_bytes: bytes, signature: str) -> bool:
        """Verify Azure DevOps webhook basic auth token if configured."""
        secret = get_secret("AZURE_DEVOPS_WEBHOOK_SECRET", "")
        if not secret:
            return True  # Skip verification in dev mode
        return secret == signature

    def parse_push_event(self, payload: dict) -> PushEvent:
        """Extract key fields from an Azure DevOps git.push service hook payload."""
        resource = payload.get("resource", {})
        repo = resource.get("repository", {})
        
        # Format repo name: organization/project/repo_name
        org = payload.get("organization", "default-org")
        project = repo.get("project", {}).get("name", "default-project")
        repo_name = f"{org}/{project}/{repo.get('name', '')}"

        commits = resource.get("commits", [])
        commit_sha = ""
        commit_msg = ""
        if commits:
            commit_sha = commits[0].get("commitId", "")
            commit_msg = commits[0].get("comment", "")

        # ADO pushes report changes in a separate changes list or we can inspect modified
        modified = []
        added = []
        for c in commits:
            # Service hooks sometimes include change details under resource
            for change in resource.get("refUpdates", []):
                pass # placeholder

        # In ADO payload: resource.refUpdates[0].name -> refs/heads/branch
        ref_updates = resource.get("refUpdates", [{}])
        ref = ref_updates[0].get("name", "")
        branch = ref.replace("refs/heads/", "") if "refs/heads/" in ref else ref

        pushed_by = resource.get("pushedBy", {}).get("displayName", "unknown")

        return PushEvent(
            repo_full_name=repo_name,
            commit_sha=commit_sha or payload.get("id", ""),
            commit_message=commit_msg,
            pusher=pushed_by,
            branch=branch,
            files_modified=list(set(modified)),
            files_added=list(set(added)),
        )

    async def fetch_changed_files(self, event: PushEvent, max_files: int = 5) -> List[SourceFile]:
        """Fetch changed source files from Azure DevOps Git Repository items API."""
        # For simulation or when changes list is empty, default to files from push commit
        # In a real environment, ADO REST APIs are queried to fetch changed items
        all_files = event.files_modified + event.files_added
        
        # Fallback to defaults if event didn't pack changes in webhook payload
        if not all_files:
            all_files = ["app.py", "index.js", "main.cpp", "workflow.yml"]
            
        source_exts = (".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".c", ".cpp", ".h", ".go", ".yml", ".yaml")
        target_files = [f for f in all_files if f.lower().endswith(source_exts)][:max_files]

        results = []
        for filepath in target_files:
            file = await self._fetch_file_content(event.repo_full_name, event.commit_sha, filepath)
            if file:
                results.append(file)
        return results

    async def _fetch_file_content(
        self, repo: str, sha: str, filepath: str
    ) -> Optional[SourceFile]:
        """Fetch file raw content from ADO Git Item API."""
        token = get_secret("AZURE_DEVOPS_TOKEN")
        
        # Split repo path: org/project/repo_name
        parts = repo.split("/")
        org = parts[0] if len(parts) > 0 else "default-org"
        project = parts[1] if len(parts) > 1 else "default-project"
        repo_name = parts[2] if len(parts) > 2 else (parts[-1] if parts else "repo")

        # ADO basic auth header: base64(PAT)
        headers = {}
        if token:
            auth_str = f":{token}"
            encoded = base64.b64encode(auth_str.encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"

        # ADO API for item
        url = (
            f"https://dev.azure.com/{org}/{project}/_apis/git/repositories/{repo_name}/items"
            f"?path={filepath}&versionDescriptor.version={sha}&$format=text&api-version=7.1-preview.1"
        )
        
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
        """Fetch Build pipeline runs for a commit using ADO Build API."""
        token = get_secret("AZURE_DEVOPS_TOKEN")
        
        parts = repo.split("/")
        org = parts[0] if len(parts) > 0 else "default-org"
        project = parts[1] if len(parts) > 1 else "default-project"
        repo_name = parts[2] if len(parts) > 2 else (parts[-1] if parts else "repo")

        headers = {}
        if token:
            auth_str = f":{token}"
            encoded = base64.b64encode(auth_str.encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"

        # ADO Builds endpoint
        url = f"https://dev.azure.com/{org}/{project}/_apis/build/builds?commitId={sha}&api-version=7.1-preview.2"

        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                r = await client.get(url, headers=headers)
                if r.status_code != 200:
                    return {"total_count": 0, "check_runs": [], "summary": "no_checks"}

                data = r.json()
                builds = data.get("value", [])
                if not builds:
                    return {"total_count": 0, "check_runs": [], "summary": "no_checks"}

                latest_build = builds[0]
                result = latest_build.get("result", "")
                status = latest_build.get("status", "")
                
                run = {
                    "name": f"Azure Pipeline Build #{latest_build.get('id')}",
                    "status": status,
                    "conclusion": "success" if result == "succeeded" else "failure" if result == "failed" else "pending",
                    "url": latest_build.get("_links", {}).get("web", {}).get("href"),
                }

                return {
                    "total_count": len(builds),
                    "check_runs": [run],
                    "summary": "all_passing" if result == "succeeded" else "failing" if result == "failed" else "pending",
                }
            except httpx.RequestError:
                return {"total_count": 0, "check_runs": [], "summary": "no_checks"}

    async def create_pull_request(
        self,
        repo: str,
        base_branch: str,
        head_branch: str,
        title: str,
        body: str,
    ) -> Optional[str]:
        """Create an Azure DevOps Pull Request."""
        token = get_secret("AZURE_DEVOPS_TOKEN")
        if not token:
            return None

        parts = repo.split("/")
        org = parts[0] if len(parts) > 0 else "default-org"
        project = parts[1] if len(parts) > 1 else "default-project"
        repo_name = parts[2] if len(parts) > 2 else (parts[-1] if parts else "repo")

        headers = {}
        auth_str = f":{token}"
        encoded = base64.b64encode(auth_str.encode()).decode()
        headers["Authorization"] = f"Basic {encoded}"

        # ADO PR endpoint
        url = f"https://dev.azure.com/{org}/{project}/_apis/git/repositories/{repo_name}/pullrequests?api-version=7.1-preview.1"

        # ADO wants refs/heads/ prefix
        source_ref = f"refs/heads/{head_branch}" if not head_branch.startswith("refs/") else head_branch
        target_ref = f"refs/heads/{base_branch}" if not base_branch.startswith("refs/") else base_branch

        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                r = await client.post(
                    url,
                    headers=headers,
                    json={
                        "sourceRefName": source_ref,
                        "targetRefName": target_ref,
                        "title": title,
                        "description": body,
                    },
                )
                if r.status_code in (200, 201):
                    # Format standard PR web link
                    pr_id = r.json().get("pullRequestId")
                    return f"https://dev.azure.com/{org}/{project}/_git/{repo_name}/pullrequest/{pr_id}"
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
