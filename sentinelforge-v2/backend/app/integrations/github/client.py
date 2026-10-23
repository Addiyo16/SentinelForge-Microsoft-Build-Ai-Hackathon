"""
SentinelForge — Real-World GitHub Repository Client
Provides secure, read-only ingestion of GitHub repositories via official REST APIs.
Features:
  - SSRF protection: strictly validates domain and URL structure.
  - Repository metadata and access validation.
  - Immutable commit SHA resolution.
  - Recursive file tree enumeration with security/performance filtering.
  - Concurrent content retrieval with size and file count guardrails.
"""

import asyncio
import base64
import os
import re
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse

import httpx
from app.utils.vault import get_secret


class GitHubIntegrationError(Exception):
    """Base exception for GitHub integration operations."""
    pass


class InvalidGitHubUrlError(GitHubIntegrationError):
    """Raised when the submitted repository URL is invalid or malformed."""
    pass


class RepositoryNotFoundError(GitHubIntegrationError):
    """Raised when repository does not exist or is inaccessible."""
    pass


class RepositoryAccessDeniedError(GitHubIntegrationError):
    """Raised when authentication fails or private repository lacks permission."""
    pass


class RateLimitExceededError(GitHubIntegrationError):
    """Raised when GitHub API rate limits are exceeded."""
    pass


@dataclass
class RepositoryMetadata:
    owner: str
    name: str
    full_name: str
    default_branch: str
    commit_sha: str
    description: str = ""
    is_private: bool = False
    stars: int = 0
    primary_language: str = "Unknown"
    html_url: str = ""


@dataclass
class ScanCoverageReport:
    commit_sha: str
    discovered_files_count: int
    eligible_files_count: int
    selected_files_count: int
    successfully_scanned_count: int
    failed_count: int
    skipped_count: int
    is_truncated: bool
    scanner_config: dict[str, Any]
    skipped_summary: dict[str, int]
    is_partial_scan: bool = False
    coverage_percentage: float = 100.0
    discovery_coverage_percentage: float = 100.0
    file_offset: int = 0
    next_offset: Optional[int] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "commit_sha": self.commit_sha,
            "discovered_files_count": self.discovered_files_count,
            "eligible_files_count": self.eligible_files_count,
            "selected_files_count": self.selected_files_count,
            "successfully_scanned_count": self.successfully_scanned_count,
            "failed_count": self.failed_count,
            "skipped_count": self.skipped_count,
            "is_truncated": self.is_truncated,
            "is_partial_scan": self.is_partial_scan,
            "coverage_percentage": self.coverage_percentage,
            "discovery_coverage_percentage": self.discovery_coverage_percentage,
            "file_offset": self.file_offset,
            "next_offset": self.next_offset,
            "resumable": self.next_offset is not None,
            "scanner_config": self.scanner_config,
            "skipped_summary": self.skipped_summary,
            "skip_reasons_summary": self.skipped_summary,
        }


@dataclass
class ScannedFile:
    filename: str
    content: str
    size_bytes: int
    language: str
    sha: str = ""


class GitHubRepoClient:
    """
    Secure, read-only GitHub API client for repository scanning.
    Enforces strict timeouts, file filters, and size restrictions.
    """

    ALLOWED_EXTENSIONS = (
        ".py", ".js", ".jsx", ".ts", ".tsx",
        ".java", ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp",
        ".go", ".yml", ".yaml", ".sh", ".rb", ".rs"
    )

    EXCLUDED_DIRS = {
        "node_modules", "vendor", "venv", ".venv", "env", ".env",
        "__pycache__", ".git", ".github", ".vscode", ".idea",
        "dist", "build", "out", "target", "bin", "obj",
        "coverage", ".next", ".nuxt", "site-packages"
    }

    TEST_DIRS = {
        "test", "tests", "spec", "specs", "__tests__", "testing"
    }

    EXCLUDED_FILES = {
        "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
        "cargo.lock", "poetry.lock", "gemfile.lock", "composer.lock"
    }

    def __init__(self, api_token: Optional[str] = None):
        self.api_token = api_token or get_secret("GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN")
        self.base_url = "https://api.github.com"
        self.user_agent = "SentinelForge-Security-Scanner/2.0"
        self._token_invalid = False
        self.last_coverage_report: Optional[ScanCoverageReport] = None

    @staticmethod
    def score_file_priority(path: str) -> int:
        """
        Calculate prioritization score for a source file.
        Higher score = higher scanning priority.
        """
        p = path.lower()
        parts = p.split("/")
        fn = parts[-1]
        score = 10

        # Core application entrypoints
        if fn in (
            "main.py", "app.py", "server.py", "wsgi.py", "asgi.py", "manage.py",
            "index.js", "index.ts", "app.js", "app.ts", "server.js", "server.ts",
            "main.go", "main.rs", "application.java", "program.cs"
        ):
            score += 100

        # High-risk security keywords in path
        security_keywords = (
            "auth", "login", "session", "token", "jwt", "oauth", "password",
            "crypto", "security", "permission", "user", "admin", "secret",
            "api", "route", "router", "endpoint", "controller", "handler",
            "middleware", "db", "database", "sql", "model", "query"
        )
        if any(k in p for k in security_keywords):
            score += 50

        # Security-critical configurations
        if fn in (
            "dockerfile", "docker-compose.yml", "docker-compose.yaml",
            ".env.example", ".env.sample", "settings.py", "config.py",
            "config.yml", "config.yaml", "requirements.txt", "package.json", "go.mod"
        ):
            score += 40

        # Deprioritize tests and fixtures if included
        if any(part in ("test", "tests", "spec", "specs", "__tests__", "fixtures") for part in parts):
            score -= 30

        return score

    def _get_headers(self, include_token: bool = True) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": self.user_agent,
            "X-GitHub-Api-Version": "2022-11-28",
        }
        token = (self.api_token or "").strip()
        if include_token and token and not self._token_invalid:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def parse_repo_url(self, raw_url: str) -> tuple[str, str, Optional[str]]:
        """
        Parse and validate a GitHub repository URL or owner/repo string.
        Returns: (owner, repo, optional_ref)
        Raises: InvalidGitHubUrlError
        """
        clean = raw_url.strip()
        if not clean:
            raise InvalidGitHubUrlError("GitHub repository URL cannot be empty.")

        # Support "owner/repo" shorthand
        if re.match(r"^[a-zA-Z0-9_\-\.]+/[a-zA-Z0-9_\-\.]+$", clean):
            parts = clean.split("/")
            return parts[0], parts[1].removesuffix(".git"), None

        # Parse standard URL
        parsed = urlparse(clean)
        if parsed.scheme not in ("http", "https"):
            raise InvalidGitHubUrlError("URL must use HTTP or HTTPS protocol.")

        # SSRF Protection: strictly enforce github.com domain
        host = (parsed.hostname or "").lower()
        if host != "github.com" and not host.endswith(".github.com"):
            raise InvalidGitHubUrlError(f"Security Alert: Host '{host}' is not a valid GitHub domain.")

        path_parts = [p for p in parsed.path.strip("/").split("/") if p]
        if len(path_parts) < 2:
            raise InvalidGitHubUrlError("URL must contain repository owner and name (e.g. https://github.com/owner/repo).")

        owner = path_parts[0]
        repo = path_parts[1].removesuffix(".git")

        ref = None
        if len(path_parts) >= 4 and path_parts[2] in ("tree", "commits", "commit"):
            ref = "/".join(path_parts[3:])

        return owner, repo, ref

    async def validate_repository(
        self,
        url_or_slug: str,
        requested_ref: Optional[str] = None,
    ) -> RepositoryMetadata:
        """
        Validate repository existence, accessibility, and resolve immutable commit SHA.
        """
        owner, repo, url_ref = self.parse_repo_url(url_or_slug)
        target_ref = requested_ref or url_ref

        async with httpx.AsyncClient(timeout=10.0) as client:
            repo_url = f"{self.base_url}/repos/{owner}/{repo}"
            repo_res = await client.get(
                repo_url,
                headers=self._get_headers(),
            )
            # An invalid token should not prevent public-repository scanning.
            if repo_res.status_code == 401:
                try:
                    error_message = repo_res.json().get("message", "")
                except ValueError:
                    error_message = ""
                if "bad credentials" in error_message.lower():
                    self._token_invalid = True
                    repo_res = await client.get(
                        repo_url,
                        headers=self._get_headers(include_token=False),
                    )
            if repo_res.status_code == 404:
                raise RepositoryNotFoundError(
                    f"Repository '{owner}/{repo}' not found or not accessible."
                )
            if repo_res.status_code in (401, 403):
                try:
                    message = repo_res.json().get("message", "Access denied")
                except ValueError:
                    message = "Access denied"
                if "rate limit" in message.lower():
                    raise RateLimitExceededError(
                        "GitHub API rate limit exceeded. Configure a valid token."
                    )
                raise RepositoryAccessDeniedError(f"Access denied to '{owner}/{repo}': {message}")
            elif repo_res.status_code != 200:
                raise GitHubIntegrationError(f"GitHub API error (HTTP {repo_res.status_code}): {repo_res.text[:120]}")

            repo_data = repo_res.json()
            default_branch = repo_data.get("default_branch", "main")
            ref_to_resolve = target_ref or default_branch

            # 2. Resolve Exact Commit SHA
            commit_url = f"{self.base_url}/repos/{owner}/{repo}/commits/{ref_to_resolve}"
            commit_res = await client.get(
                commit_url,
                headers=self._get_headers(),
            )
            if commit_res.status_code == 401:
                try:
                    error_message = commit_res.json().get("message", "")
                except ValueError:
                    error_message = ""
                if "bad credentials" in error_message.lower():
                    self._token_invalid = True
                    commit_res = await client.get(
                        commit_url,
                        headers=self._get_headers(include_token=False),
                    )
            if commit_res.status_code != 200:
                if commit_res.status_code in (401, 403):
                    try:
                        err_msg = commit_res.json().get("message", "")
                    except ValueError:
                        err_msg = ""
                    if "rate limit" in err_msg.lower():
                        raise RateLimitExceededError("GitHub API rate limit exceeded. Configure a valid token.")
                raise GitHubIntegrationError(
                    f"Failed to resolve ref '{ref_to_resolve}' on '{owner}/{repo}' (HTTP {commit_res.status_code})."
                )

            commit_sha = commit_res.json().get("sha", "")

            return RepositoryMetadata(
                owner=owner,
                name=repo,
                full_name=repo_data.get("full_name", f"{owner}/{repo}"),
                default_branch=default_branch,
                commit_sha=commit_sha,
                description=repo_data.get("description") or "No description provided.",
                is_private=repo_data.get("private", False),
                stars=repo_data.get("stargazers_count", 0),
                primary_language=repo_data.get("language") or "Polyglot",
                html_url=repo_data.get("html_url", f"https://github.com/{owner}/{repo}"),
            )

    async def fetch_repository_files(
        self,
        owner: str,
        repo: str,
        commit_sha: str,
        max_files: int = 50,
        file_offset: int = 0,
        max_bytes_per_file: int = 250_000,
        include_paths: Optional[list[str]] = None,
        exclude_paths: Optional[list[str]] = None,
        exclude_tests: bool = True,
    ) -> list[ScannedFile]:
        """
        Enumerate and fetch candidate source files for security scanning.
        Uses recursive Git Tree API, prioritizes critical application files,
        supports paginated/resumable scanning, tracks scan coverage, and filters non-source/oversized files.
        """
        async with httpx.AsyncClient(timeout=30.0) as client:
            # 1. Fetch recursive tree
            tree_url = f"{self.base_url}/repos/{owner}/{repo}/git/trees/{commit_sha}?recursive=1"
            tree_res = await client.get(tree_url, headers=self._get_headers())
            if tree_res.status_code == 401:
                try:
                    error_message = tree_res.json().get("message", "")
                except ValueError:
                    error_message = ""
                if "bad credentials" in error_message.lower():
                    self._token_invalid = True
                    tree_res = await client.get(tree_url, headers=self._get_headers(include_token=False))

            if tree_res.status_code != 200:
                if tree_res.status_code in (401, 403):
                    try:
                        err_msg = tree_res.json().get("message", "")
                    except ValueError:
                        err_msg = ""
                    if "rate limit" in err_msg.lower():
                        raise RateLimitExceededError("GitHub API rate limit exceeded. Configure a valid token.")
                raise GitHubIntegrationError(
                    f"Unable to read file tree for {owner}/{repo}@{commit_sha[:8]} (HTTP {tree_res.status_code})"
                )

            tree_data = tree_res.json()
            is_truncated = bool(tree_data.get("truncated", False))
            raw_tree = tree_data.get("tree", [])

            # 2. Filter and prioritize eligible files with skip tracking
            skipped_summary: dict[str, int] = {}
            all_blobs = [n for n in raw_tree if n.get("type") == "blob"]
            eligible_nodes = []

            for node in all_blobs:
                path = node.get("path", "")
                parts = path.lower().split("/")

                # Exclude blacklisted directories
                if any(p in self.EXCLUDED_DIRS for p in parts[:-1]):
                    skipped_summary["excluded_directory"] = skipped_summary.get("excluded_directory", 0) + 1
                    continue

                # Configurable test directory exclusion
                if exclude_tests and any(p in self.TEST_DIRS for p in parts[:-1]):
                    skipped_summary["excluded_test_directory"] = skipped_summary.get("excluded_test_directory", 0) + 1
                    continue

                filename = parts[-1]
                # Exclude lockfiles
                if filename in self.EXCLUDED_FILES:
                    skipped_summary["excluded_lockfile"] = skipped_summary.get("excluded_lockfile", 0) + 1
                    continue

                # Check extension
                if not filename.endswith(self.ALLOWED_EXTENSIONS):
                    skipped_summary["unsupported_extension"] = skipped_summary.get("unsupported_extension", 0) + 1
                    continue

                # Check custom inclusions/exclusions
                if include_paths and not any(p in path for p in include_paths):
                    skipped_summary["excluded_custom_path"] = skipped_summary.get("excluded_custom_path", 0) + 1
                    continue
                if exclude_paths and any(p in path for p in exclude_paths):
                    skipped_summary["excluded_custom_path"] = skipped_summary.get("excluded_custom_path", 0) + 1
                    continue

                # Check file size if available in git tree
                size = node.get("size", 0)
                if size > max_bytes_per_file:
                    skipped_summary["file_size_exceeded"] = skipped_summary.get("file_size_exceeded", 0) + 1
                    continue

                eligible_nodes.append(node)

            # Prioritize files (core application code & security configs first)
            eligible_nodes.sort(
                key=lambda n: self.score_file_priority(n.get("path", "")),
                reverse=True
            )

            # Apply configurable file limit and offset for resumable scanning
            total_eligible = len(eligible_nodes)
            start_idx = max(0, file_offset)
            end_idx = min(total_eligible, start_idx + max_files)
            selected_nodes = eligible_nodes[start_idx:end_idx]
            next_offset = end_idx if end_idx < total_eligible else None

            if total_eligible > len(selected_nodes):
                skipped_summary["quota_limit_exceeded"] = total_eligible - len(selected_nodes)

            # 3. Concurrently fetch file contents
            semaphore = asyncio.Semaphore(15)

            async def fetch_blob(node: dict) -> Optional[ScannedFile]:
                async with semaphore:
                    path = node["path"]
                    url = node["url"]
                    try:
                        res = await client.get(url, headers=self._get_headers())
                        if res.status_code == 401:
                            try:
                                error_message = res.json().get("message", "")
                            except ValueError:
                                error_message = ""
                            if "bad credentials" in error_message.lower():
                                self._token_invalid = True
                        if res.status_code != 200:
                            # Fallback to raw.githubusercontent.com CDN for public repos to bypass API rate limits
                            raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{commit_sha}/{path}"
                            raw_res = await client.get(raw_url)
                            if raw_res.status_code == 200:
                                content_str = raw_res.text
                                lang = self._detect_file_language(path)
                                return ScannedFile(
                                    filename=path,
                                    content=content_str,
                                    size_bytes=len(content_str.encode("utf-8")),
                                    language=lang,
                                    sha=node.get("sha", ""),
                                )
                            return None
                        blob_json = res.json()
                        encoding = blob_json.get("encoding", "utf-8")
                        raw_content = blob_json.get("content", "")

                        if encoding == "base64":
                            content_bytes = base64.b64decode(raw_content)
                            content_str = content_bytes.decode("utf-8", errors="replace")
                        else:
                            content_str = raw_content

                        # Determine language
                        lang = self._detect_file_language(path)
                        return ScannedFile(
                            filename=path,
                            content=content_str,
                            size_bytes=len(content_str.encode("utf-8")),
                            language=lang,
                            sha=node.get("sha", ""),
                        )
                    except Exception:
                        return None

            tasks = [fetch_blob(node) for node in selected_nodes]
            results = await asyncio.gather(*tasks)
            valid_files = [f for f in results if f is not None]

            failed_count = len(selected_nodes) - len(valid_files)
            if failed_count > 0:
                skipped_summary["download_error"] = failed_count

            total_skipped = len(all_blobs) - len(valid_files)
            is_partial_scan = bool((len(valid_files) < len(eligible_nodes)) or is_truncated)
            coverage_pct = round((len(valid_files) / max(1, len(eligible_nodes))) * 100.0, 2) if eligible_nodes else 100.0
            discovery_coverage_pct = round((len(valid_files) / max(1, len(all_blobs))) * 100.0, 2) if all_blobs else 100.0

            # Store transparent scan coverage report
            self.last_coverage_report = ScanCoverageReport(
                commit_sha=commit_sha,
                discovered_files_count=len(all_blobs),
                eligible_files_count=len(eligible_nodes),
                selected_files_count=len(selected_nodes),
                successfully_scanned_count=len(valid_files),
                failed_count=failed_count,
                skipped_count=max(0, total_skipped),
                is_truncated=is_truncated,
                scanner_config={
                    "max_files": max_files,
                    "file_offset": file_offset,
                    "max_bytes_per_file": max_bytes_per_file,
                    "exclude_tests": exclude_tests,
                    "include_paths": include_paths or [],
                    "exclude_paths": exclude_paths or [],
                },
                skipped_summary=skipped_summary,
                is_partial_scan=is_partial_scan,
                coverage_percentage=coverage_pct,
                discovery_coverage_percentage=discovery_coverage_pct,
                file_offset=file_offset,
                next_offset=next_offset,
            )

            return valid_files

    @staticmethod
    def _detect_file_language(filepath: str) -> str:
        fn = filepath.lower()
        if fn.endswith((".py", ".pyw")):
            return "python"
        if fn.endswith((".js", ".jsx", ".mjs")):
            return "javascript"
        if fn.endswith((".ts", ".tsx")):
            return "typescript"
        if fn.endswith((".java",)):
            return "java"
        if fn.endswith((".c", ".cpp", ".cc", ".cxx", ".h", ".hpp")):
            return "c_cpp"
        if fn.endswith((".go",)):
            return "go"
        if fn.endswith((".yml", ".yaml")):
            return "yaml"
        return "generic"
