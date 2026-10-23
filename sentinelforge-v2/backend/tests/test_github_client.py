"""
Unit tests for SentinelForge GitHub Integration Client.
Tests URL parsing, SSRF domain validation, ref extraction, and file filtering rules.
"""

import pytest
from unittest.mock import AsyncMock, patch
import httpx
from app.integrations.github.client import (
    GitHubRepoClient,
    InvalidGitHubUrlError,
    RepositoryNotFoundError,
    RepositoryAccessDeniedError,
    RateLimitExceededError,
)


class TestGitHubClient:
    @pytest.fixture
    def client(self):
        return GitHubRepoClient()

    def test_parse_standard_https_url(self, client):
        owner, repo, ref = client.parse_repo_url("https://github.com/pallets/flask")
        assert owner == "pallets"
        assert repo == "flask"
        assert ref is None

    def test_parse_shorthand_slug(self, client):
        owner, repo, ref = client.parse_repo_url("fastapi/fastapi")
        assert owner == "fastapi"
        assert repo == "fastapi"
        assert ref is None

    def test_parse_git_suffix(self, client):
        owner, repo, ref = client.parse_repo_url("https://github.com/psf/requests.git")
        assert owner == "psf"
        assert repo == "requests"

    def test_parse_tree_branch_url(self, client):
        owner, repo, ref = client.parse_repo_url("https://github.com/microsoft/vscode/tree/main")
        assert owner == "microsoft"
        assert repo == "vscode"
        assert ref == "main"

    def test_ssrf_rejects_non_github_host(self, client):
        with pytest.raises(InvalidGitHubUrlError) as exc_info:
            client.parse_repo_url("https://malicious-site.com/owner/repo")
        assert "not a valid GitHub domain" in str(exc_info.value)

    def test_ssrf_rejects_localhost_and_internal_ips(self, client):
        with pytest.raises(InvalidGitHubUrlError):
            client.parse_repo_url("http://localhost/owner/repo")
        with pytest.raises(InvalidGitHubUrlError):
            client.parse_repo_url("http://127.0.0.1/owner/repo")

    def test_empty_url_raises_error(self, client):
        with pytest.raises(InvalidGitHubUrlError):
            client.parse_repo_url("")

    def test_file_language_detection(self, client):
        assert client._detect_file_language("app/main.py") == "python"
        assert client._detect_file_language("src/index.tsx") == "typescript"
        assert client._detect_file_language("server.js") == "javascript"
        assert client._detect_file_language("Main.java") == "java"
        assert client._detect_file_language("native/buffer.cpp") == "c_cpp"
        assert client._detect_file_language("cmd/app.go") == "go"
        assert client._detect_file_language("ci.yml") == "yaml"

    def test_headers_with_and_without_token(self):
        client_with_token = GitHubRepoClient(api_token="ghp_test123456789")
        headers = client_with_token._get_headers(include_token=True)
        assert headers["Accept"] == "application/vnd.github+json"
        assert headers["X-GitHub-Api-Version"] == "2022-11-28"
        assert headers["Authorization"] == "Bearer ghp_test123456789"

        headers_no_token = client_with_token._get_headers(include_token=False)
        assert "Authorization" not in headers_no_token

        # Test invalid token flag
        client_with_token._token_invalid = True
        headers_invalid = client_with_token._get_headers(include_token=True)
        assert "Authorization" not in headers_invalid

    @pytest.mark.asyncio
    async def test_validate_repository_retries_on_bad_credentials(self):
        client = GitHubRepoClient(api_token="bad_token_value")

        mock_401 = httpx.Response(401, json={"message": "Bad credentials"}, request=httpx.Request("GET", "https://api.github.com"))
        mock_repo_200 = httpx.Response(200, json={
            "name": "flask",
            "full_name": "pallets/flask",
            "default_branch": "main",
            "description": "The Python micro framework",
            "private": False,
            "stargazers_count": 65000,
            "language": "Python",
            "html_url": "https://github.com/pallets/flask",
        }, request=httpx.Request("GET", "https://api.github.com"))
        mock_commit_200 = httpx.Response(200, json={"sha": "abc123commitsha"}, request=httpx.Request("GET", "https://api.github.com"))

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = [mock_401, mock_repo_200, mock_commit_200]
            metadata = await client.validate_repository("pallets/flask")

            assert metadata.owner == "pallets"
            assert metadata.name == "flask"
            assert metadata.commit_sha == "abc123commitsha"
            assert client._token_invalid is True
            assert mock_get.call_count == 3

    @pytest.mark.asyncio
    async def test_validate_repository_real_access_denied(self):
        client = GitHubRepoClient(api_token="some_token")
        mock_403 = httpx.Response(403, json={"message": "Resource not accessible by integration"}, request=httpx.Request("GET", "https://api.github.com"))

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_403
            with pytest.raises(RepositoryAccessDeniedError) as exc_info:
                await client.validate_repository("private/repo")
            assert "Resource not accessible" in str(exc_info.value)
            assert client._token_invalid is False

    def test_file_prioritization(self, client):
        score_main = client.score_file_priority("src/main.py")
        score_auth = client.score_file_priority("controllers/auth_controller.ts")
        score_docker = client.score_file_priority("Dockerfile")
        score_util = client.score_file_priority("helpers/string_utils.py")
        score_test = client.score_file_priority("tests/test_auth.py")

        assert score_main > score_util
        assert score_auth > score_util
        assert score_docker > score_util
        assert score_test < score_auth

    @pytest.mark.asyncio
    async def test_fetch_repository_files_coverage_tracking(self, client):
        tree_response = {
            "truncated": False,
            "tree": [
                {"type": "blob", "path": "main.py", "url": "https://api.github.com/blob/1", "size": 500, "sha": "s1"},
                {"type": "blob", "path": "package-lock.json", "url": "https://api.github.com/blob/2", "size": 1000, "sha": "s2"},
                {"type": "blob", "path": "tests/test_main.py", "url": "https://api.github.com/blob/3", "size": 400, "sha": "s3"},
                {"type": "blob", "path": "image.png", "url": "https://api.github.com/blob/4", "size": 2000, "sha": "s4"},
                {"type": "tree", "path": "src", "url": "https://api.github.com/tree/1"},
            ]
        }
        blob_response = {"encoding": "utf-8", "content": "print('hello')", "sha": "s1"}

        mock_tree = httpx.Response(200, json=tree_response, request=httpx.Request("GET", "https://api.github.com"))
        mock_blob = httpx.Response(200, json=blob_response, request=httpx.Request("GET", "https://api.github.com"))

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = [mock_tree, mock_blob]
            scanned = await client.fetch_repository_files(
                owner="owner",
                repo="repo",
                commit_sha="abcd1234ef",
                max_files=10,
                exclude_tests=True,
            )

            assert len(scanned) == 1
            assert scanned[0].filename == "main.py"

            report = client.last_coverage_report
            assert report is not None
            assert report.discovered_files_count == 4
            assert report.eligible_files_count == 1
            assert report.successfully_scanned_count == 1
            assert report.skipped_summary.get("excluded_lockfile") == 1
            assert report.skipped_summary.get("excluded_test_directory") == 1
            assert report.skipped_summary.get("unsupported_extension") == 1


