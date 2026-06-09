"""
SentinelForge — Base CI/CD Platform Service Interface
Defines the standard interface for Git provider integrations.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, List


@dataclass
class SourceFile:
    filename: str
    content: str
    sha: str
    language: str


@dataclass
class PushEvent:
    repo_full_name: str
    commit_sha: str
    commit_message: str
    pusher: str
    branch: str
    files_modified: List[str]
    files_added: List[str]


class BaseCIService(ABC):
    """
    Abstract Base Class for CI/CD Git provider services.
    Handles webhook parsing, code ingestion, status checks, and pull request integration.
    """

    @abstractmethod
    def verify_webhook(self, payload_bytes: bytes, signature: str) -> bool:
        """Verify the webhook payload signature from the provider."""
        pass

    @abstractmethod
    def parse_push_event(self, payload: dict) -> PushEvent:
        """Extract standardized push event details from payload."""
        pass

    @abstractmethod
    async def fetch_changed_files(self, event: PushEvent, max_files: int = 5) -> List[SourceFile]:
        """Fetch file names and contents changed in the push event."""
        pass

    @abstractmethod
    async def get_ci_status(self, repo: str, sha: str) -> dict:
        """Fetch the current CI build/test pipeline status for a commit."""
        pass

    @abstractmethod
    async def create_pull_request(
        self,
        repo: str,
        base_branch: str,
        head_branch: str,
        title: str,
        body: str,
    ) -> Optional[str]:
        """Create a new Pull Request/Merge Request. Returns the PR URL or None."""
        pass
