"""
SentinelForge — GitHub Repository Integration Package
Provides secure, read-only repository validation, commit resolution, and file tree fetching.
"""

from app.integrations.github.client import GitHubRepoClient, RepositoryMetadata, ScannedFile

__all__ = ["GitHubRepoClient", "RepositoryMetadata", "ScannedFile"]
