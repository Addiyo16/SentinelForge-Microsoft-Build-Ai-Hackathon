"""
SentinelForge — CI/CD Service Factory
Resolves the correct platform service implementation.
"""

from app.services.base_ci_service import BaseCIService
from app.services.github_service import GitHubService
from app.services.gitlab_service import GitLabService
from app.services.azure_devops_service import AzureDevOpsService


def get_ci_service(platform: str) -> BaseCIService:
    """
    Factory function to retrieve the appropriate CI/CD platform service.
    Supported platforms: 'github', 'gitlab', 'azure-devops'
    """
    p = platform.lower().strip()
    if p == "github":
        return GitHubService()
    elif p == "gitlab":
        return GitLabService()
    elif p in ("azure-devops", "azure_devops", "ado"):
        return AzureDevOpsService()
    else:
        raise ValueError(f"Unsupported CI/CD platform: {platform}")
