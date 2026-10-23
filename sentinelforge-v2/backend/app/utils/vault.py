"""
SentinelForge — Azure Key Vault Secret Resolver
Retrieves credentials from Azure Key Vault in production, falling back to local .env in development.
"""

import os
import subprocess
from pathlib import Path
from typing import Optional

# Lazy imports for Azure SDK to allow out-of-the-box local runs without library installation
_has_azure_sdk = False
try:
    from azure.identity import DefaultAzureCredential
    from azure.keyvault.secrets import SecretClient
    _has_azure_sdk = True
except ImportError:
    pass

_env_checked = False


def _ensure_env():
    global _env_checked
    if not _env_checked:
        _env_checked = True
        try:
            from dotenv import load_dotenv
            # Check likely .env locations
            candidates = [
                Path(__file__).resolve().parent.parent.parent / ".env",
                Path(__file__).resolve().parent.parent / ".env",
                Path.cwd() / "sentinelforge-v2" / "backend" / ".env",
                Path.cwd() / ".env",
            ]
            for p in candidates:
                if p.is_file():
                    load_dotenv(dotenv_path=p)
                    break
        except Exception:
            pass


def get_git_credential_token() -> Optional[str]:
    """
    Attempt to discover a valid GitHub token from the local system Git Credential Manager.
    Works seamlessly on Windows, macOS Keychain, and Linux credential helpers.
    """
    try:
        proc = subprocess.run(
            ["git", "credential", "fill"],
            input="protocol=https\nhost=github.com\n",
            capture_output=True,
            text=True,
            timeout=2.0,
        )
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                if line.startswith("password="):
                    val = line.split("=", 1)[1].strip()
                    if val.startswith(("ghp_", "github_pat_", "gho_")):
                        return val
    except Exception:
        pass
    return None


def get_secret(key_name: str, default: Optional[str] = None) -> Optional[str]:
    """
    Retrieve a secret value.
    1. Ensures .env is loaded.
    2. Checks if AZURE_KEYVAULT_URL is set and Azure SDK is present.
    3. If Key Vault fails or is disabled, falls back to os.getenv().
    4. For GITHUB_TOKEN, falls back to Git Credential Manager if unset.
    """
    _ensure_env()
    vault_url = os.environ.get("AZURE_KEYVAULT_URL")
    
    if vault_url and _has_azure_sdk:
        try:
            # Clean up secret name for Key Vault compatibility (replaces underscores with hyphens)
            kv_name = key_name.replace("_", "-").lower()
            
            # Using DefaultAzureCredential
            credential = DefaultAzureCredential(exclude_shared_token_cache_credential=True)
            client = SecretClient(vault_url=vault_url, credential=credential)
            
            secret = client.get_secret(kv_name)
            if secret and secret.value:
                return secret.value
        except Exception as e:
            print(f"[VAULT] Warning: Failed to retrieve '{key_name}' from Key Vault ({e}). Falling back to local env.")
    
    # Fallback to local environment variable
    val = os.environ.get(key_name, default)
    if not val and key_name == "GITHUB_TOKEN":
        git_token = get_git_credential_token()
        if git_token:
            os.environ["GITHUB_TOKEN"] = git_token
            return git_token

    return val

