"""
SentinelForge — Azure Key Vault Secret Resolver
Retrieves credentials from Azure Key Vault in production, falling back to local .env in development.
"""

import os
from typing import Optional

# Lazy imports for Azure SDK to allow out-of-the-box local runs without library installation
_has_azure_sdk = False
try:
    from azure.identity import DefaultAzureCredential
    from azure.keyvault.secrets import SecretClient
    _has_azure_sdk = True
except ImportError:
    pass


def get_secret(key_name: str, default: Optional[str] = None) -> Optional[str]:
    """
    Retrieve a secret value.
    1. Checks if AZURE_KEYVAULT_URL is set and Azure SDK is present.
    2. If yes, attempts to fetch from Azure Key Vault.
    3. If Key Vault fails or is disabled, falls back to os.getenv().
    """
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
    return os.environ.get(key_name, default)
