---
name: azure-keyvault
description: Manage secrets and certificates in Azure Key Vault. Configure access policies, integrate with Azure services, and implement secure secret management. Use when managing secrets in Azure environments. 
category: AI & Agents
source: antigravity
tags: [python, node, api, ai, agent, template, image, security, kubernetes, azure]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-keyvault
---


# Azure Key Vault

Securely store and manage secrets, keys, and certificates in Azure.

## Prerequisites

- Azure subscription with appropriate permissions
- Azure CLI installed (`az` command)
- Control-plane vault-management permission and separate least-privilege data-plane roles; assigning roles additionally needs authorized role-assignment permission
- Managed identity configured for application access
- Understanding of Azure RBAC vs. Key Vault access policies

## Vault Creation and Configuration

```bash
# Create a resource group
az group create --name rg-secrets --location eastus

# Create Key Vault with RBAC authorization (recommended)
az keyvault create \
  --name myapp-vault-prod \
  --resource-group rg-secrets \
  --location eastus \
  --enable-rbac-authorization true \
  --enable-soft-delete true \
  --retention-days 90 \
  --enable-purge-protection true \
  --sku premium  # Use premium for HSM-backed keys

# Legacy policy mode must be explicitly selected; modern new vaults default to RBAC.
# Create Key Vault with access policies (legacy)
az keyvault create \
  --name myapp-vault-dev \
  --enable-rbac-authorization false \
  --resource-group rg-secrets \
  --location eastus \
  --enable-soft-delete true \
  --retention-days 30

# Disable public access only AFTER creating/approving a private endpoint and DNS path;
# this update does not create an endpoint and otherwise locks out clients.
az keyvault update \
  --name myapp-vault-prod \
  --resource-group rg-secrets \
  --public-network-access Disabled

# Enable diagnostics logging
az monitor diagnostic-settings create \
  --name kv-diagnostics \
  --resource "/subscriptions/{sub}/resourceGroups/rg-secrets/providers/Microsoft.KeyVault/vaults/myapp-vault-prod" \
  --workspace "/subscriptions/{sub}/resourceGroups/rg-monitor/providers/Microsoft.OperationalInsights/workspaces/security-logs" \
  --logs '[{"category":"AuditEvent","enabled":true,"retentionPolicy":{"enabled":true,"days":365}}]'
```

## Secret Management

Create referenced secret files via protected local input with mode0600, never commit them or expose values in argv/logs. Secret set responses include values unless output is suppressed. Confirm subscription/vault/object IDs and recovery before mutation/purge; purge protection cannot be disabled after enabling. Read-only `show` also exposes secret values, so use only for a concrete authorized need. Expiry metadata does not rotate downstream application credentials. Public-access disablement is not private-endpoint provisioning.

```bash
# Set a secret
az keyvault secret set \
  --vault-name myapp-vault-prod \
  --name db-password \
  --file db-password.txt --output none \
  --content-type "text/plain" \
  --tags Environment=production Team=platform

# Set a multi-line secret (JSON credentials)
az keyvault secret set \
  --vault-name myapp-vault-prod \
  --name db-credentials \
  --file db-credentials.json --output none

# Get secret value
az keyvault secret show \
  --vault-name myapp-vault-prod \
  --name db-password \
  --query value -o tsv

# Get specific version
az keyvault secret show \
  --vault-name myapp-vault-prod \
  --name db-password \
  --version abc123def456

# List all secrets
az keyvault secret list --vault-name myapp-vault-prod -o table

# List secret versions
az keyvault secret list-versions \
  --vault-name myapp-vault-prod \
  --name db-password -o table

# Set expiration date
az keyvault secret set-attributes \
  --vault-name myapp-vault-prod \
  --name api-key \
  --expires "2026-01-01T00:00:00Z"

# Disable a secret (without deleting)
az keyvault secret set-attributes \
  --vault-name myapp-vault-prod \
  --name old-api-key \
  --enabled false

# Delete a secret (soft-delete)
az keyvault secret delete \
  --vault-name myapp-vault-prod \
  --name old-api-key

# Recover a deleted secret
az keyvault secret recover \
  --vault-name myapp-vault-prod \
  --name old-api-key

# Purge a deleted secret (permanent, requires purge protection to be off)
az keyvault secret purge \
  --vault-name myapp-vault-prod \
  --name old-api-key

# Backup and restore
az keyvault secret backup \
  --vault-name myapp-vault-prod \
  --name db-password \
  --file db-password.backup

az keyvault secret restore \
  --vault-name myapp-vault-prod \
  --file db-password.backup
```

## Key Management

```bash
# Create an RSA key for encryption
az keyvault key create \
  --vault-name myapp-vault-prod \
  --name data-encryption-key \
  --kty RSA \
  --size 4096 \
  --ops encrypt decrypt wrapKey unwrapKey

# Create an EC key for signing
az keyvault key create \
  --vault-name myapp-vault-prod \
  --name signing-key \
  --kty EC \
  --curve P-256 \
  --ops sign verify

# Import an existing key
az keyvault key import \
  --vault-name myapp-vault-prod \
  --name imported-key \
  --pem-file key.pem

# Encrypt data
az keyvault key encrypt \
  --vault-name myapp-vault-prod \
  --name data-encryption-key \
  --algorithm RSA-OAEP-256 \
  --value "base64-encoded-
