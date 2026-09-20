---
name: azure-keyvault
description: Manage secrets and certificates in Azure Key Vault. Configure access policies, integrate with Azure services, and implement secure secret management. Use when managing secrets in Azure environments. 
category: AI & Agents
source: antigravity
tags: [python, api, ai, agent, template, image, security, kubernetes, azure, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-keyvault
---


# Azure Key Vault

Securely store and manage secrets, keys, and certificates in Azure.

## Prerequisites

- Azure subscription with appropriate permissions
- Azure CLI installed (`az` command)
- Contributor or Key Vault Administrator role for vault management
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

# Create Key Vault with access policies (legacy)
az keyvault create \
  --name myapp-vault-dev \
  --resource-group rg-secrets \
  --location eastus \
  --enable-soft-delete true \
  --retention-days 30

# Enable private endpoint (no public access)
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

```bash
# Set a secret
az keyvault secret set \
  --vault-name myapp-vault-prod \
  --name db-password \
  --value "S3cur3P@ssw0rd!" \
  --content-type "text/plain" \
  --tags Environment=production Team=platform

# Set a multi-line secret (JSON credentials)
az keyvault secret set \
  --vault-name myapp-vault-prod \
  --name db-credentials \
  --value '{"username":"dbadmin","password":"S3cur3P@ss!","host":"db.postgres.database.azure.com","port":5432}'

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
  --value "base64-encoded-plaintext"

# Rotate a key
az keyvault key rotate \
  --vault-name myapp-vault-prod \
  --name data-encryption-key

# Set key rotation policy
az keyvault key rotation-policy update \
  --vault-name myapp-vault-prod \
  --name data-encryption-key \
  --value '{
    "lifetimeActions": [
      {
        "trigger": {"timeBeforeExpiry": "P30D"},
        "action": {"type": "Notify"}
      },
      {
        "trigger": {"timeAfterCreate": "P90D"},
        "action": {"type": "Rotate"}
      }
    ],
    "attributes": {"expiryTime": "P180D"}
  }'
```

## Certificate Management

```bash
# Create a self-signed certificate
az keyvault certificate create \
  --vault-name myapp-vault-prod \
  --name app-tls-cert \
  --policy '{
    "issuerParameters": {"name": "Self"},
    "keyProperties": {"exportable": true, "keyS
