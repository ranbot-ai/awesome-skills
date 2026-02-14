---
name: azd-deployment
description: Deploy containerized applications to Azure Container Apps using Azure Developer CLI (azd). Use when setting up azd projects, writing azure.yaml configuration, creating Bicep infrastructure for Contain
category: Development & Code Tools
source: antigravity
tags: [python, api, ai, template, image, docker, azure, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azd-deployment
---


# Azure Developer CLI (azd) Container Apps Deployment

Deploy containerized frontend + backend applications to Azure Container Apps with remote builds, managed identity, and idempotent infrastructure.

## Quick Start

```bash
# Initialize and deploy
azd auth login
azd init                    # Creates azure.yaml and .azure/ folder
azd env new <env-name>      # Create environment (dev, staging, prod)
azd up                      # Provision infra + build + deploy
```

## Core File Structure

```
project/
├── azure.yaml              # azd service definitions + hooks
├── infra/
│   ├── main.bicep          # Root infrastructure module
│   ├── main.parameters.json # Parameter injection from env vars
│   └── modules/
│       ├── container-apps-environment.bicep
│       └── container-app.bicep
├── .azure/
│   ├── config.json         # Default environment pointer
│   └── <env-name>/
│       ├── .env            # Environment-specific values (azd-managed)
│       └── config.json     # Environment metadata
└── src/
    ├── frontend/Dockerfile
    └── backend/Dockerfile
```

## azure.yaml Configuration

### Minimal Configuration

```yaml
name: azd-deployment
services:
  backend:
    project: ./src/backend
    language: python
    host: containerapp
    docker:
      path: ./Dockerfile
      remoteBuild: true
```

### Full Configuration with Hooks

```yaml
name: azd-deployment
metadata:
  template: my-project@1.0.0

infra:
  provider: bicep
  path: ./infra

azure:
  location: eastus2

services:
  frontend:
    project: ./src/frontend
    language: ts
    host: containerapp
    docker:
      path: ./Dockerfile
      context: .
      remoteBuild: true

  backend:
    project: ./src/backend
    language: python
    host: containerapp
    docker:
      path: ./Dockerfile
      context: .
      remoteBuild: true

hooks:
  preprovision:
    shell: sh
    run: |
      echo "Before provisioning..."
      
  postprovision:
    shell: sh
    run: |
      echo "After provisioning - set up RBAC, etc."
      
  postdeploy:
    shell: sh
    run: |
      echo "Frontend: ${SERVICE_FRONTEND_URI}"
      echo "Backend: ${SERVICE_BACKEND_URI}"
```

### Key azure.yaml Options

| Option | Description |
|--------|-------------|
| `remoteBuild: true` | Build images in Azure Container Registry (recommended) |
| `context: .` | Docker build context relative to project path |
| `host: containerapp` | Deploy to Azure Container Apps |
| `infra.provider: bicep` | Use Bicep for infrastructure |

## Environment Variables Flow

### Three-Level Configuration

1. **Local `.env`** - For local development only
2. **`.azure/<env>/.env`** - azd-managed, auto-populated from Bicep outputs
3. **`main.parameters.json`** - Maps env vars to Bicep parameters

### Parameter Injection Pattern

```json
// infra/main.parameters.json
{
  "parameters": {
    "environmentName": { "value": "${AZURE_ENV_NAME}" },
    "location": { "value": "${AZURE_LOCATION=eastus2}" },
    "azureOpenAiEndpoint": { "value": "${AZURE_OPENAI_ENDPOINT}" }
  }
}
```

Syntax: `${VAR_NAME}` or `${VAR_NAME=default_value}`

### Setting Environment Variables

```bash
# Set for current environment
azd env set AZURE_OPENAI_ENDPOINT "https://my-openai.openai.azure.com"
azd env set AZURE_SEARCH_ENDPOINT "https://my-search.search.windows.net"

# Set during init
azd env new prod
azd env set AZURE_OPENAI_ENDPOINT "..." 
```

### Bicep Output → Environment Variable

```bicep
// In main.bicep - outputs auto-populate .azure/<env>/.env
output SERVICE_FRONTEND_URI string = frontend.outputs.uri
output SERVICE_BACKEND_URI string = backend.outputs.uri
output BACKEND_PRINCIPAL_ID string = backend.outputs.principalId
```

## Idempotent Deployments

### Why azd up is Idempotent

1. **Bicep is declarative** - Resources reconcile to desired state
2. **Remote builds tag uniquely** - Image tags include deployment timestamp
3. **ACR reuses layers** - Only changed layers upload

### Preserving Manual Changes

Custom domains added via Portal can be lost on redeploy. Preserve with hooks:

```yaml
hooks:
  preprovision:
    shell: sh
    run: |
      # Save custom domains before provision
      if az containerapp show --name "$FRONTEND_NAME" -g "$RG" &>/dev/null; then
        az containerapp show --name "$FRONTEND_NAME" -g "$RG" \
          --query "properties.configuration.ingress.customDomains" \
          -o json > /tmp/domains.json
      fi

  postprovision:
    shell: sh
    run: |
      # Verify/restore custom domains
      if [ -f /tmp/domains.json ]; then
        echo "Saved domains: $(cat /tmp/domains.json)"
      fi
```

### Handling Existing Resources

```bicep
// Reference existing ACR (don't recreate)
resource containerRegistry 'Microsoft.ContainerRegistry/registries@2023-07-01' existing = {
  name: containerRegistryName
}

// Set customDomains to null to preserve Portal-added domains
customDomains: empty(customDomainsParam) ? null : customDomainsParam
```

## Container App Service Discovery

Internal HTTP routin
