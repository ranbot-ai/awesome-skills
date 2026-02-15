---
name: azure-identity-ts
description: Authenticate to Azure services using Azure Identity SDK for JavaScript (@azure/identity). Use when configuring authentication with DefaultAzureCredential, managed identity, service principals, or inte
category: Creative & Media
source: antigravity
tags: [javascript, typescript, api, ai, kubernetes, azure, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-identity-ts
---


# Azure Identity SDK for TypeScript

Authenticate to Azure services with various credential types.

## Installation

```bash
npm install @azure/identity
```

## Environment Variables

### Service Principal (Secret)

```bash
AZURE_TENANT_ID=<tenant-id>
AZURE_CLIENT_ID=<client-id>
AZURE_CLIENT_SECRET=<client-secret>
```

### Service Principal (Certificate)

```bash
AZURE_TENANT_ID=<tenant-id>
AZURE_CLIENT_ID=<client-id>
AZURE_CLIENT_CERTIFICATE_PATH=/path/to/cert.pem
AZURE_CLIENT_CERTIFICATE_PASSWORD=<optional-password>
```

### Workload Identity (Kubernetes)

```bash
AZURE_TENANT_ID=<tenant-id>
AZURE_CLIENT_ID=<client-id>
AZURE_FEDERATED_TOKEN_FILE=/var/run/secrets/tokens/azure-identity
```

## DefaultAzureCredential (Recommended)

```typescript
import { DefaultAzureCredential } from "@azure/identity";

const credential = new DefaultAzureCredential();

// Use with any Azure SDK client
import { BlobServiceClient } from "@azure/storage-blob";
const blobClient = new BlobServiceClient(
  "https://<account>.blob.core.windows.net",
  credential
);
```

**Credential Chain Order:**
1. EnvironmentCredential
2. WorkloadIdentityCredential
3. ManagedIdentityCredential
4. VisualStudioCodeCredential
5. AzureCliCredential
6. AzurePowerShellCredential
7. AzureDeveloperCliCredential

## Managed Identity

### System-Assigned

```typescript
import { ManagedIdentityCredential } from "@azure/identity";

const credential = new ManagedIdentityCredential();
```

### User-Assigned (by Client ID)

```typescript
const credential = new ManagedIdentityCredential({
  clientId: "<user-assigned-client-id>"
});
```

### User-Assigned (by Resource ID)

```typescript
const credential = new ManagedIdentityCredential({
  resourceId: "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.ManagedIdentity/userAssignedIdentities/<name>"
});
```

## Service Principal

### Client Secret

```typescript
import { ClientSecretCredential } from "@azure/identity";

const credential = new ClientSecretCredential(
  "<tenant-id>",
  "<client-id>",
  "<client-secret>"
);
```

### Client Certificate

```typescript
import { ClientCertificateCredential } from "@azure/identity";

const credential = new ClientCertificateCredential(
  "<tenant-id>",
  "<client-id>",
  { certificatePath: "/path/to/cert.pem" }
);

// With password
const credentialWithPwd = new ClientCertificateCredential(
  "<tenant-id>",
  "<client-id>",
  { 
    certificatePath: "/path/to/cert.pem",
    certificatePassword: "<password>"
  }
);
```

## Interactive Authentication

### Browser-Based Login

```typescript
import { InteractiveBrowserCredential } from "@azure/identity";

const credential = new InteractiveBrowserCredential({
  clientId: "<client-id>",
  tenantId: "<tenant-id>",
  loginHint: "user@example.com"
});
```

### Device Code Flow

```typescript
import { DeviceCodeCredential } from "@azure/identity";

const credential = new DeviceCodeCredential({
  clientId: "<client-id>",
  tenantId: "<tenant-id>",
  userPromptCallback: (info) => {
    console.log(info.message);
    // "To sign in, use a web browser to open..."
  }
});
```

## Custom Credential Chain

```typescript
import { 
  ChainedTokenCredential,
  ManagedIdentityCredential,
  AzureCliCredential
} from "@azure/identity";

// Try managed identity first, fall back to CLI
const credential = new ChainedTokenCredential(
  new ManagedIdentityCredential(),
  new AzureCliCredential()
);
```

## Developer Credentials

### Azure CLI

```typescript
import { AzureCliCredential } from "@azure/identity";

const credential = new AzureCliCredential();
// Uses: az login
```

### Azure Developer CLI

```typescript
import { AzureDeveloperCliCredential } from "@azure/identity";

const credential = new AzureDeveloperCliCredential();
// Uses: azd auth login
```

### Azure PowerShell

```typescript
import { AzurePowerShellCredential } from "@azure/identity";

const credential = new AzurePowerShellCredential();
// Uses: Connect-AzAccount
```

## Sovereign Clouds

```typescript
import { ClientSecretCredential, AzureAuthorityHosts } from "@azure/identity";

// Azure Government
const credential = new ClientSecretCredential(
  "<tenant>", "<client>", "<secret>",
  { authorityHost: AzureAuthorityHosts.AzureGovernment }
);

// Azure China
const credentialChina = new ClientSecretCredential(
  "<tenant>", "<client>", "<secret>",
  { authorityHost: AzureAuthorityHosts.AzureChina }
);
```

## Bearer Token Provider

```typescript
import { DefaultAzureCredential, getBearerTokenProvider } from "@azure/identity";

const credential = new DefaultAzureCredential();

// Create a function that returns tokens
const getAccessToken = getBearerTokenProvider(
  credential,
  "https://cognitiveservices.azure.com/.default"
);

// Use with APIs that need bearer tokens
const token = await getAccessToken();
```

## Key Types

```typescript
import type { 
  TokenCredential, 
  AccessToken, 
  GetTokenOptions 
} from "@azure/core-auth";

import {
  DefaultAzureCredential,
 
