---
name: azure-identity-dotnet
description: Azure Identity SDK for .NET. Authentication library for Azure SDK clients using Microsoft Entra ID. Use for DefaultAzureCredential, managed identity, service principals, and developer credentials. 
category: Creative & Media
source: antigravity
tags: [api, ai, workflow, security, kubernetes, azure, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-identity-dotnet
---


# Azure.Identity (.NET)

Authentication library for Azure SDK clients using Microsoft Entra ID (formerly Azure AD).

## Installation

```bash
dotnet add package Azure.Identity

# For ASP.NET Core
dotnet add package Microsoft.Extensions.Azure

# For brokered authentication (Windows)
dotnet add package Azure.Identity.Broker
```

**Version context**: Examples reference the 1.17/1.18 generation; verify the installed package and target framework rather than treating these as current releases.

## Environment Variables

### Service Principal with Secret
```bash
AZURE_CLIENT_ID=<application-client-id>
AZURE_TENANT_ID=<directory-tenant-id>
AZURE_CLIENT_SECRET=<client-secret-value>
```

### Service Principal with Certificate
```bash
AZURE_CLIENT_ID=<application-client-id>
AZURE_TENANT_ID=<directory-tenant-id>
AZURE_CLIENT_CERTIFICATE_PATH=<path-to-pfx-or-pem>
AZURE_CLIENT_CERTIFICATE_PASSWORD=<certificate-password>  # Optional
```

### Managed Identity
```bash
AZURE_CLIENT_ID=<user-assigned-managed-identity-client-id>  # Only for user-assigned
```

Credential chains and broker inclusion change with SDK version and optional packages. Check the effective identity/tenant and constrain production credentials explicitly; authentication alone grants no resource-operation authority. Keep tokens, certificate passwords and diagnostic output private. The certificate-loading example needs a runtime supporting X509CertificateLoader and a private-key-bearing PKCS#12 file. See [credential chains](https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication/credential-chains) and [PKCS#12 loading](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509certificateloader.loadpkcs12fromfile).

## DefaultAzureCredential

The recommended credential for most scenarios. Tries multiple authentication methods in order:

| Order | Credential | Enabled by Default |
|-------|------------|-------------------|
| 1 | EnvironmentCredential | Yes |
| 2 | WorkloadIdentityCredential | Yes |
| 3 | ManagedIdentityCredential | Yes |
| 4 | VisualStudioCredential | Yes |
| 5 | VisualStudioCodeCredential | Yes |
| 6 | AzureCliCredential | Yes |
| 7 | AzurePowerShellCredential | Yes |
| 8 | AzureDeveloperCliCredential | Yes |
| 9 | InteractiveBrowserCredential | **No** |

### Basic Usage

```csharp
using Azure.Identity;
using Azure.Storage.Blobs;

var credential = new DefaultAzureCredential();
var blobClient = new BlobServiceClient(
    new Uri("https://myaccount.blob.core.windows.net"),
    credential);
```

### ASP.NET Core with Dependency Injection

```csharp
using Azure.Identity;
using Microsoft.Extensions.Azure;

builder.Services.AddAzureClients(clientBuilder =>
{
    clientBuilder.AddBlobServiceClient(
        new Uri("https://myaccount.blob.core.windows.net"));
    clientBuilder.AddSecretClient(
        new Uri("https://myvault.vault.azure.net"));
    
    // Uses DefaultAzureCredential by default
    clientBuilder.UseCredential(new DefaultAzureCredential());
});
```

### Customizing DefaultAzureCredential

```csharp
var credential = new DefaultAzureCredential(
    new DefaultAzureCredentialOptions
    {
        ExcludeEnvironmentCredential = true,
        ExcludeManagedIdentityCredential = false,
        ExcludeVisualStudioCredential = false,
        ExcludeAzureCliCredential = false,
        ExcludeInteractiveBrowserCredential = false, // Enable interactive
        TenantId = "<tenant-id>",
        ManagedIdentityClientId = "<user-assigned-mi-client-id>"
    });
```

## Credential Types

### ManagedIdentityCredential (Production)

```csharp
// System-assigned managed identity
var credential = new ManagedIdentityCredential(ManagedIdentityId.SystemAssigned);

// User-assigned by client ID
var credential = new ManagedIdentityCredential(
    ManagedIdentityId.FromUserAssignedClientId("<client-id>"));

// User-assigned by resource ID
var credential = new ManagedIdentityCredential(
    ManagedIdentityId.FromUserAssignedResourceId("<resource-id>"));
```

### ClientSecretCredential

```csharp
var credential = new ClientSecretCredential(
    tenantId: "<tenant-id>",
    clientId: "<client-id>",
    clientSecret: "<client-secret>");

var client = new SecretClient(
    new Uri("https://myvault.vault.azure.net"),
    credential);
```

### ClientCertificateCredential

```csharp
var certificate = X509CertificateLoader.LoadPkcs12FromFile(
    "MyCertificate.pfx", Environment.GetEnvironmentVariable("CERTIFICATE_PASSWORD"));
var credential = new ClientCertificateCredential(
    tenantId: "<tenant-id>",
    clientId: "<client-id>",
    certificate);
```

### ChainedTokenCredential (Custom Chain)

```csharp
var credential = new ChainedTokenCredential(
    new ManagedIdentityCredential(),
    new AzureCliCredential());

var client = new SecretClient(
    new Uri("https://myvault.vault.azure.net"),
    credential);
```

### Developer Credentials

```csharp
// Azure CLI
var credential = new AzureCliCredential();

// Azure P
