---
name: azure-security-keyvault-keys-dotnet
description: Azure Key Vault Keys SDK for .NET. Client library for managing cryptographic keys in Azure Key Vault and Managed HSM. Use for key creation, rotation, encryption, decryption, signing, and verification.
category: Security & Systems
source: antigravity
tags: [api, ai, workflow, security, azure, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-security-keyvault-keys-dotnet
---


# Azure.Security.KeyVault.Keys (.NET)

Client library for managing cryptographic keys in Azure Key Vault and Managed HSM.

Confirm vault/Managed HSM capability, tenant/RBAC, key name/version and lifecycle scope before changes. Symmetric Oct keys and hardware protection require a compatible service/tier; do not assume all examples work on an ordinary vault. Key operations must match the actual algorithm; narrow RSA Encrypt/Decrypt options cannot also sign/wrap without the corresponding allowed operations. Preserve version IDs with ciphertext/signatures and retain old keys until data no longer needs them. Backup files are sensitive and have service restore restrictions. RSA is for small payloads; use authenticated envelope encryption for bulk data.

## Installation

```bash
dotnet add package Azure.Security.KeyVault.Keys
dotnet add package Azure.Identity
```

**Example SDK version**: 4.7.0; verify the supported package version/API for the target project.

## Environment Variables

```bash
KEY_VAULT_NAME=<your-key-vault-name>
# Or full URI
AZURE_KEYVAULT_URL=https://<vault-name>.vault.azure.net
```

## Client Hierarchy

```
KeyClient (key management)
├── CreateKey / CreateRsaKey / CreateEcKey
├── GetKey / GetKeys
├── UpdateKeyProperties
├── DeleteKey / PurgeDeletedKey
├── BackupKey / RestoreKey
└── GetCryptographyClient() → CryptographyClient

CryptographyClient (cryptographic operations)
├── Encrypt / Decrypt
├── WrapKey / UnwrapKey
├── Sign / Verify
└── SignData / VerifyData

KeyResolver (key resolution)
└── Resolve(keyId) → CryptographyClient
```

## Authentication

### DefaultAzureCredential (Recommended)

```csharp
using Azure.Identity;
using Azure.Security.KeyVault.Keys;

var keyVaultName = Environment.GetEnvironmentVariable("KEY_VAULT_NAME");
var kvUri = $"https://{keyVaultName}.vault.azure.net";

var client = new KeyClient(new Uri(kvUri), new DefaultAzureCredential());
```

### Service Principal

```csharp
var credential = new ClientSecretCredential(
    tenantId: "<tenant-id>",
    clientId: "<client-id>",
    clientSecret: "<client-secret>");

var client = new KeyClient(new Uri(kvUri), credential);
```

## Key Management

### Create Keys

```csharp
// Create RSA key
KeyVaultKey rsaKey = await client.CreateKeyAsync("my-rsa-key", KeyType.Rsa);
Console.WriteLine($"Created key: {rsaKey.Name}, Type: {rsaKey.KeyType}");

// Create RSA key with options
var rsaOptions = new CreateRsaKeyOptions("my-rsa-key-2048")
{
    KeySize = 2048,
    HardwareProtected = false, // true for HSM-backed
    ExpiresOn = DateTimeOffset.UtcNow.AddYears(1),
    NotBefore = DateTimeOffset.UtcNow,
    Enabled = true
};
rsaOptions.KeyOperations.Add(KeyOperation.Encrypt);
rsaOptions.KeyOperations.Add(KeyOperation.Decrypt);

KeyVaultKey rsaKey2 = await client.CreateRsaKeyAsync(rsaOptions);

// Create EC key
var ecOptions = new CreateEcKeyOptions("my-ec-key")
{
    CurveName = KeyCurveName.P256,
    HardwareProtected = true // HSM-backed
};
KeyVaultKey ecKey = await client.CreateEcKeyAsync(ecOptions);

// Create Oct (symmetric) key for wrap/unwrap
var octOptions = new CreateOctKeyOptions("my-oct-key")
{
    KeySize = 256,
    HardwareProtected = true
};
KeyVaultKey octKey = await client.CreateOctKeyAsync(octOptions);
```

### Retrieve Keys

```csharp
// Get specific key (latest version)
KeyVaultKey key = await client.GetKeyAsync("my-rsa-key");
Console.WriteLine($"Key ID: {key.Id}");
Console.WriteLine($"Key Type: {key.KeyType}");
Console.WriteLine($"Version: {key.Properties.Version}");

// Get specific version
KeyVaultKey keyVersion = await client.GetKeyAsync("my-rsa-key", "version-id");

// List all keys
await foreach (KeyProperties keyProps in client.GetPropertiesOfKeysAsync())
{
    Console.WriteLine($"Key: {keyProps.Name}, Enabled: {keyProps.Enabled}");
}

// List key versions
await foreach (KeyProperties version in client.GetPropertiesOfKeyVersionsAsync("my-rsa-key"))
{
    Console.WriteLine($"Version: {version.Version}, Created: {version.CreatedOn}");
}
```

### Update Key Properties

```csharp
KeyVaultKey key = await client.GetKeyAsync("my-rsa-key");

key.Properties.ExpiresOn = DateTimeOffset.UtcNow.AddYears(2);
key.Properties.Tags["environment"] = "production";

KeyVaultKey updatedKey = await client.UpdateKeyPropertiesAsync(key.Properties);
```

### Delete and Purge Keys

```csharp
// Start delete operation
DeleteKeyOperation operation = await client.StartDeleteKeyAsync("my-rsa-key");

// Wait for deletion to complete (required before purge)
await operation.WaitForCompletionAsync();
Console.WriteLine($"Deleted key scheduled purge date: {operation.Value.ScheduledPurgeDate}");

// Purge is a separate irreversible operation, subject to purge protection.
// await client.PurgeDeletedKeyAsync("my-rsa-key");

// Or recover deleted key
RecoverDeletedKeyOperation recovery = await client.StartRecoverDeletedKeyAsync("my-rsa-key");
await recovery.WaitForCompletionAsync();
KeyVaultKey recoveredKey = recovery.Value;
```

### Backup and Rest
