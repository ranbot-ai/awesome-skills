---
name: azure-security-keyvault-secrets-java
description: Azure Key Vault Secrets Java SDK for secret management. Use when storing, retrieving, or managing passwords, API keys, connection strings, or other sensitive configuration data. 
category: Security & Systems
source: antigravity
tags: [api, ai, workflow, security, stripe, azure]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-security-keyvault-secrets-java
---


# Azure Key Vault Secrets (Java)

Securely store and manage secrets like passwords, API keys, and connection strings.

Confirm vault, tenant, RBAC and intended secret/version before mutations. Examples use synthetic values: obtain real values from approved secret input, never source code or chat. Backups contain sensitive encrypted material and have service restore restrictions; protect files and retention. Expiration metadata is not credential rotation at the issuing service. Required secrets must fail closed if unavailable; do not silently start with a partial configuration. Async snippets need error handling and an application lifecycle that awaits completion.

## Installation

```xml
<dependency>
    <groupId>com.azure</groupId>
    <artifactId>azure-security-keyvault-secrets</artifactId>
    <version>4.9.0</version>
</dependency>
```

## Client Creation

```java
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.identity.DefaultAzureCredentialBuilder;

// Sync client
SecretClient secretClient = new SecretClientBuilder()
    .vaultUrl("https://<vault-name>.vault.azure.net")
    .credential(new DefaultAzureCredentialBuilder().build())
    .buildClient();

// Async client
SecretAsyncClient secretAsyncClient = new SecretClientBuilder()
    .vaultUrl("https://<vault-name>.vault.azure.net")
    .credential(new DefaultAzureCredentialBuilder().build())
    .buildAsyncClient();
```

## Create/Set Secret

```java
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;

// Simple secret
KeyVaultSecret secret = secretClient.setSecret("database-password", "P@ssw0rd123!");
System.out.println("Secret name: " + secret.getName());
System.out.println("Secret ID: " + secret.getId());

// Secret with options
KeyVaultSecret secretWithOptions = secretClient.setSecret(
    new KeyVaultSecret("api-key", "sk_live_abc123xyz")
        .setProperties(new SecretProperties()
            .setContentType("application/json")
            .setExpiresOn(OffsetDateTime.now().plusYears(1))
            .setNotBefore(OffsetDateTime.now())
            .setEnabled(true)
            .setTags(Map.of(
                "environment", "production",
                "service", "payment-api"
            ))
        )
);
```

## Get Secret

```java
// Get latest version
KeyVaultSecret secret = secretClient.getSecret("database-password");
String value = secret.getValue();
// Consume value in memory; never print secret material.

// Get specific version
KeyVaultSecret specificVersion = secretClient.getSecret("database-password", "<version-id>");

// Get only properties (no value)
SecretProperties props = secretClient.getSecret("database-password").getProperties();
System.out.println("Enabled: " + props.isEnabled());
System.out.println("Created: " + props.getCreatedOn());
```

## Update Secret Properties

```java
// Get secret
KeyVaultSecret secret = secretClient.getSecret("api-key");

// Update properties (cannot update value - create new version instead)
secret.getProperties()
    .setEnabled(false)
    .setExpiresOn(OffsetDateTime.now().plusMonths(6))
    .setTags(Map.of("status", "rotating"));

SecretProperties updated = secretClient.updateSecretProperties(secret.getProperties());
System.out.println("Updated: " + updated.getUpdatedOn());
```

## List Secrets

```java
import com.azure.core.util.paging.PagedIterable;
import com.azure.security.keyvault.secrets.models.SecretProperties;

// List all secrets (properties only, no values)
for (SecretProperties secretProps : secretClient.listPropertiesOfSecrets()) {
    System.out.println("Secret: " + secretProps.getName());
    System.out.println("  Enabled: " + secretProps.isEnabled());
    System.out.println("  Created: " + secretProps.getCreatedOn());
    System.out.println("  Content-Type: " + secretProps.getContentType());
    
    // Get value if needed
    if (secretProps.isEnabled()) {
        KeyVaultSecret fullSecret = secretClient.getSecret(secretProps.getName());
        // Do not print even a prefix of the secret.
    }
}

// List versions of a secret
for (SecretProperties version : secretClient.listPropertiesOfSecretVersions("database-password")) {
    System.out.println("Version: " + version.getVersion());
    System.out.println("Created: " + version.getCreatedOn());
    System.out.println("Enabled: " + version.isEnabled());
}
```

## Delete Secret

```java
import com.azure.core.util.polling.SyncPoller;
import com.azure.security.keyvault.secrets.models.DeletedSecret;

// Begin delete (returns poller for soft-delete enabled vaults)
SyncPoller<DeletedSecret, Void> deletePoller = secretClient.beginDeleteSecret("old-secret");

// Wait for deletion
DeletedSecret deletedSecret = deletePoller.poll().getValue();
System.out.println("Deleted on: " + deletedSecret.getDeletedOn());
System.out.println("Scheduled purge: " + deletedSecret.getScheduledPurgeDate());

deletePoller.waitForCompletion();
```

## Recover 
