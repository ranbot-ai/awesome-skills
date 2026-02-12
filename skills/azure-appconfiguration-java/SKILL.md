---
name: azure-appconfiguration-java
description: Azure App Configuration SDK for Java. Centralized application configuration management with key-value settings, feature flags, and snapshots. Triggers: "ConfigurationClient java", "app configuration j
category: Document Processing
source: antigravity
tags: [react, api, ai, document, azure, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-appconfiguration-java
---


# Azure App Configuration SDK for Java

Client library for Azure App Configuration, a managed service for centralizing application configurations.

## Installation

```xml
<dependency>
    <groupId>com.azure</groupId>
    <artifactId>azure-data-appconfiguration</artifactId>
    <version>1.8.0</version>
</dependency>
```

Or use Azure SDK BOM:

```xml
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>com.azure</groupId>
            <artifactId>azure-sdk-bom</artifactId>
            <version>{bom_version}</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>

<dependencies>
    <dependency>
        <groupId>com.azure</groupId>
        <artifactId>azure-data-appconfiguration</artifactId>
    </dependency>
</dependencies>
```

## Prerequisites

- Azure App Configuration store
- Connection string or Entra ID credentials

## Environment Variables

```bash
AZURE_APPCONFIG_CONNECTION_STRING=Endpoint=https://<store>.azconfig.io;Id=<id>;Secret=<secret>
AZURE_APPCONFIG_ENDPOINT=https://<store>.azconfig.io
```

## Client Creation

### With Connection String

```java
import com.azure.data.appconfiguration.ConfigurationClient;
import com.azure.data.appconfiguration.ConfigurationClientBuilder;

ConfigurationClient configClient = new ConfigurationClientBuilder()
    .connectionString(System.getenv("AZURE_APPCONFIG_CONNECTION_STRING"))
    .buildClient();
```

### Async Client

```java
import com.azure.data.appconfiguration.ConfigurationAsyncClient;

ConfigurationAsyncClient asyncClient = new ConfigurationClientBuilder()
    .connectionString(connectionString)
    .buildAsyncClient();
```

### With Entra ID (Recommended)

```java
import com.azure.identity.DefaultAzureCredentialBuilder;

ConfigurationClient configClient = new ConfigurationClientBuilder()
    .credential(new DefaultAzureCredentialBuilder().build())
    .endpoint(System.getenv("AZURE_APPCONFIG_ENDPOINT"))
    .buildClient();
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Configuration Setting | Key-value pair with optional label |
| Label | Dimension for separating settings (e.g., environments) |
| Feature Flag | Special setting for feature management |
| Secret Reference | Setting pointing to Key Vault secret |
| Snapshot | Point-in-time immutable view of settings |

## Configuration Setting Operations

### Create Setting (Add)

Creates only if setting doesn't exist:

```java
import com.azure.data.appconfiguration.models.ConfigurationSetting;

ConfigurationSetting setting = configClient.addConfigurationSetting(
    "app/database/connection", 
    "Production", 
    "Server=prod.db.com;Database=myapp"
);
```

### Create or Update Setting (Set)

Creates or overwrites:

```java
ConfigurationSetting setting = configClient.setConfigurationSetting(
    "app/cache/enabled", 
    "Production", 
    "true"
);
```

### Get Setting

```java
ConfigurationSetting setting = configClient.getConfigurationSetting(
    "app/database/connection", 
    "Production"
);
System.out.println("Value: " + setting.getValue());
System.out.println("Content-Type: " + setting.getContentType());
System.out.println("Last Modified: " + setting.getLastModified());
```

### Conditional Get (If Changed)

```java
import com.azure.core.http.rest.Response;
import com.azure.core.util.Context;

Response<ConfigurationSetting> response = configClient.getConfigurationSettingWithResponse(
    setting,      // Setting with ETag
    null,         // Accept datetime
    true,         // ifChanged - only fetch if modified
    Context.NONE
);

if (response.getStatusCode() == 304) {
    System.out.println("Setting not modified");
} else {
    ConfigurationSetting updated = response.getValue();
}
```

### Update Setting

```java
ConfigurationSetting updated = configClient.setConfigurationSetting(
    "app/cache/enabled", 
    "Production", 
    "false"
);
```

### Conditional Update (If Unchanged)

```java
// Only update if ETag matches (no concurrent modifications)
Response<ConfigurationSetting> response = configClient.setConfigurationSettingWithResponse(
    setting,     // Setting with current ETag
    true,        // ifUnchanged
    Context.NONE
);
```

### Delete Setting

```java
ConfigurationSetting deleted = configClient.deleteConfigurationSetting(
    "app/cache/enabled", 
    "Production"
);
```

### Conditional Delete

```java
Response<ConfigurationSetting> response = configClient.deleteConfigurationSettingWithResponse(
    setting,     // Setting with ETag
    true,        // ifUnchanged
    Context.NONE
);
```

## List and Filter Settings

### List by Key Pattern

```java
import com.azure.data.appconfiguration.models.SettingSelector;
import com.azure.core.http.rest.PagedIterable;

SettingSelector selector = new SettingSelector()
    .setKeyFilter("app/*");

PagedIterable<ConfigurationSetting> settings = configClient.listConfigurationSettings(selector);
f
