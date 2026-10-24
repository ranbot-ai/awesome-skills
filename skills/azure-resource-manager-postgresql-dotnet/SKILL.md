---
name: azure-resource-manager-postgresql-dotnet
description: Azure PostgreSQL Flexible Server SDK for .NET. Database management for PostgreSQL Flexible Server deployments. 
category: Document Processing
source: antigravity
tags: [api, ai, workflow, document, azure, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-resource-manager-postgresql-dotnet
---


# Azure.ResourceManager.PostgreSql (.NET)

Azure Resource Manager SDK for managing PostgreSQL Flexible Server deployments.

## Installation

```bash
dotnet add package Azure.ResourceManager.PostgreSql
dotnet add package Azure.Identity
```

**Example baseline**: SDK v1.2.0 / API 2023-12-01-preview. This is not a current-version assertion; select and pin a supported SDK/API for the target subscription and compile these snippets against it.

> **Note**: This skill focuses on PostgreSQL Flexible Server. Single Server is retired; use Flexible Server and check current regional/version support.

## Environment Variables

```bash
AZURE_SUBSCRIPTION_ID=<your-subscription-id>
AZURE_RESOURCE_GROUP=<your-resource-group>
AZURE_POSTGRESQL_SERVER_NAME=<your-postgresql-server>
```

## Authentication

```csharp
using Azure.Identity;
using Azure.ResourceManager;
using Azure.ResourceManager.PostgreSql;
using Azure.ResourceManager.PostgreSql.FlexibleServers;

ArmClient client = new ArmClient(new DefaultAzureCredential());
```

## Resource Hierarchy

```
Subscription
└── ResourceGroup
    └── PostgreSqlFlexibleServer              # PostgreSQL Flexible Server instance
        ├── PostgreSqlFlexibleServerDatabase  # Database within the server
        ├── PostgreSqlFlexibleServerFirewallRule # IP firewall rules
        ├── PostgreSqlFlexibleServerConfiguration # Server parameters
        ├── PostgreSqlFlexibleServerBackup    # Backup information
        ├── PostgreSqlFlexibleServerActiveDirectoryAdministrator # Entra ID admin
        └── PostgreSqlFlexibleServerVirtualEndpoint # Read replica endpoints
```

## Core Workflows

These are separate illustrative snippets, not one compilable program. Add imports (`Azure`, `Azure.Core`, resource-group types) as required by the installed SDK. Confirm subscription/resource IDs, cost, availability and rollback before provisioning or resizing; confirm a recoverable backup and exact target before deletion. ARM credentials manage infrastructure; database connections separately need authorized database roles. Refresh Entra tokens for newly opened pooled connections using Npgsql’s password-provider API rather than retaining one token indefinitely.

### 1. Create PostgreSQL Flexible Server

```csharp
using System;
using Azure.ResourceManager.PostgreSql.FlexibleServers;
using Azure.ResourceManager.PostgreSql.FlexibleServers.Models;

var subscription = await client.GetDefaultSubscriptionAsync();
ResourceGroupResource resourceGroup = (await subscription.GetResourceGroupAsync("my-resource-group")).Value;

PostgreSqlFlexibleServerCollection servers = resourceGroup.GetPostgreSqlFlexibleServers();

PostgreSqlFlexibleServerData data = new PostgreSqlFlexibleServerData(AzureLocation.EastUS)
{
    Sku = new PostgreSqlFlexibleServerSku("Standard_D2ds_v4", PostgreSqlFlexibleServerSkuTier.GeneralPurpose),
    AdministratorLogin = "pgadmin",
    AdministratorLoginPassword = Environment.GetEnvironmentVariable("POSTGRES_ADMIN_PASSWORD") ?? throw new InvalidOperationException("POSTGRES_ADMIN_PASSWORD is required"),
    Version = PostgreSqlFlexibleServerVersion.Ver16,
    Storage = new PostgreSqlFlexibleServerStorage
    {
        StorageSizeInGB = 128,
        AutoGrow = StorageAutoGrow.Enabled,
        Tier = PostgreSqlStorageTierName.P30
    },
    Backup = new PostgreSqlFlexibleServerBackupProperties
    {
        BackupRetentionDays = 7,
        GeoRedundantBackup = PostgreSqlFlexibleServerGeoRedundantBackupEnum.Disabled
    },
    HighAvailability = new PostgreSqlFlexibleServerHighAvailability
    {
        Mode = PostgreSqlFlexibleServerHighAvailabilityMode.ZoneRedundant,
        StandbyAvailabilityZone = "2"
    },
    AvailabilityZone = "1",
    AuthConfig = new PostgreSqlFlexibleServerAuthConfig
    {
        ActiveDirectoryAuth = PostgreSqlFlexibleServerActiveDirectoryAuthEnum.Enabled,
        PasswordAuth = PostgreSqlFlexibleServerPasswordAuthEnum.Enabled
    }
};

ArmOperation<PostgreSqlFlexibleServerResource> operation = await servers
    .CreateOrUpdateAsync(WaitUntil.Completed, "my-postgresql-server", data);

PostgreSqlFlexibleServerResource server = operation.Value;
Console.WriteLine($"Server created: {server.Data.FullyQualifiedDomainName}");
```

### 2. Create Database

```csharp
PostgreSqlFlexibleServerResource server = await resourceGroup
    .GetPostgreSqlFlexibleServerAsync("my-postgresql-server");

PostgreSqlFlexibleServerDatabaseCollection databases = server.GetPostgreSqlFlexibleServerDatabases();

PostgreSqlFlexibleServerDatabaseData dbData = new PostgreSqlFlexibleServerDatabaseData
{
    Charset = "UTF8",
    Collation = "en_US.utf8"
};

ArmOperation<PostgreSqlFlexibleServerDatabaseResource> operation = await databases
    .CreateOrUpdateAsync(WaitUntil.Completed, "myappdb", dbData);

PostgreSqlFlexibleServerDatabaseResource database = operation.Value;
Console.WriteLine($"Database created: {database.Data.Name}");
```

### 3. Configure Firewall Rules

```csharp
PostgreSqlFlexibleServerFirew
