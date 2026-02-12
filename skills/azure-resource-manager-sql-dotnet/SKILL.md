---
name: azure-resource-manager-sql-dotnet
description: Azure Resource Manager SDK for Azure SQL in .NET. Use for MANAGEMENT PLANE operations: creating/managing SQL servers, databases, elastic pools, firewall rules, and failover groups via Azure Resource M
category: AI & Agents
source: antigravity
tags: [api, ai, workflow, security, azure, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-resource-manager-sql-dotnet
---


# Azure.ResourceManager.Sql (.NET)

Management plane SDK for provisioning and managing Azure SQL resources via Azure Resource Manager.

> **⚠️ Management vs Data Plane**
> - **This SDK (Azure.ResourceManager.Sql)**: Create servers, databases, elastic pools, configure firewall rules, manage failover groups
> - **Data Plane SDK (Microsoft.Data.SqlClient)**: Execute queries, stored procedures, manage connections

## Installation

```bash
dotnet add package Azure.ResourceManager.Sql
dotnet add package Azure.Identity
```

**Current Versions**: Stable v1.3.0, Preview v1.4.0-beta.3

## Environment Variables

```bash
AZURE_SUBSCRIPTION_ID=<your-subscription-id>
# For service principal auth (optional)
AZURE_TENANT_ID=<tenant-id>
AZURE_CLIENT_ID=<client-id>
AZURE_CLIENT_SECRET=<client-secret>
```

## Authentication

```csharp
using Azure.Identity;
using Azure.ResourceManager;
using Azure.ResourceManager.Sql;

// Always use DefaultAzureCredential
var credential = new DefaultAzureCredential();
var armClient = new ArmClient(credential);

// Get subscription
var subscriptionId = Environment.GetEnvironmentVariable("AZURE_SUBSCRIPTION_ID");
var subscription = armClient.GetSubscriptionResource(
    new ResourceIdentifier($"/subscriptions/{subscriptionId}"));
```

## Resource Hierarchy

```
ArmClient
└── SubscriptionResource
    └── ResourceGroupResource
        └── SqlServerResource
            ├── SqlDatabaseResource
            ├── ElasticPoolResource
            │   └── ElasticPoolDatabaseResource
            ├── SqlFirewallRuleResource
            ├── FailoverGroupResource
            ├── ServerBlobAuditingPolicyResource
            ├── EncryptionProtectorResource
            └── VirtualNetworkRuleResource
```

## Core Workflow

### 1. Create SQL Server

```csharp
using Azure.ResourceManager.Sql;
using Azure.ResourceManager.Sql.Models;

// Get resource group
var resourceGroup = await subscription
    .GetResourceGroupAsync("my-resource-group");

// Define server
var serverData = new SqlServerData(AzureLocation.EastUS)
{
    AdministratorLogin = "sqladmin",
    AdministratorLoginPassword = "YourSecurePassword123!",
    Version = "12.0",
    MinimalTlsVersion = SqlMinimalTlsVersion.Tls1_2,
    PublicNetworkAccess = ServerNetworkAccessFlag.Enabled
};

// Create server (long-running operation)
var serverCollection = resourceGroup.Value.GetSqlServers();
var operation = await serverCollection.CreateOrUpdateAsync(
    WaitUntil.Completed,
    "my-sql-server",
    serverData);

SqlServerResource server = operation.Value;
```

### 2. Create SQL Database

```csharp
var databaseData = new SqlDatabaseData(AzureLocation.EastUS)
{
    Sku = new SqlSku("S0") { Tier = "Standard" },
    MaxSizeBytes = 2L * 1024 * 1024 * 1024, // 2 GB
    Collation = "SQL_Latin1_General_CP1_CI_AS",
    RequestedBackupStorageRedundancy = SqlBackupStorageRedundancy.Local
};

var databaseCollection = server.GetSqlDatabases();
var dbOperation = await databaseCollection.CreateOrUpdateAsync(
    WaitUntil.Completed,
    "my-database",
    databaseData);

SqlDatabaseResource database = dbOperation.Value;
```

### 3. Create Elastic Pool

```csharp
var poolData = new ElasticPoolData(AzureLocation.EastUS)
{
    Sku = new SqlSku("StandardPool")
    {
        Tier = "Standard",
        Capacity = 100 // 100 eDTUs
    },
    PerDatabaseSettings = new ElasticPoolPerDatabaseSettings
    {
        MinCapacity = 0,
        MaxCapacity = 100
    }
};

var poolCollection = server.GetElasticPools();
var poolOperation = await poolCollection.CreateOrUpdateAsync(
    WaitUntil.Completed,
    "my-elastic-pool",
    poolData);

ElasticPoolResource pool = poolOperation.Value;
```

### 4. Add Database to Elastic Pool

```csharp
var databaseData = new SqlDatabaseData(AzureLocation.EastUS)
{
    ElasticPoolId = pool.Id
};

await databaseCollection.CreateOrUpdateAsync(
    WaitUntil.Completed,
    "pooled-database",
    databaseData);
```

### 5. Configure Firewall Rules

```csharp
// Allow Azure services
var azureServicesRule = new SqlFirewallRuleData
{
    StartIPAddress = "0.0.0.0",
    EndIPAddress = "0.0.0.0"
};

var firewallCollection = server.GetSqlFirewallRules();
await firewallCollection.CreateOrUpdateAsync(
    WaitUntil.Completed,
    "AllowAzureServices",
    azureServicesRule);

// Allow specific IP range
var clientRule = new SqlFirewallRuleData
{
    StartIPAddress = "203.0.113.0",
    EndIPAddress = "203.0.113.255"
};

await firewallCollection.CreateOrUpdateAsync(
    WaitUntil.Completed,
    "AllowClientIPs",
    clientRule);
```

### 6. List Resources

```csharp
// List all servers in subscription
await foreach (var srv in subscription.GetSqlServersAsync())
{
    Console.WriteLine($"Server: {srv.Data.Name} in {srv.Data.Location}");
}

// List databases in a server
await foreach (var db in server.GetSqlDatabases())
{
    Console.WriteLine($"Database: {db.Data.Name}, SKU: {db.Data.Sku?.Name}");
}

// List elastic pools
await foreach (var ep in server.GetElasticPools()
