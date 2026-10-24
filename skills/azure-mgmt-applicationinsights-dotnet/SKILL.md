---
name: azure-mgmt-applicationinsights-dotnet
description: Azure Application Insights SDK for .NET. Application performance monitoring and observability resource management. 
category: Document Processing
source: antigravity
tags: [node, api, ai, workflow, template, document, azure, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-mgmt-applicationinsights-dotnet
---


# Azure.ResourceManager.ApplicationInsights (.NET)

Azure Resource Manager SDK for managing Application Insights resources for application performance monitoring.

## Installation

```bash
dotnet add package Azure.ResourceManager.ApplicationInsights
dotnet add package Azure.Identity
```

Pin a supported tested SDK version and verify each operation against its API reference; package and ARM API versions differ. These independent fragments are not a single compiled program.

## Environment Variables

```bash
AZURE_SUBSCRIPTION_ID=<your-subscription-id>
AZURE_RESOURCE_GROUP=<your-resource-group>
AZURE_APPINSIGHTS_NAME=<your-appinsights-component>
```

## Authentication

```csharp
using Azure.Identity;
using Azure.ResourceManager;
using Azure.ResourceManager.ApplicationInsights;

ArmClient client = new ArmClient(new DefaultAzureCredential());
```

## Resource Hierarchy

```
Subscription
└── ResourceGroup
    └── ApplicationInsightsComponent          # App Insights resource
        ├── ApplicationInsightsComponentApiKey  # API keys for programmatic access
        ├── ComponentLinkedStorageAccount      # Linked storage for data export
        └── (via component ID)
            ├── WebTest                        # Availability tests
            ├── Workbook                       # Workbooks for analysis
            ├── WorkbookTemplate               # Workbook templates
            └── MyWorkbook                     # Private workbooks
```

Select the intended tenant/subscription and verify the credential/roles. Create/update/delete operations and scheduled tests require target-specific authorization, cost review and rollback/retention planning. Avoid logging telemetry content or keys. Workspace-based retention is governed by the linked workspace/table configuration; component fields alone do not establish effective retention or application SDK sampling. Private Link requires the complete scope, DNS and access policy setup.

## Core Workflows

### 1. Create Application Insights Component (Workspace-based)

```csharp
using Azure.ResourceManager.ApplicationInsights;
using Azure.ResourceManager.ApplicationInsights.Models;

using Azure;
using Azure.Core;
using Azure.ResourceManager.Resources;

string subscriptionId = Environment.GetEnvironmentVariable("AZURE_SUBSCRIPTION_ID")
    ?? throw new InvalidOperationException("Missing subscription");
SubscriptionResource subscription = client.GetSubscriptionResource(
    new ResourceIdentifier($"/subscriptions/{subscriptionId}"));
ResourceGroupResource resourceGroup = (await subscription
    .GetResourceGroupAsync("my-resource-group")).Value;

ApplicationInsightsComponentCollection components = resourceGroup.GetApplicationInsightsComponents();

// Workspace-based Application Insights (recommended)
ApplicationInsightsComponentData data = new ApplicationInsightsComponentData(
    AzureLocation.EastUS,
    ApplicationInsightsApplicationType.Web)
{
    Kind = "web",
    WorkspaceResourceId = new ResourceIdentifier(
        "/subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<workspace-name>"),
    IngestionMode = IngestionMode.LogAnalytics,
    PublicNetworkAccessForIngestion = PublicNetworkAccessType.Enabled,
    PublicNetworkAccessForQuery = PublicNetworkAccessType.Enabled,
    RetentionInDays = 90,
    SamplingPercentage = 100,
    DisableIPMasking = false,
    ImmediatePurgeDataOn30Days = false,
    Tags =
    {
        { "environment", "production" },
        { "application", "mywebapp" }
    }
};

ArmOperation<ApplicationInsightsComponentResource> operation = await components
    .CreateOrUpdateAsync(WaitUntil.Completed, "my-appinsights", data);

ApplicationInsightsComponentResource component = operation.Value;

Console.WriteLine($"Component created: {component.Data.Name}");
// Keep ingestion identifiers in approved configuration; do not log them.
// Pass the connection string to approved configuration without logging.
```

### 2. Get Connection String and Keys

```csharp
ApplicationInsightsComponentResource component = await resourceGroup
    .GetApplicationInsightsComponentAsync("my-appinsights");

// Get connection string for SDK configuration
string connectionString = component.Data.ConnectionString;
string instrumentationKey = component.Data.InstrumentationKey;
string appId = component.Data.AppId;

// Do not print connectionString.
// Do not print instrumentationKey.
Console.WriteLine($"App ID: {appId}");
```

### 3. Telemetry Query Authentication

Prefer supported Microsoft Entra authentication and least-privilege query roles. Do not create or log legacy telemetry-query API keys; verify the current query API/authentication lifecycle before migrating existing clients. Management-plane credentials are separate from ingestion and query access.

### 4. Availability Monitoring

Use supported Standard availability tests for new deployments. The former URL Ping XML example was deprecated, and multi-step `.webtest` tests retired in
