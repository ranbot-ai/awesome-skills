---
name: azure-mgmt-applicationinsights-dotnet
description: Azure Application Insights SDK for .NET. Application performance monitoring and observability resource management. Use for creating Application Insights components, web tests, workbooks, analytics ite
category: Document Processing
source: antigravity
tags: [node, api, ai, agent, workflow, template, document, azure, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-mgmt-applicationinsights-dotnet
---


# Azure.ResourceManager.ApplicationInsights (.NET)

Azure Resource Manager SDK for managing Application Insights resources for application performance monitoring.

## Installation

```bash
dotnet add package Azure.ResourceManager.ApplicationInsights
dotnet add package Azure.Identity
```

**Current Version**: v1.0.0 (GA)  
**API Version**: 2022-06-15

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

## Core Workflows

### 1. Create Application Insights Component (Workspace-based)

```csharp
using Azure.ResourceManager.ApplicationInsights;
using Azure.ResourceManager.ApplicationInsights.Models;

ResourceGroupResource resourceGroup = await client
    .GetDefaultSubscriptionAsync()
    .Result
    .GetResourceGroupAsync("my-resource-group");

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
Console.WriteLine($"Instrumentation Key: {component.Data.InstrumentationKey}");
Console.WriteLine($"Connection String: {component.Data.ConnectionString}");
```

### 2. Get Connection String and Keys

```csharp
ApplicationInsightsComponentResource component = await resourceGroup
    .GetApplicationInsightsComponentAsync("my-appinsights");

// Get connection string for SDK configuration
string connectionString = component.Data.ConnectionString;
string instrumentationKey = component.Data.InstrumentationKey;
string appId = component.Data.AppId;

Console.WriteLine($"Connection String: {connectionString}");
Console.WriteLine($"Instrumentation Key: {instrumentationKey}");
Console.WriteLine($"App ID: {appId}");
```

### 3. Create API Key

```csharp
ApplicationInsightsComponentResource component = await resourceGroup
    .GetApplicationInsightsComponentAsync("my-appinsights");

ApplicationInsightsComponentApiKeyCollection apiKeys = component.GetApplicationInsightsComponentApiKeys();

// API key for reading telemetry
ApplicationInsightsApiKeyContent keyContent = new ApplicationInsightsApiKeyContent
{
    Name = "ReadTelemetryKey",
    LinkedReadProperties =
    {
        $"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/microsoft.insights/components/{component.Data.Name}/api",
        $"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/microsoft.insights/components/{component.Data.Name}/agentconfig"
    }
};

ApplicationInsightsComponentApiKeyResource apiKey = await apiKeys
    .CreateOrUpdateAsync(WaitUntil.Completed, keyContent);

Console.WriteLine($"API Key Name: {apiKey.Data.Name}");
Console.WriteLine($"API Key: {apiKey.Data.ApiKey}"); // Only shown once!
```

### 4. Create Web Test (Availability Test)

```csharp
WebTestCollection webTests = resourceGroup.GetWebTests();

// URL Ping Test
WebTestData urlPingTest = new WebTestData(AzureLocation.EastUS)
{
    Kind = WebTestKind.Ping,
    SyntheticMonitorId = "webtest-ping-myapp",
    WebTestName = "Homepage Availability",
    Description = "Checks if homepage is available",
    IsEnable
