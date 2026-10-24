---
name: azure-resource-manager-playwright-dotnet
description: Azure Resource Manager SDK for Microsoft Playwright Testing in .NET. 
category: Document Processing
source: antigravity
tags: [api, ai, workflow, document, azure, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-resource-manager-playwright-dotnet
---


# Azure.ResourceManager.Playwright (.NET)

Management plane SDK for provisioning and managing Microsoft Playwright Testing workspaces via Azure Resource Manager.

> **⚠️ Management vs Test Execution**
> - **This SDK (Azure.ResourceManager.Playwright)**: Create workspaces, manage quotas, check name availability
> - **Test Execution SDK (Azure.Developer.MicrosoftPlaywrightTesting.NUnit)**: Run Playwright tests at scale on cloud browsers

## Version and provisioning boundary

These are historical SDK fragments, not verified current package/service versions. Confirm the current Microsoft service lifecycle, package migration guidance and target resource provider before provisioning; stop if the named service is retired or unavailable. Select a production credential deliberately for the deployment environment rather than assuming every DefaultAzureCredential source is intended. Confirm subscription/resource group/region, budget and deletion scope; resource creation is billable and does not authorize remote test execution or uploading private test artifacts.

## Installation

```bash
dotnet add package Azure.ResourceManager.Playwright
dotnet add package Azure.Identity
```

**Example version context**: v1.0.0 / v1.0.0-beta.1 are historical references; verify the supported package before use.

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
using Azure.ResourceManager.Playwright;

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
    ├── PlaywrightQuotaResource (subscription-level quotas)
    └── ResourceGroupResource
        └── PlaywrightWorkspaceResource
            └── PlaywrightWorkspaceQuotaResource (workspace-level quotas)
```

## Core Workflow

### 1. Create Playwright Workspace

```csharp
using Azure.ResourceManager.Playwright;
using Azure.ResourceManager.Playwright.Models;

// Get resource group
var resourceGroup = await subscription
    .GetResourceGroupAsync("my-resource-group");

// Define workspace
var workspaceData = new PlaywrightWorkspaceData(AzureLocation.WestUS3)
{
    // Optional: Configure regional affinity and local auth
    RegionalAffinity = PlaywrightRegionalAffinity.Enabled,
    LocalAuth = PlaywrightLocalAuth.Enabled,
    Tags =
    {
        ["Team"] = "Dev Exp",
        ["Environment"] = "Production"
    }
};

// Create workspace (long-running operation)
var workspaceCollection = resourceGroup.Value.GetPlaywrightWorkspaces();
var operation = await workspaceCollection.CreateOrUpdateAsync(
    WaitUntil.Completed,
    "my-playwright-workspace",
    workspaceData);

PlaywrightWorkspaceResource workspace = operation.Value;

// Get the data plane URI for running tests
Console.WriteLine($"Data Plane URI: {workspace.Data.DataplaneUri}");
Console.WriteLine($"Workspace ID: {workspace.Data.WorkspaceId}");
```

### 2. Get Existing Workspace

```csharp
// Get by name
var workspace = await workspaceCollection.GetAsync("my-playwright-workspace");

// Or check if exists first
bool exists = await workspaceCollection.ExistsAsync("my-playwright-workspace");
if (exists)
{
    var existingWorkspace = await workspaceCollection.GetAsync("my-playwright-workspace");
    Console.WriteLine($"Workspace found: {existingWorkspace.Value.Data.Name}");
}
```

### 3. List Workspaces

```csharp
// List in resource group
await foreach (var workspace in workspaceCollection.GetAllAsync())
{
    Console.WriteLine($"Workspace: {workspace.Data.Name}");
    Console.WriteLine($"  Location: {workspace.Data.Location}");
    Console.WriteLine($"  State: {workspace.Data.ProvisioningState}");
    Console.WriteLine($"  Data Plane URI: {workspace.Data.DataplaneUri}");
}

// List across subscription
await foreach (var workspace in subscription.GetPlaywrightWorkspacesAsync())
{
    Console.WriteLine($"Workspace: {workspace.Data.Name}");
}
```

### 4. Update Workspace

```csharp
var patch = new PlaywrightWorkspacePatch
{
    Tags =
    {
        ["Team"] = "Dev Exp",
        ["Environment"] = "Staging",
        ["UpdatedAt"] = DateTime.UtcNow.ToString("o")
    }
};

var updatedWorkspace = await workspace.Value.UpdateAsync(patch);
```

### 5. Check Name Availability

```csharp
using Azure.ResourceManager.Playwright.Models;

var checkRequest = new PlaywrightCheckNameAvailabilityContent
{
    Name = "my-new-workspace",
    ResourceType = "Microsoft.LoadTestService/playwrightWorkspaces"
};

var result = await subscription.CheckPlaywrightNa
