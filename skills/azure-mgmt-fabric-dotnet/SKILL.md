---
name: azure-mgmt-fabric-dotnet
description: Azure Resource Manager SDK for Fabric in .NET. Use for MANAGEMENT PLANE operations: provisioning, scaling, suspending/resuming Microsoft Fabric capacities, checking name availability, and listing SKUs
category: Document Processing
source: antigravity
tags: [api, ai, workflow, document, azure, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-mgmt-fabric-dotnet
---


# Azure.ResourceManager.Fabric (.NET)

Management plane SDK for provisioning and managing Microsoft Fabric capacity resources via Azure Resource Manager.

> **Management Plane Only**
> This SDK manages Fabric *capacities* (compute resources). For working with Fabric workspaces, lakehouses, warehouses, and data items, use the Microsoft Fabric REST API or data plane SDKs.

## Installation

```bash
dotnet add package Azure.ResourceManager.Fabric
dotnet add package Azure.Identity
```

**Current Version**: 1.0.0 (GA - September 2025)  
**API Version**: 2023-11-01  
**Target Frameworks**: .NET 8.0, .NET Standard 2.0

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
using Azure.ResourceManager.Fabric;

// Always use DefaultAzureCredential
var credential = new DefaultAzureCredential();
var armClient = new ArmClient(credential);

// Get subscription
var subscription = await armClient.GetDefaultSubscriptionAsync();
```

## Resource Hierarchy

```
ArmClient
└── SubscriptionResource
    └── ResourceGroupResource
        └── FabricCapacityResource
```

## Core Workflows

### 1. Create Fabric Capacity

```csharp
using Azure.ResourceManager.Fabric;
using Azure.ResourceManager.Fabric.Models;
using Azure.Core;

// Get resource group
var resourceGroup = await subscription.GetResourceGroupAsync("my-resource-group");

// Define capacity configuration
var administration = new FabricCapacityAdministration(
    new[] { "admin@contoso.com" }  // Capacity administrators (UPNs or object IDs)
);

var properties = new FabricCapacityProperties(administration);

var sku = new FabricSku("F64", FabricSkuTier.Fabric);

var capacityData = new FabricCapacityData(
    AzureLocation.WestUS2,
    properties,
    sku)
{
    Tags = { ["Environment"] = "Production" }
};

// Create capacity (long-running operation)
var capacityCollection = resourceGroup.Value.GetFabricCapacities();
var operation = await capacityCollection.CreateOrUpdateAsync(
    WaitUntil.Completed,
    "my-fabric-capacity",
    capacityData);

FabricCapacityResource capacity = operation.Value;
Console.WriteLine($"Created capacity: {capacity.Data.Name}");
Console.WriteLine($"State: {capacity.Data.Properties.State}");
```

### 2. Get Fabric Capacity

```csharp
// Get existing capacity
var capacity = await resourceGroup.Value
    .GetFabricCapacityAsync("my-fabric-capacity");

Console.WriteLine($"Name: {capacity.Value.Data.Name}");
Console.WriteLine($"Location: {capacity.Value.Data.Location}");
Console.WriteLine($"SKU: {capacity.Value.Data.Sku.Name}");
Console.WriteLine($"State: {capacity.Value.Data.Properties.State}");
Console.WriteLine($"Provisioning State: {capacity.Value.Data.Properties.ProvisioningState}");
```

### 3. Update Capacity (Scale SKU or Change Admins)

```csharp
var capacity = await resourceGroup.Value
    .GetFabricCapacityAsync("my-fabric-capacity");

var patch = new FabricCapacityPatch
{
    Sku = new FabricSku("F128", FabricSkuTier.Fabric),  // Scale up
    Properties = new FabricCapacityUpdateProperties
    {
        Administration = new FabricCapacityAdministration(
            new[] { "admin@contoso.com", "newadmin@contoso.com" }
        )
    }
};

var updateOperation = await capacity.Value.UpdateAsync(
    WaitUntil.Completed,
    patch);

Console.WriteLine($"Updated SKU: {updateOperation.Value.Data.Sku.Name}");
```

### 4. Suspend and Resume Capacity

```csharp
// Suspend capacity (stop billing for compute)
await capacity.Value.SuspendAsync(WaitUntil.Completed);
Console.WriteLine("Capacity suspended");

// Resume capacity
var resumeOperation = await capacity.Value.ResumeAsync(WaitUntil.Completed);
Console.WriteLine($"Capacity resumed. State: {resumeOperation.Value.Data.Properties.State}");
```

### 5. Delete Capacity

```csharp
await capacity.Value.DeleteAsync(WaitUntil.Completed);
Console.WriteLine("Capacity deleted");
```

### 6. List All Capacities

```csharp
// In a resource group
await foreach (var cap in resourceGroup.Value.GetFabricCapacities())
{
    Console.WriteLine($"- {cap.Data.Name} ({cap.Data.Sku.Name})");
}

// In a subscription
await foreach (var cap in subscription.GetFabricCapacitiesAsync())
{
    Console.WriteLine($"- {cap.Data.Name} in {cap.Data.Location}");
}
```

### 7. Check Name Availability

```csharp
var checkContent = new FabricNameAvailabilityContent
{
    Name = "my-new-capacity",
    ResourceType = "Microsoft.Fabric/capacities"
};

var result = await subscription.CheckFabricCapacityNameAvailabilityAsync(
    AzureLocation.WestUS2,
    checkContent);

if (result.Value.IsNameAvailable == true)
{
    Console.WriteLine("Name is available!");
}
else
{
    Console.WriteLine($"Name unavailable: {result.Value.Reason} - {result.Value.Message}");
}
```

### 8. List Available SKUs

```csharp
//
