---
name: azure-mgmt-weightsandbiases-dotnet
description: Azure Weights & Biases SDK for .NET. ML experiment tracking and model management via Azure Marketplace. Use for creating W&B instances, managing SSO, marketplace integration, and ML observability. Tri
category: Document Processing
source: antigravity
tags: [python, api, ai, workflow, document, security, azure, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-mgmt-weightsandbiases-dotnet
---


# Azure.ResourceManager.WeightsAndBiases (.NET)

Azure Resource Manager SDK for deploying and managing Weights & Biases ML experiment tracking instances via Azure Marketplace.

## Installation

```bash
dotnet add package Azure.ResourceManager.WeightsAndBiases --prerelease
dotnet add package Azure.Identity
```

**Current Version**: v1.0.0-beta.1 (preview)  
**API Version**: 2024-09-18-preview

## Environment Variables

```bash
AZURE_SUBSCRIPTION_ID=<your-subscription-id>
AZURE_RESOURCE_GROUP=<your-resource-group>
AZURE_WANDB_INSTANCE_NAME=<your-wandb-instance>
```

## Authentication

```csharp
using Azure.Identity;
using Azure.ResourceManager;
using Azure.ResourceManager.WeightsAndBiases;

ArmClient client = new ArmClient(new DefaultAzureCredential());
```

## Resource Hierarchy

```
Subscription
└── ResourceGroup
    └── WeightsAndBiasesInstance    # W&B deployment from Azure Marketplace
        ├── Properties
        │   ├── Marketplace          # Offer details, plan, publisher
        │   ├── User                 # Admin user info
        │   ├── PartnerProperties    # W&B-specific config (region, subdomain)
        │   └── SingleSignOnPropertiesV2  # Entra ID SSO configuration
        └── Identity                 # Managed identity (optional)
```

## Core Workflows

### 1. Create Weights & Biases Instance

```csharp
using Azure.ResourceManager.WeightsAndBiases;
using Azure.ResourceManager.WeightsAndBiases.Models;

ResourceGroupResource resourceGroup = await client
    .GetDefaultSubscriptionAsync()
    .Result
    .GetResourceGroupAsync("my-resource-group");

WeightsAndBiasesInstanceCollection instances = resourceGroup.GetWeightsAndBiasesInstances();

WeightsAndBiasesInstanceData data = new WeightsAndBiasesInstanceData(AzureLocation.EastUS)
{
    Properties = new WeightsAndBiasesInstanceProperties
    {
        // Marketplace configuration
        Marketplace = new WeightsAndBiasesMarketplaceDetails
        {
            SubscriptionId = "<marketplace-subscription-id>",
            OfferDetails = new WeightsAndBiasesOfferDetails
            {
                PublisherId = "wandb",
                OfferId = "wandb-pay-as-you-go",
                PlanId = "wandb-payg",
                PlanName = "Pay As You Go",
                TermId = "monthly",
                TermUnit = "P1M"
            }
        },
        // Admin user
        User = new WeightsAndBiasesUserDetails
        {
            FirstName = "Admin",
            LastName = "User",
            EmailAddress = "admin@example.com",
            Upn = "admin@example.com"
        },
        // W&B-specific configuration
        PartnerProperties = new WeightsAndBiasesPartnerProperties
        {
            Region = WeightsAndBiasesRegion.EastUS,
            Subdomain = "my-company-wandb"
        }
    },
    // Optional: Enable managed identity
    Identity = new ManagedServiceIdentity(ManagedServiceIdentityType.SystemAssigned)
};

ArmOperation<WeightsAndBiasesInstanceResource> operation = await instances
    .CreateOrUpdateAsync(WaitUntil.Completed, "my-wandb-instance", data);

WeightsAndBiasesInstanceResource instance = operation.Value;

Console.WriteLine($"W&B Instance created: {instance.Data.Name}");
Console.WriteLine($"Provisioning state: {instance.Data.Properties.ProvisioningState}");
```

### 2. Get Existing Instance

```csharp
WeightsAndBiasesInstanceResource instance = await resourceGroup
    .GetWeightsAndBiasesInstanceAsync("my-wandb-instance");

Console.WriteLine($"Instance: {instance.Data.Name}");
Console.WriteLine($"Location: {instance.Data.Location}");
Console.WriteLine($"State: {instance.Data.Properties.ProvisioningState}");

if (instance.Data.Properties.PartnerProperties != null)
{
    Console.WriteLine($"Region: {instance.Data.Properties.PartnerProperties.Region}");
    Console.WriteLine($"Subdomain: {instance.Data.Properties.PartnerProperties.Subdomain}");
}
```

### 3. List All Instances

```csharp
// List in resource group
await foreach (WeightsAndBiasesInstanceResource instance in 
    resourceGroup.GetWeightsAndBiasesInstances())
{
    Console.WriteLine($"Instance: {instance.Data.Name}");
    Console.WriteLine($"  Location: {instance.Data.Location}");
    Console.WriteLine($"  State: {instance.Data.Properties.ProvisioningState}");
}

// List in subscription
SubscriptionResource subscription = await client.GetDefaultSubscriptionAsync();
await foreach (WeightsAndBiasesInstanceResource instance in 
    subscription.GetWeightsAndBiasesInstancesAsync())
{
    Console.WriteLine($"{instance.Data.Name} in {instance.Id.ResourceGroupName}");
}
```

### 4. Configure Single Sign-On (SSO)

```csharp
WeightsAndBiasesInstanceResource instance = await resourceGroup
    .GetWeightsAndBiasesInstanceAsync("my-wandb-instance");

// Update with SSO configuration
WeightsAndBiasesInstanceData updateData = instance.Data;

updateData.Properties.SingleSignOnPropertiesV2 = new WeightsAndBiasSingleSignOnPropertiesV2
{
    Type = WeightsAndBiasSingleSign
