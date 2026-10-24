---
name: azure-mgmt-weightsandbiases-dotnet
description: Azure Weights & Biases SDK for .NET. ML experiment tracking and model management via Azure Marketplace. Use for creating W&B instances, managing SSO, marketplace integration, and ML observability. 
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

**Example package baseline**: v1.0.0-beta.1 (preview); verify available version and generated API before adapting
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

Select an explicit authorized tenant/subscription/resource group rather than relying on the default for billable creation. Import Azure/Azure.Core, Resources and Models types required by the chosen SDK. Marketplace offer/plan/term/region and SSO details below are illustrative and must match current provider terms and permissions; a missing ARM resource is not a global name-availability check. Creation may incur Marketplace charges and deletion may destroy access/data; preview exact resources and preserve exports before approved mutations. ARM management and W&B experiment tracking are distinct APIs: retrieve the actual provisioned base URL instead of constructing an assumed wandb.ai host. Keep API keys, experiment data and admin PII out of logs; verify retention/egress approval before logging runs.

## Core Workflows

### 1. Create Weights & Biases Instance

```csharp
using Azure.ResourceManager.WeightsAndBiases;
using Azure.ResourceManager.WeightsAndBiases.Models;

SubscriptionResource subscription = await client.GetDefaultSubscriptionAsync();
ResourceGroupResource resourceGroup = (await subscription.GetResourceGroupAsync("my-resource-group")).Value;

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
    resourceGroup.GetWeightsAndBiasesInstanc
