---
name: azure-mgmt-apimanagement-dotnet
description: Azure Resource Manager SDK for API Management in .NET. Use for MANAGEMENT PLANE operations: creating/managing APIM services, APIs, products, subscriptions, policies, users, groups, gateways, and backe
category: Document Processing
source: antigravity
tags: [api, ai, workflow, document, azure, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-mgmt-apimanagement-dotnet
---


# Azure.ResourceManager.ApiManagement (.NET)

Management plane SDK for provisioning and managing Azure API Management resources via Azure Resource Manager.

> **⚠️ Management vs Data Plane**
> - **This SDK (Azure.ResourceManager.ApiManagement)**: Create services, APIs, products, subscriptions, policies, users, groups
> - **Data Plane**: Direct API calls to your APIM gateway endpoints

## Installation

```bash
dotnet add package Azure.ResourceManager.ApiManagement
dotnet add package Azure.Identity
```

**Current Version**: v1.3.0

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
using Azure.ResourceManager.ApiManagement;

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
        └── ApiManagementServiceResource
            ├── ApiResource
            │   ├── ApiOperationResource
            │   │   └── ApiOperationPolicyResource
            │   ├── ApiPolicyResource
            │   ├── ApiSchemaResource
            │   └── ApiDiagnosticResource
            ├── ApiManagementProductResource
            │   ├── ProductApiResource
            │   ├── ProductGroupResource
            │   └── ProductPolicyResource
            ├── ApiManagementSubscriptionResource
            ├── ApiManagementPolicyResource
            ├── ApiManagementUserResource
            ├── ApiManagementGroupResource
            ├── ApiManagementBackendResource
            ├── ApiManagementGatewayResource
            ├── ApiManagementCertificateResource
            ├── ApiManagementNamedValueResource
            └── ApiManagementLoggerResource
```

## Core Workflow

### 1. Create API Management Service

```csharp
using Azure.ResourceManager.ApiManagement;
using Azure.ResourceManager.ApiManagement.Models;

// Get resource group
var resourceGroup = await subscription
    .GetResourceGroupAsync("my-resource-group");

// Define service
var serviceData = new ApiManagementServiceData(
    location: AzureLocation.EastUS,
    sku: new ApiManagementServiceSkuProperties(
        ApiManagementServiceSkuType.Developer, 
        capacity: 1),
    publisherEmail: "admin@contoso.com",
    publisherName: "Contoso");

// Create service (long-running operation - can take 30+ minutes)
var serviceCollection = resourceGroup.Value.GetApiManagementServices();
var operation = await serviceCollection.CreateOrUpdateAsync(
    WaitUntil.Completed,
    "my-apim-service",
    serviceData);

ApiManagementServiceResource service = operation.Value;
```

### 2. Create an API

```csharp
var apiData = new ApiCreateOrUpdateContent
{
    DisplayName = "My API",
    Path = "myapi",
    Protocols = { ApiOperationInvokableProtocol.Https },
    ServiceUri = new Uri("https://backend.contoso.com/api")
};

var apiCollection = service.GetApis();
var apiOperation = await apiCollection.CreateOrUpdateAsync(
    WaitUntil.Completed,
    "my-api",
    apiData);

ApiResource api = apiOperation.Value;
```

### 3. Create a Product

```csharp
var productData = new ApiManagementProductData
{
    DisplayName = "Starter",
    Description = "Starter tier with limited access",
    IsSubscriptionRequired = true,
    IsApprovalRequired = false,
    SubscriptionsLimit = 1,
    State = ApiManagementProductState.Published
};

var productCollection = service.GetApiManagementProducts();
var productOperation = await productCollection.CreateOrUpdateAsync(
    WaitUntil.Completed,
    "starter",
    productData);

ApiManagementProductResource product = productOperation.Value;

// Add API to product
await product.GetProductApis().CreateOrUpdateAsync(
    WaitUntil.Completed,
    "my-api");
```

### 4. Create a Subscription

```csharp
var subscriptionData = new ApiManagementSubscriptionCreateOrUpdateContent
{
    DisplayName = "My Subscription",
    Scope = $"/products/{product.Data.Name}",
    State = ApiManagementSubscriptionState.Active
};

var subscriptionCollection = service.GetApiManagementSubscriptions();
var subOperation = await subscriptionCollection.CreateOrUpdateAsync(
    WaitUntil.Completed,
    "my-subscription",
    subscriptionData);

ApiManagementSubscriptionResource subscription = subOperation.Value;

// Get subscription keys
var keys = await subscription.GetSecretsAsync();
Console.WriteLine($"Primary Key: {keys.Value.PrimaryKey}");
```

### 5. Set API Policy

```csharp
var policyXml = @"
<policies>
    <inbound>
        <rate-limit calls=""100"" renewal-period=
