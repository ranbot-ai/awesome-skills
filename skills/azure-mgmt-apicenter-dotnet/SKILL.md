---
name: azure-mgmt-apicenter-dotnet
description: Azure API Center SDK for .NET. Centralized API inventory management with governance, versioning, and discovery. Use for creating API services, workspaces, APIs, versions, definitions, environments, de
category: Document Processing
source: antigravity
tags: [api, mcp, ai, workflow, design, document, azure, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-mgmt-apicenter-dotnet
---


# Azure.ResourceManager.ApiCenter (.NET)

Centralized API inventory and governance SDK for managing APIs across your organization.

## Installation

```bash
dotnet add package Azure.ResourceManager.ApiCenter
dotnet add package Azure.Identity
```

**Current Version**: v1.0.0 (GA)  
**API Version**: 2024-03-01

## Environment Variables

```bash
AZURE_SUBSCRIPTION_ID=<your-subscription-id>
AZURE_RESOURCE_GROUP=<your-resource-group>
AZURE_APICENTER_SERVICE_NAME=<your-apicenter-service>
```

## Authentication

```csharp
using Azure.Identity;
using Azure.ResourceManager;
using Azure.ResourceManager.ApiCenter;

ArmClient client = new ArmClient(new DefaultAzureCredential());
```

## Resource Hierarchy

```
Subscription
└── ResourceGroup
    └── ApiCenterService                    # API inventory service
        ├── Workspace                       # Logical grouping of APIs
        │   ├── Api                         # API definition
        │   │   └── ApiVersion              # Version of the API
        │   │       └── ApiDefinition       # OpenAPI/GraphQL/etc specification
        │   ├── Environment                 # Deployment target (dev/staging/prod)
        │   └── Deployment                  # API deployed to environment
        └── MetadataSchema                  # Custom metadata definitions
```

## Core Workflows

### 1. Create API Center Service

```csharp
using Azure.ResourceManager.ApiCenter;
using Azure.ResourceManager.ApiCenter.Models;

ResourceGroupResource resourceGroup = await client
    .GetDefaultSubscriptionAsync()
    .Result
    .GetResourceGroupAsync("my-resource-group");

ApiCenterServiceCollection services = resourceGroup.GetApiCenterServices();

ApiCenterServiceData data = new ApiCenterServiceData(AzureLocation.EastUS)
{
    Identity = new ManagedServiceIdentity(ManagedServiceIdentityType.SystemAssigned)
};

ArmOperation<ApiCenterServiceResource> operation = await services
    .CreateOrUpdateAsync(WaitUntil.Completed, "my-api-center", data);

ApiCenterServiceResource service = operation.Value;
```

### 2. Create Workspace

```csharp
ApiCenterWorkspaceCollection workspaces = service.GetApiCenterWorkspaces();

ApiCenterWorkspaceData workspaceData = new ApiCenterWorkspaceData
{
    Title = "Engineering APIs",
    Description = "APIs owned by the engineering team"
};

ArmOperation<ApiCenterWorkspaceResource> operation = await workspaces
    .CreateOrUpdateAsync(WaitUntil.Completed, "engineering", workspaceData);

ApiCenterWorkspaceResource workspace = operation.Value;
```

### 3. Create API

```csharp
ApiCenterApiCollection apis = workspace.GetApiCenterApis();

ApiCenterApiData apiData = new ApiCenterApiData
{
    Title = "Orders API",
    Description = "API for managing customer orders",
    Kind = ApiKind.Rest,
    LifecycleStage = ApiLifecycleStage.Production,
    TermsOfService = new ApiTermsOfService
    {
        Uri = new Uri("https://example.com/terms")
    },
    ExternalDocumentation = 
    {
        new ApiExternalDocumentation
        {
            Title = "Documentation",
            Uri = new Uri("https://docs.example.com/orders")
        }
    },
    Contacts =
    {
        new ApiContact
        {
            Name = "API Support",
            Email = "api-support@example.com"
        }
    }
};

// Add custom metadata
apiData.CustomProperties = BinaryData.FromObjectAsJson(new
{
    team = "orders-team",
    costCenter = "CC-1234"
});

ArmOperation<ApiCenterApiResource> operation = await apis
    .CreateOrUpdateAsync(WaitUntil.Completed, "orders-api", apiData);

ApiCenterApiResource api = operation.Value;
```

### 4. Create API Version

```csharp
ApiCenterApiVersionCollection versions = api.GetApiCenterApiVersions();

ApiCenterApiVersionData versionData = new ApiCenterApiVersionData
{
    Title = "v1.0.0",
    LifecycleStage = ApiLifecycleStage.Production
};

ArmOperation<ApiCenterApiVersionResource> operation = await versions
    .CreateOrUpdateAsync(WaitUntil.Completed, "v1-0-0", versionData);

ApiCenterApiVersionResource version = operation.Value;
```

### 5. Create API Definition (Upload OpenAPI Spec)

```csharp
ApiCenterApiDefinitionCollection definitions = version.GetApiCenterApiDefinitions();

ApiCenterApiDefinitionData definitionData = new ApiCenterApiDefinitionData
{
    Title = "OpenAPI Specification",
    Description = "Orders API OpenAPI 3.0 definition"
};

ArmOperation<ApiCenterApiDefinitionResource> operation = await definitions
    .CreateOrUpdateAsync(WaitUntil.Completed, "openapi", definitionData);

ApiCenterApiDefinitionResource definition = operation.Value;

// Import specification
string openApiSpec = await File.ReadAllTextAsync("orders-api.yaml");

ApiSpecImportContent importContent = new ApiSpecImportContent
{
    Format = ApiSpecImportSourceFormat.Inline,
    Value = openApiSpec,
    Specification = new ApiSpecImportSpecification
    {
        Name = "openapi",
        Version = "3.0.1"
    }
};

await definition.ImportSpecificationAsync(WaitUntil.Comp
