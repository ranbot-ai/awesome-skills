---
name: azure-cosmos-ts
description: Azure Cosmos DB JavaScript/TypeScript SDK (@azure/cosmos) for data plane operations. Use for CRUD operations on documents, queries, bulk operations, and container management. Triggers: "Cosmos DB", "@
category: Document Processing
source: antigravity
tags: [javascript, typescript, node, api, ai, document, azure, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-cosmos-ts
---


# @azure/cosmos (TypeScript/JavaScript)

Data plane SDK for Azure Cosmos DB NoSQL API operations — CRUD on documents, queries, bulk operations.

> **⚠️ Data vs Management Plane**
> - **This SDK (@azure/cosmos)**: CRUD operations on documents, queries, stored procedures
> - **Management SDK (@azure/arm-cosmosdb)**: Create accounts, databases, containers via ARM

## Installation

```bash
npm install @azure/cosmos @azure/identity
```

**Current Version**: 4.9.0  
**Node.js**: >= 20.0.0

## Environment Variables

```bash
COSMOS_ENDPOINT=https://<account>.documents.azure.com:443/
COSMOS_DATABASE=<database-name>
COSMOS_CONTAINER=<container-name>
# For key-based auth only (prefer AAD)
COSMOS_KEY=<account-key>
```

## Authentication

### AAD with DefaultAzureCredential (Recommended)

```typescript
import { CosmosClient } from "@azure/cosmos";
import { DefaultAzureCredential } from "@azure/identity";

const client = new CosmosClient({
  endpoint: process.env.COSMOS_ENDPOINT!,
  aadCredentials: new DefaultAzureCredential(),
});
```

### Key-Based Authentication

```typescript
import { CosmosClient } from "@azure/cosmos";

// Option 1: Endpoint + Key
const client = new CosmosClient({
  endpoint: process.env.COSMOS_ENDPOINT!,
  key: process.env.COSMOS_KEY!,
});

// Option 2: Connection String
const client = new CosmosClient(process.env.COSMOS_CONNECTION_STRING!);
```

## Resource Hierarchy

```
CosmosClient
└── Database
    └── Container
        ├── Items (documents)
        ├── Scripts (stored procedures, triggers, UDFs)
        └── Conflicts
```

## Core Operations

### Database & Container Setup

```typescript
const { database } = await client.databases.createIfNotExists({
  id: "my-database",
});

const { container } = await database.containers.createIfNotExists({
  id: "my-container",
  partitionKey: { paths: ["/partitionKey"] },
});
```

### Create Document

```typescript
interface Product {
  id: string;
  partitionKey: string;
  name: string;
  price: number;
}

const item: Product = {
  id: "product-1",
  partitionKey: "electronics",
  name: "Laptop",
  price: 999.99,
};

const { resource } = await container.items.create<Product>(item);
```

### Read Document

```typescript
const { resource } = await container
  .item("product-1", "electronics") // id, partitionKey
  .read<Product>();

if (resource) {
  console.log(resource.name);
}
```

### Update Document (Replace)

```typescript
const { resource: existing } = await container
  .item("product-1", "electronics")
  .read<Product>();

if (existing) {
  existing.price = 899.99;
  const { resource: updated } = await container
    .item("product-1", "electronics")
    .replace<Product>(existing);
}
```

### Upsert Document

```typescript
const item: Product = {
  id: "product-1",
  partitionKey: "electronics",
  name: "Laptop Pro",
  price: 1299.99,
};

const { resource } = await container.items.upsert<Product>(item);
```

### Delete Document

```typescript
await container.item("product-1", "electronics").delete();
```

### Patch Document (Partial Update)

```typescript
import { PatchOperation } from "@azure/cosmos";

const operations: PatchOperation[] = [
  { op: "replace", path: "/price", value: 799.99 },
  { op: "add", path: "/discount", value: true },
  { op: "remove", path: "/oldField" },
];

const { resource } = await container
  .item("product-1", "electronics")
  .patch<Product>(operations);
```

## Queries

### Simple Query

```typescript
const { resources } = await container.items
  .query<Product>("SELECT * FROM c WHERE c.price < 1000")
  .fetchAll();
```

### Parameterized Query (Recommended)

```typescript
import { SqlQuerySpec } from "@azure/cosmos";

const querySpec: SqlQuerySpec = {
  query: "SELECT * FROM c WHERE c.partitionKey = @category AND c.price < @maxPrice",
  parameters: [
    { name: "@category", value: "electronics" },
    { name: "@maxPrice", value: 1000 },
  ],
};

const { resources } = await container.items
  .query<Product>(querySpec)
  .fetchAll();
```

### Query with Pagination

```typescript
const queryIterator = container.items.query<Product>(querySpec, {
  maxItemCount: 10, // Items per page
});

while (queryIterator.hasMoreResults()) {
  const { resources, continuationToken } = await queryIterator.fetchNext();
  console.log(`Page with ${resources?.length} items`);
  // Use continuationToken for next page if needed
}
```

### Cross-Partition Query

```typescript
const { resources } = await container.items
  .query<Product>(
    "SELECT * FROM c WHERE c.price > 500",
    { enableCrossPartitionQuery: true }
  )
  .fetchAll();
```

## Bulk Operations

### Execute Bulk Operations

```typescript
import { BulkOperationType, OperationInput } from "@azure/cosmos";

const operations: OperationInput[] = [
  {
    operationType: BulkOperationType.Create,
    resourceBody: { id: "1", partitionKey: "cat-a", name: "Item 1" },
  },
  {
    operationType: BulkOperationType.Upsert,
    resourceBody: { id: "2", partitionKey: "cat-a", name: "Item
