---
name: azure-cosmos-py
description: Azure Cosmos DB SDK for Python (NoSQL API). Use for document CRUD, queries, containers, and globally distributed data. Triggers: "cosmos db", "CosmosClient", "container", "document", "NoSQL", "partiti
category: Document Processing
source: antigravity
tags: [python, api, ai, workflow, design, document, azure, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-cosmos-py
---


# Azure Cosmos DB SDK for Python

Client library for Azure Cosmos DB NoSQL API — globally distributed, multi-model database.

## Installation

```bash
pip install azure-cosmos azure-identity
```

## Environment Variables

```bash
COSMOS_ENDPOINT=https://<account>.documents.azure.com:443/
COSMOS_DATABASE=mydb
COSMOS_CONTAINER=mycontainer
```

## Authentication

```python
from azure.identity import DefaultAzureCredential
from azure.cosmos import CosmosClient

credential = DefaultAzureCredential()
endpoint = "https://<account>.documents.azure.com:443/"

client = CosmosClient(url=endpoint, credential=credential)
```

## Client Hierarchy

| Client | Purpose | Get From |
|--------|---------|----------|
| `CosmosClient` | Account-level operations | Direct instantiation |
| `DatabaseProxy` | Database operations | `client.get_database_client()` |
| `ContainerProxy` | Container/item operations | `database.get_container_client()` |

## Core Workflow

### Setup Database and Container

```python
# Get or create database
database = client.create_database_if_not_exists(id="mydb")

# Get or create container with partition key
container = database.create_container_if_not_exists(
    id="mycontainer",
    partition_key=PartitionKey(path="/category")
)

# Get existing
database = client.get_database_client("mydb")
container = database.get_container_client("mycontainer")
```

### Create Item

```python
item = {
    "id": "item-001",           # Required: unique within partition
    "category": "electronics",   # Partition key value
    "name": "Laptop",
    "price": 999.99,
    "tags": ["computer", "portable"]
}

created = container.create_item(body=item)
print(f"Created: {created['id']}")
```

### Read Item

```python
# Read requires id AND partition key
item = container.read_item(
    item="item-001",
    partition_key="electronics"
)
print(f"Name: {item['name']}")
```

### Update Item (Replace)

```python
item = container.read_item(item="item-001", partition_key="electronics")
item["price"] = 899.99
item["on_sale"] = True

updated = container.replace_item(item=item["id"], body=item)
```

### Upsert Item

```python
# Create if not exists, replace if exists
item = {
    "id": "item-002",
    "category": "electronics",
    "name": "Tablet",
    "price": 499.99
}

result = container.upsert_item(body=item)
```

### Delete Item

```python
container.delete_item(
    item="item-001",
    partition_key="electronics"
)
```

## Queries

### Basic Query

```python
# Query within a partition (efficient)
query = "SELECT * FROM c WHERE c.price < @max_price"
items = container.query_items(
    query=query,
    parameters=[{"name": "@max_price", "value": 500}],
    partition_key="electronics"
)

for item in items:
    print(f"{item['name']}: ${item['price']}")
```

### Cross-Partition Query

```python
# Cross-partition (more expensive, use sparingly)
query = "SELECT * FROM c WHERE c.price < @max_price"
items = container.query_items(
    query=query,
    parameters=[{"name": "@max_price", "value": 500}],
    enable_cross_partition_query=True
)

for item in items:
    print(item)
```

### Query with Projection

```python
query = "SELECT c.id, c.name, c.price FROM c WHERE c.category = @category"
items = container.query_items(
    query=query,
    parameters=[{"name": "@category", "value": "electronics"}],
    partition_key="electronics"
)
```

### Read All Items

```python
# Read all in a partition
items = container.read_all_items()  # Cross-partition
# Or with partition key
items = container.query_items(
    query="SELECT * FROM c",
    partition_key="electronics"
)
```

## Partition Keys

**Critical**: Always include partition key for efficient operations.

```python
from azure.cosmos import PartitionKey

# Single partition key
container = database.create_container_if_not_exists(
    id="orders",
    partition_key=PartitionKey(path="/customer_id")
)

# Hierarchical partition key (preview)
container = database.create_container_if_not_exists(
    id="events",
    partition_key=PartitionKey(path=["/tenant_id", "/user_id"])
)
```

## Throughput

```python
# Create container with provisioned throughput
container = database.create_container_if_not_exists(
    id="mycontainer",
    partition_key=PartitionKey(path="/pk"),
    offer_throughput=400  # RU/s
)

# Read current throughput
offer = container.read_offer()
print(f"Throughput: {offer.offer_throughput} RU/s")

# Update throughput
container.replace_throughput(throughput=1000)
```

## Async Client

```python
from azure.cosmos.aio import CosmosClient
from azure.identity.aio import DefaultAzureCredential

async def cosmos_operations():
    credential = DefaultAzureCredential()
    
    async with CosmosClient(endpoint, credential=credential) as client:
        database = client.get_database_client("mydb")
        container = database.get_container_client("mycontainer")
        
        # Create
        await container.create_item(body={"id": "1", "pk": "test"})
        
        # Read
        item =
