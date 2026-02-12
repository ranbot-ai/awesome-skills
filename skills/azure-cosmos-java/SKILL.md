---
name: azure-cosmos-java
description: Azure Cosmos DB SDK for Java. NoSQL database operations with global distribution, multi-model support, and reactive patterns. Triggers: "CosmosClient java", "CosmosAsyncClient", "cosmos database java"
category: Document Processing
source: antigravity
tags: [react, api, ai, agent, workflow, document, azure, rag, seo, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-cosmos-java
---


# Azure Cosmos DB SDK for Java

Client library for Azure Cosmos DB NoSQL API with global distribution and reactive patterns.

## Installation

```xml
<dependency>
    <groupId>com.azure</groupId>
    <artifactId>azure-cosmos</artifactId>
    <version>LATEST</version>
</dependency>
```

Or use Azure SDK BOM:

```xml
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>com.azure</groupId>
            <artifactId>azure-sdk-bom</artifactId>
            <version>{bom_version}</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>

<dependencies>
    <dependency>
        <groupId>com.azure</groupId>
        <artifactId>azure-cosmos</artifactId>
    </dependency>
</dependencies>
```

## Environment Variables

```bash
COSMOS_ENDPOINT=https://<account>.documents.azure.com:443/
COSMOS_KEY=<your-primary-key>
```

## Authentication

### Key-based Authentication

```java
import com.azure.cosmos.CosmosClient;
import com.azure.cosmos.CosmosClientBuilder;

CosmosClient client = new CosmosClientBuilder()
    .endpoint(System.getenv("COSMOS_ENDPOINT"))
    .key(System.getenv("COSMOS_KEY"))
    .buildClient();
```

### Async Client

```java
import com.azure.cosmos.CosmosAsyncClient;

CosmosAsyncClient asyncClient = new CosmosClientBuilder()
    .endpoint(serviceEndpoint)
    .key(key)
    .buildAsyncClient();
```

### With Customizations

```java
import com.azure.cosmos.ConsistencyLevel;
import java.util.Arrays;

CosmosClient client = new CosmosClientBuilder()
    .endpoint(serviceEndpoint)
    .key(key)
    .directMode(directConnectionConfig, gatewayConnectionConfig)
    .consistencyLevel(ConsistencyLevel.SESSION)
    .connectionSharingAcrossClientsEnabled(true)
    .contentResponseOnWriteEnabled(true)
    .userAgentSuffix("my-application")
    .preferredRegions(Arrays.asList("West US", "East US"))
    .buildClient();
```

## Client Hierarchy

| Class | Purpose |
|-------|---------|
| `CosmosClient` / `CosmosAsyncClient` | Account-level operations |
| `CosmosDatabase` / `CosmosAsyncDatabase` | Database operations |
| `CosmosContainer` / `CosmosAsyncContainer` | Container/item operations |

## Core Workflow

### Create Database

```java
// Sync
client.createDatabaseIfNotExists("myDatabase")
    .map(response -> client.getDatabase(response.getProperties().getId()));

// Async with chaining
asyncClient.createDatabaseIfNotExists("myDatabase")
    .map(response -> asyncClient.getDatabase(response.getProperties().getId()))
    .subscribe(database -> System.out.println("Created: " + database.getId()));
```

### Create Container

```java
asyncClient.createDatabaseIfNotExists("myDatabase")
    .flatMap(dbResponse -> {
        String databaseId = dbResponse.getProperties().getId();
        return asyncClient.getDatabase(databaseId)
            .createContainerIfNotExists("myContainer", "/partitionKey")
            .map(containerResponse -> asyncClient.getDatabase(databaseId)
                .getContainer(containerResponse.getProperties().getId()));
    })
    .subscribe(container -> System.out.println("Container: " + container.getId()));
```

### CRUD Operations

```java
import com.azure.cosmos.models.PartitionKey;

CosmosAsyncContainer container = asyncClient
    .getDatabase("myDatabase")
    .getContainer("myContainer");

// Create
container.createItem(new User("1", "John Doe", "john@example.com"))
    .flatMap(response -> {
        System.out.println("Created: " + response.getItem());
        // Read
        return container.readItem(
            response.getItem().getId(),
            new PartitionKey(response.getItem().getId()),
            User.class);
    })
    .flatMap(response -> {
        System.out.println("Read: " + response.getItem());
        // Update
        User user = response.getItem();
        user.setEmail("john.doe@example.com");
        return container.replaceItem(
            user,
            user.getId(),
            new PartitionKey(user.getId()));
    })
    .flatMap(response -> {
        // Delete
        return container.deleteItem(
            response.getItem().getId(),
            new PartitionKey(response.getItem().getId()));
    })
    .block();
```

### Query Documents

```java
import com.azure.cosmos.models.CosmosQueryRequestOptions;
import com.azure.cosmos.util.CosmosPagedIterable;

CosmosContainer container = client.getDatabase("myDatabase").getContainer("myContainer");

String query = "SELECT * FROM c WHERE c.status = @status";
CosmosQueryRequestOptions options = new CosmosQueryRequestOptions();

CosmosPagedIterable<User> results = container.queryItems(
    query,
    options,
    User.class
);

results.forEach(user -> System.out.println("User: " + user.getName()));
```

## Key Concepts

### Partition Keys

Choose a partition key with:
- High cardinality (many distinct values)
- Even distribution of data and requests
- Frequently used in queries

### Consistency Levels

| Level 
