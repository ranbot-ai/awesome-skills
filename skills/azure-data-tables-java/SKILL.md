---
name: azure-data-tables-java
description: Build table storage applications with Azure Tables SDK for Java. Use when working with Azure Table Storage or Cosmos DB Table API for NoSQL key-value data, schemaless storage, or structured data at sc
category: AI & Agents
source: antigravity
tags: [api, ai, design, azure, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-data-tables-java
---


# Azure Tables SDK for Java

Build table storage applications using the Azure Tables SDK for Java. Works with both Azure Table Storage and Cosmos DB Table API.

## Installation

```xml
<dependency>
  <groupId>com.azure</groupId>
  <artifactId>azure-data-tables</artifactId>
  <version>12.6.0-beta.1</version>
</dependency>
```

## Client Creation

### With Connection String

```java
import com.azure.data.tables.TableServiceClient;
import com.azure.data.tables.TableServiceClientBuilder;
import com.azure.data.tables.TableClient;

TableServiceClient serviceClient = new TableServiceClientBuilder()
    .connectionString("<your-connection-string>")
    .buildClient();
```

### With Shared Key

```java
import com.azure.core.credential.AzureNamedKeyCredential;

AzureNamedKeyCredential credential = new AzureNamedKeyCredential(
    "<account-name>",
    "<account-key>");

TableServiceClient serviceClient = new TableServiceClientBuilder()
    .endpoint("<your-table-account-url>")
    .credential(credential)
    .buildClient();
```

### With SAS Token

```java
TableServiceClient serviceClient = new TableServiceClientBuilder()
    .endpoint("<your-table-account-url>")
    .sasToken("<sas-token>")
    .buildClient();
```

### With DefaultAzureCredential (Storage only)

```java
import com.azure.identity.DefaultAzureCredentialBuilder;

TableServiceClient serviceClient = new TableServiceClientBuilder()
    .endpoint("<your-table-account-url>")
    .credential(new DefaultAzureCredentialBuilder().build())
    .buildClient();
```

## Key Concepts

- **TableServiceClient**: Manage tables (create, list, delete)
- **TableClient**: Manage entities within a table (CRUD)
- **Partition Key**: Groups entities for efficient queries
- **Row Key**: Unique identifier within a partition
- **Entity**: A row with up to 252 properties (1MB Storage, 2MB Cosmos)

## Core Patterns

### Create Table

```java
// Create table (throws if exists)
TableClient tableClient = serviceClient.createTable("mytable");

// Create if not exists (no exception)
TableClient tableClient = serviceClient.createTableIfNotExists("mytable");
```

### Get Table Client

```java
// From service client
TableClient tableClient = serviceClient.getTableClient("mytable");

// Direct construction
TableClient tableClient = new TableClientBuilder()
    .connectionString("<connection-string>")
    .tableName("mytable")
    .buildClient();
```

### Create Entity

```java
import com.azure.data.tables.models.TableEntity;

TableEntity entity = new TableEntity("partitionKey", "rowKey")
    .addProperty("Name", "Product A")
    .addProperty("Price", 29.99)
    .addProperty("Quantity", 100)
    .addProperty("IsAvailable", true);

tableClient.createEntity(entity);
```

### Get Entity

```java
TableEntity entity = tableClient.getEntity("partitionKey", "rowKey");

String name = (String) entity.getProperty("Name");
Double price = (Double) entity.getProperty("Price");
System.out.printf("Product: %s, Price: %.2f%n", name, price);
```

### Update Entity

```java
import com.azure.data.tables.models.TableEntityUpdateMode;

// Merge (update only specified properties)
TableEntity updateEntity = new TableEntity("partitionKey", "rowKey")
    .addProperty("Price", 24.99);
tableClient.updateEntity(updateEntity, TableEntityUpdateMode.MERGE);

// Replace (replace entire entity)
TableEntity replaceEntity = new TableEntity("partitionKey", "rowKey")
    .addProperty("Name", "Product A Updated")
    .addProperty("Price", 24.99)
    .addProperty("Quantity", 150);
tableClient.updateEntity(replaceEntity, TableEntityUpdateMode.REPLACE);
```

### Upsert Entity

```java
// Insert or update (merge mode)
tableClient.upsertEntity(entity, TableEntityUpdateMode.MERGE);

// Insert or replace
tableClient.upsertEntity(entity, TableEntityUpdateMode.REPLACE);
```

### Delete Entity

```java
tableClient.deleteEntity("partitionKey", "rowKey");
```

### List Entities

```java
import com.azure.data.tables.models.ListEntitiesOptions;

// List all entities
for (TableEntity entity : tableClient.listEntities()) {
    System.out.printf("%s - %s%n",
        entity.getPartitionKey(),
        entity.getRowKey());
}

// With filtering and selection
ListEntitiesOptions options = new ListEntitiesOptions()
    .setFilter("PartitionKey eq 'sales'")
    .setSelect("Name", "Price");

for (TableEntity entity : tableClient.listEntities(options, null, null)) {
    System.out.printf("%s: %.2f%n",
        entity.getProperty("Name"),
        entity.getProperty("Price"));
}
```

### Query with OData Filter

```java
// Filter by partition key
ListEntitiesOptions options = new ListEntitiesOptions()
    .setFilter("PartitionKey eq 'electronics'");

// Filter with multiple conditions
options.setFilter("PartitionKey eq 'electronics' and Price gt 100");

// Filter with comparison operators
options.setFilter("Quantity ge 10 and Quantity le 100");

// Top N results
options.setTop(10);

for (TableEntity entity : tableClient.listEntities(options, null, null)) {
