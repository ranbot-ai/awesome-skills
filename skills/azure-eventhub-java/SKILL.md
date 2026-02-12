---
name: azure-eventhub-java
description: Build real-time streaming applications with Azure Event Hubs SDK for Java. Use when implementing event streaming, high-throughput data ingestion, or building event-driven architectures. 
category: AI & Agents
source: antigravity
tags: [ai, azure, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-eventhub-java
---


# Azure Event Hubs SDK for Java

Build real-time streaming applications using the Azure Event Hubs SDK for Java.

## Installation

```xml
<dependency>
    <groupId>com.azure</groupId>
    <artifactId>azure-messaging-eventhubs</artifactId>
    <version>5.19.0</version>
</dependency>

<!-- For checkpoint store (production) -->
<dependency>
    <groupId>com.azure</groupId>
    <artifactId>azure-messaging-eventhubs-checkpointstore-blob</artifactId>
    <version>1.20.0</version>
</dependency>
```

## Client Creation

### EventHubProducerClient

```java
import com.azure.messaging.eventhubs.EventHubProducerClient;
import com.azure.messaging.eventhubs.EventHubClientBuilder;

// With connection string
EventHubProducerClient producer = new EventHubClientBuilder()
    .connectionString("<connection-string>", "<event-hub-name>")
    .buildProducerClient();

// Full connection string with EntityPath
EventHubProducerClient producer = new EventHubClientBuilder()
    .connectionString("<connection-string-with-entity-path>")
    .buildProducerClient();
```

### With DefaultAzureCredential

```java
import com.azure.identity.DefaultAzureCredentialBuilder;

EventHubProducerClient producer = new EventHubClientBuilder()
    .fullyQualifiedNamespace("<namespace>.servicebus.windows.net")
    .eventHubName("<event-hub-name>")
    .credential(new DefaultAzureCredentialBuilder().build())
    .buildProducerClient();
```

### EventHubConsumerClient

```java
import com.azure.messaging.eventhubs.EventHubConsumerClient;

EventHubConsumerClient consumer = new EventHubClientBuilder()
    .connectionString("<connection-string>", "<event-hub-name>")
    .consumerGroup(EventHubClientBuilder.DEFAULT_CONSUMER_GROUP_NAME)
    .buildConsumerClient();
```

### Async Clients

```java
import com.azure.messaging.eventhubs.EventHubProducerAsyncClient;
import com.azure.messaging.eventhubs.EventHubConsumerAsyncClient;

EventHubProducerAsyncClient asyncProducer = new EventHubClientBuilder()
    .connectionString("<connection-string>", "<event-hub-name>")
    .buildAsyncProducerClient();

EventHubConsumerAsyncClient asyncConsumer = new EventHubClientBuilder()
    .connectionString("<connection-string>", "<event-hub-name>")
    .consumerGroup("$Default")
    .buildAsyncConsumerClient();
```

## Core Patterns

### Send Single Event

```java
import com.azure.messaging.eventhubs.EventData;

EventData eventData = new EventData("Hello, Event Hubs!");
producer.send(Collections.singletonList(eventData));
```

### Send Event Batch

```java
import com.azure.messaging.eventhubs.EventDataBatch;
import com.azure.messaging.eventhubs.models.CreateBatchOptions;

// Create batch
EventDataBatch batch = producer.createBatch();

// Add events (returns false if batch is full)
for (int i = 0; i < 100; i++) {
    EventData event = new EventData("Event " + i);
    if (!batch.tryAdd(event)) {
        // Batch is full, send and create new batch
        producer.send(batch);
        batch = producer.createBatch();
        batch.tryAdd(event);
    }
}

// Send remaining events
if (batch.getCount() > 0) {
    producer.send(batch);
}
```

### Send to Specific Partition

```java
CreateBatchOptions options = new CreateBatchOptions()
    .setPartitionId("0");

EventDataBatch batch = producer.createBatch(options);
batch.tryAdd(new EventData("Partition 0 event"));
producer.send(batch);
```

### Send with Partition Key

```java
CreateBatchOptions options = new CreateBatchOptions()
    .setPartitionKey("customer-123");

EventDataBatch batch = producer.createBatch(options);
batch.tryAdd(new EventData("Customer event"));
producer.send(batch);
```

### Event with Properties

```java
EventData event = new EventData("Order created");
event.getProperties().put("orderId", "ORD-123");
event.getProperties().put("customerId", "CUST-456");
event.getProperties().put("priority", 1);

producer.send(Collections.singletonList(event));
```

### Receive Events (Simple)

```java
import com.azure.messaging.eventhubs.models.EventPosition;
import com.azure.messaging.eventhubs.models.PartitionEvent;

// Receive from specific partition
Iterable<PartitionEvent> events = consumer.receiveFromPartition(
    "0",                           // partitionId
    10,                            // maxEvents
    EventPosition.earliest(),      // startingPosition
    Duration.ofSeconds(30)         // timeout
);

for (PartitionEvent partitionEvent : events) {
    EventData event = partitionEvent.getData();
    System.out.println("Body: " + event.getBodyAsString());
    System.out.println("Sequence: " + event.getSequenceNumber());
    System.out.println("Offset: " + event.getOffset());
}
```

### EventProcessorClient (Production)

```java
import com.azure.messaging.eventhubs.EventProcessorClient;
import com.azure.messaging.eventhubs.EventProcessorClientBuilder;
import com.azure.messaging.eventhubs.checkpointstore.blob.BlobCheckpointStore;
import com.azure.storage.blob.BlobContainerAsyncClient;
import com.azure.storage.blob.BlobCon
