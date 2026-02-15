---
name: azure-eventhub-ts
description: Build event streaming applications using Azure Event Hubs SDK for JavaScript (@azure/event-hubs). Use when implementing high-throughput event ingestion, real-time analytics, IoT telemetry, or event-dr
category: AI & Agents
source: antigravity
tags: [javascript, typescript, ai, workflow, azure, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-eventhub-ts
---


# Azure Event Hubs SDK for TypeScript

High-throughput event streaming and real-time data ingestion.

## Installation

```bash
npm install @azure/event-hubs @azure/identity
```

For checkpointing with consumer groups:
```bash
npm install @azure/eventhubs-checkpointstore-blob @azure/storage-blob
```

## Environment Variables

```bash
EVENTHUB_NAMESPACE=<namespace>.servicebus.windows.net
EVENTHUB_NAME=my-eventhub
STORAGE_ACCOUNT_NAME=<storage-account>
STORAGE_CONTAINER_NAME=checkpoints
```

## Authentication

```typescript
import { EventHubProducerClient, EventHubConsumerClient } from "@azure/event-hubs";
import { DefaultAzureCredential } from "@azure/identity";

const fullyQualifiedNamespace = process.env.EVENTHUB_NAMESPACE!;
const eventHubName = process.env.EVENTHUB_NAME!;
const credential = new DefaultAzureCredential();

// Producer
const producer = new EventHubProducerClient(fullyQualifiedNamespace, eventHubName, credential);

// Consumer
const consumer = new EventHubConsumerClient(
  "$Default", // Consumer group
  fullyQualifiedNamespace,
  eventHubName,
  credential
);
```

## Core Workflow

### Send Events

```typescript
const producer = new EventHubProducerClient(namespace, eventHubName, credential);

// Create batch and add events
const batch = await producer.createBatch();
batch.tryAdd({ body: { temperature: 72.5, deviceId: "sensor-1" } });
batch.tryAdd({ body: { temperature: 68.2, deviceId: "sensor-2" } });

await producer.sendBatch(batch);
await producer.close();
```

### Send to Specific Partition

```typescript
// By partition ID
const batch = await producer.createBatch({ partitionId: "0" });

// By partition key (consistent hashing)
const batch = await producer.createBatch({ partitionKey: "device-123" });
```

### Receive Events (Simple)

```typescript
const consumer = new EventHubConsumerClient("$Default", namespace, eventHubName, credential);

const subscription = consumer.subscribe({
  processEvents: async (events, context) => {
    for (const event of events) {
      console.log(`Partition: ${context.partitionId}, Body: ${JSON.stringify(event.body)}`);
    }
  },
  processError: async (err, context) => {
    console.error(`Error on partition ${context.partitionId}: ${err.message}`);
  },
});

// Stop after some time
setTimeout(async () => {
  await subscription.close();
  await consumer.close();
}, 60000);
```

### Receive with Checkpointing (Production)

```typescript
import { EventHubConsumerClient } from "@azure/event-hubs";
import { ContainerClient } from "@azure/storage-blob";
import { BlobCheckpointStore } from "@azure/eventhubs-checkpointstore-blob";

const containerClient = new ContainerClient(
  `https://${storageAccount}.blob.core.windows.net/${containerName}`,
  credential
);

const checkpointStore = new BlobCheckpointStore(containerClient);

const consumer = new EventHubConsumerClient(
  "$Default",
  namespace,
  eventHubName,
  credential,
  checkpointStore
);

const subscription = consumer.subscribe({
  processEvents: async (events, context) => {
    for (const event of events) {
      console.log(`Processing: ${JSON.stringify(event.body)}`);
    }
    // Checkpoint after processing batch
    if (events.length > 0) {
      await context.updateCheckpoint(events[events.length - 1]);
    }
  },
  processError: async (err, context) => {
    console.error(`Error: ${err.message}`);
  },
});
```

### Receive from Specific Position

```typescript
const subscription = consumer.subscribe({
  processEvents: async (events, context) => { /* ... */ },
  processError: async (err, context) => { /* ... */ },
}, {
  startPosition: {
    // Start from beginning
    "0": { offset: "@earliest" },
    // Start from end (new events only)
    "1": { offset: "@latest" },
    // Start from specific offset
    "2": { offset: "12345" },
    // Start from specific time
    "3": { enqueuedOn: new Date("2024-01-01") },
  },
});
```

## Event Hub Properties

```typescript
// Get hub info
const hubProperties = await producer.getEventHubProperties();
console.log(`Partitions: ${hubProperties.partitionIds}`);

// Get partition info
const partitionProperties = await producer.getPartitionProperties("0");
console.log(`Last sequence: ${partitionProperties.lastEnqueuedSequenceNumber}`);
```

## Batch Processing Options

```typescript
const subscription = consumer.subscribe(
  {
    processEvents: async (events, context) => { /* ... */ },
    processError: async (err, context) => { /* ... */ },
  },
  {
    maxBatchSize: 100,           // Max events per batch
    maxWaitTimeInSeconds: 30,    // Max wait for batch
  }
);
```

## Key Types

```typescript
import {
  EventHubProducerClient,
  EventHubConsumerClient,
  EventData,
  ReceivedEventData,
  PartitionContext,
  Subscription,
  SubscriptionEventHandlers,
  CreateBatchOptions,
  EventPosition,
} from "@azure/event-hubs";

import { BlobCheckpointStore } from "@azure/eventhubs-checkpointstore-blob";
```

## Event Properties

```typescript
// Send with properties
