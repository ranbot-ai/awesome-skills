---
name: azure-eventhub-dotnet
description: Azure Event Hubs SDK for .NET. 
category: AI & Agents
source: antigravity
tags: [ai, workflow, azure, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-eventhub-dotnet
---


# Azure.Messaging.EventHubs (.NET)

High-throughput event streaming SDK for sending and receiving events via Azure Event Hubs.

## Installation

```bash
# Core package (sending and simple receiving)
dotnet add package Azure.Messaging.EventHubs

# Processor package (production receiving with checkpointing)
dotnet add package Azure.Messaging.EventHubs.Processor

# Authentication
dotnet add package Azure.Identity

# For checkpointing (required by EventProcessorClient)
dotnet add package Azure.Storage.Blobs
```

**Current Versions**: Azure.Messaging.EventHubs v5.12.2, Azure.Messaging.EventHubs.Processor v5.12.2

## Environment Variables

```bash
EVENTHUB_FULLY_QUALIFIED_NAMESPACE=<namespace>.servicebus.windows.net
EVENTHUB_NAME=<event-hub-name>

# For checkpointing (EventProcessorClient)
BLOB_STORAGE_CONNECTION_STRING=<storage-connection-string>
BLOB_CONTAINER_NAME=<checkpoint-container>

# Alternative: Connection string auth (not recommended for production)
EVENTHUB_CONNECTION_STRING=Endpoint=sb://<namespace>.servicebus.windows.net/;SharedAccessKeyName=...
```

## Authentication

```csharp
using Azure.Identity;
using Azure.Messaging.EventHubs;
using Azure.Messaging.EventHubs.Producer;

// Always use DefaultAzureCredential for production
var credential = new DefaultAzureCredential();

var fullyQualifiedNamespace = Environment.GetEnvironmentVariable("EVENTHUB_FULLY_QUALIFIED_NAMESPACE");
var eventHubName = Environment.GetEnvironmentVariable("EVENTHUB_NAME");

var producer = new EventHubProducerClient(
    fullyQualifiedNamespace,
    eventHubName,
    credential);
```

**Required RBAC Roles**:
- **Sending**: `Azure Event Hubs Data Sender`
- **Receiving**: `Azure Event Hubs Data Receiver`
- **Both**: `Azure Event Hubs Data Owner`

## Delivery, checkpoint and shutdown limits

These are SDK fragments requiring verified installed versions and fixtures. Enqueueing a buffered event is not broker acknowledgement; handle success/failure and shutdown flush explicitly. Receiving is at-least-once: perform durable idempotent processing before partition-local checkpoints, never use the shared counter below across concurrent partitions as a correctness boundary. Check for an actual event before dereferencing empty reads. Wrap processing lifetime in try/finally so cancellation still calls StopProcessingAsync; keep event bodies/errors private. Sender plus Receiver roles can be combined without granting Data Owner. Select credential/tenant deliberately and scope creation/sending/receiving/checkpoint storage authority.

## Client Types

| Client | Purpose | When to Use |
|--------|---------|-------------|
| `EventHubProducerClient` | Send events immediately in batches | Real-time sending, full control over batching |
| `EventHubBufferedProducerClient` | Automatic batching with background sending | High-volume, fire-and-forget scenarios |
| `EventHubConsumerClient` | Simple event reading | Prototyping only, NOT for production |
| `EventProcessorClient` | Production event processing | **Always use this for receiving in production** |

## Core Workflow

### 1. Send Events (Batch)

```csharp
using Azure.Identity;
using Azure.Messaging.EventHubs;
using Azure.Messaging.EventHubs.Producer;

await using var producer = new EventHubProducerClient(
    fullyQualifiedNamespace,
    eventHubName,
    new DefaultAzureCredential());

// Create a batch (respects size limits automatically)
EventDataBatch batch = await producer.CreateBatchAsync();

// Add events to batch
var events = new[]
{
    new EventData(BinaryData.FromString("{\"id\": 1, \"message\": \"Hello\"}")),
    new EventData(BinaryData.FromString("{\"id\": 2, \"message\": \"World\"}"))
};

foreach (var eventData in events)
{
    if (!batch.TryAdd(eventData))
    {
        // Batch is full - send it and create a new one
        await producer.SendAsync(batch);
        batch.Dispose();
        batch = await producer.CreateBatchAsync();
        
        if (!batch.TryAdd(eventData))
        {
            throw new Exception("Event too large for empty batch");
        }
    }
}

// Send remaining events; production code wraps the whole loop in try/finally
// so the current batch is disposed on every exception path.
if (batch.Count > 0)
{
    await producer.SendAsync(batch);
}
batch.Dispose();
```

### 2. Send Events (Buffered - High Volume)

```csharp
using Azure.Messaging.EventHubs.Producer;

var options = new EventHubBufferedProducerClientOptions
{
    MaximumWaitTime = TimeSpan.FromSeconds(1)
};

await using var producer = new EventHubBufferedProducerClient(
    fullyQualifiedNamespace,
    eventHubName,
    new DefaultAzureCredential(),
    options);

// Handle send success/failure
producer.SendEventBatchSucceededAsync += args =>
{
    Console.WriteLine($"Batch sent: {args.EventBatch.Count} events");
    return Task.CompletedTask;
};

producer.SendEventBatchFailedAsync += args =>
{
    Console.WriteLine($"Batch failed: {args.Exception.Message}");
    return Task.CompletedTask;
};

/
