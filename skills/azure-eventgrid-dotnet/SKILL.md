---
name: azure-eventgrid-dotnet
description: Azure Event Grid SDK for .NET. Client library for publishing and consuming events with Azure Event Grid. Use for event-driven architectures, pub/sub messaging, CloudEvents, and EventGridEvents. Trigge
category: AI & Agents
source: antigravity
tags: [api, ai, image, azure, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-eventgrid-dotnet
---


# Azure.Messaging.EventGrid (.NET)

Client library for publishing events to Azure Event Grid topics, domains, and namespaces.

## Installation

```bash
# For topics and domains (push delivery)
dotnet add package Azure.Messaging.EventGrid

# For namespaces (pull delivery)
dotnet add package Azure.Messaging.EventGrid.Namespaces

# For CloudNative CloudEvents interop
dotnet add package Microsoft.Azure.Messaging.EventGrid.CloudNativeCloudEvents
```

**Current Version**: 4.28.0 (stable)

## Environment Variables

```bash
# Topic/Domain endpoint
EVENT_GRID_TOPIC_ENDPOINT=https://<topic-name>.<region>.eventgrid.azure.net/api/events
EVENT_GRID_TOPIC_KEY=<access-key>

# Namespace endpoint (for pull delivery)
EVENT_GRID_NAMESPACE_ENDPOINT=https://<namespace>.<region>.eventgrid.azure.net
EVENT_GRID_TOPIC_NAME=<topic-name>
EVENT_GRID_SUBSCRIPTION_NAME=<subscription-name>
```

## Client Hierarchy

```
Push Delivery (Topics/Domains)
└── EventGridPublisherClient
    ├── SendEventAsync(EventGridEvent)
    ├── SendEventsAsync(IEnumerable<EventGridEvent>)
    ├── SendEventAsync(CloudEvent)
    └── SendEventsAsync(IEnumerable<CloudEvent>)

Pull Delivery (Namespaces)
├── EventGridSenderClient
│   └── SendAsync(CloudEvent)
└── EventGridReceiverClient
    ├── ReceiveAsync()
    ├── AcknowledgeAsync()
    ├── ReleaseAsync()
    └── RejectAsync()
```

## Authentication

### API Key Authentication

```csharp
using Azure;
using Azure.Messaging.EventGrid;

EventGridPublisherClient client = new(
    new Uri("https://mytopic.eastus-1.eventgrid.azure.net/api/events"),
    new AzureKeyCredential("<access-key>"));
```

### Microsoft Entra ID (Recommended)

```csharp
using Azure.Identity;
using Azure.Messaging.EventGrid;

EventGridPublisherClient client = new(
    new Uri("https://mytopic.eastus-1.eventgrid.azure.net/api/events"),
    new DefaultAzureCredential());
```

### SAS Token Authentication

```csharp
string sasToken = EventGridPublisherClient.BuildSharedAccessSignature(
    new Uri(topicEndpoint),
    DateTimeOffset.UtcNow.AddHours(1),
    new AzureKeyCredential(topicKey));

var sasCredential = new AzureSasCredential(sasToken);
EventGridPublisherClient client = new(
    new Uri(topicEndpoint),
    sasCredential);
```

## Publishing Events

### EventGridEvent Schema

```csharp
EventGridPublisherClient client = new(
    new Uri(topicEndpoint),
    new AzureKeyCredential(topicKey));

// Single event
EventGridEvent egEvent = new(
    subject: "orders/12345",
    eventType: "Order.Created",
    dataVersion: "1.0",
    data: new { OrderId = "12345", Amount = 99.99 });

await client.SendEventAsync(egEvent);

// Batch of events
List<EventGridEvent> events = new()
{
    new EventGridEvent(
        subject: "orders/12345",
        eventType: "Order.Created",
        dataVersion: "1.0",
        data: new OrderData { OrderId = "12345", Amount = 99.99 }),
    new EventGridEvent(
        subject: "orders/12346",
        eventType: "Order.Created",
        dataVersion: "1.0",
        data: new OrderData { OrderId = "12346", Amount = 149.99 })
};

await client.SendEventsAsync(events);
```

### CloudEvent Schema

```csharp
CloudEvent cloudEvent = new(
    source: "/orders/system",
    type: "Order.Created",
    data: new { OrderId = "12345", Amount = 99.99 });

cloudEvent.Subject = "orders/12345";
cloudEvent.Id = Guid.NewGuid().ToString();
cloudEvent.Time = DateTimeOffset.UtcNow;

await client.SendEventAsync(cloudEvent);

// Batch of CloudEvents
List<CloudEvent> cloudEvents = new()
{
    new CloudEvent("/orders", "Order.Created", new { OrderId = "1" }),
    new CloudEvent("/orders", "Order.Updated", new { OrderId = "2" })
};

await client.SendEventsAsync(cloudEvents);
```

### Publishing to Event Grid Domain

```csharp
// Events must specify the Topic property for domain routing
List<EventGridEvent> events = new()
{
    new EventGridEvent(
        subject: "orders/12345",
        eventType: "Order.Created",
        dataVersion: "1.0",
        data: new { OrderId = "12345" })
    {
        Topic = "orders-topic"  // Domain topic name
    },
    new EventGridEvent(
        subject: "inventory/item-1",
        eventType: "Inventory.Updated",
        dataVersion: "1.0",
        data: new { ItemId = "item-1" })
    {
        Topic = "inventory-topic"
    }
};

await client.SendEventsAsync(events);
```

### Custom Serialization

```csharp
using System.Text.Json;

var serializerOptions = new JsonSerializerOptions
{
    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
};

var customSerializer = new JsonObjectSerializer(serializerOptions);

EventGridEvent egEvent = new(
    subject: "orders/12345",
    eventType: "Order.Created",
    dataVersion: "1.0",
    data: customSerializer.Serialize(new OrderData { OrderId = "12345" }));

await client.SendEventAsync(egEvent);
```

## Pull Delivery (Namespaces)

### Send Events to Namespace Topic

```csharp
using Azure;
using Azure.Messaging;
using Azure.Messaging.EventGrid.Namespaces;

var senderClient = new Event
