---
name: azure-servicebus-dotnet
description: Azure Service Bus SDK for .NET. Enterprise messaging with queues, topics, subscriptions, and sessions. 
category: AI & Agents
source: antigravity
tags: [api, ai, workflow, azure, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-servicebus-dotnet
---


# Azure.Messaging.ServiceBus (.NET)

Enterprise messaging SDK for reliable message delivery with queues, topics, subscriptions, and sessions.

## Installation

```bash
dotnet add package Azure.Messaging.ServiceBus
dotnet add package Azure.Identity
```

**Example SDK baseline**: v7.20.1; verify the installed package and compatible API before adapting snippets.

## Environment Variables

```bash
AZURE_SERVICEBUS_FULLY_QUALIFIED_NAMESPACE=<namespace>.servicebus.windows.net
# Or connection string (less secure)
AZURE_SERVICEBUS_CONNECTION_STRING=Endpoint=sb://...
```

## Authentication

### Microsoft Entra ID (Recommended)

```csharp
using Azure.Identity;
using Azure.Messaging.ServiceBus;

string fullyQualifiedNamespace = "<namespace>.servicebus.windows.net";
await using ServiceBusClient client = new(fullyQualifiedNamespace, new DefaultAzureCredential());
```

### Connection String

```csharp
string connectionString = "<connection_string>";
await using ServiceBusClient client = new(connectionString);
```

### ASP.NET Core Dependency Injection

```csharp
services.AddAzureClients(builder =>
{
    builder.AddServiceBusClientWithNamespace("<namespace>.servicebus.windows.net");
    builder.UseCredential(new DefaultAzureCredential());
});
```

## Client Hierarchy

```
ServiceBusClient
├── CreateSender(queueOrTopicName)      → ServiceBusSender
├── CreateReceiver(queueName)           → ServiceBusReceiver
├── CreateReceiver(topicName, subName)  → ServiceBusReceiver
├── AcceptNextSessionAsync(queueName)   → ServiceBusSessionReceiver
├── CreateProcessor(queueName)          → ServiceBusProcessor
└── CreateSessionProcessor(queueName)   → ServiceBusSessionProcessor

ServiceBusAdministrationClient (separate client for CRUD)
```

Use separate snippets independently and import Azure.Messaging.ServiceBus.Administration for CRUD and System.Transactions for TransactionScope. Confirm namespace/entity and least-privilege sender/receiver/admin roles. Receive can return null; DLQ and transaction examples also need that guard. Completing removes a message: perform the durable business operation first, make it idempotent for redelivery and reconcile uncertain sends/settlements. Abandoning every exception can create poison-message loops. Do not log message bodies or raw exceptions containing sensitive payloads. Session-enabled queues require session receivers; the basic receive example is for a different non-session queue. Processors need async disposal and bounded lock-renewal/shutdown policies.

## Core Workflows

### 1. Send Messages

```csharp
await using ServiceBusClient client = new(fullyQualifiedNamespace, new DefaultAzureCredential());
ServiceBusSender sender = client.CreateSender("my-queue");

// Single message
ServiceBusMessage message = new("Hello world!");
await sender.SendMessageAsync(message);

// Safe batching (recommended)
using ServiceBusMessageBatch batch = await sender.CreateMessageBatchAsync();
if (!batch.TryAddMessage(new ServiceBusMessage("Message 1")))
    throw new InvalidOperationException("Message 1 exceeds the batch capacity");
if (!batch.TryAddMessage(new ServiceBusMessage("Message 2")))
    throw new InvalidOperationException("Message 2 exceeds remaining batch capacity; flush and retry in a new batch");
await sender.SendMessagesAsync(batch);
```

### 2. Receive Messages

```csharp
ServiceBusReceiver receiver = client.CreateReceiver("my-queue");

// Single message
ServiceBusReceivedMessage message = await receiver.ReceiveMessageAsync();
if (message is null) return; // A timed receive can return no message
string body = message.Body.ToString();
Console.WriteLine(body);

// Complete the message (removes from queue)
await receiver.CompleteMessageAsync(message);

// Batch receive
IReadOnlyList<ServiceBusReceivedMessage> messages = await receiver.ReceiveMessagesAsync(maxMessages: 10);
foreach (var msg in messages)
{
    Console.WriteLine(msg.Body.ToString());
    await receiver.CompleteMessageAsync(msg);
}
```

### 3. Message Settlement

```csharp
// Complete - removes message from queue
await receiver.CompleteMessageAsync(message);

// Abandon - releases lock, message can be received again
await receiver.AbandonMessageAsync(message);

// Defer - prevents normal receive, use ReceiveDeferredMessageAsync
await receiver.DeferMessageAsync(message);

// Dead Letter - moves to dead letter subqueue
await receiver.DeadLetterMessageAsync(message, "InvalidFormat", "Message body was not valid JSON");
```

### 4. Background Processing with Processor

```csharp
ServiceBusProcessor processor = client.CreateProcessor("my-queue", new ServiceBusProcessorOptions
{
    AutoCompleteMessages = false,
    MaxConcurrentCalls = 2
});

processor.ProcessMessageAsync += async (args) =>
{
    try
    {
        string body = args.Message.Body.ToString();
        Console.WriteLine($"Received: {body}");
        await args.CompleteMessageAsync(args.Message);
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Error processing: {ex.Me
