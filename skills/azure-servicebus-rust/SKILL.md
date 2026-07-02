---
name: azure-servicebus-rust
description: Azure Service Bus library for Rust. Send and receive messages using queues, topics, and subscriptions. Triggers: "service bus rust", "ServiceBusClient rust", "send message servicebus rust", "receive m
category: Development & Code Tools
source: antigravity
tags: [api, ai, workflow, security, azure, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-servicebus-rust
---


# Azure Service Bus library for Rust
## When to Use

Use this skill when you need azure Service Bus library for Rust. Send and receive messages using queues, topics, and subscriptions. Triggers: "service bus rust", "ServiceBusClient rust", "send message servicebus rust", "receive message servicebus rust", "queue rust messaging", "topic subscription rust".


Client library for Azure Service Bus — enterprise message broker with queues and publish-subscribe topics.

> **⚠️ WARNING:** This crate is in early development and **SHOULD NOT** be used in production. APIs may change without notice.

Use this skill when:

- An app needs to send or receive messages via Azure Service Bus from Rust
- You need queue-based messaging with competing consumers
- You need publish-subscribe messaging with topics and subscriptions
- You need reliable message delivery with completion semantics

> **IMPORTANT:** Only use the official `azure_messaging_servicebus` crate published by the [azure-sdk](https://crates.io/users/azure-sdk) crates.io user. Do NOT use unofficial or community crates. Official crates use underscores in names and none have version 0.21.0.

## Installation

```sh
cargo add azure_messaging_servicebus azure_identity tokio
```

> If your code uses `azure_core` types directly, add `azure_core` to `Cargo.toml`. If you only use `azure_messaging_servicebus` re-exports, direct `azure_core` dependency is optional.

## Environment Variables

```bash
SERVICEBUS_NAMESPACE=<namespace>.servicebus.windows.net # Required — fully qualified namespace
```

## Key Concepts

| Concept          | Description                                                     |
| ---------------- | --------------------------------------------------------------- |
| **Namespace**    | Container for all messaging components                          |
| **Queue**        | Point-to-point messaging with competing consumers               |
| **Topic**        | Publish-subscribe messaging — one sender, many subscribers      |
| **Subscription** | Receives messages from a topic                                  |
| **Message**      | Package of data and metadata, with completion/abandon semantics |

## Authentication

```rust
use azure_identity::DeveloperToolsCredential;
use azure_messaging_servicebus::ServiceBusClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Local dev: DeveloperToolsCredential. Production: use ManagedIdentityCredential.
    let credential = DeveloperToolsCredential::new(None)?;
    let client = ServiceBusClient::builder()
        .open("your_namespace.servicebus.windows.net", credential.clone())
        .await?;
    Ok(())
}
```

## Core Workflow

### Send a Message to a Queue

```rust
use azure_identity::DeveloperToolsCredential;
use azure_messaging_servicebus::{ServiceBusClient, Message};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let credential = DeveloperToolsCredential::new(None)?;
    let client = ServiceBusClient::builder()
        .open("your_namespace.servicebus.windows.net", credential.clone())
        .await?;
    let sender = client.create_sender("my_queue", None).await?;

    let message = Message::from("Hello, Service Bus!");
    sender.send_message(message, None).await?;
    Ok(())
}
```

### Receive Messages from a Queue

```rust
use azure_identity::DeveloperToolsCredential;
use azure_messaging_servicebus::ServiceBusClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let credential = DeveloperToolsCredential::new(None)?;
    let client = ServiceBusClient::builder()
        .open("your_namespace.servicebus.windows.net", credential.clone())
        .await?;
    let receiver = client.create_receiver("my_queue", None).await?;

    let messages = receiver.receive_messages(5, None).await?;
    for message in messages {
        println!("Received: {}", message.body_as_string()?);
        receiver.complete_message(&message, None).await?;
    }
    Ok(())
}
```

### Send a Message to a Topic

```rust
let sender = client.create_sender("my_topic", None).await?;
let message = Message::from("Hello, Topic subscribers!");
sender.send_message(message, None).await?;
```

### Receive Messages from a Subscription

```rust
let receiver = client
    .create_receiver_for_subscription("my_topic", "my_subscription", None)
    .await?;

let messages = receiver.receive_messages(5, None).await?;
for message in messages {
    println!("Received: {}", message.body_as_string()?);
    receiver.complete_message(&message, None).await?;
}
```

## Message Settlement

| Action     | Purpose                                            |
| ---------- | -------------------------------------------------- |
| `complete` | Remove message from queue — processing succeeded   |
| `abandon`  | Release lock — message becomes available for retry |

Always complete messages after successful processing to prevent redelivery.

## RBAC Roles

For Entra ID auth, as
