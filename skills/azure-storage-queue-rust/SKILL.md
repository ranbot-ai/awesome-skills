---
name: azure-storage-queue-rust
description: Azure Queue Storage library for Rust. Send, receive, and manage queue messages. Triggers: "queue storage rust", "QueueClient rust", "send message rust", "receive messages rust", "QueueServiceClient ru
category: Development & Code Tools
source: antigravity
tags: [api, ai, workflow, security, azure, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-storage-queue-rust
---


# Azure Queue Storage library for Rust
## When to Use

Use this skill when you need azure Queue Storage library for Rust. Send, receive, and manage queue messages. Triggers: "queue storage rust", "QueueClient rust", "send message rust", "receive messages rust", "QueueServiceClient rust", "queue rust".


Client library for Azure Queue Storage — send, receive, and manage queue messages.

Use this skill when:

- An app needs to send or receive messages from Azure Queue Storage in Rust
- You need to create or manage queues
- You need to peek, receive, or delete queue messages
- You need RBAC-based auth for queue operations

> **IMPORTANT:** Only use the official `azure_storage_queue` crate published by the [azure-sdk](https://crates.io/users/azure-sdk) crates.io user. Do NOT use unofficial or community crates. Official crates use underscores in names and none have version 0.21.0.

## Installation

```sh
cargo add azure_storage_queue azure_identity azure_core tokio
```

> If your code uses `azure_core` types directly, add `azure_core` to `Cargo.toml`. If you only use `azure_storage_queue` re-exports, direct `azure_core` dependency is optional.

## Environment Variables

```bash
AZURE_STORAGE_QUEUE_ENDPOINT=https://<account>.queue.core.windows.net/ # Required for all operations
```

## Authentication

```rust
use azure_core::http::Url;
use azure_identity::DeveloperToolsCredential;
use azure_storage_queue::QueueServiceClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Local dev: DeveloperToolsCredential. Production: use ManagedIdentityCredential.
    let credential = DeveloperToolsCredential::new(None)?;
    let service_url = Url::parse("https://<storage_account_name>.queue.core.windows.net/")?;
    let service_client = QueueServiceClient::new(service_url, Some(credential), None)?;

    // Derive a queue client by name.
    let queue_client = service_client.queue_client("<queue_name>")?;
    Ok(())
}
```

## Client Types

| Client               | Purpose                               | Access                                   |
| -------------------- | ------------------------------------- | ---------------------------------------- |
| `QueueServiceClient` | Account-level operations, list queues | `QueueServiceClient::new()`              |
| `QueueClient`        | Queue operations, send/receive/delete | `service_client.queue_client("<name>")?` |

## Core Workflow

### Send a Message

```rust
use azure_core::http::Url;
use azure_identity::DeveloperToolsCredential;
use azure_storage_queue::{models::QueueMessage, QueueServiceClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let credential = DeveloperToolsCredential::new(None)?;
    let service_url = Url::parse("https://<storage_account_name>.queue.core.windows.net/")?;
    let service_client = QueueServiceClient::new(service_url, Some(credential), None)?;
    let queue_client = service_client.queue_client("<queue_name>")?;

    let message = QueueMessage {
        message_text: Some("hello world".to_string()),
    };
    queue_client.send_message(message.try_into()?, None).await?;
    Ok(())
}
```

### Receive Messages

```rust
use azure_core::http::Url;
use azure_identity::DeveloperToolsCredential;
use azure_storage_queue::QueueServiceClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let credential = DeveloperToolsCredential::new(None)?;
    let service_url = Url::parse("https://<storage_account_name>.queue.core.windows.net/")?;
    let service_client = QueueServiceClient::new(service_url, Some(credential), None)?;
    let queue_client = service_client.queue_client("<queue_name>")?;

    let response = queue_client.receive_messages(None).await?;
    let messages = response.into_model()?;
    for msg in messages.items.unwrap_or_default() {
        println!("{}", msg.message_text.as_deref().unwrap_or("<empty>"));
    }
    Ok(())
}
```

### Delete a Message

After receiving a message, delete it using the message ID and pop receipt:

```rust
let response = queue_client.receive_messages(None).await?;
let messages = response.into_model()?;
for msg in messages.items.unwrap_or_default() {
    if let (Some(id), Some(pop_receipt)) = (&msg.message_id, &msg.pop_receipt) {
        queue_client.delete_message(id, pop_receipt, None).await?;
    }
}
```

### Peek Messages

Peek at messages without removing them from the queue:

```rust
let response = queue_client.peek_messages(None).await?;
let messages = response.into_model()?;
for msg in messages.items.unwrap_or_default() {
    println!("Peeked: {}", msg.message_text.as_deref().unwrap_or("<empty>"));
}
```

## RBAC Roles

For Entra ID auth, assign one of these roles to the identity:

| Role                                   | Access                 |
| -------------------------------------- | ---------------------- |
| `Storage Queue Data Reader`            | Read and peek messages |
| `Storage Queue Data Contrib
