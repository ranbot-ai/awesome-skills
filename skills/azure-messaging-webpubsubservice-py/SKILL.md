---
name: azure-messaging-webpubsubservice-py
description: Azure Web PubSub Service SDK for Python. Use for real-time messaging, WebSocket connections, and pub/sub patterns. 
category: AI & Agents
source: antigravity
tags: [python, ai, workflow, security, azure, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-messaging-webpubsubservice-py
---


# Azure Web PubSub Service SDK for Python

Real-time messaging with WebSocket connections at scale.

## Installation

```bash
# Service SDK (server-side)
pip install azure-messaging-webpubsubservice

# Client SDK (for Python WebSocket clients)
pip install azure-messaging-webpubsubclient
```

## Environment Variables

```bash
AZURE_WEBPUBSUB_CONNECTION_STRING=Endpoint=https://<name>.webpubsub.azure.com;AccessKey=...
AZURE_WEBPUBSUB_HUB=my-hub
```

## Service Client (Server-Side)

### Authentication

```python
import os
from azure.messaging.webpubsubservice import WebPubSubServiceClient

# Connection string
client = WebPubSubServiceClient.from_connection_string(
    connection_string=os.environ["AZURE_WEBPUBSUB_CONNECTION_STRING"],
    hub="my-hub"
)

# Entra ID
from azure.identity import DefaultAzureCredential

client = WebPubSubServiceClient(
    endpoint="https://<name>.webpubsub.azure.com",
    hub="my-hub",
    credential=DefaultAzureCredential()
)
```

### Generate Client Access Token

```python
# Token for anonymous user
token = client.get_client_access_token()
# Treat token["url"] as a bearer secret; return it only to the authenticated intended client.

# Token with user ID
token = client.get_client_access_token(
    user_id="user123",
    roles=["webpubsub.sendToGroup.my-group", "webpubsub.joinLeaveGroup.my-group"]
)

# Token with groups
token = client.get_client_access_token(
    user_id="user123",
    groups=["group1", "group2"]
)
```

### Send to All Clients

```python
# Send text
client.send_to_all(message="Hello everyone!", content_type="text/plain")

# Send JSON
client.send_to_all(
    message={"type": "notification", "data": "Hello"},
    content_type="application/json"
)
```

### Send to User

```python
client.send_to_user(
    user_id="user123",
    message="Hello user!",
    content_type="text/plain"
)
```

### Send to Group

```python
client.send_to_group(
    group="my-group",
    message="Hello group!",
    content_type="text/plain"
)
```

### Send to Connection

```python
client.send_to_connection(
    connection_id="abc123",
    message="Hello connection!",
    content_type="text/plain"
)
```

### Group Management

```python
# Add user to group
client.add_user_to_group(group="my-group", user_id="user123")

# Remove user from group
client.remove_user_from_group(group="my-group", user_id="user123")

# Add connection to group
client.add_connection_to_group(group="my-group", connection_id="abc123")

# Remove connection from group
client.remove_connection_from_group(group="my-group", connection_id="abc123")
```

### Connection Management

```python
# Check if connection exists
exists = client.connection_exists(connection_id="abc123")

# Check if user has connections
exists = client.user_exists(user_id="user123")

# Check if group has connections
exists = client.group_exists(group="my-group")

# Close connection
client.close_connection(connection_id="abc123", reason="Session ended")

# Close all connections for user
client.close_all_connections(user_id="user123")
```

### Grant/Revoke Permissions

```python
from azure.messaging.webpubsubservice import WebPubSubServiceClient

# Grant permission
client.grant_permission(
    permission="joinLeaveGroup",
    connection_id="abc123",
    target_name="my-group"
)

# Revoke permission
client.revoke_permission(
    permission="joinLeaveGroup",
    connection_id="abc123",
    target_name="my-group"
)

# Check permission
has_permission = client.check_permission(
    permission="joinLeaveGroup",
    connection_id="abc123",
    target_name="my-group"
)
```

## Client SDK (Python WebSocket Client)

```python
from azure.messaging.webpubsubclient import WebPubSubClient
from azure.messaging.webpubsubclient.models import CallbackType, WebPubSubDataType

with WebPubSubClient(token["url"]) as ws_client:
    ws_client.subscribe(CallbackType.CONNECTED, lambda e: print("Connected"))
    ws_client.subscribe(CallbackType.GROUP_MESSAGE, lambda e: print("Group message received"))
    ws_client.join_group("my-group")
    ws_client.send_to_group("my-group", "Hello from Python!", WebPubSubDataType.TEXT)
```

Authorize token issuance on the server; derive user IDs and allowed groups from the authenticated session, never untrusted request fields. Use a short explicit expiration supported by the pinned SDK, avoid logging access URLs or message bodies, and close service clients and credentials when done. These sends/group changes affect live clients; use a test hub for examples.


## Async Service Client

```python
from azure.messaging.webpubsubservice.aio import WebPubSubServiceClient
from azure.identity.aio import DefaultAzureCredential

async def broadcast():
    credential = DefaultAzureCredential()
    client = WebPubSubServiceClient(
        endpoint="https://<name>.webpubsub.azure.com",
        hub="my-hub",
        credential=credential
    )
    
    await client.send_to_all("Hello async!", content_type="text/plain")
    
    await client.close()
    await credenti
