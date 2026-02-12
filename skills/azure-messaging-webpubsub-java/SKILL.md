---
name: azure-messaging-webpubsub-java
description: Build real-time web applications with Azure Web PubSub SDK for Java. Use when implementing WebSocket-based messaging, live updates, chat applications, or server-to-client push notifications. 
category: Development & Code Tools
source: antigravity
tags: [ai, security, azure]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-messaging-webpubsub-java
---


# Azure Web PubSub SDK for Java

Build real-time web applications using the Azure Web PubSub SDK for Java.

## Installation

```xml
<dependency>
    <groupId>com.azure</groupId>
    <artifactId>azure-messaging-webpubsub</artifactId>
    <version>1.5.0</version>
</dependency>
```

## Client Creation

### With Connection String

```java
import com.azure.messaging.webpubsub.WebPubSubServiceClient;
import com.azure.messaging.webpubsub.WebPubSubServiceClientBuilder;

WebPubSubServiceClient client = new WebPubSubServiceClientBuilder()
    .connectionString("<connection-string>")
    .hub("chat")
    .buildClient();
```

### With Access Key

```java
import com.azure.core.credential.AzureKeyCredential;

WebPubSubServiceClient client = new WebPubSubServiceClientBuilder()
    .credential(new AzureKeyCredential("<access-key>"))
    .endpoint("<endpoint>")
    .hub("chat")
    .buildClient();
```

### With DefaultAzureCredential

```java
import com.azure.identity.DefaultAzureCredentialBuilder;

WebPubSubServiceClient client = new WebPubSubServiceClientBuilder()
    .credential(new DefaultAzureCredentialBuilder().build())
    .endpoint("<endpoint>")
    .hub("chat")
    .buildClient();
```

### Async Client

```java
import com.azure.messaging.webpubsub.WebPubSubServiceAsyncClient;

WebPubSubServiceAsyncClient asyncClient = new WebPubSubServiceClientBuilder()
    .connectionString("<connection-string>")
    .hub("chat")
    .buildAsyncClient();
```

## Key Concepts

- **Hub**: Logical isolation unit for connections
- **Group**: Subset of connections within a hub
- **Connection**: Individual WebSocket client connection
- **User**: Entity that can have multiple connections

## Core Patterns

### Send to All Connections

```java
import com.azure.messaging.webpubsub.models.WebPubSubContentType;

// Send text message
client.sendToAll("Hello everyone!", WebPubSubContentType.TEXT_PLAIN);

// Send JSON
String jsonMessage = "{\"type\": \"notification\", \"message\": \"New update!\"}";
client.sendToAll(jsonMessage, WebPubSubContentType.APPLICATION_JSON);
```

### Send to All with Filter

```java
import com.azure.core.http.rest.RequestOptions;
import com.azure.core.util.BinaryData;

BinaryData message = BinaryData.fromString("Hello filtered users!");

// Filter by userId
client.sendToAllWithResponse(
    message,
    WebPubSubContentType.TEXT_PLAIN,
    message.getLength(),
    new RequestOptions().addQueryParam("filter", "userId ne 'user1'"));

// Filter by groups
client.sendToAllWithResponse(
    message,
    WebPubSubContentType.TEXT_PLAIN,
    message.getLength(),
    new RequestOptions().addQueryParam("filter", "'GroupA' in groups and not('GroupB' in groups)"));
```

### Send to Group

```java
// Send to all connections in a group
client.sendToGroup("java-developers", "Hello Java devs!", WebPubSubContentType.TEXT_PLAIN);

// Send JSON to group
String json = "{\"event\": \"update\", \"data\": {\"version\": \"2.0\"}}";
client.sendToGroup("subscribers", json, WebPubSubContentType.APPLICATION_JSON);
```

### Send to Specific Connection

```java
// Send to a specific connection by ID
client.sendToConnection("connectionId123", "Private message", WebPubSubContentType.TEXT_PLAIN);
```

### Send to User

```java
// Send to all connections for a specific user
client.sendToUser("andy", "Hello Andy!", WebPubSubContentType.TEXT_PLAIN);
```

### Manage Groups

```java
// Add connection to group
client.addConnectionToGroup("premium-users", "connectionId123");

// Remove connection from group
client.removeConnectionFromGroup("premium-users", "connectionId123");

// Add user to group (all their connections)
client.addUserToGroup("admin-group", "userId456");

// Remove user from group
client.removeUserFromGroup("admin-group", "userId456");

// Check if user is in group
boolean exists = client.userExistsInGroup("admin-group", "userId456");
```

### Manage Connections

```java
// Check if connection exists
boolean connected = client.connectionExists("connectionId123");

// Close a connection
client.closeConnection("connectionId123");

// Close with reason
client.closeConnection("connectionId123", "Session expired");

// Check if user exists (has any connections)
boolean userOnline = client.userExists("userId456");

// Close all connections for a user
client.closeUserConnections("userId456");

// Close all connections in a group
client.closeGroupConnections("inactive-group");
```

### Generate Client Access Token

```java
import com.azure.messaging.webpubsub.models.GetClientAccessTokenOptions;
import com.azure.messaging.webpubsub.models.WebPubSubClientAccessToken;

// Basic token
WebPubSubClientAccessToken token = client.getClientAccessToken(
    new GetClientAccessTokenOptions());
System.out.println("URL: " + token.getUrl());

// With user ID
WebPubSubClientAccessToken userToken = client.getClientAccessToken(
    new GetClientAccessTokenOptions().setUserId("user123"));

// With roles (permissions)
WebPubSubClientAccessToken roleToken = client.ge
