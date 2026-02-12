---
name: azure-communication-chat-java
description: Build real-time chat applications with Azure Communication Services Chat Java SDK. Use when implementing chat threads, messaging, participants, read receipts, typing notifications, or real-time chat f
category: AI & Agents
source: antigravity
tags: [azure]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-communication-chat-java
---


# Azure Communication Chat (Java)

Build real-time chat applications with thread management, messaging, participants, and read receipts.

## Installation

```xml
<dependency>
    <groupId>com.azure</groupId>
    <artifactId>azure-communication-chat</artifactId>
    <version>1.6.0</version>
</dependency>
```

## Client Creation

```java
import com.azure.communication.chat.ChatClient;
import com.azure.communication.chat.ChatClientBuilder;
import com.azure.communication.chat.ChatThreadClient;
import com.azure.communication.common.CommunicationTokenCredential;

// ChatClient requires a CommunicationTokenCredential (user access token)
String endpoint = "https://<resource>.communication.azure.com";
String userAccessToken = "<user-access-token>";

CommunicationTokenCredential credential = new CommunicationTokenCredential(userAccessToken);

ChatClient chatClient = new ChatClientBuilder()
    .endpoint(endpoint)
    .credential(credential)
    .buildClient();

// Async client
ChatAsyncClient chatAsyncClient = new ChatClientBuilder()
    .endpoint(endpoint)
    .credential(credential)
    .buildAsyncClient();
```

## Key Concepts

| Class | Purpose |
|-------|---------|
| `ChatClient` | Create/delete chat threads, get thread clients |
| `ChatThreadClient` | Operations within a thread (messages, participants, receipts) |
| `ChatParticipant` | User in a chat thread with display name |
| `ChatMessage` | Message content, type, sender info, timestamps |
| `ChatMessageReadReceipt` | Read receipt tracking per participant |

## Create Chat Thread

```java
import com.azure.communication.chat.models.*;
import com.azure.communication.common.CommunicationUserIdentifier;
import java.util.ArrayList;
import java.util.List;

// Define participants
List<ChatParticipant> participants = new ArrayList<>();

ChatParticipant participant1 = new ChatParticipant()
    .setCommunicationIdentifier(new CommunicationUserIdentifier("<user-id-1>"))
    .setDisplayName("Alice");

ChatParticipant participant2 = new ChatParticipant()
    .setCommunicationIdentifier(new CommunicationUserIdentifier("<user-id-2>"))
    .setDisplayName("Bob");

participants.add(participant1);
participants.add(participant2);

// Create thread
CreateChatThreadOptions options = new CreateChatThreadOptions("Project Discussion")
    .setParticipants(participants);

CreateChatThreadResult result = chatClient.createChatThread(options);
String threadId = result.getChatThread().getId();

// Get thread client for operations
ChatThreadClient threadClient = chatClient.getChatThreadClient(threadId);
```

## Send Messages

```java
// Send text message
SendChatMessageOptions messageOptions = new SendChatMessageOptions()
    .setContent("Hello, team!")
    .setSenderDisplayName("Alice")
    .setType(ChatMessageType.TEXT);

SendChatMessageResult sendResult = threadClient.sendMessage(messageOptions);
String messageId = sendResult.getId();

// Send HTML message
SendChatMessageOptions htmlOptions = new SendChatMessageOptions()
    .setContent("<strong>Important:</strong> Meeting at 3pm")
    .setType(ChatMessageType.HTML);

threadClient.sendMessage(htmlOptions);
```

## Get Messages

```java
import com.azure.core.util.paging.PagedIterable;

// List all messages
PagedIterable<ChatMessage> messages = threadClient.listMessages();

for (ChatMessage message : messages) {
    System.out.println("ID: " + message.getId());
    System.out.println("Type: " + message.getType());
    System.out.println("Content: " + message.getContent().getMessage());
    System.out.println("Sender: " + message.getSenderDisplayName());
    System.out.println("Created: " + message.getCreatedOn());
    
    // Check if edited or deleted
    if (message.getEditedOn() != null) {
        System.out.println("Edited: " + message.getEditedOn());
    }
    if (message.getDeletedOn() != null) {
        System.out.println("Deleted: " + message.getDeletedOn());
    }
}

// Get specific message
ChatMessage message = threadClient.getMessage(messageId);
```

## Update and Delete Messages

```java
// Update message
UpdateChatMessageOptions updateOptions = new UpdateChatMessageOptions()
    .setContent("Updated message content");

threadClient.updateMessage(messageId, updateOptions);

// Delete message
threadClient.deleteMessage(messageId);
```

## Manage Participants

```java
// List participants
PagedIterable<ChatParticipant> participants = threadClient.listParticipants();

for (ChatParticipant participant : participants) {
    CommunicationUserIdentifier user = 
        (CommunicationUserIdentifier) participant.getCommunicationIdentifier();
    System.out.println("User: " + user.getId());
    System.out.println("Display Name: " + participant.getDisplayName());
}

// Add participants
List<ChatParticipant> newParticipants = new ArrayList<>();
newParticipants.add(new ChatParticipant()
    .setCommunicationIdentifier(new CommunicationUserIdentifier("<new-user-id>"))
    .setDisplayName("Charlie")
    .setShareHistoryTime(OffsetDateTime
