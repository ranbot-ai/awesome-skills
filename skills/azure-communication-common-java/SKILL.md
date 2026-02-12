---
name: azure-communication-common-java
description: Azure Communication Services common utilities for Java. Use when working with CommunicationTokenCredential, user identifiers, token refresh, or shared authentication across ACS services. 
category: AI & Agents
source: antigravity
tags: [ai, security, azure, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-communication-common-java
---


# Azure Communication Common (Java)

Shared authentication utilities and data structures for Azure Communication Services.

## Installation

```xml
<dependency>
    <groupId>com.azure</groupId>
    <artifactId>azure-communication-common</artifactId>
    <version>1.4.0</version>
</dependency>
```

## Key Concepts

| Class | Purpose |
|-------|---------|
| `CommunicationTokenCredential` | Authenticate users with ACS services |
| `CommunicationTokenRefreshOptions` | Configure automatic token refresh |
| `CommunicationUserIdentifier` | Identify ACS users |
| `PhoneNumberIdentifier` | Identify PSTN phone numbers |
| `MicrosoftTeamsUserIdentifier` | Identify Teams users |
| `UnknownIdentifier` | Generic identifier for unknown types |

## CommunicationTokenCredential

### Static Token (Short-lived Clients)

```java
import com.azure.communication.common.CommunicationTokenCredential;

// Simple static token - no refresh
String userToken = "<user-access-token>";
CommunicationTokenCredential credential = new CommunicationTokenCredential(userToken);

// Use with Chat, Calling, etc.
ChatClient chatClient = new ChatClientBuilder()
    .endpoint("https://<resource>.communication.azure.com")
    .credential(credential)
    .buildClient();
```

### Proactive Token Refresh (Long-lived Clients)

```java
import com.azure.communication.common.CommunicationTokenRefreshOptions;
import java.util.concurrent.Callable;

// Token refresher callback - called when token is about to expire
Callable<String> tokenRefresher = () -> {
    // Call your server to get a fresh token
    return fetchNewTokenFromServer();
};

// With proactive refresh
CommunicationTokenRefreshOptions refreshOptions = new CommunicationTokenRefreshOptions(tokenRefresher)
    .setRefreshProactively(true)      // Refresh before expiry
    .setInitialToken(currentToken);    // Optional initial token

CommunicationTokenCredential credential = new CommunicationTokenCredential(refreshOptions);
```

### Async Token Refresh

```java
import java.util.concurrent.CompletableFuture;

// Async token fetcher
Callable<String> asyncRefresher = () -> {
    CompletableFuture<String> future = fetchTokenAsync();
    return future.get();  // Block until token is available
};

CommunicationTokenRefreshOptions options = new CommunicationTokenRefreshOptions(asyncRefresher)
    .setRefreshProactively(true);

CommunicationTokenCredential credential = new CommunicationTokenCredential(options);
```

## Entra ID (Azure AD) Authentication

```java
import com.azure.identity.InteractiveBrowserCredentialBuilder;
import com.azure.communication.common.EntraCommunicationTokenCredentialOptions;
import java.util.Arrays;
import java.util.List;

// For Teams Phone Extensibility
InteractiveBrowserCredential entraCredential = new InteractiveBrowserCredentialBuilder()
    .clientId("<your-client-id>")
    .tenantId("<your-tenant-id>")
    .redirectUrl("<your-redirect-uri>")
    .build();

String resourceEndpoint = "https://<resource>.communication.azure.com";
List<String> scopes = Arrays.asList(
    "https://auth.msft.communication.azure.com/TeamsExtension.ManageCalls"
);

EntraCommunicationTokenCredentialOptions entraOptions = 
    new EntraCommunicationTokenCredentialOptions(entraCredential, resourceEndpoint)
        .setScopes(scopes);

CommunicationTokenCredential credential = new CommunicationTokenCredential(entraOptions);
```

## Communication Identifiers

### CommunicationUserIdentifier

```java
import com.azure.communication.common.CommunicationUserIdentifier;

// Create identifier for ACS user
CommunicationUserIdentifier user = new CommunicationUserIdentifier("8:acs:resource-id_user-id");

// Get raw ID
String rawId = user.getId();
```

### PhoneNumberIdentifier

```java
import com.azure.communication.common.PhoneNumberIdentifier;

// E.164 format phone number
PhoneNumberIdentifier phone = new PhoneNumberIdentifier("+14255551234");

String phoneNumber = phone.getPhoneNumber();  // "+14255551234"
String rawId = phone.getRawId();              // "4:+14255551234"
```

### MicrosoftTeamsUserIdentifier

```java
import com.azure.communication.common.MicrosoftTeamsUserIdentifier;

// Teams user identifier
MicrosoftTeamsUserIdentifier teamsUser = new MicrosoftTeamsUserIdentifier("<teams-user-id>")
    .setCloudEnvironment(CommunicationCloudEnvironment.PUBLIC);

// For anonymous Teams users
MicrosoftTeamsUserIdentifier anonymousTeamsUser = new MicrosoftTeamsUserIdentifier("<teams-user-id>")
    .setAnonymous(true);
```

### UnknownIdentifier

```java
import com.azure.communication.common.UnknownIdentifier;

// For identifiers of unknown type
UnknownIdentifier unknown = new UnknownIdentifier("some-raw-id");
```

## Identifier Parsing

```java
import com.azure.communication.common.CommunicationIdentifier;
import com.azure.communication.common.CommunicationIdentifierModel;

// Parse raw ID to appropriate type
public CommunicationIdentifier parseIdentifier(String rawId) {
    if (rawId.startsWith("8:acs:")) {
 
