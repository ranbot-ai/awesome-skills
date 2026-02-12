---
name: azure-eventgrid-java
description: Build event-driven applications with Azure Event Grid SDK for Java. Use when publishing events, implementing pub/sub patterns, or integrating with Azure services via events. 
category: AI & Agents
source: antigravity
tags: [api, ai, azure, rag, seo, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-eventgrid-java
---


# Azure Event Grid SDK for Java

Build event-driven applications using the Azure Event Grid SDK for Java.

## Installation

```xml
<dependency>
    <groupId>com.azure</groupId>
    <artifactId>azure-messaging-eventgrid</artifactId>
    <version>4.27.0</version>
</dependency>
```

## Client Creation

### EventGridPublisherClient

```java
import com.azure.messaging.eventgrid.EventGridPublisherClient;
import com.azure.messaging.eventgrid.EventGridPublisherClientBuilder;
import com.azure.core.credential.AzureKeyCredential;

// With API Key
EventGridPublisherClient<EventGridEvent> client = new EventGridPublisherClientBuilder()
    .endpoint("<topic-endpoint>")
    .credential(new AzureKeyCredential("<access-key>"))
    .buildEventGridEventPublisherClient();

// For CloudEvents
EventGridPublisherClient<CloudEvent> cloudClient = new EventGridPublisherClientBuilder()
    .endpoint("<topic-endpoint>")
    .credential(new AzureKeyCredential("<access-key>"))
    .buildCloudEventPublisherClient();
```

### With DefaultAzureCredential

```java
import com.azure.identity.DefaultAzureCredentialBuilder;

EventGridPublisherClient<EventGridEvent> client = new EventGridPublisherClientBuilder()
    .endpoint("<topic-endpoint>")
    .credential(new DefaultAzureCredentialBuilder().build())
    .buildEventGridEventPublisherClient();
```

### Async Client

```java
import com.azure.messaging.eventgrid.EventGridPublisherAsyncClient;

EventGridPublisherAsyncClient<EventGridEvent> asyncClient = new EventGridPublisherClientBuilder()
    .endpoint("<topic-endpoint>")
    .credential(new AzureKeyCredential("<access-key>"))
    .buildEventGridEventPublisherAsyncClient();
```

## Event Types

| Type | Description |
|------|-------------|
| `EventGridEvent` | Azure Event Grid native schema |
| `CloudEvent` | CNCF CloudEvents 1.0 specification |
| `BinaryData` | Custom schema events |

## Core Patterns

### Publish EventGridEvent

```java
import com.azure.messaging.eventgrid.EventGridEvent;
import com.azure.core.util.BinaryData;

EventGridEvent event = new EventGridEvent(
    "resource/path",           // subject
    "MyApp.Events.OrderCreated", // eventType
    BinaryData.fromObject(new OrderData("order-123", 99.99)), // data
    "1.0"                      // dataVersion
);

client.sendEvent(event);
```

### Publish Multiple Events

```java
List<EventGridEvent> events = Arrays.asList(
    new EventGridEvent("orders/1", "Order.Created", 
        BinaryData.fromObject(order1), "1.0"),
    new EventGridEvent("orders/2", "Order.Created", 
        BinaryData.fromObject(order2), "1.0")
);

client.sendEvents(events);
```

### Publish CloudEvent

```java
import com.azure.core.models.CloudEvent;
import com.azure.core.models.CloudEventDataFormat;

CloudEvent cloudEvent = new CloudEvent(
    "/myapp/orders",           // source
    "order.created",           // type
    BinaryData.fromObject(orderData), // data
    CloudEventDataFormat.JSON  // dataFormat
);
cloudEvent.setSubject("orders/12345");
cloudEvent.setId(UUID.randomUUID().toString());

cloudClient.sendEvent(cloudEvent);
```

### Publish CloudEvents Batch

```java
List<CloudEvent> cloudEvents = Arrays.asList(
    new CloudEvent("/app", "event.type1", BinaryData.fromString("data1"), CloudEventDataFormat.JSON),
    new CloudEvent("/app", "event.type2", BinaryData.fromString("data2"), CloudEventDataFormat.JSON)
);

cloudClient.sendEvents(cloudEvents);
```

### Async Publishing

```java
asyncClient.sendEvent(event)
    .subscribe(
        unused -> System.out.println("Event sent successfully"),
        error -> System.err.println("Error: " + error.getMessage())
    );

// With multiple events
asyncClient.sendEvents(events)
    .doOnSuccess(unused -> System.out.println("All events sent"))
    .doOnError(error -> System.err.println("Failed: " + error))
    .block(); // Block if needed
```

### Custom Event Data Class

```java
public class OrderData {
    private String orderId;
    private double amount;
    private String customerId;
    
    public OrderData(String orderId, double amount) {
        this.orderId = orderId;
        this.amount = amount;
    }
    
    // Getters and setters
}

// Usage
OrderData order = new OrderData("ORD-123", 150.00);
EventGridEvent event = new EventGridEvent(
    "orders/" + order.getOrderId(),
    "MyApp.Order.Created",
    BinaryData.fromObject(order),
    "1.0"
);
```

## Receiving Events

### Parse EventGridEvent

```java
import com.azure.messaging.eventgrid.EventGridEvent;

// From JSON string (e.g., webhook payload)
String jsonPayload = "[{\"id\": \"...\", ...}]";
List<EventGridEvent> events = EventGridEvent.fromString(jsonPayload);

for (EventGridEvent event : events) {
    System.out.println("Event Type: " + event.getEventType());
    System.out.println("Subject: " + event.getSubject());
    System.out.println("Event Time: " + event.getEventTime());
    
    // Get data
    BinaryData data = event.getData();
    OrderData orderData = data.toObject(OrderDa
