---
name: azure-monitor-opentelemetry-exporter-java
description: Azure Monitor OpenTelemetry Exporter for Java. Export OpenTelemetry traces, metrics, and logs to Azure Monitor/Application Insights. Triggers: "AzureMonitorExporter java", "opentelemetry azure java", 
category: AI & Agents
source: antigravity
tags: [api, ai, azure, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-monitor-opentelemetry-exporter-java
---


# Azure Monitor OpenTelemetry Exporter for Java

> **⚠️ DEPRECATION NOTICE**: This package is deprecated. Migrate to `azure-monitor-opentelemetry-autoconfigure`.
>
> See [Migration Guide](https://github.com/Azure/azure-sdk-for-java/blob/main/sdk/monitor/azure-monitor-opentelemetry-exporter/MIGRATION.md) for detailed instructions.

Export OpenTelemetry telemetry data to Azure Monitor / Application Insights.

## Installation (Deprecated)

```xml
<dependency>
    <groupId>com.azure</groupId>
    <artifactId>azure-monitor-opentelemetry-exporter</artifactId>
    <version>1.0.0-beta.x</version>
</dependency>
```

## Recommended: Use Autoconfigure Instead

```xml
<dependency>
    <groupId>com.azure</groupId>
    <artifactId>azure-monitor-opentelemetry-autoconfigure</artifactId>
    <version>LATEST</version>
</dependency>
```

## Environment Variables

```bash
APPLICATIONINSIGHTS_CONNECTION_STRING=InstrumentationKey=xxx;IngestionEndpoint=https://xxx.in.applicationinsights.azure.com/
```

## Basic Setup with Autoconfigure (Recommended)

### Using Environment Variable

```java
import io.opentelemetry.sdk.autoconfigure.AutoConfiguredOpenTelemetrySdk;
import io.opentelemetry.sdk.autoconfigure.AutoConfiguredOpenTelemetrySdkBuilder;
import io.opentelemetry.api.OpenTelemetry;
import com.azure.monitor.opentelemetry.exporter.AzureMonitorExporter;

// Connection string from APPLICATIONINSIGHTS_CONNECTION_STRING env var
AutoConfiguredOpenTelemetrySdkBuilder sdkBuilder = AutoConfiguredOpenTelemetrySdk.builder();
AzureMonitorExporter.customize(sdkBuilder);
OpenTelemetry openTelemetry = sdkBuilder.build().getOpenTelemetrySdk();
```

### With Explicit Connection String

```java
AutoConfiguredOpenTelemetrySdkBuilder sdkBuilder = AutoConfiguredOpenTelemetrySdk.builder();
AzureMonitorExporter.customize(sdkBuilder, "{connection-string}");
OpenTelemetry openTelemetry = sdkBuilder.build().getOpenTelemetrySdk();
```

## Creating Spans

```java
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.context.Scope;

// Get tracer
Tracer tracer = openTelemetry.getTracer("com.example.myapp");

// Create span
Span span = tracer.spanBuilder("myOperation").startSpan();

try (Scope scope = span.makeCurrent()) {
    // Your application logic
    doWork();
} catch (Throwable t) {
    span.recordException(t);
    throw t;
} finally {
    span.end();
}
```

## Adding Span Attributes

```java
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;

Span span = tracer.spanBuilder("processOrder")
    .setAttribute("order.id", "12345")
    .setAttribute("customer.tier", "premium")
    .startSpan();

try (Scope scope = span.makeCurrent()) {
    // Add attributes during execution
    span.setAttribute("items.count", 3);
    span.setAttribute("total.amount", 99.99);
    
    processOrder();
} finally {
    span.end();
}
```

## Custom Span Processor

```java
import io.opentelemetry.sdk.trace.SpanProcessor;
import io.opentelemetry.sdk.trace.ReadWriteSpan;
import io.opentelemetry.sdk.trace.ReadableSpan;
import io.opentelemetry.context.Context;

private static final AttributeKey<String> CUSTOM_ATTR = AttributeKey.stringKey("custom.attribute");

SpanProcessor customProcessor = new SpanProcessor() {
    @Override
    public void onStart(Context context, ReadWriteSpan span) {
        // Add custom attribute to every span
        span.setAttribute(CUSTOM_ATTR, "customValue");
    }

    @Override
    public boolean isStartRequired() {
        return true;
    }

    @Override
    public void onEnd(ReadableSpan span) {
        // Post-processing if needed
    }

    @Override
    public boolean isEndRequired() {
        return false;
    }
};

// Register processor
AutoConfiguredOpenTelemetrySdkBuilder sdkBuilder = AutoConfiguredOpenTelemetrySdk.builder();
AzureMonitorExporter.customize(sdkBuilder);

sdkBuilder.addTracerProviderCustomizer(
    (sdkTracerProviderBuilder, configProperties) -> 
        sdkTracerProviderBuilder.addSpanProcessor(customProcessor)
);

OpenTelemetry openTelemetry = sdkBuilder.build().getOpenTelemetrySdk();
```

## Nested Spans

```java
public void parentOperation() {
    Span parentSpan = tracer.spanBuilder("parentOperation").startSpan();
    try (Scope scope = parentSpan.makeCurrent()) {
        childOperation();
    } finally {
        parentSpan.end();
    }
}

public void childOperation() {
    // Automatically links to parent via Context
    Span childSpan = tracer.spanBuilder("childOperation").startSpan();
    try (Scope scope = childSpan.makeCurrent()) {
        // Child work
    } finally {
        childSpan.end();
    }
}
```

## Recording Exceptions

```java
Span span = tracer.spanBuilder("riskyOperation").startSpan();
try (Scope scope = span.makeCurrent()) {
    performRiskyWork();
} catch (Exception e) {
    span.recordException(e);
    span.setStatus(StatusCode.ERROR, e.getMessage());
    throw e;
} finally {
    span.end();
}
```

## 
