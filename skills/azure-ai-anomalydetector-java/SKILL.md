---
name: azure-ai-anomalydetector-java
description: Build anomaly detection applications with Azure AI Anomaly Detector SDK for Java. Use when implementing univariate/multivariate anomaly detection, time-series analysis, or AI-powered monitoring. 
category: AI & Agents
source: antigravity
tags: [api, ai, azure, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-ai-anomalydetector-java
---


# Azure AI Anomaly Detector SDK for Java

Build anomaly detection applications using the Azure AI Anomaly Detector SDK for Java.

## Installation

```xml
<dependency>
  <groupId>com.azure</groupId>
  <artifactId>azure-ai-anomalydetector</artifactId>
  <version>3.0.0-beta.6</version>
</dependency>
```

## Client Creation

### Sync and Async Clients

```java
import com.azure.ai.anomalydetector.AnomalyDetectorClientBuilder;
import com.azure.ai.anomalydetector.MultivariateClient;
import com.azure.ai.anomalydetector.UnivariateClient;
import com.azure.core.credential.AzureKeyCredential;

String endpoint = System.getenv("AZURE_ANOMALY_DETECTOR_ENDPOINT");
String key = System.getenv("AZURE_ANOMALY_DETECTOR_API_KEY");

// Multivariate client for multiple correlated signals
MultivariateClient multivariateClient = new AnomalyDetectorClientBuilder()
    .credential(new AzureKeyCredential(key))
    .endpoint(endpoint)
    .buildMultivariateClient();

// Univariate client for single variable analysis
UnivariateClient univariateClient = new AnomalyDetectorClientBuilder()
    .credential(new AzureKeyCredential(key))
    .endpoint(endpoint)
    .buildUnivariateClient();
```

### With DefaultAzureCredential

```java
import com.azure.identity.DefaultAzureCredentialBuilder;

MultivariateClient client = new AnomalyDetectorClientBuilder()
    .credential(new DefaultAzureCredentialBuilder().build())
    .endpoint(endpoint)
    .buildMultivariateClient();
```

## Key Concepts

### Univariate Anomaly Detection
- **Batch Detection**: Analyze entire time series at once
- **Streaming Detection**: Real-time detection on latest data point
- **Change Point Detection**: Detect trend changes in time series

### Multivariate Anomaly Detection
- Detect anomalies across 300+ correlated signals
- Uses Graph Attention Network for inter-correlations
- Three-step process: Train → Inference → Results

## Core Patterns

### Univariate Batch Detection

```java
import com.azure.ai.anomalydetector.models.*;
import java.time.OffsetDateTime;
import java.util.List;

List<TimeSeriesPoint> series = List.of(
    new TimeSeriesPoint(OffsetDateTime.parse("2023-01-01T00:00:00Z"), 1.0),
    new TimeSeriesPoint(OffsetDateTime.parse("2023-01-02T00:00:00Z"), 2.5),
    // ... more data points (minimum 12 points required)
);

UnivariateDetectionOptions options = new UnivariateDetectionOptions(series)
    .setGranularity(TimeGranularity.DAILY)
    .setSensitivity(95);

UnivariateEntireDetectionResult result = univariateClient.detectUnivariateEntireSeries(options);

// Check for anomalies
for (int i = 0; i < result.getIsAnomaly().size(); i++) {
    if (result.getIsAnomaly().get(i)) {
        System.out.printf("Anomaly detected at index %d with value %.2f%n",
            i, series.get(i).getValue());
    }
}
```

### Univariate Last Point Detection (Streaming)

```java
UnivariateLastDetectionResult lastResult = univariateClient.detectUnivariateLastPoint(options);

if (lastResult.isAnomaly()) {
    System.out.println("Latest point is an anomaly!");
    System.out.printf("Expected: %.2f, Upper: %.2f, Lower: %.2f%n",
        lastResult.getExpectedValue(),
        lastResult.getUpperMargin(),
        lastResult.getLowerMargin());
}
```

### Change Point Detection

```java
UnivariateChangePointDetectionOptions changeOptions = 
    new UnivariateChangePointDetectionOptions(series, TimeGranularity.DAILY);

UnivariateChangePointDetectionResult changeResult = 
    univariateClient.detectUnivariateChangePoint(changeOptions);

for (int i = 0; i < changeResult.getIsChangePoint().size(); i++) {
    if (changeResult.getIsChangePoint().get(i)) {
        System.out.printf("Change point at index %d with confidence %.2f%n",
            i, changeResult.getConfidenceScores().get(i));
    }
}
```

### Multivariate Model Training

```java
import com.azure.ai.anomalydetector.models.*;
import com.azure.core.util.polling.SyncPoller;

// Prepare training request with blob storage data
ModelInfo modelInfo = new ModelInfo()
    .setDataSource("https://storage.blob.core.windows.net/container/data.zip?sasToken")
    .setStartTime(OffsetDateTime.parse("2023-01-01T00:00:00Z"))
    .setEndTime(OffsetDateTime.parse("2023-06-01T00:00:00Z"))
    .setSlidingWindow(200)
    .setDisplayName("MyMultivariateModel");

// Train model (long-running operation)
AnomalyDetectionModel trainedModel = multivariateClient.trainMultivariateModel(modelInfo);

String modelId = trainedModel.getModelId();
System.out.println("Model ID: " + modelId);

// Check training status
AnomalyDetectionModel model = multivariateClient.getMultivariateModel(modelId);
System.out.println("Status: " + model.getModelInfo().getStatus());
```

### Multivariate Batch Inference

```java
MultivariateBatchDetectionOptions detectionOptions = new MultivariateBatchDetectionOptions()
    .setDataSource("https://storage.blob.core.windows.net/container/inference-data.zip?sasToken")
    .setStartTime(OffsetDateTime.parse("2023-07-01T00:00:00Z"))
    .setE
