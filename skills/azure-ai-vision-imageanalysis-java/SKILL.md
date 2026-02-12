---
name: azure-ai-vision-imageanalysis-java
description: Build image analysis applications with Azure AI Vision SDK for Java. Use when implementing image captioning, OCR text extraction, object detection, tagging, or smart cropping. 
category: Document Processing
source: antigravity
tags: [api, ai, document, image, azure, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-ai-vision-imageanalysis-java
---


# Azure AI Vision Image Analysis SDK for Java

Build image analysis applications using the Azure AI Vision Image Analysis SDK for Java.

## Installation

```xml
<dependency>
    <groupId>com.azure</groupId>
    <artifactId>azure-ai-vision-imageanalysis</artifactId>
    <version>1.1.0-beta.1</version>
</dependency>
```

## Client Creation

### With API Key

```java
import com.azure.ai.vision.imageanalysis.ImageAnalysisClient;
import com.azure.ai.vision.imageanalysis.ImageAnalysisClientBuilder;
import com.azure.core.credential.KeyCredential;

String endpoint = System.getenv("VISION_ENDPOINT");
String key = System.getenv("VISION_KEY");

ImageAnalysisClient client = new ImageAnalysisClientBuilder()
    .endpoint(endpoint)
    .credential(new KeyCredential(key))
    .buildClient();
```

### Async Client

```java
import com.azure.ai.vision.imageanalysis.ImageAnalysisAsyncClient;

ImageAnalysisAsyncClient asyncClient = new ImageAnalysisClientBuilder()
    .endpoint(endpoint)
    .credential(new KeyCredential(key))
    .buildAsyncClient();
```

### With DefaultAzureCredential

```java
import com.azure.identity.DefaultAzureCredentialBuilder;

ImageAnalysisClient client = new ImageAnalysisClientBuilder()
    .endpoint(endpoint)
    .credential(new DefaultAzureCredentialBuilder().build())
    .buildClient();
```

## Visual Features

| Feature | Description |
|---------|-------------|
| `CAPTION` | Generate human-readable image description |
| `DENSE_CAPTIONS` | Captions for up to 10 regions |
| `READ` | OCR - Extract text from images |
| `TAGS` | Content tags for objects, scenes, actions |
| `OBJECTS` | Detect objects with bounding boxes |
| `SMART_CROPS` | Smart thumbnail regions |
| `PEOPLE` | Detect people with locations |

## Core Patterns

### Generate Caption

```java
import com.azure.ai.vision.imageanalysis.models.*;
import com.azure.core.util.BinaryData;
import java.io.File;
import java.util.Arrays;

// From file
BinaryData imageData = BinaryData.fromFile(new File("image.jpg").toPath());

ImageAnalysisResult result = client.analyze(
    imageData,
    Arrays.asList(VisualFeatures.CAPTION),
    new ImageAnalysisOptions().setGenderNeutralCaption(true));

System.out.printf("Caption: \"%s\" (confidence: %.4f)%n",
    result.getCaption().getText(),
    result.getCaption().getConfidence());
```

### Generate Caption from URL

```java
ImageAnalysisResult result = client.analyzeFromUrl(
    "https://example.com/image.jpg",
    Arrays.asList(VisualFeatures.CAPTION),
    new ImageAnalysisOptions().setGenderNeutralCaption(true));

System.out.printf("Caption: \"%s\"%n", result.getCaption().getText());
```

### Extract Text (OCR)

```java
ImageAnalysisResult result = client.analyze(
    BinaryData.fromFile(new File("document.jpg").toPath()),
    Arrays.asList(VisualFeatures.READ),
    null);

for (DetectedTextBlock block : result.getRead().getBlocks()) {
    for (DetectedTextLine line : block.getLines()) {
        System.out.printf("Line: '%s'%n", line.getText());
        System.out.printf("  Bounding polygon: %s%n", line.getBoundingPolygon());
        
        for (DetectedTextWord word : line.getWords()) {
            System.out.printf("  Word: '%s' (confidence: %.4f)%n",
                word.getText(),
                word.getConfidence());
        }
    }
}
```

### Detect Objects

```java
ImageAnalysisResult result = client.analyzeFromUrl(
    imageUrl,
    Arrays.asList(VisualFeatures.OBJECTS),
    null);

for (DetectedObject obj : result.getObjects()) {
    System.out.printf("Object: %s (confidence: %.4f)%n",
        obj.getTags().get(0).getName(),
        obj.getTags().get(0).getConfidence());
    
    ImageBoundingBox box = obj.getBoundingBox();
    System.out.printf("  Location: x=%d, y=%d, w=%d, h=%d%n",
        box.getX(), box.getY(), box.getWidth(), box.getHeight());
}
```

### Get Tags

```java
ImageAnalysisResult result = client.analyzeFromUrl(
    imageUrl,
    Arrays.asList(VisualFeatures.TAGS),
    null);

for (DetectedTag tag : result.getTags()) {
    System.out.printf("Tag: %s (confidence: %.4f)%n",
        tag.getName(),
        tag.getConfidence());
}
```

### Detect People

```java
ImageAnalysisResult result = client.analyzeFromUrl(
    imageUrl,
    Arrays.asList(VisualFeatures.PEOPLE),
    null);

for (DetectedPerson person : result.getPeople()) {
    ImageBoundingBox box = person.getBoundingBox();
    System.out.printf("Person at x=%d, y=%d (confidence: %.4f)%n",
        box.getX(), box.getY(), person.getConfidence());
}
```

### Smart Cropping

```java
ImageAnalysisResult result = client.analyzeFromUrl(
    imageUrl,
    Arrays.asList(VisualFeatures.SMART_CROPS),
    new ImageAnalysisOptions().setSmartCropsAspectRatios(Arrays.asList(1.0, 1.5)));

for (CropRegion crop : result.getSmartCrops()) {
    System.out.printf("Crop region: aspect=%.2f, x=%d, y=%d, w=%d, h=%d%n",
        crop.getAspectRatio(),
        crop.getBoundingBox().getX(),
        crop.getBoundingBox().getY(),
        crop.getBound
