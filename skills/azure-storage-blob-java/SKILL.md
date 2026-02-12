---
name: azure-storage-blob-java
description: Build blob storage applications with Azure Storage Blob SDK for Java. Use when uploading, downloading, or managing files in Azure Blob Storage, working with containers, or implementing streaming data 
category: AI & Agents
source: antigravity
tags: [ai, azure, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-storage-blob-java
---


# Azure Storage Blob SDK for Java

Build blob storage applications using the Azure Storage Blob SDK for Java.

## Installation

```xml
<dependency>
    <groupId>com.azure</groupId>
    <artifactId>azure-storage-blob</artifactId>
    <version>12.33.0</version>
</dependency>
```

## Client Creation

### BlobServiceClient

```java
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;

// With SAS token
BlobServiceClient serviceClient = new BlobServiceClientBuilder()
    .endpoint("<storage-account-url>")
    .sasToken("<sas-token>")
    .buildClient();

// With connection string
BlobServiceClient serviceClient = new BlobServiceClientBuilder()
    .connectionString("<connection-string>")
    .buildClient();
```

### With DefaultAzureCredential

```java
import com.azure.identity.DefaultAzureCredentialBuilder;

BlobServiceClient serviceClient = new BlobServiceClientBuilder()
    .endpoint("<storage-account-url>")
    .credential(new DefaultAzureCredentialBuilder().build())
    .buildClient();
```

### BlobContainerClient

```java
import com.azure.storage.blob.BlobContainerClient;

// From service client
BlobContainerClient containerClient = serviceClient.getBlobContainerClient("mycontainer");

// Direct construction
BlobContainerClient containerClient = new BlobContainerClientBuilder()
    .connectionString("<connection-string>")
    .containerName("mycontainer")
    .buildClient();
```

### BlobClient

```java
import com.azure.storage.blob.BlobClient;

// From container client
BlobClient blobClient = containerClient.getBlobClient("myblob.txt");

// With directory structure
BlobClient blobClient = containerClient.getBlobClient("folder/subfolder/myblob.txt");

// Direct construction
BlobClient blobClient = new BlobClientBuilder()
    .connectionString("<connection-string>")
    .containerName("mycontainer")
    .blobName("myblob.txt")
    .buildClient();
```

## Core Patterns

### Create Container

```java
// Create container
serviceClient.createBlobContainer("mycontainer");

// Create if not exists
BlobContainerClient container = serviceClient.createBlobContainerIfNotExists("mycontainer");

// From container client
containerClient.create();
containerClient.createIfNotExists();
```

### Upload Data

```java
import com.azure.core.util.BinaryData;

// Upload string
String data = "Hello, Azure Blob Storage!";
blobClient.upload(BinaryData.fromString(data));

// Upload with overwrite
blobClient.upload(BinaryData.fromString(data), true);
```

### Upload from File

```java
blobClient.uploadFromFile("local-file.txt");

// With overwrite
blobClient.uploadFromFile("local-file.txt", true);
```

### Upload from Stream

```java
import com.azure.storage.blob.specialized.BlockBlobClient;

BlockBlobClient blockBlobClient = blobClient.getBlockBlobClient();

try (ByteArrayInputStream dataStream = new ByteArrayInputStream(data.getBytes())) {
    blockBlobClient.upload(dataStream, data.length());
}
```

### Upload with Options

```java
import com.azure.storage.blob.models.BlobHttpHeaders;
import com.azure.storage.blob.options.BlobParallelUploadOptions;

BlobHttpHeaders headers = new BlobHttpHeaders()
    .setContentType("text/plain")
    .setCacheControl("max-age=3600");

Map<String, String> metadata = Map.of("author", "john", "version", "1.0");

try (InputStream stream = new FileInputStream("large-file.bin")) {
    BlobParallelUploadOptions options = new BlobParallelUploadOptions(stream)
        .setHeaders(headers)
        .setMetadata(metadata);
    
    blobClient.uploadWithResponse(options, null, Context.NONE);
}
```

### Upload if Not Exists

```java
import com.azure.storage.blob.models.BlobRequestConditions;

BlobParallelUploadOptions options = new BlobParallelUploadOptions(inputStream, length)
    .setRequestConditions(new BlobRequestConditions().setIfNoneMatch("*"));

blobClient.uploadWithResponse(options, null, Context.NONE);
```

### Download Data

```java
// Download to BinaryData
BinaryData content = blobClient.downloadContent();
String text = content.toString();

// Download to file
blobClient.downloadToFile("downloaded-file.txt");
```

### Download to Stream

```java
try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
    blobClient.downloadStream(outputStream);
    byte[] data = outputStream.toByteArray();
}
```

### Download with InputStream

```java
import com.azure.storage.blob.specialized.BlobInputStream;

try (BlobInputStream blobIS = blobClient.openInputStream()) {
    byte[] buffer = new byte[1024];
    int bytesRead;
    while ((bytesRead = blobIS.read(buffer)) != -1) {
        // Process buffer
    }
}
```

### Upload via OutputStream

```java
import com.azure.storage.blob.specialized.BlobOutputStream;

try (BlobOutputStream blobOS = blobClient.getBlockBlobClient().getBlobOutputStream()) {
    blobOS.write("Data to upload".getBytes());
}
```

### List Blobs

```java
import com.azure.storage.blob.models.BlobItem;

// List all blobs
for (B
