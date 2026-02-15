---
name: azure-storage-file-share-ts
description: Azure File Share JavaScript/TypeScript SDK (@azure/storage-file-share) for SMB file share operations. Use for creating shares, managing directories, uploading/downloading files, and handling file meta
category: Document Processing
source: antigravity
tags: [javascript, typescript, node, ai, document, azure, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-storage-file-share-ts
---


# @azure/storage-file-share (TypeScript/JavaScript)

SDK for Azure File Share operations — SMB file shares, directories, and file operations.

## Installation

```bash
npm install @azure/storage-file-share @azure/identity
```

**Current Version**: 12.x  
**Node.js**: >= 18.0.0

## Environment Variables

```bash
AZURE_STORAGE_ACCOUNT_NAME=<account-name>
AZURE_STORAGE_ACCOUNT_KEY=<account-key>
# OR connection string
AZURE_STORAGE_CONNECTION_STRING=DefaultEndpointsProtocol=https;AccountName=...
```

## Authentication

### Connection String (Simplest)

```typescript
import { ShareServiceClient } from "@azure/storage-file-share";

const client = ShareServiceClient.fromConnectionString(
  process.env.AZURE_STORAGE_CONNECTION_STRING!
);
```

### StorageSharedKeyCredential (Node.js only)

```typescript
import { ShareServiceClient, StorageSharedKeyCredential } from "@azure/storage-file-share";

const accountName = process.env.AZURE_STORAGE_ACCOUNT_NAME!;
const accountKey = process.env.AZURE_STORAGE_ACCOUNT_KEY!;

const sharedKeyCredential = new StorageSharedKeyCredential(accountName, accountKey);
const client = new ShareServiceClient(
  `https://${accountName}.file.core.windows.net`,
  sharedKeyCredential
);
```

### DefaultAzureCredential

```typescript
import { ShareServiceClient } from "@azure/storage-file-share";
import { DefaultAzureCredential } from "@azure/identity";

const accountName = process.env.AZURE_STORAGE_ACCOUNT_NAME!;
const client = new ShareServiceClient(
  `https://${accountName}.file.core.windows.net`,
  new DefaultAzureCredential()
);
```

### SAS Token

```typescript
import { ShareServiceClient } from "@azure/storage-file-share";

const accountName = process.env.AZURE_STORAGE_ACCOUNT_NAME!;
const sasToken = process.env.AZURE_STORAGE_SAS_TOKEN!;

const client = new ShareServiceClient(
  `https://${accountName}.file.core.windows.net${sasToken}`
);
```

## Client Hierarchy

```
ShareServiceClient (account level)
└── ShareClient (share level)
    └── ShareDirectoryClient (directory level)
        └── ShareFileClient (file level)
```

## Share Operations

### Create Share

```typescript
const shareClient = client.getShareClient("my-share");
await shareClient.create();

// Create with quota (in GB)
await shareClient.create({ quota: 100 });
```

### List Shares

```typescript
for await (const share of client.listShares()) {
  console.log(share.name, share.properties.quota);
}

// With prefix filter
for await (const share of client.listShares({ prefix: "logs-" })) {
  console.log(share.name);
}
```

### Delete Share

```typescript
await shareClient.delete();

// Delete if exists
await shareClient.deleteIfExists();
```

### Get Share Properties

```typescript
const properties = await shareClient.getProperties();
console.log("Quota:", properties.quota, "GB");
console.log("Last Modified:", properties.lastModified);
```

### Set Share Quota

```typescript
await shareClient.setQuota(200); // 200 GB
```

## Directory Operations

### Create Directory

```typescript
const directoryClient = shareClient.getDirectoryClient("my-directory");
await directoryClient.create();

// Create nested directory
const nestedDir = shareClient.getDirectoryClient("parent/child/grandchild");
await nestedDir.create();
```

### List Directories and Files

```typescript
const directoryClient = shareClient.getDirectoryClient("my-directory");

for await (const item of directoryClient.listFilesAndDirectories()) {
  if (item.kind === "directory") {
    console.log(`[DIR] ${item.name}`);
  } else {
    console.log(`[FILE] ${item.name} (${item.properties.contentLength} bytes)`);
  }
}
```

### Delete Directory

```typescript
await directoryClient.delete();

// Delete if exists
await directoryClient.deleteIfExists();
```

### Check if Directory Exists

```typescript
const exists = await directoryClient.exists();
if (!exists) {
  await directoryClient.create();
}
```

## File Operations

### Upload File (Simple)

```typescript
const fileClient = shareClient
  .getDirectoryClient("my-directory")
  .getFileClient("my-file.txt");

// Upload string
const content = "Hello, World!";
await fileClient.create(content.length);
await fileClient.uploadRange(content, 0, content.length);
```

### Upload File (Node.js - from local file)

```typescript
import * as fs from "fs";
import * as path from "path";

const fileClient = shareClient.rootDirectoryClient.getFileClient("uploaded.txt");
const localFilePath = "/path/to/local/file.txt";
const fileSize = fs.statSync(localFilePath).size;

await fileClient.create(fileSize);
await fileClient.uploadFile(localFilePath);
```

### Upload File (Buffer)

```typescript
const buffer = Buffer.from("Hello, Azure Files!");
const fileClient = shareClient.rootDirectoryClient.getFileClient("buffer-file.txt");

await fileClient.create(buffer.length);
await fileClient.uploadRange(buffer, 0, buffer.length);
```

### Upload File (Stream)

```typescript
import * as fs from "fs";

const fileClient = shareClient.rootDirectoryClien
