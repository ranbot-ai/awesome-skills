---
name: azure-ai-contentsafety-ts
description: Analyze text and images for harmful content using Azure AI Content Safety (@azure-rest/ai-content-safety). Use when moderating user-generated content, detecting hate speech, violence, sexual content, 
category: AI & Agents
source: antigravity
tags: [typescript, node, api, ai, image, azure, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-ai-contentsafety-ts
---


# Azure AI Content Safety REST SDK for TypeScript

Analyze text and images for harmful content with customizable blocklists.

## Installation

```bash
npm install @azure-rest/ai-content-safety @azure/identity @azure/core-auth
```

## Environment Variables

```bash
CONTENT_SAFETY_ENDPOINT=https://<resource>.cognitiveservices.azure.com
CONTENT_SAFETY_KEY=<api-key>
```

## Authentication

**Important**: This is a REST client. `ContentSafetyClient` is a **function**, not a class.

### API Key

```typescript
import ContentSafetyClient from "@azure-rest/ai-content-safety";
import { AzureKeyCredential } from "@azure/core-auth";

const client = ContentSafetyClient(
  process.env.CONTENT_SAFETY_ENDPOINT!,
  new AzureKeyCredential(process.env.CONTENT_SAFETY_KEY!)
);
```

### DefaultAzureCredential

```typescript
import ContentSafetyClient from "@azure-rest/ai-content-safety";
import { DefaultAzureCredential } from "@azure/identity";

const client = ContentSafetyClient(
  process.env.CONTENT_SAFETY_ENDPOINT!,
  new DefaultAzureCredential()
);
```

## Analyze Text

```typescript
import ContentSafetyClient, { isUnexpected } from "@azure-rest/ai-content-safety";

const result = await client.path("/text:analyze").post({
  body: {
    text: "Text content to analyze",
    categories: ["Hate", "Sexual", "Violence", "SelfHarm"],
    outputType: "FourSeverityLevels"  // or "EightSeverityLevels"
  }
});

if (isUnexpected(result)) {
  throw result.body;
}

for (const analysis of result.body.categoriesAnalysis) {
  console.log(`${analysis.category}: severity ${analysis.severity}`);
}
```

## Analyze Image

### Base64 Content

```typescript
import { readFileSync } from "node:fs";

const imageBuffer = readFileSync("./image.png");
const base64Image = imageBuffer.toString("base64");

const result = await client.path("/image:analyze").post({
  body: {
    image: { content: base64Image }
  }
});

if (isUnexpected(result)) {
  throw result.body;
}

for (const analysis of result.body.categoriesAnalysis) {
  console.log(`${analysis.category}: severity ${analysis.severity}`);
}
```

### Blob URL

```typescript
const result = await client.path("/image:analyze").post({
  body: {
    image: { blobUrl: "https://storage.blob.core.windows.net/container/image.png" }
  }
});
```

## Blocklist Management

### Create Blocklist

```typescript
const result = await client
  .path("/text/blocklists/{blocklistName}", "my-blocklist")
  .patch({
    contentType: "application/merge-patch+json",
    body: {
      description: "Custom blocklist for prohibited terms"
    }
  });

if (isUnexpected(result)) {
  throw result.body;
}

console.log(`Created: ${result.body.blocklistName}`);
```

### Add Items to Blocklist

```typescript
const result = await client
  .path("/text/blocklists/{blocklistName}:addOrUpdateBlocklistItems", "my-blocklist")
  .post({
    body: {
      blocklistItems: [
        { text: "prohibited-term-1", description: "First blocked term" },
        { text: "prohibited-term-2", description: "Second blocked term" }
      ]
    }
  });

if (isUnexpected(result)) {
  throw result.body;
}

for (const item of result.body.blocklistItems ?? []) {
  console.log(`Added: ${item.blocklistItemId}`);
}
```

### Analyze with Blocklist

```typescript
const result = await client.path("/text:analyze").post({
  body: {
    text: "Text that might contain blocked terms",
    blocklistNames: ["my-blocklist"],
    haltOnBlocklistHit: false
  }
});

if (isUnexpected(result)) {
  throw result.body;
}

// Check blocklist matches
if (result.body.blocklistsMatch) {
  for (const match of result.body.blocklistsMatch) {
    console.log(`Blocked: "${match.blocklistItemText}" from ${match.blocklistName}`);
  }
}
```

### List Blocklists

```typescript
const result = await client.path("/text/blocklists").get();

if (isUnexpected(result)) {
  throw result.body;
}

for (const blocklist of result.body.value ?? []) {
  console.log(`${blocklist.blocklistName}: ${blocklist.description}`);
}
```

### Delete Blocklist

```typescript
await client.path("/text/blocklists/{blocklistName}", "my-blocklist").delete();
```

## Harm Categories

| Category | API Term | Description |
|----------|----------|-------------|
| Hate and Fairness | `Hate` | Discriminatory language targeting identity groups |
| Sexual | `Sexual` | Sexual content, nudity, pornography |
| Violence | `Violence` | Physical harm, weapons, terrorism |
| Self-Harm | `SelfHarm` | Self-injury, suicide, eating disorders |

## Severity Levels

| Level | Risk | Recommended Action |
|-------|------|-------------------|
| 0 | Safe | Allow |
| 2 | Low | Review or allow with warning |
| 4 | Medium | Block or require human review |
| 6 | High | Block immediately |

**Output Types**:
- `FourSeverityLevels` (default): Returns 0, 2, 4, 6
- `EightSeverityLevels`: Returns 0-7

## Content Moderation Helper

```typescript
import ContentSafetyClient, { 
  isUnexpected, 
  TextCategoriesAnalysisOutput 
} from "@azure-rest/ai-content-safety";
