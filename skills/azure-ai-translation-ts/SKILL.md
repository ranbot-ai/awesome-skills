---
name: azure-ai-translation-ts
description: Build translation applications using Azure Translation SDKs for JavaScript (@azure-rest/ai-translation-text, @azure-rest/ai-translation-document). Use when implementing text translation, transliterati
category: Document Processing
source: antigravity
tags: [javascript, typescript, node, api, ai, llm, document, azure, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-ai-translation-ts
---


# Azure Translation SDKs for TypeScript

Text and document translation with REST-style clients.

## Installation

```bash
# Text translation
npm install @azure-rest/ai-translation-text @azure/identity

# Document translation
npm install @azure-rest/ai-translation-document @azure/identity
```

## Environment Variables

```bash
TRANSLATOR_ENDPOINT=https://api.cognitive.microsofttranslator.com
TRANSLATOR_SUBSCRIPTION_KEY=<your-api-key>
TRANSLATOR_REGION=<your-region>  # e.g., westus, eastus
```

## Text Translation Client

### Authentication

```typescript
import TextTranslationClient, { TranslatorCredential } from "@azure-rest/ai-translation-text";

// API Key + Region
const credential: TranslatorCredential = {
  key: process.env.TRANSLATOR_SUBSCRIPTION_KEY!,
  region: process.env.TRANSLATOR_REGION!,
};
const client = TextTranslationClient(process.env.TRANSLATOR_ENDPOINT!, credential);

// Or just credential (uses global endpoint)
const client2 = TextTranslationClient(credential);
```

### Translate Text

```typescript
import TextTranslationClient, { isUnexpected } from "@azure-rest/ai-translation-text";

const response = await client.path("/translate").post({
  body: {
    inputs: [
      {
        text: "Hello, how are you?",
        language: "en",  // source (optional, auto-detect)
        targets: [
          { language: "es" },
          { language: "fr" },
        ],
      },
    ],
  },
});

if (isUnexpected(response)) {
  throw response.body.error;
}

for (const result of response.body.value) {
  for (const translation of result.translations) {
    console.log(`${translation.language}: ${translation.text}`);
  }
}
```

### Translate with Options

```typescript
const response = await client.path("/translate").post({
  body: {
    inputs: [
      {
        text: "Hello world",
        language: "en",
        textType: "Plain",  // or "Html"
        targets: [
          {
            language: "de",
            profanityAction: "NoAction",  // "Marked" | "Deleted"
            tone: "formal",  // LLM-specific
          },
        ],
      },
    ],
  },
});
```

### Get Supported Languages

```typescript
const response = await client.path("/languages").get();

if (isUnexpected(response)) {
  throw response.body.error;
}

// Translation languages
for (const [code, lang] of Object.entries(response.body.translation || {})) {
  console.log(`${code}: ${lang.name} (${lang.nativeName})`);
}
```

### Transliterate

```typescript
const response = await client.path("/transliterate").post({
  body: { inputs: [{ text: "这是个测试" }] },
  queryParameters: {
    language: "zh-Hans",
    fromScript: "Hans",
    toScript: "Latn",
  },
});

if (!isUnexpected(response)) {
  for (const t of response.body.value) {
    console.log(`${t.script}: ${t.text}`);  // Latn: zhè shì gè cè shì
  }
}
```

### Detect Language

```typescript
const response = await client.path("/detect").post({
  body: { inputs: [{ text: "Bonjour le monde" }] },
});

if (!isUnexpected(response)) {
  for (const result of response.body.value) {
    console.log(`Language: ${result.language}, Score: ${result.score}`);
  }
}
```

## Document Translation Client

### Authentication

```typescript
import DocumentTranslationClient from "@azure-rest/ai-translation-document";
import { DefaultAzureCredential } from "@azure/identity";

const endpoint = "https://<translator>.cognitiveservices.azure.com";

// TokenCredential
const client = DocumentTranslationClient(endpoint, new DefaultAzureCredential());

// API Key
const client2 = DocumentTranslationClient(endpoint, { key: "<api-key>" });
```

### Single Document Translation

```typescript
import DocumentTranslationClient from "@azure-rest/ai-translation-document";
import { writeFile } from "node:fs/promises";

const response = await client.path("/document:translate").post({
  queryParameters: {
    targetLanguage: "es",
    sourceLanguage: "en",  // optional
  },
  contentType: "multipart/form-data",
  body: [
    {
      name: "document",
      body: "Hello, this is a test document.",
      filename: "test.txt",
      contentType: "text/plain",
    },
  ],
}).asNodeStream();

if (response.status === "200") {
  await writeFile("translated.txt", response.body);
}
```

### Batch Document Translation

```typescript
import { ContainerSASPermissions, BlobServiceClient } from "@azure/storage-blob";

// Generate SAS URLs for source and target containers
const sourceSas = await sourceContainer.generateSasUrl({
  permissions: ContainerSASPermissions.parse("rl"),
  expiresOn: new Date(Date.now() + 24 * 60 * 60 * 1000),
});

const targetSas = await targetContainer.generateSasUrl({
  permissions: ContainerSASPermissions.parse("rwl"),
  expiresOn: new Date(Date.now() + 24 * 60 * 60 * 1000),
});

// Start batch translation
const response = await client.path("/document/batches").post({
  body: {
    inputs: [
      {
        source: { sourceUrl: sourceSas },
        targets: [
          { targetUrl: targetSas, language: "fr" },
     
