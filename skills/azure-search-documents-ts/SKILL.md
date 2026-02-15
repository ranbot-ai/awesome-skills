---
name: azure-search-documents-ts
description: Build search applications using Azure AI Search SDK for JavaScript (@azure/search-documents). Use when creating/managing indexes, implementing vector/hybrid search, semantic ranking, or building agent
category: Document Processing
source: antigravity
tags: [javascript, typescript, ai, agent, workflow, document, security, azure]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-search-documents-ts
---


# Azure AI Search SDK for TypeScript

Build search applications with vector, hybrid, and semantic search capabilities.

## Installation

```bash
npm install @azure/search-documents @azure/identity
```

## Environment Variables

```bash
AZURE_SEARCH_ENDPOINT=https://<service-name>.search.windows.net
AZURE_SEARCH_INDEX_NAME=my-index
AZURE_SEARCH_ADMIN_KEY=<admin-key>  # Optional if using Entra ID
```

## Authentication

```typescript
import { SearchClient, SearchIndexClient } from "@azure/search-documents";
import { DefaultAzureCredential } from "@azure/identity";

const endpoint = process.env.AZURE_SEARCH_ENDPOINT!;
const indexName = process.env.AZURE_SEARCH_INDEX_NAME!;
const credential = new DefaultAzureCredential();

// For searching
const searchClient = new SearchClient(endpoint, indexName, credential);

// For index management
const indexClient = new SearchIndexClient(endpoint, credential);
```

## Core Workflow

### Create Index with Vector Field

```typescript
import { SearchIndex, SearchField, VectorSearch } from "@azure/search-documents";

const index: SearchIndex = {
  name: "products",
  fields: [
    { name: "id", type: "Edm.String", key: true },
    { name: "title", type: "Edm.String", searchable: true },
    { name: "description", type: "Edm.String", searchable: true },
    { name: "category", type: "Edm.String", filterable: true, facetable: true },
    {
      name: "embedding",
      type: "Collection(Edm.Single)",
      searchable: true,
      vectorSearchDimensions: 1536,
      vectorSearchProfileName: "vector-profile",
    },
  ],
  vectorSearch: {
    algorithms: [
      { name: "hnsw-algorithm", kind: "hnsw" },
    ],
    profiles: [
      { name: "vector-profile", algorithmConfigurationName: "hnsw-algorithm" },
    ],
  },
};

await indexClient.createOrUpdateIndex(index);
```

### Index Documents

```typescript
const documents = [
  { id: "1", title: "Widget", description: "A useful widget", category: "Tools", embedding: [...] },
  { id: "2", title: "Gadget", description: "A cool gadget", category: "Electronics", embedding: [...] },
];

const result = await searchClient.uploadDocuments(documents);
console.log(`Indexed ${result.results.length} documents`);
```

### Full-Text Search

```typescript
const results = await searchClient.search("widget", {
  select: ["id", "title", "description"],
  filter: "category eq 'Tools'",
  orderBy: ["title asc"],
  top: 10,
});

for await (const result of results.results) {
  console.log(`${result.document.title}: ${result.score}`);
}
```

### Vector Search

```typescript
const queryVector = await getEmbedding("useful tool"); // Your embedding function

const results = await searchClient.search("*", {
  vectorSearchOptions: {
    queries: [
      {
        kind: "vector",
        vector: queryVector,
        fields: ["embedding"],
        kNearestNeighborsCount: 10,
      },
    ],
  },
  select: ["id", "title", "description"],
});

for await (const result of results.results) {
  console.log(`${result.document.title}: ${result.score}`);
}
```

### Hybrid Search (Text + Vector)

```typescript
const queryVector = await getEmbedding("useful tool");

const results = await searchClient.search("tool", {
  vectorSearchOptions: {
    queries: [
      {
        kind: "vector",
        vector: queryVector,
        fields: ["embedding"],
        kNearestNeighborsCount: 50,
      },
    ],
  },
  select: ["id", "title", "description"],
  top: 10,
});
```

### Semantic Search

```typescript
// Index must have semantic configuration
const index: SearchIndex = {
  name: "products",
  fields: [...],
  semanticSearch: {
    configurations: [
      {
        name: "semantic-config",
        prioritizedFields: {
          titleField: { name: "title" },
          contentFields: [{ name: "description" }],
        },
      },
    ],
  },
};

// Search with semantic ranking
const results = await searchClient.search("best tool for the job", {
  queryType: "semantic",
  semanticSearchOptions: {
    configurationName: "semantic-config",
    captions: { captionType: "extractive" },
    answers: { answerType: "extractive", count: 3 },
  },
  select: ["id", "title", "description"],
});

for await (const result of results.results) {
  console.log(`${result.document.title}`);
  console.log(`  Caption: ${result.captions?.[0]?.text}`);
  console.log(`  Reranker Score: ${result.rerankerScore}`);
}
```

## Filtering and Facets

```typescript
// Filter syntax
const results = await searchClient.search("*", {
  filter: "category eq 'Electronics' and price lt 100",
  facets: ["category,count:10", "brand"],
});

// Access facets
for (const [facetName, facetResults] of Object.entries(results.facets || {})) {
  console.log(`${facetName}:`);
  for (const facet of facetResults) {
    console.log(`  ${facet.value}: ${facet.count}`);
  }
}
```

## Autocomplete and Suggestions

```typescript
// Create suggester in index
const index: SearchIndex = {
  name: "products",
  fields: [...],
  suggesters
