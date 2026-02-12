---
name: azure-search-documents-dotnet
description: Azure AI Search SDK for .NET (Azure.Search.Documents). Use for building search applications with full-text, vector, semantic, and hybrid search. Covers SearchClient (queries, document CRUD), SearchInd
category: Document Processing
source: antigravity
tags: [api, ai, document, azure]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-search-documents-dotnet
---


# Azure.Search.Documents (.NET)

Build search applications with full-text, vector, semantic, and hybrid search capabilities.

## Installation

```bash
dotnet add package Azure.Search.Documents
dotnet add package Azure.Identity
```

**Current Versions**: Stable v11.7.0, Preview v11.8.0-beta.1

## Environment Variables

```bash
SEARCH_ENDPOINT=https://<search-service>.search.windows.net
SEARCH_INDEX_NAME=<index-name>
# For API key auth (not recommended for production)
SEARCH_API_KEY=<api-key>
```

## Authentication

**DefaultAzureCredential (preferred)**:
```csharp
using Azure.Identity;
using Azure.Search.Documents;

var credential = new DefaultAzureCredential();
var client = new SearchClient(
    new Uri(Environment.GetEnvironmentVariable("SEARCH_ENDPOINT")),
    Environment.GetEnvironmentVariable("SEARCH_INDEX_NAME"),
    credential);
```

**API Key**:
```csharp
using Azure;
using Azure.Search.Documents;

var credential = new AzureKeyCredential(
    Environment.GetEnvironmentVariable("SEARCH_API_KEY"));
var client = new SearchClient(
    new Uri(Environment.GetEnvironmentVariable("SEARCH_ENDPOINT")),
    Environment.GetEnvironmentVariable("SEARCH_INDEX_NAME"),
    credential);
```

## Client Selection

| Client | Purpose |
|--------|---------|
| `SearchClient` | Query indexes, upload/update/delete documents |
| `SearchIndexClient` | Create/manage indexes, synonym maps |
| `SearchIndexerClient` | Manage indexers, skillsets, data sources |

## Index Creation

### Using FieldBuilder (Recommended)

```csharp
using Azure.Search.Documents.Indexes;
using Azure.Search.Documents.Indexes.Models;

// Define model with attributes
public class Hotel
{
    [SimpleField(IsKey = true, IsFilterable = true)]
    public string HotelId { get; set; }

    [SearchableField(IsSortable = true)]
    public string HotelName { get; set; }

    [SearchableField(AnalyzerName = LexicalAnalyzerName.EnLucene)]
    public string Description { get; set; }

    [SimpleField(IsFilterable = true, IsSortable = true, IsFacetable = true)]
    public double? Rating { get; set; }

    [VectorSearchField(VectorSearchDimensions = 1536, VectorSearchProfileName = "vector-profile")]
    public ReadOnlyMemory<float>? DescriptionVector { get; set; }
}

// Create index
var indexClient = new SearchIndexClient(endpoint, credential);
var fieldBuilder = new FieldBuilder();
var fields = fieldBuilder.Build(typeof(Hotel));

var index = new SearchIndex("hotels")
{
    Fields = fields,
    VectorSearch = new VectorSearch
    {
        Profiles = { new VectorSearchProfile("vector-profile", "hnsw-algo") },
        Algorithms = { new HnswAlgorithmConfiguration("hnsw-algo") }
    }
};

await indexClient.CreateOrUpdateIndexAsync(index);
```

### Manual Field Definition

```csharp
var index = new SearchIndex("hotels")
{
    Fields =
    {
        new SimpleField("hotelId", SearchFieldDataType.String) { IsKey = true, IsFilterable = true },
        new SearchableField("hotelName") { IsSortable = true },
        new SearchableField("description") { AnalyzerName = LexicalAnalyzerName.EnLucene },
        new SimpleField("rating", SearchFieldDataType.Double) { IsFilterable = true, IsSortable = true },
        new SearchField("descriptionVector", SearchFieldDataType.Collection(SearchFieldDataType.Single))
        {
            VectorSearchDimensions = 1536,
            VectorSearchProfileName = "vector-profile"
        }
    }
};
```

## Document Operations

```csharp
var searchClient = new SearchClient(endpoint, indexName, credential);

// Upload (add new)
var hotels = new[] { new Hotel { HotelId = "1", HotelName = "Hotel A" } };
await searchClient.UploadDocumentsAsync(hotels);

// Merge (update existing)
await searchClient.MergeDocumentsAsync(hotels);

// Merge or Upload (upsert)
await searchClient.MergeOrUploadDocumentsAsync(hotels);

// Delete
await searchClient.DeleteDocumentsAsync("hotelId", new[] { "1", "2" });

// Batch operations
var batch = IndexDocumentsBatch.Create(
    IndexDocumentsAction.Upload(hotel1),
    IndexDocumentsAction.Merge(hotel2),
    IndexDocumentsAction.Delete(hotel3));
await searchClient.IndexDocumentsAsync(batch);
```

## Search Patterns

### Basic Search

```csharp
var options = new SearchOptions
{
    Filter = "rating ge 4",
    OrderBy = { "rating desc" },
    Select = { "hotelId", "hotelName", "rating" },
    Size = 10,
    Skip = 0,
    IncludeTotalCount = true
};

SearchResults<Hotel> results = await searchClient.SearchAsync<Hotel>("luxury", options);

Console.WriteLine($"Total: {results.TotalCount}");
await foreach (SearchResult<Hotel> result in results.GetResultsAsync())
{
    Console.WriteLine($"{result.Document.HotelName} (Score: {result.Score})");
}
```

### Faceted Search

```csharp
var options = new SearchOptions
{
    Facets = { "rating,count:5", "category" }
};

var results = await searchClient.SearchAsync<Hotel>("*", options);

foreach (var facet in results.Value.Facets["rating"])
{
    Console.WriteLine($"Rating {facet.Value}: {f
