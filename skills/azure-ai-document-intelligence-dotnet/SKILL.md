---
name: azure-ai-document-intelligence-dotnet
description: Azure AI Document Intelligence SDK for .NET. Extract text, tables, and structured data from documents using prebuilt and custom models. Use for invoice processing, receipt extraction, ID document anal
category: Document Processing
source: antigravity
tags: [pdf, api, ai, workflow, template, document, azure, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-ai-document-intelligence-dotnet
---


# Azure.AI.DocumentIntelligence (.NET)

Extract text, tables, and structured data from documents using prebuilt and custom models.

## Installation

```bash
dotnet add package Azure.AI.DocumentIntelligence
dotnet add package Azure.Identity
```

**Current Version**: v1.0.0 (GA)

## Environment Variables

```bash
DOCUMENT_INTELLIGENCE_ENDPOINT=https://<resource-name>.cognitiveservices.azure.com/
DOCUMENT_INTELLIGENCE_API_KEY=<your-api-key>
BLOB_CONTAINER_SAS_URL=https://<storage>.blob.core.windows.net/<container>?<sas-token>
```

## Authentication

### Microsoft Entra ID (Recommended)

```csharp
using Azure.Identity;
using Azure.AI.DocumentIntelligence;

string endpoint = Environment.GetEnvironmentVariable("DOCUMENT_INTELLIGENCE_ENDPOINT");
var credential = new DefaultAzureCredential();
var client = new DocumentIntelligenceClient(new Uri(endpoint), credential);
```

> **Note**: Entra ID requires a **custom subdomain** (e.g., `https://<resource-name>.cognitiveservices.azure.com/`), not a regional endpoint.

### API Key

```csharp
string endpoint = Environment.GetEnvironmentVariable("DOCUMENT_INTELLIGENCE_ENDPOINT");
string apiKey = Environment.GetEnvironmentVariable("DOCUMENT_INTELLIGENCE_API_KEY");
var client = new DocumentIntelligenceClient(new Uri(endpoint), new AzureKeyCredential(apiKey));
```

## Client Types

| Client | Purpose |
|--------|---------|
| `DocumentIntelligenceClient` | Analyze documents, classify documents |
| `DocumentIntelligenceAdministrationClient` | Build/manage custom models and classifiers |

## Prebuilt Models

| Model ID | Description |
|----------|-------------|
| `prebuilt-read` | Extract text, languages, handwriting |
| `prebuilt-layout` | Extract text, tables, selection marks, structure |
| `prebuilt-invoice` | Extract invoice fields (vendor, items, totals) |
| `prebuilt-receipt` | Extract receipt fields (merchant, items, total) |
| `prebuilt-idDocument` | Extract ID document fields (name, DOB, address) |
| `prebuilt-businessCard` | Extract business card fields |
| `prebuilt-tax.us.w2` | Extract W-2 tax form fields |
| `prebuilt-healthInsuranceCard.us` | Extract health insurance card fields |

## Core Workflows

### 1. Analyze Invoice

```csharp
using Azure.AI.DocumentIntelligence;

Uri invoiceUri = new Uri("https://example.com/invoice.pdf");

Operation<AnalyzeResult> operation = await client.AnalyzeDocumentAsync(
    WaitUntil.Completed, 
    "prebuilt-invoice", 
    invoiceUri);

AnalyzeResult result = operation.Value;

foreach (AnalyzedDocument document in result.Documents)
{
    if (document.Fields.TryGetValue("VendorName", out DocumentField vendorNameField)
        && vendorNameField.FieldType == DocumentFieldType.String)
    {
        string vendorName = vendorNameField.ValueString;
        Console.WriteLine($"Vendor Name: '{vendorName}', confidence: {vendorNameField.Confidence}");
    }

    if (document.Fields.TryGetValue("InvoiceTotal", out DocumentField invoiceTotalField)
        && invoiceTotalField.FieldType == DocumentFieldType.Currency)
    {
        CurrencyValue invoiceTotal = invoiceTotalField.ValueCurrency;
        Console.WriteLine($"Invoice Total: '{invoiceTotal.CurrencySymbol}{invoiceTotal.Amount}'");
    }
    
    // Extract line items
    if (document.Fields.TryGetValue("Items", out DocumentField itemsField)
        && itemsField.FieldType == DocumentFieldType.List)
    {
        foreach (DocumentField item in itemsField.ValueList)
        {
            var itemFields = item.ValueDictionary;
            if (itemFields.TryGetValue("Description", out DocumentField descField))
                Console.WriteLine($"  Item: {descField.ValueString}");
        }
    }
}
```

### 2. Extract Layout (Text, Tables, Structure)

```csharp
Uri fileUri = new Uri("https://example.com/document.pdf");

Operation<AnalyzeResult> operation = await client.AnalyzeDocumentAsync(
    WaitUntil.Completed, 
    "prebuilt-layout", 
    fileUri);

AnalyzeResult result = operation.Value;

// Extract text by page
foreach (DocumentPage page in result.Pages)
{
    Console.WriteLine($"Page {page.PageNumber}: {page.Lines.Count} lines, {page.Words.Count} words");
    
    foreach (DocumentLine line in page.Lines)
    {
        Console.WriteLine($"  Line: '{line.Content}'");
    }
}

// Extract tables
foreach (DocumentTable table in result.Tables)
{
    Console.WriteLine($"Table: {table.RowCount} rows x {table.ColumnCount} columns");
    foreach (DocumentTableCell cell in table.Cells)
    {
        Console.WriteLine($"  Cell ({cell.RowIndex}, {cell.ColumnIndex}): {cell.Content}");
    }
}
```

### 3. Analyze Receipt

```csharp
Operation<AnalyzeResult> operation = await client.AnalyzeDocumentAsync(
    WaitUntil.Completed, 
    "prebuilt-receipt", 
    receiptUri);

AnalyzeResult result = operation.Value;

foreach (AnalyzedDocument document in result.Documents)
{
    if (document.Fields.TryGetValue("MerchantName", out DocumentField merchantField))
        Console.WriteLine($"Merchant: {mercha
