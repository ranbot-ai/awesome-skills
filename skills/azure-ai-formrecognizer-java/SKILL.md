---
name: azure-ai-formrecognizer-java
description: Build document analysis applications with Azure Document Intelligence (Form Recognizer) SDK for Java. Use when extracting text, tables, key-value pairs from documents, receipts, invoices, or building 
category: Document Processing
source: antigravity
tags: [pdf, api, ai, template, document, azure]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-ai-formrecognizer-java
---


# Azure Document Intelligence (Form Recognizer) SDK for Java

Build document analysis applications using the Azure AI Document Intelligence SDK for Java.

## Installation

```xml
<dependency>
    <groupId>com.azure</groupId>
    <artifactId>azure-ai-formrecognizer</artifactId>
    <version>4.2.0-beta.1</version>
</dependency>
```

## Client Creation

### DocumentAnalysisClient

```java
import com.azure.ai.formrecognizer.documentanalysis.DocumentAnalysisClient;
import com.azure.ai.formrecognizer.documentanalysis.DocumentAnalysisClientBuilder;
import com.azure.core.credential.AzureKeyCredential;

DocumentAnalysisClient client = new DocumentAnalysisClientBuilder()
    .credential(new AzureKeyCredential("{key}"))
    .endpoint("{endpoint}")
    .buildClient();
```

### DocumentModelAdministrationClient

```java
import com.azure.ai.formrecognizer.documentanalysis.administration.DocumentModelAdministrationClient;
import com.azure.ai.formrecognizer.documentanalysis.administration.DocumentModelAdministrationClientBuilder;

DocumentModelAdministrationClient adminClient = new DocumentModelAdministrationClientBuilder()
    .credential(new AzureKeyCredential("{key}"))
    .endpoint("{endpoint}")
    .buildClient();
```

### With DefaultAzureCredential

```java
import com.azure.identity.DefaultAzureCredentialBuilder;

DocumentAnalysisClient client = new DocumentAnalysisClientBuilder()
    .endpoint("{endpoint}")
    .credential(new DefaultAzureCredentialBuilder().build())
    .buildClient();
```

## Prebuilt Models

| Model ID | Purpose |
|----------|---------|
| `prebuilt-layout` | Extract text, tables, selection marks |
| `prebuilt-document` | General document with key-value pairs |
| `prebuilt-receipt` | Receipt data extraction |
| `prebuilt-invoice` | Invoice field extraction |
| `prebuilt-businessCard` | Business card parsing |
| `prebuilt-idDocument` | ID document (passport, license) |
| `prebuilt-tax.us.w2` | US W2 tax forms |

## Core Patterns

### Extract Layout

```java
import com.azure.ai.formrecognizer.documentanalysis.models.*;
import com.azure.core.util.BinaryData;
import com.azure.core.util.polling.SyncPoller;
import java.io.File;

File document = new File("document.pdf");
BinaryData documentData = BinaryData.fromFile(document.toPath());

SyncPoller<OperationResult, AnalyzeResult> poller = 
    client.beginAnalyzeDocument("prebuilt-layout", documentData);

AnalyzeResult result = poller.getFinalResult();

// Process pages
for (DocumentPage page : result.getPages()) {
    System.out.printf("Page %d: %.2f x %.2f %s%n",
        page.getPageNumber(),
        page.getWidth(),
        page.getHeight(),
        page.getUnit());
    
    // Lines
    for (DocumentLine line : page.getLines()) {
        System.out.println("Line: " + line.getContent());
    }
    
    // Selection marks (checkboxes)
    for (DocumentSelectionMark mark : page.getSelectionMarks()) {
        System.out.printf("Checkbox: %s (confidence: %.2f)%n",
            mark.getSelectionMarkState(),
            mark.getConfidence());
    }
}

// Tables
for (DocumentTable table : result.getTables()) {
    System.out.printf("Table: %d rows x %d columns%n",
        table.getRowCount(),
        table.getColumnCount());
    
    for (DocumentTableCell cell : table.getCells()) {
        System.out.printf("Cell[%d,%d]: %s%n",
            cell.getRowIndex(),
            cell.getColumnIndex(),
            cell.getContent());
    }
}
```

### Analyze from URL

```java
String documentUrl = "https://example.com/invoice.pdf";

SyncPoller<OperationResult, AnalyzeResult> poller = 
    client.beginAnalyzeDocumentFromUrl("prebuilt-invoice", documentUrl);

AnalyzeResult result = poller.getFinalResult();
```

### Analyze Receipt

```java
SyncPoller<OperationResult, AnalyzeResult> poller = 
    client.beginAnalyzeDocumentFromUrl("prebuilt-receipt", receiptUrl);

AnalyzeResult result = poller.getFinalResult();

for (AnalyzedDocument doc : result.getDocuments()) {
    Map<String, DocumentField> fields = doc.getFields();
    
    DocumentField merchantName = fields.get("MerchantName");
    if (merchantName != null && merchantName.getType() == DocumentFieldType.STRING) {
        System.out.printf("Merchant: %s (confidence: %.2f)%n",
            merchantName.getValueAsString(),
            merchantName.getConfidence());
    }
    
    DocumentField transactionDate = fields.get("TransactionDate");
    if (transactionDate != null && transactionDate.getType() == DocumentFieldType.DATE) {
        System.out.printf("Date: %s%n", transactionDate.getValueAsDate());
    }
    
    DocumentField items = fields.get("Items");
    if (items != null && items.getType() == DocumentFieldType.LIST) {
        for (DocumentField item : items.getValueAsList()) {
            Map<String, DocumentField> itemFields = item.getValueAsMap();
            System.out.printf("Item: %s, Price: %.2f%n",
                itemFields.get("Name").getValueAsString(),
                itemFields.get("Price").getV
