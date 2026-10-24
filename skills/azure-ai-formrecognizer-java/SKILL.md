---
name: azure-ai-formrecognizer-java
description: Build document analysis applications using the Azure AI Document Intelligence SDK for Java. 
category: Document Processing
source: antigravity
tags: [pdf, api, ai, workflow, template, document, azure]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-ai-formrecognizer-java
---


# Azure Document Intelligence (Form Recognizer) SDK for Java

Build document analysis applications using the Azure AI Document Intelligence SDK for Java.

## Version and document boundaries

These examples target the legacy azure-ai-formrecognizer API and a prerelease dependency; verify the selected artifact/service API and supported model IDs before use, rather than assuming parity with newer Document Intelligence SDKs. Obtain permission before uploading documents, especially identity and financial records; use short-lived narrowly scoped SAS URLs and never log their query strings or extracted content. Build/delete model operations change billable resources. OCR fields and confidence are uncertain: check null/type for each nested Items field before calling its typed getter, validate results against source documents, and handle terminal polling failures/timeouts as well as initiation errors. Client declarations are alternative independent snippets, not one compilable file.

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
    if (merchantName != null && merchantName.getType() == DocumentFi
