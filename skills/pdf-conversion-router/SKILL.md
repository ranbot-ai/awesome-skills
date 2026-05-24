---
name: pdf-conversion-router
description: Use when converting a PDF into another format such as Markdown, HTML, text, JSON, DOCX, or structured notes and the agent must choose the best extraction route, settings, and cleanup strategy for maxi
category: Document Processing
source: antigravity
tags: [pdf, docx, markdown, ai, agent, llm, document, presentation, image, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/pdf-conversion-router
---


# PDF Conversion Router

Route every PDF conversion through a short analysis step before choosing tools or CLI flags.

The goal is not "extract the most text". The goal is:
- preserve structure
- preserve attachment between labels and values
- choose the most faithful output shape
- avoid noisy defaults when a better route exists

## When to Use

- The user wants a PDF converted into another format.
- The requested output is `.md`, `.html`, `.txt`, `.json`, `.docx`, or structured notes.
- The PDF may be scanned, OCR-heavy, table-heavy, slide-based, medical, academic, or multi-column.

## Core Rule

Never start with one fixed default pipeline.

Always:
1. classify the PDF
2. classify the target output
3. choose the strongest route for that combination
4. validate the result on representative sections
5. if needed, retry with better settings before delivering

Heuristics are starting points, not guarantees.

Do not promote one flag combination into a universal default just because it worked well on one PDF.
Prefer document-specific evidence over habit.

## Primary Engine Rule

Use `opendataloader-pdf` as the primary conversion engine for every PDF conversion task by default.

This skill should assume:
- `opendataloader-pdf` is always the first conversion attempt
- other tools are used to classify, validate, OCR, inspect, or support cleanup
- other extractors are not the default replacement for the main conversion route

Use other tools only for one of these reasons:
- quick classification of the PDF
- OCR preprocessing before conversion
- validation against layout-preserving text
- manual repair when the generated output is still noisy
- fallback only if `opendataloader-pdf` cannot produce a usable result

## Step 1: Classify the Source PDF

Identify the document class as quickly as possible:

- Native digital PDF with selectable text
- OCR PDF with noisy text
- Image-only/scanned PDF
- Slide deck / presentation export
- Medical or lab report
- Table-heavy business/finance document
- Narrative report / letter / article
- Mixed layout document with diagrams, tables, and prose

Useful fast checks:

```bash
pdfinfo input.pdf
pdftotext -layout input.pdf -
```

If text is missing or very poor, treat OCR as required.

## Document-Type Heuristics

Use these as default starting points:

- medical / lab report
  `markdown-with-html + --table-method cluster + --image-output off`

- slide deck / PowerPoint export
  `markdown-with-html + --image-output off`
  add `--table-method cluster` only if the default route under-structures important tabular content
  if tables are visually obvious but missing or badly fused, treat this as a detection problem, not a Markdown formatting problem
  if the selected route already reconstructs a real table but clips leading characters at column boundaries, treat that as a boundary-splitting defect, not a missing-table failure

- narrative / article / letter
  start with `markdown` or `text`
  use `markdown-with-html` only if structure clearly matters

- table-heavy business / finance PDF
  start with `markdown-with-html`
  add `--table-method cluster` when rows or columns flatten

- scanned / image-heavy PDF
  OCR first, then convert with `opendataloader-pdf`

- mixed-layout PDF
  prefer `markdown-with-html`
  validate one easy section and one hard section before accepting output

## Step 2: Choose the Output Shape

Pick the output that best matches the document and the user's goal.

- `markdown-with-html`
  Use by default when the user wants Markdown and fidelity matters.
  Prefer this for tables, medical reports, slides, mixed-layout PDFs, and anything likely to break in pure Markdown.

- `markdown`
  Use only when clean plain Markdown matters more than layout fidelity.

- `html`
  Use when visual structure matters more than LLM readability.

- `text`
  Use for quick linear extraction, narrative documents, or when structure is unimportant.

- `json`
  Use when downstream machine processing matters more than human readability.

- `docx`
  Use when the user wants editable office output and layout reconstruction matters.

## Step 3: Choose the Extraction Route

### For OpenDataLoader CLI

Use OpenDataLoader as the default route.

Preferred defaults:

- For Markdown output with fidelity priority:
  `-f markdown-with-html`

- For medical PDFs:
  add `--table-method cluster`

- For table-heavy PDFs:
  add `--table-method cluster`

- For slide decks:
  start without `--table-method cluster`
  add it only after a structure check shows meaningful improvement
  if a pseudo-table is already collapsed inside one detected row, changing only the Markdown flavor usually will not fix it
  if the active engine build recovers the pseudo-table structure, prefer fixing residual boundary artifacts before escalating to hybrid/full mode

- For conversions where images are not requested:
  add `--image-output off`

- For slide decks, medical reports, and structure-sensitive PDFs:
  prefer validating both the
