---
name: dsh-deepread
description: Use for evidence-first reading of articles, books, PDFs, web pages, or document sets, with knowledge maps and Feynman checks. 
category: Document Processing
source: antigravity
tags: [node, pdf, claude, ai, agent, workflow, document, security, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/dsh-deepread
---


# DeepRead

## Overview

DeepRead turns long-form material into an evidence-first reading report. It separates claims, evidence, data, examples, assumptions, counterarguments, and limitations instead of producing an untraceable summary.

The workflow supports five modes: quick orientation, deep argument analysis, knowledge mapping, Feynman explanation, and whole-book synthesis. Use the host agent's available file, PDF, OCR, and web-reading tools; never invent source content that was not successfully retrieved.

## When to Use

- Use when a user asks to read, summarize, or critically analyze an article, book, PDF, web page, or document collection.
- Use when important claims must remain connected to evidence and source locations.
- Use when the user wants a mind map, concept map, comparison matrix, or structured study notes.
- Use when the user wants to test understanding with plain-language explanations or recall questions.
- Use when multiple documents need to be compared without collapsing disagreements into one answer.

## Choose a Mode

| Mode | Use it for | Required output |
| --- | --- | --- |
| `quick` | Orientation or time-limited reading | Short summary, core claim, up to three supporting points, open questions |
| `deep` | Argument analysis | Claim hierarchy, reasoning chain, evidence, concepts, counterarguments, limitations |
| `map` | Knowledge organization | Claim-evidence-data table, labeled relationships, confidence tags, concept map |
| `feynman` | Understanding and retention | Plain-language explanation, knowledge gaps, corrections, recall plan |
| `book` | Whole-book synthesis | Chapter map, thesis development, cross-chapter links, final evaluation |

Default to `deep` unless the user names another mode or the time budget clearly calls for `quick`.

## How It Works

### Step 1: Establish the Reading Contract

Record:

1. The source or set of sources.
2. The user's reading question.
3. The selected mode.
4. The desired depth and output format.
5. Any deadline, token budget, or chapter limit.

If the source cannot be accessed, stop and request the text or a readable file. Do not fill gaps from memory.

### Step 2: Survey Before Reading Closely

Inspect the title, author, date, table of contents, headings, abstract or introduction, conclusion, figures, and tables. Convert the structure into three to seven questions the reading should answer.

For a long source, divide it on semantic boundaries such as chapters or headings. Keep a progress list and synthesize only after every selected section has been processed.

### Step 3: Extract Atomic Reading Units

Each note should contain one idea and one type:

- `claim`: a conclusion the author wants the reader to accept;
- `reason`: a premise or mechanism supporting a claim;
- `evidence`: a quotation, observation, method, or source-backed result;
- `data`: a numeric fact with unit, time, population, baseline, and source when available;
- `example`: an illustration that must not be treated as general proof;
- `assumption`: an unstated dependency of the argument;
- `counterargument`: a challenge or alternative explanation;
- `limitation`: a boundary on where the claim applies;
- `action`: a recommendation that follows from the analysis.

Keep the author's statements separate from the agent's inference and the user's interpretation.

### Step 4: Build the Evidence Ledger

For every important claim, record:

| Field | Requirement |
| --- | --- |
| Claim | Complete proposition, not a topic label |
| Evidence | Source passage or faithful paraphrase |
| Location | Page, section, paragraph, timestamp, or URL anchor when available |
| Data context | Value, unit, timeframe, sample, baseline, source |
| Relationship | Supports, contradicts, causes, explains, depends on, exemplifies, or limits |
| Confidence | Author claim, source fact, reasoned inference, or unverified |
| Caveat | Missing evidence, alternative explanation, or applicability boundary |

Write `source does not provide evidence` when appropriate. Never manufacture a supporting quotation or location.

### Step 5: Produce the Mode-Specific Artifact

For `deep`, organize the report as:

1. Reading question and concise answer.
2. Core thesis and subclaims.
3. Argument flow with evidence.
4. Key concepts and definitions.
5. Strongest evidence and weakest link.
6. Counterarguments and limitations.
7. Practical implications.

For `map`, create labeled propositions rather than an unlabeled topic tree. A useful edge reads as a sentence, for example: `retrieval practice --improves--> delayed recall`.

For `book`, preserve chapter order during extraction, then reorganize the final map around the book's central question instead of copying the table of contents.

### Step 6: Run the Feynman Check

Without looking at the source, explain the central idea to an intelligent twelve-year-old:

1. Define it in plain language.
2. Explain the mechanism step by step.
3. Give a concrete example.
4. State where the expla
