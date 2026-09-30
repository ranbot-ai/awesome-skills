---
name: csv-manual-export
description: CSV Manual Export: a UTF-8 CSV template from a confirmed field list, empty by default, with no invented columns or values. Use for an import, staging or handoff file. 
category: Document Processing
source: antigravity
tags: [api, ai, agent, workflow, template, design, document, spreadsheet, presentation, image]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/csv-manual-export
---


# CSV Manual Export

**What it is:** a clean, empty CSV of a field list someone already confirmed - the
transport format, with nothing invented and nothing hidden.

## Overview

Produces a CSV representation of a confirmed business schema. Use it for CSV templates,
import files, Excel-compatible CSV, a Notion import CSV, a database staging CSV, or a
handoff file between systems.

CSV is data transport, not a database. This is a helper: it defines no table of its own
and renders whatever field list the active module already confirmed, so the header here
is the same header the module emits.

Layer: n/a. Fits: every stage. Table code: n/a - it renders the active module's table.

## When to Use This Skill

- give me a CSV template
- export this as a CSV
- I need a file to import into another system
- stage this data for a load
- hand this over to another team as a CSV
- make it Notion-importable

Also use it when a module has confirmed a field list and the user wants that list as a
file for a system that is not this repository's.

Do not use it when the user asked only for a mapping, an explanation, or a different
format. Then output only what was asked for.

## How It Works

Follow the shared execution contract. The module-specific rules below define only domain fields, decisions, calculations, and safety constraints.

### Step 1 - Identify intent

Read the request and pick the intent before asking anything.

- "a template" -> an empty CSV template: header row, no data rows.
- "with a couple of rows to see the shape" -> a CSV with example rows, only when asked,
  and obviously fake.
- "this import rejected my file", "the columns are wrong" -> CSV correction: only the
  columns or escaping that was asked for.
- "what goes in which column" -> CSV column mapping: the mapping, no file.
- "for Notion", "to load into the accounting package" -> CSV for import into that system,
  which may need an encoding or a delimiter the user names.

Default to no example rows and to UTF-8:

```yaml
example_rows: false
encoding: UTF-8
```

Use UTF-8 with a byte order mark when Excel compatibility matters. Ask for a delimiter
only when the target system is one the user has named and its delimiter is not a comma.

### Step 2 - Ask only what is missing

Reuse everything already confirmed, including by the module that owns the field list: the
field names and types, the select options, the date and currency fields, the statuses and
the IDs. Never ask again for information the user has already supplied.

Ask one short question per message, and only when the answer changes the file:

> **Q:** Do you want the header only, or a couple of example rows?

> **Q:** Which system is importing this file?

If the answer does not materially change the result, do not ask.

### Step 3 - Hold the internal context

Hold the answers in this shape. It stays internal - it is not shown to the user unless
they ask, and it never carries a value the user did not give.

```yaml
module: csv-manual-export
intent: null            # set in Step 1, one of: template, examples, import, correction, mapping
source_module: null     # the module whose field list this renders
target_system: null     # named only when the user names one
delimiter: ","
encoding: UTF-8
bom: true               # false only when the target system rejects a byte order mark
example_rows: false
confirmed_facts: []     # only what the user actually said
open_questions: []      # the unanswered ones, in the order worth asking
```

`source_module` is the one field this skill needs that a module skill does not have. If it
is unknown, ask which list to export, because a header invented from a guess is a header
the user has to fix by hand.

### Step 4 - Recommend the smallest workflow

Produce an already requested output without asking again. For advice-only requests, give a short recommendation and offer the relevant output.

**Recommended approach:** one UTF-8 file, a header of the exact field names in the
canonical order, and no rows. Add a one-line type note beside it if the importing system
needs one.

**Why this one:** a CSV carries no types, formulas, relations or validation. The file is
the easy half; the columns that come in as Text on the far side are the half that decides
whether the import was worth doing.

**Workflow:** Field list confirmed -> Header written -> Encoding and delimiter set ->
(imported) -> Column types set on the far side

### Step 5 - Build only on request

Once the user asks, emit the CSV as data only. Keep prose outside machine-readable data; provide file links and material limitations separately.
Do not add SQL, JSON or a Notion mapping unless it was asked for - a file plus a paragraph
of explanation is not what "just the CSV" means.

#### The header

Every header comes from the confirmed field list, in the canonical order. Never rename a
column silently, reorder columns without reason, invent a column, or drop a field.

#### Empty by default

```csv
Field 1,Field 2,Fie
