---
name: monte-carlo-push-ingestion
description: Expert guide for pushing metadata, lineage, and query logs to Monte Carlo from any data warehouse. 
category: AI & Agents
source: antigravity
tags: [python, node, api, claude, ai, agent, template, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/monte-carlo-push-ingestion
---


# Monte Carlo Push Ingestion

You are an agent that helps customers collect metadata, lineage, and query logs from their
data warehouses and push that data to Monte Carlo via the push ingestion API. The push model
works with **any data source** — if the customer's warehouse does not have a ready-made
template, derive the appropriate collection queries from that warehouse's system catalog or
metadata APIs. The push format and pycarlo SDK calls are the same regardless of source.

Monte Carlo's push model lets customers send metadata, lineage, and query logs directly to
Monte Carlo instead of waiting for the pull collector to gather it. It fills gaps the pull
model cannot always cover — integrations that don't expose query history, custom lineage
between non-warehouse assets, or customers who already have this data and want to send it
directly.

## When to Use

Use this skill when the user needs to collect metadata, lineage, freshness, volume, or query-log data from a warehouse or adjacent system and push it into Monte Carlo through the push-ingestion API.

Push data travels through the integration gateway → dedicated Kinesis streams → thin
adapter/normalizer code → the same downstream systems that power the pull model. The only
new infrastructure is the ingress layer; everything after it is shared.

## MANDATORY — Always start from templates

When generating any push-ingestion script, you MUST:

1. **Read the corresponding template** before writing any code. Templates live in this skill's
   directory under `scripts/templates/<warehouse>/`. To find them, glob for
   `**/push-ingestion/scripts/templates/<warehouse>/*.py` — this works regardless of where the
   skill is installed. Do NOT search from the current working directory alone.
2. **Adapt the template** to the customer's needs — do not write pycarlo imports, model constructors,
   or SDK method calls from memory.
3. If no template exists for the target warehouse, read the **Snowflake template** as the canonical
   reference and adapt only the warehouse-specific collection queries.

Template files follow this naming pattern:
- `collect_<flow>.py` — collection only (queries the warehouse, writes a JSON manifest)
- `push_<flow>.py` — push only (reads the manifest, sends to Monte Carlo)
- `collect_and_push_<flow>.py` — combined (imports from both, runs in sequence)

**After running any push script**, you MUST surface the `invocation_id`(s) returned by the API
to the user. The invocation ID is the only way to trace pushed data through downstream systems
and is required for validation. Never let a push complete without showing the user the
invocation IDs — they need them for `/mc-validate-metadata`, `/mc-validate-lineage`, and
debugging.

## Canonical pycarlo API — authoritative reference

The following imports, classes, and method signatures are the **ONLY** correct pycarlo API for
push ingestion. If your training data suggests different names, **it is wrong**. Use exactly
what is listed here.

### Imports and client setup

```python
from pycarlo.core import Client, Session
from pycarlo.features.ingestion import IngestionService
from pycarlo.features.ingestion.models import (
    # Metadata
    RelationalAsset, AssetMetadata, AssetField, AssetVolume, AssetFreshness, Tag,
    # Lineage
    LineageEvent, LineageAssetRef, ColumnLineageField, ColumnLineageSourceField,
    # Query logs
    QueryLogEntry,
)

client = Client(session=Session(mcd_id=key_id, mcd_token=key_token, scope="Ingestion"))
service = IngestionService(mc_client=client)
```

### Method signatures

```python
# Metadata
service.send_metadata(resource_uuid=..., resource_type=..., events=[RelationalAsset(...)])

# Lineage (table or column)
service.send_lineage(resource_uuid=..., resource_type=..., events=[LineageEvent(...)])

# Query logs — note: log_type, NOT resource_type
service.send_query_logs(resource_uuid=..., log_type=..., events=[QueryLogEntry(...)])

# Extract invocation ID from any response
service.extract_invocation_id(result)
```

### RelationalAsset structure (nested, NOT flat)

```python
RelationalAsset(
    type="TABLE",  # ONLY "TABLE" or "VIEW" (uppercase) — normalize warehouse-native values
    metadata=AssetMetadata(
        name="my_table",
        database="analytics",
        schema="public",
        description="optional description",
    ),
    fields=[
        AssetField(name="id", type="INTEGER", description=None),
        AssetField(name="amount", type="DECIMAL(10,2)"),
    ],
    volume=AssetVolume(row_count=1000000, byte_count=111111111),  # optional
    freshness=AssetFreshness(last_update_time="2026-03-12T14:30:00Z"),  # optional
)
```

## Environment variable conventions

All generated scripts MUST use these exact variable names. Do NOT invent alternatives like
`MCD_KEY_ID`, `MC_TOKEN`, `MONTE_CARLO_KEY`, etc.

| Variable | Purpose | Used by |
|---|---|---|
| `MCD_INGEST_ID` | Ingestion key ID (scope=Ingestion) | push scripts |
| `MCD_INGEST_TOKEN` | Ingestion key se
