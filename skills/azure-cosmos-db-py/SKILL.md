---
name: azure-cosmos-db-py
description: Build production-grade Azure Cosmos DB NoSQL services following clean code, security best practices, and TDD principles. 
category: Document Processing
source: antigravity
tags: [python, api, ai, workflow, template, document, security, azure, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-cosmos-db-py
---

## Bundled upstream support

Supporting files are included at skill-relative paths. See [UPSTREAM-NOTICE.md](UPSTREAM-NOTICE.md) for their pinned sources, licenses, hashes, and import changes.

## Restored helper safety

The integration fixture in `assets/conftest_template.py` connects to the configured Cosmos endpoint; `cleanup_test_docs` deletes records explicitly added to its tracking list. Use only an isolated disposable test container with test-only records, never production data. Copying the template does not connect to Cosmos.

# Cosmos DB Service Implementation

Review corrections (2026-10-23): these snippets are incomplete application starters. Initialize the synchronous client during startup outside the event loop, serialize initialization and close client/credential on shutdown. A cached failed initialization needs an explicit bounded recovery path. `azure.cosmos.aio` is also available; the SDK is not synchronous-only. Enforce tenant authorization independently of partition routing; the bundled client assumes `/workspaceId`. Never accept caller SQL fragments. Distinguish unavailable storage (503) from not-found (404) and empty data; the older graceful-default examples below illustrate a policy to avoid for authoritative reads. Use ETag conditional writes to prevent lost updates, enforce uniqueness atomically, and implement cross-partition moves with conflict-aware compensation; read-then-upsert/delete is not atomic. No live Cosmos behavior is verified by these templates.



Build production-grade Azure Cosmos DB NoSQL services following clean code, security best practices, and TDD principles.

## Installation

```bash
pip install azure-cosmos azure-identity
```

## Environment Variables

```bash
COSMOS_ENDPOINT=https://<account>.documents.azure.com:443/
COSMOS_DATABASE_NAME=<database-name>
COSMOS_CONTAINER_ID=<container-id>
# For emulator only (not production)
COSMOS_KEY=<emulator-key>
```

## Authentication

**DefaultAzureCredential (preferred)**:
```python
from azure.cosmos import CosmosClient
from azure.identity import DefaultAzureCredential

client = CosmosClient(
    url=os.environ["COSMOS_ENDPOINT"],
    credential=DefaultAzureCredential()
)
```

**Emulator (local development)**:
```python
from azure.cosmos import CosmosClient

client = CosmosClient(
    url="https://localhost:8081",
    credential=os.environ["COSMOS_KEY"],
    connection_verify=False
)
```

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         FastAPI Router                          │
│  - Auth dependencies (get_current_user, get_current_user_required)
│  - HTTP error responses (HTTPException)                         │
└──────────────────────────────┬──────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│                        Service Layer                            │
│  - Business logic and validation                                │
│  - Document ↔ Model conversion                                  │
│  - Graceful degradation when Cosmos unavailable                 │
└──────────────────────────────┬──────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│                     Cosmos DB Client Module                     │
│  - Singleton container initialization                           │
│  - Dual auth: DefaultAzureCredential (Azure) / Key (emulator)   │
│  - Async wrapper via run_in_threadpool                          │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Client Module Setup

Create a singleton Cosmos client with dual authentication:

```python
# db/cosmos.py
from azure.cosmos import CosmosClient
from azure.identity import DefaultAzureCredential
from starlette.concurrency import run_in_threadpool

_cosmos_container = None

def _is_emulator_endpoint(endpoint: str) -> bool:
    from urllib.parse import urlsplit
    parsed = urlsplit(endpoint)
    return (parsed.scheme == "https" and parsed.username is None
            and parsed.password is None
            and parsed.hostname in {"localhost", "127.0.0.1", "::1"})

def get_container():
    global _cosmos_container
    if _cosmos_container is None:
        if _is_emulator_endpoint(settings.cosmos_endpoint):
            client = CosmosClient(
                url=settings.cosmos_endpoint,
                credential=settings.cosmos_key,
                connection_verify=False
            )
        else:
            client = CosmosClient(
                url=settings.cosmos_endpoint,
                credential=DefaultAzureCredential()
            )
        db = client.get_database_client(settings.cosmos_database_name)
        _cosmos_container = db.get_container_client(settings.cosmos_container_id)
    return _cosmos_container
```

**Full implementation**: See references/client-setup.md
