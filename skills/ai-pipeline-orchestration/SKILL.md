---
name: ai-pipeline-orchestration
description: Orchestrate AI/ML pipelines for data ingestion, model training, batch inference, and RAG indexing using Prefect, Airflow, or Dagster. 
category: Document Processing
source: antigravity
tags: [python, node, api, ai, agent, llm, gpt, workflow, template, document]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/ai-pipeline-orchestration
---


# AI Pipeline Orchestration

Build reliable, observable AI workflows — from document ingestion to batch inference to model training pipelines.

## When to Use This Skill

Use this skill when:
- Scheduling recurring RAG document ingestion and re-indexing
- Orchestrating multi-step batch LLM processing workflows
- Running nightly model evaluation and fine-tuning jobs
- Building ETL pipelines that feed into AI models
- Managing dependencies between data preparation and model serving

## Tool Selection

| Tool | Best For | Complexity | GPU Jobs |
|------|----------|------------|----------|
| **Prefect** | Modern Python-first; easy to adopt | Low | Good |
| **Airflow** | Complex DAGs; large teams; existing usage | High | Good |
| **Dagster** | Asset-centric; strong data lineage | Medium | Excellent |
| **Temporal** | Long-running workflows; reliability-first | Medium | Good |

## Prefect — Quick Start

```bash
pip install prefect prefect-kubernetes

# Start Prefect server (or use Prefect Cloud)
prefect server start

# In another terminal
prefect worker start --pool default-agent-pool
```

## Prefect: RAG Ingestion Pipeline

```python
from prefect import flow, task, get_run_logger
from prefect.tasks import task_input_hash
from datetime import timedelta
import hashlib

@task(cache_key_fn=task_input_hash, cache_expiration=timedelta(hours=24))
def fetch_documents(source_url: str) -> list[dict]:
    """Fetch documents from source; cached to avoid re-fetching."""
    logger = get_run_logger()
    logger.info(f"Fetching from {source_url}")
    # ... fetch logic
    return documents

@task(retries=3, retry_delay_seconds=30)
def chunk_and_embed(documents: list[dict]) -> list[dict]:
    """Chunk documents and generate embeddings with retry on failure."""
    from sentence_transformers import SentenceTransformer
    model = SentenceTransformer("BAAI/bge-large-en-v1.5")
    chunks = []
    for doc in documents:
        doc_chunks = chunk_text(doc["content"])
        embeddings = model.encode(doc_chunks, batch_size=64)
        for chunk, emb in zip(doc_chunks, embeddings):
            chunks.append({"text": chunk, "embedding": emb.tolist(),
                           "source": doc["url"], "doc_hash": doc["hash"]})
    return chunks

@task(retries=2)
def upsert_to_vector_store(chunks: list[dict]) -> int:
    """Upsert embeddings to Qdrant, skip unchanged documents."""
    from qdrant_client import QdrantClient
    client = QdrantClient("http://qdrant:6333")
    client.upsert(collection_name="knowledge-base", points=[...])
    return len(chunks)

@flow(name="rag-ingestion", log_prints=True)
def rag_ingestion_pipeline(sources: list[str]):
    """Full RAG ingestion flow — runs daily."""
    logger = get_run_logger()
    total = 0
    for source in sources:
        docs = fetch_documents(source)
        chunks = chunk_and_embed(docs)
        count = upsert_to_vector_store(chunks)
        total += count
        logger.info(f"Ingested {count} chunks from {source}")
    logger.info(f"Pipeline complete: {total} total chunks indexed")

if __name__ == "__main__":
    rag_ingestion_pipeline.serve(
        name="daily-rag-ingestion",
        cron="0 2 * * *",          # 2 AM daily
        parameters={"sources": ["https://docs.myapp.com", "https://api.myapp.com/kb"]},
    )
```

## Prefect: Batch LLM Inference Pipeline

```python
from prefect import flow, task
from prefect.concurrency.sync import concurrency
import asyncio
from openai import AsyncOpenAI

@task(retries=3, retry_delay_seconds=60)
async def process_batch(items: list[dict], model: str = "gpt-4o-mini") -> list[dict]:
    """Process a batch of items through LLM with rate limit protection."""
    client = AsyncOpenAI()
    async with concurrency("openai-api", occupy=len(items)):  # rate limit
        tasks = [
            client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": item["prompt"]}],
                max_tokens=256,
            )
            for item in items
        ]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

    results = []
    for item, response in zip(items, responses):
        if isinstance(response, Exception):
            results.append({**item, "error": str(response), "output": None})
        else:
            results.append({**item, "output": response.choices[0].message.content})
    return results

@flow(name="batch-llm-inference")
async def batch_inference_flow(input_file: str, output_file: str, batch_size: int = 50):
    import json
    items = [json.loads(line) for line in open(input_file)]
    batches = [items[i:i+batch_size] for i in range(0, len(items), batch_size)]

    all_results = []
    for batch in batches:
        results = await process_batch(batch)
        all_results.extend(results)

    with open(output_file, "w") as f:
        for result in all_results:
            f.write(json.dumps(result) + "\n")
    return len(all_results)
```

## Airflow: Model 
