---
name: hugging-face-datasets
description: Create and manage datasets on Hugging Face Hub. Supports initializing repos, defining configs/system prompts, streaming row updates, and SQL-based dataset querying/transformation. Designed to work alo
category: Creative & Media
source: antigravity
tags: [python, api, mcp, ai, workflow, template, design]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/hugging-face-datasets
---


# Overview
This skill provides tools to manage datasets on the Hugging Face Hub with a focus on creation, configuration, content management, and SQL-based data manipulation. It is designed to complement the existing Hugging Face MCP server by providing dataset editing and querying capabilities.

## When to Use
- You need to create, configure, or update datasets on the Hugging Face Hub.
- You want SQL-style querying, transformation, or export flows over Hub datasets.
- You are managing dataset content and metadata directly rather than only searching existing datasets.

## Integration with HF MCP Server
- **Use HF MCP Server for**: Dataset discovery, search, and metadata retrieval
- **Use This Skill for**: Dataset creation, content editing, SQL queries, data transformation, and structured data formatting

# Version
2.1.0

# Dependencies
# This skill uses PEP 723 scripts with inline dependency management
# Scripts auto-install requirements when run with: uv run scripts/script_name.py

- uv (Python package manager)
- Getting Started: See "Usage Instructions" below for PEP 723 usage

# Core Capabilities

## 1. Dataset Lifecycle Management
- **Initialize**: Create new dataset repositories with proper structure
- **Configure**: Store detailed configuration including system prompts and metadata
- **Stream Updates**: Add rows efficiently without downloading entire datasets

## 2. SQL-Based Dataset Querying (NEW)
Query any Hugging Face dataset using DuckDB SQL via `scripts/sql_manager.py`:
- **Direct Queries**: Run SQL on datasets using the `hf://` protocol
- **Schema Discovery**: Describe dataset structure and column types
- **Data Sampling**: Get random samples for exploration
- **Aggregations**: Count, histogram, unique values analysis
- **Transformations**: Filter, join, reshape data with SQL
- **Export & Push**: Save results locally or push to new Hub repos

## 3. Multi-Format Dataset Support
Supports diverse dataset types through template system:
- **Chat/Conversational**: Chat templating, multi-turn dialogues, tool usage examples
- **Text Classification**: Sentiment analysis, intent detection, topic classification
- **Question-Answering**: Reading comprehension, factual QA, knowledge bases
- **Text Completion**: Language modeling, code completion, creative writing
- **Tabular Data**: Structured data for regression/classification tasks
- **Custom Formats**: Flexible schema definition for specialized needs

## 4. Quality Assurance Features
- **JSON Validation**: Ensures data integrity during uploads
- **Batch Processing**: Efficient handling of large datasets
- **Error Recovery**: Graceful handling of upload failures and conflicts

# Usage Instructions

The skill includes two Python scripts that use PEP 723 inline dependency management:

> **All paths are relative to the directory containing this SKILL.md
file.**
> Scripts are run with: `uv run scripts/script_name.py [arguments]`

- `scripts/dataset_manager.py` - Dataset creation and management
- `scripts/sql_manager.py` - SQL-based dataset querying and transformation

### Prerequisites
- `uv` package manager installed
- `HF_TOKEN` environment variable must be set with a Write-access token

---

# SQL Dataset Querying (sql_manager.py)

Query, transform, and push Hugging Face datasets using DuckDB SQL. The `hf://` protocol provides direct access to any public dataset (or private with token).

## Quick Start

```bash
# Query a dataset
uv run scripts/sql_manager.py query \
  --dataset "cais/mmlu" \
  --sql "SELECT * FROM data WHERE subject='nutrition' LIMIT 10"

# Get dataset schema
uv run scripts/sql_manager.py describe --dataset "cais/mmlu"

# Sample random rows
uv run scripts/sql_manager.py sample --dataset "cais/mmlu" --n 5

# Count rows with filter
uv run scripts/sql_manager.py count --dataset "cais/mmlu" --where "subject='nutrition'"
```

## SQL Query Syntax

Use `data` as the table name in your SQL - it gets replaced with the actual `hf://` path:

```sql
-- Basic select
SELECT * FROM data LIMIT 10

-- Filtering
SELECT * FROM data WHERE subject='nutrition'

-- Aggregations
SELECT subject, COUNT(*) as cnt FROM data GROUP BY subject ORDER BY cnt DESC

-- Column selection and transformation
SELECT question, choices[answer] AS correct_answer FROM data

-- Regex matching
SELECT * FROM data WHERE regexp_matches(question, 'nutrition|diet')

-- String functions
SELECT regexp_replace(question, '\n', '') AS cleaned FROM data
```

## Common Operations

### 1. Explore Dataset Structure
```bash
# Get schema
uv run scripts/sql_manager.py describe --dataset "cais/mmlu"

# Get unique values in column
uv run scripts/sql_manager.py unique --dataset "cais/mmlu" --column "subject"

# Get value distribution
uv run scripts/sql_manager.py histogram --dataset "cais/mmlu" --column "subject" --bins 20
```

### 2. Filter and Transform
```bash
# Complex filtering with SQL
uv run scripts/sql_manager.py query \
  --dataset "cais/mmlu" \
  --sql "SELECT subject, COUNT(*) as cnt FROM data 
