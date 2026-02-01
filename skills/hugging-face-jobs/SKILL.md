---
name: hugging-face-jobs
description: This skill should be used when users want to run any workload on Hugging Face Jobs infrastructure. Covers UV scripts, Docker-based jobs, hardware selection, cost estimation, authentication with tokens
category: Document Processing
source: antigravity
tags: [python, pdf, api, mcp, ai, llm, workflow, template, design, document]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/hugging-face-jobs
---


# Running Workloads on Hugging Face Jobs

## Overview

Run any workload on fully managed Hugging Face infrastructure. No local setup required—jobs run on cloud CPUs, GPUs, or TPUs and can persist results to the Hugging Face Hub.

**Common use cases:**
- **Data Processing** - Transform, filter, or analyze large datasets
- **Batch Inference** - Run inference on thousands of samples
- **Experiments & Benchmarks** - Reproducible ML experiments
- **Model Training** - Fine-tune models (see `model-trainer` skill for TRL-specific training)
- **Synthetic Data Generation** - Generate datasets using LLMs
- **Development & Testing** - Test code without local GPU setup
- **Scheduled Jobs** - Automate recurring tasks

**For model training specifically:** See the `model-trainer` skill for TRL-based training workflows.

## When to Use This Skill

Use this skill when users want to:
- Run Python workloads on cloud infrastructure
- Execute jobs without local GPU/TPU setup
- Process data at scale
- Run batch inference or experiments
- Schedule recurring tasks
- Use GPUs/TPUs for any workload
- Persist results to the Hugging Face Hub

## Key Directives

When assisting with jobs:

1. **ALWAYS use `hf_jobs()` MCP tool** - Submit jobs using `hf_jobs("uv", {...})` or `hf_jobs("run", {...})`. The `script` parameter accepts Python code directly. Do NOT save to local files unless the user explicitly requests it. Pass the script content as a string to `hf_jobs()`.

2. **Always handle authentication** - Jobs that interact with the Hub require `HF_TOKEN` via secrets. See Token Usage section below.

3. **Provide job details after submission** - After submitting, provide job ID, monitoring URL, estimated time, and note that the user can request status checks later.

4. **Set appropriate timeouts** - Default 30min may be insufficient for long-running tasks.

## Prerequisites Checklist

Before starting any job, verify:

### ✅ **Account & Authentication**
- Hugging Face Account with [Pro](https://hf.co/pro), [Team](https://hf.co/enterprise), or [Enterprise](https://hf.co/enterprise) plan (Jobs require paid plan)
- Authenticated login: Check with `hf_whoami()`
- **HF_TOKEN for Hub Access** ⚠️ CRITICAL - Required for any Hub operations (push models/datasets, download private repos, etc.)
- Token must have appropriate permissions (read for downloads, write for uploads)

### ✅ **Token Usage** (See Token Usage section for details)

**When tokens are required:**
- Pushing models/datasets to Hub
- Accessing private repositories
- Using Hub APIs in scripts
- Any authenticated Hub operations

**How to provide tokens:**
```python
{
    "secrets": {"HF_TOKEN": "$HF_TOKEN"}  # Recommended: automatic token
}
```

**⚠️ CRITICAL:** The `$HF_TOKEN` placeholder is automatically replaced with your logged-in token. Never hardcode tokens in scripts.

## Token Usage Guide

### Understanding Tokens

**What are HF Tokens?**
- Authentication credentials for Hugging Face Hub
- Required for authenticated operations (push, private repos, API access)
- Stored securely on your machine after `hf auth login`

**Token Types:**
- **Read Token** - Can download models/datasets, read private repos
- **Write Token** - Can push models/datasets, create repos, modify content
- **Organization Token** - Can act on behalf of an organization

### When Tokens Are Required

**Always Required:**
- Pushing models/datasets to Hub
- Accessing private repositories
- Creating new repositories
- Modifying existing repositories
- Using Hub APIs programmatically

**Not Required:**
- Downloading public models/datasets
- Running jobs that don't interact with Hub
- Reading public repository information

### How to Provide Tokens to Jobs

#### Method 1: Automatic Token (Recommended)

```python
hf_jobs("uv", {
    "script": "your_script.py",
    "secrets": {"HF_TOKEN": "$HF_TOKEN"}  # ✅ Automatic replacement
})
```

**How it works:**
- `$HF_TOKEN` is a placeholder that gets replaced with your actual token
- Uses the token from your logged-in session (`hf auth login`)
- Most secure and convenient method
- Token is encrypted server-side when passed as a secret

**Benefits:**
- No token exposure in code
- Uses your current login session
- Automatically updated if you re-login
- Works seamlessly with MCP tools

#### Method 2: Explicit Token (Not Recommended)

```python
hf_jobs("uv", {
    "script": "your_script.py",
    "secrets": {"HF_TOKEN": "hf_abc123..."}  # ⚠️ Hardcoded token
})
```

**When to use:**
- Only if automatic token doesn't work
- Testing with a specific token
- Organization tokens (use with caution)

**Security concerns:**
- Token visible in code/logs
- Must manually update if token rotates
- Risk of token exposure

#### Method 3: Environment Variable (Less Secure)

```python
hf_jobs("uv", {
    "script": "your_script.py",
    "env": {"HF_TOKEN": "hf_abc123..."}  # ⚠️ Less secure than secrets
})
```

**Difference from secrets:**
- `env` variables are visible in job logs
- `secrets` are en
