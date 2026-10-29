---
name: bifrost-gateway
description: Run and configure Bifrost, the open-source AI gateway: one OpenAI-compatible API for 20+ LLM providers with fallbacks, virtual keys and budgets, semantic caching, observability and an MCP gateway. 
category: Document Processing
source: antigravity
tags: [python, node, api, mcp, claude, ai, agent, llm, gpt, document]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/bifrost-gateway
---


# Bifrost AI Gateway

## Overview

[Bifrost](https://github.com/maximhq/bifrost) is an open-source (Apache-2.0), self-hosted AI gateway written in Go. It puts 20+ providers (OpenAI, Anthropic, AWS Bedrock, Google Vertex and Gemini, Azure OpenAI, Mistral, Groq, Ollama, vLLM and others) behind one OpenAI-compatible API, and adds fallbacks, weighted load balancing, virtual keys with budgets and rate limits, semantic caching, request logging, Prometheus and OpenTelemetry export, and an MCP gateway. Applications keep their existing SDKs and change only the base URL. Documentation: https://docs.getbifrost.ai

## When to Use This Skill

- One application or agent needs several LLM providers behind a single endpoint
- Provider failover, retries or key load balancing should live in config, not application code
- Teams, customers or apps need their own keys with spend budgets and rate limits
- Repeated or similar prompts should be served from a cache
- LLM traffic needs request logs, cost tracking, Prometheus metrics or OpenTelemetry traces
- Several MCP servers should be exposed to agents through one governed endpoint
- Claude Code, Codex CLI or another coding agent should run through a self-hosted gateway

Not a fit when the user cannot run a service at all (Bifrost is self-hosted), or for model training and fine-tuning.

## How It Works

### 1. Start the gateway

```bash
# Node.js: download and run the binary
npx -y @maximhq/bifrost

# Docker: persist config and logs in ./data
docker run -p 8080:8080 -v $(pwd)/data:/app/data maximhq/bifrost
```

- The gateway and web UI listen on port 8080 (`-port` with npx; `-e APP_PORT=...` plus `-p` with Docker). Open http://localhost:8080.
- Pin a version for anything beyond local evaluation: `maximhq/bifrost:<version>` or `npx -y @maximhq/bifrost --transport-version <version>`.
- A fresh instance has no dashboard password. Before exposing it beyond localhost, start it with `BIFROST_SETUP_TOKEN` set and enable password protection under Workspace → Config → Security.

### 2. Add providers

Use the web UI (Model Providers page), the management API, or `config.json` in the app directory (the mounted `./data` folder for Docker; `~/.config/bifrost` for npx unless `-app-dir` is set):

```json
{
  "$schema": "https://www.getbifrost.ai/schema",
  "providers": {
    "openai": {
      "keys": [{ "name": "openai-1", "value": "env.OPENAI_API_KEY", "models": ["*"], "weight": 1.0 }]
    },
    "anthropic": {
      "keys": [{ "name": "anthropic-1", "value": "env.ANTHROPIC_API_KEY", "models": ["*"], "weight": 1.0 }]
    }
  }
}
```

```bash
curl -X POST http://localhost:8080/api/providers \
  -H "Content-Type: application/json" \
  -d '{"provider": "openai", "keys": [{"name": "openai-1", "value": "env.OPENAI_API_KEY", "models": ["*"], "weight": 1.0}]}'
```

- `env.VAR_NAME` reads the secret from the gateway's environment. Never inline real keys.
- `"models": ["*"]` allows every model on that key; an empty list denies all models.

### 3. Send requests

Address models as `provider/model` on the OpenAI-compatible endpoint:

```bash
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model": "openai/gpt-4o-mini", "messages": [{"role": "user", "content": "Hello"}]}'
```

Existing SDKs only change their base URL:

| Client | Base URL |
|---|---|
| Any OpenAI-compatible client | `http://localhost:8080/v1` |
| OpenAI SDK | `http://localhost:8080/openai` |
| Anthropic SDK | `http://localhost:8080/anthropic` |
| Google GenAI SDK | `http://localhost:8080/genai` |
| LangChain | `http://localhost:8080/langchain` |

```python
import os
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8080/openai",
    api_key=os.environ["BIFROST_VIRTUAL_KEY"],
)
reply = client.chat.completions.create(
    model="anthropic/claude-sonnet-4-6",  # any configured provider through the same client
    messages=[{"role": "user", "content": "Summarize this ticket in one line."}],
)
```

### 4. Add fallbacks, retries and load balancing

- **Fallbacks:** list backup models in the request body. Each is tried in order after the primary fails, with its own retry budget.

  ```json
  {"model": "openai/gpt-4o-mini", "messages": [{"role": "user", "content": "Hi"}], "fallbacks": ["anthropic/claude-sonnet-4-6", "gemini/gemini-2.5-flash"]}
  ```

- **Retries:** set per provider in `network_config` (`"max_retries": 3`, `"retry_backoff_initial": 500`, `"retry_backoff_max": 5000`). The default is 0 retries. Keys rejected for credentials, quota or model access always move on to the next key; rotating away from a rate-limited (`429`) key needs `max_retries` above 0 and more than one key.
- **Key load balancing:** give a provider several keys with different `weight` values; Bifrost picks keys by weighted random selection.
- **Provider load balancing:** weight providers inside a virtual key's `provider_configs` (next step).

### 5. Govern access with virtual keys

Virtu
