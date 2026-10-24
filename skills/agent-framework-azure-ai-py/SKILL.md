---
name: agent-framework-azure-ai-py
description: Build persistent agents on Azure AI Foundry using the Microsoft Agent Framework Python SDK. 
category: AI & Agents
source: antigravity
tags: [python, api, mcp, ai, agent, gpt, workflow, document, azure, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/agent-framework-azure-ai-py
---

## Bundled upstream support

Supporting files are included at skill-relative paths. See [UPSTREAM-NOTICE.md](UPSTREAM-NOTICE.md) for their pinned sources, licenses, hashes, and import changes.

# Agent Framework Azure Hosted Agents

Build persistent agents on Azure AI Foundry using the Microsoft Agent Framework Python SDK.

## Architecture

```
User Query → AzureAIAgentsProvider → Azure AI Agent Service (Persistent)
                    ↓
              Agent.run() / Agent.run_stream()
                    ↓
              Tools: Functions | Hosted (Code/Search/Web) | MCP
                    ↓
              AgentThread (conversation persistence)
```

## SDK generation and execution scope

The examples below preserve an older Agent Framework generation (`AzureAIAgentsProvider`, `AgentThread`, `Hosted*Tool`). They are not verified against the current package. Current Microsoft documentation separates model providers from agent services, and the Python README lists `agent-framework-foundry`. Before adapting these snippets, identify the installed version and use its matching official API/sample; no compatible legacy version is established here. Do not combine the old classes with an unpinned latest install and assume it works.

Choose the exact Azure tenant/project/deployment, principal and least-privilege role. Creating agents, uploading files, enabling code/web/MCP tools and running prompts sends data to services, can persist records and incur charges. Scope authorization, budget, timeout, tool allowlist and resource cleanup first. Closing clients does not delete hosted agents/files/vector stores/threads. Treat retrieved/tool text as untrusted and enforce tenant/resource/action authorization in tools; prompts are not access controls.

## Installation

```bash
# Current package discovery only; pin reviewed versions in your project lockfile.
# These installs do not make the legacy snippets below compatible.
pip install agent-framework
# Selective current Foundry integration:
pip install agent-framework-foundry
```

## Environment Variables

```bash
export AZURE_AI_PROJECT_ENDPOINT="https://<project>.services.ai.azure.com/api/projects/<project-id>"
export AZURE_AI_MODEL_DEPLOYMENT_NAME="gpt-4o-mini"
export BING_CONNECTION_ID="your-bing-connection-id"  # For web search
```

## Authentication

```python
from azure.identity.aio import AzureCliCredential, DefaultAzureCredential

# Development
credential = AzureCliCredential()

# Production
credential = DefaultAzureCredential()
```

## Core Workflow

### Basic Agent

```python
import asyncio
from agent_framework.azure import AzureAIAgentsProvider
from azure.identity.aio import AzureCliCredential

async def main():
    async with (
        AzureCliCredential() as credential,
        AzureAIAgentsProvider(credential=credential) as provider,
    ):
        agent = await provider.create_agent(
            name="MyAgent",
            instructions="You are a helpful assistant.",
        )
        
        result = await agent.run("Hello!")
        print(result.text)

asyncio.run(main())
```

### Agent with Function Tools

```python
from typing import Annotated
from pydantic import Field
from agent_framework.azure import AzureAIAgentsProvider
from azure.identity.aio import AzureCliCredential

def get_weather(
    location: Annotated[str, Field(description="City name to get weather for")],
) -> str:
    """Return fixture weather (not a live observation)."""
    return f"Weather in {location}: 72°F, sunny"

def get_current_time() -> str:
    """Get the current UTC time."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

async def main():
    async with (
        AzureCliCredential() as credential,
        AzureAIAgentsProvider(credential=credential) as provider,
    ):
        agent = await provider.create_agent(
            name="WeatherAgent",
            instructions="You help with weather and time queries.",
            tools=[get_weather, get_current_time],  # Pass functions directly
        )
        
        result = await agent.run("What's the weather in Seattle?")
        print(result.text)
```

### Agent with Hosted Tools

```python
from agent_framework import (
    HostedCodeInterpreterTool,
    HostedFileSearchTool,
    HostedWebSearchTool,
)
from agent_framework.azure import AzureAIAgentsProvider
from azure.identity.aio import AzureCliCredential

async def main():
    async with (
        AzureCliCredential() as credential,
        AzureAIAgentsProvider(credential=credential) as provider,
    ):
        agent = await provider.create_agent(
            name="MultiToolAgent",
            instructions="You can execute code, search files, and search the web.",
            tools=[
                HostedCodeInterpreterTool(),
                HostedWebSearchTool(name="Bing"),
            ],
        )
        
        result = await agent.run("Calculate the factorial of 20 in Python")
        print(result.t
