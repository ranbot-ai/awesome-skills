---
name: agent-framework-azure-ai-py
description: Build Azure AI Foundry agents using the Microsoft Agent Framework Python SDK (agent-framework-azure-ai). Use when creating persistent agents with AzureAIAgentsProvider, using hosted tools (code interp
category: AI & Agents
source: antigravity
tags: [python, api, mcp, ai, agent, gpt, workflow, azure, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/agent-framework-azure-ai-py
---


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

## Installation

```bash
# Full framework (recommended)
pip install agent-framework --pre

# Or Azure-specific package only
pip install agent-framework-azure-ai --pre
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
    """Get the current weather for a location."""
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
        print(result.text)
```

### Streaming Responses

```python
async def main():
    async with (
        AzureCliCredential() as credential,
        AzureAIAgentsProvider(credential=credential) as provider,
    ):
        agent = await provider.create_agent(
            name="StreamingAgent",
            instructions="You are a helpful assistant.",
        )
        
        print("Agent: ", end="", flush=True)
        async for chunk in agent.run_stream("Tell me a short story"):
            if chunk.text:
                print(chunk.text, end="", flush=True)
        print()
```

### Conversation Threads

```python
from agent_framework.azure import AzureAIAgentsProvider
from azure.identity.aio import AzureCliCredential

async def main():
    async with (
        AzureCliCredential() as credential,
        AzureAIAgentsProvider(credential=credential) as provider,
    ):
        agent = await provider.create_agent(
            name="ChatAgent",
            instructions="You are a helpful assistant.",
            tools=[get_weather],
        )
        
        # Create thread for conversation persistence
        thread = agent.get_new_thread()
        
        # First turn
        result1 = await agent.run("What's the weather in Seattle?", thread=thread)
        print(f"Agent: {result1.text}")
        
        # Second turn - context is maintained
        result2 = await agent.run("What about Portland?", thread=thr
