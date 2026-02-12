---
name: azure-ai-projects-py
description: Build AI applications using the Azure AI Projects Python SDK (azure-ai-projects). Use when working with Foundry project clients, creating versioned agents with PromptAgentDefinition, running evaluatio
category: Document Processing
source: antigravity
tags: [python, api, mcp, ai, agent, gpt, document, azure, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-ai-projects-py
---


# Azure AI Projects Python SDK (Foundry SDK)

Build AI applications on Microsoft Foundry using the `azure-ai-projects` SDK.

## Installation

```bash
pip install azure-ai-projects azure-identity
```

## Environment Variables

```bash
AZURE_AI_PROJECT_ENDPOINT="https://<resource>.services.ai.azure.com/api/projects/<project>"
AZURE_AI_MODEL_DEPLOYMENT_NAME="gpt-4o-mini"
```

## Authentication

```python
import os
from azure.identity import DefaultAzureCredential
from azure.ai.projects import AIProjectClient

credential = DefaultAzureCredential()
client = AIProjectClient(
    endpoint=os.environ["AZURE_AI_PROJECT_ENDPOINT"],
    credential=credential,
)
```

## Client Operations Overview

| Operation | Access | Purpose |
|-----------|--------|---------|
| `client.agents` | `.agents.*` | Agent CRUD, versions, threads, runs |
| `client.connections` | `.connections.*` | List/get project connections |
| `client.deployments` | `.deployments.*` | List model deployments |
| `client.datasets` | `.datasets.*` | Dataset management |
| `client.indexes` | `.indexes.*` | Index management |
| `client.evaluations` | `.evaluations.*` | Run evaluations |
| `client.red_teams` | `.red_teams.*` | Red team operations |

## Two Client Approaches

### 1. AIProjectClient (Native Foundry)

```python
from azure.ai.projects import AIProjectClient

client = AIProjectClient(
    endpoint=os.environ["AZURE_AI_PROJECT_ENDPOINT"],
    credential=DefaultAzureCredential(),
)

# Use Foundry-native operations
agent = client.agents.create_agent(
    model=os.environ["AZURE_AI_MODEL_DEPLOYMENT_NAME"],
    name="my-agent",
    instructions="You are helpful.",
)
```

### 2. OpenAI-Compatible Client

```python
# Get OpenAI-compatible client from project
openai_client = client.get_openai_client()

# Use standard OpenAI API
response = openai_client.chat.completions.create(
    model=os.environ["AZURE_AI_MODEL_DEPLOYMENT_NAME"],
    messages=[{"role": "user", "content": "Hello!"}],
)
```

## Agent Operations

### Create Agent (Basic)

```python
agent = client.agents.create_agent(
    model=os.environ["AZURE_AI_MODEL_DEPLOYMENT_NAME"],
    name="my-agent",
    instructions="You are a helpful assistant.",
)
```

### Create Agent with Tools

```python
from azure.ai.agents import CodeInterpreterTool, FileSearchTool

agent = client.agents.create_agent(
    model=os.environ["AZURE_AI_MODEL_DEPLOYMENT_NAME"],
    name="tool-agent",
    instructions="You can execute code and search files.",
    tools=[CodeInterpreterTool(), FileSearchTool()],
)
```

### Versioned Agents with PromptAgentDefinition

```python
from azure.ai.projects.models import PromptAgentDefinition

# Create a versioned agent
agent_version = client.agents.create_version(
    agent_name="customer-support-agent",
    definition=PromptAgentDefinition(
        model=os.environ["AZURE_AI_MODEL_DEPLOYMENT_NAME"],
        instructions="You are a customer support specialist.",
        tools=[],  # Add tools as needed
    ),
    version_label="v1.0",
)
```

See [references/agents.md](references/agents.md) for detailed agent patterns.

## Tools Overview

| Tool | Class | Use Case |
|------|-------|----------|
| Code Interpreter | `CodeInterpreterTool` | Execute Python, generate files |
| File Search | `FileSearchTool` | RAG over uploaded documents |
| Bing Grounding | `BingGroundingTool` | Web search (requires connection) |
| Azure AI Search | `AzureAISearchTool` | Search your indexes |
| Function Calling | `FunctionTool` | Call your Python functions |
| OpenAPI | `OpenApiTool` | Call REST APIs |
| MCP | `McpTool` | Model Context Protocol servers |
| Memory Search | `MemorySearchTool` | Search agent memory stores |
| SharePoint | `SharepointGroundingTool` | Search SharePoint content |

See [references/tools.md](references/tools.md) for all tool patterns.

## Thread and Message Flow

```python
# 1. Create thread
thread = client.agents.threads.create()

# 2. Add message
client.agents.messages.create(
    thread_id=thread.id,
    role="user",
    content="What's the weather like?",
)

# 3. Create and process run
run = client.agents.runs.create_and_process(
    thread_id=thread.id,
    agent_id=agent.id,
)

# 4. Get response
if run.status == "completed":
    messages = client.agents.messages.list(thread_id=thread.id)
    for msg in messages:
        if msg.role == "assistant":
            print(msg.content[0].text.value)
```

## Connections

```python
# List all connections
connections = client.connections.list()
for conn in connections:
    print(f"{conn.name}: {conn.connection_type}")

# Get specific connection
connection = client.connections.get(connection_name="my-search-connection")
```

See [references/connections.md](references/connections.md) for connection patterns.

## Deployments

```python
# List available model deployments
deployments = client.deployments.list()
for deployment in deployments:
    print(f"{deployment.name}: {deployment.model}")
```

See [references/deployments.md](references/dep
