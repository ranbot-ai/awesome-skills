---
name: agents-v2-py
description: Build container-based Foundry Agents with Azure AI Projects SDK (HostedAgentDefinition). Use when creating hosted agents with custom container images in Azure AI Foundry. 
category: AI & Agents
source: antigravity
tags: [python, api, mcp, ai, agent, workflow, document, image, azure, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/agents-v2-py
---


## Compatibility and maintenance

Compatibility alias of `hosted-agents-v2-py`; use that ID for new references when no existing contract requires this one. The instruction-only procedure remains local; no executable support files are bundled so existing installations
continue to work offline. This compatibility guide documents the hosted-agent procedure, not an additional capability; older copies may use retired preview names.
Preserve the callable ID when an existing manifest or client configuration uses it.
Modified in AAS on 2026-09-05; original metadata and license notices are retained.

# Azure AI Hosted Agents (Python)

Build container-based hosted agents using `HostedAgentDefinition` from the Azure AI Projects SDK.

## Installation

```bash
pip install 'azure-ai-projects==2.3.0' azure-identity
```

These are SDK 2.3.0 instruction fragments aligned with the current Microsoft hosted-agent guide. Validate the installed schema and service support before provisioning; documentation inspection is not a cloud integration test.

## Environment Variables

```bash
export AZURE_AI_PROJECT_ENDPOINT="https://<resource>.services.ai.azure.com/api/projects/<project>"
```

## Prerequisites

Before creating hosted agents:

1. **Container Image** - Build and push to Azure Container Registry (ACR)
2. **ACR Pull Permissions** - Grant the project identity the registry role supported by its permission mode; current hosted-agent guidance uses Container Registry Repository Reader
3. **Capability Host** - Confirm current project/region hosted-agent availability and the application's network policy; do not enable public hosting automatically
4. **SDK Version** - Ensure `azure-ai-projects==2.3.0`

## Authentication

Use the approved Azure credential flow for the intended tenant/subscription; this sketch uses `DefaultAzureCredential`:

```python
from azure.identity import DefaultAzureCredential
from azure.ai.projects import AIProjectClient

import os

credential = DefaultAzureCredential()
client = AIProjectClient(
    endpoint=os.environ["AZURE_AI_PROJECT_ENDPOINT"],
    credential=credential
)
```

## Core Workflow

### 1. Imports

```python
import os
from azure.identity import DefaultAzureCredential
from azure.ai.projects import AIProjectClient
from azure.ai.projects.models import (
    HostedAgentDefinition,
    ContainerConfiguration,
    ProtocolVersionRecord,
    AgentEndpointProtocol,
)
```

### 2. Create Hosted Agent

```python
client = AIProjectClient(
    endpoint=os.environ["AZURE_AI_PROJECT_ENDPOINT"],
    credential=DefaultAzureCredential()
)

agent = client.agents.create_version(
    agent_name="my-hosted-agent",
    definition=HostedAgentDefinition(
        protocol_versions=[
            ProtocolVersionRecord(protocol=AgentEndpointProtocol.RESPONSES, version="2.0.0")
        ],
        cpu="1",
        memory="2Gi",
        container_configuration=ContainerConfiguration(image=os.environ["REVIEWED_CONTAINER_IMAGE"]),
        environment_variables={
            "AZURE_AI_PROJECT_ENDPOINT": os.environ["AZURE_AI_PROJECT_ENDPOINT"],
            "MODEL_NAME": os.environ["MODEL_DEPLOYMENT_NAME"]
        }
    )
)

print(f"Created agent: {agent.name} (version: {agent.version})")
```

### 3. List Agent Versions

```python
versions = client.agents.list_versions(agent_name="my-hosted-agent")
for version in versions:
    print(f"Version: {version.version}")  # Inspect supported status fields via get_version
```

Inspect the exact returned model for supported fields; a created version is not proof a running container is healthy. Close synchronous client/credential resources through their supported context managers or `close()` methods.

### 4. Delete Agent Version

```python
client.agents.delete_version(
    agent_name="my-hosted-agent",
    agent_version=agent.version
)
```

## HostedAgentDefinition Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `protocol_versions` | `list[ProtocolVersionRecord]` | Yes | Protocol versions the agent supports |
| `container_configuration` | `ContainerConfiguration` | Yes for an image deployment | Reviewed registry image reference |
| `cpu` | `str` | No | CPU allocation (e.g., "1", "2") |
| `memory` | `str` | No | Memory allocation (e.g., "2Gi", "4Gi") |
| `environment_variables` | `dict[str, str]` | No | Environment variables for the container |

## Protocol Versions

The `protocol_versions` parameter specifies which protocols your agent supports:

```python
from azure.ai.projects.models import ProtocolVersionRecord, AgentEndpointProtocol

# RESPONSES protocol - standard agent responses
protocol_versions=[
    ProtocolVersionRecord(protocol=AgentEndpointProtocol.RESPONSES, version="2.0.0")
]
```

**Available Protocols:**
| Protocol | Description |
|----------|-------------|
| `AgentEndpointProtocol.RESPONSES` | Standard response protocol for agent interactions |

## Resource Allocation

Specify CPU and memory for your container:

```p
