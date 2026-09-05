---
name: agents-v2-py
description: Build container-based Foundry Agents with Azure AI Projects SDK (ImageBasedHostedAgentDefinition). Use when creating hosted agents with custom container images in Azure AI Foundry. 
category: AI & Agents
source: antigravity
tags: [python, api, mcp, ai, agent, gpt, workflow, document, image, azure]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/agents-v2-py
---


## Compatibility and maintenance

Compatibility alias of `hosted-agents-v2-py`; use that ID for new references when no existing contract requires this one. The full instructions and support files remain local so existing installations
continue to work offline. This is one shared procedure, not an additional capability.
Preserve the callable ID when an existing manifest or client configuration uses it.
Modified in AAS on 2026-09-05; original metadata and license notices are retained.

# Azure AI Hosted Agents (Python)

Build container-based hosted agents using `ImageBasedHostedAgentDefinition` from the Azure AI Projects SDK.

## Installation

```bash
pip install 'azure-ai-projects>=2.0.0b3,<3' azure-identity
```

These are preview-era SDK v2 sketches. Check the exact installed version and current Azure hosted-agent documentation before provisioning; a broad version range is not an integration test.

## Environment Variables

```bash
AZURE_AI_PROJECT_ENDPOINT=https://<resource>.services.ai.azure.com/api/projects/<project>
```

## Prerequisites

Before creating hosted agents:

1. **Container Image** - Build and push to Azure Container Registry (ACR)
2. **ACR Pull Permissions** - Grant your project's managed identity `AcrPull` role on the ACR
3. **Capability Host** - Account-level capability host with `enablePublicHostingEnvironment=true`
4. **SDK Version** - Ensure `azure-ai-projects>=2.0.0b3`

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
    ImageBasedHostedAgentDefinition,
    ProtocolVersionRecord,
    AgentProtocol,
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
    definition=ImageBasedHostedAgentDefinition(
        container_protocol_versions=[
            ProtocolVersionRecord(protocol=AgentProtocol.RESPONSES, version="v1")
        ],
        cpu="1",
        memory="2Gi",
        image="myregistry.azurecr.io/my-agent:latest",
        tools=[{"type": "code_interpreter"}],
        environment_variables={
            "AZURE_AI_PROJECT_ENDPOINT": os.environ["AZURE_AI_PROJECT_ENDPOINT"],
            "MODEL_NAME": "gpt-4o-mini"
        }
    )
)

print(f"Created agent: {agent.name} (version: {agent.version})")
```

### 3. List Agent Versions

```python
versions = client.agents.list_versions(agent_name="my-hosted-agent")
for version in versions:
    print(f"Version: {version.version}, State: {version.state}")
```

### 4. Delete Agent Version

```python
client.agents.delete_version(
    agent_name="my-hosted-agent",
    version=agent.version
)
```

## ImageBasedHostedAgentDefinition Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `container_protocol_versions` | `list[ProtocolVersionRecord]` | Yes | Protocol versions the agent supports |
| `image` | `str` | Yes | Full container image path (registry/image:tag) |
| `cpu` | `str` | No | CPU allocation (e.g., "1", "2") |
| `memory` | `str` | No | Memory allocation (e.g., "2Gi", "4Gi") |
| `tools` | `list[dict]` | No | Tools available to the agent |
| `environment_variables` | `dict[str, str]` | No | Environment variables for the container |

## Protocol Versions

The `container_protocol_versions` parameter specifies which protocols your agent supports:

```python
from azure.ai.projects.models import ProtocolVersionRecord, AgentProtocol

# RESPONSES protocol - standard agent responses
container_protocol_versions=[
    ProtocolVersionRecord(protocol=AgentProtocol.RESPONSES, version="v1")
]
```

**Available Protocols:**
| Protocol | Description |
|----------|-------------|
| `AgentProtocol.RESPONSES` | Standard response protocol for agent interactions |

## Resource Allocation

Specify CPU and memory for your container:

```python
definition=ImageBasedHostedAgentDefinition(
    container_protocol_versions=[...],
    image="myregistry.azurecr.io/my-agent:latest",
    cpu="2",      # 2 CPU cores
    memory="4Gi"  # 4 GiB memory
)
```

**Illustrative resource sizes; verify regional/SKU limits before provisioning:**
| Resource | Min | Max | Default |
|----------|-----|-----|---------|
| CPU | 0.5 | 4 | 1 |
| Memory | 1Gi | 8Gi | 2Gi |

## Tools Configuration

Add tools to your hosted agent:

### Code Interpreter

```python
tools=[{"type": "code_interpreter"}]
```

### MCP Tools

```
