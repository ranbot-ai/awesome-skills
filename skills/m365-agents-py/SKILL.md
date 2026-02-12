---
name: m365-agents-py
description: Microsoft 365 Agents SDK for Python. Build multichannel agents for Teams/M365/Copilot Studio with aiohttp hosting, AgentApplication routing, streaming responses, and MSAL-based auth. Triggers: "Micros
category: AI & Agents
source: antigravity
tags: [python, api, mcp, ai, agent, gpt, workflow, azure, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/m365-agents-py
---


# Microsoft 365 Agents SDK (Python)

Build enterprise agents for Microsoft 365, Teams, and Copilot Studio using the Microsoft Agents SDK with aiohttp hosting, AgentApplication routing, streaming responses, and MSAL-based authentication.

## Before implementation
- Use the microsoft-docs MCP to verify the latest API signatures for AgentApplication, start_agent_process, and authentication options.
- Confirm package versions on PyPI for the microsoft-agents-* packages you plan to use.

## Important Notice - Import Changes

> **⚠️ Breaking Change**: Recent updates have changed the Python import structure from `microsoft.agents` to `microsoft_agents` (using underscores instead of dots).

## Installation

```bash
pip install microsoft-agents-hosting-core
pip install microsoft-agents-hosting-aiohttp
pip install microsoft-agents-activity
pip install microsoft-agents-authentication-msal
pip install microsoft-agents-copilotstudio-client
pip install python-dotenv aiohttp
```

## Environment Variables (.env)

```bash
CONNECTIONS__SERVICE_CONNECTION__SETTINGS__CLIENTID=<client-id>
CONNECTIONS__SERVICE_CONNECTION__SETTINGS__CLIENTSECRET=<client-secret>
CONNECTIONS__SERVICE_CONNECTION__SETTINGS__TENANTID=<tenant-id>

# Optional: OAuth handlers for auto sign-in
AGENTAPPLICATION__USERAUTHORIZATION__HANDLERS__GRAPH__SETTINGS__AZUREBOTOAUTHCONNECTIONNAME=<connection-name>

# Optional: Azure OpenAI for streaming
AZURE_OPENAI_ENDPOINT=<endpoint>
AZURE_OPENAI_API_VERSION=<version>
AZURE_OPENAI_API_KEY=<key>

# Optional: Copilot Studio client
COPILOTSTUDIOAGENT__ENVIRONMENTID=<environment-id>
COPILOTSTUDIOAGENT__SCHEMANAME=<schema-name>
COPILOTSTUDIOAGENT__TENANTID=<tenant-id>
COPILOTSTUDIOAGENT__AGENTAPPID=<app-id>
```

## Core Workflow: aiohttp-hosted AgentApplication

```python
import logging
from os import environ

from dotenv import load_dotenv
from aiohttp.web import Request, Response, Application, run_app

from microsoft_agents.activity import load_configuration_from_env
from microsoft_agents.hosting.core import (
    Authorization,
    AgentApplication,
    TurnState,
    TurnContext,
    MemoryStorage,
)
from microsoft_agents.hosting.aiohttp import (
    CloudAdapter,
    start_agent_process,
    jwt_authorization_middleware,
)
from microsoft_agents.authentication.msal import MsalConnectionManager

# Enable logging
ms_agents_logger = logging.getLogger("microsoft_agents")
ms_agents_logger.addHandler(logging.StreamHandler())
ms_agents_logger.setLevel(logging.INFO)

# Load configuration
load_dotenv()
agents_sdk_config = load_configuration_from_env(environ)

# Create storage and connection manager
STORAGE = MemoryStorage()
CONNECTION_MANAGER = MsalConnectionManager(**agents_sdk_config)
ADAPTER = CloudAdapter(connection_manager=CONNECTION_MANAGER)
AUTHORIZATION = Authorization(STORAGE, CONNECTION_MANAGER, **agents_sdk_config)

# Create AgentApplication
AGENT_APP = AgentApplication[TurnState](
    storage=STORAGE, adapter=ADAPTER, authorization=AUTHORIZATION, **agents_sdk_config
)


@AGENT_APP.conversation_update("membersAdded")
async def on_members_added(context: TurnContext, _state: TurnState):
    await context.send_activity("Welcome to the agent!")


@AGENT_APP.activity("message")
async def on_message(context: TurnContext, _state: TurnState):
    await context.send_activity(f"You said: {context.activity.text}")


@AGENT_APP.error
async def on_error(context: TurnContext, error: Exception):
    await context.send_activity("The agent encountered an error.")


# Server setup
async def entry_point(req: Request) -> Response:
    agent: AgentApplication = req.app["agent_app"]
    adapter: CloudAdapter = req.app["adapter"]
    return await start_agent_process(req, agent, adapter)


APP = Application(middlewares=[jwt_authorization_middleware])
APP.router.add_post("/api/messages", entry_point)
APP["agent_configuration"] = CONNECTION_MANAGER.get_default_connection_configuration()
APP["agent_app"] = AGENT_APP
APP["adapter"] = AGENT_APP.adapter

if __name__ == "__main__":
    run_app(APP, host="localhost", port=environ.get("PORT", 3978))
```

## AgentApplication Routing

```python
import re
from microsoft_agents.hosting.core import (
    AgentApplication, TurnState, TurnContext, MessageFactory
)
from microsoft_agents.activity import ActivityTypes

AGENT_APP = AgentApplication[TurnState](
    storage=STORAGE, adapter=ADAPTER, authorization=AUTHORIZATION, **agents_sdk_config
)

# Welcome handler
@AGENT_APP.conversation_update("membersAdded")
async def on_members_added(context: TurnContext, _state: TurnState):
    await context.send_activity("Welcome!")

# Regex-based message handler
@AGENT_APP.message(re.compile(r"^hello$", re.IGNORECASE))
async def on_hello(context: TurnContext, _state: TurnState):
    await context.send_activity("Hello!")

# Simple string message handler
@AGENT_APP.message("/status")
async def on_status(context: TurnContext, _state: TurnState):
    await context.send_activity("Status: OK")

# Auth-protected message ha
