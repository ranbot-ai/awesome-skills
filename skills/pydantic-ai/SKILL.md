---
name: pydantic-ai
description: Build production-ready AI agents with PydanticAI — type-safe tool use, structured outputs, dependency injection, and multi-model support. 
category: AI & Agents
source: antigravity
tags: [python, api, claude, ai, agent, llm, gpt, template, security, azure]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/pydantic-ai
---


# PydanticAI — Typed AI Agents in Python

## Overview

PydanticAI is a Python agent framework from the Pydantic team that brings the same type-safety and validation guarantees as Pydantic to LLM-based applications. It supports structured outputs (validated with Pydantic models), dependency injection for testability, streamed responses, multi-turn conversations, and tool use — across OpenAI, Anthropic, Google Gemini, Groq, Mistral, and Ollama. Use this skill when building production AI agents, chatbots, or LLM pipelines where correctness and testability matter.

## When to Use This Skill

- Use when building Python AI agents that call tools and return structured data
- Use when you need validated, typed LLM outputs (not raw strings)
- Use when you want to write unit tests for agent logic without hitting a real LLM
- Use when switching between LLM providers without rewriting agent code
- Use when the user asks about `Agent`, `@agent.tool`, `RunContext`, `ModelRetry`, or `result_type`

## How It Works

### Step 1: Installation

```bash
pip install pydantic-ai

# Install extras for specific providers
pip install 'pydantic-ai[openai]'       # OpenAI / Azure OpenAI
pip install 'pydantic-ai[anthropic]'    # Anthropic Claude
pip install 'pydantic-ai[gemini]'       # Google Gemini
pip install 'pydantic-ai[groq]'         # Groq
pip install 'pydantic-ai[vertexai]'     # Google Vertex AI
```

### Step 2: A Minimal Agent

```python
from pydantic_ai import Agent

# Simple agent — returns a plain string
agent = Agent(
    'anthropic:claude-sonnet-4-6',
    system_prompt='You are a helpful assistant. Be concise.',
)

result = agent.run_sync('What is the capital of Japan?')
print(result.data)  # "Tokyo"
print(result.usage())  # Usage(requests=1, request_tokens=..., response_tokens=...)
```

### Step 3: Structured Output with Pydantic Models

```python
from pydantic import BaseModel
from pydantic_ai import Agent

class MovieReview(BaseModel):
    title: str
    year: int
    rating: float  # 0.0 to 10.0
    summary: str
    recommended: bool

agent = Agent(
    'openai:gpt-4o',
    result_type=MovieReview,
    system_prompt='You are a film critic. Return structured reviews.',
)

result = agent.run_sync('Review Inception (2010)')
review = result.data  # Fully typed MovieReview instance
print(f"{review.title} ({review.year}): {review.rating}/10")
print(f"Recommended: {review.recommended}")
```

### Step 4: Tool Use

Register tools with `@agent.tool` — the LLM can call them during a run:

```python
from pydantic_ai import Agent, RunContext
from pydantic import BaseModel
import httpx

class WeatherReport(BaseModel):
    city: str
    temperature_c: float
    condition: str

weather_agent = Agent(
    'anthropic:claude-sonnet-4-6',
    result_type=WeatherReport,
    system_prompt='Get current weather for the requested city.',
)

@weather_agent.tool
async def get_temperature(ctx: RunContext, city: str) -> dict:
    """Fetch the current temperature for a city from the weather API."""
    async with httpx.AsyncClient() as client:
        r = await client.get(f'https://wttr.in/{city}?format=j1')
        data = r.json()
        return {
            'temp_c': float(data['current_condition'][0]['temp_C']),
            'description': data['current_condition'][0]['weatherDesc'][0]['value'],
        }

import asyncio
result = asyncio.run(weather_agent.run('What is the weather in Tokyo?'))
print(result.data)
```

### Step 5: Dependency Injection

Inject services (database, HTTP clients, config) into agents for testability:

```python
from dataclasses import dataclass
from pydantic_ai import Agent, RunContext
from pydantic import BaseModel

@dataclass
class Deps:
    db: Database
    user_id: str

class SupportResponse(BaseModel):
    message: str
    escalate: bool

support_agent = Agent(
    'openai:gpt-4o-mini',
    deps_type=Deps,
    result_type=SupportResponse,
    system_prompt='You are a support agent. Use the tools to help customers.',
)

@support_agent.tool
async def get_order_history(ctx: RunContext[Deps]) -> list[dict]:
    """Fetch recent orders for the current user."""
    return await ctx.deps.db.get_orders(ctx.deps.user_id, limit=5)

@support_agent.tool
async def create_refund(ctx: RunContext[Deps], order_id: str, reason: str) -> dict:
    """Initiate a refund for a specific order."""
    return await ctx.deps.db.create_refund(order_id, reason, ctx.deps.user_id)

# Usage
async def handle_support(user_id: str, message: str):
    deps = Deps(db=get_db(), user_id=user_id)
    result = await support_agent.run(message, deps=deps)
    return result.data
```

### Step 6: Testing with TestModel

Write unit tests without real LLM calls:

```python
from pydantic_ai.models.test import TestModel

def test_support_agent_escalates():
    with support_agent.override(model=TestModel()):
        # TestModel returns a minimal valid response matching result_type
        result = support_agent.run_sync(
            'I want to cancel my account'
