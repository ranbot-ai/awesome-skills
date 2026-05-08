---
name: multi-agent-architect
description: Design and optimize production-grade multi-agent systems with LangGraph, LangChain, and DeepAgents for complex AI workflows. 
category: AI & Agents
source: antigravity
tags: [python, node, api, claude, ai, agent, llm, gpt, workflow, template]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/multi-agent-architect
---



# Multi-Agent Architect & Updater Skill

## Overview

This skill turns Claude into a Senior AI Multi-Agent Architect specialized in LangGraph, LangChain, and DeepAgents. It provides structured workflows for creating and updating production-grade multi-agent systems — including supervisor agents, planners, researchers, coders, and memory-backed autonomous pipelines. Use it whenever you need to design, build, debug, or scale any multi-agent AI system.

If this skill adapts material from an external GitHub repository, declare both:

- `source_repo: owner/repo`
- `source_type: official` or `source_type: community`

## When to Use This Skill

- Use when you need to create a new agent or multi-agent workflow from scratch
- Use when working with LangGraph state graphs, nodes, edges, or conditional routing
- Use when the user asks about agent communication, memory systems, or tool-calling pipelines
- Use when debugging or optimizing an existing LangChain/LangGraph agent system
- Use when architecting supervisor, planner, research, coding, or validation agent roles
- Use when integrating DeepAgents with hierarchical planning and delegation

## How It Works

### Step 1: Understand the Goal

Before writing any code, clarify:
- What is the **business objective** this agent system must achieve?
- What **agent roles** are needed (supervisor, planner, researcher, coder, validator)?
- What **tools** does each agent require?
- What **memory** strategy is needed (Redis, Vector DB, LangChain Memory)?
- What **communication protocol** connects agents (shared state, message passing)?

### Step 2: Define the State Schema

All agents share a typed state object passed through the graph:

```python
from typing import TypedDict

class AgentState(TypedDict):
    user_goal: str
    tasks: list[str]
    completed_tasks: list[str]
    next_agent: str
    context: dict
    step_count: int          # guards against infinite loops
    error: str | None
```

### Step 3: Define Agent Nodes

Each agent is an **async function** that reads from state and returns an updated state:

```python
import logging
from langchain_openai import ChatOpenAI

logger = logging.getLogger(__name__)

async def research_node(state: AgentState) -> AgentState:
    logger.info("research_node: starting")
    llm = ChatOpenAI(model="gpt-4o")
    result = await llm.bind_tools(research_tools).ainvoke(state["user_goal"])
    state["context"]["research"] = result.content
    state["next_agent"] = "coder"
    return state
```

### Step 4: Build the LangGraph

Wire nodes together with edges and conditional routing:

```python
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode

def build_graph() -> StateGraph:
    graph = StateGraph(AgentState)

    graph.add_node("supervisor", supervisor_node)
    graph.add_node("research",   research_node)
    graph.add_node("coder",      coding_node)
    graph.add_node("validator",  validation_node)
    graph.add_node("tools",      ToolNode(all_tools))

    graph.set_entry_point("supervisor")

    graph.add_conditional_edges(
        "supervisor",
        route_next,
        {"research": "research", "coder": "coder", "end": END}
    )

    graph.add_edge("research",  "supervisor")
    graph.add_edge("coder",     "validator")
    graph.add_edge("validator", "supervisor")

    return graph.compile()

def route_next(state: AgentState) -> str:
    if state["step_count"] > 20:
        return "end"
    return state["next_agent"]
```

### Step 5: Add Memory

```python
from langchain_community.chat_message_histories import RedisChatMessageHistory

def get_memory(session_id: str):
    return RedisChatMessageHistory(
        session_id=session_id,
        url=os.getenv("REDIS_URL"),
        ttl=3600
    )
```

### Step 6: Run the Graph

```python
async def run(user_goal: str, session_id: str):
    graph = build_graph()
    initial_state = AgentState(
        user_goal=user_goal,
        tasks=[],
        completed_tasks=[],
        next_agent="supervisor",
        context={},
        step_count=0,
        error=None,
    )
    return await graph.ainvoke(initial_state)
```

### Step 7: Expose via FastAPI (optional)

```python
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class RunRequest(BaseModel):
    goal: str
    session_id: str

@app.post("/run")
async def run_agent(req: RunRequest):
    result = await run(req.goal, req.session_id)
    return {"result": result}
```

---

## Updating an Existing Agent

When the user wants to update or debug an existing agent, structure the response as:

```
## Existing Issue
[Describe the current problem]

## Root Cause
[Identify why it's happening in the architecture]

## Proposed Update
[Outline the changes at architecture level]

## Updated Code
[Generate only the changed modules]

## Migration Notes
[What breaks, what's backward-compatible]

## Performance Impact
[Latency / token / memory delta]
```

---

## Standard Folder Structure

Always g
