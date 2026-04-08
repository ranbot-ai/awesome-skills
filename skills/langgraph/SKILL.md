---
name: langgraph
description: Expert in LangGraph - the production-grade framework for building stateful, multi-actor AI applications. Covers graph construction, state management, cycles and branches, persistence with checkpointer
category: AI & Agents
source: antigravity
tags: [python, typescript, react, node, api, ai, agent, llm, gpt, workflow]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/langgraph
---


# LangGraph

Expert in LangGraph - the production-grade framework for building stateful, multi-actor
AI applications. Covers graph construction, state management, cycles and branches,
persistence with checkpointers, human-in-the-loop patterns, and the ReAct agent pattern.
Used in production at LinkedIn, Uber, and 400+ companies. This is LangChain's recommended
approach for building agents.

**Role**: LangGraph Agent Architect

You are an expert in building production-grade AI agents with LangGraph. You
understand that agents need explicit structure - graphs make the flow visible
and debuggable. You design state carefully, use reducers appropriately, and
always consider persistence for production. You know when cycles are needed
and how to prevent infinite loops.

### Expertise

- Graph topology design
- State schema patterns
- Conditional branching
- Persistence strategies
- Human-in-the-loop
- Tool integration
- Error handling and recovery

## Capabilities

- Graph construction (StateGraph)
- State management and reducers
- Node and edge definitions
- Conditional routing
- Checkpointers and persistence
- Human-in-the-loop patterns
- Tool integration
- Streaming and async execution

## Prerequisites

- 0: Python proficiency
- 1: LLM API basics
- 2: Async programming concepts
- 3: Graph theory fundamentals
- Required skills: Python 3.9+, langgraph package, LLM API access (OpenAI, Anthropic, etc.), Understanding of graph concepts

## Scope

- 0: Python-only (TypeScript in early stages)
- 1: Learning curve for graph concepts
- 2: State management complexity
- 3: Debugging can be challenging

## Ecosystem

### Primary

- LangGraph
- LangChain
- LangSmith (observability)

### Common_integrations

- OpenAI / Anthropic / Google
- Tavily (search)
- SQLite / PostgreSQL (persistence)
- Redis (state store)

### Platforms

- Python applications
- FastAPI / Flask backends
- Cloud deployments

## Patterns

### Basic Agent Graph

Simple ReAct-style agent with tools

**When to use**: Single agent with tool calling

from typing import Annotated, TypedDict
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool

# 1. Define State
class AgentState(TypedDict):
    messages: Annotated[list, add_messages]
    # add_messages reducer appends, doesn't overwrite

# 2. Define Tools
@tool
def search(query: str) -> str:
    """Search the web for information."""
    # Implementation here
    return f"Results for: {query}"

@tool
def calculator(expression: str) -> str:
    """Evaluate a math expression."""
    return str(eval(expression))

tools = [search, calculator]

# 3. Create LLM with tools
llm = ChatOpenAI(model="gpt-4o").bind_tools(tools)

# 4. Define Nodes
def agent(state: AgentState) -> dict:
    """The agent node - calls LLM."""
    response = llm.invoke(state["messages"])
    return {"messages": [response]}

# Tool node handles tool execution
tool_node = ToolNode(tools)

# 5. Define Routing
def should_continue(state: AgentState) -> str:
    """Route based on whether tools were called."""
    last_message = state["messages"][-1]
    if last_message.tool_calls:
        return "tools"
    return END

# 6. Build Graph
graph = StateGraph(AgentState)

# Add nodes
graph.add_node("agent", agent)
graph.add_node("tools", tool_node)

# Add edges
graph.add_edge(START, "agent")
graph.add_conditional_edges("agent", should_continue, ["tools", END])
graph.add_edge("tools", "agent")  # Loop back

# Compile
app = graph.compile()

# 7. Run
result = app.invoke({
    "messages": [("user", "What is 25 * 4?")]
})

### State with Reducers

Complex state management with custom reducers

**When to use**: Multiple agents updating shared state

from typing import Annotated, TypedDict
from operator import add
from langgraph.graph import StateGraph

# Custom reducer for merging dictionaries
def merge_dicts(left: dict, right: dict) -> dict:
    return {**left, **right}

# State with multiple reducers
class ResearchState(TypedDict):
    # Messages append (don't overwrite)
    messages: Annotated[list, add_messages]

    # Research findings merge
    findings: Annotated[dict, merge_dicts]

    # Sources accumulate
    sources: Annotated[list[str], add]

    # Current step (overwrites - no reducer)
    current_step: str

    # Error count (custom reducer)
    errors: Annotated[int, lambda a, b: a + b]

# Nodes return partial state updates
def researcher(state: ResearchState) -> dict:
    # Only return fields being updated
    return {
        "findings": {"topic_a": "New finding"},
        "sources": ["source1.com"],
        "current_step": "researching"
    }

def writer(state: ResearchState) -> dict:
    # Access accumulated state
    all_findings = state["findings"]
    all_sources = state["sources"]

    return {
        "messages": [("assistant", f"Report based on {len(all_sources)} sources")],
