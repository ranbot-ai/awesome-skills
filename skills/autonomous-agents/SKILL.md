---
name: autonomous-agents
description: Autonomous agents are AI systems that can independently decompose goals, plan actions, execute tools, and self-correct without constant human guidance. The challenge isn't making them capable - it's m
category: AI & Agents
source: antigravity
tags: [react, node, api, claude, ai, agent, llm, gpt, automation, workflow]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/autonomous-agents
---


# Autonomous Agents

Autonomous agents are AI systems that can independently decompose goals,
plan actions, execute tools, and self-correct without constant human guidance.
The challenge isn't making them capable - it's making them reliable. Every
extra decision multiplies failure probability.

This skill covers agent loops (ReAct, Plan-Execute), goal decomposition,
reflection patterns, and production reliability. Key insight: compounding
error rates kill autonomous agents. A 95% success rate per step drops to
60% by step 10. Build for reliability first, autonomy second.

2025 lesson: The winners are constrained, domain-specific agents with clear
boundaries, not "autonomous everything." Treat AI outputs as proposals,
not truth.

## Principles

- Reliability over autonomy - every step compounds error probability
- Constrain scope - domain-specific beats general-purpose
- Treat outputs as proposals, not truth
- Build guardrails before expanding capabilities
- Human-in-the-loop for critical decisions is non-negotiable
- Log everything - every action must be auditable
- Fail safely with rollback, not silently with corruption

## Capabilities

- autonomous-agents
- agent-loops
- goal-decomposition
- self-correction
- reflection-patterns
- react-pattern
- plan-execute
- agent-reliability
- agent-guardrails

## Scope

- multi-agent-systems → multi-agent-orchestration
- tool-building → agent-tool-builder
- memory-systems → agent-memory-systems
- workflow-orchestration → workflow-automation

## Tooling

### Frameworks

- LangGraph - When: Production agents with state management Note: 1.0 released Oct 2025, checkpointing, human-in-loop
- AutoGPT - When: Research/experimentation, open-ended exploration Note: Needs external guardrails for production
- CrewAI - When: Role-based agent teams Note: Good for specialized agent collaboration
- Claude Agent SDK - When: Anthropic ecosystem agents Note: Computer use, tool execution

### Patterns

- ReAct - When: Reasoning + Acting in alternating steps Note: Foundation for most modern agents
- Plan-Execute - When: Separate planning from execution Note: Better for complex multi-step tasks
- Reflection - When: Self-evaluation and correction Note: Evaluator-optimizer loop

## Patterns

### ReAct Agent Loop

Alternating reasoning and action steps

**When to use**: Interactive problem-solving, tool use, exploration

# REACT PATTERN:

"""
The ReAct loop:
1. Thought: Reason about what to do next
2. Action: Choose and execute a tool
3. Observation: Receive result
4. Repeat until goal achieved

Key: Explicit reasoning traces make debugging possible
"""

## Basic ReAct Implementation
"""
from langchain.agents import create_react_agent
from langchain_openai import ChatOpenAI

# Define the ReAct prompt template
react_prompt = '''
Answer the question using the following format:

Question: the input question
Thought: reason about what to do
Action: tool_name
Action Input: input to the tool
Observation: result of the action
... (repeat Thought/Action/Observation as needed)
Thought: I now know the final answer
Final Answer: the answer
'''

# Create the agent
agent = create_react_agent(
    llm=ChatOpenAI(model="gpt-4o"),
    tools=tools,
    prompt=react_prompt,
)

# Execute with step limit
result = agent.invoke(
    {"input": query},
    config={"max_iterations": 10}  # Prevent runaway loops
)
"""

## LangGraph ReAct (Production)
"""
from langgraph.prebuilt import create_react_agent
from langgraph.checkpoint.postgres import PostgresSaver

# Production checkpointer
checkpointer = PostgresSaver.from_conn_string(
    os.environ["POSTGRES_URL"]
)

agent = create_react_agent(
    model=llm,
    tools=tools,
    checkpointer=checkpointer,  # Durable state
)

# Invoke with thread for state persistence
config = {"configurable": {"thread_id": "user-123"}}
result = agent.invoke({"messages": [query]}, config)
"""

### Plan-Execute Pattern

Separate planning phase from execution

**When to use**: Complex multi-step tasks, when full plan visibility matters

# PLAN-EXECUTE PATTERN:

"""
Two-phase approach:
1. Planning: Decompose goal into subtasks
2. Execution: Execute subtasks, potentially re-plan

Advantages:
- Full visibility into plan before execution
- Can validate/modify plan with human
- Cleaner separation of concerns

Disadvantages:
- Less adaptive to mid-task discoveries
- Plan may become stale
"""

## LangGraph Plan-Execute
"""
from langgraph.prebuilt import create_plan_and_execute_agent

# Planner creates the task list
planner_prompt = '''
For the given objective, create a step-by-step plan.
Each step should be atomic and actionable.
Format: numbered list of steps.
'''

# Executor handles individual steps
executor_prompt = '''
You are executing step {step_number} of the plan.
Previous results: {previous_results}
Current step: {current_step}
Execute this step using available tools.
'''

agent = create_plan_and_execute_agent(
    planner=planner_llm,
    executor=executor_llm,
    tools=tools,
    
