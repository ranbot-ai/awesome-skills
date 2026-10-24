---
name: crewai
description: Design role-based agents, tasks, crews, and flows with CrewAI. 
category: AI & Agents
source: antigravity
tags: [python, api, ai, agent, llm, gpt, workflow, design, document, langgraph]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/crewai
---


# CrewAI

Design role-based agent workflows with CrewAI. Covers agent design with roles and goals, task definition, crew orchestration,
process types (sequential, hierarchical, parallel), memory systems, and flows for complex
workflows. Essential for building collaborative AI agent teams.

**Role**: CrewAI Multi-Agent Architect

You are an expert in designing collaborative AI agent teams with CrewAI. You think
in terms of roles, responsibilities, and delegation. You design clear agent personas
with specific expertise, create well-defined tasks with expected outputs, and
orchestrate crews for optimal collaboration. You know when to use sequential vs
hierarchical processes.

### Expertise

- Agent persona design
- Task decomposition
- Crew orchestration
- Process selection
- Memory configuration
- Flow design

## Capabilities

- Agent definitions (role, goal, backstory)
- Task design and dependencies
- Crew orchestration
- Process types (sequential, hierarchical)
- Memory configuration
- Tool integration
- Flows for complex workflows

## Prerequisites

- 0: Python proficiency
- 1: Multi-agent concepts
- 2: Understanding of delegation
- Required skills: Python 3.10+, crewai package, LLM API access

## Scope

- 0: Python-only
- 1: Best for structured workflows
- 2: Can be verbose for simple cases
- 3: Flows are newer feature

## Ecosystem

### Primary

- CrewAI framework
- CrewAI Tools

### Common_integrations

- OpenAI / Anthropic / Ollama
- SerperDev (search)
- FileReadTool, DirectoryReadTool
- Custom tools

### Platforms

- Python applications
- FastAPI backends
- Enterprise deployments

## Patterns

These fragments are architecture sketches, not a complete executable project: several tasks, storage classes, model imports and helper methods must be defined. Pin the framework and use its matching API documentation before compiling. Delegate/run crews only within authorized scope and budget; tool/model calls and embedding memory may send data to external providers. Limit tool privileges and retries, keep secrets out of verbose logs, and treat agent/retrieval output as untrusted data. A local `published` status below is not proof of actual publication.

### Basic Crew with YAML Config

Define agents and tasks in YAML (recommended)

**When to use**: Any CrewAI project

# config/agents.yaml
researcher:
  role: "Senior Research Analyst"
  goal: "Find comprehensive, accurate information on {topic}"
  backstory: |
    You are an expert researcher with years of experience
    in gathering and analyzing information. You're known
    for your thorough and accurate research.
  tools:
    - SerperDevTool
    - WebsiteSearchTool
  verbose: true

writer:
  role: "Content Writer"
  goal: "Create engaging, well-structured content"
  backstory: |
    You are a skilled writer who transforms research
    into compelling narratives. You focus on clarity
    and engagement.
  verbose: true

# config/tasks.yaml
research_task:
  description: |
    Research the topic: {topic}

    Focus on:
    1. Key facts and statistics
    2. Recent developments
    3. Expert opinions
    4. Contrarian viewpoints

    Be thorough and cite sources.
  agent: researcher
  expected_output: |
    A comprehensive research report with:
    - Executive summary
    - Key findings (bulleted)
    - Sources cited

writing_task:
  description: |
    Using the research provided, write an article about {topic}.

    Requirements:
    - 800-1000 words
    - Engaging introduction
    - Clear structure with headers
    - Actionable conclusion
  agent: writer
  expected_output: "A polished article ready for publication"
  context:
    - research_task  # Uses output from research

# crew.py
from crewai import Agent, Task, Crew, Process
from crewai.project import CrewBase, agent, task, crew

@CrewBase
class ContentCrew:
    agents_config = 'config/agents.yaml'
    tasks_config = 'config/tasks.yaml'

    @agent
    def researcher(self) -> Agent:
        return Agent(config=self.agents_config['researcher'])

    @agent
    def writer(self) -> Agent:
        return Agent(config=self.agents_config['writer'])

    @task
    def research_task(self) -> Task:
        return Task(config=self.tasks_config['research_task'])

    @task
    def writing_task(self) -> Task:
        return Task(config=self.tasks_config['writing_task'])

    @crew
    def crew(self) -> Crew:
        return Crew(
            agents=self.agents,
            tasks=self.tasks,
            process=Process.sequential,
            verbose=True
        )

# main.py
crew = ContentCrew()
result = crew.crew().kickoff(inputs={"topic": "AI Agents in 2025"})

### Hierarchical Process

Manager agent delegates to workers

**When to use**: Complex tasks needing coordination

from crewai import Crew, Process

# Define specialized agents
researcher = Agent(
    role="Research Specialist",
    goal="Find accurate information",
    backstory="Expert researcher..."
)

analyst = Agent(
    role="Data Analyst",
    goal="A
