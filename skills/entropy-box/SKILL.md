---
name: entropy-box
description: Entropy Box knowledge-compiler for embodied-AI: turns bounded requirements into grounded workflows via Solution Consult, Search, Lookup, and Evidence. Do not use it to control physical robots. 
category: Document Processing
source: antigravity
tags: [node, api, mcp, claude, ai, agent, llm, workflow, design, document]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/entropy-box
---

# Entropy Box

Entropy Box is an agent-native knowledge compiler and capability substrate for
embodied-AI development. It compiles fragmented papers, repositories, ROS packages,
models, datasets, simulators, benchmarks, standards, and engineering documentation
into a persistent, typed, deduplicated, machine-consumable knowledge artifact.

Its public Panorama Graph is not merely a search index or visualization. It represents
the field through domains, vertical topics, task chains, normalized capabilities,
implementation assets, dependency relations, and evidence. Use it to understand where
a technical problem sits in the whole embodied-AI system and how knowledge can be
composed into an engineering path.

Solution Consult is the primary runtime capability. The calling agent remains
responsible for clarifying the request, decomposing broad goals into bounded technical
questions, deciding which questions need separate consultations, and synthesizing the
results. Do not send an underspecified ambition such as "build a general robot" as one
query and treat the returned text as a complete solution.

The current public surface reports more than 52,177 entity nodes, 7,913 task chains,
66,714 dependency edges, 37,757 atomic capabilities or associated assets, and 2,511
vertical topic libraries. These counts evolve; verify the live site before quoting
them.

## When to Use

- Use when you need a grounded, source-linked implementation path for an embodied-AI task (manipulation, navigation, perception, control, planning, simulation, and related systems).
- Use when selecting or comparing methods, capabilities, assets, dependencies, or evidence for a bounded technical requirement.
- Use when mapping a problem to the embodied-AI field, tracing task chains, or assembling a development workflow from retrieved structure.
- Do not use it to directly control physical robots, or for unrelated scientific domains or generic software development.

## What this skill enables

Choose and sequence modes according to the user's task:

1. **Solution consultation** — ask how a bounded technical requirement can be
   implemented, which approaches can satisfy it, and which capabilities, dependencies,
   assets, constraints, and gaps belong in the candidate solution.
2. **Targeted knowledge search** — run RAG retrieval for a concrete question or build a
   fuller understanding of a technology selected during consultation.
3. **Entity anchoring** — resolve a known ID, name, or alias to a structured topic,
   capability, or asset record.
4. **Evidence verification** — retrieve source-linked comparisons, limitations,
   engineering notes, negative results, and benchmark context.
5. **Panorama navigation** — place a question within the embodied-AI field, find
   adjacent domains and topics, and explain the wider technical context.
6. **Topic research** — inspect a vertical topic as a structured unit rather than a
   bag of documents.
7. **Task-chain analysis** — decompose a goal into ordered, branching, or merging
   engineering steps.
8. **Capability and dependency analysis** — identify what a system must be able to do,
   what each capability requires, and which capabilities are reusable across topics.
9. **Asset discovery and selection** — connect capabilities to repositories, packages,
   models, datasets, simulators, sensors, benchmarks, and other implementation assets.
10. **Grounded workflow assembly** — compose task chains, capabilities, assets, evidence,
   constraints, and gaps into a candidate development workflow.
11. **Knowledge-compiler analysis** — study how fragmented technical knowledge is
   normalized, admitted, related, updated, and made available to agents.

The scope is broad inside embodied AI and bounded outside it. Do not trigger this skill
for unrelated scientific domains or generic software development merely because a task
mentions AI.

## Panorama structure

The public taxonomy spans 15 top-level domains:

- Foundation Models
- Human-Robot Interaction
- Learning and Adaptation
- Localization
- Manipulation
- Mapping and SLAM
- Motion and Control
- Multi-Robot Systems
- Navigation
- Perception
- Planning and Decision
- Reasoning and Agents
- Safety and Trust
- Simulation and Digital Twins
- System Infrastructure

Do not treat these domains as isolated folders. Many real systems cross several of
them. A mobile manipulator, for example, may require perception, localization,
navigation, planning, manipulation, motion control, safety, simulation, and system
infrastructure.

Read [references/panorama.md](references/panorama.md) when mapping a field, traversing
graph layers, or producing a capability landscape.

## Route each question correctly

| User need | Route |
| --- | --- |
| Task-level "how": accomplish an embodied-AI task with given robots/sensors | **Consult** |
| A concrete technical question or a deep study of a selected method | **Search** |
| A known `CAP_...`, `AST_...`, topic ID, name, or alias | **Lookup*
