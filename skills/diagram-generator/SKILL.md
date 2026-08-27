---
name: diagram-generator
description: Generate, refine, validate, and render diagrams from natural language, notes, code, schemas, or existing diagram sources: flowcharts, swimlanes, attack-path graphs, data-flow diagrams, architecture, a
category: Creative & Media
source: antigravity
tags: [python, node, pdf, markdown, api, ai, workflow, template, image, pentest]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/diagram-generator
---

# Diagram Generator
## When to Use

- Turning textual analysis into Mermaid/Graphviz/PlantUML visuals.
- Producing attack-path or architecture diagrams for reports.


## Purpose

Create clear, editable diagrams from messy or structured inputs. Prefer text-based diagram source first so the result can be reviewed, versioned, and refined. Render to files only when the user asks for an image/PDF or when a downloadable artifact would materially help.

## Default workflow

1. Identify the user's intent, audience, and source material.
2. Choose the diagram family and language using the decision table below.
3. Normalize entities, relationships, labels, states, branches, and time/order information before writing diagram code.
4. Generate concise, readable diagram source.
5. Validate the syntax mentally and, when creating files, run `scripts/render_diagram.py`.
6. Return the diagram source plus a short note about assumptions. When files are generated, include links to the output files.

Do not over-ask for clarification. If the request is underspecified, make reasonable assumptions and label them briefly.

## Diagram language decision table

Use Mermaid unless another language is clearly better.

| User wants | Prefer | Why |
|---|---|---|
| process flow, decision tree, simple swimlane | Mermaid flowchart | readable and easy to paste into Markdown |
| sequence of system/user interactions | Mermaid sequenceDiagram or PlantUML sequence | Mermaid for docs; PlantUML for UML formality |
| lifecycle, state machine, transitions | Mermaid stateDiagram-v2 or PlantUML state | compact transition syntax |
| database schema, entities, relationships | Mermaid erDiagram | portable ER notation |
| class/interface/object model | Mermaid classDiagram or PlantUML class | Mermaid for docs; PlantUML for detailed UML |
| project schedule | Mermaid gantt | concise timeline syntax |
| hierarchy, ideas, notes | Mermaid mindmap | good default for idea maps |
| customer/product journey | Mermaid journey | built-in journey notation |
| git history | Mermaid gitGraph | built-in git notation |
| dependency graph, package graph, large network | Graphviz DOT | better layout engines for dense graphs |
| architecture with layers, clusters, boundaries | Mermaid flowchart with subgraphs, Graphviz clusters, or PlantUML C4-style | choose based on requested fidelity |
| weighted flow/sankey-like relationship | Mermaid sankey-beta when supported, otherwise SVG or Graphviz | Mermaid support may vary by renderer |
| custom visual where source languages fit poorly | SVG | precise control over layout and styling |

## Output policy

- Always provide editable source unless the user explicitly asks only for an image.
- Default to a single best diagram. Offer alternatives only when genuinely useful.
- Prefer stable, simple syntax over fancy features that may not render in older Mermaid/PlantUML versions.
- Use short labels. Split long text into notes outside the diagram when needed.
- Avoid ambiguous node IDs. Use ASCII IDs and human-readable labels.
- Preserve user terminology, but standardize capitalization within a diagram.
- For technical diagrams, include boundaries such as client, service, database, queue, external API, and operator/user when they are implied.
- For business-process diagrams, distinguish happy path, decision points, failures, retries, and manual steps when present.
- For diagrams created from uncertain text, include an `Assumptions` section after the code.

## Mermaid generation rules

Consult `references/diagram-patterns.md` for compact templates.

General Mermaid rules:
- Start with the correct diagram directive, for example `flowchart TD`, `sequenceDiagram`, `erDiagram`, `gantt`, `mindmap`, or `journey`.
- For flowcharts, use `flowchart TD` unless the user asks for left-to-right; use `flowchart LR` for architecture and pipelines.
- Use subgraphs for swimlanes or architecture layers. Name subgraphs with readable labels.
- Keep node IDs stable and ASCII-only, for example `ingest_service[Ingest Service]`.
- Quote labels that contain punctuation likely to confuse the parser.
- Use decision diamonds for branching: `decision{Condition?}`.
- Use consistent edge labels: `-- yes -->`, `-- no -->`, `-. async .->`, or `== critical ==>` only when meaningful.
- In sequence diagrams, declare participants before messages. Use `actor` for humans and `participant` for systems.
- Use `alt/else/end`, `opt/end`, `loop/end`, and `par/and/end` blocks for conditional, optional, repeated, and parallel flows.

## Graphviz DOT generation rules

Use Graphviz for large, dense, or layout-sensitive relationship diagrams.

- Prefer `digraph G` for directed relationships and `graph G` for undirected networks.
- Set layout-friendly graph attributes at the top: `rankdir=LR`, `nodesep`, `ranksep`, and `splines=true` when helpful.
- Use `subgraph cluster_name` for boundaries and subsystems.
- Use plain labels and restrained styling.
- Use edge labels only when they add me
