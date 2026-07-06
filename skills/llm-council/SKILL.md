---
name: llm-council
description: Run Fireworks-hosted open-weight model councils that compare responses and synthesize a final answer. 
category: AI & Agents
source: antigravity
tags: [python, api, claude, ai, agent, llm, workflow, document, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/llm-council
---


# LLM Council (Fireworks AI)

## When to Use

Use when this workflow matches the user request: Use this skill for its documented workflow.


_Source: [dair-ai/dair-academy-plugins](https://github.com/dair-ai/dair-academy-plugins) (MIT)._

This skill implements Karpathy's LLM Council concept where multiple open-weight LLMs deliberate on a query, powered entirely by Fireworks AI:

1. **Phase 1**: All models respond to the query independently (parallel)
2. **Phase 2**: Models rank each other's anonymized responses
3. **Phase 3**: A Chairman LLM synthesizes the final answer

All inference runs through **Fireworks AI** using open-weight models. The speed and pricing of Fireworks makes it practical to run multi-model deliberation that would be slow or expensive on other providers.

## CRITICAL RULES

1. **ALWAYS use AskUserQuestion** to let the user select council models (multiselect) and the Chairman model
2. **ALWAYS save raw responses to files** - never summarize or truncate API outputs
3. **ALWAYS show full transparency** - display all individual responses, all rankings, AND the final synthesis
4. **NEVER skip the ranking phase** - it is essential to the council deliberation process
5. **Read from files for display** - ensures content is shown unmodified
6. **ALWAYS display the final output to the user** after Phase 3 completes

## Pre-flight Check

Before running any phase, verify the Fireworks API key is set:

```bash
if [ -z "$FIREWORKS_API_KEY" ]; then
  echo "ERROR: FIREWORKS_API_KEY is not set."
  echo "Create a Fireworks AI account at: https://fireworks.ai/"
  echo "Then export it in your shell profile (~/.zshrc or ~/.bashrc):"
  echo '  read -rsp "Fireworks API key: " FIREWORKS_API_KEY; echo; export FIREWORKS_API_KEY'
  exit 1
fi
echo "FIREWORKS_API_KEY is set."
```

## Available Models

Present these options to the user via AskUserQuestion (multiselect):

| Model | Fireworks ID | Provider |
|-------|-------------|----------|
| GLM 5 | accounts/fireworks/models/glm-5 | Z.ai |
| DeepSeek V3.1 | accounts/fireworks/models/deepseek-v3p1 | DeepSeek |
| DeepSeek V3.2 | accounts/fireworks/models/deepseek-v3p2 | DeepSeek |
| MiniMax M2.1 | accounts/fireworks/models/minimax-m2p1 | MiniMax |
| Kimi K2.5 | accounts/fireworks/models/kimi-k2p5 | Moonshot |
| Qwen3 235B | accounts/fireworks/models/qwen3-235b-a22b | Alibaba |
| Llama 4 Maverick | accounts/fireworks/models/llama4-maverick-instruct-basic | Meta |

## Workflow

### Step 1: Gather User Input

Use AskUserQuestion to get:
1. The query/question for the council (or accept it from the conversation)
2. Which models to include (multiselect, recommend 3-5 models)
3. Which model should be the Chairman (single select)

Note: AskUserQuestion supports max 4 options per question. Since there are 7 models, split model selection across two questions, or show the most popular 4 and let the user type "Other" for the rest. A good default is to show 4 models in the first question and note the others are available via "Other". Rotate which models are shown based on variety.

Example AskUserQuestion for model selection (show 4, mention others):
```
question: "Which models should participate in the LLM Council? (Also available via Other: Llama 4 Maverick, Qwen3 235B, GLM 5)"
header: "Models"
multiSelect: true
options:
  - label: "DeepSeek V3.2"
    description: "DeepSeek's newest and most capable model"
  - label: "MiniMax M2.1"
    description: "MiniMax's strong open-weight model"
  - label: "Kimi K2.5"
    description: "Moonshot's strong open-weight model"
  - label: "DeepSeek V3.1"
    description: "DeepSeek's proven reasoning model"
```

Example AskUserQuestion for chairman:
```
question: "Which model should be the Chairman (synthesizes the final answer)?"
header: "Chairman"
multiSelect: false
options:
  - label: "DeepSeek V3.2 (Recommended)"
    description: "Newest DeepSeek, strong at comprehensive analysis"
  - label: "GLM 5"
    description: "Strong reasoning for synthesis"
  - label: "Kimi K2.5"
    description: "Strong at structured synthesis"
  - label: "MiniMax M2.1"
    description: "Strong open-weight model for synthesis"
```

### Model Name to ID Mapping

Use this mapping to convert user selections to Fireworks model IDs:

```python
MODEL_MAP = {
    "GLM 5": "accounts/fireworks/models/glm-5",
    "DeepSeek V3.1": "accounts/fireworks/models/deepseek-v3p1",
    "DeepSeek V3.2": "accounts/fireworks/models/deepseek-v3p2",
    "MiniMax M2.1": "accounts/fireworks/models/minimax-m2p1",
    "Kimi K2.5": "accounts/fireworks/models/kimi-k2p5",
    "Qwen3 235B": "accounts/fireworks/models/qwen3-235b-a22b",
    "Llama 4 Maverick": "accounts/fireworks/models/llama4-maverick-instruct-basic",
}
```

### Step 2: Run Phase 1 - Individual Responses

After gathering input, run this script to get responses from all selected models in parallel:

```bash
QUERY="USER_QUERY_HERE"
MODELS='["accounts/fireworks/models/glm-5", "accounts/fireworks/models/deepseek-v3p1"]'

python3 << 'PY
