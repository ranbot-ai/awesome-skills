---
name: axonx
description: Develop AxonX research plugins and operate quantitative research tasks through CLI or MCP, inspecting execution status, logs, artifacts, and lineage. 
category: Document Processing
source: antigravity
tags: [python, node, api, mcp, ai, agent, llm, workflow, document, presentation]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/axonx
---


# AxonX Development and Operations Guide

This guide can be read independently or installed as an Agent skill. Documentation and source links use absolute URLs, so copying this file does not depend on its original directory. The maintained project is [FlowLLM-AI/AxonX](https://github.com/FlowLLM-AI/AxonX).

Source paths such as `plugins/a158/...` are relative to the root of an AxonX source checkout, not to this document or the Agent workspace. Run source development and plugin build commands from that checkout. Workspace paths passed to Jobs such as `preview_file` are relative to the selected service's workspace. Package installation alone does not provide the example plugin sources.

## When to Use This Skill

- Use when developing or modifying AxonX research plugins and their typed Task contracts.
- Use when a user requests AxonX research task submission, execution tracking, failure investigation, or artifact inspection.
- Use when integrating an external Agent with an existing AxonX MCP service.

## Security & Safety Notes

This skill is labeled `critical` because it documents package installation, task submission, remote shell execution, cancellation, deletion, and artifact replacement. Establish the user's requested operation and exact service/workspace first. Do not treat command examples as authorization. Request clarification when the execution target or the scope of a destructive operation is unclear; existing explicit authorization remains valid. Never expose service or data-provider tokens in reports, logs, or committed files. Back up irreplaceable artifacts before authorized replacement or deletion.

## Prepare the Environment and Service

Use Python 3.12+ on macOS or Linux for local Task execution. In your chosen working directory, create and activate a virtual environment, then install the core:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install axonx
axonx help
```

For the prebuilt Studio UI, install `axonx[studio]` instead. Research plugins are installed separately. For source development, clone the project, enter its root, and install it in an activated virtual environment:

```bash
git clone https://github.com/FlowLLM-AI/AxonX.git
cd AxonX
pip install -e .
```

Configure credentials through environment variables or a `.env` file discovered from the process working directory or its parents. Before starting a local service, replace the token placeholder with your own value:

```bash
export AXONX_SERVICE_TOKEN='replace-with-your-local-service-token'
axonx start --service.host 127.0.0.1
```

Keep that process running. In another terminal, activate the same environment and configure the same token, then run `axonx version` to verify the connection. The default port is `1024`; the default workspace is `.axonx` under the startup directory. If using an existing service, obtain its address and authentication configuration before making calls. Keep one execution target for plugin queries, submissions, status, logs, and artifact inspection.

For MCP clients, connect to `http://127.0.0.1:1024/mcp` using Streamable HTTP and the header `Authorization: Bearer <service-token>`; replace the address and token with those of your service. Discover tools from the connected service rather than assuming a fixed tool catalog. The CLI examples below describe the same operations; use the discovered MCP input schemas when calling tools.

The built-in `demo` Task can verify submission and tracking without market-data or model credentials; the Alpha158 workflow requires its research plugin and prepared input data. Market-data downloads require `AXONX_TUSHARE_TOKEN`; model-backed Agents require separate model configuration. See [Quick start](https://flowllm-ai.github.io/AxonX/en/getting-started/quickstart), [Research workflow](https://flowllm-ai.github.io/AxonX/en/research/workflow), and [MCP integration](https://flowllm-ai.github.io/AxonX/en/agent/mcp-integration) for complete setup examples.

When using this document as a skill, perform only the operations required by the user's request. Documentation examples do not authorize installation, task execution, deletion, or remote changes by themselves. For changes to the source checkout, follow its `AGENTS.md` and [contribution guide](https://github.com/FlowLLM-AI/AxonX/blob/main/CONTRIBUTING.md).

## Background

AxonX is a harness framework for financial quantitative research, organizing data acquisition and ETL, factor analysis, model training, prediction, and backtesting into Tasks with consistent input/output contracts.
Plugins register research implementations; Tasks link upstream and downstream work through Task IDs. The CLI and HTTP service support submitting execution on local or remote machines and querying machine resources, runtime status, and logs.
The framework records task configuration, dependencies, result metadata, and artifacts in the workspace, and provides Agents with task, dependency graph, and file query tools to verify research 
