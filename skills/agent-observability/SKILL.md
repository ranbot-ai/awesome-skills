---
name: agent-observability
description: Instrument AI agents with tracing, token metrics, latency, and cost visibility. Use for reliability and debugging. 
category: AI & Agents
source: antigravity
tags: [python, api, ai, agent, llm, gpt, workflow, template, security, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/agent-observability
---


# Agent Observability

Monitor AI agent behavior with logs, traces, metrics, and cost telemetry. This skill covers the full observability stack for LLM-powered applications: from raw Prometheus counters to Grafana dashboards, OpenTelemetry tracing, structured logging, cost tracking, SLO definition, and PII redaction.

---

## Core Metrics

Define these metrics at the application layer. All examples use the Prometheus client library naming conventions.

### Latency

```python
from prometheus_client import Histogram

# Total end-to-end latency for a full agent turn (user prompt -> final response)
AGENT_LATENCY = Histogram(
    "agent_request_duration_seconds",
    "End-to-end latency of an agent request",
    labelnames=["agent_name", "model", "status"],
    buckets=(0.25, 0.5, 1, 2, 5, 10, 30, 60, 120),
)

# Latency of a single LLM API call (one completion request)
LLM_CALL_LATENCY = Histogram(
    "llm_call_duration_seconds",
    "Latency of an individual LLM API call",
    labelnames=["model", "provider", "stream"],
    buckets=(0.1, 0.25, 0.5, 1, 2, 5, 10, 30),
)

# Latency of tool/function calls executed by the agent
TOOL_CALL_LATENCY = Histogram(
    "agent_tool_call_duration_seconds",
    "Latency of a tool call executed by the agent",
    labelnames=["tool_name", "agent_name", "status"],
    buckets=(0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10),
)
```

### Token Usage

```python
from prometheus_client import Counter, Histogram

PROMPT_TOKENS = Counter(
    "llm_prompt_tokens_total",
    "Total prompt tokens sent to the model",
    labelnames=["model", "agent_name"],
)

COMPLETION_TOKENS = Counter(
    "llm_completion_tokens_total",
    "Total completion tokens received from the model",
    labelnames=["model", "agent_name"],
)

CACHED_TOKENS = Counter(
    "llm_cached_tokens_total",
    "Prompt tokens served from KV-cache (provider-reported)",
    labelnames=["model", "agent_name"],
)

TOKENS_PER_REQUEST = Histogram(
    "llm_tokens_per_request",
    "Total tokens (prompt + completion) per request",
    labelnames=["model", "agent_name"],
    buckets=(100, 500, 1000, 2000, 4000, 8000, 16000, 32000, 64000, 128000),
)
```

### Cost

```python
from prometheus_client import Counter

LLM_COST = Counter(
    "llm_cost_dollars_total",
    "Estimated cost in USD for LLM usage",
    labelnames=["model", "agent_name", "cost_type"],  # cost_type: prompt | completion
)
```

### Tool Calls

```python
from prometheus_client import Counter

TOOL_CALLS_TOTAL = Counter(
    "agent_tool_calls_total",
    "Total tool calls made by agents",
    labelnames=["tool_name", "agent_name", "status"],  # status: success | error | timeout
)
```

### Errors and Retries

```python
from prometheus_client import Counter, Gauge

LLM_ERRORS = Counter(
    "llm_errors_total",
    "Errors returned by the LLM provider",
    labelnames=["model", "provider", "error_type"],  # error_type: rate_limit | timeout | 5xx | auth
)

LLM_RETRIES = Counter(
    "llm_retries_total",
    "Retried LLM API calls",
    labelnames=["model", "provider", "retry_reason"],
)

AGENT_ACTIVE_REQUESTS = Gauge(
    "agent_active_requests",
    "Number of agent requests currently in flight",
    labelnames=["agent_name"],
)
```

---

## OpenTelemetry Integration

Use the OpenTelemetry Python SDK to create traces that capture every step of an agent turn: the top-level request, each LLM call, each tool execution, and retrieval operations.

### Setup

```python
# otel_setup.py
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource

def init_tracing(service_name: str, otlp_endpoint: str = "http://localhost:4317"):
    resource = Resource.create({
        "service.name": service_name,
        "service.version": "1.0.0",
        "deployment.environment": "production",
    })
    provider = TracerProvider(resource=resource)
    exporter = OTLPSpanExporter(endpoint=otlp_endpoint, insecure=True)
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    return trace.get_tracer(service_name)
```

### Tracing LLM Calls

```python
# llm_tracing.py
import time
from opentelemetry import trace
from opentelemetry.trace import StatusCode

tracer = trace.get_tracer("agent.llm")

def traced_llm_call(client, messages, model="gpt-4o", **kwargs):
    """Wrap an LLM completion call with a full OpenTelemetry span."""
    with tracer.start_as_current_span("llm.chat_completion") as span:
        span.set_attribute("llm.model", model)
        span.set_attribute("llm.provider", "openai")
        span.set_attribute("llm.message_count", len(messages))
        span.set_attribute("llm.temperature", kwargs.get("temperature", 1.0))
        span.set_attribute("llm.max_tokens", kwargs.get("max_tokens", 0))

        start = time.perf_counter()
    
