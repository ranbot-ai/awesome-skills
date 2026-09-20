---
name: ai-agent-security
description: Secure AI agents against prompt injection, tool abuse, and data exfiltration with defense-in-depth controls. 
category: Security & Systems
source: antigravity
tags: [python, api, ai, agent, workflow, template, design, document, image, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/ai-agent-security
---


# AI Agent Security

Protect agentic AI systems from adversarial input, unsafe tool execution, data leakage, and privilege abuse with layered security controls.

## Prerequisites

- Python 3.10+ for guardrail code examples
- Docker or Podman for sandbox execution
- OpenTelemetry collector for audit logging
- Familiarity with your agent framework (LangChain, CrewAI, Autogen, custom)
- Access to policy engine (OPA/Cedar) for permission boundaries

## Threat Model — STRIDE for AI Agents

AI agents introduce a unique threat surface. Apply STRIDE specifically to agentic components:

| Threat | Agent-Specific Example | Control |
|--------|----------------------|---------|
| **Spoofing** | Attacker crafts input that mimics a trusted internal tool response | Signed tool responses, HMAC verification |
| **Tampering** | Prompt injection modifies agent reasoning mid-chain | Input validation, prompt armoring |
| **Repudiation** | Agent takes destructive action with no audit trail | Immutable structured logging |
| **Information Disclosure** | Agent leaks PII, secrets, or internal architecture in responses | Output filtering, content classifiers |
| **Denial of Service** | Adversarial prompt causes infinite tool loops or token exhaustion | Rate limits, token budgets, circuit breakers |
| **Elevation of Privilege** | Agent escalates from read-only to write via chained tool calls | RBAC per tool, least-privilege scoping |

### Key Threat Categories

**Prompt Injection** — Untrusted content (user input, web scrapes, document contents) manipulates the agent's system prompt or reasoning chain to execute unintended actions.

**Tool Abuse** — The agent calls tools in sequences or with parameters the designer did not anticipate, achieving effects beyond its intended scope.

**Data Exfiltration** — The agent encodes sensitive data (credentials, PII, internal IPs) into its responses, tool calls, or outbound HTTP requests.

**Cross-Tenant Leakage** — In multi-tenant deployments, context from one tenant's session bleeds into another through shared memory, vector stores, or cache.

**Privilege Escalation** — The agent chains low-privilege tool calls to achieve high-privilege outcomes (e.g., read config -> extract credentials -> call admin API).

## Input Validation

Every input to an agent must be sanitized before it reaches the model or any tool. This includes user messages, tool outputs being fed back, and retrieved documents.

### Prompt Injection Detection

```python
import re
from dataclasses import dataclass
from enum import Enum

class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ValidationResult:
    is_safe: bool
    risk_level: RiskLevel
    matched_rules: list[str]
    sanitized_input: str

INJECTION_PATTERNS = [
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)", "instruction_override"),
    (r"you\s+are\s+now\s+(a|an|the)\s+", "role_hijack"),
    (r"system\s*:\s*", "system_prompt_inject"),
    (r"<\|?(system|im_start|endoftext)\|?>", "control_token_inject"),
    (r"\[INST\]|\[\/INST\]|<<SYS>>", "template_inject"),
    (r"(?:execute|run|eval)\s*\(", "code_execution_attempt"),
    (r"(?:curl|wget|nc|ncat)\s+", "network_command_inject"),
    (r"(?:rm\s+-rf|mkfs|dd\s+if=|chmod\s+777)", "destructive_command"),
    (r"(?:\/etc\/passwd|\/etc\/shadow|\.env\b|\.ssh\/)", "path_traversal"),
    (r"(?:BEGIN\s+(?:RSA|DSA|EC)\s+PRIVATE\s+KEY)", "secret_exfil_attempt"),
]

def validate_agent_input(user_input: str, max_length: int = 4096) -> ValidationResult:
    """Validate and sanitize input before passing to agent."""
    matched = []
    risk = RiskLevel.LOW

    # Length check
    if len(user_input) > max_length:
        matched.append("input_too_long")
        risk = RiskLevel.MEDIUM

    # Null byte and control character removal
    sanitized = user_input.replace("\x00", "")
    sanitized = re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1f]", "", sanitized)

    # Pattern matching
    for pattern, rule_name in INJECTION_PATTERNS:
        if re.search(pattern, sanitized, re.IGNORECASE):
            matched.append(rule_name)
            risk = RiskLevel.HIGH

    # Stacked injection detection (multiple suspicious patterns)
    if len(matched) >= 3:
        risk = RiskLevel.CRITICAL

    is_safe = risk in (RiskLevel.LOW, RiskLevel.MEDIUM)

    return ValidationResult(
        is_safe=is_safe,
        risk_level=risk,
        matched_rules=matched,
        sanitized_input=sanitized[:max_length] if is_safe else "",
    )
```

### Content Classification Middleware

Use a lightweight classifier as middleware before the agent processes any input:

```python
from functools import wraps
from typing import Callable

def input_guard(validator: Callable = validate_agent_input):
    """Decorator that guards agent entry points against unsafe input."""
    def decorator(func):
        @wraps(func)
        async def wrapper(user_input: str, *args, **kwargs):
