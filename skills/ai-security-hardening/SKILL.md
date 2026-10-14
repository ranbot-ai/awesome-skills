---
name: ai-security-hardening
description: Harden AI/LLM deployments against prompt injection, data exfiltration, model theft, and supply chain attacks. 
category: Security & Systems
source: antigravity
tags: [python, javascript, api, ai, agent, llm, gpt, template, security, kubernetes]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/ai-security-hardening
---


# AI Security Hardening

Secure LLM and AI systems against prompt injection, jailbreaks, data leakage, and supply chain threats in production environments.

## When to Use This Skill

Use this skill when:
- Deploying an LLM-powered application handling sensitive user data
- Protecting against prompt injection attacks in AI agents
- Implementing output filtering and content moderation
- Securing model weights and API endpoints from theft
- Achieving SOC2 or ISO 27001 compliance for AI systems

## AI-Specific Threat Model

```
Threat                    Risk                          Control
─────────────────────────────────────────────────────────────────────
Prompt injection          System prompt override         Input sanitization, separate context
Data exfiltration         PII in model outputs           Output filtering, DLP scanning
Jailbreaking             Policy bypass                  Content moderation, guardrails
Model theft               Weight extraction via API      Rate limiting, access controls
Training data poisoning   Backdoored fine-tuned model    Dataset validation, provenance
Supply chain attack       Malicious model weights        Signature verification, scanning
Insecure output           XSS/SQLi from LLM response     Output encoding, parameterized queries
```

## Prompt-injection indicators and authorization boundaries

Regex indicators have false positives and bypasses. They do not establish a prompt-injection security boundary. Keep untrusted content separate, enforce server-side tool/data authorization independent of model text, minimize accessible secrets and require approval for scoped side effects. The examples below are illustrative detectors, not proof an input or output is safe.

```python
import re
from typing import Optional

INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
    r"you\s+are\s+now\s+",
    r"new\s+instructions?:",
    r"system\s+prompt",
    r"forget\s+everything",
    r"act\s+as\s+",
    r"jailbreak",
    r"dan\s+mode",
    r"<\s*system\s*>",
    r"\[INST\]",
]

def detect_prompt_injection(user_input: str) -> tuple[bool, Optional[str]]:
    """Return (is_suspicious, matched_pattern)."""
    normalized = user_input.lower().strip()
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, normalized, re.IGNORECASE):
            return True, pattern
    return False, None

def sanitize_user_input(user_input: str, max_length: int = 4000) -> str:
    """Sanitize input before passing to LLM."""
    # Truncate
    user_input = user_input[:max_length]

    # Remove null bytes and control characters
    user_input = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', user_input)

    # Check for injection
    suspicious, pattern = detect_prompt_injection(user_input)
    if suspicious:
        raise ValueError(f"Potential prompt injection detected: {pattern}")

    return user_input
```

## Guardrails with NeMo Guardrails

```python
# guardrails.yaml
from nemoguardrails import RailsConfig, LLMRails

config = RailsConfig.from_path("./guardrails-config")
rails = LLMRails(config)

async def safe_llm_call(user_message: str) -> str:
    response = await rails.generate_async(
        messages=[{"role": "user", "content": user_message}]
    )
    return response["content"]
```

```yaml
# guardrails-config/config.yml
models:
  - type: main
    engine: openai
    model: gpt-4o-mini

rails:
  input:
    flows:
      - check jailbreak
      - check sensitive data
  output:
    flows:
      - check output for PII
      - check output for harmful content
```

## Output Filtering & PII Scrubbing

```python
import re
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

PII_ENTITIES = ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD",
                "US_SSN", "IBAN_CODE", "IP_ADDRESS", "LOCATION"]

def scrub_pii_from_output(text: str) -> str:
    """Remove PII from LLM output before returning to user."""
    results = analyzer.analyze(text=text, entities=PII_ENTITIES, language="en")
    if not results:
        return text
    anonymized = anonymizer.anonymize(text=text, analyzer_results=results)
    return anonymized.text

def has_no_known_output_indicators(output: str) -> bool:
    """No known regex match; does not prove SQL, HTML or command safety."""
    dangerous_patterns = [
        r"<\s*script\s*>",         # XSS
        r"javascript:",             # XSS
        r";\s*(DROP|DELETE|INSERT)",# SQLi
        r"\$\{.*\}",               # template injection
        r"`.*`",                   # command injection in some contexts
    ]
    for pattern in dangerous_patterns:
        if re.search(pattern, output, re.IGNORECASE):
            return False
    return True
```

## API Security for LLM Endpoints

Schematic example: bind SECRET_KEY, TOKEN_ISSUER and TOKEN_AUDIENCE to a verified trusted configuration. Require explicit scopes
