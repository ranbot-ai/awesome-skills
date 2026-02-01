---
name: computer-use-agents
description: Build AI agents that interact with computers like humans do - viewing screens, moving cursors, clicking buttons, and typing text. Covers Anthropic's Computer Use, OpenAI's Operator/CUA, and open-sourc
category: AI & Agents
source: antigravity
tags: [python, api, claude, ai, agent, automation, image, security, docker, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/computer-use-agents
---


# Computer Use Agents

## Patterns

### Perception-Reasoning-Action Loop

The fundamental architecture of computer use agents: observe screen,
reason about next action, execute action, repeat. This loop integrates
vision models with action execution through an iterative pipeline.

Key components:
1. PERCEPTION: Screenshot captures current screen state
2. REASONING: Vision-language model analyzes and plans
3. ACTION: Execute mouse/keyboard operations
4. FEEDBACK: Observe result, continue or correct

Critical insight: Vision agents are completely still during "thinking"
phase (1-5 seconds), creating a detectable pause pattern.


**When to use**: ['Building any computer use agent from scratch', 'Integrating vision models with desktop control', 'Understanding agent behavior patterns']

```python
from anthropic import Anthropic
from PIL import Image
import base64
import pyautogui
import time

class ComputerUseAgent:
    """
    Perception-Reasoning-Action loop implementation.
    Based on Anthropic Computer Use patterns.
    """

    def __init__(self, client: Anthropic, model: str = "claude-sonnet-4-20250514"):
        self.client = client
        self.model = model
        self.max_steps = 50  # Prevent runaway loops
        self.action_delay = 0.5  # Seconds between actions

    def capture_screenshot(self) -> str:
        """Capture screen and return base64 encoded image."""
        screenshot = pyautogui.screenshot()
        # Resize for token efficiency (1280x800 is good balance)
        screenshot = screenshot.resize((1280, 800), Image.LANCZOS)

        import io
        buffer = io.BytesIO()
        screenshot.save(buffer, format="PNG")
        return base64.b64encode(buffer.getvalue()).decode()

    def execute_action(self, action: dict) -> dict:
        """Execute mouse/keyboard action on the computer."""
        action_type = action.get("type")

        if action_type == "click":
            x, y = action["x"], action["y"]
            button = action.get("button", "left")
            pyautogui.click(x, y, button=button)
            return {"success": True, "action": f"clicked at ({x}, {y})"}

        elif action_type == "type":
            text = action["text"]
            pyautogui.typewrite(text, interval=0.02)
            return {"success": True, "action": f"typed {len(text)} chars"}

        elif action_type == "key":
            key = action["key"]
            pyautogui.press(key)
            return {"success": True, "action": f"pressed {key}"}

        elif action_type == "scroll":
            direction = action.get("direction", "down")
            amount = action.get("amount", 3)
            scroll = -amount if direction == "down" else amount
            pyautogui.scroll(scroll)
            return {"success": True, "action": f"scrolled {dir
```

### Sandboxed Environment Pattern

Computer use agents MUST run in isolated, sandboxed environments.
Never give agents direct access to your main system - the security
risks are too high. Use Docker containers with virtual desktops.

Key isolation requirements:
1. NETWORK: Restrict to necessary endpoints only
2. FILESYSTEM: Read-only or scoped to temp directories
3. CREDENTIALS: No access to host credentials
4. SYSCALLS: Filter dangerous system calls
5. RESOURCES: Limit CPU, memory, time

The goal is "blast radius minimization" - if the agent goes wrong,
damage is contained to the sandbox.


**When to use**: ['Deploying any computer use agent', 'Testing agent behavior safely', 'Running untrusted automation tasks']

```python
# Dockerfile for sandboxed computer use environment
# Based on Anthropic's reference implementation pattern

FROM ubuntu:22.04

# Install desktop environment
RUN apt-get update && apt-get install -y \
    xvfb \
    x11vnc \
    fluxbox \
    xterm \
    firefox \
    python3 \
    python3-pip \
    supervisor

# Security: Create non-root user
RUN useradd -m -s /bin/bash agent && \
    mkdir -p /home/agent/.vnc

# Install Python dependencies
COPY requirements.txt /tmp/
RUN pip3 install -r /tmp/requirements.txt

# Security: Drop capabilities
RUN apt-get install -y --no-install-recommends libcap2-bin && \
    setcap -r /usr/bin/python3 || true

# Copy agent code
COPY --chown=agent:agent . /app
WORKDIR /app

# Supervisor config for virtual display + VNC
COPY supervisord.conf /etc/supervisor/conf.d/

# Expose VNC port only (not desktop directly)
EXPOSE 5900

# Run as non-root
USER agent

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]

---

# docker-compose.yml with security constraints
version: '3.8'

services:
  computer-use-agent:
    build: .
    ports:
      - "5900:5900"  # VNC for observation
      - "8080:8080"  # API for control

    # Security constraints
    security_opt:
      - no-new-privileges:true
      - seccomp:seccomp-profile.json

    # Resource limits
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 4G
        reservations:
          cpus: '0.5'
      
