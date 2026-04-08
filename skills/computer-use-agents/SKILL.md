---
name: computer-use-agents
description: Build AI agents that interact with computers like humans do - viewing screens, moving cursors, clicking buttons, and typing text. Covers Anthropic's Computer Use, OpenAI's Operator/CUA, and open-sourc
category: AI & Agents
source: antigravity
tags: [python, react, api, mcp, claude, ai, agent, llm, gpt, automation]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/computer-use-agents
---


# Computer Use Agents

Build AI agents that interact with computers like humans do - viewing screens,
moving cursors, clicking buttons, and typing text. Covers Anthropic's Computer
Use, OpenAI's Operator/CUA, and open-source alternatives. Critical focus on
sandboxing, security, and handling the unique challenges of vision-based control.

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

**When to use**: Building any computer use agent from scratch,Integrating vision models with desktop control,Understanding agent behavior patterns

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
            return {"success": True, "action": f"scrolled {direction}"}

        elif action_type == "move":
            x, y = action["x"], action["y"]
            pyautogui.moveTo(x, y)
            return {"success": True, "action": f"moved to ({x}, {y})"}

        else:
            return {"success": False, "error": f"Unknown action: {action_type}"}

    def run(self, task: str) -> dict:
        """
        Run perception-reasoning-action loop until task complete.

        The loop:
        1. Screenshot current state
        2. Send to vision model with task context
        3. Parse action from response
        4. Execute action
        5. Repeat until done or max steps
        """
        messages = []
        step_count = 0

        system_prompt = """You are a computer use agent. You can see the screen
        and control mouse/keyboard.

        Available actions (respond with JSON):
        - {"type": "click", "x": 100, "y": 200, "button": "left"}
        - {"type": "type", "text": "hello world"}
        - {"type": "key", "key": "enter"}
        - {"type": "scroll", "direction": "down", "amount": 3}
        - {"type": "done", "result": "task completed successfully"}

        Always respond with ONLY a JSON action object.
        Be precise with coordinates - click exactly where needed.
        If you see an error, try to recover.
        """

        while step_count < self.max_steps:
            step_count += 1

            # 1. PERCEPTION: Capture current screen
            screenshot_b64 = self.capture_screenshot()

            # 2. REASONING: Send to vision model
            user_content = [
                {"type": "text", "text": f"Task: {task}\n\nStep {step_count}. What action should I take?"},
                {"type": "image", "source": {
                    "type": "base64",
                    "media_type": "image/png",
                    "data": screenshot_b64
                }}
            ]

            me
