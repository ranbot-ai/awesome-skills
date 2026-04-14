---
name: hugging-face-gradio
description: Build or edit Gradio apps, layouts, components, and chat interfaces in Python. 
category: Document Processing
source: antigravity
tags: [python, markdown, api, mcp, ai, agent, workflow, template, document, image]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/hugging-face-gradio
---


# Gradio

## When to Use
Use this skill when a user wants a Gradio demo, UI prototype, or Python-based ML interface.

Gradio is a Python library for building interactive web UIs and ML demos. This skill covers the core API, patterns, and examples.

## Guides

Detailed guides on specific topics (read these when relevant):

- [Quickstart](https://www.gradio.app/guides/quickstart)
- [The Interface Class](https://www.gradio.app/guides/the-interface-class)
- [Blocks and Event Listeners](https://www.gradio.app/guides/blocks-and-event-listeners)
- [Controlling Layout](https://www.gradio.app/guides/controlling-layout)
- [More Blocks Features](https://www.gradio.app/guides/more-blocks-features)
- [Custom CSS and JS](https://www.gradio.app/guides/custom-CSS-and-JS)
- [Streaming Outputs](https://www.gradio.app/guides/streaming-outputs)
- [Streaming Inputs](https://www.gradio.app/guides/streaming-inputs)
- [Sharing Your App](https://www.gradio.app/guides/sharing-your-app)
- [Custom HTML Components](https://www.gradio.app/guides/custom-HTML-components)
- [Getting Started with the Python Client](https://www.gradio.app/guides/getting-started-with-the-python-client)
- [Getting Started with the JS Client](https://www.gradio.app/guides/getting-started-with-the-js-client)

## Core Patterns

**Interface** (high-level): wraps a function with input/output components.

```python
import gradio as gr

def greet(name):
    return f"Hello {name}!"

gr.Interface(fn=greet, inputs="text", outputs="text").launch()
```

**Blocks** (low-level): flexible layout with explicit event wiring.

```python
import gradio as gr

with gr.Blocks() as demo:
    name = gr.Textbox(label="Name")
    output = gr.Textbox(label="Greeting")
    btn = gr.Button("Greet")
    btn.click(fn=lambda n: f"Hello {n}!", inputs=name, outputs=output)

demo.launch()
```

**ChatInterface**: high-level wrapper for chatbot UIs.

```python
import gradio as gr

def respond(message, history):
    return f"You said: {message}"

gr.ChatInterface(fn=respond).launch()
```

## Key Component Signatures

### `Textbox(value: str | I18nData | Callable | None = None, type: Literal['text', 'password', 'email'] = "text", lines: int = 1, max_lines: int | None = None, placeholder: str | I18nData | None = None, label: str | I18nData | None = None, info: str | I18nData | None = None, every: Timer | float | None = None, inputs: Component | Sequence[Component] | set[Component] | None = None, show_label: bool | None = None, container: bool = True, scale: int | None = None, min_width: int = 160, interactive: bool | None = None, visible: bool | Literal['hidden'] = True, elem_id: str | None = None, autofocus: bool = False, autoscroll: bool = True, elem_classes: list[str] | str | None = None, render: bool = True, key: int | str | tuple[int | str, ...] | None = None, preserved_by_key: list[str] | str | None = "value", text_align: Literal['left', 'right'] | None = None, rtl: bool = False, buttons: list[Literal['copy'] | Button] | None = None, max_length: int | None = None, submit_btn: str | bool | None = False, stop_btn: str | bool | None = False, html_attributes: InputHTMLAttributes | None = None)`
Creates a textarea for user to enter string input or display string output..

### `Number(value: float | Callable | None = None, label: str | I18nData | None = None, placeholder: str | I18nData | None = None, info: str | I18nData | None = None, every: Timer | float | None = None, inputs: Component | Sequence[Component] | set[Component] | None = None, show_label: bool | None = None, container: bool = True, scale: int | None = None, min_width: int = 160, interactive: bool | None = None, visible: bool | Literal['hidden'] = True, elem_id: str | None = None, elem_classes: list[str] | str | None = None, render: bool = True, key: int | str | tuple[int | str, ...] | None = None, preserved_by_key: list[str] | str | None = "value", buttons: list[Button] | None = None, precision: int | None = None, minimum: float | None = None, maximum: float | None = None, step: float = 1)`
Creates a numeric field for user to enter numbers as input or display numeric output..

### `Slider(minimum: float = 0, maximum: float = 100, value: float | Callable | None = None, step: float | None = None, precision: int | None = None, label: str | I18nData | None = None, info: str | I18nData | None = None, every: Timer | float | None = None, inputs: Component | Sequence[Component] | set[Component] | None = None, show_label: bool | None = None, container: bool = True, scale: int | None = None, min_width: int = 160, interactive: bool | None = None, visible: bool | Literal['hidden'] = True, elem_id: str | None = None, elem_classes: list[str] | str | None = None, render: bool = True, key: int | str | tuple[int | str, ...] | None = None, preserved_by_key: list[str] | str | None = "value", randomize: bool = False, buttons: list[Literal['reset']] | None = None)`
Creates a slider that ranges from {minimum} to {maximum} with a step size of {step}..

##
