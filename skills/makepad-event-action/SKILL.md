---
name: makepad-event-action
description: CRITICAL: Use for Makepad event and action handling. Triggers on: makepad event, makepad action, Event enum, ActionTrait, handle_event, MouseDown, KeyDown, TouchUpdate, Hit, FingerDown, post_action, m
category: Document Processing
source: antigravity
tags: [claude, ai, design, document, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/makepad-event-action
---


# Makepad Event/Action Skill

> **Version:** makepad-widgets (dev branch) | **Last Updated:** 2026-01-19
>
> Check for updates: https://crates.io/crates/makepad-widgets

You are an expert at Makepad event and action handling. Help users by:
- **Handling events**: Mouse, keyboard, touch, lifecycle events
- **Creating actions**: Widget-to-parent communication
- **Event flow**: Understanding event propagation

## When to Use
- You need to handle input, lifecycle, or UI interaction events in Makepad.
- The task involves `handle_event`, `Event` variants, `Hit` processing, or widget action propagation.
- You need to design or debug Makepad event/action flow between widgets and parents.

## Documentation

Refer to the local files for detailed documentation:
- `./references/event-system.md` - Event enum and handling
- `./references/action-system.md` - Action trait and patterns

## IMPORTANT: Documentation Completeness Check

**Before answering questions, Claude MUST:**

1. Read the relevant reference file(s) listed above
2. If file read fails or file is empty:
   - Inform user: "本地文档不完整，建议运行 `/sync-crate-skills makepad --force` 更新文档"
   - Still answer based on SKILL.md patterns + built-in knowledge
3. If reference file exists, incorporate its content into the answer

## Event Enum (Key Variants)

```rust
pub enum Event {
    // Lifecycle
    Startup,
    Shutdown,
    Foreground,
    Background,
    Resume,
    Pause,

    // Drawing
    Draw(DrawEvent),
    LiveEdit,

    // Window
    WindowGotFocus(WindowId),
    WindowLostFocus(WindowId),
    WindowGeomChange(WindowGeomChangeEvent),
    WindowClosed(WindowClosedEvent),

    // Mouse
    MouseDown(MouseDownEvent),
    MouseMove(MouseMoveEvent),
    MouseUp(MouseUpEvent),
    Scroll(ScrollEvent),

    // Touch
    TouchUpdate(TouchUpdateEvent),

    // Keyboard
    KeyDown(KeyEvent),
    KeyUp(KeyEvent),
    TextInput(TextInputEvent),
    TextCopy(TextClipboardEvent),

    // Timer
    Timer(TimerEvent),
    NextFrame(NextFrameEvent),

    // Network
    HttpResponse(HttpResponse),

    // Widget Actions
    Actions(ActionsBuf),
}
```

## Handling Events in Widgets

```rust
impl Widget for MyWidget {
    fn handle_event(&mut self, cx: &mut Cx, event: &Event, scope: &mut Scope) {
        // Check if event hits this widget's area
        match event.hits(cx, self.area()) {
            Hit::FingerDown(fe) => {
                // Mouse/touch down on this widget
                cx.action(MyWidgetAction::Pressed);
            }
            Hit::FingerUp(fe) => {
                if fe.is_over {
                    // Released while still over widget = click
                    cx.action(MyWidgetAction::Clicked);
                }
            }
            Hit::FingerHoverIn(_) => {
                self.animator_play(cx, id!(hover.on));
            }
            Hit::FingerHoverOut(_) => {
                self.animator_play(cx, id!(hover.off));
            }
            Hit::KeyDown(ke) => {
                if ke.key_code == KeyCode::Return {
                    cx.action(MyWidgetAction::Submitted);
                }
            }
            _ => {}
        }
    }
}
```

## Hit Enum

```rust
pub enum Hit {
    // Finger/Mouse
    FingerDown(FingerDownEvent),
    FingerUp(FingerUpEvent),
    FingerMove(FingerMoveEvent),
    FingerHoverIn(FingerHoverEvent),
    FingerHoverOver(FingerHoverEvent),
    FingerHoverOut(FingerHoverEvent),
    FingerLongPress(FingerLongPressEvent),

    // Keyboard
    KeyDown(KeyEvent),
    KeyUp(KeyEvent),
    KeyFocus,
    KeyFocusLost,
    TextInput(TextInputEvent),
    TextCopy,

    // Nothing
    Nothing,
}
```

## Action System

### Defining Actions

```rust
#[derive(Clone, Debug, DefaultNone)]
pub enum ButtonAction {
    None,
    Clicked,
    Pressed,
    Released,
}

// DefaultNone derives Default returning None variant
```

### Emitting Actions

```rust
// From main thread (in handle_event)
cx.action(ButtonAction::Clicked);

// From any thread (thread-safe)
Cx::post_action(MyAction::DataLoaded(data));
```

### Handling Actions

```rust
fn handle_event(&mut self, cx: &mut Cx, event: &Event, scope: &mut Scope) {
    // Handle child widget actions
    let actions = cx.capture_actions(|cx| {
        self.button.handle_event(cx, event, scope);
    });

    // Check for specific action
    if self.button(id!(my_button)).clicked(&actions) {
        // Button was clicked
    }

    // Or iterate actions
    for action in actions.iter() {
        if let Some(ButtonAction::Clicked) = action.downcast_ref() {
            // Handle click
        }
    }
}
```

## Widget Action Helpers

```rust
// Common widget action checks
impl ButtonRef {
    fn clicked(&self, actions: &ActionsBuf) -> bool;
    fn pressed(&self, actions: &ActionsBuf) -> bool;
    fn released(&self, actions: &ActionsBuf) -> bool;
}

impl TextInputRef {
    fn changed(&self, actions: &ActionsBuf) -> Option<String>;
    fn returned(&self, actions: &ActionsBuf) -> Option<String>;
