---
name: robius-app-architecture
description: CRITICAL: Use for Robius app architecture patterns. Triggers on: Tokio, async, submit_async_request, 异步, 架构, SignalToUI, Cx::post_action, worker task, app structure, MatchEvent, handle_startup
category: AI & Agents
source: antigravity
tags: [api, ai, design, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/robius-app-architecture
---


# Robius App Architecture Skill

Best practices for structuring Makepad applications based on the Robrix and Moly codebases - production applications built with Makepad and Robius framework.

**Source codebases:**
- **Robrix**: Matrix chat client - complex sync/async with background subscriptions
- **Moly**: AI chat application - cross-platform (native + WASM) with streaming APIs

## Triggers

Use this skill when:
- Building a Makepad application with async backend integration
- Designing sync/async communication patterns in Makepad
- Structuring a Robius-style application
- Keywords: robrix, robius, makepad app structure, async makepad, tokio makepad

## Production Patterns

For production-ready async patterns, see the `_base/` directory:

| Pattern | Description |
|---------|-------------|
| 08-async-loading | Async data loading with loading states |
| 09-streaming-results | Incremental results with SignalToUI |
| 13-tokio-integration | Full tokio runtime integration |

## Core Architecture Pattern

```
┌─────────────────────────────────────────────────────────────┐
│                     UI Thread (Makepad)                     │
│  ┌─────────┐     ┌──────────┐     ┌──────────────────────┐ │
│  │   App   │────▶│ WidgetRef │────▶│ Widget Tree (View)  │ │
│  │ State   │     │    ui     │     │ Scope::with_data()  │ │
│  └────┬────┘     └──────────┘     └──────────────────────┘ │
│       │                                                     │
│       │ submit_async_request()                              │
│       ▼                                                     │
│  ┌─────────────────┐          ┌─────────────────────────┐  │
│  │ REQUEST_SENDER  │─────────▶│  Crossbeam SegQueue     │  │
│  │ (MPSC Channel)  │          │  (Lock-free Updates)    │  │
│  └─────────────────┘          └─────────────────────────┘  │
└───────────────────────────────────┬─────────────────────────┘
                                    │
                    SignalToUI::set_ui_signal()
                                    │
┌───────────────────────────────────┴─────────────────────────┐
│                   Tokio Runtime (Async)                      │
│  ┌──────────────────────────────────────────────────────┐   │
│  │           worker_task (Request Handler)               │   │
│  │  - Receives Request from UI                           │   │
│  │  - Spawns async tasks per request                     │   │
│  │  - Posts actions back via Cx::post_action()           │   │
│  └──────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │         Per-Item Subscriber Tasks                     │   │
│  │  - Listens to external data stream                    │   │
│  │  - Sends Update via crossbeam channel                 │   │
│  │  - Calls SignalToUI::set_ui_signal() to wake UI       │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## App Structure

### Top-Level App Definition

```rust
use makepad_widgets::*;

live_design! {
    use link::theme::*;
    use link::widgets::*;

    App = {{App}} {
        ui: <Root>{
            main_window = <Window> {
                window: {inner_size: vec2(1280, 800), title: "MyApp"},
                body = {
                    // Main content here
                }
            }
        }
    }
}

app_main!(App);

#[derive(Live)]
pub struct App {
    #[live] ui: WidgetRef,
    #[rust] app_state: AppState,
}

impl LiveRegister for App {
    fn live_register(cx: &mut Cx) {
        // Order matters: register base widgets first
        makepad_widgets::live_design(cx);
        // Then shared/common widgets
        crate::shared::live_design(cx);
        // Then feature modules
        crate::home::live_design(cx);
    }
}

impl LiveHook for App {
    fn after_new_from_doc(&mut self, cx: &mut Cx) {
        // One-time initialization after widget tree is created
    }
}
```

### AppMain Implementation

```rust
impl AppMain for App {
    fn handle_event(&mut self, cx: &mut Cx, event: &Event) {
        // Forward to MatchEvent trait
        self.match_event(cx, event);

        // Pass AppState through widget tree via Scope
        let scope = &mut Scope::with_data(&mut self.app_state);
        self.ui.handle_event(cx, event, scope);
    }
}
```

## Tokio Runtime Integration

### Static Runtime Initialization

```rust
use std::sync::Mutex;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

static TOKIO_RUNTIME: Mutex<Option<tokio::runtime::Runtime>> = Mutex::new(None);
static REQUEST_SENDER: Mutex<Option<UnboundedSender<AppRequest>>> = Mutex::new(None);

pub fn start_async_runtime() -> Result<tokio::runtime::Handle> {
    let (request_sender, request_receiver) = tokio::sync::mpsc::unbounded_channel();

    let rt_handle = TOKIO_RUNTIME.lock().unwrap()
        .get_or_insert_with(|| {
            tokio::runtime::Runtime::new()
                .e
