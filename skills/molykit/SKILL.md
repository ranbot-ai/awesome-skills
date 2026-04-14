---
name: molykit
description: CRITICAL: Use for MolyKit AI chat toolkit. Triggers on: BotClient, OpenAI, SSE streaming, AI chat, molykit, PlatformSend, spawn(), ThreadToken, cross-platform async, Chat widget, Messages, PromptInput
category: AI & Agents
source: antigravity
tags: [markdown, api, mcp, ai, llm, gpt, design, image, aws, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/molykit
---


# MolyKit Skill

Best practices for building AI chat interfaces with Makepad using MolyKit - a toolkit for cross-platform AI chat applications.

**Source codebase**: `/Users/zhangalex/Work/Projects/FW/robius/moly/moly-kit`

## When to Use
Use this skill when:
- Building AI chat interfaces with Makepad
- Integrating OpenAI or other LLM APIs
- Implementing cross-platform async for native and WASM
- Creating chat widgets (messages, prompts, avatars)
- Handling SSE streaming responses
- Keywords: molykit, moly-kit, ai chat, bot client, openai makepad, chat widget, sse streaming

## Overview

MolyKit provides:
- Cross-platform async utilities (PlatformSend, spawn(), ThreadToken)
- Ready-to-use chat widgets (Chat, Messages, PromptInput, Avatar)
- BotClient trait for AI provider integration
- OpenAI-compatible client with SSE streaming
- Protocol types for messages, bots, and tool calls
- MCP (Model Context Protocol) support

## Cross-Platform Async Patterns

### PlatformSend - Send Only on Native

```rust
/// Implies Send only on native platforms, not on WASM
/// - On native: implemented by types that implement Send
/// - On WASM: implemented by ALL types
pub trait PlatformSend: PlatformSendInner {}

/// Boxed future type for cross-platform use
pub type BoxPlatformSendFuture<'a, T> = Pin<Box<dyn PlatformSendFuture<Output = T> + 'a>>;

/// Boxed stream type for cross-platform use
pub type BoxPlatformSendStream<'a, T> = Pin<Box<dyn PlatformSendStream<Item = T> + 'a>>;
```

### Platform-Agnostic Spawning

```rust
/// Runs a future independently
/// - Uses tokio on native (requires Send)
/// - Uses wasm-bindgen-futures on WASM (no Send required)
pub fn spawn(fut: impl PlatformSendFuture<Output = ()> + 'static);

// Usage
spawn(async move {
    let result = fetch_data().await;
    Cx::post_action(DataReady(result));
    SignalToUI::set_ui_signal();
});
```

### Task Cancellation with AbortOnDropHandle

```rust
/// Handle that aborts its future when dropped
pub struct AbortOnDropHandle(AbortHandle);

// Usage - task cancelled when widget dropped
#[rust]
task_handle: Option<AbortOnDropHandle>,

fn start_task(&mut self) {
    let (future, handle) = abort_on_drop(async move {
        // async work...
    });
    self.task_handle = Some(handle);
    spawn(async move { let _ = future.await; });
}
```

### ThreadToken for Non-Send Types on WASM

```rust
/// Store non-Send value in thread-local, access via token
pub struct ThreadToken<T: 'static>;

impl<T> ThreadToken<T> {
    pub fn new(value: T) -> Self;
    pub fn peek<R>(&self, f: impl FnOnce(&T) -> R) -> R;
    pub fn peek_mut<R>(&self, f: impl FnOnce(&mut T) -> R) -> R;
}

// Usage - wrap non-Send type for use across Send boundaries
let token = ThreadToken::new(non_send_value);
spawn(async move {
    token.peek(|value| {
        // use value...
    });
});
```

## BotClient Trait

### Implementing AI Provider Integration

```rust
pub trait BotClient: Send {
    /// Send message with streamed response
    fn send(
        &mut self,
        bot_id: &BotId,
        messages: &[Message],
        tools: &[Tool],
    ) -> BoxPlatformSendStream<'static, ClientResult<MessageContent>>;

    /// Get available bots/models
    fn bots(&self) -> BoxPlatformSendFuture<'static, ClientResult<Vec<Bot>>>;

    /// Clone for passing around
    fn clone_box(&self) -> Box<dyn BotClient>;
}

// Usage
let client = OpenAIClient::new("https://api.openai.com/v1".into());
client.set_key("sk-...")?;
let context = BotContext::from(client);
```

### BotContext - Sharable Wrapper

```rust
/// Sharable wrapper with loaded bots for sync UI access
pub struct BotContext(Arc<Mutex<InnerBotContext>>);

impl BotContext {
    pub fn load(&mut self) -> BoxPlatformSendFuture<ClientResult<()>>;
    pub fn bots(&self) -> Vec<Bot>;
    pub fn get_bot(&self, id: &BotId) -> Option<Bot>;
    pub fn client(&self) -> Box<dyn BotClient>;
}

// Usage
let mut context = BotContext::from(client);
spawn(async move {
    if let Err(errors) = context.load().await.into_result() {
        // handle errors
    }
    Cx::post_action(BotsLoaded);
});
```

## Protocol Types

### Message Structure

```rust
pub struct Message {
    pub from: EntityId,         // User, System, Bot(BotId), App
    pub metadata: MessageMetadata,
    pub content: MessageContent,
}

pub struct MessageContent {
    pub text: String,           // Main content (markdown)
    pub reasoning: String,      // AI reasoning/thinking
    pub citations: Vec<String>, // Source URLs
    pub attachments: Vec<Attachment>,
    pub tool_calls: Vec<ToolCall>,
    pub tool_results: Vec<ToolResult>,
}

pub struct MessageMetadata {
    pub is_writing: bool,       // Still being streamed
    pub created_at: DateTime<Utc>,
}
```

### Bot Identification

```rust
/// Globally unique bot ID: <len>;<id>@<provider>
pub struct BotId(Arc<str>);

impl BotId {
    pub fn new(id: &str, provider: &str) -> Self;
    pub fn id(&self) -> &str;       // provider-local id
    pub fn provider
