---
name: swiftui-expert-skill
description: Write, review, or improve SwiftUI code following best practices for state management, view composition, performance, modern APIs, Swift concurrency, and iOS 26+ Liquid Glass adoption. Use when buildin
category: Creative & Media
source: antigravity
tags: [react, api, ai, agent, workflow, design, presentation, image, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/swiftui-expert-skill
---


# SwiftUI Expert Skill

## Overview
Use this skill to build, review, or improve SwiftUI features with correct state management, modern API usage, Swift concurrency best practices, optimal view composition, and iOS 26+ Liquid Glass styling. Prioritize native APIs, Apple design guidance, and performance-conscious patterns. This skill focuses on facts and best practices without enforcing specific architectural patterns.

## When to Use This Skill

Use this skill when:
- Building new SwiftUI features
- Refactoring existing SwiftUI views
- Reviewing SwiftUI code quality
- Adopting modern SwiftUI patterns
- Working with SwiftUI state management
- Implementing iOS 26+ Liquid Glass styling

## Workflow Decision Tree

### 1) Review existing SwiftUI code
- Check property wrapper usage against the selection guide (see `references/state-management.md`)
- Verify modern API usage (see `references/modern-apis.md`)
- Verify view composition follows extraction rules (see `references/view-structure.md`)
- Check performance patterns are applied (see `references/performance-patterns.md`)
- Verify list patterns use stable identity (see `references/list-patterns.md`)
- Inspect Liquid Glass usage for correctness and consistency (see `references/liquid-glass.md`)
- Validate iOS 26+ availability handling with sensible fallbacks

### 2) Improve existing SwiftUI code
- Audit state management for correct wrapper selection (prefer `@Observable` over `ObservableObject`)
- Replace deprecated APIs with modern equivalents (see `references/modern-apis.md`)
- Extract complex views into separate subviews (see `references/view-structure.md`)
- Refactor hot paths to minimize redundant state updates (see `references/performance-patterns.md`)
- Ensure ForEach uses stable identity (see `references/list-patterns.md`)
- Suggest image downsampling when `UIImage(data:)` is used (as optional optimization, see `references/image-optimization.md`)
- Adopt Liquid Glass only when explicitly requested by the user

### 3) Implement new SwiftUI feature
- Design data flow first: identify owned vs injected state (see `references/state-management.md`)
- Use modern APIs (no deprecated modifiers or patterns, see `references/modern-apis.md`)
- Use `@Observable` for shared state (with `@MainActor` if not using default actor isolation)
- Structure views for optimal diffing (extract subviews early, keep views small, see `references/view-structure.md`)
- Separate business logic into testable models (see `references/layout-best-practices.md`)
- Apply glass effects after layout/appearance modifiers (see `references/liquid-glass.md`)
- Gate iOS 26+ features with `#available` and provide fallbacks

## Core Guidelines

### State Management
- **Always prefer `@Observable` over `ObservableObject`** for new code
- **Mark `@Observable` classes with `@MainActor`** unless using default actor isolation
- **Always mark `@State` and `@StateObject` as `private`** (makes dependencies clear)
- **Never declare passed values as `@State` or `@StateObject`** (they only accept initial values)
- Use `@State` with `@Observable` classes (not `@StateObject`)
- `@Binding` only when child needs to **modify** parent state
- `@Bindable` for injected `@Observable` objects needing bindings
- Use `let` for read-only values; `var` + `.onChange()` for reactive reads
- Legacy: `@StateObject` for owned `ObservableObject`; `@ObservedObject` for injected
- Nested `ObservableObject` doesn't work (pass nested objects directly); `@Observable` handles nesting fine

### Modern APIs
- Use `foregroundStyle()` instead of `foregroundColor()`
- Use `clipShape(.rect(cornerRadius:))` instead of `cornerRadius()`
- Use `Tab` API instead of `tabItem()`
- Use `Button` instead of `onTapGesture()` (unless need location/count)
- Use `NavigationStack` instead of `NavigationView`
- Use `navigationDestination(for:)` for type-safe navigation
- Use two-parameter or no-parameter `onChange()` variant
- Use `ImageRenderer` for rendering SwiftUI views
- Use `.sheet(item:)` instead of `.sheet(isPresented:)` for model-based content
- Sheets should own their actions and call `dismiss()` internally
- Use `ScrollViewReader` for programmatic scrolling with stable IDs
- Avoid `UIScreen.main.bounds` for sizing
- Avoid `GeometryReader` when alternatives exist (e.g., `containerRelativeFrame()`)

### Swift Best Practices
- Use modern Text formatting (`.format` parameters, not `String(format:)`)
- Use `localizedStandardContains()` for user-input filtering (not `contains()`)
- Prefer static member lookup (`.blue` vs `Color.blue`)
- Use `.task` modifier for automatic cancellation of async work
- Use `.task(id:)` for value-dependent tasks

### View Composition
- **Prefer modifiers over conditional views** for state changes (maintains view identity)
- Extract complex views into separate subviews for better readability and performance
- Keep views small for optimal performance
- Keep view `body` simple and pure (no side effects or complex logic)
- Use
