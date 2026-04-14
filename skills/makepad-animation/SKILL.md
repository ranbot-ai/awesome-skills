---
name: makepad-animation
description: CRITICAL: Use for Makepad animation system. Triggers on: makepad animation, makepad animator, makepad hover, makepad state, makepad transition, "from: { all: Forward", makepad pressed, makepad 动画,
category: Document Processing
source: antigravity
tags: [api, claude, ai, document, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/makepad-animation
---


# Makepad Animation Skill

> **Version:** makepad-widgets (dev branch) | **Last Updated:** 2026-01-19
>
> Check for updates: https://crates.io/crates/makepad-widgets

You are an expert at Makepad animations. Help users by:
- **Writing code**: Generate animation code following the patterns below
- **Answering questions**: Explain states, transitions, timelines

## When to Use
- You need to build or debug animations, transitions, hover states, or animator timelines in Makepad.
- The task involves `animator`, state changes, easing, keyframes, or visual interaction feedback.
- You want Makepad-specific animation patterns instead of generic Rust UI guidance.

## Documentation

Refer to the local files for detailed documentation:
- `./references/animation-system.md` - Complete animation reference

## Advanced Patterns

For production-ready animation patterns, see the `_base/` directory:

| Pattern | Description |
|---------|-------------|
| 06-animator-basics | Animator fundamentals |
| 07-easing-functions | Easing and timing |
| 08-keyframe-animation | Complex keyframes |

## IMPORTANT: Documentation Completeness Check

**Before answering questions, Claude MUST:**

1. Read the relevant reference file(s) listed above
2. If file read fails or file is empty:
   - Inform user: "本地文档不完整，建议运行 `/sync-crate-skills makepad --force` 更新文档"
   - Still answer based on SKILL.md patterns + built-in knowledge
3. If reference file exists, incorporate its content into the answer

## Key Patterns

### 1. Basic Hover Animation

```rust
<Button> {
    text: "Hover Me"

    animator: {
        hover = {
            default: off

            off = {
                from: { all: Forward { duration: 0.15 } }
                apply: {
                    draw_bg: { color: #333333 }
                }
            }

            on = {
                from: { all: Forward { duration: 0.15 } }
                apply: {
                    draw_bg: { color: #555555 }
                }
            }
        }
    }
}
```

### 2. Multi-State Animation

```rust
<View> {
    animator: {
        hover = {
            default: off
            off = {
                from: { all: Forward { duration: 0.2 } }
                apply: { draw_bg: { color: #222222 } }
            }
            on = {
                from: { all: Forward { duration: 0.2 } }
                apply: { draw_bg: { color: #444444 } }
            }
        }

        pressed = {
            default: off
            off = {
                from: { all: Forward { duration: 0.1 } }
                apply: { draw_bg: { scale: 1.0 } }
            }
            on = {
                from: { all: Forward { duration: 0.1 } }
                apply: { draw_bg: { scale: 0.95 } }
            }
        }
    }
}
```

### 3. Focus State Animation

```rust
<TextInput> {
    animator: {
        focus = {
            default: off

            off = {
                from: { all: Forward { duration: 0.2 } }
                apply: {
                    draw_bg: {
                        border_color: #444444
                        border_size: 1.0
                    }
                }
            }

            on = {
                from: { all: Forward { duration: 0.2 } }
                apply: {
                    draw_bg: {
                        border_color: #0066CC
                        border_size: 2.0
                    }
                }
            }
        }
    }
}
```

### 4. Disabled State

```rust
<Button> {
    animator: {
        disabled = {
            default: off

            off = {
                from: { all: Snap }
                apply: {
                    draw_bg: { color: #0066CC }
                    draw_text: { color: #FFFFFF }
                }
            }

            on = {
                from: { all: Snap }
                apply: {
                    draw_bg: { color: #333333 }
                    draw_text: { color: #666666 }
                }
            }
        }
    }
}
```

## Animator Structure

| Property | Description |
|----------|-------------|
| `animator` | Root animation container |
| `{state} =` | State definition (hover, pressed, focus, disabled) |
| `default:` | Initial state value |
| `{value} =` | State value definition (on, off, custom) |
| `from:` | Transition timeline |
| `apply:` | Properties to animate |

## Timeline Types (Play Enum)

| Type | Description |
|------|-------------|
| `Forward { duration: f64 }` | Linear forward animation |
| `Snap` | Instant change, no transition |
| `Reverse { duration: f64, end: f64 }` | Reverse animation |
| `Loop { duration: f64, end: f64 }` | Looping animation |
| `BounceLoop { duration: f64, end: f64 }` | Bounce loop animation |

## Easing Functions (Ease Enum)

```rust
// Basic
Linear

// Quadratic
InQuad, OutQuad, InOutQuad

// Cubic
InCubic, OutCubic, InOutCubic

// Quartic
InQuart, OutQuart, InOutQuart

// Quintic
InQuint, OutQuint, InOutQuint

// Sinusoidal
InSine, OutSine, InOutSi
