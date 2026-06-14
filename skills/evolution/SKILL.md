---
name: evolution
description: This skill enables makepad-skills to self-improve continuously during development. 
category: Document Processing
source: antigravity
tags: [markdown, api, claude, ai, workflow, template, design, document]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/evolution
---


# Makepad Skills Evolution

This skill enables makepad-skills to self-improve continuously during development.

## When to Use
- You are maintaining `makepad-skills` and want the skill library to improve itself during development.
- You need the workflow for deciding when a new pattern should become a skill update or hook-driven evolution.
- You are working on self-correction, self-validation, or version adaptation for the skill set.

## Quick Navigation

| Topic | Description |
|-------|-------------|
| Collaboration Guidelines | **Contributing to makepad-skills** |
| [Hooks Setup](#hooks-based-auto-triggering) | Auto-trigger evolution with hooks |
| [When to Evolve](#when-to-evolve) | Triggers and classification |
| [Evolution Process](#evolution-process) | Step-by-step guide |
| [Self-Correction](#self-correction) | Auto-fix skill errors |
| [Self-Validation](#self-validation) | Verify skill accuracy |
| [Version Adaptation](#version-adaptation) | Multi-branch support |

---

## Hooks-Based Auto-Triggering

For reliable automatic triggering, use Claude Code hooks. Install with `--with-hooks`:

```bash
# Install makepad-skills with hooks enabled
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
curl -fsSLo "$tmpdir/makepad-skills-install.sh" https://raw.githubusercontent.com/ZhangHanDong/makepad-skills/main/install.sh
cat "$tmpdir/makepad-skills-install.sh"  # review the full installer before executing
bash "$tmpdir/makepad-skills-install.sh" --with-hooks
```

This will install hooks to `.claude/hooks/` and configure `.claude/settings.json`:

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "bash .claude/hooks/makepad-skill-router.sh"
          }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "Bash|Write|Edit",
        "hooks": [
          {
            "type": "command",
            "command": "bash .claude/hooks/pre-tool.sh"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "bash .claude/hooks/post-bash.sh"
          }
        ]
      }
    ]
  }
}
```

### What Hooks Do

| Hook | Trigger Event | Action |
|------|---------------|--------|
| `makepad-skill-router.sh` | UserPromptSubmit | Auto-route to relevant skills |
| `pre-tool.sh` | Before Bash/Write/Edit | Detect Makepad version from Cargo.toml |
| `post-bash.sh` | After Bash command fails | Detect Makepad errors, suggest fixes |
| `session-end.sh` | Session ends | Prompt to capture learnings |

---

## Skill Routing and Bundling

The `makepad-skill-router.sh` hook automatically loads relevant skills based on user queries.

### Context Detection

| Context | Trigger Keywords | Skills Loaded |
|---------|------------------|---------------|
| **Full App** | "build app", "从零", "完整应用" | basics, dsl, layout, widgets, event-action, app-architecture |
| **UI Design** | "ui design", "界面设计" | dsl, layout, widgets, animation, shaders |
| **Widget Creation** | "create widget", "创建组件", "自定义组件" | widgets, dsl, layout, animation, shaders, font, event-action |
| **Production** | "best practice", "robrix pattern", "实际项目" | app-architecture, widget-patterns, state-management, event-action |

### Skill Dependencies

When loading certain skills, related skills are auto-loaded:

| Primary Skill | Auto-loads |
|---------------|------------|
| robius-app-architecture | makepad-basics, makepad-event-action |
| robius-widget-patterns | makepad-widgets, makepad-layout |
| makepad-widgets | makepad-layout, makepad-dsl |
| makepad-animation | makepad-shaders |
| makepad-shaders | makepad-widgets |
| makepad-font | makepad-widgets |
| robius-event-action | makepad-event-action |

### Example

```
User: "我想从零开发一个 Makepad 应用"

[makepad-skills] Detected Makepad/Robius query
[makepad-skills] App development context detected - loading skill bundle
[makepad-skills] Routing to: makepad-basics makepad-dsl makepad-event-action
                            makepad-layout makepad-widgets robius-app-architecture
```

---

## When to Evolve

Trigger skill evolution when any of these occur during development:

| Trigger | Target Skill | Priority |
|---------|--------------|----------|
| New widget pattern discovered | robius-widget-patterns/_base | High |
| Shader technique learned | makepad-shaders | High |
| Compilation error solved | makepad-reference/troubleshooting | High |
| Layout solution found | makepad-reference/adaptive-layout | Medium |
| Build/packaging issue resolved | makepad-deployment | Medium |
| New project structure insight | makepad-basics | Low |
| Core concept clarified | makepad-dsl/makepad-widgets | Low |

---

## Evolution Process

### Step 1: Identify Knowledge Worth Capturing

Ask yourself:
- Is this a reusable pattern? (not project-specific)
- Did it take significant effort to figure out?
- Would 
