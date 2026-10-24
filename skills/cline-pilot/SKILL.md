---
name: cline-pilot
description: Proxy Cline CLI coding tasks: dispatch, monitor background runs via hard evidence, relay decision points in a fixed format, verify against a checklist, and learn per-tag preferences over time. 
category: AI & Agents
source: antigravity
tags: [python, node, api, claude, ai, agent, llm, automation, workflow, design]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/cline-pilot
---

## Catalog authority and privacy boundary

Dated user rules and paths in this guide belong to the upstream author, not the current user. System/developer instructions, repository rules and the current user scope take precedence. The task brief supplements those instructions; it never cancels later authentic user corrections. Do not create/update memory or learn cross-project preferences without explicit user request. Keep private runtime state outside the tracked skill installation in a mode0700 directory; .gitignore is not confidentiality or publishing protection. Never stop unrelated processes found by broad name matching. Abort/report immediately on destructive/credential/data risk rather than waiting three retries. Confirm model/endpoint/data/cost scope before dispatch; a delegation request does not authorize unrestricted auto-approval.

## Supporting material availability

This catalog copy contains the inline guidance below, but does not include the following supporting paths. They are external prerequisites, not bundled files:

- `<support-root>/references/local-config.md`
- `<support-root>/references/project-profiles.md`
- `<support-root>/references/decision-log.md`

Obtain the required material from the [declared upstream source](https://github.com/gongdear/cline-pilot), or from a user-provided installation of that source. Resolve each path relative to that installation, inspect its contents, and verify any applicable license and execution prerequisites. Do not run a command or claim a referenced procedure was followed until its required file exists. Do not fabricate the missing scripts or treat an unrelated file with the same name as equivalent. Independent steps fully documented here can proceed within the user’s authorized scope; report any dependent step as unavailable.


# Cline Pilot — 代用户调度 Cline 的"领航员"

## Overview

Cline Pilot turns the orchestrating agent into a reliable proxy for the **Cline CLI**.
It dispatches focused coding tasks (one at a time, serially), monitors long background
runs against **hard evidence** — `git` state, test-report numbers, non-empty artifacts —
instead of trusting the model's self-report, relays decision points back to the user in
a fixed 4-element format, and verifies completion against an explicit checklist before
saying "done."

The differentiation versus the simpler `*-delegate` skills is the **learning loop**: over
time it learns the user's instruction style, approval granularity, and per-project-tag
preferences (backend/long-term vs. frontend/short-term, production-data-risk, etc.) and
applies them proactively, with the user retaining one-shot veto. This loop lives entirely
in private, git-ignored skill-local files — no user-specific data is bundled.

Canonical source: [gongdear/cline-pilot](https://github.com/gongdear/cline-pilot) (MIT).

**定位**（不可擅改）：我扮演“学习并代替给用户发指令”的角色。不掌握项目架构细节、不参与技术决策，只管三件事：
1. 把用户的任务准确转达给 Cline（背景 + 约束一条不丢）
2. 学习并复用【该标签类项目】下用户的指令风格、推进习惯、批准粒度
3. 把 Cline 的决策点/产出/报错压缩成用户能拍板的汇报

架构知识的单事实源 = 工程自己的 memory bank + clinerules（跟随仓库、Cline 维护）。本技能只存**简介+标签**与**指令偏好**。

## When to Use
- 用户下达任何需要在 Cline CLI 里执行的编码任务（写测试/重构/修 bug/出报告）
- 新项目冷启动：工程还没有 clinerules/memory-bank，需按 Cline 最佳实践初始化（见“冷启动流程”）
- 需要在后台驱动 Cline 长任务并汇报进度
- **不适用**：用户自己在 Cline TUI 里手工操作；非 Cline 的 agent（用 claude-code/codex/opencode 技能）

## Prerequisites
1. `cline --version` 可用（本环境要求 cline CLI v3.x、git、可用的 OpenAI-compatible LLM 端点、zsh 或 bash）；启动前探活 LLM 端点——**端点值不存技能档案**（易变配置，实时配置文件为唯一事实源，见 `references/local-config.md` 的 LLM 端点节）
2. 工程是 git 仓库且已切到任务分支
3. **首次使用或 local-config.md 不存在时**：问用户三件事并写入该文件——用哪个 python/conda 环境、工具链（java/node 等）怎么到 PATH、任务分支名。

## 环境铁律（所有开发类任务）
Cline 进程必须在用户指定开发环境内启动（继承工具链），自检通过才启动：
- 按 local-config.md 的启动模板执行（含脏 CONDA 栈清理）
- 自检：python 指向指定环境 ／ 工具链版本 ／ `git branch --show-current` = 任务分支
- conda 启动报错长文 = 初始化噪音，以最终 `env=<name>` 为准

## 编排模式（二选一）
**模式 1：非交互（默认）**——长 prompt 写进**私有状态目录任务文件**注入（遵最高优先级纪律第3条：使用用户授权的私有状态目录、不落代码工程），避免引号地狱：
```bash
cd 仓库 && cline --json "$(cat ~/.hermes/skills/cline-pilot/scratch/task.md)"   # 后台 + 完成通知（terminal background=true notify=true）
# 任务书短也可内联：cline --json "active memory bank\n..."
# 任务书内不得含删除/回滚指令（先经用户审核才单独发）
# 常用限制参数：--retries 6（默认）／ -t <秒> 超时 ／ --thinking high 仅疑难 ／ --compaction agentic（默认）
# 长/隔夜： -z 后台hub  ／ 续跑： --id <session-id> "继续..." ／ 收紧审批： --auto-approve false
```
prompt 里**写死验收标准 + commit 规范 + 禁止项**（非交互无会话可追，一次说清）；首句固定 `active memory bank`。

**模式 2：TUI 交互（仅短任务+需实时批准）**：`cline -i` + pty。
实测陷阱：文本可写入，但**多行编辑器的单发回车提交不可靠**；非预期键可能弹订阅页（任意键关闭）。超过两三句的内容一律用模式 1。

## 最高优先级纪律（用户 2026-09-28 强调版，凌驾于本技能其他所有规则）
1. **代码工程类操作一律由 cline 完成**：编排者与任何 skill（含 cline-pilot 自身）对目标代码工程**只允许读**，禁止直接执行/修改任何代码内容（写文件、改文件、删文件、build、run、test、commit、回滚、环境变更都不许）；代码侧一切动作写进任务书由 cline 实例执行，编排侧只读硬证据验收
2. **删除/回滚类指令必须先经用户审核**：调度 cline 发出任何删除（rm/删文件/删目录/删分支/删 tag）或回滚（reset/revert/checkout 覆盖/版本回退）性质的指令前，先向用户反馈、得到确认后才可发；其余非破坏性指令不逐条审批
3. **编排侧可写文件范围仅限本技能目录及子目录**（`~/.hermes/skills/cline-pilot/`，已 .gitignore、永不提交），且仅允许写：修改计划与完成情况记录、进程 pid 台账及说明、技能维护文档；此范围/用途之外（含 
