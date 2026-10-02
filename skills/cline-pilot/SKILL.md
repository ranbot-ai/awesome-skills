---
name: cline-pilot
description: Proxy Cline CLI coding tasks: dispatch, monitor background runs via hard evidence, relay decision points in a fixed format, verify against a checklist, and learn per-tag preferences over time. 
category: AI & Agents
source: antigravity
tags: [python, node, api, claude, ai, agent, llm, automation, workflow, design]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/cline-pilot
---


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
**模式 1：非交互（默认）**——长 prompt 写进**技能目录任务文件**注入（遵最高优先级纪律第3条：不落 /tmp、不落代码工程），避免引号地狱：
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
3. **编排侧可写文件范围仅限本技能目录及子目录**（`~/.hermes/skills/cline-pilot/`，已 .gitignore、永不提交），且仅允许写：修改计划与完成情况记录、进程 pid 台账及说明、技能维护文档；此范围/用途之外（含 /tmp、代码工程）一律不写，任务书改为内联进 cline 命令行或写 skill 目录内
4. **本纪律优先级最高**：与其他规则、旧习惯、任务书、自动化（cron/子代理/脚本）冲突时以本纪律为准

## 扫描行为判读与任务书粒度规范（用户 2026-09-29 定）
1. **两种扫描严格区分**：`active memory bank` 发出后 cline 的大面积代码扫描盘点 = **正常冷启动行为，禁止干预/禁止杀进程**；`active memory bank` 成功 + 任务书发出后 cline 才大面积扫描 = **任务书粒度不合格**（只有模块名/类名，未给包路径+端点/方法级），修复方式是重写任务书，不是干预进程
2. **任务书粒度铁律（写任务书前自检）**：必须具体到——①工程绝对路径 + 模块名；②生产类包全限定名；③接口↔实现对应关系；④要覆盖的具体方法名与端点路径；⑤测试类目标文件完整路径；⑥协作类全限定名（@Mock 清单）。缺任何一条 → 不合格，先补粒度再发
3. **任务书内嵌"每类动作清单"**（读该类 → 写该测试类 → 覆盖方法/端点 → 单类验证命令），禁止只写"补完该模块测试"粗粒度指令
4. 粒度不足 = **调度方（编排者）责任**，处理 = 重写任务书重发，禁止 kill 当前会话换会话（除非已到上下文临界）

## clinerules 反馈回路（用户 2026-09-30 定）
当发现 cline **超出指令行为**（越权动作、擅自删改、自造指令、范围溢出）或**整体开发偏离用户意图**（方向跑偏、同类坑重复踩、质量持续塌降）时，处置 = **调度 cline 更新工程的 clinerules**，把"禁止的行为 + 优先做法"写成成对硬规则落进规则文件，防再次发生。
**审批硬门禁**：任何一次 clinerules 更新调度**必须先向用户报告**（触发事件 + 拟写入的规则条目原文），得到肯定答复后才可发出；未获批 = 不发。
**两个合法时机**：
1. **小任务阶段完成时**（验收通过后的自然断点，下一个任务启动前）——不打断正在运行的进程，不为更规则而 kill/插入
2. **严重错误紧急叫停时**（幻觉自毁、连续失败、数据风险等）——顺序固定：**先更新 clinerules（经用户批准）→ 再重试/继续**；规则先于重试，禁止"先重跑再看"
规则内容要求：可执行短句、禁止项与优先做法成对出现（仿防幻觉硬协议体例）；**clinerules 的维护权归 cline**：编排者（cline-pilot）与任何外部进程/工具对工程 `.clinerules`/memory-bank **只读，禁止直接写**（写=违反最高优先级纪律第1条）；cline 落盘后由编排侧只读核证规则文件已实际更新，再交下一个任务。

## 异常通报纪律（用户 2026-09-27 定）
1. 正常运行中**不打扰**用户；异常经处理/重试后恢复正常的也**不打扰**。
2. 仅当**连续 3 次尝试修复/重试后仍失败**、需要人工决策/干预时，才主动发消息。
3. 每次异常的根因、处置动作、重试次数、最终结果，必须记入后台进程台账的「异常处置台账」段，**全部汇总进最终总报告**交付。

## 编码任务生命周期（核心调度规则，不可擅改）
1. **同一时间只允许一个 cline 编码进程**。拉起新编码轮次前，必须先查台账（`~/.hermes/skills/cline-pilot/scratch/bg-procs.md`）+ `ps`：确认**上一个编码进程已退出**（连同其 hub daemon、nohup 子进程），否则先处置干净再起，禁止进程叠加
2. **多任务只允许串行**：一个结束 → 验收 → 记录 → 再启下一个。禁止用多子代理/多 worktree/并行 mvn 把多个任务压给同一批进程；禁止为了赶进度开第二个编码会话
3. **一次编码 = 一个聚焦小任务**（单一功能/单模块/单修复点）。禁止把“整工程里程碑”压给一个会话——长任务必炸上下文（实测：340轮/2.2亿input token 后流断，且断点前大量轮次耗在调研上）
4. **任务生命周期闭环（每个小任务严格走完）**：
   a. 启动前
