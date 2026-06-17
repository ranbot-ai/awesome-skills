---
name: crossframe
description: Use when the user explicitly invokes CrossFrame or 跨尺度结构诊断 for Chinese-canonical structural diagnosis of complex relationships, organizations, institutions, public disputes, or long-term
category: Business & Marketing
source: antigravity
tags: [claude, ai, agent, workflow, template, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/crossframe
---

# CrossFrame


## When to Use This Skill

- Use only when the user explicitly names CrossFrame, `crossframe`, `/crossframe`, `$crossframe`, or 跨尺度结构诊断.
- Use for Chinese-canonical structural diagnosis where facts, scale, evidence, responsibility, mechanisms, and action limits must be separated.
- Do not use passively for ordinary analysis, writing, relationship advice, public commentary, philosophy, or long-term forecasting.

## Packaged Source Note

This AAS-ready copy preserves the original CrossFrame skill body below. Chinese remains the canonical semantic layer; English metadata is only for discovery, installation, and repository review.

## Limitations

- The skill body is intentionally Chinese-canonical; English metadata is for discovery and does not replace the original Chinese terms.
- Use only after explicit CrossFrame invocation or `crossframe-suite` routing; do not apply it as a generic default reasoning layer.
- It structures analysis, drafting, and review, but does not replace source verification, domain expertise, or legal, medical, or financial judgment.

如果用户任务需要多个 CrossFrame 平行 skill 连续协作，先读取 `../crossframe-suite/SKILL.md` 做总调度；本 skill 负责其中的结构诊断、事实边界、尺度窗口、机制候选、七闸复核和判断档位。

## 语言原则

本 skill 的权威语义是中文。`CrossFrame` 只是英文传播名与 skill id，不承担概念解释权。

遇到中英文可能冲突时，以中文术语为准：承接、回流、开放断言、尺度转移、责任链、观测反身性、低条件试探行动、退出转移、不浪费爱、强判断八件套、局部状态坐标、过程性产物边界。

英文可以用于文件名、别名、对外简介或必要的双语标注；不要把中文概念硬译成英文后再反向理解。

## 核心定位

CrossFrame 不是“把 v5.0 文本塞进上下文”的提示词包，而是一个可执行的结构推理协议。

每次使用都必须先形成内部推理产物，再输出结论。结论可以很短，但不能跳过事实抽取、七闸复核、机制候选、判断档位、源结构连续性和表达闸。

## 必须执行的顺序

1. 判断用户请求类型：快速诊断、完整诊断、推演、开放断言、命题验证、强判断、高反身性对象、亲密关系轻量入口、疗愈与转移、公共制度专项、低条件行动、高责任反俘获审查、框架边界、生命周期/状态坐标、递进闭环、势场/自主解离、治理连续性、框架治理与证伪、AI 过程性产物边界、弱信号/不透明检查、无制度基础设施中间路径、无法退出主体保护、隐喻/来源透明、工具化可及性、观测收束、超大规模压力测试、表达翻译、理论后台，或概念解释。
2. 读取 `references/runtime-read-policy.md`、`references/read-routing-map.md` 和必要时 `references/v5-material-selection-map.md`，确定本次需要加载的 v5 source modules、连读包、协议、工作表、概念卡和模板。
3. 先定位 v5 source modules，不全量打开大文件。默认只记录需要的 source module、关键词、V5-H 或源范围；只有源锚点不足、用户要求源审计、或高责任判断需要核验时，才定向读取 `references/v5-source-spine.md`、`references/v5-section-digest-index.md`、`references/v5-coverage-map.md` 或 `references/v5-term-fidelity.md` 的相关局部。
4. 读取 `references/continuity-closure-map.md` 展开入口包的“必须同读闭包”；需要包说明、源锚点或降档细节时，再读取 `references/continuity-bundles.md` 和对应 `references/continuity-bundles/v5/<bundle-id>.md`。默认最多读取 3 个入口核心包 + 2 个相邻辅助包；这个上限不限制必须同读闭包。高责任、公共制度、组织处置、公开判断必须优先读七闸、强判断八件套、低权力保护、证据降级与行动上限包及其闭包。
5. 按 `templates/read-state-capsule.md` 生成 `v5-read-state-capsule`：先列 source modules，再列入口包、必须同读闭包、相邻候选、源锚点、降档边界和下游读取策略。suite 不生成胶囊，胶囊由本核心层生成并传给专项 skill、essay 和 review。
6. 填写内部 intake：对象、尺度、事实、证据缺口、用户用途、受影响对象、观测影响、权力结构、行动上限。
7. 通过七闸：对象闸、证据闸、尺度闸、责任闸、观测闸、权力闸、行动闸。七闸任一不完整，不能维持强判断。
8. 形成至少两个机制候选；除非证据足以说明只有一个机制。
9. 对承担判断作用的概念做完整吸收：读取对应概念卡，并用 `worksheets/concept-fidelity-check.md` 做保真检查。
10. 用 `worksheets/source-continuity-check.md` 检查是否只读了孤立概念卡、漏掉 v5 相邻约束或需要降档。
11. 用 `worksheets/source-anchor-integrity-check.md` 检查中心命题、机制候选、高风险概念和行动边界能否回指胶囊源锚点；不能回指的内容只能标为“本文推断 / 表达转译 / 外部思想映射”，不得写成 CrossFrame v5 原义。
12. 决定判断档位：轻量观察、开放断言、完整诊断、强判断、低条件试探行动、退出转移。若必须联读但未联读，或源锚点不足，不能维持强判断。
13. 先输出可见推理提纲，再选择模板输出：先说现实语言，再按需要附内部映射。

## 读取规则

- 默认遵守 `references/runtime-read-policy.md`：不读取 `evals/`、`examples/`、完整成功案例、完整失败案例或全量 v5 大索引。它们只用于开发压测、回归验证、风格调试、用户显式要求源审计或源锚点失败后的定向补读。
- 普通诊断：读 `protocols/diagnosis-protocol.md`，并使用 `worksheets/intake-worksheet.md`、`worksheets/seven-gates-worksheet.md`、`worksheets/evidence-ledger.md`、`worksheets/mechanism-candidates.md`。
- 推演、后续走向、路径展开、分支终点：读 `protocols/inference-protocol.md` 和 `templates/inference-output.md`，并按需追加状态坐标、长期演化、治理连续性包。
- 低到中等把握的判断：读 `protocols/open-assertion-protocol.md`、`worksheets/open-assertion-record.md`、`templates/open-assertion-output.md` 和 `v5-open-assertion-proposition-pack`。
- 高责任、强权力密度、处分、名誉、权利、资源、公共记忆类问题：读 `protocols/anti-capture-protocol.md`、`worksheets/high-responsibility-check.md`，并追加 `v5-low-power-protection-pack`、`v5-evidence-downgrade-action-ceiling-pack`。
- 影响资格、名誉、资源、权利、处置、公共记忆的强判断：读 `protocols/proposition-verification-protocol.md`、`worksheets/proposition-verification.md`、`worksheets/prospective-registration.md`、`templates/strong-judgment-output.md`，并追加 `v5-strong-judgment-eight-pack`。
- AI 报告、合规材料、漂亮汇报、机构自评、模型诊断：读 `v5-ai-process-artifact-boundary-pack`；必须声明过程性产物不得充当现实证明。
- 会因被观察、命名、公开或处置而改变行为、身份、证据或边界的对象：读 `protocols/high-reflexivity-protocol.md`、`worksheets/reflexivity-state-transfer.md`、`templates/high-reflexivity-output.md` 和 `v5-observation-reflexivity-release-pack`。
- 亲密关系、家庭、朋友、照护、单方承接、解释劳动和爱被要求的场景：读 `protocols/intimate-relationship-protocol.md`、`worksheets/intimate-relationship-light-check.md`、`templates/intimate-relationship-output.md`，并先读 `v5-love-trapped-trauma-pack` 和 `v5-low-power-protection-pack`。
- 系统停滞、创伤、修复、退出转移和重建场景：读 `protocols/healing-transfer-protocol.md`、`worksheets/healing-transfer-map.md`、`templates/healing-transfer-output.md` 和 `v5-action-healing-transfer-pack`。
- 公共制度、平台治理、公共承诺和高权力密度公共议题：读 `protocols/public-institution-protocol.md`、`worksheets/p
