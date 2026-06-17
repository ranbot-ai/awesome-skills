---
name: crossframe-essay
description: Use when explicit CrossFrame work needs a Chinese critical insight essay, commentary, concept essay, public piece, or structure-to-article draft after diagnosis. 
category: Business & Marketing
source: antigravity
tags: [claude, ai, agent, workflow, template, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/crossframe-essay
---

# CrossFrame Essay


## When to Use This Skill

- Use only after explicit CrossFrame Essay invocation or after `crossframe-suite` routes a CrossFrame task into article output.
- Use for Chinese critical insight essays, public commentary, concept essays, long-form reader replies, and structure-to-article drafting.
- Do not use as a generic writing skill outside explicit CrossFrame context.

## Packaged Source Note

This AAS-ready copy preserves the original CrossFrame skill body below. Chinese remains the canonical semantic layer; English metadata is only for discovery, installation, and repository review.

## Limitations

- The skill body is intentionally Chinese-canonical; English metadata is for discovery and does not replace the original Chinese terms.
- Use only after explicit CrossFrame invocation or `crossframe-suite` routing; do not apply it as a generic default reasoning layer.
- It structures analysis, drafting, and review, but does not replace source verification, domain expertise, or legal, medical, or financial judgment.

如果用户任务需要先诊断、再进入公共/组织/辩论/读书等专项判断，最后才成文，先读取 `../crossframe-suite/SKILL.md` 做总调度；本 skill 只负责文章底稿与正文生成。

## 语言原则

中文为权威语义。`CrossFrame Essay` 只是写作入口和 skill id，不承担概念解释权；英文只用于文件名、接口、必要双语标注或对外传播名。遇到中英文理解冲突时，以中文术语、中文判断和普通中文读者可理解的表达为准。

CrossFrame Essay 是 `crossframe` 的平行写作 skill，不替代 `crossframe`。它把 CrossFrame 的结构诊断、概念保真、尺度拆分和证据边界，转成面向普通中文读者的批判性洞察文章；当主题需要更深表达时，再把结构判断提升为上位概念、思想参照和经典互文。自动成文默认使用 `full-visible-v5-longform` 输出档位：完整可见底稿 + 完整长文正文。声口由 `crossframe-suite` 传入的 `voice_mode`、角色和 `topic_sensitivity` 决定；用户显式要求亲切/编辑口吻时启用现代编辑底色，显式要求中性报告、备忘录、表格、纯诊断或学术摘要时关闭文章声口。

核心原则：先形成结构洞察底稿，再写文章正文。不要跳过推理直接成文。

长文原则：底稿不是正文的替代品。输出了完整可见底稿之后，仍必须写完整文章正文；凡来自 `crossframe-suite` 且未显式关闭文章层的任务，一律按完整文章处理，不压缩成摘要、短答或项目符号说明。

## 必须执行的顺序

1. 判断写作模式：
   - 自动成文：一次性输出 `结构洞察底稿` 和 `文章正文`，默认 `output_mode=full-visible-v5-longform`。
   - 互动打磨：给候选开头、中心命题和文章骨架，再逐段推进。
2. 读取 `../crossframe/SKILL.md`。
3. 读取 `../crossframe/references/runtime-read-policy.md` 和 `../crossframe/references/read-routing-map.md`，把主题路由到相应 CrossFrame protocol。
4. 读取 `../crossframe/references/continuity-closure-map.md`，至少确认 `v5-seven-gates-diagnosis-pack` 与 `v5-domain-translation-normative-source-pack`，并展开它们的必须同读闭包；公共、亲密、长期演化、AI 材料或高责任主题追加对应 v5 联读包及其闭包。需要包说明时再定向读取 `../crossframe/references/continuity-bundles.md` 或具体包文件。
5. 用 `../crossframe/worksheets/source-continuity-check.md` 检查是否只读了孤立概念卡；深度文章只在源锚点不足、用户要求源审计或高责任核验时，定向读取 `../crossframe/references/v5-source-spine.md`、`../crossframe/references/v5-section-digest-index.md`、`../crossframe/references/v5-material-selection-map.md` 或 `../crossframe/references/v5-term-fidelity.md` 的相关局部。
6. 复用 `../crossframe/templates/read-state-capsule.md` 规定的 `v5-read-state-capsule`；若上游未生成，回到 `../crossframe/SKILL.md` 补齐，不在 essay 内重新发明源路由。
7. 用 `../crossframe/worksheets/source-anchor-integrity-check.md` 检查文章中心命题、机制候选、高风险概念、行动边界和文章转译是否能回指胶囊源锚点；不能回指的内容必须标为“本文推断 / 表达转译 / 外部思想映射”。
8. 读取 `references/evidence-and-search-rules.md` 和 `../crossframe/references/source-ledger-workflow.md`，决定本次是否需要联网或查源，并统一写入来源台账。
9. 按需读取 `references/critical-insight-principles.md`。
10. 如果主题是思想文章、公共议题、复杂关系/组织文章，或用户要求深度、概念上升、引经据典，读取 `protocols/concept-elevation-protocol.md`、`references/reference-and-allusion-rules.md` 和 `references/concept-reference-map.md`。
11. 按 suite 传入的 `voice_mode` 判断是否读取 `protocols/editorial-comrade-voice-protocol.md` 和 `references/editorial-voice-principles.md`，并在底稿中写出 `正文声口方案`。如果用户明确要求中性报告、备忘录、表格、纯诊断或学术摘要，才可关闭文章声口，并说明关闭原因。
12. 自动成文时读取 `protocols/essay-protocol.md`，互动打磨时读取 `protocols/interactive-drafting-protocol.md`。
13. 先生成 `结构洞察底稿`，底稿中写出 `文章类型推荐与待选择`，但不先读取写作技法文件。
14. 底稿后确认文章类型：若用户或 suite 已显式指定 `article_type`，在底稿中记录并直接采用；若未指定且文章层开启，必须完整渲染 `templates/article-type-selection-dialog.md` 的九个选项、填入基于底稿的推荐项和推荐理由，并等待用户回复；若用户回复“默认/自动/都行”，采用选择器中的推荐项。不得只写“已展示文章类型选择器（1-9）”。
15. 用户选择文章类型后，再读取技法路由表和技法文件，然后生成 `文章正文`：读取 `references/article-technique-routing-map.md`，默认最多读取 3 个核心技法 + 2 个辅助技法，再读取对应 `references/writing-techniques/*.md` 文件。
16. 补全底稿中的 `文章类型与写作技法选择` 字段，再从底稿转译出 `文章正文`。

## 读取规则

- 默认遵守 `../crossframe/references/runtime-read-policy.md`：正常成文不读取 evals、examples、完整成功/失败案例、全量 v5 大索引或全量 50 技法卡。
- 自动成文：读取 `templates/insight-dossier-template.md` 和 `templates/essay-output-template.md`；默认执行 `full-visible-v5-longform`。
- 互动打磨：读取 `templates/interactive-session-template.md`。
- 如果主题涉及公共议题、最新事实、真实组织、平台、政策、公司、人物、法律、技术标准或数据，必须查源并按 `../crossframe/references/source-ledger-workflow.md` 写来源台账；来源只进入证据边界、反例、现实案例和事实限制，不接管文章命题。
- 如果主题是私人关系、泛论随笔、哲学概念或用户给出的虚构/概括性材料，默认不联网，除非用户要求或文章需要现实来源来避免误导。
- 如果启用概念上升，先从 CrossFrame 机制抽象上位概念，再选择中西经典、历史经验、理论或文学互文，最后回落到现实判断。
- 自动成文先写 `正文声口方案`，再成文。声口由 suite 传入的 `voice_mode` 决定：`neutral-analysis` / `neutral-decisive` / `editorial-reply` / `editorial-commentary`。只有显式短答/中性报告/备忘录/表格/纯诊断/学术摘要才关闭声口或长文档位。
- 先生成 `结构洞察底稿`，再展示文章类型选择器；文章类型选择器只在底稿之后、正文之前出现。文章类型只决定正文组织和写作技法读取，不改变事实边界、判断档位、连续联读包、证据责任和质量闸。
- 写作技法只在用户选择文章类型后按需读取。每次默认最多读取 3 个核心技法 + 2 个辅助技法；不得全量读取 50 个技法文件。技法只能改变表达结构，不能越过 `v5-read-state-capsule` 的源锚点边界新增事实、强判断或框架原义。
- `full-visible-v5-lon
