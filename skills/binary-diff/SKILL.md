---
name: binary-diff
description: Cross-version binary symbol migration: diff updated binaries, recover function names without PDBs, and propagate annotations after software updates using BinDiff-style tooling. 
category: AI & Agents
source: antigravity
tags: [python, api, claude, ai, agent, llm, gpt, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/binary-diff
---

# 跨版本符号迁移 (Binary Diff)
## When to Use

- A program updated and old annotations/symbols must be migrated to the new build.
- Recovering changed functions between two versions of a stripped binary.


## 适用范围

当任务属于以下场景时使用本 skill：

1. **内核/驱动缺 PDB** — 有旧版 ntoskrnl.exe 的符号，新版 PDB 被微软下架，需要用旧版符号推导新版非导出函数地址
2. **程序更新后符号迁移** — 曾经逆向过某个程序，程序更新了，不想重新逆一遍，用旧版结果批量迁移
3. **保护机制更新** — 旧版有完整逆向结果，新版需要快速定位同一函数的新偏移
4. **任何"有旧版符号 + 新版无符号"的二进制对比场景**

### 与其他 skill 的分工

| 场景 | 用什么 |
|------|--------|
| 从零开始逆向一个二进制 | `ida-reverse/` 或 `radare2/` |
| 有旧版结果，迁移到新版 | **本 skill** |
| 两个完全不同的二进制对比 | BinDiff / Diaphora（传统工具） |

### 核心优势

相比传统方案：

| 方案 | 200 个函数成本 | 时间 | 准确率 |
|------|--------------|------|--------|
| 人工开两个 IDA 窗口对比 | 免费但耗命 | 数小时 | 高 |
| BinDiff 自动匹配 | 免费 | 快 | 中（结构变化大时失效） |
| 完全交给 Agent（CC/Codex） | 50-100 元 | 慢 | 高 |
| **本 skill（LLM 批量比对）** | **~1 元** | **~10 秒/函数** | **高** |

## 核心原理

```text
旧版函数（有符号）          新版同一函数（无符号）
    ↓                              ↓
导出反汇编 + 伪代码          导出反汇编 + 伪代码
    ↓                              ↓
    └──────── LLM 结构化比对 ────────┘
                    ↓
         输出 YAML（符号映射表）
                    ↓
         程序化解析 → 批量应用到新版 IDB
```

关键点：
- prompt 是固定模板，程序化填充
- 输入输出格式确定，程序化解析
- LLM 只负责"看两段代码，找出对应关系"这一步
- 时间成本和 token 成本极低

## Prompt 模板

### 标准比对 Prompt

```text
I have disassembly outputs and procedure code of the same function.

This is the function for reference:

**Disassembly for Reference**
```c
{disasm_for_reference}
```

**Procedure code for Reference**
```c
{procedure_for_reference}
```

This is the function you need to reverse-engineering:

**Disassembly to reverse-engineering**
```c
{disasm_code}
```

**Procedure code to reverse-engineering**
```c
{procedure}
```

What you need to do is to collect all references to "{symbol_name_list}" in the function you need to reverse-engineering and output those references as YAML.

Example:
```yaml
found_vcall: # This is for indirect call to virtual function or virtual function pointer fetching.
  - insn_va: '0x180777700' # Always be the instruction with displacement offset
    insn_disasm: call [rax+68h] # Always be the instruction with displacement offset
    vfunc_offset: '0x68'
    func_name: ILoopMode_OnLoopActivate
  - insn_va: '0x180777778' # Always be the instruction with displacement offset
    insn_disasm: mov rax, [rax+80h] # Always be the instruction with displacement offset
    vfunc_offset: '0x80'
    func_name: INetworkMessages_GetNetworkGroupCount

found_call: # This is for direct call to non-virtual regular function.
  - insn_va: '0x180888800'
    insn_disasm: call sub_180999900
    func_name: CLoopMode_RegisterEventMapInternal
  - insn_va: '0x180888880'
    insn_disasm: call sub_180555500
    func_name: CLoopMode_SetSystemState

found_funcptr: # This is for non-virtual regular function pointer.
  - insn_va: '0x180666600' # Must load/reference the function pointer target address
    insn_disasm: lea rdx, sub_15BC910 # Must load/reference the function pointer target address
    funcptr_name: CLoopMode_OnClientPollNetworking

found_gv: # This is for reference to global variable.
  - insn_va: '0x180444400'
    insn_disasm: mov rcx, cs:qword_180666600 # Must load/reference the global variable
    gv_name: g_pNetworkMessages
  - insn_va: '0x180333300'
    insn_disasm: lea rax, unk_180222200 # Must load/reference the global variable
    gv_name: s_EventManager

found_struct_offset: # This is for reference to struct offset. NOTE THAT virtual function pointer should not be here! virtual function pointer should ALWAYS be in found_vcall !
  - insn_va: '0x1801BA12A' # Always be the instruction with displacement offset
    insn_disasm: mov rcx, [r14+58h] # Always be the instruction with displacement offset
    offset: '0x58'
    size: 8
    struct_name: CResourceService
    member_name: m_pEntitySystem
```

If nothing found, output an empty YAML. DO NOT output anything other than the desired YAML. DO NOT collect unrelated symbols.
```

### 变量说明

| 变量 | 来源 | 说明 |
|------|------|------|
| `{disasm_for_reference}` | 旧版 IDA 导出 | 有符号的反汇编 |
| `{procedure_for_reference}` | 旧版 IDA 导出 | 有符号的伪代码 |
| `{disasm_code}` | 新版 IDA 导出 | 无符号的反汇编 |
| `{procedure}` | 新版 IDA 导出 | 无符号的伪代码 |
| `{symbol_name_list}` | 从旧版提取 | 需要在新版中定位的符号列表 |

## 工作流

### 完整流程

```text
Step 1: 准备数据
  - 旧版二进制加载到 IDA（有 PDB/符号）
  - 新版二进制加载到 IDA（无符号）
  - 找到两个版本中相同的锚点函数（导出函数、字符串引用等）

Step 2: 批量导出
  - 从旧版导出：锚点函数的反汇编 + 伪代码（含符号名）
  - 从新版导出：同一锚点函数的反汇编 + 伪代码（无符号名）

Step 3: LLM 比对
  - 用 prompt 模板填充数据
  - 调用 LLM API（推荐：deepseek 量大便宜，超大函数切 gpt）
  - 解析返回的 YAML

Step 4: 应用结果
  - 将 YAML 中的符号映射批量应用到新版 IDB
  - 用 idapro_rename 或 IDAPython 脚本批量重命名

Step 5: 迭代
  - 第一轮迁移的函数成为新的锚点
  - 进入这些函数，继续对比内部调用
  - 重复直到覆盖所有目标函数
```

### 锚点选择策略

| 锚点类型 | 可靠性 | 说明 |
|---------|--------|------|
| 导出函数 | 最高 | 名字不变，地址可能变 |
| 字符串引用 | 高 | 字符串内容不变，引用位置可能变 |
| 常量/魔数 | 中 | 特征值不变 |
| 代码模式 | 中 | 函数结构相似但地址全变 |

### 批量处理建议

- 每次比对 1 个函数（避免 context 爆炸）
- 中等函数（<200 行）用 deepseek
- 超大函数（>500 行）切 gpt-4o 或 claude
- 并发调用提高速度（10-20 并发）
- 结果
