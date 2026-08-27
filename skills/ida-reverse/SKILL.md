---
name: ida-reverse
description: Reverse engineer binaries with IDA Pro: decompilation, disassembly, data-flow tracking, cross-references, and IDA MCP automation for deep static analysis of PE/ELF/Mach-O targets. 
category: AI & Agents
source: antigravity
tags: [python, api, mcp, claude, ai, llm, automation, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/ida-reverse
---

# IDA Pro 逆向分析技能
## When to Use

- Deep static analysis of a compiled target where IDA is available.
- Tracking data flow or cross-references through large binaries.


## 已知问题与反思（必读）

### 踩过的坑

1. **`idb_open`（旧名 `idalib_open`）不要直接靠部分 AI 客户端 MCP 调用**
   - 部分代码 AI 客户端 的 MCP 客户端对 open 类工具的 output schema 校验有 BUG
   - 报错：`Structured content does not match the tool's output schema`
   - **解决办法**：使用 `scripts/open.ps1` 脚本通过 HTTP API 直调，绕过 MCP 校验层
   - 当前 ida-pro-mcp 2.x 工具名为 `idb_open` / `idb_list` / `idb_save`（不再是 `idalib_*`）
   - 文件打开后返回 `session_id`（database），后续工具调用需带该 session

2. **`C:\Windows\System32\` 文件无权限打开**
   - idalib 无法直接读取 System32 目录下的文件
   - **解决办法**：`open.ps1` 自动检测并复制到 `临时目录` 目录后再打开

3. **启动服务器命令阻塞对话**
   - `idalib-mcp` 启动后会持续输出 INFO 日志到控制台
   - **解决办法**：使用 `scripts/start.ps1`（`-WindowStyle Hidden` 后台静默启动）
   - 脚本会等待服务就绪后自动退出，不阻塞对话

4. **MCP 服务器名不能用横线**
   - 之前用 `ida-pro-mcp` 作为服务器名，可能引起工具注册问题
   - **当前配置**：服务器名 `idapro`，工具前缀 `idapro_*`

5. **Remote HTTP vs Local Stdio**
   - `type:"local"`（stdio）模式：`idalib_open` 同样有 schema 校验问题
   - `type:"remote"`（HTTP）模式：可以先用脚本直开文件，再用 MCP 工具
   - **当前方案**：Remote HTTP 模式

6. **PR #389 修复了部分 schema 问题**
   - 作者 mrexodia 在 issue #388 后通过 PR #389 合并了修复
   - 修复了 HTTP 模式下的 structuredContent schema，但 部分代码 AI 客户端 侧校验仍有问题
   - 已安装最新 `main` 分支版本

7. **idalib 超时留下孤儿 worker 进程锁文件**
   - 第一次 `open.ps1` 超时后，idalib 的 python worker 子进程可能变成孤儿，咬着 `.id0`/`.id1`/`.nam` 不放
   - 后续任何工具或手动拖入 IDA GUI 都会报"权限不足"
   - **禁止** `taskkill /F /T` 杀进程树——`/T` 会把 GUI `ida.exe` 子进程一起干掉
   - **解决办法**：`start.ps1` 只在端口无人监听、或 `tools/list` 快速返回但缺 `py_eval`（旧 supervisor）时替换 managed supervisor；RPC 超时且 13337 仍在听视为忙，不杀
   - **兜底**：`open.ps1` 检测到旧库被锁自动复制到 Temp 并加 GUID 前缀

8. **带自动分析打开看起来像卡死**
   - `idalib_open(run_auto_analysis=true)` 可能长时间不回包，但后端实际上仍在继续打开和分析
   - 之前用户侧看到的是“PowerShell 一直无输出”，容易误判成脚本卡死
   - **当前解决办法**：`open.ps1` 新增 `-TimeoutSeconds`，并改为后台请求 + 前台轮询 + 定时进度输出
   - 轮询到会话已就绪时会提前返回 `OK:文件名:session_id`，超时则返回 `ERR:open_timeout_xxs`

9. **HTTP MCP 会在登录后静默退出**
   - Cursor/Claude 的 `type: http` 不会代为拉起进程；旧计划任务只在登录时跑一次
   - `pythonw` 无控制台，崩溃时 Application 日志也是空的
   - **解决办法**：`start.ps1` 默认健康则复用；`watchdog.ps1` 每分钟巡检；日志在 `%LOCALAPPDATA%\reverse-skill\ida-mcp\`
   - 安装：`scripts/install-autostart.ps1`。Cursor 若启动时端口还没起来，仍需在 MCP 面板手动刷新一次

### 工作流程原则

| 步骤 | 做什么 | 用什么 |
|------|--------|--------|
| 1 | 确保 HTTP 服务器在运行 | `scripts/start.ps1`（无参数） |
| 2 | 打开目标二进制文件 | `scripts/open.ps1 -Path "xxx.exe"` |
| 3 | 使用 MCP 分析工具 | 直接调用 `idapro_*` / HTTP tools（约 65 个，视版本而定） |
| 4 | 分析完毕 | 工具自动可用 |

## 脚本资源

### start.ps1 — 启动 MCP HTTP 服务器

路径：`scripts/start.ps1`

- 自动解析 `IDADIR`（环境变量 / 便携版桌面路径 / 常见安装路径）
- 优先用 IDA 自带 `Python314\python.exe -m ida_pro_mcp.idalib_supervisor`
- 默认先探测 `http://127.0.0.1:13337/mcp`，健康则输出 `OK:<n>:reuse` 并退出
- 13337 在听但 `tools/list` 超时 → `WARN:busy` / `OK:busy:reuse`，**不杀**（supervisor 单线程，开库时无法回包）
- 仅在端口无人监听、或快速返回且缺 `py_eval` 时替换 managed supervisor；**永不杀 `ida.exe`，不用 `taskkill /T`**
- GUI 占用 13337 时输出 `WARN:gui_busy` 并退出，不另起 supervisor
- 成功输出 `OK:<工具数>`（当前约 66），失败输出 `ERR:timeout`
- supervisor 日志：`%LOCALAPPDATA%\reverse-skill\ida-mcp\supervisor.log`
- 服务器在后台运行，不阻塞对话

**调用方式**：
```
powershell -File "<skill-root>\ida-reverse\scripts\start.ps1"
```

### watchdog.ps1 / install-autostart.ps1 — 保活

- `watchdog.ps1`：探测 13337，健康则 `OK:<n>:reuse`，挂了才调用 `start.ps1`
- `install-autostart.ps1`：注册计划任务 `reverse-skill-ida-mcp`（登录 + 每分钟）
- 日志：`%LOCALAPPDATA%\reverse-skill\ida-mcp\watchdog.log`

### open.ps1 — 打开二进制文件

路径：`scripts/open.ps1`

- 通过 HTTP API 直调 `idb_open`，绕过 MCP schema 校验
- 自动检测 System32 路径并复制到临时目录
- 自动清理同名旧数据库文件（`.id0`/`.id1`/`.nam`/`.til`/`.i64`）
- 旧库被锁时自动降级：复制到 Temp 加 GUID 前缀后打开，不报错
- 将打开请求放到后台执行，避免长时间同步等待导致脚本无响应
- 支持 `-TimeoutSeconds`，超时后返回 `ERR:open_timeout_xxs`，不会无限卡住
- 每隔 10 秒输出一次 `INFO:opening:已用时/超时秒数`，便于判断仍在分析中
- 成功输出 `OK:文件名:session_id`，降级时加 `(temp copy)` 标记
- 失败时自动重试走 Temp 副本

**调用方式**：
```
powershell -File "<skill-root>\ida-reverse\scripts\open.ps1" -Path "C:\path\to\file.exe"
```

**可选参数**：
```
# 指定 SessionId
powershell -File "scripts\open.ps1" -Path "file.exe" -SessionId "my_session"

# 跳过自动分析（大文件推荐）
powershell -File "scripts\open.ps1" -Path "large.exe" -NoAutoAnalysis

# 设置超时，避免带自动分析时长时间无返回
powershell -File "scripts\open.ps1" -Path "file.exe" -TimeoutSeconds 600
```

**输出约定**：
```
# 分析进行中（每 10 秒输出一次）
INFO:opening:11/600s

# 成功打开
OK:sample.exe:abcd1234

# 成功打开，但因锁文件降级到 Temp 副本
OK:1234abcd-sample.exe:abcd1234 (temp copy)

# 达到超时上限
ERR:open_timeout_600s
```

**实测说明**：
- `Snipaste.exe` 带自动分析实测约 `324s` 才返回成功，属于“分析很久”而不是“脚本死锁”
- 因此遇到 GUI 程序或较复杂样本时，建议优先显式设置 `-TimeoutSeconds 600`

## 核心工具列表

### 概况分析（第一步）
- `idapro_survey_binary(detail_level="minimal")` — 快速概况：函数数、字符串、段、入口点、导入分类（加密/网络/文件IO）
- `idapro_list_funcs(queries)` — 列出函数（分页、按名称过滤）
- `idapro_list_globals(queries)` — 列出全局变量
- `idapro_entity_query(kind, filter)` — 统一查询：functions/globals/imports/strings/names

### 反编译与反汇编
- `idapro_decompile(addr)` — 反编译为伪代码
- `idapro_disasm(addr, max_instructions=N)` — 反汇编
- `idapro_analyze_function(addr, incl
