---
name: apk-reverse
description: Android APK reverse engineering: unpacking, Java decompilation, smali modification, repacking and signing, Frida dynamic hooking, and native .so analysis with jadx, apktool, adb, and related tools. 
category: AI & Agents
source: antigravity
tags: [python, api, mcp, ai, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/apk-reverse
---

> **⚠️ AUTHORIZED USE ONLY**
> This skill is for educational purposes or authorized security assessments only.
> You must have explicit, written permission from the system owner before using this tool.
> Misuse of this tool is illegal and strictly prohibited.

> **Mandatory confirmation gate**
> Before running any command that probes, exploits, changes, persists on, extracts data from, or attempts credential access against a target:
> 1. Ask the user to state the exact target URL, IP, account, or resource.
> 2. Ask the user to confirm written authorization and the permitted scope.
> 3. Show the exact command(s) and explain their expected effect.
> 4. Wait for explicit confirmation in the current conversation.
>
> Without that confirmation, remain read-only and provide defensive guidance only. Prefer a sandbox, disposable VM, or controlled lab.

## When to Use

- Analyzing or modifying an Android APK during an authorized assessment.
- Hooking runtime behavior of an app you own or are cleared to test.

## 适用范围

当任务属于以下场景时优先使用本 skill：

- 分析 APK 的 Java 业务逻辑
- 定位登录、签名、风控、证书校验、root 检测
- 查看与修改 `AndroidManifest.xml`
- 查看与修改 smali
- 重打包 APK
- 用 Frida 做 Java/native 动态 Hook
- APK 内含 `.so` 时切到 native 分析

## 当前机器已验证可用的 CLI 工具

- `jadx` `1.5.5`
- `apktool` `3.0.2`
- `frida-ps` `17.9.6`
- `adb`
- `java`

## 优先使用脚本的场景

以下流程高频且参数容易出错，优先用 skill 自带脚本：

- 一次性完成 `jadx + apktool` 落盘并产出摘要：`scripts/decode.ps1`
- Frida 设备检查、进程列举、spawn/attach 注入：`scripts/frida-run.ps1`
- 重建、对齐、签名、安装 APK：`scripts/rebuild-sign-install.ps1`
- 快速抽取 Manifest 关键组件与权限：`scripts/manifest-summary.ps1`

以下一行命令保持直接调用，不单独封装：

- `adb devices`
- `adb logcat`
- `frida-ps -U`
- `jadx --version`
- `apktool --version`

## 自带脚本

### `scripts/decode.ps1`

用途：

- 统一跑 `jadx` 和 `apktool`
- 默认在原 APK 同目录创建任务输出目录
- 输出 `package`、`java_files`、`smali_dirs`、`so_files` 等摘要
- 兼容 `jadx` 部分反编译错误但仍然有可用产物的情况

示例：

```powershell
pwsh -File "<skill-root>\apk-reverse\scripts\decode.ps1" -ApkPath "D:\DOWNLOAD\app.apk" -Clean
pwsh -File "<skill-root>\apk-reverse\scripts\decode.ps1" -ApkPath "D:\DOWNLOAD\app.apk" -Name demo -SkipJadx
```

### `scripts/frida-run.ps1`

用途：

- 统一 Frida 的设备、进程、spawn/attach 入口
- 避免手写参数时混淆 `-f`、`-n`、`-U`

示例：

```powershell
pwsh -File "<skill-root>\apk-reverse\scripts\frida-run.ps1" -ListDevices
pwsh -File "<skill-root>\apk-reverse\scripts\frida-run.ps1" -Usb -ListProcesses
pwsh -File "<skill-root>\apk-reverse\scripts\frida-run.ps1" -Usb -Spawn -Package com.example.app -ScriptPath "D:\hooks\test.js"
```

### `scripts/rebuild-sign-install.ps1`

用途：

- `apktool b` 重建 APK
- `zipalign` 对齐
- `apksigner` 签名与验签
- 可选直接 `adb install`

示例：

```powershell
pwsh -File "<skill-root>\apk-reverse\scripts\rebuild-sign-install.ps1" -ProjectDir "C:\work\apktool_out" -Clean
pwsh -File "<skill-root>\apk-reverse\scripts\rebuild-sign-install.ps1" -ProjectDir "C:\work\apktool_out" -Install -Reinstall -DeviceSerial "127.0.0.1:7555"
```

说明：

- 默认生成并复用调试 keystore
- 默认输出到 `ProjectDir` 同目录，便于和原始包、解包目录放在一起

### `scripts/manifest-summary.ps1`

用途：

- 抽取包名
- 列权限
- 列 activity/service/receiver/provider
- 标出主启动 activity

示例：

```powershell
pwsh -File "<skill-root>\apk-reverse\scripts\manifest-summary.ps1" -ManifestPath "C:\work\apktool_out\AndroidManifest.xml"
```

如果要分析 `.so`、`lib/arm64-v8a/*.so`、`lib/armeabi-v7a/*.so`，再结合：

- `ida-reverse`
- `radare2`

## 工具分工

### `jadx`

用于：

- Java 反编译阅读
- 包名、类名、方法名搜索
- 先从高层逻辑理解 APK

常用命令：

```bash
jadx -d jadx_out app.apk
jadx --single-class com.example.LoginActivity -d jadx_out app.apk
jadx --deobf -d jadx_out app.apk
```

### `JEB Pro`（可选商业工具）

用于：

- Android DEX / APK / ARM 的交叉验证与深度反编译
- 在 JADX 输出不完整或混淆较重时补充静态分析
- 对同一目标的类、方法与调用关系进行第二工具链校验

边界：

- JEB Pro 是商业软件，必须由用户自行取得并安装有效许可证；本包不会下载、破解或规避许可。
- 仅在 `tool-index` 已确认本机 JEB 可用时调用；否则继续使用 `jadx`、`apktool`、Ghidra、IDA 或 radare2。
- 第三方 JEB MCP bridge 不是本包依赖。安装前必须按 `../ops/skill-supply-chain.md` 审阅源码、权限、网络行为和版本，再由用户明确确认注册。

### `apktool`

用于：

- 解包 APK
- 查看和修改 `AndroidManifest.xml`
- 查看和修改 smali
- 重建 APK

常用命令：

```bash
apktool d app.apk -o apktool_out
apktool b apktool_out -o rebuilt.apk
```

### `frida`

用于：

- 动态观察 Java 方法调用
- Hook native 导出函数
- 绕过 root 检测、证书校验、调试检测

常用命令：

```bash
frida-ps -U
frida -U -f com.example.app -l hook.js
frida-trace -U -f com.example.app -j '*!*certificate*'
```

### `adb`

用于：

- 设备连接
- 安装 APK
- 查看日志
- 拉取文件

常用命令：

```bash
adb devices
adb install -r app.apk
adb shell pm list packages
adb logcat
adb pull /data/local/tmp/file .
```

## 推荐工作流

### 1. Triage

先确定 APK 大致构成，不急着改包或 Hook。

建议动作：

1. 用 `jadx -d jadx_out app.apk` 导出 Java 代码
2. 用 `apktool d app.apk -o apktool_out` 导出 smali 和资源
3. 先看：
   - `AndroidManifest.xml`
   - 主 `package`
   - `application`、`activity`、`service`、`receiver`
   - `lib/` 目录里是否有 `.so`
4. Issue #65 威胁形态速查（授权样本/设备；详见 `../reverse-engineering/references/nonpe-format-cookbook.md` §7–8）：
   - 透明/隐藏图标（AU）：`aapt dump badging` + manifest theme/label/icon → `E-android-hidden-icon-manifest`
   - Magisk/脚本格机特征与远程 curl|sh（AR/AS）→ 特征与 URL 入证，**不执行**破坏命令 <!-- security-allowl
