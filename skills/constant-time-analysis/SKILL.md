---
name: constant-time-analysis
description: Analyze cryptographic code to detect operations that leak secret data through execution timing variations. 
category: Security & Systems
source: antigravity
tags: [python, javascript, typescript, node, api, ai, document, vulnerability, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/constant-time-analysis
---

## Bundled upstream support

Supporting files are included at skill-relative paths. See [UPSTREAM-NOTICE.md](UPSTREAM-NOTICE.md) for their pinned sources, licenses, hashes, and import changes.

# Constant-Time Analysis

Analyze cryptographic code to detect operations that leak secret data through execution timing variations.

## When to Use
```text
User writing crypto code? ──yes──> Use this skill
         │
         no
         │
         v
User asking about timing attacks? ──yes──> Use this skill
         │
         no
         │
         v
Code handles secret keys/tokens? ──yes──> Use this skill
         │
         no
         │
         v
Skip this skill
```

**Concrete triggers:**

- User implements signature, encryption, or key derivation
- Code contains `/` or `%` operators on secret-derived values
- User mentions "constant-time", "timing attack", "side-channel", "KyberSlash"
- Reviewing functions named `sign`, `verify`, `encrypt`, `decrypt`, `derive_key`

## When NOT to Use

- Non-cryptographic code (business logic, UI, etc.)
- Public data processing where timing leaks don't matter
- Code that doesn't handle secrets, keys, or authentication tokens
- High-level API usage where timing is handled by the library

## Language Selection

Based on the file extension or language context, refer to the appropriate guide:

| Language   | File Extensions                   | Guide                                                    |
| ---------- | --------------------------------- | -------------------------------------------------------- |
| C, C++     | `.c`, `.h`, `.cpp`, `.cc`, `.hpp` | references/compiled.md         |
| Go         | `.go`                             | references/compiled.md         |
| Rust       | `.rs`                             | references/compiled.md         |
| Swift      | `.swift`                          | references/swift.md               |
| Java       | `.java`                           | references/vm-compiled.md   |
| Kotlin     | `.kt`, `.kts`                     | references/kotlin.md             |
| C#         | `.cs`                             | references/vm-compiled.md   |
| PHP        | `.php`                            | references/php.md                   |
| JavaScript | `.js`, `.mjs`, `.cjs`             | references/javascript.md     |
| TypeScript | `.ts`, `.tsx`                     | references/javascript.md     |
| Python     | `.py`                             | references/python.md             |
| Ruby       | `.rb`                             | references/ruby.md                 |

## Runtime prerequisite and execution boundary

This catalog bundles documentation only; `ct_analyzer/analyzer.py` is not included.
The commands below and in the language references are illustrative upstream usage,
not an instruction to resolve or execute missing code. Stop if a separately installed,
reviewed analyzer is unavailable. Record its immutable source identity and inspect its
complete runtime and locked dependencies before any separately authorized setup.
Use only existing approved language tools; do not let `uv`, `npx`, PECL or a guide's
bootstrap commands fetch a moving dependency. Review the selected analyzer's command
construction and target-execution behavior before using it on untrusted code.

For PHP, require VLD with `vld.execute=0`; refuse any analyzer that falls back to
OPcache target execution. For compilation, bytecode inspection and all other language
backends, use an isolated environment without unrelated credentials or network access.
Do not treat disassembly as proof that a tool cannot execute target code.

## Quick Start

```bash
# Analyze any supported file type
uv run {baseDir}/ct_analyzer/analyzer.py <source_file>

# Include conditional branch warnings
uv run {baseDir}/ct_analyzer/analyzer.py --warnings <source_file>

# Filter to specific functions
uv run {baseDir}/ct_analyzer/analyzer.py --func 'sign|verify' <source_file>

# JSON output for CI
uv run {baseDir}/ct_analyzer/analyzer.py --json <source_file>
```

### Native Compiled Languages Only (C, C++, Go, Rust)

```bash
# Cross-architecture testing (RECOMMENDED)
uv run {baseDir}/ct_analyzer/analyzer.py --arch x86_64 crypto.c
uv run {baseDir}/ct_analyzer/analyzer.py --arch arm64 crypto.c

# Multiple optimization levels
uv run {baseDir}/ct_analyzer/analyzer.py --opt-level O0 crypto.c
uv run {baseDir}/ct_analyzer/analyzer.py --opt-level O3 crypto.c
```

### VM-Compiled Languages (Java, Kotlin, C#)

```bash
# Analyze Java bytecode
uv run {baseDir}/ct_analyzer/analyzer.py CryptoUtils.java

# Analyze Kotlin bytecode (Android/JVM)
uv run {baseDir}/ct_analyzer/analyzer.py CryptoUtils.kt

# Analyze C# IL
uv run {baseDir}/ct_analyzer/analyzer.py CryptoUtils.cs
```

Note: Java, Kotlin, and C# compile to bytecode (JVM/CIL) that runs on a virtual machine with JIT compilation. The analyzer examines the bytecode directly, not the JIT-compiled native code. The `--arch` and `--opt-level` flags do not apply to these 
