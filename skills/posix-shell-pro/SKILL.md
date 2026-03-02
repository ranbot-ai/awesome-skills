---
name: posix-shell-pro
description: Expert in strict POSIX sh scripting for maximum portability across Unix-like systems. Specializes in shell scripts that run on any POSIX-compliant shell (dash, ash, sh, bash --posix). 
category: Document Processing
source: antigravity
tags: [ai, workflow, design, document, security, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/posix-shell-pro
---


## Use this skill when

- Working on posix shell pro tasks or workflows
- Needing guidance, best practices, or checklists for posix shell pro

## Do not use this skill when

- The task is unrelated to posix shell pro
- You need a different domain or tool outside this scope

## Instructions

- Clarify goals, constraints, and required inputs.
- Apply relevant best practices and validate outcomes.
- Provide actionable steps and verification.
- If detailed examples are required, open `resources/implementation-playbook.md`.

## Focus Areas

- Strict POSIX compliance for maximum portability
- Shell-agnostic scripting that works on any Unix-like system
- Defensive programming with portable error handling
- Safe argument parsing without bash-specific features
- Portable file operations and resource management
- Cross-platform compatibility (Linux, BSD, Solaris, AIX, macOS)
- Testing with dash, ash, and POSIX mode validation
- Static analysis with ShellCheck in POSIX mode
- Minimalist approach using only POSIX-specified features
- Compatibility with legacy systems and embedded environments

## POSIX Constraints

- No arrays (use positional parameters or delimited strings)
- No `[[` conditionals (use `[` test command only)
- No process substitution `<()` or `>()`
- No brace expansion `{1..10}`
- No `local` keyword (use function-scoped variables carefully)
- No `declare`, `typeset`, or `readonly` for variable attributes
- No `+=` operator for string concatenation
- No `${var//pattern/replacement}` substitution
- No associative arrays or hash tables
- No `source` command (use `.` for sourcing files)

## Approach

- Always use `#!/bin/sh` shebang for POSIX shell
- Use `set -eu` for error handling (no `pipefail` in POSIX)
- Quote all variable expansions: `"$var"` never `$var`
- Use `[ ]` for all conditional tests, never `[[`
- Implement argument parsing with `while` and `case` (no `getopts` for long options)
- Create temporary files safely with `mktemp` and cleanup traps
- Use `printf` instead of `echo` for all output (echo behavior varies)
- Use `. script.sh` instead of `source script.sh` for sourcing
- Implement error handling with explicit `|| exit 1` checks
- Design scripts to be idempotent and support dry-run modes
- Use `IFS` manipulation carefully and restore original value
- Validate inputs with `[ -n "$var" ]` and `[ -z "$var" ]` tests
- End option parsing with `--` and use `rm -rf -- "$dir"` for safety
- Use command substitution `$()` instead of backticks for readability
- Implement structured logging with timestamps using `date`
- Test scripts with dash/ash to verify POSIX compliance

## Compatibility & Portability

- Use `#!/bin/sh` to invoke the system's POSIX shell
- Test on multiple shells: dash (Debian/Ubuntu default), ash (Alpine/BusyBox), bash --posix
- Avoid GNU-specific options; use POSIX-specified flags only
- Handle platform differences: `uname -s` for OS detection
- Use `command -v` instead of `which` (more portable)
- Check for command availability: `command -v cmd >/dev/null 2>&1 || exit 1`
- Provide portable implementations for missing utilities
- Use `[ -e "$file" ]` for existence checks (works on all systems)
- Avoid `/dev/stdin`, `/dev/stdout` (not universally available)
- Use explicit redirection instead of `&>` (bash-specific)

## Readability & Maintainability

- Use descriptive variable names in UPPER_CASE for exports, lower_case for locals
- Add section headers with comment blocks for organization
- Keep functions under 50 lines; extract complex logic
- Use consistent indentation (spaces only, typically 2 or 4)
- Document function purpose and parameters in comments
- Use meaningful names: `validate_input` not `check`
- Add comments for non-obvious POSIX workarounds
- Group related functions with descriptive headers
- Extract repeated code into functions
- Use blank lines to separate logical sections

## Safety & Security Patterns

- Quote all variable expansions to prevent word splitting
- Validate file permissions before operations: `[ -r "$file" ] || exit 1`
- Sanitize user input before using in commands
- Validate numeric input: `case $num in *[!0-9]*) exit 1 ;; esac`
- Never use `eval` on untrusted input
- Use `--` to separate options from arguments: `rm -- "$file"`
- Validate required variables: `[ -n "$VAR" ] || { echo "VAR required" >&2; exit 1; }`
- Check exit codes explicitly: `cmd || { echo "failed" >&2; exit 1; }`
- Use `trap` for cleanup: `trap 'rm -f "$tmpfile"' EXIT INT TERM`
- Set restrictive umask for sensitive files: `umask 077`
- Log security-relevant operations to syslog or file
- Validate file paths don't contain unexpected characters
- Use full paths for commands in security-critical scripts: `/bin/rm` not `rm`

## Performance Optimization

- Use shell built-ins over external commands when possible
- Avoid spawning subshells in loops: use `while read` not `for i in $(cat)`
- Cache command results in variables instead of repeated execution
- Use `case` for multiple st
