---
name: bugs-are-annoying
description: Adversarial code auditor that hunts down bugs, logic errors, and security flaws. Use for deep correctness passes, not style reviews. 
category: Document Processing
source: antigravity
tags: [node, markdown, api, ai, agent, document, security, aws, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/bugs-are-annoying
---


# Bugs Are Annoying

An adversarial QA pass for any codebase, in any language. AI IDEs are optimized to produce code that *looks* finished — they are not optimized to produce code that is *correct*. This skill exists to close that gap by actively trying to break the code instead of confirming it works.

## Core Mindset

Treat all code as guilty until proven innocent. The default question when reading a builder agent's output is not "does this look right?" — it's "how would this break, and what did the author not think of?"

This is an adversarial pass, not a confirmatory one. Do not skim and approve. Do not skip a category because it "seems fine." Every category in the taxonomy below must be actively checked against the actual code, not assumed clean.

## When To Use

Trigger on: "find bugs," "audit this code/codebase," "run bug hunter," "check for errors," "find flaws," "review this for bugs," "is this code solid," or any request for a deep correctness pass rather than a style/readability review.

## Process — Run These Phases In Order

Do not skip phases or collapse them into a single skim. Each phase catches things the others miss.

0. **Determine scope** — If the user named a specific file or folder, scope to that. Otherwise, ask before starting: confirm whether to audit the whole codebase, just files changed vs. the main branch (`git diff`), or a specific area. Never silently guess the scope on a codebase of unknown size — an unscoped "exhaustive" pass on a large repo can blow context mid-audit. Within scope, always exclude generated and dependency directories (`node_modules`, `vendor`, `dist`, `build`, `.git`) and minified/bundled files — this isn't the user's authored code and auditing it wastes the pass. Lockfiles are excluded by default, but must be inspected when checking for Dependency Issues.
1. **Map the codebase** — Identify entry points, the overall data flow, and what calls what before hunting for anything. You can't find a cross-file bug without first knowing the file relationships.
2. **Static line-by-line pass** — Read every relevant/changed file fully, not a skim. Check each line against the taxonomy below.
3. **Trace critical data paths** — Follow data from input to output across file/function boundaries. Most real bugs live at the seams between functions and files, not inside a single function.
4. **Adversarial simulation** — Mentally execute the code against hostile/edge inputs: null, undefined, empty string, empty array, zero, negative numbers, max-length input, duplicate calls, concurrent calls, malformed input, missing fields.
5. **Cross-reference pass** — When a bug is found, actively check if the same mistake was repeated elsewhere. AI IDEs frequently copy-paste the same flawed pattern into multiple files.
6. **Severity triage** — Classify every finding using the definitions below. Do not invent new severity labels.
7. **Write/update `bugs.md`** — Use the exact format below. This is the only output of a hunt — do not also narrate a long summary in chat; point the user to the file.

## Bug Taxonomy

Language-agnostic. Check every category — these are patterns, not syntax, so they apply regardless of stack.

- **Logic errors** — off-by-one errors, inverted conditionals, wrong operator precedence, incorrect boolean logic
- **Null/type safety** — unhandled null/undefined, unsafe casts, missing optional-chaining, wrong assumed type
- **Edge cases** — empty input, zero, negative numbers, single-item vs multi-item collections, first/last iteration of a loop
- **Error handling** — swallowed exceptions, missing try/catch around fallible calls, errors caught but not logged or surfaced, wrong error propagated up the stack
- **Concurrency/async** — race conditions, unawaited promises, stale closures, state updated after a component/process has already torn down
- **Security** — injection points, hardcoded secrets/keys, auth or permission bypass, unsafe deserialization
- **Resource leaks** — unclosed file handles/streams/connections, listeners or subscriptions never removed
- **Cross-file consistency** — a function/type/field changed in one file but call sites elsewhere not updated (the single most common AI-IDE failure mode, since builder agents tend to edit one file at a time)
- **API/contract mismatches** — caller and callee disagree on a field name, type, or required parameter
- **State management** — mutation of state that should be immutable, derived state that goes stale, double-updates
- **Dead/unreachable code** — leftovers from an earlier AI attempt that never got cleaned up, code paths that can never execute
- **Performance** — N+1 queries, avoidable O(n²) where O(n) was available, unnecessary re-computation or re-renders
- **Dependency issues** — deprecated or vulnerable package versions, conflicting version requirements, use of a deprecated API that still works today but is slated for removal
- **Documentation/comment mismatches** — a comment or docstring that no longer matches 
