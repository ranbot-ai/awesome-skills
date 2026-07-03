---
name: code-polish
description: Rewrites unprofessional code comments into clear ones and performs non-semantic cleanup. Use to professionalize code without altering logic or behavior. 
category: Document Processing
source: antigravity
tags: [python, api, ai, document, security, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/code-polish
---


# Code Polish

A constraint-based protocol for normalizing code comments and performing safe, non-semantic cleanup. This skill exists because human-written code tends to carry casual, outdated, or missing comments, while the goal is professional-grade documentation without touching behavior.

This file is self-contained. Do not require any other skill file to execute this protocol.

## Prime Directive

Comments and non-semantic cleanup are the job. Logic is never the job. If a change would alter what the code *does* — not just what it *says* or how it's *arranged* — it is out of scope, no matter how obviously "correct" the fix seems.

---

## When to Use

Apply this skill when:
- The user asks to "clean up," "professionalize," or "polish" existing code
- Code is being prepped for code review, handoff, open-sourcing, or documentation
- A file has a mix of human and AI-written comments and needs one consistent, professional voice
- Comments are outdated, missing, redundant, or written casually (venting, placeholders, inside jokes)
- The user wants comments improved but explicitly does **not** want logic touched

Do not apply this skill when:
- The user wants a bug fixed or behavior changed (that's a different job — logic edits are out of scope here)
- The user wants a full rewrite or architectural restructuring
- The only ask is adding new features or functionality

---

## Phase 0 — Full Read

Before editing anything, read the entire file (or the entire relevant module if the codebase is large — not just the function in question). Do not comment or clean incrementally while still reading. A comment written without full context is a guess, and guesses are how "professional" comments end up wrong.

Identify:
- The language and its idiomatic comment/docstring convention (JSDoc, Python docstrings, `///` for Rust, XML doc comments, etc.)
- Any existing project comment style already in use elsewhere in the file — match it rather than importing a foreign convention
- Any comment that encodes real, non-obvious information (race conditions, workarounds for external bugs, "don't reorder this" warnings, business-rule justifications)

---

## Phase 1 — Comment Audit

Classify every existing comment into one of these categories before touching it:

| Category | Example | Action |
|---|---|---|
| **Junk / venting** | `// wtf is this`, `// idk why but it works` | Remove tone, extract any real information underneath, rewrite professionally — or delete if it truly holds zero information |
| **Placeholder** | `// fix later`, `// TODO hack` | Convert to a proper `TODO:` note with the actual concern stated plainly, or remove if stale/resolved |
| **Dead code comments** | Blocks of commented-out code | Remove, unless the surrounding context makes clear it's intentionally preserved (e.g., a documented fallback) — flag these to the user rather than silently deleting |
| **Redundant** | `i++ // increment i` | Delete — the code already says this |
| **Outdated / wrong** | Comment describes behavior the code no longer has | Rewrite to match current behavior. Flag to the user that it was stale, don't just silently fix it |
| **Valuable but informal** | `// careful, this breaks if you call it twice, learned that the hard way` | Preserve the *information*, rewrite the *tone*. Never delete real warnings just because the phrasing is casual |
| **Missing** | Complex logic, non-obvious business rules, or public APIs with no docstring | Add one. Don't over-comment simple, self-explanatory lines |

---

## Phase 2 — Non-Semantic Cleanup

Scope is strictly limited to changes that cannot alter behavior:

- Consistent indentation and whitespace
- Consistent brace/bracket style matching the surrounding file
- Removing truly dead code (unreachable blocks) — only when unambiguous, and flagged in the summary
- Splitting overly long lines for readability
- Local variable renaming for clarity is allowed **only** for private/local-scope names, and only when the improvement is unambiguous — never rename anything exported, public, or referenced across files without calling it out explicitly first

Anything beyond this — reordering logic, extracting functions, changing control flow, altering algorithms — is out of scope for this skill.

---

## Phase 3 — Comment Rewrite / Addition

Apply these standards to every comment touched or added:

- **Explain why, not what.** The code already shows *what* it does; a comment earns its place by explaining intent, tradeoffs, or non-obvious constraints.
- **Use the language's idiomatic doc format** for functions, classes, and public APIs (JSDoc, docstrings, `///`, etc.) — match the convention already used elsewhere in the file if one exists.
- **Be concise.** No padding, no restating the obvious, no filler sentences.
- **No informal register.** No jokes, no venting, no first-person asides ("I think this works because...").
- **No AI-tell phrasing.** Avoid generic filler like "This function is responsible for..." or "
