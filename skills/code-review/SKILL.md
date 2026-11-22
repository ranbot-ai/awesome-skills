---
name: code-review
description: 'Review this', 'find bugs', 'is this fix safe': review code for defects that matter, correctness first, each finding refuted before it's reported. 
category: Document Processing
source: antigravity
tags: [claude, ai, agent, document, security, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/code-review
---


# Code Review

## Operational boundaries

Keep the scope, sandbox, credentials and approval settings supplied by the user or host. Obtain authorization before delegating, exposing project files to another provider, enabling connectors or hooks, using paid services or deploying. Use synthetic or redacted inputs for examples. Keep security reviews static and defensive, with findings and fixes grounded in source inspection.

## When to Use

'Review this', 'find bugs', 'is this fix safe': review code for defects that matter, correctness first, each finding refuted before it's reported.


## Purpose

**Review for supported defects with concrete consequences and checked counterarguments.** Most review output is noise: unranked suspicions that cannot be acted on. Each finding here needs required behaviour, a feasible trigger, a concrete contradiction, an observable consequence and the strongest counterargument checked.

**the defects reviewers miss are rarely visible inside one file.** They are disagreements between participants that each look reasonable alone. Examples include caller and callee, producer and consumer, writer and later reader, or branches that should establish the same state. A file-by-file checklist never holds both halves together. Review the agreement, not the file.

## Structure: one engine, three anchors

**Use correctness as the core, with performance and security as sub-cases.** Generic tooling covers correctness worst. Each sub-case uses the same engine, refutation discipline and report contract. Only its anchor and one or two extra rules differ.

| Sub-case | Anchor | Where its rules live |
|---|---|---|
| Correctness *(core, default)* | Agreements between participants across a boundary | This file + `references/correctness-taxonomy.md` |
| Performance | Workload → resource demand → growth or contention → consequence | `references/performance-review.md` |
| Security | Source → trust boundary → sink, with an attacker controlling the source | `references/security-review.md` |

**Read a sub-case's file only when that sub-case is selected.** Its short file states what differs; the rest of this file still applies. Sub-cases activate independently, not exclusively. Report one root cause once, with both impacts when it carries correctness and security impact.

## Invocation

**State the selected dimensions, the scope and the comparison baseline before investigating.** These are instruction arguments, not shell flags:

```
code-review
code-review dimensions=correctness scope=changes
code-review dimensions=performance,security
code-review dimensions=all
```

Claude Code ships its own bundled `/code-review`. Use the plugin-qualified form above when you mean this one.

- Bare "review this" or "find bugs" means correctness only.
- An explicit list selects exactly those sub-cases; `all` selects three. Never silently reinterpret an unknown or empty selection — ask.
- Use the scope asked for. Otherwise review working changes if present, else the repository.
- When reviewing changes, follow dependencies beyond changed lines. Distinguish defects the change introduced from defects it merely revealed.
- Review and report. Apply fixes only when asked.

## Shared engine

**Map the flow, establish an obligation and try to refute its violation.** Every sub-case uses this sequence; only its anchor and refutation rules differ:

Map a flow → identify an obligation → inspect every participant → construct a violating execution → trace the consequence → attempt refutation → report.

Build one minimal map first: inputs, major execution flows, state owners, external dependencies and observable effects. Enrich it for each selected sub-case. Do not build three maps or make a security-only run wait on correctness mapping.

## Correctness: the agreement engine

**Track consequential agreements across semantic boundaries, not just file splits.** A boundary separates caller and callee, callbacks, executions of one function, producer and consumer, or a value written now and read later.

For each consequential agreement, hold these in working notes, not the report:

```
Participants:
Value, entity or effect exchanged:
Authority (who decides the real answer):
Identity and lifetime/version:
Required relationship:
Evidence for that relationship:
Relevant transitions or orderings:
Observable consumer or consequence:
```

**Establish the obligation without inventing intent.** Use specifications, documented contracts, language or protocol semantics, tests encoding expectations, or a necessary producer/consumer relationship. A consumer's implementation alone does not prove the consumer is right. When participants disagree, explain why the outcome is wrong. The contradiction may be certain while which side should change remains open. Missing documentation is a limitation, not automatically a finding.

**Start where agreements are most likely to break.** Inspect transformed or negotiated values, reassigned identities, asynchronous wor
