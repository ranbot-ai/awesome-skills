---
name: break-ai-fix-loops
description: Stop ineffective AI coding repair loops with stable failure fingerprints, a three-attempt budget, real-path proof, negative controls, and tested rollback. 
category: Document Processing
source: antigravity
tags: [python, api, claude, ai, agent, workflow, document, presentation, security, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/break-ai-fix-loops
---


# Break AI Fix Loops

Replace patch-and-retry behavior with a bounded, evidence-producing repair. Treat a changed patch as progress only when an observable state changes.

## When to Use This Skill

- Use when an AI coding agent cycles through similar patches without changing the observed failure.
- Use when a focused test passes but the installed, deployed, UI, API, persistence, or other real execution path still fails.
- Use when a repair claim needs a verifier that can reject a known-bad state and a rollback that has actually restored the baseline on a disposable copy.
- Do not use for a one-shot, already-understood edit whose acceptance check directly exercises the complete claimed behavior.

## Establish the repair contract

Before the first edit, record:

- the exact defect and the behavior that would disprove it;
- the revision, configuration, input, and execution path under test;
- the baseline command, literal result, and exit status;
- the strongest check that directly observes the claimed behavior;
- the rollback command and the state it must restore.

Save raw evidence before normalizing it. Redact credentials, tokens, cookies, personal data, and private URLs. Never put secrets into a fingerprint record or committed ledger.

If the defect cannot be reproduced, stop editing. Report `INCONCLUSIVE` with the missing observation instead of guessing at a fix.

## Use a three-attempt budget

Allow at most **three repair attempts for one acceptance claim**. An attempt begins when code, configuration, dependencies, generated artifacts, or test expectations change. Inspections and read-only probes do not consume an attempt.

Do not reset the budget because the agent restarts, opens a new session, rewrites the same patch, changes models, clears a cache, or renames the hypothesis. A newly exposed downstream failure still belongs to the same three-attempt budget unless it is a separately accepted task.

For every attempt, write these fields before the next edit:

| Field | Required evidence |
| --- | --- |
| Hypothesis | One causal mechanism, not a restatement of the symptom |
| Prediction | An observation that would distinguish this hypothesis from the previous one |
| Change | Exact changed paths and a patch or before/after hash |
| Focused check | Exact command, input, literal output, and exit status |
| Real-path check | Direct observation, or `NOT_RUN` with a reason |
| Symptom fingerprint | Stable fingerprint described below |
| Decision | `ADVANCE`, `SHIFT_CAUSE`, `PROVEN`, or `STOP` |

Use [the evidence ledger](references/evidence-ledger.md) as a copyable record.

## Fingerprint the observable failure

Fingerprint what the system did, not the agent's explanation. Build a canonical record from:

```json
{
  "schema_version": 1,
  "command": "the exact verification command",
  "input_digest": "digest or stable identifier of the tested input",
  "exit_code": 1,
  "failure_class": "stable-machine-readable-class",
  "stable_excerpt": "the smallest decisive output with volatile values removed",
  "real_path_state": "the directly observed state, or NOT_OBSERVED"
}
```

Keep the unedited output beside this sanitized record. Remove timestamps, run IDs, ANSI codes, random ports, and temporary paths from `stable_excerpt` only when they do not affect the defect. Do not normalize away values that could distinguish two causes.

Optionally compute the canonical SHA-256 fingerprint from this skill directory:

```bash
python3 scripts/fingerprint.py evidence/attempt-1.json
```

The helper validates the record, rejects unknown fields, and prints the fingerprint. It does not execute commands or redact evidence.

The helper uses only the Python 3.9+ standard library. When changing it, run its bundled regression tests:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts/test_fingerprint.py -v
```

The same fingerprint after a different patch means the observable failure did not move. A cosmetically different message with the same failure class, input, command, and real-path state also counts as a repeated failure when the changed text is only volatile data. Do not use a patch hash in the symptom fingerprint; record it separately so different edits cannot masquerade as different outcomes.

## Shift the root-cause strategy

Set the decision to `SHIFT_CAUSE` immediately when any of these occurs:

- a symptom fingerprint repeats;
- the patch changes but the decisive state does not;
- a focused test passes while the real path still fails;
- a retry produces no new discriminating evidence.

Then stop editing and perform this sequence:

1. List the attempted mechanisms and the observation that falsified or failed to distinguish each one.
2. Identify the next unobserved owner boundary along the live path: input, dispatch, configuration, dependency, generated artifact, process, persistence, network, or presentation.
3. Collect one new observation at that boundary with tracing, logging, inspection, or a minimal probe.
4
