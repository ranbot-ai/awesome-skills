---
name: ai-prompt-regression-testing
description: Use when comparing prompt changes against a fixed evaluation set: record actual model settings, required checks, missing results, judge limitations and case-level regression evidence. 
category: Document Processing
source: antigravity
tags: [python, ai, agent, llm, workflow, spreadsheet, presentation]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/ai-prompt-regression-testing
---


# AI Prompt Regression Testing

## When to Use

- Compare a prompt change with an observed baseline on a fixed evaluation set.
- Detect schema, factuality, refusal, tool-selection or task-completion regressions.
- Record a reviewable decision when results are noisy, missing or contradictory.

## Workflow

1. Define the task, representative cases and forbidden outcomes. Use synthetic
   or approved/redacted data; freeze case IDs and the dataset revision before runs.
2. Record baseline/candidate prompt digests, exact available model/version,
   inference settings, tool versions and evaluation environment. Do not hardcode
   old model-family options or silently change models between comparisons.
3. Predeclare checks and acceptance rules. Use deterministic schema/field checks
   for structured output, behavioral checks for tools and a clear human/rubric
   standard for open text. Similarity does not prove factual or code correctness.
4. Run matched baseline/candidate cases under the same permissions and budget.
   Record latency/cost and repeated runs when variability matters. A timeout,
   missing output or judge error is incomplete, not a pass or a zero-cost result.
5. Treat judge outputs as evidence with limitations. Blind/randomize presentation
   where feasible, calibrate against human-labeled examples, and record judge
   identity/rubric. Do not ask a model to verify private reasoning or accept a
   judge's confidence as an objective correctness measurement.
6. Review differences case by case and report the denominators, failures and
   uncertainty. Keep mandatory safety/schema failures visible even if aggregate
   similarity improves. Use the predeclared rule, not a threshold selected after results.
7. Store a redacted report and exact artifacts at an authorized destination.
   Decide retain/revise/reject for the stated dataset; deployment is separate.

## Regression register

| Field | Type | Example / meaning |
|---|---|---|
| case_id | string | PTEST-001; a textual ID, not SERIAL |
| dataset_revision | immutable reference | exact case inventory, expected checks and labels |
| prompt_revision | string | baseline/candidate digest |
| model_runtime | string | exact available ID/version plus settings |
| check | string | required JSON fields or approved rubric criterion |
| result | enum | pass / fail / incomplete |
| evidence | reference | redacted actual output, tool trace or observed check |
| judge_configuration | optional object | exact judge ID/rubric/version and calibration limits |
| latency_ms | nonnegative number or null | null if not observed; never invented |
| cost | amount/currency or null | actual billing basis; unknown remains unknown |
| run_revision | immutable reference | binds the report to the actual run |

IDs and statuses must have consistent SQL/JSON/CSV representations. Do not store
private prompts, user messages or tokens in a public spreadsheet or Notion register.

## Worked example

Two cases test a support-answer prompt. PTEST-001 requires an answer grounded in
the supplied policy; PTEST-002 requires a structured escalation when the policy
is absent. The candidate sounds more helpful but PTEST-002 has no observed result.
The report is incomplete, not a win. The following Python 3 helper aggregates
already reviewed case statuses; it does not call models or decide correctness.

```python
def summarize_regression(results, expected_case_ids):
    if not isinstance(expected_case_ids, list) or not expected_case_ids:
        return {"status": "incomplete", "reason": "missing case inventory"}
    if any(not isinstance(case, str) or not case for case in expected_case_ids):
        return {"status": "incomplete", "reason": "invalid case IDs"}
    if len(set(expected_case_ids)) != len(expected_case_ids):
        return {"status": "incomplete", "reason": "duplicate expected case IDs"}
    if not isinstance(results, list) or any(not isinstance(row, dict) for row in results):
        return {"status": "incomplete", "reason": "invalid results"}
    by_id = {}
    for row in results:
        case = row.get("case_id")
        if not isinstance(case, str) or case not in expected_case_ids or case in by_id:
            return {"status": "incomplete", "reason": "unexpected or duplicate result"}
        if row.get("result") not in ("pass", "fail", "incomplete"):
            return {"status": "incomplete", "reason": "unknown result"}
        by_id[case] = row["result"]
    failed_cases = [case for case, result in by_id.items() if result == "fail"]
    if set(by_id) != set(expected_case_ids) or "incomplete" in by_id.values():
        return {"status": "incomplete", "reason": "missing or incomplete case",
                "failed_cases": failed_cases, "evaluated": len(by_id)}
    return {"status": "regression" if failed_cases else "checks-passed",
            "failed_cases": failed_cases, "evaluated": len(by_id)}


print(summarize_regression(
    [{"case_id": "PTEST-001", "result": "pass"}],
    ["PTE
