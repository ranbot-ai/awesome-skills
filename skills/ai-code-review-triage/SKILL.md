---
name: ai-code-review-triage
description: Review AI-authored pull requests when line-by-line reading no longer scales; separate defect detection, product-context checks, and scoped human sign-off. 
category: Document Processing
source: antigravity
tags: [api, claude, ai, agent, workflow, template, design, document, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/ai-code-review-triage
---


# AI Code Review Triage

## Overview

AI-generated changes can be tidy while still violating the task, changing behavior unexpectedly, or relying on tests that miss the important path. This skill separates review into three jobs: find defects, check product context, and make a scoped sign-off decision. It produces evidence and open questions; it does not approve or merge a pull request.

## When to Use

Use this when reviewing an AI-authored pull request, when the diff is too large for a reliable line-by-line pass, or when clean-looking code still needs independent scrutiny. For a general security or performance checklist, use a general code-review skill instead.

## Prerequisites

- The diff and its stated intent.
- Repository context and relevant tests, when available.
- A fresh-context reviewer for the independent pass. If one is unavailable, mark that pass as not run; a self-review is not independent.
- A human approver who retains responsibility for approval and merge.

## Workflow

### 1. Triage the diff

Before reading implementation details, establish what the change claims to do and what files it touches.

- Read the PR description, linked issue, and acceptance criteria. If intent is missing or contradictory, record that gap rather than guessing.
- Group changed files by role: production code, tests, configuration, generated output, and documentation.
- Mark high-risk areas for closer inspection: authentication, authorization, data access, persistence, external calls, concurrency, public APIs, and error handling.
- Note generated files or broad changes that do not appear necessary to the stated task.

### 2. Find behavioral defects independently

Use a reviewer that did not author the change and has not been primed with another reviewer's conclusions. Give it the diff, stated intent, and only the repository context needed to check behavior.

Ask it to look for:

- Incorrect edge cases, state transitions, and boundary conditions.
- Broken callers or changed API and data contracts.
- Missing validation, swallowed errors, unsafe defaults, and resource leaks.
- Tests that pass without exercising the claimed behavior.
- Unrelated or unnecessarily broad changes.

Request findings with file and line, triggering condition, expected and actual behavior, and a minimal reproduction or reasoned evidence. Separate confirmed defects from plausible risks. Do not treat a reviewer’s confidence or a tool’s output as proof; reproduce material findings where feasible.

For Claude Code, use a fresh-context Agent reviewer. If using another host, use its equivalent independent-review mechanism. If no independent reviewer is available, report that limitation plainly.

### 3. Check context beyond the diff

Inspect the surrounding implementation, callers, tests, and project history to determine whether the code fits the product and repository conventions.

- Compare behavior with nearby implementations and documented contracts.
- Check whether the change addresses the linked request without silently expanding scope.
- Inspect relevant history when it clarifies an existing design or a prior regression.
- Distinguish missing evidence from a demonstrated bug. Do not invent product intent.

### 4. Make a scoped recommendation

Before recommending approval, answer:

1. Is the behavior correct for the stated request and known contracts?
2. Are material edge cases covered by code or tests?
3. Are there confirmed defects or unresolved high-impact risks?
4. What did the reviewer actually execute, and what remains unverified?

A recommendation is not a merge decision. Keep confirmed defects, plausible concerns, context gaps, and optional preferences in separate sections. The human approver decides whether to request changes, approve, or merge.

## Example

Request: “Review this AI-generated PR before I approve it.”

Inputs: the diff, the PR’s stated intent, relevant callers, and focused tests.

Expected output: a short report with confirmed findings, context gaps, checks actually run, and a scoped recommendation. Do not give blanket approval when material behavior remains unverified.

## Limitations

- A diff cannot supply missing product requirements or operational context; mark these unknown.
- Tests and automated reviewers provide evidence, not proof of correctness.
- Independent review is unavailable if the only reviewer is the change’s author.
- This workflow does not authorize account actions, approvals, merges, or changes outside the reviewed scope.

## Safety and side effects

This skill is instructional and does not include scripts or make changes by itself. Review only the files and repository context needed for the task. Inspect test commands before running them because tests can write files, access services, or consume resources. Do not send private code or data to an external reviewer unless that transfer is authorized. Keep approval and merge actions with the designated human approver.

## Sources and related skills

-
