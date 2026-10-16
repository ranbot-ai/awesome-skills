---
name: agentic-verify
description: Check that a Python change is caught by tests: run every mutant of the changed lines and write tests until they catch them. Reports evidence instead of a diff to read. 
category: AI & Agents
source: antigravity
tags: [python, api, claude, ai, agent, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/agentic-verify
---


# Verify a change

## Overview

This skill checks that code Claude wrote or changed is actually tested. It defines the check
before coding, runs every mutant of the changed lines with a pinned runner, and writes tests until
the tests catch them. It reports which mutants were killed and which new tests fail on the old
code, so the user can trust the change from evidence. Upstream source:
[timini/agentic-verification](https://github.com/timini/agentic-verification/tree/v0.3.0/plugin/skills/verify).

## When to Use This Skill

- Use after implementing a feature or fix in a Python/pytest project, before saying the work is done.
- Use when the user asks whether a change is tested.
- Use `@agentic-test-audit` instead to review a whole test suite rather than one change.

## How It Works

Arguments: `$ARGUMENTS`. `--base` is the git revision to compare with: `HEAD` (default) checks
uncommitted work, a branch such as `main` checks a whole branch. Other options go to the runner.

The goal is that the user can trust the change from evidence, without reading every line. A
change is verified when the tests fail if any part of it is wrong. Passing tests alone do not
show that: our study found 71% of the calls that could be deleted unnoticed sat in functions
that looked well tested.

### Runner

```bash
AV='uvx --from git+https://github.com/timini/agentic-verification@v0.3.0#subdirectory=runner agentic-verification'
$AV verify <project-root> --base <rev> [--budget-minutes N]
$AV replay --run <run-dir> --mutant <id> --all
$AV base-check <project-root> --base <rev> [tests...]
```

Pass the project root (the directory pytest runs in), not a package directory or a file.
`base-check` runs tests against the production source as it was at `--base`, in a disposable
copy, and lists the tests that pass now and fail there: those detect the change.

The runner works in a disposable copy and writes only to `.test-suite-audit/` in the project.
It needs Python 3.12+ and `pytest-cov` in the project's environment, plus `pytest-randomly` for
the order check. Use a Bash timeout of the budget plus 2 minutes. The last stdout line is JSON
with the verdict and report paths.

### Rules

- Never weaken, skip or delete an existing test to get a verified verdict, and never edit a
  test so it matches wrong behaviour. If an existing test fails, the change or the test is wrong:
  find out which and tell the user.
- A new test must assert behaviour a user of the code depends on: a result, an effect, an
  error. Do not assert on private helpers or mock the code under change. A test that mocks the
  thing it checks passes when the feature is broken.
- Only the runner decides that a mutant is killed. Do not call a mutant equivalent yourself;
  list it for the user with your reasoning.
- Do not retry a failing or flaky test until it passes. Report it; it hides real failures.
- Never stash, revert or edit production files to see a test fail on the old code. Use
  `base-check`, which does it in a copy; an interrupted stash leaves the user's code broken.

### Steps

1. **Define the check first.** Before writing code (or, if the code exists, before testing it),
   restate the success criteria in one to three lines, and pick the strongest oracle available:
   - an end-to-end or public-API test of the user-visible behaviour, if there is a flow to drive;
   - a property, for pure logic: round trip, invariant, idempotence, or agreement with a simple
     reference implementation (Hypothesis, if the project has it or the user agrees to add it);
   - a differential test, for a refactor or migration: the old version (`git show <base>:<file>`)
     is the oracle; compare on generated inputs and list intentional differences with a reason;
   - example tests otherwise, including the edge cases the criteria name.
   Write that test and see it fail before the change. If the change already exists, run
   `base-check` to confirm the test fails on the old code.
2. **Keep the loop fast.** While iterating, run only the tests for the area you are changing.
   The verify report lists the tests covering the changed lines and how long they take.
3. **Run verify** once the change and its tests are written. Read the verdict:
   - `verified`: every changed line runs under a test and every mutant of the changed lines was
     killed. Go to step 5.
   - `gaps`: changed lines no test runs, surviving mutants, or a suite that is not green and
     deterministic. Go to step 4.
   - `incomplete`: the budget ended first (rerun with a larger `--budget-minutes`), or no
     mutant applies to the changed lines, for example a decorated function. Then the mutants
     give no evidence: rely on `base-check` and say so.
   - `no change`: nothing under the source packages changed since `--base`; check the base.
4. **Close each gap**, then rerun verify (step 3). Stop after three rounds and report what is left.
   - Surviving mutant: read its patch in `mutants/<id>.patch`. It shows a wrong version o
