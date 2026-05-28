---
name: complexity-cuts
description: Lower Big-O on existing code via a one-transformation-at-a-time playbook with verify-revert-stop. For new code use lemmaly; for math-level wins escalate to mathguard. 
category: AI & Agents
source: antigravity
tags: [claude, ai, workflow, prisma]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/complexity-cuts
---


# complexity-cuts — Lower Big-O on Existing Code

`lemmaly` prevents bad complexity before code is written. **complexity-cuts** fixes it after the fact: code already exists, it works, but its time or space complexity is worse than necessary.

**Violating the letter of these rules is violating the spirit of the skill.** Adapting "just a little" is how a faster-but-wrong rewrite ships.

## When to Use This Skill

Use **complexity-cuts** when refactoring existing code that has poor Big-O:

- Nested loops, `O(n²)` or worse scans, repeated work, redundant allocations, blown memory.
- Stated symptoms: "this is slow on large inputs", "times out", "OOM", "too much memory", "reduce complexity", "optimize this algorithm".
- N+1 query patterns in ORMs (Prisma, Drizzle, SQLAlchemy, Django, ActiveRecord).
- `await` inside `for` over independent items causing serial latency.

For *preventing* bad complexity before code is written, use **`lemmaly`**. For math-level optimizations (Bloom, HLL, FFT, JL projection), escalate to **`mathguard`**.

## The Iron Law

```text
NO TRANSFORMATION WITHOUT EXISTING TESTS GREEN BEFORE AND AFTER
```

If the code has no tests, you write a characterization test first (golden input → current output). Then transform. Then verify the test still passes. If you skip this, the optimization can silently break callers — and faster-but-wrong is worse than slow-and-right.

## Non-negotiable rules

1. **State current and target Big-O before touching code.** In one line:
   - Current: `time = O(?)`, `space = O(?)`
   - Target: `time = O(?)`, `space = O(?)`
   - Dominant input dimension (n = what, how large in practice)

   If you cannot state current Big-O, you do not yet understand the code. Read more.

2. **Identify the bottleneck, do not guess.** Point to the exact line(s) responsible for the dominant term. Nested loop? Repeated linear scan? Recomputation? Allocation inside a hot loop? The fix lives there, not elsewhere.

3. **One transformation at a time, with a verify-revert-stop loop.** The loop is:

   1. Apply exactly one transformation from the playbook.
   2. Run the existing test suite (or the characterization test you wrote per the Iron Law).
   3. If any test breaks: **revert immediately.** Do not patch the test. Do not patch around the failure. Revert.
   4. Count reverts on this piece of code. If **3 reverts in a row**, STOP optimizing. The bottleneck is wrong, the transformation is wrong, or the code has invariants you have not modeled. Escalate to `invariant-guard` and write the missing contract — do not try a fourth transformation.
   5. Only after a transformation lands green: pick the next one.

   Stacked changes hide regressions. Patched tests hide regressions louder.

4. **Preserve semantics exactly.** Lower complexity must not change outputs, ordering guarantees, stability, or error behavior. If the optimization requires a semantic change (e.g. unordered output), call it out explicitly and confirm it is acceptable.

5. **No invented numbers.** Never write "10x faster" or "saves 200MB" without measuring. Write `<measured: TBD>` and move on, or actually measure with a representative input.

6. **Always report the measured speedup ratio after a transformation lands.** Once the new code is green, run a representative benchmark (same input, same machine, warm cache) and report `before → after` plus the ratio as `N× faster` (or `N× less memory`). One line, attached to the diff:

   ```text
   p50:  186 ms → 1.1 ms   (169× faster, n=20,000, 200 samples)
   ```

   If you cannot measure (e.g. the win is purely asymptotic on inputs you don't have), say so explicitly: `asymptotic only, no measurement — O(n²) → O(n)`. Never silently skip this step.

## The transformation playbook

The vast majority of real-world Big-O wins come from a small set of moves. Try them in this order:

### Time-complexity reductions

| Smell | Fix | Typical win |
|---|---|---|
| `for x in A: if x in B` where B is list/array | Convert B to `Set`/`Map` once | O(n·m) → O(n+m) |
| Nested loop computing pairs/joins | Hash-join on the key; index by lookup field | O(n·m) → O(n+m) |
| Repeated `.find` / `.indexOf` / `.includes` inside a loop | Precompute index `Map<key, item>` outside loop | O(n^2) → O(n) |
| Repeated recomputation of same value | Memoize / cache by input key | O(n·f(n)) → O(n + f(n)) |
| Sort inside a loop | Sort once outside | O(n^2 log n) → O(n log n) |
| Linear scan for min/max/median repeatedly | Heap / sorted structure | O(n·k) → O(n log k) |
| Recursive recomputation (naive Fibonacci shape) | Memoize, or convert to iterative DP | exponential → O(n) |
| String concatenation in a loop (some langs) | Use builder / `join` / `array.push` then join | O(n^2) → O(n) |
| Repeated regex compile in loop | Compile once outside | constant-factor, large |
| Counting / grouping via nested loop | Single pass with `Counter` / `Map<k, count>` | O(n^2) → O(n) |
| Sliding-window written as nested loop | Two-pointer 
