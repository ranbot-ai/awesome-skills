---
name: invariant-guard
description: Correctness-first: forces writing the function contract, loop invariant, termination argument, and edge cases BEFORE code. Catches Boyer-Moore, leftmost binary search, QuickSelect traps. 
category: Document Processing
source: antigravity
tags: [typescript, node, claude, ai, template, design, document, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/invariant-guard
---


# invariant-guard — Correctness-First Coding

The model knows what a loop invariant is. It knows recursion needs a base case. It knows about empty lists, integer overflow, and the difference between `<` and `≤`. It just does not write these down before producing code, so it ships subtle correctness bugs that tests do not catch.

invariant-guard fixes the behavior. State the invariants. State the base case. State the termination argument. State the edge cases. Then write the code — and verify that the code maintains what you stated.

**Violating the letter of these rules is violating the spirit of the skill.** "I know this algorithm" is the exact rationalization that ships off-by-one and missing-postcondition bugs.

## When to Use This Skill

Use **invariant-guard** when writing or reviewing algorithms where the obvious implementation is subtly wrong:

- Postcondition stronger than the loop's natural invariant: Boyer–Moore majority, Floyd's cycle detection, leftmost vs any binary search, QuickSelect partition.
- In-place mutation with read+write pointers: dedup-in-place, partition, rotate.
- Recursion with multiple parameters or accumulator state.
- Off-by-one suspects with duplicates, empty inputs, boundary values.
- Iterative refinements that must terminate: fixed-point, Newton, EM.
- Any function where you catch yourself thinking "I know this algorithm" — the trap is usually in the contract, not the loop body.

Pairs with `lemmaly` (picks the algorithm) and `mathguard` (picks the math). Load `invariant-guard` *after* the algorithm has been chosen and *before* the loop body is written.

## The Iron Law

```text
NO LOOP OR RECURSION WITHOUT A WRITTEN INVARIANT AND TERMINATION ARGUMENT
```

If you cannot write the invariant in one sentence, you have not designed the loop. Write code anyway and you are coding by guess — and the bug will be in the case you did not enumerate.

## Non-negotiable rules

1. **Every loop gets a one-line invariant.** Before writing any loop, state in one sentence what is true at the top of every iteration. Examples:
   - "At loop top: `result` contains the sum of `a[0..i)`."
   - "At loop top: `lo ≤ target_position ≤ hi`."
   - "At loop top: `seen` contains every element processed so far; `dups` contains every element that appeared at least twice."

   If you cannot write the invariant in one sentence, you have not designed the loop yet.

2. **Every loop gets a one-line termination argument.** Name the quantity that strictly decreases (or strictly increases toward a bound) on every iteration. Examples:
   - "`hi − lo` strictly decreases each iteration."
   - "`i` increases by 1 and is bounded above by `n`."
   - "`stack.length` strictly decreases each pop; nothing pushes inside this branch."

   No termination argument, no loop.

3. **Every recursion gets an explicit base case and a measure.** Before writing a recursive function, state:
   - The base case(s) — the smallest inputs that return without recursing.
   - The measure — a non-negative integer that strictly decreases on every recursive call (e.g. `len(xs)`, `hi − lo`, `depth`, `n`).
   - The combination — how the recursive results combine into the answer.

   No base case + measure, no recursion. (Mutual recursion: state the measure across the cycle.)

4. **List edge cases before writing, not after.** For every function operating on a collection or number, list which of these apply and how they behave:
   - Empty input (`[]`, `""`, `null`, `undefined`, `None`).
   - Singleton (`[x]`).
   - All-equal elements.
   - Already-sorted / reverse-sorted input.
   - Duplicates (when uniqueness is assumed).
   - Negative numbers, zero, exactly the boundary value.
   - Integer overflow / underflow at the type max/min.
   - NaN, ±Infinity, `-0`, denormals (for floats).
   - Off-by-one boundaries: index 0, index n−1, index n, length 0, length 1.
   - Concurrent modification while iterating.

   The cases that apply must each have a one-phrase expected behavior written down.

5. **Make illegal states unreachable, not just unhandled.** Prefer encoding constraints in types and structure so the wrong state cannot be constructed:
   - Sum type over boolean flag soup (`Loading | Loaded(data) | Error(msg)` not `{loading, data, error}`).
   - Newtype for IDs that must not be swapped (`UserId` vs `OrderId`).
   - Non-empty list type when the function requires at least one element.
   - Parsed value at the boundary, not validated repeatedly downstream (parse-don't-validate).

   If the language cannot encode it, write the invariant as a comment and assert it at the boundary.

## The pre-write protocol

Before producing non-trivial code that has loops, recursion, or non-trivial state, your message must contain — in this order:

1. **Function contract** — preconditions, postconditions, and what the function returns. One line each.
2. **Loop invariants** — one per loop. (Rule 1.)
3. **Termination arguments** — one per loop or recursion. (Rules 2, 3.
