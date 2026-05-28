---
name: lemmaly
description: Algorithm-first discipline: state Big-O, data structure, and algorithm family BEFORE writing loops, queries, or recursion. Catches O(n^2), N+1, and brute-force defaults. 
category: Document Processing
source: antigravity
tags: [python, javascript, typescript, node, claude, ai, document, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/lemmaly
---


# lemmaly — Algorithm-First Proof

The model already knows Big-O, hash tables, divide-and-conquer, dynamic programming, sorting, graph algorithms, and amortized analysis. It just does not apply them spontaneously. lemmaly fixes the behavior, not the knowledge.

This skill is the gateway for an algorithm-discipline suite of four skills (`lemmaly`, `mathguard`, `invariant-guard`, `complexity-cuts`). It enforces the hard rules that every other guard in the suite assumes.

**Violating the letter of these rules is violating the spirit of the skill.** "Just this once" is how O(n²) ships to production.

## When to Use This Skill

Use **lemmaly** when:

- Writing, editing, or reviewing code that involves loops, collections, lookups, searches, joins, recursion, graphs, queries, or any computation over more than a handful of items.
- About to write a `for` inside a `for`, `.find` / `.includes` / `.indexOf` inside a loop, `await` inside `for` / `map` / `forEach` over independent items, or one query per item in a collection.
- Auditing a codebase / PR for known anti-patterns (await-in-loop, `.includes` inside `.filter`, string-concat in loop, `SELECT *`, N+1, etc.).
- Reviewing AI-generated code that "looks idiomatic" but might hide O(n²) or N+1.

When in doubt, **start at lemmaly** — it is the gateway and will tell you when to escalate to its three sibling skills.

| If you are about to… | Use | Why |
| --- | --- | --- |
| Write *new* code that loops, queries, joins, recurses, or processes a collection | **lemmaly** | Forces complexity + data structure + algorithm family **before** code is written. |
| Refactor *existing* code that is already slow, OOMs, times out, or has nested loops / N+1 / repeated work | **complexity-cuts** | Corrective playbook for code that already shipped with bad Big-O. |
| Implement an algorithm where the obvious version is subtly wrong (binary search variants, in-place dedup, Boyer–Moore, QuickSelect partition, recursion with accumulators, fixed-point / termination concerns) | **invariant-guard** | Forces writing the function contract + loop invariant before code. The trap is in the contract, not the loop body. |
| Work with n ≥ 10⁶, similarity search, dedup at scale, top-K, streaming analytics, cardinality estimation, embeddings, FFT/NTT, dimensionality reduction, computational geometry, randomized algorithms | **mathguard** | Classical algorithms have hit their lower bound; an approximate or math-heavy technique (Bloom, HLL, Count-Min, MinHash/LSH, FFT, JL projection, sweep line, kd-tree) gives the asymptotic win. |

### Routing flow

```text
Are you writing new code?
├── yes → lemmaly (state complexity, structure, family BEFORE coding)
│         ├── classical algorithm at its lower bound AND n is large? → mathguard
│         └── subtle correctness trap (invariant, base case, off-by-one)? → invariant-guard
└── no, refactoring existing slow / OOM / timed-out code → complexity-cuts
          └── still slow after classical fixes? → mathguard
```

### One-line mental model

- **lemmaly** = think first (prevention).
- **complexity-cuts** = clean up bad Big-O (correction).
- **invariant-guard** = prove it's correct (verification).
- **mathguard** = beat the classical floor (acceleration).

## The Iron Law

```text
NO NON-TRIVIAL CODE WITHOUT STATED COMPLEXITY, DATA STRUCTURE, AND ALGORITHM FAMILY
```

Before you write a loop, a recursion, a query, or any computation over more than a handful of items, three things must appear in your message — in this order:

1. `time = O(?)`, `space = O(?)`, with the dominant input dimension named.
2. The data structure you will use, with a one-phrase reason.
3. The algorithm family (one of: linear scan, two-pointer, sliding window, binary search, sort+sweep, hash join, BFS/DFS, topo sort, Dijkstra/A*, union-find, DP, greedy, recursion+memo, prefix sum, segment tree, monoid reduction).

If you cannot state all three, you do not understand the problem yet. Ask, or read more code. Do not write code.

## Non-negotiable rules

1. **State complexity before writing any non-trivial code.** In one line:
   - `time = O(?)`, `space = O(?)`
   - Dominant input dimension: `n = what`, with realistic magnitude (e.g. `n ~ 10^6 rows`)
   - If you cannot state these, you do not yet understand the problem. Ask, or read more code.

2. **Name the data structure with a one-phrase reason.** Every collection-shaped value gets a deliberate choice from `Array / List / Set / HashMap / TreeMap / Heap / Deque / Trie / Graph / BitSet / Counter / LinkedList` — with the reason: "Set for O(1) membership inside the loop", "Heap for top-K in O(n log k)", "Counter to fold the nested loop into a single pass". Default to hashed structures (`Set`, `Map`) for lookup inside loops. Default to streaming/iterator over materialized list when n is large.

3. **Identify the algorithm family before writing.** Name one of: `linear scan`, `divide and conquer`, `two-pointer`, `sliding window`, `binary search`,
