---
name: chatexport-need-miner
description: Mines offline Telegram Desktop chat exports (result.json) for unmet market needs and product opportunities using chunked streaming and verbatim quote grounding. Trigger phrases: mine chat export, tele
category: Development & Code Tools
source: antigravity
tags: [python, api, claude, ai, llm, automation, workflow, docker, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/chatexport-need-miner
---


# ChatExport Need Miner: Offline Market Signal & Pain-Point Extractor

Transform offline Telegram Desktop chat exports (`result.json`) into quantified, quote-grounded rankings of unmet market needs with zero memory crashes and absolute source fidelity.

## When to Use This Skill

Activate this skill when:
- The user provides an offline Telegram Desktop chat export (`result.json` or multi-file directory) and requests market research, customer problem analysis, or tool opportunity discovery.
- The user asks: "What are people in this chat struggling with?", "Find product ideas from this export", "What tools do users wish existed?", or "Mine complaints from this group".
- Analyzing multi-megabyte or gigabyte JSON dumps where standard in-memory deserialization (`json.load()`) risks out-of-memory (OOM) fatal crashes.
- Cross-referencing user complaints across multiple independent communities to eliminate echo-chamber noise.

Do NOT use this skill when:
- The user wants live channel scraping, continuous bot monitoring, or MTProto API automation (use dedicated online fetchers).
- Analyzing personal 1-on-1 romantic or private relationships.
- Processing generic SaaS helpdesk feeds (Zendesk, Intercom, Gong) with structured ticket schemas.

## Core Mental Models & Non-Negotiable Rules

1. **The 4MB Stream & Overlap Invariant (Memory Ceiling <= 8MB)**:
   - Telegram Desktop `result.json` files routinely exceed 500MB to 5GB.
   - NEVER load an entire export into memory with `json.load()` or `fs.readFileSync()`.
   - Read the file in fixed 4MB chunks with a 4KB overlap tail.
   - **Boundary Counting Law**: A substring hit is recorded if and only if its terminus falls past the overlap boundary. This guarantees zero missed boundary-spanning phrases and strictly zero duplicate counts.

2. **Cross-Chat Multiplicity Law ($U \ge 3$ Priority)**:
   - One user posting 50 complaints in a single chat is an anecdote; 5 distinct users posting the same complaint across 3 independent chats is a market signal.
   - Cluster rank score is calculated as:
     $$\text{Score} = U \times \sqrt{H}$$
     where $U$ is the number of distinct chat exports containing the signal, and $H$ is the total verified keyword hits.
   - A pattern appearing in $U \ge 3$ chats always outranks a pattern confined to $U = 1$, regardless of raw hit volume.

3. **Verbatim Quote Anchor & Anti-Hallucination Law**:
   - Every identified need theme MUST be backed by 2 to 5 verbatim quotes with exact ISO timestamp (`date`) and chat identifier.
   - NEVER paraphrase a quote inside quotation marks. NEVER synthesize synthetic user statements.
   - If a hypothesized theme lacks verbatim quote support, it MUST be marked `[UNCONFIRMED / NO VERBATIM EVIDENCE]`.

4. **Bi-Lingual Case-Insensitive Seed Lexicons**:
   - Russian Lexicon: `не хватает`, `вот бы`, `бесит`, `надоело`, `задолбал`, `ищу инструмент`, `ищу бот`, `есть ли бот`, `есть ли сервис`, `посоветуйте тул`, `не работает`, `вручную`, `рутина`, `приходится руками`.
   - English Lexicon: `i wish`, `missing`, `annoying`, `frustrating`, `looking for a tool`, `is there an app`, `is there a bot`, `any alternative to`, `doesn't work`, `manually`, `repetitive`, `waste of time`.
   - Custom terms may be added only when explicitly approved or provided by the user.

5. **Strict Air-Gap & Zero Exfiltration**:
   - The entire analysis executes locally and offline. No network requests, no external telemetry, no remote LLM proxying of raw message contents.

## Named Sins & Anti-Patterns (Что категорически ЗАПРЕЩЕНО)

| Anti-Pattern | Manifestation in Code/Workflow | Mandatory Production Counter-Rule |
| :--- | :--- | :--- |
| **The OOM Slurp** | `data = json.load(open('result.json'))` on 800MB file. | Use incremental regex streaming or chunked buffered file reading with `<= 8MB` RAM footprint. |
| **Chunk Boundary Blindness** | Chunking without overlap, truncating `"looking for a tool"` across 4096-byte splits. | Maintain a 4KB sliding overlap tail across chunk transitions. |
| **Double-Count Overlap Trap** | Counting hits found in both chunk $N$ and the overlap window of chunk $N+1$. | Only increment match counter if `match.end() > overlap_size`. |
| **The Echo-Chamber Distortion** | Elevating a bug mentioned 80 times by 1 single user in 1 chat to the #1 product opportunity. | Apply Cross-Chat Multiplicity Law ($U \times \sqrt{H}$) and count unique authors when available. |
| **Hallucinated Quotations** | "User expressed desire for better sync" written in quotes as `"I really need better sync"`. | Exact substring slice from source buffer; if unquoted, label as synthetic analysis. |
| **Service Message Pollution** | Mining system notifications (`"pinned a message"`, `"joined group"`, bot spam) as human needs. | Filter out messages where `type == "service"` or text begins with known bot commands (`/start`). |
| **Premature Uniqueness Claim** | Stating "No tool currently exists for this problem" without validation. | Run explicit c
