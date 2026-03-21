---
name: crypto-bd-agent
description: Production-tested patterns for building AI agents that autonomously discover, > evaluate, and acquire token listings for cryptocurrency exchanges. 
category: Security & Systems
source: antigravity
tags: [api, ai, agent, llm, workflow, design, security, vulnerability, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/crypto-bd-agent
---


# Crypto BD Agent — Autonomous Business Development for Exchanges

> Production-tested patterns for building AI agents that autonomously discover,
> evaluate, and acquire token listings for cryptocurrency exchanges.

## Overview

This skill teaches AI agents systematic crypto business development: discover
promising tokens across chains, score them with a 100-point weighted system,
verify safety through wallet forensics, and manage outreach pipelines with
human-in-the-loop oversight.

Built from production experience running Buzz BD Agent by SolCex Exchange —
an autonomous agent on decentralized infrastructure with 13 intelligence
sources, x402 micropayments, and dual-chain ERC-8004 registration.

Reference implementation: https://github.com/buzzbysolcex/buzz-bd-agent

## When to Use This Skill

- Building an AI agent for crypto/DeFi business development
- Creating token evaluation and scoring systems
- Implementing multi-chain scanning pipelines
- Setting up autonomous payment workflows (x402)
- Designing wallet forensics for deployer analysis
- Managing BD pipelines with human-in-the-loop
- Registering agents on-chain via ERC-8004
- Implementing cost-efficient LLM cascades

## Do Not Use When

- Building trading bots (this is BD, not trading)
- Creating DeFi protocols or smart contracts
- Non-crypto business development

---

## Architecture
```text
Intelligence Sources (Free + Paid via x402)
        |
        v
  Scoring Engine (100-point weighted)
        |
        v
  Wallet Forensics (deployer verification)
        |
        v
  Pipeline Manager (10-stage tracked)
        |
        v
  Outreach Drafts → Human Approval → Send
```

### LLM Cascade Pattern

Route tasks to the cheapest model that handles them correctly:
```text
Fast/cheap model (routine: tweets, forum posts, pipeline updates)
    ↓ fallback on quality issues
Free API models (scanning, initial scoring, system tasks)
    ↓ fallback
Mid-tier model (outreach drafts, deeper analysis)
    ↓ fallback
Premium model (strategy, wallet forensics, final outreach)
```

Run a quality gate (10+ test cases) before promoting any new model.

---

## 1. Intelligence Gathering

### Free-First Principle
Always exhaust free data before paying. Target: $0/day for 90% of intelligence.

### Recommended Source Categories

| Category | What to Track | Example Sources |
|----------|--------------|-----------------|
| DEX Data | Prices, liquidity, pairs, chain coverage | DexScreener, GeckoTerminal |
| AI Momentum | Trending tokens, catalysts | AIXBT or similar trackers |
| Smart Money | VC follows, KOL accumulation | leak.me, Nansen free, Arkham |
| Contract Safety | Rug scores, LP lock, authorities | RugCheck |
| Wallet Forensics | Deployer analysis, fund flow | Helius (Solana), Allium (multi-chain) |
| Web Scraping | Project verification, team info | Firecrawl or similar |
| On-Chain Identity | Agent registration, trust signals | ATV Web3 Identity, ERC-8004 |
| Community | Forum signals, ecosystem intel | Protocol forums |

### Paid Sources (via x402 micropayments)
- Whale alert services (~$0.10/call, 1-2x daily)
- Breaking news aggregators (~$0.10/call, 2x daily)
- Budget: ~$0.30/day = ~$9/month

### Rules
1. Cross-reference: every prospect needs 2+ independent source confirmations
2. Multi-source cross-match gets +5 score bonus
3. Track ROI per paid source — did this call produce a qualified prospect?
4. Store insights in experience memory for continuous calibration

---

## 2. Token Scoring (100 Points)

### Base Criteria

| Factor | Weight | Scoring |
|--------|--------|---------|
| Liquidity | 25% | >$500K excellent, $200-500K good, $100K minimum |
| Market Cap | 20% | >$10M excellent, $1-10M good, $500K-1M acceptable |
| 24h Volume | 20% | >$1M excellent, $500K-1M good, $100-500K acceptable |
| Social Metrics | 15% | Multi-platform active, 2+ platforms, 1 platform |
| Token Age | 10% | Established >6mo, moderate 1-6mo, new <1mo |
| Team Transparency | 10% | Doxxed + active, partial, anonymous |

### Catalyst Adjustments

Positive: Hackathon win +10, mainnet launch +10, major partnership +10,
CEX listing +8, audit +8, multi-source match +5, whale signal +5,
wallet verified +3-5, cross-chain deployer +3, net positive wallet +2.

Negative: Rugpull association -15, exploit history -15, mixer funded AUTO REJECT,
contract vulnerability -10, serial creator -5, already on major CEXs -5,
team controversy -10, deployer dump >50% in 7 days -10 to -15.

### Score Actions

| Range | Action |
|-------|--------|
| 85-100 HOT | Immediate outreach + wallet forensics |
| 70-84 Qualified | Priority queue + wallet forensics |
| 50-69 Watch | Monitor 48 hours |
| 0-49 Skip | Log only, no action |

---

## 3. Wallet Forensics

Run on every token scoring 70+. This differentiates serious BD agents from
simple scanners.

### 5-Step Deployer Analysis

1. **Funded-By** — Where did deployer get funds? (exchange, mixer, other wallet)
2. **Balances** — Current holdings across chains
3. *
