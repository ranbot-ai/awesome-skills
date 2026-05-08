---
name: aomi-transact
description: Build natural-language crypto/DeFi agents and EVM MCP plugins (Claude Code, Cursor, Codex, Gemini). Aomi turns prompts into wallet-signed txs on Ethereum, Base, Arbitrum, Optimism, Polygon, Linea — 
category: AI & Agents
source: antigravity
tags: [api, mcp, claude, ai, agent, workflow, template, security, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/aomi-transact
---


# Aomi Transact

> **Authorized use only.** This skill signs and broadcasts on-chain transactions on the user's behalf. The user must explicitly request each signing step. The skill will not stage `aomi tx sign` without an explicit user request and a corresponding `tx-N` queued by `aomi tx list`.

## Overview

`aomi-transact` is a procedure for driving the Aomi CLI ([`@aomi-labs/client`](https://www.npmjs.com/package/@aomi-labs/client)) from natural-language prompts. The user types something like *"swap 1 ETH for USDC on Uniswap"*; the agent picks the right protocol and contract, stages the approve+swap as a batch, simulates it on a forked chain, and returns a queued wallet request for the user to sign. The wallet only ever sees calldata that already passed simulation.

The CLI is **account-abstraction-first**: by default it signs through a zero-config Alchemy proxy (no provider credentials needed), using EIP-7702 on Ethereum mainnet and ERC-4337 on L2s. Each `aomi <subcommand>` invocation starts, runs, and exits — there is no long-running process.

The full skill including references (`account-abstraction.md`, `apps.md`, `examples.md`, `session.md`, `troubleshooting.md`, `drain-vectors.md`), templates (`aomi-workflow.sh`), and per-host metadata (`agents/openai.yaml`) lives upstream at [`aomi-labs/skills`](https://github.com/aomi-labs/skills/tree/main/aomi-transact). This entry is the canonical SKILL.md only — clone the upstream for the full bundle.

## When to Use This Skill

- The user wants to chat with the Aomi agent from the terminal.
- The user wants balances, prices, routes, quotes, or transaction status.
- The user wants to build, simulate, confirm, sign, or broadcast wallet requests.
- The user wants to simulate a batch of pending transactions before signing.
- The user wants to inspect or switch apps, models, chains, or sessions.
- The user wants to inspect or change Account Abstraction settings (EIP-7702 / ERC-4337).
- The user wants to sign EIP-712 typed-data payloads (off-chain agreements, intent fillers).

## Examples

### Read-only — price check

```bash
aomi --prompt "what is the price of ETH?" --new-session
```

Returns a quote with no wallet request queued. Use `aomi tx list` to confirm there's nothing pending.

### Single-tx flow — Lido stake

```bash
aomi chat "Stake 0.01 ETH with Lido to get stETH" \
  --public-key 0xUserAddress --chain 1 --new-session
aomi tx list
aomi tx sign tx-1
```

`submit(address(0))` on Lido stETH `0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84`, `value = 0.01 ETH`. No approve, single tx.

### Multi-step batch — Uniswap V3 swap

```bash
aomi chat "swap 1 USDC for WETH on Uniswap V3, send to my wallet" \
  --public-key 0xUserAddress --chain 1 --new-session
aomi tx list                        # tx-1 = approve, tx-2 = swap
aomi tx simulate tx-1 tx-2          # mandatory for multi-step
aomi tx sign tx-1 tx-2              # one hash on the AA 7702 atomic-batch path
```

The simulator runs each tx sequentially on a forked chain so the swap step sees the approve's state changes. Don't sign step 2 independently — it would revert.

### Cross-chain — CCTP Ethereum → Base

```bash
aomi chat "Bridge 50 USDC from Ethereum to Base via CCTP. Recipient is my wallet." \
  --public-key 0xUserAddress --chain 1 --new-session
aomi tx list
aomi tx simulate tx-1 tx-2
aomi tx sign tx-1 tx-2
# Source-chain burn confirms in 1-2 blocks; destination mint requires
# Circle's off-chain attestation (~13-19 minutes).
```

## Limitations

- **Requires `@aomi-labs/client` v0.1.30 or newer.** Older versions lack `--aa`, `--aa-provider`, `--aa-mode` and the simulation gate. Install with `npm install -g @aomi-labs/client` or run on demand via `npx @aomi-labs/client@0.1.30 ...`.
- **Active backend connection.** The skill drives a CLI that talks to `api.aomi.dev`. Without network access, only local read commands (`aomi tx list`, `aomi session log`) work.
- **AA sponsorship on L2s is not guaranteed.** The zero-config proxy path does not reliably sponsor on Base/Arbitrum/Optimism in v0.1.30. If the EOA has 0 native gas on the destination chain, `aomi tx sign` returns viem's `insufficient funds for transfer`. Either fund the EOA with a small amount of native gas, or configure a real BYOK Alchemy/Pimlico provider with a sponsorship policy. Do not retry with `--eoa` — that path also needs gas.
- **Per-session secret ingestion.** Apps that require provider tokens (`binance`, `polymarket`, `dune`, etc.) must have credentials configured by the user in their own shell or via `aomi secret add NAME=<value>`. The skill never sets credentials on its own initiative.
- **Drain vectors are guard-blocked.** The agent rejects calldata where `recipient`/`onBehalfOf`/`mintRecipient` ≠ `msg.sender`. This is a security feature, not a bug — surface the block to the user rather than reformulating the prompt.
- **Network/RPC failures.** Public RPCs may rate-limit (`429`) or fail auth (`401`). The user must supply a reliable cha
