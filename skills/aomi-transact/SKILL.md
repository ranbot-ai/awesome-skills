---
name: aomi-transact
description: Use Aomi's standalone CLI or hosted Agent/Pipeline MCP to read chain state and prepare user-authorized transactions. Review durable Commit simulation before a designated signer executes. Use for swaps
category: AI & Agents
source: antigravity
tags: [typescript, mcp, ai, agent, workflow, template, design, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/aomi-transact
---


# Aomi Transact

> **Authorized use only.** This skill can sign and broadcast on-chain transactions. The user must explicitly request each signing step and name the reviewed Commit or legacy Action.
>
> **Signing gate.** Keep signing commands out of runnable multi-command examples. First summarize the exact identifier, sender, chain, token, amount, recipient, fees, approval limits, calldata purpose, and simulation evidence. Wait for the user's separate instruction before signing those exact reviewed bytes.

## When to Use

Use when a user wants chain reads, quotes, balances, transaction preparation,
wallet review, or an explicitly authorized execution through Aomi. For App
construction, use the separate Aomi Build skill.

## Installation

The `aomi` terminal command belongs to `@aomi-labs/cli`. `@aomi-labs/client` is
the TypeScript SDK; its old terminal entry prints migration instructions.
For user-requested CLI setup:

```bash
npm install -g @aomi-labs/cli@latest
aomi --version
aomi tx --help
```

Require standalone CLI `0.2.0` or newer and verify the needed commands. The CLI
and older embedded-client package have separate version histories. Installing a
skill does not upgrade an existing global binary. For one-shot use, substitute
`npx @aomi-labs/cli@latest` for `aomi`.

The default backend is `https://chat.aomi.dev`. Account authorization and the
RPC or designated wallet signer are separate boundaries. Keep credentials
opaque and use only the existing signer authorized by the user.

## Procedure

1. Resolve the exact recipient, amount, token contract, source and destination
   chains, funding, native gas, and route fees before preparing a payment.
2. Start a new session only for a new task. Continue the original session on
   follow-ups and preserve the full durable Commit ID.
3. Export that Commit, then match its review and simulation evidence to the
   approved intent. `tx simulate` accepts legacy EVM Action IDs; a Commit's
   simulation belongs to its durable review.
4. Summarize the exact review and wait for a separate user signing instruction.
   Only then execute the named Commit through the available designated signer.
   A prepared AA payload does not imply local gas sponsorship.
5. Refresh the same Commit before retrying. Keep the original session, Commit
   ID, approved intent and transaction hash together. A known hash or outstanding
   wallet attempt needs reconciliation. Confirmation requires a successful
   receipt; bridges also require destination settlement and spendable output.

## Examples

Read-only request:

```bash
aomi chat "what is the price of ETH?" --new-session
```

Prepare and inspect a user-requested transaction without signing:

```bash
aomi chat "swap 1 USDC for WETH on Base" --new-session --public-key 0xYourAddress --chain 8453
aomi tx list --json
aomi tx export <commit-id> --format commit
```

Show the reviewed terms and simulation to the user. Signing is a separate
command after explicit approval, using that exact Commit ID.

## Hosted MCP

When the user requests hosted MCP setup, connect each resource separately:

```bash
codex mcp add aomi-agent --url https://chat.aomi.dev/v1/agent/mcp
codex mcp add aomi-pipeline --url https://chat.aomi.dev/v1/pipeline/mcp
```

Each OAuth grant must have the exact connected resource URL as its audience.
Agent, Pipeline, REST and guest tokens are not interchangeable. Codex derives
`resource` from the URL; omit `--oauth-resource` to avoid sending it twice.
If the browser reports a CIMD metadata-fetch failure, retry that server's login
with `--oauth-client-registration dcr`. Open a fresh client session and verify
one harmless session-list or catalog call for each resource.

A plain GET can return 404 because the MCP resources accept POST and OPTIONS.
OAuth grants tool access; wallet execution still uses the user's review and
signing policy.

## Limitations

Network access and a compatible backend are required. A chat response is not
proof that a transaction exists, simulation is not settlement, and a source
bridge receipt is not destination completion. Check live balances, chain IDs,
RPC endpoints, current quotes and the exact prepared bytes. Stop a missing
capability branch rather than guessing commands or reconstructing calldata.

Use the maintained [command reference](https://github.com/aomi-labs/skills/blob/c3f7ed922fc2762b1a23a49552e2ab7c86caf7de/aomi-transact/references/commands.md),
[workflow](https://github.com/aomi-labs/skills/blob/c3f7ed922fc2762b1a23a49552e2ab7c86caf7de/aomi-transact/references/workflows.md),
and [credential rules](https://github.com/aomi-labs/skills/blob/c3f7ed922fc2762b1a23a49552e2ab7c86caf7de/aomi-transact/references/gotchas.md)
when that branch is needed. This update follows Aomi's MIT-licensed canonical
source at `c3f7ed922fc2762b1a23a49552e2ab7c86caf7de` and retains this catalog's
separate signing-approval gate.

## Signing evidence boundaries

Simulation cannot guarantee live execution, slippage, MEV pro
