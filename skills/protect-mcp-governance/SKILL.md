---
name: protect-mcp-governance
description: Agent governance skill for MCP tool calls — Cedar policy authoring, shadow-to-enforce rollout, and Ed25519 receipt verification. 
category: Security & Systems
source: antigravity
tags: [node, mcp, claude, ai, agent, design, security, vulnerability, aws]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/protect-mcp-governance
---


# MCP Agent Governance with protect-mcp

## Overview

Guidance for governing AI agent tool calls using Cedar policies and Ed25519 signed receipts. This skill teaches how to write access-control policies for MCP servers, run them in shadow mode for observation, and verify the cryptographic audit trail.

## When to Use This Skill

- Use when you need to control which MCP tools an agent can call and under what conditions
- Use when you want a tamper-evident audit trail for agent tool executions
- Use when rolling out governance policies gradually (shadow mode first, then enforce)
- Use when authoring Cedar policies for MCP tool access control
- Use when verifying that a receipt or audit bundle has not been tampered with

## Do Not Use This Skill

- When you need general application security auditing (use `@security-auditor`)
- When you need to scan code for vulnerabilities (use `@security-audit`)
- When you need compliance framework guidance without agent-specific governance

## How It Works

protect-mcp intercepts MCP tool calls, evaluates them against Cedar policies (the same policy engine used by AWS Verified Permissions), and signs every decision as an Ed25519 receipt. The receipt is a cryptographic proof that a specific policy was evaluated against a specific tool call at a specific time.

```
Agent → protect-mcp → Cedar policy evaluation → MCP Server
                ↓
        Ed25519 signed receipt
```

Three modes of operation:

1. **Shadow mode** (default) — logs decisions without blocking. Use this to observe what your policies would do before enforcing them.
2. **Enforce mode** — blocks tool calls that violate policy. Use after shadow-mode validation.
3. **Hooks mode** — integrates with Claude Code hooks for pre/post tool-call governance.

## Core Concepts

### Cedar Policies

Cedar is a policy language designed for authorization. Policies are evaluated locally via WASM — no network calls required.

```cedar
// Allow read-only file operations
permit(
  principal,
  action == Action::"call_tool",
  resource
) when {
  resource.tool_name in ["read_file", "list_directory", "search_files"]
};

// Deny destructive operations
forbid(
  principal,
  action == Action::"call_tool",
  resource
) when {
  resource.tool_name in ["execute_command", "delete_file", "write_file"]
  && resource has args
  && resource.args.contains("rm -rf")
};
```

### Signed Receipts

Every policy decision produces a signed receipt:

```json
{
  "payload": {
    "type": "protectmcp:decision",
    "tool_name": "read_file",
    "decision": "allow",
    "policy_digest": "sha256:9d0fd4c9e72c1d5d",
    "issued_at": "2026-04-05T14:32:04.102Z",
    "issuer_id": "sb:issuer:de073ae64e43"
  },
  "signature": {
    "alg": "EdDSA",
    "kid": "sb:issuer:de073ae64e43",
    "sig": "2a3b5022..."
  }
}
```

The receipt format follows [IETF Internet-Draft draft-farley-acta-signed-receipts](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/).

## Step-by-Step Guide

### 1. Initialize Governance for a Project

```bash
# Install and initialize hooks (Claude Code integration)
npx protect-mcp init-hooks

# Or run as a standalone MCP gateway
npx protect-mcp serve
```

This creates a `protect-mcp.config.json` and a starter Cedar policy in your project root.

### 2. Write Your First Policy

Create `policy.cedar` in your project:

```cedar
// Start permissive — allow everything in shadow mode
permit(
  principal,
  action == Action::"call_tool",
  resource
);
```

### 3. Run in Shadow Mode (Observe First)

```bash
# Shadow mode is the default — logs decisions without blocking
npx protect-mcp --policy policy.cedar -- node your-mcp-server.js
```

Review the shadow log to understand what your agent is doing before writing restrictive policies.

### 4. Tighten and Enforce

Once you understand the tool-call patterns, write specific policies:

```cedar
// Allow file reads, deny writes outside src/
permit(
  principal,
  action == Action::"call_tool",
  resource
) when {
  resource.tool_name == "read_file"
};

permit(
  principal,
  action == Action::"call_tool",
  resource
) when {
  resource.tool_name == "write_file"
  && resource has args
  && resource.args.path like "src/*"
};

// Deny everything else
forbid(
  principal,
  action == Action::"call_tool",
  resource
);
```

Switch to enforce mode:

```bash
npx protect-mcp --policy policy.cedar --enforce -- node your-mcp-server.js
```

### 5. Verify Receipts

```bash
# Verify a single receipt
npx @veritasacta/verify receipt.json --key <public-key-hex>

# Verify an audit bundle (multiple receipts + keys)
npx @veritasacta/verify bundle.json --bundle

# Self-test the verifier (proves it works offline)
npx @veritasacta/verify --self-test
```

Exit codes: `0` = signature valid (proven authentic), `1` = signature invalid (proven tampered), `2` = verifier error (malformed input).

## Examples

### Example 1: Governance for a Claude Code Session

```bash
# Initialize hooks
npx protect-mcp init-hooks

# 
