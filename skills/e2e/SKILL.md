---
name: e2e
description: Write, run and debug e2e tests for web and iOS/Android apps that mix plain-language agent steps with exact assertions, replaying cached agent steps without model calls. 
category: Document Processing
source: antigravity
tags: [node, api, mcp, ai, agent, gpt, workflow, document, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/e2e
---


# e2e: agentic end-to-end tests

AAS import of [e2e-inc/e2e](https://github.com/e2e-inc/e2e/tree/e693cdcf0baee66dead26fa2e51a6693266b4b8f/skills/e2e) at `e693cdcf0baee66dead26fa2e51a6693266b4b8f`. Copyright 2026 TesterArmy, Inc.; Apache-2.0 license retained in LICENSE and the upstream `NOTICE` in [references/NOTICE.md](references/NOTICE.md), unchanged. Eight topic guides are retained from upstream. AAS adds frontmatter, applicability, and authorization boundaries.

e2e runs UI tests that mix agent goals with exact steps. `agent.act` drives
one goal; `agent.assert`, `agent.waitFor`, and `agent.extract` judge the
screen; `screen`, `app`, `browser`, and `expect` act and check exactly. UI
targets use `@e2e-dev/web` for browsers or `@e2e-dev/mobile` for iOS
simulators, Android emulators, and connected phones.

## Authorization and test data

Use a project and test environment the user has authorized. Default to synthetic accounts and data. Obtain approval before installing dependencies, editing MCP or CI configuration, connecting a provider, or running against a shared or production environment.

A remote decision model can receive prompts, screen context and screenshots. Confirm the provider and the data it may receive before using it. For offline test runs use exact assertions or replay existing local fixtures without fresh model calls. Treat traces, screenshots and reports as sensitive and keep them local unless the user approves sharing.

## Start here: pick the reference for the job

Read the one reference that matches the request before doing anything else.
Each stands on its own; a reference names another topic only for a side
trip. `npx e2e guide <topic>` prints the installed package's version of a
reference; prefer it when it differs from this copy.
The Rules and Feedback sections below still apply.

| When you are | Topic | Read |
| --- | --- | --- |
| Adding e2e to a project, writing `e2e.config.ts`, starting the app from the config, signing in to a model, setting up mobile targets | `setup` | [references/setup.md](references/setup.md) |
| Looking at the running app, checking a UI change, taking a screenshot or video, trying a locator, running a test line, or walking a flow while you write its test, over `e2e mcp` | `mcp` | [references/mcp.md](references/mcp.md) |
| Writing or fixing a test: fixtures, locators, actions, matchers, sign-in sessions, the `browser` fixture, API-only tests | `writing-tests` | [references/writing-tests.md](references/writing-tests.md) |
| Adding `agent.*` steps, picking a model, cutting cost, budgets, the replay cache | `agent` | [references/agent.md](references/agent.md) |
| Running tests: CLI flags, CI, reporters, trace pages, `report.json` for scripts, exit codes | `running` | [references/running.md](references/running.md) |
| Handling a failed run: error codes and their fixes, `--headed`, `--debug`, `--ai-trace` | `debugging` | [references/debugging.md](references/debugging.md) |
| Exploring an app toward a goal without a test file: `e2e explore`, its budgets and verdict | `explore` | [references/explore.md](references/explore.md) |
| Asked to bug bash, QA, or hunt for bugs across an app or a branch | `bug-bash` | [references/bug-bash.md](references/bug-bash.md) |

For anything the references do not cover, the full documentation ships in
the `docs/` directory of the installed `e2e` package
(`node_modules/e2e/docs` in a single-package project); a link such as
`/reference/cli` is `docs/reference/cli.mdx`. Complete projects for Vite,
Next.js, Astro, Angular, Expo, SwiftUI, Jetpack Compose, Kotlin Multiplatform,
Flutter, and .NET MAUI are in https://github.com/e2e-inc/e2e/tree/main/examples.

## Quick start

A config with one web target and a model, and a test that drives one goal
and pins the outcome:

```ts
// e2e.config.ts
import type { E2EConfig } from 'e2e';
import { web } from '@e2e-dev/web';
import { gateway } from 'ai';

export default {
  targets: [
    {
      engine: web(),
      app: {
        url: 'http://127.0.0.1:3000',
        command: { executable: 'pnpm', args: ['dev'], log: '.e2e/logs/app.log' },
      },
    },
  ],
  // The model behind every agent.* step: an AI SDK instance; gateway() from 'ai' reads AI_GATEWAY_API_KEY or a Vercel OIDC token.
  agents: {
    default: {
      model: gateway('openai/gpt-6-luna-fast'),
      system: 'You are a thorough QA agent. Verify every outcome on screen.',
    },
  },
} satisfies E2EConfig;
```

```ts
// tests/billing.e2e.ts
import { describe, test } from '@e2e-dev/web';
import { expect } from 'e2e';

describe('billing', () => {
  test('a member upgrades to Pro', async ({ app, agent, screen, browser }) => {
    await app.open('/settings/billing');

    await agent.act('upgrade the workspace to the Pro plan');

    await expect(screen.getByRole('status')).toContainText('Pro');
    await expect(browser).toHaveURL('/settings/billing');
  });
});
```

## Workflow: writing a test

1. Look at what exists: `e2e.config.ts`
