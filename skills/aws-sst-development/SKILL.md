---
name: aws-sst-development
description: SST v4 (Ion) expert for managing AWS resources as code with the Pulumi-backed framework. 
category: Development & Code Tools
source: antigravity
tags: [python, typescript, node, api, mcp, claude, ai, template, security, aws]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/aws-sst-development
---


# SST v4 for AWS
## When to Use

Use this skill when you need sST v4 (Ion) expert for managing AWS resources as code with the Pulumi-backed framework. Use when writing or editing sst.config.ts, building infra/ modules (sst.aws.Function/Bucket/Dynamo/Cron/Service/Router, sst.Secret, sst.Linkable, raw aws.* Pulumi resources), wiring resource links,...


SST v4 (the "Ion" engine) is a Pulumi-backed IaC framework: you describe AWS
resources in TypeScript and SST/Pulumi reconciles them into your account. It
gives you high-level `sst.aws.*` components (Function, Bucket, Dynamo, Cron,
Service, …) that expand into many underlying resources, plus an escape hatch to
*any* raw Pulumi `aws.*` resource for the long tail. This skill encodes a
production-proven way to author, link, test, deploy, and troubleshoot SST
stacks on AWS — distilled from real multi-stack projects that have paid for
each lesson with a prod incident.

**SST and Pulumi are third-party — verify current syntax with Context7**
(`resolve-library-id` → `query-docs` for `sst` or `pulumi-aws`) when you're
unsure about a component's options. Verify AWS-side facts (service limits,
model IDs, IAM action names, region availability) with the AWS docs MCP, never
from memory. The patterns here are the *how*; the docs are the *what*.

## When you're invoked

Figure out which mode you're in and jump to the right reference:

| Situation | Go to |
|-----------|-------|
| New project, or adding a resource/module to an existing SST app | **Author** → `references/authoring.md` |
| Wiring one module's output into another (links, SSM, IAM scope) | **Author** → `references/authoring.md` § Sharing |
| Writing tests for infra so changes don't silently break | **Test** → `references/testing.md` |
| Running a deploy, or a deploy just failed | **Deploy/Operate** → `references/deploy-and-troubleshoot.md` |
| Migrating a resource between Pulumi types, renaming a physical name | **Deploy/Operate** → `references/deploy-and-troubleshoot.md` § Migrations |

Always read the relevant reference before editing — they carry the *why* behind
each rule, which matters more than the rule itself.

## Orientation: read the repo before you touch it

SST projects are conventional but not identical. Before editing, build a quick
map so your change matches the house style instead of fighting it:

1. **`sst.config.ts`** — the app name, `home`, providers/region, `defaultTags`,
   any global `$transform` (Node runtime pin, bundle fixups), and the order in
   which `run()` imports `infra/` modules. The import order *is* the dependency
   order; respect it.
2. **`infra/`** — one file per domain (storage, functions, api, observability…).
   This is where resources are declared. Check for an `infra/CLAUDE.md` — these
   projects keep IaC-specific rules there, and it's the single most valuable
   file to read first.
3. **`infra/tests/`** — source-level Vitest assertions that pin resource
   invariants. If they exist, your change must keep them green and probably
   needs a new assertion.
4. **`package.json` / `.nvmrc`** — package manager (npm vs pnpm), Node version,
   and the `sst`/`pulumi` versions actually installed.

Run `npx sst version` to confirm you're on v4/Ion (the `$config` + `.sst/platform/`
signature). v2/v3 ("SST Classic", CDK-based) is a different framework — these
patterns don't apply there.

## The conventions, and which are universal vs tunable

The projects this skill is built from share a deliberate house style. Some of it
is **universal** (true for any SST v4 + AWS project — apply it everywhere); some
is **project-specific** (a sensible default these projects chose — adopt it for
consistency, but recognize a project may differ).

**Universal — these principles hold for any SST v4 + AWS project:**

- **Control the Node runtime deliberately, in one place.** Don't leave it to
  whatever the installed SST happens to default to. The idiom is a single global
  `$transform(sst.aws.Function, (args) => { args.runtime ??= "nodejs24.x" })` in
  `run()` — `??=` is correct here (the transform runs before the component
  applies its own default, so it fills in only when the user didn't set one).
  Recent SST already defaults to a current Node runtime, so check the installed
  default first (Context7); the transform is then version-independence insurance
  so a future SST downgrade can't silently move your fleet. See
  `references/authoring.md`.
- **Never interpolate a Pulumi `Output<T>` into a plain JS template literal.**
  Use `$interpolate` (or `pulumi.interpolate`). A bare top-level
  `` `${bucket.arn}/*` `` stringifies the `Output` to a `[Output<T>]` placeholder
  and produces a broken ARN that only fails at deploy time (it type-checks and
  `sst dev` runs fine). The fix is `$interpolate`​`` `${bucket.arn}/*` ``. This
  has caused prod deploy outages. See `references/authoring.md` § Outputs.
- **Migrating a resource between Pulumi *types* should default to two PRs** —
  Pulumi creates-before-de
