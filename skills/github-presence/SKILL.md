---
name: github-presence
description: When the user wants to optimize their GitHub profile, README, or project discoverability. Trigger phrases include "GitHub README," "README optimization," "GitHub profile," "GitHub stars," "GitHub disc
category: Document Processing
source: antigravity
tags: [python, javascript, react, node, nextjs, markdown, api, ai, agent, workflow]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/github-presence
---


# GitHub Presence
## When to Use

Use this skill when you need when the user wants to optimize their GitHub profile, README, or project discoverability. Trigger phrases include "GitHub README," "README optimization," "GitHub profile," "GitHub stars," "GitHub discoverability," "awesome lists," or "GitHub marketing.".


GitHub is where developers evaluate your project before trying it. This skill covers README optimization, profile READMEs, discoverability through topics and awesome lists, and using GitHub features for marketing.

---

## Before You Start

1. Read `.agents/developer-audience-context.md` if it exists
2. Audit your current GitHub presence (profile, pinned repos, READMEs)
3. Understand: GitHub is often the first technical evaluation — optimize accordingly

---

## README Structure

### The Anatomy of a Great README

| Section | Purpose | Required? |
|---------|---------|-----------|
| **Logo/Banner** | Brand recognition, visual appeal | Recommended |
| **Badges** | Quick trust signals, status | Recommended |
| **One-liner** | What it does in one sentence | Required |
| **Hero example** | Immediate "what does it look like?" | Highly recommended |
| **Features** | Why use this over alternatives | Required |
| **Quick start** | Get running in < 2 minutes | Required |
| **Installation** | All installation methods | Required |
| **Usage** | Core usage examples | Required |
| **Documentation** | Link to full docs | Required |
| **Contributing** | How to contribute | Recommended |
| **License** | Legal clarity | Required |

### README Template

```markdown
<div align="center">
  <img src="logo.svg" alt="Project Name" width="200">
  <h1>Project Name</h1>
  <p><strong>One compelling sentence explaining what this does.</strong></p>

  <!-- Badges -->
  <a href="https://github.com/org/repo/actions"><img src="https://github.com/org/repo/workflows/CI/badge.svg" alt="CI"></a>
  <a href="https://www.npmjs.com/package/name"><img src="https://img.shields.io/npm/v/name.svg" alt="npm version"></a>
  <a href="https://github.com/org/repo/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <a href="https://discord.gg/invite"><img src="https://img.shields.io/discord/123456789" alt="Discord"></a>

  <br>
  <br>

  <a href="https://docs.example.com">Documentation</a> •
  <a href="https://example.com">Website</a> •
  <a href="https://discord.gg/invite">Discord</a>
</div>

---

## Why Project Name?

- **Feature 1** — Brief explanation
- **Feature 2** — Brief explanation
- **Feature 3** — Brief explanation

## Quick Start

```bash
npm install project-name
```

```javascript
import { thing } from 'project-name';

const result = thing.doSomething();
console.log(result);
```

## Installation

### npm
```bash
npm install project-name
```

### yarn
```bash
yarn add project-name
```

### pnpm
```bash
pnpm add project-name
```

## Usage

### Basic Example

```javascript
// Code example with comments
```

### Advanced Example

```javascript
// More complex example
```

## Documentation

Full documentation available at [docs.example.com](https://docs.example.com)

- [Getting Started](https://docs.example.com/getting-started)
- [API Reference](https://docs.example.com/api)
- [Examples](https://docs.example.com/examples)

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](https://github.com/jonathimer/devmarketing-skills/tree/main/skills/github-presence/CONTRIBUTING.md) for details.

## License

MIT © [Your Name](https://yoursite.com)
```

---

## Badges That Matter

### Trust Signal Badges

| Badge | What it shows | When to use |
|-------|--------------|-------------|
| CI/Build status | Code quality | Always |
| Version | Latest release | Always for packages |
| License | Legal clarity | Always |
| Downloads/installs | Adoption | When impressive |
| Coverage | Test quality | If > 70% |
| Security | Audit status | If you have it |

### Community Badges

| Badge | Source | Purpose |
|-------|--------|---------|
| Discord members | shields.io | Show active community |
| GitHub stars | shields.io | Social proof |
| Contributors | shields.io | Open source health |
| Last commit | shields.io | Project activity |

### Badge Services

| Service | URL | Best for |
|---------|-----|----------|
| Shields.io | shields.io | Most badges |
| Badgen | badgen.net | Fast, minimal |
| GitHub badges | Native | Actions, issues |

### Badge Examples

```markdown
<!-- Build status -->
![CI](https://github.com/org/repo/workflows/CI/badge.svg)

<!-- npm version -->
[![npm](https://img.shields.io/npm/v/package-name.svg)](https://www.npmjs.com/package/package-name)

<!-- Downloads -->
[![Downloads](https://img.shields.io/npm/dm/package-name.svg)](https://www.npmjs.com/package/package-name)

<!-- License -->
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

<!-- Discord -->
[![Discord](https://img.shields.io/discord/SERVER_ID?color=7289da&logo=discord&logoColor=whit
