---
name: apple-container
description: Build, run, and manage OCI/Linux containers as lightweight per-container VMs on Apple-silicon macOS using Apple's open-source container CLI, no Docker daemon required. 
category: Document Processing
source: antigravity
tags: [api, claude, ai, agent, workflow, document, image, security, docker, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/apple-container
---


# Apple `container`

> Reference scope: this imported guide mixes release-era and later branch documentation; its `1.0.0+` annotations are not verified introduction versions. Match the installed `container --version` and subcommand `--help` to the same upstream release tag before using flags or defaults. Current branch documentation can describe unreleased behavior. No container runtime was executed for this static review.

## When to Use

- Use when building, running, or managing OCI/Linux containers on Apple-silicon macOS with Apple's open-source `container` CLI
- Use when you want lightweight per-container VMs instead of a Docker daemon
- Use when translating Docker-style workflows (build, run, exec, logs, networking) to Apple's container tooling

Apple's `container` is an open-source CLI for building, running, and managing OCI/Linux
containers on Apple-silicon Macs. Each container runs inside its own lightweight virtual
machine (backed by the Containerization framework and the Virtualization API). A shared per-user
API server and helpers run via `launchd`, with a separate runtime helper per container. Images are standard OCI
artifacts, so they interoperate with Docker registries and other OCI tooling. The CLI is
deliberately Docker-like (`container run`, `container build`, and image ops under
`container image push`/`pull`), but it is a distinct tool: do not assume Docker command paths,
flags, defaults, or daemon behavior carry over (e.g. there is no `container images`/`push`/`pull`
top-level command — image verbs live under `container image`).

## Safety Gate

Container installation, service startup, image pulls, builds, runs, registry login, pushes,
and resource cleanup change local or remote state. Keep the exact registry, mounts, ports, privileges and persistence impact within existing task authorization. Clarify missing destructive scope, sensitive mounts, credentials or external exposure before acting; do not ask again for actions already authorized.

## Requirements

- **Apple silicon only** (M1 or later). Intel Macs are not supported.
- **macOS 26 (Tahoe) is the officially supported target.** The maintainers do not support
  older macOS and typically will not fix issues that can't be reproduced on 26. The binary
  still runs on **macOS 15 (Sequoia)** but with reduced networking: only the single default
  subnet is available, and the `container network` group and `--network` flag error out.
  macOS-26-gated features are called out throughout the reference files.
- **Version:** this skill documents the **1.0.0** release (the historical reference snapshot). The `machine`
  group, `container cp`, `container export`, `container prune`, `container image prune`,
  `container registry list`, and `container system version` were **added in 1.0.0** (not in 0.7.1)
  — features that postdate 0.7.1 are flagged *(1.0.0+)* in the reference files. Run `container --version` and
  `container <group> --help` to see what your installed build supports.
- Install by downloading the signed `.pkg` installer from the project's GitHub releases
  (`apple/container`) and running it. See `references/concepts.md` for the full
  requirements/compatibility matrix and how the VM-per-container model works.

## Setup

Install the signed package, then start the background services once:

1. **Download** the latest signed installer `.pkg` from the
   [GitHub releases page](https://github.com/apple/container/releases).
2. **Double-click** the downloaded package and follow the prompts, entering your admin
   password so it can place files under `/usr/local`. For automated package installation, verify macOS installer syntax and package signature rather than inventing a container subcommand.
3. **Start the services** and confirm they are healthy:

```bash
# Start the container services (container-apiserver + helpers via launchd). On first run it
# offers to install the default Linux kernel — accept it, or start non-interactively with
# `--disable-kernel-install` and add a kernel later via `container system kernel set`.
container system start

# Verify services are healthy
container system status
```

`container system start` must have run before any container/image/build command works — a
connection/XPC error can indicate stopped services, incompatible components, permissions or launch failures. Inspect `container system status`, installed versions and logs before deciding whether startup or repair is needed. Stop and
deregister the `launchd` services with `container system stop` (which takes only `-p/--prefix`).
The startup flags for `container system start` (`-a/--app-root`, `--install-root`, `--log-root`,
`--enable-kernel-install`/`--disable-kernel-install`, `--timeout`) are in
`references/configuration.md`.

**Upgrade / downgrade / uninstall** use helper scripts in `/usr/local/bin` (stop first with
`container system stop`): `update-container.sh` (add `-v <version>` to pin a version), and
`uninstall-container.sh -d` to remove user da
