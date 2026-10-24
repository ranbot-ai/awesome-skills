---
name: fedora-hyprland-installer
description: Install, configure, verify, repair, update, and uninstall Hyprland on Fedora Linux with GPU-aware detection (NVIDIA/AMD/Intel). 
category: Document Processing
source: antigravity
tags: [claude, ai, agent, workflow, document]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/fedora-hyprland-installer
---


# Fedora Hyprland Installer Skill

This skill provides a limited workflow for a conventional mutable Fedora desktop. Fedora Atomic variants require a separate package-management plan; do not run these DNF scripts there. Use the target desktop user session, not a root shell, for user configuration and services. Backups and a working alternate session are prerequisites for disruptive changes.

## Resolve the Skill Directory

Before running a bundled script, resolve `SKILL_DIR` to the directory that
contains this `SKILL.md`. Do not assume the user's current working directory or
guess a global installation path. If the agent cannot resolve the installed
skill directory from its runtime context, stop and ask the user to provide it.
Invoke bundled shell files explicitly with `bash` and a quoted path, for
example `bash "$SKILL_DIR/scripts/detect-system.sh"`.

## When to Use

- Use when installing or updating a Fedora-packaged Hyprland desktop stack.
- Use when verifying a Hyprland session, portals, PipeWire, or WirePlumber on Fedora.
- Use when diagnosing the limited repair cases documented below or removing the Hyprland-specific packages installed by this workflow.

## Core Directives & Safety Rules

1. **Fedora-First**: Always use Fedora tools (`dnf`, `systemctl`, `loginctl`). Never use `apt`, `pacman`, or `yay`.
2. **Never Blindly Execute**: Inspect the system prior to any installation or modification.
3. **Preserve Existing Desktop**: Do not uninstall GNOME, KDE, or any existing desktop environment. Hyprland should be added as a session choice in the display manager (GDM/SDDM/LightDM).
4. **Mandatory Backup**: Always create a timestamped backup in `~/.local/state/fedora-hyprland-installer/backups/` before writing or altering configurations in `~/.config/hypr/`, `~/.config/waybar/`, etc.
5. **GPU Awareness**: Check whether the system uses NVIDIA, AMD, Intel, or Hybrid graphics before configuring environment variables or graphics drivers. Never use arbitrary `.run` installers for NVIDIA; rely on Fedora/RPM Fusion repositories.
6. **Privileged Operations**: Sudo commands must be clearly identified and communicated to the user. Do not hardcode passwords.
7. **Idempotency**: Running actions multiple times must be safe and avoid duplicate config lines.
8. **Explicit Consent**: Show the exact package or service changes first. Run scripts that mutate packages or services only after the user confirms; use `repair.sh` without `--apply` for diagnosis.

---

## Workflow Guide

### 1. Installation Workflow
When the user asks to **"Install Hyprland"** or **"Setup Hyprland on Fedora"**:
1. Execute `bash "$SKILL_DIR/scripts/detect-system.sh"` and `bash "$SKILL_DIR/scripts/detect-gpu.sh"`.
2. Execute `bash "$SKILL_DIR/scripts/preflight.sh"` to inspect the Fedora marker, network reachability, package-manager presence and sudo binary. It does not establish Fedora lifecycle support, repository health or effective sudo authorization.
3. Execute `bash "$SKILL_DIR/scripts/backup.sh"` to preserve any pre-existing configurations.
4. Show the package plan with `bash "$SKILL_DIR/scripts/install.sh" --dry-run`; after explicit approval, execute `bash "$SKILL_DIR/scripts/install.sh"` to install Hyprland, Wayland portal packages (`xdg-desktop-portal-hyprland`, `xdg-desktop-portal-gtk`), PipeWire/WirePlumber, terminal, launcher, status bar, and authentication agent.
5. Include configuration creation in the approved plan, then execute `bash "$SKILL_DIR/scripts/configure.sh"` to write a clean, functional initial Hyprland config (`~/.config/hypr/hyprland.conf`) using detected terminal/launcher defaults. Review keyboard layout, autostart paths and exact-version syntax; GPU vendor presence alone must not force NVIDIA environment variables on hybrid or non-proprietary-driver setups.
6. Execute `bash "$SKILL_DIR/scripts/verify.sh"` to ensure binaries, portal services, PipeWire, and login desktop entries (`/usr/share/wayland-sessions/hyprland.desktop`) exist and validate.
7. Present a summary report detailing installed packages, backup paths, and login instructions.

### 2. Repair Workflow
When the user asks to **"Fix Hyprland"**, **"Hyprland won't start"**, **"No audio"**, **"Screen sharing broken"**:
1. Run `bash "$SKILL_DIR/scripts/detect-system.sh"` and inspect system logs (`journalctl -xe`, `journalctl --user -u xdg-desktop-portal`).
2. Execute `bash "$SKILL_DIR/scripts/repair.sh"` to report a missing Hyprland config, missing portal package, and inactive PipeWire/WirePlumber services.
3. Review the proposed changes with the user, then execute `bash "$SKILL_DIR/scripts/repair.sh" --apply` only after approval. The script can create a missing config, install missing portal packages, and enable or restart the checked user services; investigate other faults manually.
4. Execute `bash "$SKILL_DIR/scripts/verify.sh"`.

### 3. Update Workflow
When the user asks to **"Update Hyprland"**:
1. Run `bash "$SKILL_DIR/scripts/backup.sh"`.
2. Show the package
