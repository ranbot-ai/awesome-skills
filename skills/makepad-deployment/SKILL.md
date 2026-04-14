---
name: makepad-deployment
description: CRITICAL: Use for Makepad packaging and deployment. Triggers on: deploy, package, APK, IPA, 打包, 部署, cargo-packager, cargo-makepad, WASM, Android, iOS, distribution, installer, .deb, .dmg, .nsi
category: Development & Code Tools
source: antigravity
tags: [python, javascript, ai, workflow, template, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/makepad-deployment
---


# Makepad Packaging & Deployment

This skill covers packaging Makepad applications for all supported platforms.

## When to Use
- You need to package, distribute, or automate deployment of a Makepad application.
- The task involves desktop installers, APK/IPA builds, WebAssembly output, or CI-based release artifacts.
- You need guidance on `cargo-packager`, `cargo-makepad`, or GitHub Actions packaging flows for Makepad.

## Quick Navigation

| Platform | Tool | Output |
|----------|------|--------|
| [Desktop](#desktop-packaging) | `cargo-packager` | .deb, .nsis, .dmg |
| [Android](#android) | `cargo-makepad` | .apk |
| [iOS](#ios) | `cargo-makepad` | .app, .ipa |
| [Web](#wasm-packaging) | `cargo-makepad` | Wasm + HTML/JS |
| [CI/CD](#github-actions-packaging) | `makepad-packaging-action` | GitHub Release assets |

---

## GitHub Actions Packaging

Use `makepad-packaging-action` to package Makepad apps in CI. It wraps
`cargo-packager` (desktop) and `cargo-makepad` (mobile), and can upload artifacts
to GitHub Releases.

```yaml
jobs:
  package:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
      - uses: Project-Robius-China/makepad-packaging-action@v1
        with:
          args: --target x86_64-unknown-linux-gnu --release
```

Notes:
- Desktop packages must run on matching OS runners (Linux/Windows/macOS).
- iOS builds require macOS runners.
- Android builds can run on any OS runner.

Full inputs/env/outputs and release workflows live in
`references/makepad-packaging-action.md`.

## Desktop Packaging

Desktop packaging uses `cargo-packager` with `robius-packaging-commands` for resource handling.

### Install Tools

```bash
# Install cargo-packager
cargo install cargo-packager --locked

# Install robius-packaging-commands (v0.2.1)
cargo install --version 0.2.1 --locked \
    --git https://github.com/project-robius/robius-packaging-commands.git \
    robius-packaging-commands
```

### Configure Cargo.toml

Add packaging configuration to your `Cargo.toml`:

```toml
[package.metadata.packager]
product_name = "YourAppName"
identifier = "com.yourcompany.yourapp"
authors = ["Your Name or Team"]
description = "A brief description of your Makepad application"
# Note: long_description has 80 character max per line
long_description = """
Your detailed description here.
Keep each line under 80 characters.
"""
icons = ["./assets/icon.png"]
out_dir = "./dist"

# Pre-packaging command to collect resources
before-packaging-command = """
robius-packaging-commands before-packaging \
    --force-makepad \
    --binary-name your-app \
    --path-to-binary ./target/release/your-app
"""

# Resources to include in package
resources = [
    # Makepad built-in resources (required)
    { src = "./dist/resources/makepad_widgets", target = "makepad_widgets" },
    { src = "./dist/resources/makepad_fonts_chinese_bold", target = "makepad_fonts_chinese_bold" },
    { src = "./dist/resources/makepad_fonts_chinese_bold_2", target = "makepad_fonts_chinese_bold_2" },
    { src = "./dist/resources/makepad_fonts_chinese_regular", target = "makepad_fonts_chinese_regular" },
    { src = "./dist/resources/makepad_fonts_chinese_regular_2", target = "makepad_fonts_chinese_regular_2" },
    { src = "./dist/resources/makepad_fonts_emoji", target = "makepad_fonts_emoji" },

    # Your app resources
    { src = "./dist/resources/your_app_resource", target = "your_app_resource" },
]

before-each-package-command = """
robius-packaging-commands before-each-package \
    --force-makepad \
    --binary-name your-app \
    --path-to-binary ./target/release/your-app
"""
```

### Linux (Debian/Ubuntu)

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install libssl-dev libsqlite3-dev pkg-config \
    binfmt-support libxcursor-dev libx11-dev libasound2-dev libpulse-dev

# Build package
cargo packager --release
```

Output: `.deb` file in `./dist/`

### Windows

```bash
# Build NSIS installer
cargo packager --release --formats nsis
```

Output: `.exe` installer in `./dist/`

### macOS

```bash
# Build package
cargo packager --release
```

Output: `.dmg` file in `./dist/`

### Platform-Specific Configuration

```toml
# Linux (Debian)
[package.metadata.packager.deb]
depends = "./dist/depends_deb.txt"
desktop_template = "./packaging/your-app.desktop"
section = "utils"

# macOS
[package.metadata.packager.macos]
minimum_system_version = "11.0"
frameworks = []
info_plist_path = "./packaging/Info.plist"
entitlements = "./packaging/Entitlements.plist"
# Optional: signing identity for distribution
signing_identity = "Developer ID Application: Your Name (XXXXXXXXXX)"

# macOS DMG
[package.metadata.packager.dmg]
background = "./packaging/dmg_background.png"
window_size = { width = 960, height = 540 }
app_position = { x = 200, y = 250 }
application_folder_position = { x = 760, y = 250 }

# Windows NSIS
[package.metadata.packager.nsis]
appdata_paths = [
    "$APPDATA/$PUBLISHER/$PRODUCTNAME",
    "$LOCALAPPDATA/$PRODUCTNAME",
]
```
