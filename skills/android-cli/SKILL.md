---
name: android-cli
description: Orchestrates Android development tasks including project creation, deployment, SDK management, and environment diagnostics using the `android` command-line tool. 
category: Document Processing
source: antigravity
tags: [api, claude, ai, agent, template, document, image, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/android-cli
---


<!-- security-allowlist: curl-pipe-bash -->

# Android CLI Specialist

This skill provides instructions for using the `android` CLI tool. The tool includes various commands for creating projects, running applications, interacting with devices, and managing the CLI environment.

## When to Use

- Use when you need to create, configure, or analyze Android projects from the command line.
- Use when interacting with, deploying to, or taking screenshots of running Android devices.
- Use when managing Android SDK components, versions, or virtual devices (emulators).
- Use when inspecting UI layouts or running XML-specified journey tests.

## Installation

If the `android` tool is not in the path, install it. To install, run the following command:

- **Linux:** `curl -fsSL https://dl.google.com/android/cli/latest/linux_x86_64/install.sh | bash`
- **macOS:** `curl -fsSL https://dl.google.com/android/cli/latest/darwin_arm64/install.sh | bash`
- **Windows:** `curl.exe -fsSL https://dl.google.com/android/cli/latest/windows_x86_64/install.cmd -o "%TEMP%\i.cmd" && "%TEMP%\i.cmd"`

## SDK Management

To manage the installation of Android SDKs and tools, use the `sdk` command. For example:

- `android sdk install <package>[@<version>]...`: Install specific packages. Multiple packages can be specified, separated by spaces. `<version>` defaults to latest. For example: `android sdk install platforms/android-30@2 platforms/android-34`
- `android sdk update [<pkg-name>]`: Update a specific package or all packages to the latest version.
- `android sdk remove <pkg-name>`: Remove a package from the local SDK.
- `android sdk list --all`: List installed and available SDK packages.

## Project Creation

Create projects from templates using the `create` command.

For example:
```bash
android create empty-activity --name="My App" --output=./my-app
```

## Interacting with Devices

For more information on interacting with running devices, see [here](references/interact.md).

## Running Journey Tests

For more information on running journeys, see [here](references/journeys.md).

## Doc Searching

The `docs` command searches authoritative, high-quality Android developer documentation in the Android Knowledge Base.
By providing a few keywords, this tool will return high quality articles that contain examples or guidance on how to use Android APIs or libraries.
Use this tool to obtain additional information on how to achieve Android-specific tasks or to know more about Android APIs, surfaces, libraries, or devices.

Always use this tool to get the most up-to-date information about Android concepts. Typical good use cases are:
  - Finding migration guides for APIs.
  - Finding examples for APIs.
  - Finding up-to-date information about Android APIs.
  - Finding best practices for Android concepts.

## Running APKs

Use the `run` command to run Android apps.

## Managing Emulators

Manage Android Virtual Devices (AVDs) using the `android emulator` command.

## Capturing Screenshots

Capture an image of the current screen of a connected Android device and output it to a file using the `android screen capture -o <file path>` command.

## Managing Skills

Manage antigravity agent skills for Android using the `android skills` command.

## Inspecting UI Layouts

Use the `android layout` command to inspect the UI layout of an Android application. It returns the layout tree of an Android application in JSON format. When debugging UI errors, this is often a much faster approach than taking a screenshot.

## Updating the CLI

Update the Android CLI using the `android update` command.

## Limitations

- The `android` CLI must be installed and available on `PATH`; otherwise install it first or use the platform-specific setup guidance above.
- Device, emulator, SDK, and documentation commands can depend on local Android SDK state, network access, and attached hardware.
- Treat generated commands as environment-sensitive: inspect paths, package names, device serials, and install/update targets before running them.

## Android Help Output

```text
Usage: android [-hV] [--sdk=PARAM] [COMMAND]
  -h, --help        Show this help message and exit.
      --sdk=PARAM   Path to the Android SDK
  -V, --version     Print version information and exit.
Commands:
  create    Create a new Android project
  describe  Analyzes an Android project to generate descriptive metadata.
  docs      Android documentation commands
  emulator  Emulator commands
  help      Shows the help of all commands
  info      Print environment information (SDK Location, etc.)
  init      Initializes the environment (eg. skills) for Android CLI.
  layout    Returns the layout tree of an application
  run       Deploy an Android Application
  screen    Commands to view the device
  sdk       Download and list SDK packages
  skills    Manage skills
  update    Update the Android CLI

create
          Usage: android create [-h] [--verbose] [--list] [--minSdk=api]
                               
