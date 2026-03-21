---
name: claude-in-chrome-troubleshooting
description: Diagnose and fix Claude in Chrome MCP extension connectivity issues. Use when mcp__claude-in-chrome__* tools fail, return "Browser extension is not connected", or behave erratically. 
category: AI & Agents
source: antigravity
tags: [mcp, claude, ai, automation]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/claude-in-chrome-troubleshooting
---


# Claude in Chrome MCP Troubleshooting

Use this skill when Claude in Chrome MCP tools fail to connect or work unreliably.

## When to Use
- `mcp__claude-in-chrome__*` tools fail with "Browser extension is not connected"
- Browser automation works erratically or times out
- After updating Claude Code or Claude.app
- When switching between Claude Code CLI and Claude.app (Cowork)
- Native host process is running but MCP tools still fail

## When NOT to Use

- **Linux or Windows users** - This skill covers macOS-specific paths and tools (`~/Library/Application Support/`, `osascript`)
- General Chrome automation issues unrelated to the Claude extension
- Claude.app desktop issues (not browser-related)
- Network connectivity problems
- Chrome extension installation issues (use Chrome Web Store support)

## The Claude.app vs Claude Code Conflict (Primary Issue)

**Background:** When Claude.app added Cowork support (browser automation from the desktop app), it introduced a competing native messaging host that conflicts with Claude Code CLI.

### Two Native Hosts, Two Socket Formats

| Component | Native Host Binary | Socket Location |
|-----------|-------------------|-----------------|
| **Claude.app (Cowork)** | `/Applications/Claude.app/Contents/Helpers/chrome-native-host` | `/tmp/claude-mcp-browser-bridge-$USER/<PID>.sock` |
| **Claude Code CLI** | `~/.local/share/claude/versions/<version> --chrome-native-host` | `$TMPDIR/claude-mcp-browser-bridge-$USER` (single file) |

### Why They Conflict

1. Both register native messaging configs in Chrome:
   - `com.anthropic.claude_browser_extension.json` → Claude.app helper
   - `com.anthropic.claude_code_browser_extension.json` → Claude Code wrapper

2. Chrome extension requests a native host by name
3. If the wrong config is active, the wrong binary runs
4. The wrong binary creates sockets in a format/location the MCP client doesn't expect
5. Result: "Browser extension is not connected" even though everything appears to be running

### The Fix: Disable Claude.app's Native Host

**If you use Claude Code CLI for browser automation (not Cowork):**

```bash
# Disable the Claude.app native messaging config
mv ~/Library/Application\ Support/Google/Chrome/NativeMessagingHosts/com.anthropic.claude_browser_extension.json \
   ~/Library/Application\ Support/Google/Chrome/NativeMessagingHosts/com.anthropic.claude_browser_extension.json.disabled

# Ensure the Claude Code config exists and points to the wrapper
cat ~/Library/Application\ Support/Google/Chrome/NativeMessagingHosts/com.anthropic.claude_code_browser_extension.json
```

**If you use Cowork (Claude.app) for browser automation:**

```bash
# Disable the Claude Code native messaging config
mv ~/Library/Application\ Support/Google/Chrome/NativeMessagingHosts/com.anthropic.claude_code_browser_extension.json \
   ~/Library/Application\ Support/Google/Chrome/NativeMessagingHosts/com.anthropic.claude_code_browser_extension.json.disabled
```

**You cannot use both simultaneously.** Pick one and disable the other.

### Toggle Script

Add this to `~/.zshrc` or run directly:

```bash
chrome-mcp-toggle() {
    local CONFIG_DIR=~/Library/Application\ Support/Google/Chrome/NativeMessagingHosts
    local CLAUDE_APP="$CONFIG_DIR/com.anthropic.claude_browser_extension.json"
    local CLAUDE_CODE="$CONFIG_DIR/com.anthropic.claude_code_browser_extension.json"

    if [[ -f "$CLAUDE_APP" && ! -f "$CLAUDE_APP.disabled" ]]; then
        # Currently using Claude.app, switch to Claude Code
        mv "$CLAUDE_APP" "$CLAUDE_APP.disabled"
        [[ -f "$CLAUDE_CODE.disabled" ]] && mv "$CLAUDE_CODE.disabled" "$CLAUDE_CODE"
        echo "Switched to Claude Code CLI"
        echo "Restart Chrome and Claude Code to apply"
    elif [[ -f "$CLAUDE_CODE" && ! -f "$CLAUDE_CODE.disabled" ]]; then
        # Currently using Claude Code, switch to Claude.app
        mv "$CLAUDE_CODE" "$CLAUDE_CODE.disabled"
        [[ -f "$CLAUDE_APP.disabled" ]] && mv "$CLAUDE_APP.disabled" "$CLAUDE_APP"
        echo "Switched to Claude.app (Cowork)"
        echo "Restart Chrome to apply"
    else
        echo "Current state unclear. Check configs:"
        ls -la "$CONFIG_DIR"/com.anthropic*.json* 2>/dev/null
    fi
}
```

Usage: `chrome-mcp-toggle` then restart Chrome (and Claude Code if switching to CLI).

## Quick Diagnosis

```bash
# 1. Which native host binary is running?
ps aux | grep chrome-native-host | grep -v grep
# Claude.app: /Applications/Claude.app/Contents/Helpers/chrome-native-host
# Claude Code: ~/.local/share/claude/versions/X.X.X --chrome-native-host

# 2. Where is the socket?
# For Claude Code (single file in TMPDIR):
ls -la "$(getconf DARWIN_USER_TEMP_DIR)/claude-mcp-browser-bridge-$USER" 2>&1

# For Claude.app (directory with PID files):
ls -la /tmp/claude-mcp-browser-bridge-$USER/ 2>&1

# 3. What's the native host connected to?
lsof -U 2>&1 | grep claude-mcp-browser-bridge

# 4. Which configs are active?
ls ~/Library/Application\ Support/Google/Ch
