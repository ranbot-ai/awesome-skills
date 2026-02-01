---
name: environment-setup-guide
description: Guide developers through setting up development environments with proper tools, dependencies, and configurations 
category: Document Processing
source: antigravity
tags: [python, node, markdown, api, ai, template, document, image, security, docker]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/environment-setup-guide
---


# Environment Setup Guide

## Overview

Help developers set up complete development environments from scratch. This skill provides step-by-step guidance for installing tools, configuring dependencies, setting up environment variables, and verifying the setup works correctly.

## When to Use This Skill

- Use when starting a new project and need to set up the development environment
- Use when onboarding new team members to a project
- Use when switching to a new machine or operating system
- Use when troubleshooting environment-related issues
- Use when documenting setup instructions for a project
- Use when creating development environment documentation

## How It Works

### Step 1: Identify Requirements

I'll help you determine what needs to be installed:
- Programming language and version (Node.js, Python, Go, etc.)
- Package managers (npm, pip, cargo, etc.)
- Database systems (PostgreSQL, MongoDB, Redis, etc.)
- Development tools (Git, Docker, IDE extensions, etc.)
- Environment variables and configuration files

### Step 2: Check Current Setup

Before installing anything, I'll help you check what's already installed:
```bash
# Check versions of installed tools
node --version
python --version
git --version
docker --version
```

### Step 3: Provide Installation Instructions

I'll give platform-specific installation commands:
- **macOS:** Using Homebrew
- **Linux:** Using apt, yum, or package manager
- **Windows:** Using Chocolatey, Scoop, or direct installers

### Step 4: Configure the Environment

Help set up:
- Environment variables (.env files)
- Configuration files (.gitconfig, .npmrc, etc.)
- IDE settings (VS Code, IntelliJ, etc.)
- Shell configuration (.bashrc, .zshrc, etc.)

### Step 5: Verify Installation

Provide verification steps to ensure everything works:
- Run version checks
- Test basic commands
- Verify database connections
- Check environment variables are loaded

## Examples

### Example 1: Node.js Project Setup

```markdown
## Setting Up Node.js Development Environment

### Prerequisites
- macOS, Linux, or Windows
- Terminal/Command Prompt access
- Internet connection

### Step 1: Install Node.js

**macOS (using Homebrew):**
\`\`\`bash
# Install Homebrew if not installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Node.js
brew install node
\`\`\`

**Linux (Ubuntu/Debian):**
\`\`\`bash
# Update package list
sudo apt update

# Install Node.js and npm
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
\`\`\`

**Windows (using Chocolatey):**
\`\`\`powershell
# Install Chocolatey if not installed
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Install Node.js
choco install nodejs
\`\`\`

### Step 2: Verify Installation

\`\`\`bash
node --version  # Should show v20.x.x or higher
npm --version   # Should show 10.x.x or higher
\`\`\`

### Step 3: Install Project Dependencies

\`\`\`bash
# Clone the repository
git clone https://github.com/your-repo/project.git
cd project

# Install dependencies
npm install
\`\`\`

### Step 4: Set Up Environment Variables

Create a \`.env\` file:
\`\`\`bash
# Copy example environment file
cp .env.example .env

# Edit with your values
nano .env
\`\`\`

Example \`.env\` content:
\`\`\`
NODE_ENV=development
PORT=3000
DATABASE_URL=postgresql://localhost:5432/mydb
API_KEY=your-api-key-here
\`\`\`

### Step 5: Run the Project

\`\`\`bash
# Start development server
npm run dev

# Should see: Server running on http://localhost:3000
\`\`\`

### Troubleshooting

**Problem:** "node: command not found"
**Solution:** Restart your terminal or run \`source ~/.bashrc\` (Linux) or \`source ~/.zshrc\` (macOS)

**Problem:** "Permission denied" errors
**Solution:** Don't use sudo with npm. Fix permissions:
\`\`\`bash
mkdir ~/.npm-global
npm config set prefix '~/.npm-global'
echo 'export PATH=~/.npm-global/bin:$PATH' >> ~/.bashrc
source ~/.bashrc
\`\`\`
```

### Example 2: Python Project Setup

```markdown
## Setting Up Python Development Environment

### Step 1: Install Python

**macOS:**
\`\`\`bash
brew install python@3.11
\`\`\`

**Linux:**
\`\`\`bash
sudo apt update
sudo apt install python3.11 python3.11-venv python3-pip
\`\`\`

**Windows:**
\`\`\`powershell
choco install python --version=3.11
\`\`\`

### Step 2: Verify Installation

\`\`\`bash
python3 --version  # Should show Python 3.11.x
pip3 --version     # Should show pip 23.x.x
\`\`\`

### Step 3: Create Virtual Environment

\`\`\`bash
# Navigate to project directory
cd my-project

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# macOS/Linux:
source venv/bin/activate

# Windows:
venv\Scripts\activate
\`\`\`

### Step 4: Install Dependencies

\`\`\`bash
# Install fro
