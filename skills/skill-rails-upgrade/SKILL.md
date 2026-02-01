---
name: skill-rails-upgrade
description: Analyze Rails apps and provide upgrade assessments 
category: Document Processing
source: antigravity
tags: [javascript, api, ai, template, document, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/skill-rails-upgrade
---


## When to Use This Skill

Analyze Rails apps and provide upgrade assessments

Use this skill when working with analyze rails apps and provide upgrade assessments.
# Rails Upgrade Analyzer

Analyze the current Rails application and provide a comprehensive upgrade assessment with selective file merging.

## Step 1: Verify Rails Application

Check that we're in a Rails application by looking for these files:
- `Gemfile` (must exist and contain 'rails')
- `config/application.rb` (Rails application config)
- `config/environment.rb` (Rails environment)

If any of these are missing or don't indicate a Rails app, stop and inform the user this doesn't appear to be a Rails application.

## Step 2: Get Current Rails Version

Extract the current Rails version from:
1. First, check `Gemfile.lock` for the exact installed version (look for `rails (x.y.z)`)
2. If not found, check `Gemfile` for the version constraint

Report the exact current version (e.g., `7.1.3`).

## Step 3: Find Latest Rails Version

Use the GitHub CLI to fetch the latest Rails release:

```bash
gh api repos/rails/rails/releases/latest --jq '.tag_name'
```

This returns the latest stable version tag (e.g., `v8.0.1`). Strip the 'v' prefix for comparison.

Also check recent tags to understand the release landscape:

```bash
gh api repos/rails/rails/tags --jq '.[0:10] | .[].name'
```

## Step 4: Determine Upgrade Type

Compare current and latest versions to classify the upgrade:

- **Patch upgrade**: Same major.minor, different patch (e.g., 7.1.3 → 7.1.5)
- **Minor upgrade**: Same major, different minor (e.g., 7.1.3 → 7.2.0)
- **Major upgrade**: Different major version (e.g., 7.1.3 → 8.0.0)

## Step 5: Fetch Upgrade Guide

Use WebFetch to get the official Rails upgrade guide:

URL: `https://guides.rubyonrails.org/upgrading_ruby_on_rails.html`

Look for sections relevant to the version jump. The guide is organized by target version with sections like:
- "Upgrading from Rails X.Y to Rails X.Z"
- Breaking changes
- Deprecation warnings
- Configuration changes
- Required migrations

Extract and summarize the relevant sections for the user's specific upgrade path.

## Step 6: Fetch Rails Diff

Use WebFetch to get the diff between versions from railsdiff.org:

URL: `https://railsdiff.org/{current_version}/{target_version}`

For example: `https://railsdiff.org/7.1.3/8.0.0`

This shows:
- Changes to default configuration files
- New files that need to be added
- Modified initializers
- Updated dependencies
- Changes to bin/ scripts

Summarize the key file changes.

## Step 7: Check JavaScript Dependencies

Rails applications often include JavaScript packages that should be updated alongside Rails. Check for and report on these dependencies.

### 7.1: Identify JS Package Manager

Check which package manager the app uses:

```bash
# Check for package.json (npm/yarn)
ls package.json 2>/dev/null

# Check for importmap (Rails 7+)
ls config/importmap.rb 2>/dev/null
```

### 7.2: Check Rails-Related JS Packages

If `package.json` exists, check for these Rails-related packages:

```bash
# Extract current versions of Rails-related packages
cat package.json | grep -E '"@hotwired/|"@rails/|"stimulus"|"turbo-rails"' || echo "No Rails JS packages found"
```

**Key packages to check:**

| Package | Purpose | Version Alignment |
|---------|---------|-------------------|
| `@hotwired/turbo-rails` | Turbo Drive/Frames/Streams | Should match Rails version era |
| `@hotwired/stimulus` | Stimulus JS framework | Generally stable across Rails versions |
| `@rails/actioncable` | WebSocket support | Should match Rails version |
| `@rails/activestorage` | Direct uploads | Should match Rails version |
| `@rails/actiontext` | Rich text editing | Should match Rails version |
| `@rails/request.js` | Rails UJS replacement | Should match Rails version era |

### 7.3: Check for Updates

For npm/yarn projects, check for available updates:

```bash
# Using npm
npm outdated @hotwired/turbo-rails @hotwired/stimulus @rails/actioncable @rails/activestorage 2>/dev/null

# Or check latest versions directly
npm view @hotwired/turbo-rails version 2>/dev/null
npm view @rails/actioncable version 2>/dev/null
```

### 7.4: Check Importmap Pins (if applicable)

If the app uses importmap-rails, check `config/importmap.rb` for pinned versions:

```bash
cat config/importmap.rb | grep -E 'pin.*turbo|pin.*stimulus|pin.*@rails' || echo "No importmap pins found"
```

To update importmap pins:
```bash
bin/importmap pin @hotwired/turbo-rails
bin/importmap pin @hotwired/stimulus
```

### 7.5: JS Dependency Summary

Include in the upgrade summary:

```
### JavaScript Dependencies

**Package Manager**: [npm/yarn/importmap/none]

| Package | Current | Latest | Action |
|---------|---------|--------|--------|
| @hotwired/turbo-rails | 8.0.4 | 8.0.12 | Update recommended |
| @rails/actioncable | 7.1.0 | 8.0.0 | Update with Rails |
| ... | ... | ... | ... |

**Recommended JS Updates:**
- Run `npm update @hotwired/turbo-rai
