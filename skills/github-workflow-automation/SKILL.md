---
name: github-workflow-automation
description: Automate GitHub workflows with AI assistance. Includes PR reviews, issue triage, CI/CD integration, and Git operations. Use when automating GitHub workflows, setting up PR review automation, creating 
category: Document Processing
source: antigravity
tags: [javascript, typescript, markdown, api, claude, ai, automation, workflow, document, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/github-workflow-automation
---


# 🔧 GitHub Workflow Automation

> Patterns for automating GitHub workflows with AI assistance, inspired by [Gemini CLI](https://github.com/google-gemini/gemini-cli) and modern DevOps practices.

## When to Use This Skill

Use this skill when:

- Automating PR reviews with AI
- Setting up issue triage automation
- Creating GitHub Actions workflows
- Integrating AI into CI/CD pipelines
- Automating Git operations (rebases, cherry-picks)

---

## 1. Automated PR Review

### 1.1 PR Review Action

```yaml
# .github/workflows/ai-review.yml
name: AI Code Review

on:
  pull_request:
    types: [opened, synchronize]

jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Get changed files
        id: changed
        run: |
          files=$(git diff --name-only origin/${{ github.base_ref }}...HEAD)
          echo "files<<EOF" >> $GITHUB_OUTPUT
          echo "$files" >> $GITHUB_OUTPUT
          echo "EOF" >> $GITHUB_OUTPUT

      - name: Get diff
        id: diff
        run: |
          diff=$(git diff origin/${{ github.base_ref }}...HEAD)
          echo "diff<<EOF" >> $GITHUB_OUTPUT
          echo "$diff" >> $GITHUB_OUTPUT
          echo "EOF" >> $GITHUB_OUTPUT

      - name: AI Review
        uses: actions/github-script@v7
        with:
          script: |
            const { Anthropic } = require('@anthropic-ai/sdk');
            const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

            const response = await client.messages.create({
              model: "claude-3-sonnet-20240229",
              max_tokens: 4096,
              messages: [{
                role: "user",
                content: `Review this PR diff and provide feedback:
                
                Changed files: ${{ steps.changed.outputs.files }}
                
                Diff:
                ${{ steps.diff.outputs.diff }}
                
                Provide:
                1. Summary of changes
                2. Potential issues or bugs
                3. Suggestions for improvement
                4. Security concerns if any
                
                Format as GitHub markdown.`
              }]
            });

            await github.rest.pulls.createReview({
              owner: context.repo.owner,
              repo: context.repo.repo,
              pull_number: context.issue.number,
              body: response.content[0].text,
              event: 'COMMENT'
            });
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

### 1.2 Review Comment Patterns

````markdown
# AI Review Structure

## 📋 Summary

Brief description of what this PR does.

## ✅ What looks good

- Well-structured code
- Good test coverage
- Clear naming conventions

## ⚠️ Potential Issues

1. **Line 42**: Possible null pointer exception
   ```javascript
   // Current
   user.profile.name;
   // Suggested
   user?.profile?.name ?? "Unknown";
   ```
````

2. **Line 78**: Consider error handling
   ```javascript
   // Add try-catch or .catch()
   ```

## 💡 Suggestions

- Consider extracting the validation logic into a separate function
- Add JSDoc comments for public methods

## 🔒 Security Notes

- No sensitive data exposure detected
- API key handling looks correct

````

### 1.3 Focused Reviews

```yaml
# Review only specific file types
- name: Filter code files
  run: |
    files=$(git diff --name-only origin/${{ github.base_ref }}...HEAD | \
            grep -E '\.(ts|tsx|js|jsx|py|go)$' || true)
    echo "code_files=$files" >> $GITHUB_OUTPUT

# Review with context
- name: AI Review with context
  run: |
    # Include relevant context files
    context=""
    for file in ${{ steps.changed.outputs.files }}; do
      if [[ -f "$file" ]]; then
        context+="=== $file ===\n$(cat $file)\n\n"
      fi
    done

    # Send to AI with full file context
````

---

## 2. Issue Triage Automation

### 2.1 Auto-label Issues

```yaml
# .github/workflows/issue-triage.yml
name: Issue Triage

on:
  issues:
    types: [opened]

jobs:
  triage:
    runs-on: ubuntu-latest
    permissions:
      issues: write

    steps:
      - name: Analyze issue
        uses: actions/github-script@v7
        with:
          script: |
            const issue = context.payload.issue;

            // Call AI to analyze
            const analysis = await analyzeIssue(issue.title, issue.body);

            // Apply labels
            const labels = [];

            if (analysis.type === 'bug') {
              labels.push('bug');
              if (analysis.severity === 'high') labels.push('priority: high');
            } else if (analysis.type === 'feature') {
              labels.push('enhancement');
            } else if (analysis.type === 'question') {
              labels.push('question');
            }

            if (analysis.area) {
              labels.push
