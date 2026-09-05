---
name: devrel-content
description: When the user wants to create technical content for developers including blog posts, tutorials, and documentation. 
category: Document Processing
source: antigravity
tags: [python, javascript, typescript, react, node, markdown, api, ai, agent, template]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/devrel-content
---


# DevRel Content
## When to Use

Use this skill when you need when the user wants to create technical content for developers including blog posts, tutorials, and documentation. Trigger phrases include "write a blog post," "technical article," "developer content," "tutorial," "devrel content," "dev blog," "technical writing," or "content for...


This skill helps you create technical content that developers actually read: blog posts, tutorials, documentation, and thought leadership pieces that build trust and drive adoption.

---

## Before You Start

**Load your audience context first.** Read `.agents/developer-audience-context.md` to understand:

- Who you're writing for (role, seniority, tech stack)
- Their pain points (what problems resonate)
- Verbatim language (how they describe things)
- Voice & tone (how formal/technical to be)

If the context file doesn't exist, run the `developer-audience-context` skill first.

---

## The DevRel Content Framework

### Phase 1: Research & Validation

Before writing anything, validate the topic is worth writing about.

| Research Type | What to Do |
|--------------|------------|
| **Search intent** | Google your topic. What already ranks? What's missing? |
| **Community signals** | Search Reddit, HN, Stack Overflow. Are developers asking about this? |
| **Competitor gaps** | What have competitors written? What haven't they covered? |
| **Internal data** | Support tickets, Discord questions, GitHub issues about this topic |
| **Keyword research** | Use Ahrefs/SEMrush for search volume on technical terms |

**Red flags** — Don't write if:
- You're the only one who cares about this topic
- 10 identical articles already exist
- The topic is too broad ("Introduction to JavaScript")
- The topic is too narrow (no search volume, no community interest)

### Phase 2: Content Type Selection

Choose the right format for your goal:

| Content Type | Best For | Structure |
|-------------|----------|-----------|
| **Tutorial** | Teaching a specific skill | Step-by-step, code-heavy |
| **Guide** | Covering a topic comprehensively | Sections, reference material |
| **Comparison** | Helping with decisions | Table-based, pros/cons |
| **Announcement** | Launching features/products | News lead, what/why/how |
| **Thought leadership** | Building authority | Opinion, predictions, takes |
| **Case study** | Social proof | Problem → Solution → Results |
| **Troubleshooting** | Solving specific errors | Error → Cause → Fix |

### Phase 3: Outline Structure

Use this outline template:

```markdown
# [Title that promises specific value]

## Hook (2-3 sentences)
- State the problem or opportunity
- Establish credibility ("We migrated 10,000 repos...")
- Promise what the reader will learn

## Context (optional)
- Brief background if needed
- Link to prerequisites

## The Meat
### Section 1: [First major concept]
- Explanation
- Code example
- Common pitfall

### Section 2: [Second major concept]
- Explanation
- Code example
- Real-world application

### Section 3: [Third major concept]
- Explanation
- Code example
- Advanced tip

## Putting It Together
- Complete example
- Working code

## What's Next
- Links to deeper content
- Call to action (try the product, join Discord, etc.)
```

---

## Writing Code Examples

Code is the content. Get it right.

### The Copy-Paste Test

Every code example must:

| Requirement | Why It Matters |
|------------|----------------|
| **Run without modification** | Developers will copy-paste. If it fails, you lose trust. |
| **Include imports** | Don't assume they know which libraries to import. |
| **Show output** | What should they see when it works? |
| **Handle errors** | Real code has error handling. Show it. |
| **Use real values** | No `foo`, `bar`, `example.com` unless necessary. |

### Code Example Structure

```markdown
First, install the dependencies:

\`\`\`bash
npm install your-library axios
\`\`\`

Now create a file called `fetch-data.js`:

\`\`\`javascript
// fetch-data.js
import { Client } from 'your-library';
import axios from 'axios';

const client = new Client({
  apiKey: process.env.YOUR_API_KEY // Use environment variables
});

async function fetchUserData(userId) {
  try {
    const user = await client.users.get(userId);
    console.log(`Fetched user: ${user.name}`);
    return user;
  } catch (error) {
    console.error(`Failed to fetch user: ${error.message}`);
    throw error;
  }
}

// Example usage
fetchUserData('user_123')
  .then(user => console.log(user))
  .catch(err => process.exit(1));
\`\`\`

Run it:

\`\`\`bash
YOUR_API_KEY=sk_test_xxx node fetch-data.js
\`\`\`

Expected output:

\`\`\`
Fetched user: Jane Developer
{ id: 'user_123', name: 'Jane Developer', email: 'jane@example.dev' }
\`\`\`
```

### Language-Specific Conventions

| Language | Code Block | Package Install | Env Vars |
|----------|-----------|-----------------|----------|
| JavaScript/Node | `javascript` or `js` | `npm install` | `process.env.VAR` |
| TypeScript
