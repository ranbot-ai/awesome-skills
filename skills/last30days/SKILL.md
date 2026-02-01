---
name: last30days
description: Research a topic from the last 30 days on Reddit + X + Web, become an expert, and write copy-paste-ready prompts for the user's target tool. 
category: Business & Marketing
source: antigravity
tags: [python, api, claude, ai, agent, gpt, design, image, cro, marketing]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/last30days
---


# last30days: Research Any Topic from the Last 30 Days

Research ANY topic across Reddit, X, and the web. Surface what people are actually discussing, recommending, and debating right now.

Use cases:

- **Prompting**: "photorealistic people in Nano Banana Pro", "Midjourney prompts", "ChatGPT image generation" → learn techniques, get copy-paste prompts
- **Recommendations**: "best Claude Code skills", "top AI tools" → get a LIST of specific things people mention
- **News**: "what's happening with OpenAI", "latest AI announcements" → current events and updates
- **General**: any topic you're curious about → understand what the community is saying

## CRITICAL: Parse User Intent

Before doing anything, parse the user's input for:

1. **TOPIC**: What they want to learn about (e.g., "web app mockups", "Claude Code skills", "image generation")
2. **TARGET TOOL** (if specified): Where they'll use the prompts (e.g., "Nano Banana Pro", "ChatGPT", "Midjourney")
3. **QUERY TYPE**: What kind of research they want:
   - **PROMPTING** - "X prompts", "prompting for X", "X best practices" → User wants to learn techniques and get copy-paste prompts
   - **RECOMMENDATIONS** - "best X", "top X", "what X should I use", "recommended X" → User wants a LIST of specific things
   - **NEWS** - "what's happening with X", "X news", "latest on X" → User wants current events/updates
   - **GENERAL** - anything else → User wants broad understanding of the topic

Common patterns:

- `[topic] for [tool]` → "web mockups for Nano Banana Pro" → TOOL IS SPECIFIED
- `[topic] prompts for [tool]` → "UI design prompts for Midjourney" → TOOL IS SPECIFIED
- Just `[topic]` → "iOS design mockups" → TOOL NOT SPECIFIED, that's OK
- "best [topic]" or "top [topic]" → QUERY_TYPE = RECOMMENDATIONS
- "what are the best [topic]" → QUERY_TYPE = RECOMMENDATIONS

**IMPORTANT: Do NOT ask about target tool before research.**

- If tool is specified in the query, use it
- If tool is NOT specified, run research first, then ask AFTER showing results

**Store these variables:**

- `TOPIC = [extracted topic]`
- `TARGET_TOOL = [extracted tool, or "unknown" if not specified]`
- `QUERY_TYPE = [RECOMMENDATIONS | NEWS | HOW-TO | GENERAL]`

---

## Setup Check

The skill works in three modes based on available API keys:

1. **Full Mode** (both keys): Reddit + X + WebSearch - best results with engagement metrics
2. **Partial Mode** (one key): Reddit-only or X-only + WebSearch
3. **Web-Only Mode** (no keys): WebSearch only - still useful, but no engagement metrics

**API keys are OPTIONAL.** The skill will work without them using WebSearch fallback.

### First-Time Setup (Optional but Recommended)

If the user wants to add API keys for better results:

```bash
mkdir -p ~/.config/last30days
cat > ~/.config/last30days/.env << 'ENVEOF'
# last30days API Configuration
# Both keys are optional - skill works with WebSearch fallback

# For Reddit research (uses OpenAI's web_search tool)
OPENAI_API_KEY=

# For X/Twitter research (uses xAI's x_search tool)
XAI_API_KEY=
ENVEOF

chmod 600 ~/.config/last30days/.env
echo "Config created at ~/.config/last30days/.env"
echo "Edit to add your API keys for enhanced research."
```

**DO NOT stop if no keys are configured.** Proceed with web-only mode.

---

## Research Execution

**IMPORTANT: The script handles API key detection automatically.** Run it and check the output to determine mode.

**Step 1: Run the research script**

```bash
python3 ~/.claude/skills/last30days/scripts/last30days.py "$ARGUMENTS" --emit=compact 2>&1
```

The script will automatically:

- Detect available API keys
- Show a promo banner if keys are missing (this is intentional marketing)
- Run Reddit/X searches if keys exist
- Signal if WebSearch is needed

**Step 2: Check the output mode**

The script output will indicate the mode:

- **"Mode: both"** or **"Mode: reddit-only"** or **"Mode: x-only"**: Script found results, WebSearch is supplementary
- **"Mode: web-only"**: No API keys, Claude must do ALL research via WebSearch

**Step 3: Do WebSearch**

For **ALL modes**, do WebSearch to supplement (or provide all data in web-only mode).

Choose search queries based on QUERY_TYPE:

**If RECOMMENDATIONS** ("best X", "top X", "what X should I use"):

- Search for: `best {TOPIC} recommendations`
- Search for: `{TOPIC} list examples`
- Search for: `most popular {TOPIC}`
- Goal: Find SPECIFIC NAMES of things, not generic advice

**If NEWS** ("what's happening with X", "X news"):

- Search for: `{TOPIC} news 2026`
- Search for: `{TOPIC} announcement update`
- Goal: Find current events and recent developments

**If PROMPTING** ("X prompts", "prompting for X"):

- Search for: `{TOPIC} prompts examples 2026`
- Search for: `{TOPIC} techniques tips`
- Goal: Find prompting techniques and examples to create copy-paste prompts

**If GENERAL** (default):

- Search for: `{TOPIC} 2026`
- Search for: `{TOPIC} discussion`
- Goal: Find what people are actually saying

For ALL query types:
