---
name: meeting-insights-analyzer
description: Analyzes meeting transcripts and recordings to uncover behavioral patterns, communication insights, and actionable feedback. Identifies when you avoid conflict, use filler words, dominate conversation
category: Communication & Writing
source: awesome-llm
tags: [docx, markdown, claude, ai, meeting, insights, analyzer]
url: https://github.com/Prat011/awesome-llm-skills/tree/master/meeting-insights-analyzer
---


# Meeting Insights Analyzer

This skill transforms your meeting transcripts into actionable insights about your communication patterns, helping you become a more effective communicator and leader.

## When to Use This Skill

- Analyzing your communication patterns across multiple meetings
- Getting feedback on your leadership and facilitation style
- Identifying when you avoid difficult conversations
- Understanding your speaking habits and filler words
- Tracking improvement in communication skills over time
- Preparing for performance reviews with concrete examples
- Coaching team members on their communication style

## What This Skill Does

1. **Pattern Recognition**: Identifies recurring behaviors across meetings like:
   - Conflict avoidance or indirect communication
   - Speaking ratios and turn-taking
   - Question-asking vs. statement-making patterns
   - Active listening indicators
   - Decision-making approaches

2. **Communication Analysis**: Evaluates communication effectiveness:
   - Clarity and directness
   - Use of filler words and hedging language
   - Tone and sentiment patterns
   - Meeting control and facilitation

3. **Actionable Feedback**: Provides specific, timestamped examples with:
   - What happened
   - Why it matters
   - How to improve

4. **Trend Tracking**: Compares patterns over time when analyzing multiple meetings

## How to Use

### Basic Setup

1. Download your meeting transcripts to a folder (e.g., `~/meetings/`)
2. Navigate to that folder in Claude Code
3. Ask for the analysis you want

### Quick Start Examples

```
Analyze all meetings in this folder and tell me when I avoided conflict.
```

```
Look at my meetings from the past month and identify my communication patterns.
```

```
Compare my facilitation style between these two meeting folders.
```

### Advanced Analysis

```
Analyze all transcripts in this folder and:
1. Identify when I interrupted others
2. Calculate my speaking ratio
3. Find moments I avoided giving direct feedback
4. Track my use of filler words
5. Show examples of good active listening
```

## Instructions

When a user requests meeting analysis:

1. **Discover Available Data**
   - Scan the folder for transcript files (.txt, .md, .vtt, .srt, .docx)
   - Check if files contain speaker labels and timestamps
   - Confirm the date range of meetings
   - Identify the user's name/identifier in transcripts

2. **Clarify Analysis Goals**
   
   If not specified, ask what they want to learn:
   - Specific behaviors (conflict avoidance, interruptions, filler words)
   - Communication effectiveness (clarity, directness, listening)
   - Meeting facilitation skills
   - Speaking patterns and ratios
   - Growth areas for improvement
   
3. **Analyze Patterns**

   For each requested insight:
   
   **Conflict Avoidance**:
   - Look for hedging language ("maybe", "kind of", "I think")
   - Indirect phrasing instead of direct requests
   - Changing subject when tension arises
   - Agreeing without commitment ("yeah, but...")
   - Not addressing obvious problems
   
   **Speaking Ratios**:
   - Calculate percentage of meeting spent speaking
   - Count interruptions (by and of the user)
   - Measure average speaking turn length
   - Track question vs. statement ratios
   
   **Filler Words**:
   - Count "um", "uh", "like", "you know", "actually", etc.
   - Note frequency per minute or per speaking turn
   - Identify situations where they increase (nervous, uncertain)
   
   **Active Listening**:
   - Questions that reference others' previous points
   - Paraphrasing or summarizing others' ideas
   - Building on others' contributions
   - Asking clarifying questions
   
   **Leadership & Facilitation**:
   - Decision-making approach (directive vs. collaborative)
   - How disagreements are handled
   - Inclusion of quieter participants
   - Time management and agenda control
   - Follow-up and action item clarity

4. **Provide Specific Examples**

   For each pattern found, include:
   
   ```markdown
   ### [Pattern Name]
   
   **Finding**: [One-sentence summary of the pattern]
   
   **Frequency**: [X times across Y meetings]
   
   **Examples**:
   
   1. **[Meeting Name/Date]** - [Timestamp]
      
      **What Happened**:
      > [Actual quote from transcript]
      
      **Why This Matters**:
      [Explanation of the impact or missed opportunity]
      
      **Better Approach**:
      [Specific alternative phrasing or behavior]
   
   [Repeat for 2-3 strongest examples]
   ```

5. **Synthesize Insights**

   After analyzing all patterns, provide:
   
   ```markdown
   # Meeting Insights Summary
   
   **Analysis Period**: [Date range]
   **Meetings Analyzed**: [X meetings]
   **Total Duration**: [X hours]
   
   ## Key Patterns Identified
   
   ### 1. [Primary Pattern]
   - **Observed**: [What you saw]
   - **Impact**: [Why it matters]
   - **Recommendation**: [How to improve]
   
   ### 2. [Second Pattern]
   [Same structure]
   
   ## Communication 
