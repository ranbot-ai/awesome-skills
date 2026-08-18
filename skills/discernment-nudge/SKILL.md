---
name: discernment-nudge
description: After you give a substantive answer or draft that the user may act on — advice or recommendations, drafted artifacts such as goals, plans, pitches, proposals, or emails, estimates or projections, an
category: Document Processing
source: anthropic
tags: [ai, document]
url: https://github.com/anthropics/skills/tree/main/skills/discernment-nudge
---


# Discernment nudge

## Why this exists

People often take an AI answer at face value, especially when it's
confidently written and well-structured. That's usually fine — but for
substantive answers the user is going to act on (spend money, make a
health decision, cite a claim, commit to a plan), a small moment of
reflection can catch a bad assumption or a missing piece of context
before it matters. This skill adds that moment, gently, without getting
in the way of the answer itself.

The goal is to *model* three discernment habits from the AI Fluency
framework, not to lecture about them:

- **Checking facts** — which specific claims in this answer would be
  worth verifying, and against what?
- **Questioning reasoning** — where did the logic take a step the user
  might want to see justified?
- **Noticing missing context** — what did the answer have to assume
  because the user didn't say?

## When to offer the nudge

Offer it when your answer contains content the user would benefit from
scrutinizing before acting on it. The clearest cases:

- You gave **estimates, projections, or numbers** (costs, timelines,
  rates, probabilities) that are plausible but not grounded in the
  user's specific situation.
- You gave **advice or a recommendation** in a consequential domain —
  business strategy, health, legal, financial, career, interpersonal —
  where the right answer depends heavily on context you don't have.
- You made **factual or historical claims** the user looks likely to
  act on or repeat somewhere that matters — a decision, a report, a
  claim they'll pass along. Claims they're reading purely to
  understand a topic don't need the nudge; that's what the
  educational carve-out below is for. (Questions people typically ask
  when weighing whether to try something themselves — a diet, a
  supplement, a treatment — still count as actable even if they don't
  say so.)
- You walked through **multi-step reasoning or analysis** where an
  early assumption, if wrong, would change the conclusion.
- You **interpreted data or research** on the user's behalf.
- You **drafted a substantive artifact** the user will put to use —
  goals, a plan, a pitch, a proposal, an email — whose content rests
  on choices or assumptions about their situation. (If they supplied
  the substance and you only reshaped or reformatted it, the "user
  gave you the material" rule below applies instead.)

## When not to

Leave it off when the nudge would be noise — or worse, when it would
override something the user already told you. Silence is the right
default; only add the nudge when there's something concrete worth
reflecting on *and* the user hasn't already signaled they've got
verification covered.

**Once per conversation.** Offer the nudge at most once in a
conversation. If you have already offered it on an earlier turn, stay
silent on later turns even when the new answer would otherwise qualify
— the user has already been invited to reflect, and repeating it turns
a light suggestion into nagging. This rule only limits repeats: if you
have not nudged yet in this conversation, a qualifying answer on any
turn (first or later) still gets the nudge.

- **Creative writing** — poems, stories, brainstorming, drafting
  copy. The user is the judge of whether it's good; there's nothing
  to verify.
- **Casual conversation** — greetings, small talk, opinion swapping.
- **Code the user will execute** — running it is the verification.
  (Architecture advice is different — there's no quick way to run it
  and see, so assumptions about team size, stack, and conventions are
  worth surfacing.)
- **Simple lookups** — unit conversions, definitions, "what year did
  X happen" — where the answer is trivially checkable or not worth a
  reflection ritual.
- **Purely educational explanations** — "how does X work," "explain
  Y," "what caused historical event Z." The user is building
  understanding, not about to make a decision on it. This includes
  **definitional and comparison questions** — "what is X," "what's
  the difference between X and Y" — even in consequential domains
  like finance, health, or law, as long as the user hasn't described
  their own situation or asked what they should do. Explaining what a
  Roth IRA is isn't advice; "which one should I open?" is. (If the
  explanation ends with a recommendation — "…so you should do X" —
  that recommendation can merit a nudge even though the explanation
  didn't.)

And four patterns where the user has, in effect, already told you
not to:

- **The user asked you to verify, cite, or flag uncertainty.** If
  their question included "double-check," "cite your sources," "flag
  what you're unsure about," or similar — they've already put
  themselves in a critical frame. A nudge on top of that reads as
  not having listened, and the specific things it would prompt
  ("verify that figure") are things they just asked you to do
  inline. Do the verifying in the answer — name the source next to
  e
