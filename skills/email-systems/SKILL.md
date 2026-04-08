---
name: email-systems
description: Email has the highest ROI of any marketing channel. $36 for every $1 spent. Yet most startups treat it as an afterthought - bulk blasts, no personalization, landing in spam folders. 
category: Creative & Media
source: antigravity
tags: [typescript, react, api, ai, automation, workflow, template, design, image, aws]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/email-systems
---


# Email Systems

Email has the highest ROI of any marketing channel. $36 for every $1 spent.
Yet most startups treat it as an afterthought - bulk blasts, no personalization,
landing in spam folders.

This skill covers transactional email that works, marketing automation that
converts, deliverability that reaches inboxes, and the infrastructure decisions
that scale.

## Principles

- Transactional vs Marketing separation | Description: Transactional emails (password reset, receipts) need 100% delivery.
Marketing emails (newsletters, promos) have lower priority. Use separate
IP addresses and providers to protect transactional deliverability. | Examples: Good: Password resets via Postmark, marketing via ConvertKit | Bad: All emails through one SendGrid account
- Permission is everything | Description: Only email people who asked to hear from you. Double opt-in for marketing.
Easy unsubscribe. Clean your list ruthlessly. Bad lists destroy deliverability. | Examples: Good: Confirmed subscription + one-click unsubscribe | Bad: Scraped email list, hidden unsubscribe, bought contacts
- Deliverability is infrastructure | Description: SPF, DKIM, DMARC are not optional. Warm up new IPs. Monitor bounce rates.
Deliverability is earned through technical setup and good behavior. | Examples: Good: All DNS records configured, dedicated IP warmed for 4 weeks | Bad: Using free tier shared IP, no authentication records
- One email, one goal | Description: Each email should have exactly one purpose and one CTA. Multiple asks
means nothing gets clicked. Clear single action. | Examples: Good: "Click here to verify your email" (one button) | Bad: "Verify email, check out our blog, follow us on Twitter, refer a friend..."
- Timing and frequency matter | Description: Wrong time = low open rates. Too frequent = unsubscribes. Let users
set preferences. Test send times. Respect inbox fatigue. | Examples: Good: Weekly digest on Tuesday 10am user's timezone, preference center | Bad: Daily emails at random times, no way to reduce frequency

## Patterns

### Transactional Email Queue

Queue all transactional emails with retry logic and monitoring

**When to use**: Sending any critical email (password reset, receipts, confirmations)

// Don't block request on email send
await queue.add('email', {
  template: 'password-reset',
  to: user.email,
  data: { resetToken, expiresAt }
}, {
  attempts: 3,
  backoff: { type: 'exponential', delay: 2000 }
});

### Email Event Tracking

Track delivery, opens, clicks, bounces, and complaints

**When to use**: Any email campaign or transactional flow

# Track lifecycle:
- Queued: Email entered system
- Sent: Handed to provider
- Delivered: Reached inbox
- Opened: Recipient viewed
- Clicked: Recipient engaged
- Bounced: Permanent failure
- Complained: Marked as spam

### Template Versioning

Version email templates for rollback and A/B testing

**When to use**: Changing production email templates

templates/
  password-reset/
    v1.tsx (current)
    v2.tsx (testing 10%)
    v1-deprecated.tsx (archived)

# Deploy new version gradually
# Monitor metrics before full rollout

### Bounce Handling State Machine

Automatically handle bounces to protect sender reputation

**When to use**: Processing bounce and complaint webhooks

switch (bounceType) {
  case 'hard':
    await markEmailInvalid(email);
    break;
  case 'soft':
    await incrementBounceCount(email);
    if (count >= 3) await markEmailInvalid(email);
    break;
  case 'complaint':
    await unsubscribeImmediately(email);
    break;
}

### React Email Components

Build emails with reusable React components

**When to use**: Creating email templates

import { Button, Html } from '@react-email/components';

export default function WelcomeEmail({ userName }) {
  return (
    <Html>
      <h1>Welcome {userName}!</h1>
      <Button href="https://app.com/start">
        Get Started
      </Button>
    </Html>
  );
}

### Preference Center

Let users control email frequency and topics

**When to use**: Building marketing or notification systems

Preferences:
☑ Product updates (weekly)
☑ New features (monthly)
☐ Marketing promotions
☑ Account notifications (always)

# Respect preferences in all sends
# Required for GDPR compliance

## Sharp Edges

### Missing SPF, DKIM, or DMARC records

Severity: CRITICAL

Situation: Sending emails without authentication. Emails going to spam folder.
Low open rates. No idea why. Turns out DNS records were never set up.

Symptoms:
- Emails going to spam
- Low deliverability rates
- mail-tester.com score below 8
- No DMARC reports received

Why this breaks:
Email authentication (SPF, DKIM, DMARC) tells receiving servers you're
legit. Without them, you look like a spammer. Modern email providers
increasingly require all three.

Recommended fix:

# Required DNS records:

## SPF (Sender Policy Framework)
TXT record: v=spf1 include:_spf.google.com include:sendgrid.net ~all

## DKIM (DomainKeys Identified Mail)
TXT record provide
