---
name: feature-flags
description: Implement feature flags for progressive feature rollout using LaunchDarkly, Unleash, or custom solutions. 
category: AI & Agents
source: antigravity
tags: [python, javascript, react, node, api, ai, agent, template, image, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/feature-flags
---


# Feature Flags

Control feature releases and enable progressive rollout with feature flag systems.

## Prerequisites

- Application code access
- Feature flag service or self-hosted solution
- Basic understanding of deployment patterns

## Feature Flag Types

| Type | Purpose | Example |
|------|---------|---------|
| Release | Control feature visibility | New checkout flow |
| Experiment | A/B testing | Button color test |
| Ops | Runtime configuration | Rate limiting |
| Permission | User access control | Premium features |
| Kill Switch | Emergency disable | Third-party integration |

## LaunchDarkly

### SDK Setup (Node.js)

```javascript
const LaunchDarkly = require('launchdarkly-node-server-sdk');

const client = LaunchDarkly.init(process.env.LAUNCHDARKLY_SDK_KEY);

await client.waitForInitialization();

// Evaluate flag
const user = {
  key: 'user-123',
  email: 'user@example.com',
  custom: {
    plan: 'premium',
    company: 'acme'
  }
};

const showNewFeature = await client.variation('new-checkout', user, false);

if (showNewFeature) {
  // New feature code
} else {
  // Existing code
}
```

### React SDK

```javascript
import { withLDProvider, useFlags, useLDClient } from 'launchdarkly-react-client-sdk';

// Provider setup
export default withLDProvider({
  clientSideID: 'your-client-side-id',
  user: {
    key: 'user-123',
    email: 'user@example.com'
  }
})(App);

// Using flags in component
function FeatureComponent() {
  const { newCheckout, experimentVariant } = useFlags();
  const ldClient = useLDClient();

  // Track events
  const handleClick = () => {
    ldClient.track('checkout-started');
  };

  if (newCheckout) {
    return <NewCheckout onClick={handleClick} />;
  }
  return <OldCheckout onClick={handleClick} />;
}
```

### Targeting Rules

```yaml
# LaunchDarkly targeting configuration
flag: new-checkout
targeting:
  # Individual users
  targets:
    - variation: true
      values: ['user-123', 'user-456']
  
  # Rules
  rules:
    # Beta users
    - variation: true
      clauses:
        - attribute: email
          op: endsWith
          values: ['@company.com']
    
    # Premium plan
    - variation: true
      clauses:
        - attribute: plan
          op: in
          values: ['premium', 'enterprise']
    
    # Percentage rollout
    - variation: true
      rollout:
        variations:
          - variation: true
            weight: 20000  # 20%
          - variation: false
            weight: 80000  # 80%
  
  # Default
  fallthrough:
    variation: false
```

## Unleash

### Server Setup

```yaml
# docker-compose.yml
version: '3.8'

services:
  unleash:
    image: unleashorg/unleash-server:latest
    ports:
      - "4242:4242"
    environment:
      - DATABASE_URL=postgres://postgres:password@db/unleash
      - DATABASE_SSL=false
    depends_on:
      - db

  db:
    image: postgres:15
    environment:
      - POSTGRES_PASSWORD=password
      - POSTGRES_DB=unleash
    volumes:
      - postgres-data:/var/lib/postgresql/data

volumes:
  postgres-data:
```

### SDK Setup (Node.js)

```javascript
const { initialize } = require('unleash-client');

const unleash = initialize({
  url: 'http://localhost:4242/api',
  appName: 'my-app',
  customHeaders: {
    Authorization: 'your-api-token'
  }
});

unleash.on('ready', () => {
  // Check feature
  const isEnabled = unleash.isEnabled('new-checkout');
  
  // With context
  const context = {
    userId: 'user-123',
    properties: {
      plan: 'premium'
    }
  };
  
  const isEnabledForUser = unleash.isEnabled('new-checkout', context);
  
  // Get variant
  const variant = unleash.getVariant('experiment-flag', context);
  console.log(variant.name); // 'control' or 'treatment'
});
```

### Activation Strategies

```yaml
# Standard strategies
strategies:
  - name: default
    # On/off for everyone
    
  - name: userWithId
    parameters:
      userIds: 'user-1,user-2,user-3'
    
  - name: gradualRolloutUserId
    parameters:
      percentage: 25
      groupId: 'new-feature'
    
  - name: gradualRolloutRandom
    parameters:
      percentage: 50
    
  - name: flexibleRollout
    parameters:
      rollout: 30
      stickiness: userId
      groupId: 'checkout-exp'
```

## Custom Implementation

### Database-Backed Flags

```python
# models.py
from django.db import models

class FeatureFlag(models.Model):
    name = models.CharField(max_length=100, unique=True)
    enabled = models.BooleanField(default=False)
    rollout_percentage = models.IntegerField(default=0)
    allowed_users = models.JSONField(default=list)
    rules = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

# service.py
import hashlib

class FeatureFlagService:
    def __init__(self):
        self._cache = {}
    
    def is_enabled(self, flag_name, user_id=None, context=None):
        flag = self._get_flag(flag_name)
        
        if not flag or not flag.enabled:
      
