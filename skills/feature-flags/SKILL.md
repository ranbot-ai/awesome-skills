---
name: feature-flags
description: Implement feature flags for progressive feature rollout using LaunchDarkly, Unleash, or custom solutions. 
category: AI & Agents
source: antigravity
tags: [python, javascript, react, node, api, ai, agent, template, presentation, image]
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
| Entitlement presentation | Display already-authorized features | Premium UI visibility |
| Kill Switch | Emergency disable | Third-party integration |

Feature flags do not replace server-side authorization. Never trust client evaluation or a client-supplied identity for access to protected data or paid operations. Keep server SDK keys out of browsers; minimize personal attributes sent to providers. SDK snippets are historical sketches: pin compatible package versions and verify current schemas. Custom examples omit storage/rule helpers and production error/cache handling.

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
    ldClient?.track('checkout-started');
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

### Local Development Server Setup

Disposable local demonstration only: replace the image tag with a reviewed digest and supply a unique local database password through ignored environment configuration. Do not expose this service publicly or reuse these settings in production.

```yaml
# docker-compose.yml
version: '3.8'

services:
  unleash:
    image: unleashorg/unleash-server:<reviewed-version-or-digest>
    ports:
      - "127.0.0.1:4242:4242"
    environment:
      - DATABASE_URL=postgres://postgres:${UNLEASH_DB_PASSWORD:?set local password}@db/unleash
      - DATABASE_SSL=false
    depends_on:
      - db

  db:
    image: postgres:15
    environment:
      - POSTGRES_PASSWORD=${UNLEASH_DB_PASSWORD:?set local password}
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
      st
