---
name: stripe-integration
description: Implement Stripe payment processing for robust, PCI-compliant payment flows including checkout, subscriptions, and webhooks. Use when integrating Stripe payments, building subscription systems, or imp
category: Development & Code Tools
source: antigravity
tags: [python, javascript, api, ai, template, document, image, security, stripe]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/stripe-integration
---


# Stripe Integration

Master Stripe payment processing integration for robust, PCI-compliant payment flows including checkout, subscriptions, webhooks, and refunds.

## Do not use this skill when

- The task is unrelated to stripe integration
- You need a different domain or tool outside this scope

## Instructions

- Clarify goals, constraints, and required inputs.
- Apply relevant best practices and validate outcomes.
- Provide actionable steps and verification.
- If detailed examples are required, open `resources/implementation-playbook.md`.

## Use this skill when

- Implementing payment processing in web/mobile applications
- Setting up subscription billing systems
- Handling one-time payments and recurring charges
- Processing refunds and disputes
- Managing customer payment methods
- Implementing SCA (Strong Customer Authentication) for European payments
- Building marketplace payment flows with Stripe Connect

## Core Concepts

### 1. Payment Flows
**Checkout Session (Hosted)**
- Stripe-hosted payment page
- Minimal PCI compliance burden
- Fastest implementation
- Supports one-time and recurring payments

**Payment Intents (Custom UI)**
- Full control over payment UI
- Requires Stripe.js for PCI compliance
- More complex implementation
- Better customization options

**Setup Intents (Save Payment Methods)**
- Collect payment method without charging
- Used for subscriptions and future payments
- Requires customer confirmation

### 2. Webhooks
**Critical Events:**
- `payment_intent.succeeded`: Payment completed
- `payment_intent.payment_failed`: Payment failed
- `customer.subscription.updated`: Subscription changed
- `customer.subscription.deleted`: Subscription canceled
- `charge.refunded`: Refund processed
- `invoice.payment_succeeded`: Subscription payment successful

### 3. Subscriptions
**Components:**
- **Product**: What you're selling
- **Price**: How much and how often
- **Subscription**: Customer's recurring payment
- **Invoice**: Generated for each billing cycle

### 4. Customer Management
- Create and manage customer records
- Store multiple payment methods
- Track customer metadata
- Manage billing details

## Quick Start

```python
import stripe

stripe.api_key = "sk_test_..."

# Create a checkout session
session = stripe.checkout.Session.create(
    payment_method_types=['card'],
    line_items=[{
        'price_data': {
            'currency': 'usd',
            'product_data': {
                'name': 'Premium Subscription',
            },
            'unit_amount': 2000,  # $20.00
            'recurring': {
                'interval': 'month',
            },
        },
        'quantity': 1,
    }],
    mode='subscription',
    success_url='https://yourdomain.com/success?session_id={CHECKOUT_SESSION_ID}',
    cancel_url='https://yourdomain.com/cancel',
)

# Redirect user to session.url
print(session.url)
```

## Payment Implementation Patterns

### Pattern 1: One-Time Payment (Hosted Checkout)
```python
def create_checkout_session(amount, currency='usd'):
    """Create a one-time payment checkout session."""
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': currency,
                    'product_data': {
                        'name': 'Purchase',
                        'images': ['https://example.com/product.jpg'],
                    },
                    'unit_amount': amount,  # Amount in cents
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url='https://yourdomain.com/success?session_id={CHECKOUT_SESSION_ID}',
            cancel_url='https://yourdomain.com/cancel',
            metadata={
                'order_id': 'order_123',
                'user_id': 'user_456'
            }
        )
        return session
    except stripe.error.StripeError as e:
        # Handle error
        print(f"Stripe error: {e.user_message}")
        raise
```

### Pattern 2: Custom Payment Intent Flow
```python
def create_payment_intent(amount, currency='usd', customer_id=None):
    """Create a payment intent for custom checkout UI."""
    intent = stripe.PaymentIntent.create(
        amount=amount,
        currency=currency,
        customer=customer_id,
        automatic_payment_methods={
            'enabled': True,
        },
        metadata={
            'integration_check': 'accept_a_payment'
        }
    )
    return intent.client_secret  # Send to frontend

# Frontend (JavaScript)
"""
const stripe = Stripe('pk_test_...');
const elements = stripe.elements();
const cardElement = elements.create('card');
cardElement.mount('#card-element');

const {error, paymentIntent} = await stripe.confirmCardPayment(
    clientSecret,
    {
        payment_method: {
            card: cardElement,
            billing_details: {
                name: 'Customer Name'
            }
        }
    }
);
