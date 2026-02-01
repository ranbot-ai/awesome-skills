---
name: paypal-integration
description: Integrate PayPal payment processing with support for express checkout, subscriptions, and refund management. Use when implementing PayPal payments, processing online transactions, or building e-commer
category: Development & Code Tools
source: antigravity
tags: [python, javascript, api, ai, workflow]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/paypal-integration
---


# PayPal Integration

Master PayPal payment integration including Express Checkout, IPN handling, recurring billing, and refund workflows.

## Do not use this skill when

- The task is unrelated to paypal integration
- You need a different domain or tool outside this scope

## Instructions

- Clarify goals, constraints, and required inputs.
- Apply relevant best practices and validate outcomes.
- Provide actionable steps and verification.
- If detailed examples are required, open `resources/implementation-playbook.md`.

## Use this skill when

- Integrating PayPal as a payment option
- Implementing express checkout flows
- Setting up recurring billing with PayPal
- Processing refunds and payment disputes
- Handling PayPal webhooks (IPN)
- Supporting international payments
- Implementing PayPal subscriptions

## Core Concepts

### 1. Payment Products
**PayPal Checkout**
- One-time payments
- Express checkout experience
- Guest and PayPal account payments

**PayPal Subscriptions**
- Recurring billing
- Subscription plans
- Automatic renewals

**PayPal Payouts**
- Send money to multiple recipients
- Marketplace and platform payments

### 2. Integration Methods
**Client-Side (JavaScript SDK)**
- Smart Payment Buttons
- Hosted payment flow
- Minimal backend code

**Server-Side (REST API)**
- Full control over payment flow
- Custom checkout UI
- Advanced features

### 3. IPN (Instant Payment Notification)
- Webhook-like payment notifications
- Asynchronous payment updates
- Verification required

## Quick Start

```javascript
// Frontend - PayPal Smart Buttons
<div id="paypal-button-container"></div>

<script src="https://www.paypal.com/sdk/js?client-id=YOUR_CLIENT_ID&currency=USD"></script>
<script>
  paypal.Buttons({
    createOrder: function(data, actions) {
      return actions.order.create({
        purchase_units: [{
          amount: {
            value: '25.00'
          }
        }]
      });
    },
    onApprove: function(data, actions) {
      return actions.order.capture().then(function(details) {
        // Payment successful
        console.log('Transaction completed by ' + details.payer.name.given_name);

        // Send to backend for verification
        fetch('/api/paypal/capture', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({orderID: data.orderID})
        });
      });
    }
  }).render('#paypal-button-container');
</script>
```

```python
# Backend - Verify and capture order
from paypalrestsdk import Payment
import paypalrestsdk

paypalrestsdk.configure({
    "mode": "sandbox",  # or "live"
    "client_id": "YOUR_CLIENT_ID",
    "client_secret": "YOUR_CLIENT_SECRET"
})

def capture_paypal_order(order_id):
    """Capture a PayPal order."""
    payment = Payment.find(order_id)

    if payment.execute({"payer_id": payment.payer.payer_info.payer_id}):
        # Payment successful
        return {
            'status': 'success',
            'transaction_id': payment.id,
            'amount': payment.transactions[0].amount.total
        }
    else:
        # Payment failed
        return {
            'status': 'failed',
            'error': payment.error
        }
```

## Express Checkout Implementation

### Server-Side Order Creation
```python
import requests
import json

class PayPalClient:
    def __init__(self, client_id, client_secret, mode='sandbox'):
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = 'https://api-m.sandbox.paypal.com' if mode == 'sandbox' else 'https://api-m.paypal.com'
        self.access_token = self.get_access_token()

    def get_access_token(self):
        """Get OAuth access token."""
        url = f"{self.base_url}/v1/oauth2/token"
        headers = {"Accept": "application/json", "Accept-Language": "en_US"}

        response = requests.post(
            url,
            headers=headers,
            data={"grant_type": "client_credentials"},
            auth=(self.client_id, self.client_secret)
        )

        return response.json()['access_token']

    def create_order(self, amount, currency='USD'):
        """Create a PayPal order."""
        url = f"{self.base_url}/v2/checkout/orders"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.access_token}"
        }

        payload = {
            "intent": "CAPTURE",
            "purchase_units": [{
                "amount": {
                    "currency_code": currency,
                    "value": str(amount)
                }
            }]
        }

        response = requests.post(url, headers=headers, json=payload)
        return response.json()

    def capture_order(self, order_id):
        """Capture payment for an order."""
        url = f"{self.base_url}/v2/checkout/orders/{order_id}/capture"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.access_token}"
   
