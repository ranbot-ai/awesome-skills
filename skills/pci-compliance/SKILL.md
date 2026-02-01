---
name: pci-compliance
description: Implement PCI DSS compliance requirements for secure handling of payment card data and payment systems. Use when securing payment processing, achieving PCI compliance, or implementing payment card sec
category: Security & Systems
source: antigravity
tags: [python, javascript, api, ai, document, security, vulnerability, stripe, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/pci-compliance
---


# PCI Compliance

Master PCI DSS (Payment Card Industry Data Security Standard) compliance for secure payment processing and handling of cardholder data.

## Do not use this skill when

- The task is unrelated to pci compliance
- You need a different domain or tool outside this scope

## Instructions

- Clarify goals, constraints, and required inputs.
- Apply relevant best practices and validate outcomes.
- Provide actionable steps and verification.
- If detailed examples are required, open `resources/implementation-playbook.md`.

## Use this skill when

- Building payment processing systems
- Handling credit card information
- Implementing secure payment flows
- Conducting PCI compliance audits
- Reducing PCI compliance scope
- Implementing tokenization and encryption
- Preparing for PCI DSS assessments

## PCI DSS Requirements (12 Core Requirements)

### Build and Maintain Secure Network
1. Install and maintain firewall configuration
2. Don't use vendor-supplied defaults for passwords

### Protect Cardholder Data
3. Protect stored cardholder data
4. Encrypt transmission of cardholder data across public networks

### Maintain Vulnerability Management
5. Protect systems against malware
6. Develop and maintain secure systems and applications

### Implement Strong Access Control
7. Restrict access to cardholder data by business need-to-know
8. Identify and authenticate access to system components
9. Restrict physical access to cardholder data

### Monitor and Test Networks
10. Track and monitor all access to network resources and cardholder data
11. Regularly test security systems and processes

### Maintain Information Security Policy
12. Maintain a policy that addresses information security

## Compliance Levels

**Level 1**: > 6 million transactions/year (annual ROC required)
**Level 2**: 1-6 million transactions/year (annual SAQ)
**Level 3**: 20,000-1 million e-commerce transactions/year
**Level 4**: < 20,000 e-commerce or < 1 million total transactions

## Data Minimization (Never Store)

```python
# NEVER STORE THESE
PROHIBITED_DATA = {
    'full_track_data': 'Magnetic stripe data',
    'cvv': 'Card verification code/value',
    'pin': 'PIN or PIN block'
}

# CAN STORE (if encrypted)
ALLOWED_DATA = {
    'pan': 'Primary Account Number (card number)',
    'cardholder_name': 'Name on card',
    'expiration_date': 'Card expiration',
    'service_code': 'Service code'
}

class PaymentData:
    """Safe payment data handling."""

    def __init__(self):
        self.prohibited_fields = ['cvv', 'cvv2', 'cvc', 'pin']

    def sanitize_log(self, data):
        """Remove sensitive data from logs."""
        sanitized = data.copy()

        # Mask PAN
        if 'card_number' in sanitized:
            card = sanitized['card_number']
            sanitized['card_number'] = f"{card[:6]}{'*' * (len(card) - 10)}{card[-4:]}"

        # Remove prohibited data
        for field in self.prohibited_fields:
            sanitized.pop(field, None)

        return sanitized

    def validate_no_prohibited_storage(self, data):
        """Ensure no prohibited data is being stored."""
        for field in self.prohibited_fields:
            if field in data:
                raise SecurityError(f"Attempting to store prohibited field: {field}")
```

## Tokenization

### Using Payment Processor Tokens
```python
import stripe

class TokenizedPayment:
    """Handle payments using tokens (no card data on server)."""

    @staticmethod
    def create_payment_method_token(card_details):
        """Create token from card details (client-side only)."""
        # THIS SHOULD ONLY BE DONE CLIENT-SIDE WITH STRIPE.JS
        # NEVER send card details to your server

        """
        // Frontend JavaScript
        const stripe = Stripe('pk_...');

        const {token, error} = await stripe.createToken({
            card: {
                number: '4242424242424242',
                exp_month: 12,
                exp_year: 2024,
                cvc: '123'
            }
        });

        // Send token.id to server (NOT card details)
        """
        pass

    @staticmethod
    def charge_with_token(token_id, amount):
        """Charge using token (server-side)."""
        # Your server only sees the token, never the card number
        stripe.api_key = "sk_..."

        charge = stripe.Charge.create(
            amount=amount,
            currency="usd",
            source=token_id,  # Token instead of card details
            description="Payment"
        )

        return charge

    @staticmethod
    def store_payment_method(customer_id, payment_method_token):
        """Store payment method as token for future use."""
        stripe.Customer.modify(
            customer_id,
            source=payment_method_token
        )

        # Store only customer_id and payment_method_id in your database
        # NEVER store actual card details
        return {
            'customer_id': customer_id,
            'has_payment_method': True
  
