---
name: monetization
description: Estrategia e implementacao de monetizacao para produtos digitais - Stripe, subscriptions, pricing experiments, freemium, upgrade flows, churn prevention, revenue optimization e modelos de negocio SaaS
category: Creative & Media
source: antigravity
tags: [python, api, claude, ai, gpt, template, design, stripe, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/monetization
---


# MONETIZATION - Do Produto ao Revenue

## Overview

Estrategia e implementacao de monetizacao para produtos digitais - Stripe, subscriptions, pricing experiments, freemium, upgrade flows, churn prevention, revenue optimization e modelos de negocio SaaS. Ativar para: integrar Stripe, criar planos de assinatura, pricing strategy, upgrade/downgrade, webhook de pagamento, trial gratuito, churn, LTV/CAC, unit economics, modelo de negocio.

## When to Use This Skill

- When you need specialized assistance with this domain

## Do Not Use This Skill When

- The task is unrelated to monetization
- A simpler, more specific tool can handle the request
- The user needs general-purpose assistance without domain expertise

## How It Works

> Price is what you pay. Value is what you get. - Warren Buffett
> A monetizacao perfeita captura valor proporcional ao valor entregue.

---

## A Regra De Ouro

Usuarios pagam quando:
1. O produto resolve um problema real (need)
2. A solucao e melhor que alternativas (differentiation)
3. O preco e percebido como justo (value perception)
4. O momento de cobranca e natural (timing)

## Erros Classicos

- Cobranca antes de mostrar valor (kill activation)
- Preco muito baixo (sinaliza baixa qualidade)
- Planos demais (paralisia de escolha)
- Trial sem carta de credito (baixa conversao)
- Churn invisivel (sem alertas de cancelamento iminente)

---

## Setup Inicial

```bash
pip install stripe

## Ou

npm install stripe
```

```python

## Config.Py

import stripe
import os

stripe.api_key = os.environ["STRIPE_SECRET_KEY"]
STRIPE_WEBHOOK_SECRET = os.environ["STRIPE_WEBHOOK_SECRET"]

PLANS = {
    "free": None,
    "pro": os.environ["STRIPE_PRICE_PRO"],
    "business": os.environ["STRIPE_PRICE_BIZ"],
}
```

## Criar Customer E Subscription

```python
def create_customer(email: str, name: str, user_id: str) -> str:
    customer = stripe.Customer.create(
        email=email,
        name=name,
        metadata={"user_id": user_id}
    )
    return customer.id

def create_subscription(customer_id: str, price_id: str, trial_days: int = 14):
    subscription = stripe.Subscription.create(
        customer=customer_id,
        items=[{"price": price_id}],
        trial_period_days=trial_days,
        payment_behavior="default_incomplete",
        expand=["latest_invoice.payment_intent"],
    )
    return {
        "subscription_id": subscription.id,
        "client_secret": subscription.latest_invoice.payment_intent.client_secret,
        "status": subscription.status
    }
```

## Checkout Session (Recomendado Para Conversao)

```python
def create_checkout_session(
    customer_id: str,
    price_id: str,
    success_url: str,
    cancel_url: str,
    trial_days: int = 14
) -> str:
    session = stripe.checkout.Session.create(
        customer=customer_id,
        mode="subscription",
        line_items=[{"price": price_id, "quantity": 1}],
        subscription_data={"trial_period_days": trial_days},
        success_url=success_url + "?session_id={CHECKOUT_SESSION_ID}",
        cancel_url=cancel_url,
        allow_promotion_codes=True,
    )
    return session.url
```

## Customer Portal (Self-Service)

```python
def create_portal_session(customer_id: str, return_url: str) -> str:
    session = stripe.billing_portal.Session.create(
        customer=customer_id,
        return_url=return_url,
    )
    return session.url
```

## Webhook - Processar Eventos

```python
from fastapi import Request, HTTPException
import stripe

async def stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid signature")

    handlers = {
        "customer.subscription.created": handle_subscription_created,
        "customer.subscription.updated": handle_subscription_updated,
        "customer.subscription.deleted": handle_subscription_deleted,
        "invoice.payment_succeeded": handle_payment_succeeded,
        "invoice.payment_failed": handle_payment_failed,
        "customer.subscription.trial_will_end": handle_trial_ending,
    }

    handler = handlers.get(event["type"])
    if handler:
        await handler(event["data"]["object"])

    return {"status": "ok"}
```

## Verificar Status Da Subscription

```python
def get_subscription_status(customer_id: str) -> dict:
    subscriptions = stripe.Subscription.list(
        customer=customer_id,
        status="all",
        limit=1
    )
    if not subscriptions.data:
        return {"tier": "free", "status": "none"}

    sub = subscriptions.data[0]
    return {
        "tier": get_tier_from_price(sub.items.data[0].price.id),
        "status": sub.status,
        "trial_en
