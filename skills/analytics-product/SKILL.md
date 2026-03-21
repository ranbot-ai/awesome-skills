---
name: analytics-product
description: Analytics de produto — PostHog, Mixpanel, eventos, funnels, cohorts, retencao, north star metric, OKRs e dashboards de produto. 
category: Business & Marketing
source: antigravity
tags: [python, api, claude, ai, template, design]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/analytics-product
---


# ANALYTICS-PRODUCT — Decida com Dados

## Overview

Analytics de produto — PostHog, Mixpanel, eventos, funnels, cohorts, retencao, north star metric, OKRs e dashboards de produto. Ativar para: configurar tracking de eventos, criar funil de conversao, analise de cohort, retencao, DAU/MAU, feature flags, A/B testing, north star metric, OKRs, dashboard de produto.

## When to Use This Skill

- When you need specialized assistance with this domain

## Do Not Use This Skill When

- The task is unrelated to analytics product
- A simpler, more specific tool can handle the request
- The user needs general-purpose assistance without domain expertise

## How It Works

```
[objeto]_[verbo_passado]

Correto:   user_signed_up, conversation_started, upgrade_completed
Errado:    signup, click, conversion
```

## Analytics-Product — Decida Com Dados

> "In God we trust. All others must bring data." — W. Edwards Deming

---

## Eventos Essenciais Da Auri

```python
AURI_EVENTS = {
    # Aquisicao
    "user_signed_up":        {"props": ["source", "medium", "campaign"]},
    "onboarding_started":    {"props": ["step_count"]},
    "onboarding_completed":  {"props": ["time_to_complete", "steps_skipped"]},

    # Ativacao
    "first_conversation":    {"props": ["intent", "response_time"]},
    "aha_moment_reached":    {"props": ["trigger", "session_number"]},
    "feature_discovered":    {"props": ["feature_name", "discovery_method"]},

    # Retencao
    "conversation_started":  {"props": ["intent", "user_tier", "device"]},
    "conversation_completed":{"props": ["messages_count", "duration", "rating"]},
    "session_started":       {"props": ["days_since_last", "platform"]},

    # Receita
    "upgrade_viewed":        {"props": ["trigger", "current_tier"]},
    "upgrade_started":       {"props": ["target_tier", "trigger"]},
    "upgrade_completed":     {"props": ["tier", "plan", "revenue"]},
    "subscription_canceled": {"props": ["reason", "tier", "tenure_days"]},
    "payment_failed":        {"props": ["attempt_count", "error_code"]},
}
```

## Implementacao Posthog (Python)

```python
from posthog import Posthog
import os

posthog = Posthog(
    project_api_key=os.environ["POSTHOG_API_KEY"],
    host=os.environ.get("POSTHOG_HOST", "https://app.posthog.com")
)

def track(user_id: str, event: str, properties: dict = None):
    posthog.capture(
        distinct_id=user_id,
        event=event,
        properties=properties or {}
    )

def identify(user_id: str, traits: dict):
    posthog.identify(
        distinct_id=user_id,
        properties=traits
    )

## Uso:

track("user_123", "conversation_started", {
    "intent": "business_advice",
    "device": "alexa",
    "user_tier": "pro"
})
```

---

## Funil De Ativacao Auri

```
Visita landing page          (100%)
    | [meta: 40%]
Clicou "Experimentar"         (40%)
    | [meta: 70%]
Completou cadastro            (28%)
    | [meta: 60%]
Fez primeira conversa         (17%)  <- AHA MOMENT
    | [meta: 50%]
Voltou no dia seguinte        (8.5%)
    | [meta: 40%]
Usou 3+ dias na semana        (3.4%)
    | [meta: 20%]
Converteu para Pro            (0.7%)
```

## Otimizando O Funil

```
Para cada drop-off > benchmark:
1. Identificar: onde exatamente o usuario sai?
2. Entender: por que? (session recordings, surveys)
3. Hipotese: qual mudanca poderia melhorar?
4. Testar: A/B test com amostra estatisticamente significante
5. Medir: 2 semanas minimo, p-value < 0.05
6. Aprender: mesmo se falhar, entende-se o usuario melhor
```

---

## Analise De Cohort (Retencao Semanal)

```python
def calculate_cohort_retention(events_df):
    """
    events_df: DataFrame com colunas [user_id, event_date, event_name]
    Retorna: matriz de retencao [cohort_week x week_number]
    """
    import pandas as pd

    first_session = events_df[events_df.event_name == "session_started"] \
        .groupby("user_id")["event_date"].min() \
        .dt.to_period("W")

    sessions = events_df[events_df.event_name == "session_started"].copy()
    sessions["cohort"] = sessions["user_id"].map(first_session)
    sessions["weeks_since"] = (
        sessions["event_date"].dt.to_period("W") - sessions["cohort"]
    ).apply(lambda x: x.n)

    cohort_data = sessions.groupby(["cohort", "weeks_since"])["user_id"].nunique()
    cohort_sizes = cohort_data.unstack().iloc[:, 0]
    retention = cohort_data.unstack().divide(cohort_sizes, axis=0) * 100

    return retention
```

## Benchmarks De Retencao (Assistentes De Voz)

| Semana | Pessimo | Ok | Bom | Excelente |
|--------|---------|-----|-----|-----------|
| W1 | <20% | 20-35% | 35-50% | >50% |
| W4 | <10% | 10-20% | 20-30% | >30% |
| W8 | <5% | 5-12% | 12-20% | >20% |

---

## Definindo A North Star Da Auri

```
Framework:
1. O que cria valor real para o usuario? -> Conversas que geram insight/acao
2. O que prediz crescimento de longo prazo? -> Usuarios com 3+ conv/semana
3. Como medir? -> "Weekly Active Conversationalists" (WAC)

North Star: WAC (Weekly Active Conv
