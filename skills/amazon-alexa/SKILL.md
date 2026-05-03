---
name: amazon-alexa
description: Integracao completa com Amazon Alexa para criar skills de voz inteligentes, transformar Alexa em assistente com Claude como cerebro (projeto Auri) e integrar com AWS ecosystem (Lambda, DynamoDB, Polly
category: Document Processing
source: antigravity
tags: [python, node, api, claude, ai, llm, template, document, presentation, aws]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/amazon-alexa
---


# AMAZON ALEXA — Voz Inteligente com Claude

## Overview

Integracao completa com Amazon Alexa para criar skills de voz inteligentes, transformar Alexa em assistente com Claude como cerebro (projeto Auri) e integrar com AWS ecosystem (Lambda, DynamoDB, Polly, Transcribe, Lex, Smart Home).

## When to Use This Skill

- When you need specialized assistance with this domain

## Do Not Use This Skill When

- The task is unrelated to amazon alexa
- A simpler, more specific tool can handle the request
- The user needs general-purpose assistance without domain expertise

## How It Works

> Voce e o especialista em Alexa e AWS Voice. Missao: transformar
> qualquer dispositivo Alexa em assistente ultra-inteligente usando
> Claude como LLM backend, com voz neural, memoria persistente e
> controle de Smart Home. Projeto-chave: AURI.

---

## 1. Visao Geral Do Ecossistema

```
[Alexa Device] → [Alexa Cloud] → [AWS Lambda] → [Claude API]
    Fala          Transcricao      Logica          Inteligencia
      ↑               ↑               ↑                ↑
   Usuario         Intent        Handler          Anthropic
                               + DynamoDB
                               + Polly TTS
                               + APL Visual
```

## Componentes Da Arquitetura Auri

| Componente | Servico AWS | Funcao |
|-----------|-------------|--------|
| Voz → Texto | Alexa ASR nativo | Reconhecimento de fala |
| NLU | ASK Interaction Model + Lex V2 | Extrair intent e slots |
| Backend | AWS Lambda (Python/Node.js) | Logica e orquestracao |
| LLM | Claude API (Anthropic) | Inteligencia e respostas |
| Persistencia | Amazon DynamoDB | Historico e preferencias |
| Texto → Voz | Amazon Polly (neural) | Fala natural da Auri |
| Interface Visual | APL (Alexa Presentation Language) | Telas em Echo Show |
| Smart Home | Alexa Smart Home API | Controle de dispositivos |
| Automacao | Alexa Routines API | Rotinas inteligentes |

---

### 2.1 Pre-Requisitos

```bash

## Ask Cli

npm install -g ask-cli
ask configure

## Aws Cli

pip install awscli
aws configure
```

## Criar Skill Com Template

ask new \
  --template hello-world \
  --skill-name auri \
  --language pt-BR

## └── .Ask/Ask-Resources.Json

```

## 2.3 Configurar Invocation Name

No arquivo `models/pt-BR.json`:
```json
{
  "interactionModel": {
    "languageModel": {
      "invocationName": "auri"
    }
  }
}
```

---

## 3.1 Intents Essenciais Para Auri

```json
{
  "interactionModel": {
    "languageModel": {
      "invocationName": "auri",
      "intents": [
        {"name": "AMAZON.HelpIntent"},
        {"name": "AMAZON.StopIntent"},
        {"name": "AMAZON.CancelIntent"},
        {"name": "AMAZON.FallbackIntent"},
        {
          "name": "ChatIntent",
          "slots": [{"name": "query", "type": "AMAZON.SearchQuery"}],
          "samples": [
            "{query}",
            "me ajuda com {query}",
            "quero saber sobre {query}",
            "o que voce sabe sobre {query}",
            "explique {query}",
            "pesquise {query}"
          ]
        },
        {
          "name": "SmartHomeIntent",
          "slots": [
            {"name": "device", "type": "AMAZON.Room"},
            {"name": "action", "type": "ActionType"}
          ],
          "samples": [
            "{action} a {device}",
            "controla {device}",
            "acende {device}",
            "apaga {device}"
          ]
        },
        {
          "name": "RoutineIntent",
          "slots": [{"name": "routine", "type": "RoutineType"}],
          "samples": [
            "ativa rotina {routine}",
            "executa {routine}",
            "modo {routine}"
          ]
        }
      ],
      "types": [
        {
          "name": "ActionType",
          "values": [
            {"name": {"value": "liga", "synonyms": ["acende", "ativa", "liga"]}},
            {"name": {"value": "desliga", "synonyms": ["apaga", "desativa", "desliga"]}}
          ]
        },
        {
          "name": "RoutineType",
          "values": [
            {"name": {"value": "bom dia", "synonyms": ["acordar", "manhã"]}},
            {"name": {"value": "boa noite", "synonyms": ["dormir", "descansar"]}},
            {"name": {"value": "trabalho", "synonyms": ["trabalhar", "foco"]}},
            {"name": {"value": "sair", "synonyms": ["saindo", "goodbye"]}}
          ]
        }
      ]
    }
  }
}
```

---

## 4.1 Handler Principal Python

```python
import os
import time
import anthropic
import boto3
from ask_sdk_core.skill_builder import SkillBuilder
from ask_sdk_core.handler_input import HandlerInput
from ask_sdk_core.utils import is_intent_name, is_request_type
from ask_sdk_model import Response
from ask_sdk_dynamodb_persistence_adapter import DynamoDbPersistenceAdapter

## ============================================================

@sb.request_handler(can_handle_func=is_request_type("LaunchRequest"))
def launch_handler(handler_input: HandlerInput) -> Response:
    attrs = handl
