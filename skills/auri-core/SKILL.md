---
name: auri-core
description: Auri: assistente de voz inteligente (Alexa + Claude claude-opus-4-20250805). Visao do produto, persona Vitoria Neural, stack AWS, modelo Free/Pro/Business/Enterprise, roadmap 4 fases, GTM, north star 
category: Development & Code Tools
source: antigravity
tags: [python, api, claude, ai, llm, gpt, template, design, aws, seo]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/auri-core
---


# Auri - Core Product Skill

## Overview

Auri: assistente de voz inteligente (Alexa + Claude claude-opus-4-20250805). Visao do produto, persona Vitoria Neural, stack AWS, modelo Free/Pro/Business/Enterprise, roadmap 4 fases, GTM, north star WAC e analise competitiva.

## When to Use This Skill

- When you need specialized assistance with this domain

## Do Not Use This Skill When

- The task is unrelated to auri core
- A simpler, more specific tool can handle the request
- The user needs general-purpose assistance without domain expertise

## How It Works

| Atributo | Definicao |
|----------|-----------|
| Nome | Auri |
| Voz | Amazon Polly Vitoria Neural pt-BR |
| Tom | Caloroso, inteligente, direto |
| Personalidade | Curiosa, empatica, confiavel |
| Linguagem | Portugues brasileiro natural |
| Atitude | Proativa, mas nunca invasiva |

## Auri - Core Product Skill

>  A voz que pensa com voce.

Auri e um assistente de voz de nova geracao construido sobre Amazon Alexa + Claude claude-opus-4-20250805.
Enquanto a Alexa tradicional executa comandos, a Auri conduz conversas reais e raciocina sobre contexto.

---

## O Que E A Auri

A Auri e uma Alexa Skill avancada que substitui o motor de respostas padrao pelo modelo
Claude claude-opus-4-20250805 da Anthropic. O resultado: um assistente de voz capaz de:

- Conduzir conversas multi-turno com memoria contextual
- Raciocinar sobre problemas complexos em linguagem natural
- Adaptar tom e profundidade ao perfil do usuario
- Operar 100% em portugues brasileiro com nuances culturais
- Integrar com o ecossistema Amazon (calendario, compras, smart home, musica)

## Proposta De Valor Unica

ANTES: Alexa, qual a previsao do tempo? -> Amanha, 28 graus e nublado.

DEPOIS: Auri, devo levar guarda-chuva amanha?
  -> Amanha 70% de chuva a tarde mas a manha estara limpa. Reuniao as 14h? Leve guarda-chuva.

## Diferencial Estrategico

1. Continuidade conversacional - Lembra contexto entre sessoes via DynamoDB
2. Personalidade consistente - Voz Vitoria Neural + persona calibrada
3. Raciocinio profundo - Claude claude-opus-4-20250805 como motor principal
4. Ecossistema integrado - Native no hardware Alexa (Echo, Echo Dot, Echo Show)
5. Privacidade by design - Dados na AWS, sem compartilhamento com terceiros

---

## Valores Da Marca

- Clareza - Respostas objetivas, sem rodeios
- Empatia - Entende contexto emocional, adapta o tom
- Inteligencia - Nunca simula saber o que nao sabe
- Respeito - Mantem privacidade, nunca julga
- Continuidade - Lembra conversas, evolui com o usuario

## Guia De Linguagem

Fazer:
- Falar na primeira pessoa
- Confirmar entendimento antes de responder
- Reconhecer incerteza e oferecer alternativa

Evitar:
- Respostas roboticas
- Formalidade excessiva
- Evasao sem alternativa

## Exemplo De Interacao

Usuario: Auri, me explica criptomoeda de um jeito simples.

Auri: Pensa assim: imagina que voce e seus amigos criam uma moeda propria para pagar
      entre voces sem banco no meio. Criptomoeda e exatamente isso, mas para milhoes
      de pessoas. O Bitcoin foi o primeiro, criado em 2009. Quer entender melhor?

## Ssml - Voz Otimizada

Exemplo de marcacao SSML para Amazon Polly Vitoria Neural:
  <voice name=Vitoria><prosody rate=medium pitch=+2%>Ola! Eu sou a Auri.</prosody>
  <break time=300ms/><prosody>Como posso te ajudar hoje?</prosody></voice>

---

## Visao Geral Da Arquitetura

Fluxo de dados: Echo -> ASK SDK (Python v2) -> Lambda Python 3.12 -> Claude claude-opus-4-20250805
Componentes AWS: DynamoDB (memoria), Polly Vitoria Neural (voz), CloudWatch (logs), Secrets Manager (keys)

### 3.1 Dependencias

ask-sdk-core==1.19.0 | ask-sdk-model==1.85.0 | boto3==1.34.0 | anthropic==0.25.0 | python-dotenv==1.0.0

### 3.2 Lambda Handler Principal

Codigo Python - lambda_function.py:
  sb = CustomSkillBuilder()
  sb.add_request_handler(ConversationIntentHandler())
  sb.add_global_request_interceptor(MemoryLoadInterceptor())
  sb.add_global_response_interceptor(MemorySaveInterceptor())
  lambda_handler = sb.lambda_handler()

### 3.3 Handler De Conversa Com Claude

Codigo Python - handlers/conversation.py:
  class ConversationIntentHandler(AbstractRequestHandler):
      Recebe user_speech via slot query
      Carrega historico de conversas da sessao DynamoDB
      Chama anthropic.Anthropic().messages.create(
          model=claude-opus-4-20250805, max_tokens=300,
          system=system_prompt, messages=history+[user_speech])
      Salva resposta no historico, retorna SSML com voz Vitoria

### 3.4 Dynamodb Schema

Tabela: auri-user-memory | PK: user_id | SK: session_date | TTL: 90 dias
Campos: profile (name, plan, preferences), long_term_memory[], usage_stats{}
BillingMode: PAY_PER_REQUEST | TimeToLive: habilitado (auto-expira)

### 3.5 Interaction Model

invocationName: auri
ConversationIntent: slot query (AMAZON.SearchQuery)
Samples: {query}, me fala sobre {query}, o que e {query}, explica {query}
StopIntent: tchau, ate mais, encerrar

### 3.6 Configuracao
