---
name: instagram
description: Integracao completa com Instagram via Graph API. Publicacao, analytics, comentarios, DMs, hashtags, agendamento, templates e gestao de contas Business/Creator. 
category: Business & Marketing
source: antigravity
tags: [python, api, claude, ai, template, image, rag, cro, marketing]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/instagram
---


# Skill: Instagram Integration

## Overview

Integracao completa com Instagram via Graph API. Publicacao, analytics, comentarios, DMs, hashtags, agendamento, templates e gestao de contas Business/Creator.

## When to Use This Skill

- When the user mentions "instagram" or related topics
- When the user mentions "ig" or related topics
- When the user mentions "post instagram" or related topics
- When the user mentions "publicar instagram" or related topics
- When the user mentions "reels instagram" or related topics
- When the user mentions "stories instagram" or related topics

## Do Not Use This Skill When

- The task is unrelated to instagram
- A simpler, more specific tool can handle the request
- The user needs general-purpose assistance without domain expertise

## How It Works

Controle completo da conta Instagram via Graph API. Publicação, comunidade, analytics,
DMs, hashtags, templates e dashboard — tudo gerido com governança (rate limits, audit log,
confirmações antes de ações públicas).

## Resumo Rápido

| Área | Scripts | O que faz |
|------|---------|-----------|
| **Setup** | `account_setup.py`, `auth.py` | Configurar conta, OAuth, token |
| **Publicação** | `publish.py`, `schedule.py` | Publicar foto/vídeo/reel/story/carrossel, agendar |
| **Comunidade** | `comments.py`, `messages.py` | Comentários, DMs, menções |
| **Analytics** | `insights.py`, `analyze.py` | Métricas, melhores horários, top posts |
| **Hashtags** | `hashtags.py` | Pesquisa e tracking |
| **Inteligência** | `templates.py`, `analyze.py` | Templates de conteúdo, tendências |
| **Infra** | `export.py`, `serve_api.py`, `run_all.py` | Exportar, dashboard, sync |
| **Leitura** | `profile.py`, `media.py` | Perfil, listar mídia |

## Localização

```
C:\Users\renat\skills\instagram\
├── SKILL.md
├── scripts/
│   ├── requirements.txt
│   │  # ── CORE ──
│   ├── config.py                     # Paths, constantes, specs de mídia
│   ├── db.py                         # SQLite: accounts, posts, comments, insights
│   ├── auth.py                       # OAuth 2.0, token storage/refresh
│   ├── api_client.py                 # Instagram Graph API wrapper + retry
│   ├── governance.py                 # Rate limits, audit log, confirmações
│   │  # ── FEATURES ──
│   ├── account_setup.py              # Detecção conta, migração, verificação
│   ├── publish.py                    # Publicar + upload local via Imgur
│   ├── schedule.py                   # Orquestrador: approved → published
│   ├── comments.py                   # Ler/responder/deletar comentários
│   ├── messages.py                   # DMs (enviar/receber/listar)
│   ├── insights.py                   # Fetch + store métricas
│   ├── hashtags.py                   # Pesquisa + tracking
│   ├── profile.py                    # Ver/atualizar perfil
│   ├── media.py                      # Listar mídia, detalhes
│   │  # ── INTELIGÊNCIA ──
│   ├── templates.py                  # Templates de caption/hashtags
│   ├── analyze.py                    # Melhores horários, top posts
│   │  # ── INFRA ──
│   ├── export.py                     # Exportar JSON/CSV/JSONL
│   ├── serve_api.py                  # FastAPI + dashboard
│   └── run_all.py                    # Sync completo
├── references/
│   ├── graph_api.md                  # Endpoints e parâmetros
│   ├── permissions.md                # Scopes OAuth por feature
│   ├── rate_limits.md                # Limites 2025
│   ├── account_types.md              # Business vs Creator
│   ├── publishing_guide.md           # Specs de mídia
│   ├── setup_walkthrough.md          # Guia Meta App
│   └── schema.md                     # ER diagram
├── static/
│   └── dashboard.html                # Dashboard Chart.js
└── data/
    

## Instalação (Uma Vez)

```bash
pip install -r C:\Users\renat\skills\instagram\scripts\requirements.txt
```

## Configuração Inicial

```bash

## 1. Verificar Tipo De Conta Instagram

python C:\Users\renat\skills\instagram\scripts\account_setup.py --check

## 2. Configurar Oauth (Abre Browser Para Autorização)

python C:\Users\renat\skills\instagram\scripts\auth.py --setup

## 3. Verificar Se Está Tudo Funcionando

python C:\Users\renat\skills\instagram\scripts\profile.py --view
```

Se a conta for pessoal, o script `account_setup.py --guide` dá instruções de migração
para Business ou Creator.

## Foto (Aceita Arquivo Local — Faz Upload Automático Via Imgur)

python C:\Users\renat\skills\instagram\scripts\publish.py --type photo --image caminho/foto.jpg --caption "Texto do post"

## Vídeo

python C:\Users\renat\skills\instagram\scripts\publish.py --type video --video caminho/video.mp4 --caption "Meu vídeo"

## Reel

python C:\Users\renat\skills\instagram\scripts\publish.py --type reel --video caminho/reel.mp4 --caption "Novo reel!"

## Story

python C:\Users\renat\skills\instagram\scripts\publish.py --type story --image caminho/story.jpg

## Carrossel (2-10 Imagens)

python C:\Users\renat\skills\instagram\scripts\publish.py 
