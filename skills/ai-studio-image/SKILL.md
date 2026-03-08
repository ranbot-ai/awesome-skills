---
name: ai-studio-image
description: Geracao de imagens humanizadas via Google AI Studio (Gemini). Fotos realistas estilo influencer ou educacional com iluminacao natural e imperfeicoes sutis. 
category: Document Processing
source: antigravity
tags: [python, api, claude, ai, workflow, template, document, image, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/ai-studio-image
---


# AI Studio Image — Especialista em Imagens Humanizadas

## Overview

Geracao de imagens humanizadas via Google AI Studio (Gemini). Fotos realistas estilo influencer ou educacional com iluminacao natural e imperfeicoes sutis.

## When to Use This Skill

- When the user mentions "gera imagem" or related topics
- When the user mentions "gerar foto" or related topics
- When the user mentions "criar imagem" or related topics
- When the user mentions "foto realista" or related topics
- When the user mentions "imagem humanizada" or related topics
- When the user mentions "foto influencer" or related topics

## Do Not Use This Skill When

- The task is unrelated to ai studio image
- A simpler, more specific tool can handle the request
- The user needs general-purpose assistance without domain expertise

## How It Works

A diferenca entre uma imagem de IA e uma foto real esta nos detalhes imperceptiveis:
a leve granulacao de um sensor de celular, a iluminacao que nao e perfeita, o enquadramento
ligeiramente descentralizado, a profundidade de campo caracteristica de uma lente pequena.
Esta skill injeta sistematicamente essas qualidades em cada geracao.

## Ai Studio Image — Especialista Em Imagens Humanizadas

Skill de geracao de imagens via Google AI Studio que transforma qualquer prompt em fotos
com aparencia genuinamente humana. Cada imagem gerada parece ter sido tirada por uma
pessoa real com seu celular — nao por uma IA.

## 1. Configurar Api Key

O usuario precisa de uma API key do Google AI Studio:
- Acesse https://aistudio.google.com/apikey
- Crie ou copie sua API key
- Configure como variavel de ambiente:

```bash

## Windows

set GEMINI_API_KEY=sua-api-key-aqui

## Linux/Mac

export GEMINI_API_KEY=sua-api-key-aqui
```

Ou crie um arquivo `.env` em `C:\Users\renat\skills\ai-studio-image\`:
```
GEMINI_API_KEY=sua-api-key-aqui
```

## 2. Instalar Dependencias

```bash
pip install -r C:\Users\renat\skills\ai-studio-image\scripts\requirements.txt
```

## 3. Gerar Sua Primeira Imagem

```bash
python C:\Users\renat\skills\ai-studio-image\scripts\generate.py --prompt "mulher jovem tomando cafe em cafeteria" --mode influencer --format square
```

## Workflow Principal

Quando o usuario pedir para gerar uma imagem, siga este fluxo:

## Passo 1: Identificar O Modo

Pergunte ou deduza pelo contexto:

| Modo | Quando Usar | Caracteristicas |
|------|-------------|-----------------|
| **influencer** | Posts de redes sociais, lifestyle, branding pessoal | Estetica atraente mas natural, cores vibrantes sem saturacao excessiva, composicao que prende atencao |
| **educacional** | Material de curso, tutorial, apresentacao, infografico | Visual limpo, profissional, foco no conteudo, elementos claros e legiveis |

Se o usuario nao especificar, use **influencer** como padrao para conteudo de redes sociais
e **educacional** para qualquer coisa relacionada a ensino/apresentacao.

## Passo 2: Identificar O Formato

| Formato | Aspect Ratio | Uso Ideal |
|---------|-------------|-----------|
| `square` | 1:1 | Feed Instagram, Facebook, perfis |
| `portrait` | 3:4 | Instagram portrait, Pinterest |
| `landscape` | 16:9 | YouTube thumbnails, banners, desktop |
| `stories` | 9:16 | Instagram/Facebook Stories, TikTok, Reels |

Se nao especificado, deduza pelo contexto (stories → 9:16, feed → 1:1, etc).

## Passo 3: Transformar O Prompt

**Esta e a etapa mais importante.** Nunca envie o prompt do usuario diretamente para a API.
Sempre passe pelo motor de humanizacao:

```bash
python C:\Users\renat\skills\ai-studio-image\scripts\prompt_engine.py --prompt "prompt do usuario" --mode influencer
```

O motor de humanizacao adiciona camadas de realismo:

**Camada 1 — Dispositivo e Tecnica:**
- Fotografado com smartphone (iPhone/Samsung Galaxy)
- Lente de celular com profundidade de campo natural
- Sem flash — apenas luz ambiente
- Leve ruido de sensor (ISO elevado em baixa luz)

**Camada 2 — Iluminacao Natural:**
- Luz do sol indireta / golden hour / luz de janela
- Sombras suaves e organicas
- Sem iluminacao de estudio
- Reflexos naturais em superficies

**Camada 3 — Imperfeicoes Humanas:**
- Enquadramento ligeiramente imperfeito (nao centralizado matematicamente)
- Foco seletivo natural (algo levemente fora de foco no background)
- Micro-tremor de maos (nitidez nao e absoluta)
- Elementos aleatorios do ambiente real

**Camada 4 — Autenticidade:**
- Expressoes faciais genuinas (nao poses de estudio)
- Roupas e cenarios do dia-a-dia
- Textura de pele real (poros, marcas sutis — sem pele de porcelana)
- Proporcoes corporais realistas

**Camada 5 — Contexto Ambiental:**
- Cenarios reais (nao fundos genericos de stock)
- Objetos do cotidiano no ambiente
- Iluminacao consistente com o cenario
- Hora do dia coerente com a atividade

## Passo 4: Gerar A Imagem

```bash
python C:\Users\renat\skills\ai-studio-image\scripts\generate.py \
  --prompt "prompt humanizado gerado no passo anterior" \
  --mode influencer \
  --format square \
  --model gemin
