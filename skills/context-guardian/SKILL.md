---
name: context-guardian
description: Guardiao de contexto que preserva dados criticos antes da compactacao automatica. Snapshots, verificacao de integridade e zero perda de informacao. 
category: Document Processing
source: antigravity
tags: [python, markdown, api, claude, ai, agent, workflow, document, image, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/context-guardian
---


# Context Guardian

## Overview

Guardiao de contexto que preserva dados criticos antes da compactacao automatica. Snapshots, verificacao de integridade e zero perda de informacao.

## When to Use This Skill

- When the user mentions "compactacao contexto" or related topics
- When the user mentions "perda de contexto" or related topics
- When the user mentions "snapshot contexto" or related topics
- When the user mentions "preservar contexto" or related topics
- When the user mentions "contexto critico" or related topics
- When the user mentions "antes de compactar" or related topics

## Do Not Use This Skill When

- The task is unrelated to context guardian
- A simpler, more specific tool can handle the request
- The user needs general-purpose assistance without domain expertise

## How It Works

Sistema de integridade de contexto que protege projetos tecnicoss complexos contra
perda de informacao durante compactacao automatica do Claude Code. Enquanto o
`context-agent` atua APOS as sessoes (save/load), o context-guardian atua DURANTE
a sessao, detectando quando a compactacao esta proxima e executando protocolos de
preservacao com verificacao redundante.

## Por Que Isto Existe

O Claude Code compacta automaticamente mensagens antigas quando o contexto se
aproxima do limite da janela. Essa compactacao e heuristica — ela resume mensagens
para liberar espaco, mas inevitavelmente perde detalhes. Para projetos simples,
isso funciona bem. Mas para projetos tecnicos pesados (como ecossistemas com 21+
skills, auditorias de seguranca, refatoracoes de arquitetura), a perda de um unico
detalhe pode causar regressoes, re-trabalho ou inconsistencias graves.

O context-guardian resolve isso criando uma camada de protecao PRE-compactacao:
extrai, classifica, verifica e persiste todas as informacoes criticas ANTES que a
compactacao automatica as destrua.

## Localizacao

```
C:\Users\renat\skills\context-guardian\
├── SKILL.md                          # Este arquivo
├── references/
│   ├── extraction-protocol.md        # Protocolo detalhado de extracao
│   └── verification-checklist.md     # Checklist de verificacao e redundancia
└── scripts/
    └── context_snapshot.py           # Script de snapshot automatico
```

## Integracao Com O Ecossistema

```
context-guardian (PRE-compactacao)    context-agent (POS-sessao)
         │                                    │
         ├── Detecta contexto grande          ├── Salva resumo ao final
         ├── Extrai dados criticos            ├── Atualiza ACTIVE_CONTEXT.md
         ├── Verifica integridade             ├── Sincroniza MEMORY.md
         ├── Salva snapshot verificado        ├── Indexa busca FTS5
         └── Gera briefing de transicao       └── Arquiva sessoes antigas
```

O context-guardian e o context-agent sao complementares:
- **context-guardian**: protecao em tempo real, DURANTE a sessao
- **context-agent**: persistencia entre sessoes, APOS a sessao

## Ativacao Automatica (O Claude Deve Iniciar Sozinho)

1. **Limite de contexto**: quando perceber que ja consumiu ~60-70% da janela de
   contexto (indicadores: mensagens comecando a ser resumidas, aviso de compactacao)
2. **Projetos pesados**: sessoes com muitos arquivos editados, muitas tool calls,
   ou projetos com dependencias complexas entre componentes
3. **Antes de tarefas longas**: quando uma proxima tarefa pode gerar output extenso
   que empurraria o contexto para alem do limite

## Ativacao Manual (Usuario Solicita)

- "salva o estado antes de comprimir"
- "faz um checkpoint"
- "snapshot do contexto"
- "nao quero perder nada dessa sessao"
- "prepara pra compactacao"
- "o contexto ta grande, protege"

## Fase 1: Extracao Estruturada

Percorrer toda a conversa ate o momento e extrair categorias criticas.
Para cada categoria, classificar por prioridade (P0 = perda fatal, P1 = perda grave,
P2 = perda toleravel).

**P0 — Perda Fatal (preservar com redundancia tripla)**

| Categoria | O que extrair | Exemplo |
|-----------|--------------|---------|
| Decisoes tecnicas | Escolhas de arquitetura, padrao, tecnologia E motivo | "Usamos parameterized queries porque f-strings causam SQL injection" |
| Estado de tarefas | O que foi feito, o que falta, dependencias | "18/18 match OK, falta ZIP" |
| Correcoes aplicadas | Bug, causa raiz, solucao exata, arquivos afetados | "instagram/db.py: SQL injection via f-string → ? placeholders" |
| Codigo gerado/modificado | Caminho exato, linhas alteradas, natureza da mudanca | "match_skills.py:40-119: adicionou 5 categorias" |
| Erros encontrados | Mensagem exata, stack trace relevante, como resolveu | "TypeError at line 45 → cast para int" |
| Comandos que funcionaram | Comando completo que produziu resultado correto | "python verify_zips.py → 22/22 OK" |

**P1 — Perda Grave (preservar com verificacao)**

| Categoria | O que extrair |
|-----------|--------------|
| Padroes descobertos | Convencoes, patterns de codigo observados |
| Dependencias entre componentes | "scan_registry
