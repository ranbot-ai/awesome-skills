---
name: agent-orchestrator
description: Meta-skill que orquestra todos os agentes do ecossistema. Scan automatico de skills, match por capacidades, coordenacao de workflows multi-skill e registry management. 
category: AI & Agents
source: antigravity
tags: [python, node, api, claude, ai, agent, automation, workflow, document]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/agent-orchestrator
---


# Agent Orchestrator

## Overview

Meta-skill que orquestra todos os agentes do ecossistema. Scan automatico de skills, match por capacidades, coordenacao de workflows multi-skill e registry management.

## When to Use This Skill

- When you need specialized assistance with this domain

## Do Not Use This Skill When

- The task is unrelated to agent orchestrator
- A simpler, more specific tool can handle the request
- The user needs general-purpose assistance without domain expertise

## How It Works

Meta-skill que funciona como camada central de decisao e coordenacao para todo
o ecossistema de skills. Faz varredura automatica, identifica agentes relevantes
e orquestra multiplos skills para tarefas complexas.

## Principio: Zero Intervencao Manual

- **SEMPRE faz varredura** antes de processar qualquer solicitacao
- Novas skills sao **auto-detectadas e incluidas** ao criar SKILL.md em qualquer subpasta
- Skills removidas sao **auto-excluidas** do registry
- Nenhum comando manual e necessario para registrar novas skills

---

## Workflow Obrigatorio (Toda Solicitacao)

Execute estes passos ANTES de processar qualquer request do usuario.
Os scripts usam paths relativos automaticamente - funciona de qualquer diretorio.

## Passo 1: Auto-Discovery (Varredura)

```bash
python agent-orchestrator/scripts/scan_registry.py
```

Ultra-rapido (<100ms) via cache de hashes MD5. So re-processa arquivos alterados.
Retorna JSON com resumo de todos os skills encontrados.

## Passo 2: Match De Skills

```bash
python agent-orchestrator/scripts/match_skills.py "<solicitacao do usuario>"
```

Retorna JSON com skills ranqueadas por relevancia. Interpretar o resultado:

| Resultado              | Acao                                                    |
|:-----------------------|:--------------------------------------------------------|
| `matched: 0`          | Nenhum skill relevante. Operar normalmente sem skills.  |
| `matched: 1`          | Um skill relevante. Carregar seu SKILL.md e seguir.     |
| `matched: 2+`         | Multiplos skills. Executar Passo 3 (orquestracao).      |

## Passo 3: Orquestracao (Se Matched >= 2)

```bash
python agent-orchestrator/scripts/orchestrate.py --skills skill1,skill2 --query "<solicitacao>"
```

Retorna plano de execucao com padrao, ordem dos steps e data flow entre skills.

## Passo Rapido (Atalho)

Para queries simples, os passos 1+2 podem ser combinados em sequencia:
```bash
python agent-orchestrator/scripts/scan_registry.py && python agent-orchestrator/scripts/match_skills.py "<solicitacao>"
```

---

## Skill Registry

O registry vive em:
```
agent-orchestrator/data/registry.json
```

## Locais De Busca

O scanner procura SKILL.md em:
1. `.claude/skills/*/` (skills registradas no Claude Code)
2. `*/` (skills standalone no top-level)
3. `*/*\` (skills em subpastas, ate profundidade 3)

## Metadata Por Skill

Cada entrada no registry contem:

| Campo          | Descricao                                          |
|:---------------|:---------------------------------------------------|
| name           | Nome da skill (do frontmatter YAML)                |
| description    | Descricao completa (triggers inclusos)             |
| location       | Caminho absoluto do diretorio                      |
| skill_md       | Caminho absoluto do SKILL.md                       |
| registered     | Se esta em .claude/skills/ (true/false)            |
| capabilities   | Tags de capacidade (auto-extraidas + explicitas)   |
| triggers       | Keywords de ativacao extraidas da description      |
| language       | Linguagem principal (python/nodejs/bash/none)      |
| status         | active / incomplete / missing                      |

## Comandos Do Registry

```bash

## Scan Rapido (Usa Cache De Hashes)

python agent-orchestrator/scripts/scan_registry.py

## Tabela De Status Detalhada

python agent-orchestrator/scripts/scan_registry.py --status

## Re-Scan Completo (Ignora Cache)

python agent-orchestrator/scripts/scan_registry.py --force
```

---

## Algoritmo De Matching

Para cada solicitacao, o matcher pontua skills usando:

| Criterio                     | Pontos | Exemplo                               |
|:-----------------------------|:-------|:--------------------------------------|
| Nome do skill na query       | +15    | "use web-scraper" -> web-scraper      |
| Keyword trigger exata        | +10    | "scrape" -> web-scraper               |
| Categoria de capacidade      | +5     | data-extraction -> web-scraper        |
| Sobreposicao de palavras     | +1     | Palavras da query na description      |
| Boost de projeto             | +20    | Skill atribuida ao projeto ativo      |

Threshold minimo: 5 pontos. Skills abaixo disso sao ignoradas.

## Match Com Projeto

```bash
python agent-orchestrator/scripts/match_skills.py --project meu-projeto "query aqui"
```

Skills atribuidas ao projeto recebem +20 de boost automatico.

---

## Padroes De Orquestracao

Quando multiplos skills sao rele
