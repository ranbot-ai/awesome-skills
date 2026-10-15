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

- Quando o usuario pede um inventario local de skills ou um plano de coordenacao para uma tarefa com varias capacidades.
- Quando e necessario comparar candidatos explicitamente, sem executar suas instrucoes nem iniciar agentes.

## Do Not Use This Skill When

- The task is unrelated to agent orchestrator
- A simpler, more specific tool can handle the request
- The user needs general-purpose assistance without domain expertise

## How It Works

Meta-skill que funciona como camada central de decisao e coordenacao para todo
o ecossistema de skills. Faz varredura automatica, identifica agentes relevantes
e orquestra multiplos skills para tarefas complexas.

## Principio: Descoberta Solicitada e Plano Revisavel

- Faz varredura somente no escopo solicitado; esta skill nao deve interceptar todas as solicitacoes
- Novas skills sao detectadas na proxima varredura explicita, dentro dos roots e do limite de profundidade
- Skills removidas sao **auto-excluidas** do registry
- Execute a varredura explicitamente; o matcher nao inicia uma varredura automaticamente

---

## Workflow Obrigatorio (Toda Solicitacao)

Execute estes passos apenas quando a tarefa pede esta ferramenta. Scores sao heuristicas locais, nao prova de seguranca, compatibilidade ou autorizacao. Um plano nao executa skills; delegacao, mensagens e publicacao exigem autorizacao do usuario.
Os scripts localizam arquivos a partir da propria instalacao, mas os comandos abaixo pressupõem que o diretorio pai de `agent-orchestrator` seja o diretorio atual. De outro local, use o caminho absoluto do script.

## Passo 1: Auto-Discovery (Varredura)

```bash
python agent-orchestrator/scripts/scan_registry.py
```

Usa cache de hashes SHA-256 para reprocessar arquivos alterados. O tempo depende do tamanho da arvore; nao ha garantia de 100ms.
Retorna JSON com resumo de todos os skills encontrados.

## Passo 2: Match De Skills

```bash
python agent-orchestrator/scripts/match_skills.py "<solicitacao do usuario>"
```

Retorna JSON com skills ranqueadas por relevancia. Interpretar o resultado:

| Resultado              | Acao                                                    |
|:-----------------------|:--------------------------------------------------------|
| `matched: 0`          | Nenhum candidato acima do limite heuristico; nao prova ausencia de skills relevantes.  |
| `matched: 1`          | Um candidato. Inspecionar escopo, arquivos, dependencias e autorizacao antes de selecionar.     |
| `matched: 2+`         | Multiplos candidatos. Propor um plano somente se a tarefa pede coordenacao.      |

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

Antes de executar, defina `AGENT_ORCHESTRATOR_DATA_DIR` como caminho absoluto de
um diretorio privado autorizado fora da instalacao da skill. Registry, hashes e
atribuicoes de projeto ficam nesse diretorio. Nao use um diretorio compartilhado
ou uma arvore com links simbolicos; inspecione o conteudo antes de reutilizar.

```bash
export AGENT_ORCHESTRATOR_DATA_DIR="<diretorio-absoluto-autorizado>"
```

Execute a varredura explicitamente antes do matcher. Falha de leitura, JSON
invalido ou registry ausente nao significa que nenhuma skill existe. Caminhos
distintos permanecem no inventario mesmo com nomes iguais; selecao por nome
ambiguo deve parar. O limite de profundidade do scanner torna o inventario parcial.

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
| registered     | Se esta em .claude/skills/ (true/false); nao prova carregamento pelo host            |
| capabilities   | Tags de capacidade (auto-extraidas + explicitas)   |
| triggers       | Keywords de ativacao extraidas da description      |
| language       | Linguagem prin
