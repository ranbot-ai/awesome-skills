---
name: context-agent
description: Agente de contexto para continuidade entre sessoes. Salva resumos, decisoes, tarefas pendentes e carrega briefing automatico na sessao seguinte. 
category: AI & Agents
source: antigravity
tags: [python, claude, ai, agent, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/context-agent
---


# Context Agent

> Este guia e intencionalmente escrito em portugues brasileiro. O cabecalho
> Os cabecalhos `When to Use` e `Limitations` permanecem em ingles apenas para
> compatibilidade com a descoberta e a validacao automatica do catalogo.

> [!WARNING]
> Esta skill escreve contexto, registros, um banco SQLite e `MEMORY.md` em
> caminhos locais; a manutencao tambem pode arquivar e remover resumos antigos.
> Confirme os caminhos, mantenha um backup e obtenha aprovacao explicita antes
> de executar `init`, `save`, `archive` ou `maintain`.

## Visao Geral

Agente de contexto para continuidade entre sessoes. Salva resumos, decisoes, tarefas pendentes e carrega briefing automatico na sessao seguinte.

## When to Use This Skill

- Quando o usuario mencionar "salvar contexto" ou assuntos relacionados
- Quando o usuario mencionar "salva o contexto" ou assuntos relacionados
- Quando o usuario mencionar "proxima sessao" ou assuntos relacionados
- Quando o usuario mencionar "briefing sessao" ou assuntos relacionados
- Quando o usuario mencionar "resumo sessao" ou assuntos relacionados
- Quando o usuario mencionar "continuidade sessao" ou assuntos relacionados

## Quando Nao Usar Esta Skill

- A tarefa nao estiver relacionada a continuidade de contexto
- Uma ferramenta mais simples e especifica puder atender ao pedido
- O usuario precisar apenas de assistencia geral, sem esta especializacao

## Como Funciona

Continuidade perfeita entre sessões do Claude Code. Captura, comprime e
restaura contexto automaticamente — tópicos, decisões, tarefas, erros,
arquivos modificados e descobertas técnicas.

## Localização

```
C:\Users\renat\skills\context-agent\
├── SKILL.md
├── scripts/
│   ├── config.py               # Paths e constantes
│   ├── models.py               # Dataclasses
│   ├── session_parser.py       # Parser JSONL do Claude Code
│   ├── session_summary.py      # Gerador de resumos
│   ├── active_context.py       # Gerencia ACTIVE_CONTEXT.md
│   ├── project_registry.py     # Registro de projetos
│   ├── compressor.py           # Compressão e arquivamento
│   ├── search.py               # Busca FTS5
│   ├── context_loader.py       # Carrega contexto
│   └── context_manager.py      # CLI entry point
├── references/
│   ├── context-format.md       # Especificação de formatos
│   └── compression-rules.md    # Regras de compressão
└── data/
    ├── sessions/               # session-001.md, session-002.md, ...
    ├── archive/                # Sessões arquivadas
    ├── ACTIVE_CONTEXT.md       # Contexto consolidado (max 150 linhas)
    ├── PROJECT_REGISTRY.md     # Status de todos os projetos
    └── context.db              # SQLite FTS5 para busca
```

## Inicialização (Primeira Vez)

```bash
python C:\Users\renat\skills\context-agent\scripts\context_manager.py init
```

## Salvar Contexto Da Sessão Atual

Quando a sessão está terminando ou antes de uma tarefa longa, salvar o contexto:

```bash
python C:\Users\renat\skills\context-agent\scripts\context_manager.py save
```

O que faz:
1. Encontra o arquivo JSONL mais recente da sessão
2. Analisa todas as mensagens, tool calls e resultados
3. Gera resumo estruturado (session-NNN.md)
4. Atualiza ACTIVE_CONTEXT.md com novas informações
5. Sincroniza com MEMORY.md (carregado no system prompt)
6. Indexa para busca full-text

## Carregar Contexto (Briefing)

No início de uma nova sessão, carregar o contexto:

```bash
python C:\Users\renat\skills\context-agent\scripts\context_manager.py load
```

Gera briefing com: projetos ativos, tarefas pendentes (por prioridade),
bloqueadores, decisões recentes, convenções e resumo das últimas sessões.

## Status Rápido

```bash
python C:\Users\renat\skills\context-agent\scripts\context_manager.py status
```

Resumo em poucas linhas: projetos, pendências críticas, bloqueadores.

## Buscar No Histórico

```bash
python C:\Users\renat\skills\context-agent\scripts\context_manager.py search "rate limit"
```

Busca full-text (SQLite FTS5) em todas as sessões — tópicos, decisões,
erros, arquivos, etc.

## Manutenção

```bash
python C:\Users\renat\skills\context-agent\scripts\context_manager.py maintain
```

Arquiva sessões antigas, comprime arquivo, ressincroniza MEMORY.md,
reconstrói índice de busca.

## Fluxo De Trabalho

```
[Sessão termina]
  → save → session-NNN.md + ACTIVE_CONTEXT.md + MEMORY.md

[Nova sessão começa]
  → MEMORY.md já está no system prompt (automático)
  → load → briefing detalhado com tudo que precisa saber

[Contexto cresce demais]
  → maintain → arquiva sessões antigas, comprime, otimiza
```

## O Que É Capturado Em Cada Sessão

- **Tópicos**: assuntos discutidos
- **Decisões**: escolhas técnicas e de arquitetura
- **Tarefas concluídas**: o que foi feito
- **Tarefas pendentes**: o que falta (com prioridade)
- **Arquivos modificados**: quais arquivos foram editados/criados
- **Descobertas**: insights técnicos importantes
- **Erros resolvidos**: problemas e suas soluções
- **Questões em aberto**: perguntas sem respost
