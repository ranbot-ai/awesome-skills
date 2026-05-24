---
name: claude-code-expert
description: Especialista profundo em Claude Code - CLI da Anthropic. Maximiza produtividade com atalhos, hooks, MCPs, configuracoes avancadas, workflows, CLAUDE.md, memoria, sub-agentes, permissoes e integracao c
category: Document Processing
source: antigravity
tags: [python, javascript, node, markdown, api, mcp, claude, ai, agent, workflow]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/claude-code-expert
---


# CLAUDE CODE EXPERT - Potencia Maxima

## Overview

Especialista profundo em Claude Code - CLI da Anthropic. Maximiza produtividade com atalhos, hooks, MCPs, configuracoes avancadas, workflows, CLAUDE.md, memoria, sub-agentes, permissoes e integracao com ecossistemas. Ativar para: configurar Claude Code, criar hooks, otimizar CLAUDE.md, usar MCPs, criar sub-agentes, resolver erros do CLI, workflows avancados, duvidas sobre qualquer feature.

## When to Use This Skill

- When you need specialized assistance with this domain

## Do Not Use This Skill When

- The task is unrelated to claude code expert
- A simpler, more specific tool can handle the request
- The user needs general-purpose assistance without domain expertise

## How It Works

Voce e o especialista definitivo em Claude Code. Seu objetivo e transformar
cada sessao em uma experiencia 10x mais poderosa, rapida e inteligente.

---

## 1. Fundamentos Do Claude Code

Claude Code e a CLI oficial da Anthropic para usar Claude como agente de codigo
diretamente no terminal. Diferente do Claude.ai web, o Claude Code:
- Acessa seu filesystem diretamente
- Executa comandos bash, git, npm, etc.
- Persiste contexto via CLAUDE.md e memory files
- Suporta MCP servers (extensoes de ferramentas)
- Suporta hooks (automacoes pre/pos-acao)
- Pode criar e orquestrar sub-agentes via Task tool

## Instalacao E Setup

```bash
npm install -g @anthropic-ai/claude-code
claude                    # iniciar sessao interativa
claude "sua tarefa aqui"  # modo nao-interativo
claude --help             # ver todos os flags
```

## Flags Essenciais

```bash
claude -p "prompt"              # print mode, ideal para scripts
claude --model claude-opus-4    # especificar modelo
claude --max-tokens 8192        # limite de tokens
claude --no-stream              # sem streaming
claude --output-format json     # saida em JSON
claude --allowed-tools "Bash,Read,Write"  # limitar ferramentas
claude --dangerously-skip-permissions     # pular confirmacoes (cuidado!)
claude --max-turns 50                     # maximo de turnos autonomos
```

---

## 2. Claude.Md - O Cerebro Do Projeto

O arquivo CLAUDE.md na raiz do projeto e carregado automaticamente em TODA sessao.
E a forma mais poderosa de dar contexto e instrucoes persistentes ao Claude Code.

## Hierarquia De Claude.Md

1. ~/.claude/CLAUDE.md          global, carregado em todo projeto
2. /projeto/CLAUDE.md           nivel de projeto
3. /projeto/subpasta/CLAUDE.md  nivel de subpasta, carregado ao navegar

## Estrutura Recomendada

```markdown

## Contexto

O que e este projeto, tecnologias, arquitetura

## Comandos Essenciais

Scripts mais usados: npm run dev, pytest, etc.

## Convencoes De Codigo

Estilo, naming, patterns obrigatorios

## Arquitetura

Estrutura de pastas, responsabilidades de cada modulo

## Regras De Negocio Criticas

O que NUNCA fazer, invariantes do sistema

## Agentes E Skills Disponiveis

Lista de skills, quando usar cada uma

## Protocolo Pre-Tarefa

Sempre rodar orchestrator antes de responder
```

## Dicas De Claude.Md De Elite

- Use secao Protocolo Pre-Tarefa para garantir que o Claude sempre use orchestrator
- Adicione secao Erros Conhecidos com solucoes para problemas recorrentes
- Use secao Memoria como indice para arquivos de memoria detalhados
- Adicione exemplos concretos de output esperado
- Referencie paths absolutos para scripts criticos

---

## Localizacao Dos Arquivos De Memoria

```
~/.claude/projects/<hash-do-path>/memory/
├── MEMORY.md          # indice e contexto rapido (max 200 linhas)
├── ai-personas.md     # detalhes de personas e skills ativas
├── project-X.md       # contexto de projetos especificos
└── decisions.md       # decisoes tecnicas importantes
```

## Memoria Ativa (Em Claude.Md)

Carregar antes de qualquer tarefa: memory/MEMORY.md
Para projetos ativos: memory/ai-personas.md

## Instrucao De Salvamento Automatico:

Ao final de sessoes longas, execute:
python context-agent/scripts/context_manager.py save
```

## Context Guardian - Prevenir Perda De Contexto

O context-guardian skill monitora compactacao automatica e salva snapshots.
Ativar no inicio de sessoes longas ou criticas.

---

## 4. Hooks - Automacao Poderosa

Hooks executam comandos automaticamente em eventos do Claude Code.

## Localizacao Dos Hooks

- Global: ~/.claude/settings.json
- Por projeto: .claude/settings.json (na raiz do projeto)

## Tipos De Hooks Disponiveis

| Hook | Quando Dispara |
|------|----------------|
| PreToolUse | Antes de qualquer ferramenta ser usada |
| PostToolUse | Apos qualquer ferramenta ser usada |
| Notification | Ao receber notificacao do sistema |
| Stop | Quando o agente para de responder |
| SubagentStop | Quando sub-agente para |

## Exemplo: Hook De Beep Ao Terminar

```json
{
  "hooks": {
    "Stop": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "powershell -c \\"[Console]::Beep(800,300)\\""
          }
        ]
