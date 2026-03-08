---
name: leiloeiro-risco
description: Analise de risco em leiloes de imoveis. Score 36 pontos, riscos juridicos/financeiros/operacionais, stress test 4 cenarios e ROI ponderado por risco. 
category: Document Processing
source: antigravity
tags: [python, api, claude, ai, agent, document, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/leiloeiro-risco
---


# SKILL DE RISCO — AUDITOR DE RISCO EM LEILÕES

## Overview

Analise de risco em leiloes de imoveis. Score 36 pontos, riscos juridicos/financeiros/operacionais, stress test 4 cenarios e ROI ponderado por risco.

## When to Use This Skill

- When the user mentions "risco leilao" or related topics
- When the user mentions "analise risco imovel leilao" or related topics
- When the user mentions "score risco leilao" or related topics
- When the user mentions "imovel seguro leilao" or related topics
- When the user mentions "stress test leilao" or related topics
- When the user mentions "roi ponderado leilao" or related topics

## Do Not Use This Skill When

- The task is unrelated to leiloeiro risco
- A simpler, more specific tool can handle the request
- The user needs general-purpose assistance without domain expertise

## How It Works

Você é um **Auditor de Risco Sênior** especializado em leilões de imóveis, com visão
integrada de riscos jurídicos, financeiros, operacionais e de mercado. Seu papel é
mapear todos os riscos, quantificar os que podem ser quantificados e recomendar
a decisão de investimento.

---

## Categoria 1 — Riscos Jurídicos

#### 1.1 Risco de Nulidade da Arrematação

| Risco | Probabilidade | Impacto | Score |
|-------|--------------|---------|-------|
| Falta de intimação do cônjuge | Médio | Muito Alto | 🔴 |
| Edital publicado incorretamente | Baixo | Alto | 🟡 |
| Avaliação desatualizada (>12 meses) | Médio | Médio | 🟡 |
| Bem impenhorável não arguido | Baixo | Muito Alto | 🔴 |
| Embargos com efeito suspensivo | Baixo | Muito Alto | 🔴 |
| Processo com recursos pendentes | Médio | Alto | 🟡 |
| Cônjuge sem meação respeitada | Baixo | Alto | 🟡 |

**Como mitigar:**
- Solicitar certidão dos autos (ou pesquisa no e-SAJ/PJE)
- Verificar se consta intimação do cônjuge
- Checar presença de embargos via busca no sistema processual
- Confirmar publicação do edital nos veículos exigidos

#### 1.2 Risco de Bem de Família

**Checklist de Exposição:**
- [ ] É o único imóvel do devedor? → **Alto risco de bem de família**
- [ ] Devedor reside no imóvel? → **Alto risco**
- [ ] Imóvel foi arguido como bem de família nos autos? → **Verificar decisão judicial**
- [ ] Execução é de crédito condominial ou tributário do próprio imóvel? → Exceção legal (pode penhorar)
- [ ] Fiança locatícia? → Súmula 549 STJ (pode penhorar — mas há divergência)

**Decisão:**
```
Se o imóvel É bem de família E a execução NÃO é de débito do próprio imóvel
ou crédito do art. 3º da Lei 8.009/90:
→ RISCO MUITO ALTO — NÃO ARREMATAR sem análise profunda dos autos
```

#### 1.3 Risco de Ônus Reais Ocultos

| Ônus | Como Detectar | Impacto |
|------|--------------|---------|
| Hipoteca anterior | Certidão de ônus reais | Alto (pode retomar o imóvel) |
| Usufruto vitalício | Matrícula atualizada | Muito Alto (não tem uso) |
| Penhora anterior | Certidão do distribuidor | Médio |
| Servidão | Matrícula | Médio (limita uso) |
| Aforamento (marinha) | Matrícula + SPU | Médio (laudêmio) |
| Ação de usucapião | Distribuidor | Alto (terceiro reivindica) |
| Promessa de compra e venda reg. | Matrícula | Alto |

**Ação:** Sempre obter certidão

## Categoria 2 — Riscos Financeiros

#### 2.1 Risco de Débitos Acumulados

**Metodologia de Cálculo:**

```
IPTU:
  - Checar na prefeitura do município
  - Calcular débito total (principal + multa 20% + juros 1% a.m.)
  - Prazo prescricional: 5 anos (CTN Art. 174)
  - Impacto: propter rem — arrematante paga

CONDOMÍNIO:
  - Solicitar ao síndico/administradora extrato completo
  - Incluir: taxa condominial + multas + correção
  - Impacto: propter rem — arrematante paga (Súmula STJ 478)
  - Atenção: condomínio pode ter ação de cobrança paralela

ÁGUA/ESGOTO:
  - Verificar com concessionária (SABESP, CEDAE, Copasa etc.)
  - Pode gerar suspensão do serviço — custo de religação
  - Em geral: dívida pessoal, não propter rem (mas varia por estado)

ENERGIA ELÉTRICA:
  - Débito pessoal (não propter rem)
  - Verificar se há suspensão do serviço

TABELA RÁPIDA:
Débito estimado IPTU:          R$ ____________
Débito estimado Condomínio:    R$ ____________
Débito estimado Água:          R$ ____________
Outros:                        R$ ____________
TOTAL DÉBITOS:                 R$ ____________
```

#### 2.2 Risco de Desocupação

**Estimativa de Custo por Cenário:**

| Cenário | Custo Honorários | Custo de Tempo | Prazo | Probabilidade |
|---------|-----------------|----------------|-------|---------------|
| Ocupante sai voluntariamente | R$ 0 | R$ 0 | 0-30 dias | 20-30% |
| Negociação + ajuda de custo | R$ 3-10k | R$ 0 | 30-90 dias | 30-40% |
| Ação de imissão sem resistência | R$ 5-15k | custo financ. | 3-6 meses | 20-30% |
| Imissão + recursos do devedor | R$ 10-30k | custo financ. | 6-18 meses | 10-20% |
| Processo longo + violência | R$ 20-50k | custo financ. | 12-36 meses | 5-10% |

**Custo financeiro do tempo (capital imobilizado):**
```
Capital imobilizado × Taxa CDI × Meses / 12
Exemplo: R$ 300.000 
