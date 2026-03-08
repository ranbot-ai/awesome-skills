---
name: leiloeiro-mercado
description: Analise de mercado imobiliario para leiloes. Liquidez, desagio tipico, ROI, estrategias de saida (flip/reforma/renda), Selic 2025 e benchmark CDI/FII. 
category: Document Processing
source: antigravity
tags: [python, api, claude, ai, agent, document, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/leiloeiro-mercado
---


# SKILL DE MERCADO — ANALISTA DE ATIVOS IMOBILIÁRIOS EM LEILÃO

## Overview

Analise de mercado imobiliario para leiloes. Liquidez, desagio tipico, ROI, estrategias de saida (flip/reforma/renda), Selic 2025 e benchmark CDI/FII.

## When to Use This Skill

- When the user mentions "mercado leilao imovel" or related topics
- When the user mentions "roi leilao" or related topics
- When the user mentions "liquidez imovel leilao" or related topics
- When the user mentions "desagio leilao" or related topics
- When the user mentions "flip imovel leilao" or related topics
- When the user mentions "reforma leilao" or related topics

## Do Not Use This Skill When

- The task is unrelated to leiloeiro mercado
- A simpler, more specific tool can handle the request
- The user needs general-purpose assistance without domain expertise

## How It Works

Você é um **Analista Profissional de Mercado Imobiliário** especializado em
ativos estressados (distressed assets) e leilões, com visão estratégica de
investimento, liquidez, retorno e timing de mercado.

---

## Mapa De Liquidez (Tempo Médio De Revenda Pós-Arrematação)

| Segmento | Capital SP/RJ | Capitais Grandes | Interior | Interior Pequeno |
|----------|--------------|-----------------|----------|-----------------|
| Apart. 1-2 quartos | 30-60 dias | 60-90 dias | 90-180 dias | 180-360 dias |
| Apart. 3 quartos | 60-90 dias | 90-150 dias | 120-240 dias | 240+ dias |
| Casa condomínio | 60-120 dias | 90-180 dias | 120-240 dias | 240+ dias |
| Sala comercial | 120-240 dias | 180-360 dias | 360+ dias | 360+ dias |
| Terreno urbano | 90-180 dias | 180-360 dias | 180-360 dias | 360+ dias |
| Galpão logístico | 90-180 dias | 90-180 dias | 180-360 dias | 360+ dias |
| Imóvel rural | 180-360 dias | 360+ dias | 360+ dias | 360+ dias |

**Fatores que aceleram a venda:**
- Preço abaixo do mercado (10-15% de desconto)
- Imóvel reformado e apresentável
- Documentação regularizada
- Boa foto e anúncio em portais (ZAP, Viva Real)
- Corretor CRECI com carteira de clientes

**Fatores que travam a venda:**
- Pendências documentais (ITBI não pago, matrícula não atualizada)
- Imóvel em mau estado / obras inacabadas
- Débitos não quitados que aparecem na matrícula
- Litígio pendente no imóvel (ação real)

---

## Por Modalidade

**Leilões Judiciais (CPC):**
```
1º Leilão (mínimo = avaliação):
  - Frequência de arrematação no 1º: 20-30%
  - Deságio médio nas arrematações do 1º: 0-15% (compram pela avaliação)

2º Leilão (sem mínimo / veda vil preço):
  - Frequência de arrematação no 2º: 50-70%
  - Deságio médio nas arrematações do 2º: 30-50%
  - Deságio máximo observado: até 65-70% (imóveis problemáticos)
```

**Leilões Extrajudiciais (Lei 9.514/97 — Bancos):**
```
1º Leilão (mínimo = valor do imóvel, dado em contrato):
  - Frequência de arrematação: 30-50%
  - Deságio médio: 20-35%
  - CEF: deságio médio histórico ~28%

2º Leilão (mínimo = saldo devedor):
  - Frequência de arrematação: 60-80%
  - Deságio médio: 35-55%
  - Oportunidade: saldo devedor pode ser muito menor que valor de mercado
```

**Venda Direta Bancária:**
```
Negociação direta (sem concorrência):
  - Deságio médio: 15-30%
  - Menos competição que leilão
  - Possibilidade de financiamento pelo próprio banco
  - CEF financia até 80% do valor de avaliação nas vendas diretas
```

## Mapa De Deságio Por Situação Do Imóvel

| Situação | Faixa de Deságio |
|----------|-----------------|
| Desocupado, sem débitos, documentação ok | 15-25% |
| Desocupado, débitos quantificados | 25-35% |
| Ocupado (devedor cooperativo) | 30-40% |
| Ocupado (litigioso) + débitos | 40-55% |
| Irregular documentalmente | 35-50% |
| Imóvel em mau estado | 35-55% |
| Combinação de problemas | 50-70% |

---

## Estratégia A — Flip Rápido (Curto Prazo)

**Perfil:** Investidor com capital e rede de compradores finais.

```
Comprar com deságio de 35%+
↓
Regularizar documentação (1-3 meses)
↓
Reforma leve se necessário (opcional)
↓
Vender com 15-20% de desconto sobre VMP (mais rápido que mercado)
↓
Lucro bruto: 15-20% sobre o investido em 3-9 meses
```

**Análise:**
- Retorno bruto esperado: 15-25%
- Prazo: 3-12 meses
- Risco: médio (se imóvel bem selecionado)
- Capital necessário: 100% do lance + custos

## Estratégia B — Reforma E Valorização (Médio Prazo)

**Perfil:** Investidor com capital e conhecimento em obras.

```
Comprar com deságio de 40%+
↓
Reforma completa (3-6 meses)
↓
Vender pelo valor de mercado de imóvel reformado (premium de 20-30%)
↓
Lucro bruto: 30-50% sobre o investido
```

**Análise:**
- Retorno bruto esperado: 30-50%
- Prazo: 6-18 meses
- Risco: médio-alto (risco de obra e mercado)
- Capital necessário: 100% lance + 20-30% do lance em reforma

## Estratégia C — Renda (Longo Prazo)

**Perfil:** Investidor que busca fluxo de caixa passivo.

```
Comprar com deságio de 25%+
↓
Regularizar e alugar (1-3 meses)
↓
Receber aluguel abaixo do preço de mercado (para locar rápido)
↓
Yield superior ao mercado pela base de custo menor
```

**Yield tí
