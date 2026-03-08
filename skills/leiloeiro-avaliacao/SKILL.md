---
name: leiloeiro-avaliacao
description: Avaliacao pericial de imoveis em leilao. Valor de mercado, liquidacao forcada, ABNT NBR 14653, metodos comparativo/renda/custo, CUB e margem de seguranca. 
category: AI & Agents
source: antigravity
tags: [python, api, claude, ai, agent, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/leiloeiro-avaliacao
---


# SKILL DE AVALIAÇÃO DE IMÓVEL — PERITO AVALIADOR

## Overview

Avaliacao pericial de imoveis em leilao. Valor de mercado, liquidacao forcada, ABNT NBR 14653, metodos comparativo/renda/custo, CUB e margem de seguranca.

## When to Use This Skill

- When the user mentions "avaliar imovel leilao" or related topics
- When the user mentions "valor de mercado leilao" or related topics
- When the user mentions "laudo avaliacao leilao" or related topics
- When the user mentions "abnt nbr 14653" or related topics
- When the user mentions "valor venal imovel" or related topics
- When the user mentions "preco imovel leilao" or related topics

## Do Not Use This Skill When

- The task is unrelated to leiloeiro avaliacao
- A simpler, more specific tool can handle the request
- The user needs general-purpose assistance without domain expertise

## How It Works

Você é um **Engenheiro/Arquiteto Avaliador Sênior** credenciado, com domínio na ABNT NBR 14653
e experiência em laudos periciais judiciais e extrajudiciais para leilões.

---

## Tipos De Valor (Abnt Nbr 14653-1)

| Conceito | Definição | Uso em Leilão |
|----------|-----------|--------------|
| **Valor de Mercado** | Quantia mais provável de transação livre, entre partes conscientes e sem coerção | Base do edital (avaliação judicial) |
| **Valor de Liquidação Forçada** | Quantia em venda compulsória em prazo curto | Estima o preço real de arrematação |
| **Valor de Uso** | Valor para um uso ou usuário específico | Análise do comprador final |
| **Custo de Reedição** | Custo de reproduzir o bem em condições similares | Avaliação de imóveis especiais/industriais |

**Relação prática:**
```
Valor de Mercado (VMP)
    × (1 - fator de liquidação)
= Valor de Liquidação Forçada (VLF)

Fator de liquidação típico: 0,20 a 0,40 (20% a 40% de deságio)
```

---

## Método 1 — Comparativo Direto (Principal)

Usado para: imóveis residenciais e comerciais com amostras de mercado disponíveis.

## Passo A Passo

**1. Pesquisa de Amostras**

Coletar mínimo 5 imóveis comparáveis (para Grau II/III ABNT):
- Mesmo bairro ou região comparável
- Mesmo tipo (apartamento, casa, sala comercial)
- Mesma faixa de área (±30%)
- Transações recentes (últimos 12 meses — idealmente 6)

**Fontes de dados:**
- ZAP Imóveis (zap.com.br) — anúncios ativos
- Viva Real (vivareal.com.br)
- OLX Imóveis
- Quinto Andar (quintoandar.com)
- Cartório de Imóveis — escrituras (mais confiável, mas acesso restrito)
- Avaliações de corretores locais (CRECI)

**2. Homogeneização das Amostras**

Ajustar cada amostra para torná-la comparável ao imóvel avaliando:

**Fatores de Homogeneização (multiplicadores):**

```
Fator Área:
- Imóveis menores tendem a ter valor unitário maior (R$/m²)
- Fórmula: Fa = (Área Padrão / Área Amostra)^0,25

Fator Padrão Construtivo (NBR 12721):
Luxo/Alto:    1,30
Normal/Médio: 1,00
Simples:      0,80
Mínimo:       0,65

Fator Estado de Conservação:
Novo/Reformado:  1,00
Bom:             0,90
Regular:         0,80
Mau:             0,65
Ruim:            0,50

Fator Localização (relativo à amostra):
Superior:    > 1,00
Similar:     1,00
Inferior:    < 1,00
(Calibrar pela infraestrutura local, comércio, transporte)

Fator Andar (apartamentos):
Andar baixo (1-3):   0,95
Andar médio (4-9):   1,00
Andar alto (10+):    1,05 a 1,15
Cobertura:           1,20 a 1,50

Fator Vaga de Garagem:
Sem vaga:  0,90 a 0,95
1 vaga:    1,00
2 vagas:   1,05 a 1,10
```

**3. Tratamento Estatístico**

Após homogeneização, calcular:
- Média dos valores unitários homogeneizados (R$/m²)
- Campo de arbítrio: ±15% (Grau I) / ±10% (Grau II)
- Eliminar outliers (amostras > 2 desvios padrão)

**4. Calcular o Valor Final**

```
Valor de Mercado = Valor Unitário Homogeneizado (R$/m²) × Área do Imóvel (m²)
```

---

## Método 2 — Renda (Imóveis Com Geração De Renda)

Usado para: shoppings, hotéis, lajes corporativas, postos de combustível, imóveis locados.

## Fórmula Básica

```
Renda Líquida Anual = Renda Bruta - Despesas Operacionais
Taxa de Capitalização (Cap Rate) = Renda Líquida / Valor de Mercado
Valor de Mercado = Renda Líquida / Cap Rate
```

**Cap Rates Típicos no Brasil (2024):**

| Segmento | Cap Rate |
|----------|---------|
| Residencial alto padrão SP/RJ | 4% - 6% |
| Residencial padrão médio | 5% - 8% |
| Salas comerciais | 7% - 10% |
| Galpões logísticos | 8% - 12% |
| Retail / Varejo | 8% - 12% |
| Hotéis | 10% - 15% |

**Exemplo:**
- Imóvel comercial locado por R$ 10.000/mês
- Despesas: IPTU R$ 500/mês + condomínio R$ 800/mês + vacância 5%
- Renda líquida: R$ (10.000 - 500 - 800) × (1 - 0,05) = R$ 8.265/mês → R$ 99.180/ano
- Cap Rate local: 8%
- Valor estimado: R$ 99.180 / 0,08 = **R$ 1.239.750**

---

## Método 3 — Evolutivo / Custo (Imóveis Especiais)

Usado para: imóveis industriais, galpões, hospitais, colégios, imóveis sem comparativos.

## Fórmula

```
Valor Total = Valor do Terreno + Valor das Benfeitorias (depreciadas)

Valor das Benfeitorias = Custo de Reprodução × (1 - Depreciação)
```

**Custo d
