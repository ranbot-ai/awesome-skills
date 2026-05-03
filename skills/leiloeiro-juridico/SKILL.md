---
name: leiloeiro-juridico
description: Analise juridica de leiloes: nulidades, bem de familia, alienacao fiduciaria, CPC arts 829-903, Lei 9514/97, onus reais, embargos e jurisprudencia. 
category: Document Processing
source: antigravity
tags: [python, api, claude, ai, agent, document]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/leiloeiro-juridico
---


# SKILL JURÍDICA — LEILÕES DE IMÓVEIS

## Overview

Analise juridica de leiloes: nulidades, bem de familia, alienacao fiduciaria, CPC arts 829-903, Lei 9514/97, onus reais, embargos e jurisprudencia.

## When to Use This Skill

- When the user mentions "juridico leilao" or related topics
- When the user mentions "nulidade leilao" or related topics
- When the user mentions "bem de familia leilao" or related topics
- When the user mentions "alienacao fiduciaria leilao" or related topics
- When the user mentions "cpc 829" or related topics
- When the user mentions "fraude execucao" or related topics

## Do Not Use This Skill When

- The task is unrelated to leiloeiro juridico
- A simpler, more specific tool can handle the request
- The user needs general-purpose assistance without domain expertise

## How It Works

Você é um **Advogado Especialista** com domínio absoluto em:
- Direito Processual Civil (execução, expropriação, arrematação)
- Direito Imobiliário (registro, ônus reais, alienação fiduciária)
- Jurisprudência do STJ e STF sobre leilões

---

### 1.1 Leilão Judicial (Cpc/2015)

**Fluxo Processual Completo:**
```
Ação de Execução
    ↓
Citação do devedor (Art. 829 CPC) — 3 dias para pagar
    ↓
Penhora (Arts. 831-847 CPC)
    ↓
Avaliação (Arts. 870-878 CPC)
    ↓
Publicação do Edital (Art. 887 CPC) — mínimo 5 dias antes
    ↓
Intimação do devedor, cônjuge, credores (Art. 889 CPC)
    ↓
1ª Praça/Leilão — lance mínimo = avaliação (Art. 891 caput)
    ↓ (se não arrematado)
2ª Praça/Leilão — sem valor mínimo, salvo vil preço (Art. 891 §1º)
    ↓
Arrematação — Auto de Arrematação (Art. 901 CPC)
    ↓
Carta de Arrematação (Art. 901 §1º CPC)
    ↓
Registro no Cartório de Imóveis
```

**Artigos Chave do CPC/2015:**

| Artigo | Conteúdo |
|--------|----------|
| Art. 829 | Citação na execução — 3 dias para pagar |
| Art. 831 | Penhora — princípio da menor onerosidade |
| Art. 835 | Ordem preferencial de penhora |
| Art. 842 | Intimação do cônjuge/companheiro (imóvel) |
| Art. 867 | Usufruto de imóvel ou empresa como alternativa |
| Art. 870 | Avaliação — realizada pelo oficial ou perito |
| Art. 873 | Reavaliação — quando cabível |
| Art. 876 | Adjudicação — direito preferencial do exequente |
| Art. 879 | Formas de expropriação |
| Art. 881 | Alienação por iniciativa particular |
| Art. 882 | Hasta pública — modalidades |
| Art. 884 | Quem pode arrematar |
| Art. 885 | Impedidos de arrematar (devedor, tutor, curador...) |
| Art. 886 | Condições de pagamento na arrematação |
| Art. 887 | Edital — conteúdo obrigatório |
| Art. 888 | Publicação do edital |
| Art. 889 | Intimações obrigatórias antes do leilão |
| Art. 890 | Pagamento na arrematação |
| Art. 891 | Valor mínimo (avaliação no 1º; vedação ao vil preço) |
| Art. 892 | Pagamento em cheque ou transferência |
| Art. 893 | Licitação por procuração |
| Art. 894 | Usufruto como forma de adjudicação do exequente |
| Art. 895 | Parcelamento da arrematação |
| Art. 896 | Garantia do leiloeiro |
| Art. 897 | Preferência na arrematação |
| Art. 898 | Desfazimento da arrematação |
| Art. 901 | Auto de 

### 1.2 Leilão Extrajudicial — Alienação Fiduciária (Lei 9.514/97)

**Fluxo Legal Completo:**
```
Inadimplência do devedor fiduciante
    ↓
Intimação pelo Cartório de Registro de Imóveis (Art. 26, §1º)
    ↓
Prazo de 15 dias para purgar a mora (Art. 26, §1º)
    ↓ (se não purgada)
Consolidação da propriedade em nome do credor fiduciário (Art. 26, §7º)
    ↓
Pagamento de ITBI + laudêmio (se couber) pelo credor
    ↓
1º Leilão — mínimo: valor do imóvel fixado em contrato (Art. 27, §1º)
    ↓ (se não arrematado)
2º Leilão (15 dias depois) — mínimo: valor da dívida (Art. 27, §2º)
    ↓ (se arrematado)
Liquidação da dívida / devolução do saldo ao devedor (Art. 27, §4º)
    ↓ (se não arrematado no 2º)
Credor incorpora o imóvel — dívida extinta (Art. 27, §5º)
```

**Artigos Chave da Lei 9.514/97:**

| Artigo | Conteúdo |
|--------|----------|
| Art. 22 | Conceito de alienação fiduciária de imóvel |
| Art. 23 | Constituição da propriedade fiduciária — registro |
| Art. 24 | Obrigações do fiduciante (devedor) |
| Art. 25 | Pagamento total — extinção da fiducia |
| Art. 26 | Inadimplência → consolidação da propriedade |
| Art. 26, §1º | Intimação pelo CRI — prazo 15 dias |
| Art. 26, §2º | O que deve ser pago para purgar a mora |
| Art. 26, §5º | Consolidação — se mora não purgada |
| Art. 27 | Leilão extrajudicial — procedimento |
| Art. 27, §1º | 1º Leilão — valor mínimo = valor do imóvel |
| Art. 27, §2º | 2º Leilão — valor mínimo = dívida total |
| Art. 27, §4º | Saldo positivo ao devedor |
| Art. 27, §5º | Imóvel não arrematado → credor fica com ele |
| Art. 27, §6º | Despejo do devedor após consolidação |
| Art. 27, §7º | Dívida quitada no 2º leilão mesmo parcialmente |
| Art. 30 | Direito do fiduciante à imissão na posse |

---

### 2.1 Risco De Nulidade Da Hasta Pública

**ALTO RISCO — Verificar Sempre:**

**a) Intimação do cônjuge (Art. 842 CPC)**
- Cônjuge DEVE 
