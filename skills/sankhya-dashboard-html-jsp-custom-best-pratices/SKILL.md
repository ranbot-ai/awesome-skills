---
name: sankhya-dashboard-html-jsp-custom-best-pratices
description: This skill should be used when the user asks for patterns, best practices, creation, or fixing of Sankhya dashboards using HTML, JSP, Java, and SQL. 
category: Document Processing
source: antigravity
tags: [javascript, react, ai, agent, design, document, image, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/sankhya-dashboard-html-jsp-custom-best-pratices
---


# sankhya-dashboard-html-jsp-custom-best-pratices

## Purpose

To provide a consolidated guide of patterns and best practices for creating and maintaining dashboards, SQL queries, BI parameterization, and UI/UX within the Sankhya ecosystem (JSP/HTML/Java).

## When to Use This Skill

This skill should be used when:
- The user asks about "boas praticas do sankhya" or "Sankhya best practices".
- The user mentions "dashboard sankhya" or is working on a Sankhya BI dashboard.
- The user asks for anything related to the word "Sankhya".
- The user wants to create or modify code files for Sankhya dashboards.

## Core Capabilities

1. **Code Generation & Review**: Apply JSP/JSTL patterns and server-side organization to reduce compilation errors and rendering failures.
2. **Visual Consistency**: Standardize visual identity in BI components using predefined CSS tokens.
3. **Database Exploration**: Structure data exploration queries for performance and correct mapping of Sankhya entities.
4. **BI Construction Guide**: Use the HTML5 component flow in BI to ensure correct rendering, reactivity, and navigation.

## Patterns

### Melhores Práticas de Código
Aplicar padrões de JSP/JSTL e organização server-side para reduzir erros de compilação, falhas de renderização e regressões em dashboards/telas.

**Diretrizes de implementação**
- Declarar diretivas JSP e taglibs obrigatórias no topo do arquivo.
- Forçar `isELIgnored="false"` para habilitar `${...}` em tempo de renderização.
- Preferir `core_rt` para JSTL core no ecossistema Sankhya.
- Evitar scriptlets Java em JSP; usar JSTL (`c:if`, `c:choose`, `c:forEach`).
- Modularizar lógica de negócio (camadas/serviços), evitando acoplamento em arquivo único.
- Evitar hardcode de credenciais, URLs sensíveis e tokens.
- Modelar estado global da UI (dados, filtros, ordenação, aba ativa) e resetar estado antes de novo carregamento.
- Persistir preferências de visualização no `localStorage` (ordem de colunas e ordenação).
- Implementar carregamento sob demanda para abas/modais pesados (lazy-load) para reduzir tempo inicial.
- **Blindagem de Parâmetros**: Sempre definir um valor padrão (fallback) para parâmetros de URL via `c:set` para evitar Erro 500 no servidor Java do Sankhya.
- **Separação de Camadas (JSP vs JS)**: Evitar injetar tags JSP diretamente dentro de blocos `<script>`. Utilizar containers HTML ocultos para passar dados ao JavaScript, mantendo a saúde do editor de código (IDE Linting).

> Os nomes de tabelas e campos abaixo são representativos e podem variar conforme a implementação da instância.

```jsp
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" isELIgnored="false" %>
<%@ taglib prefix="snk" uri="/WEB-INF/tld/sankhyaUtil.tld" %>
<%@ taglib uri="http://java.sun.com/jstl/core_rt" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>
<snk:load />
```

**Carregamento de assets em dashboard/gadget**
- Referenciar arquivos com `contextPath` + `BASE_FOLDER`.
- Em níveis secundários (`openLevel`), manter caminho absoluto para evitar quebra de resolução.

```html
<script src="${pageContext.request.contextPath}/${BASE_FOLDER}/js/app.js"></script>
<link rel="stylesheet" href="${pageContext.request.contextPath}/${BASE_FOLDER}/css/style.css" />
```

**Consumo seguro de `snk:query`**
- Iterar em `query.rows` (não no objeto raiz).
- Testar vazio com `empty query.rows`.

```jsp
<snk:query var="qDados">
    SELECT CAB.NUNOTA, CAB.CODPARC
      FROM TGFCAB CAB
</snk:query>

<c:choose>
    <c:when test="${empty qDados.rows}">
        <span>Sem resultados</span>
    </c:when>
    <c:otherwise>
        <c:forEach var="linha" items="${qDados.rows}">
            ${linha.NUNOTA}
        </c:forEach>
    </c:otherwise>
</c:choose>
```

**Sanitização de parâmetros antes da SQL**
- Normalizar valor de entrada.
- Remover aspas (`"` e `&quot;`) antes de injetar em query.
- Definir fallback seguro para evitar SQL inválida.

```jsp
<c:set var="raw_codusu" value="${empty param.P_CODUSU ? '0' : param.P_CODUSU}" />
<c:set var="codusu_limpo" value="${fn:replace(raw_codusu, '\"', '')}" />
<c:set var="codusu_limpo" value="${fn:replace(codusu_limpo, '&quot;', '')}" />
<c:set var="codusu_seguro" value="${empty codusu_limpo ? '0' : codusu_limpo}" />

<snk:query var="qAcessos">
    SELECT CODUSU, NOMEUSU
      FROM TSIUSU
     WHERE CODUSU = :codusu_seguro
</snk:query>
```

**Estado de tela e lazy-load em dashboard único**
- Definir listas globais para reutilização em KPI, gráfico, tabela e modais.
- Guardar flag de carregamento por aba para evitar reconsultas desnecessárias.
- Recarregar dados e reabrir o contexto (produto/aba) após atualização transacional.

```js
var dadosGlobais = [];
var produtoAtual = null;
var abaCarregada = {};

function abrirDetalhe(dado) {
  produtoAtual = dado;
  abaCarregada = {};
  trocarAba("estoque");
}

function trocarAba(aba) {
  if (aba === "estoque" && !abaCarregada.estoque) carregarAbaEstoque(produtoAt
