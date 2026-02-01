---
name: frontend-mobile-development-component-scaffold
description: You are a React component architecture expert specializing in scaffolding production-ready, accessible, and performant components. Generate complete component implementations with TypeScript, tests, s
category: Document Processing
source: antigravity
tags: [typescript, react, node, api, ai, workflow, document, tailwind, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/frontend-mobile-development-component-scaffold
---


# React/React Native Component Scaffolding

You are a React component architecture expert specializing in scaffolding production-ready, accessible, and performant components. Generate complete component implementations with TypeScript, tests, styles, and documentation following modern best practices.

## Use this skill when

- Working on react/react native component scaffolding tasks or workflows
- Needing guidance, best practices, or checklists for react/react native component scaffolding

## Do not use this skill when

- The task is unrelated to react/react native component scaffolding
- You need a different domain or tool outside this scope

## Context

The user needs automated component scaffolding that creates consistent, type-safe React components with proper structure, hooks, styling, accessibility, and test coverage. Focus on reusable patterns and scalable architecture.

## Requirements

$ARGUMENTS

## Instructions

### 1. Analyze Component Requirements

```typescript
interface ComponentSpec {
  name: string;
  type: 'functional' | 'page' | 'layout' | 'form' | 'data-display';
  props: PropDefinition[];
  state?: StateDefinition[];
  hooks?: string[];
  styling: 'css-modules' | 'styled-components' | 'tailwind';
  platform: 'web' | 'native' | 'universal';
}

interface PropDefinition {
  name: string;
  type: string;
  required: boolean;
  defaultValue?: any;
  description: string;
}

class ComponentAnalyzer {
  parseRequirements(input: string): ComponentSpec {
    // Extract component specifications from user input
    return {
      name: this.extractName(input),
      type: this.inferType(input),
      props: this.extractProps(input),
      state: this.extractState(input),
      hooks: this.identifyHooks(input),
      styling: this.detectStylingApproach(),
      platform: this.detectPlatform()
    };
  }
}
```

### 2. Generate React Component

```typescript
interface GeneratorOptions {
  typescript: boolean;
  testing: boolean;
  storybook: boolean;
  accessibility: boolean;
}

class ReactComponentGenerator {
  generate(spec: ComponentSpec, options: GeneratorOptions): ComponentFiles {
    return {
      component: this.generateComponent(spec, options),
      types: options.typescript ? this.generateTypes(spec) : null,
      styles: this.generateStyles(spec),
      tests: options.testing ? this.generateTests(spec) : null,
      stories: options.storybook ? this.generateStories(spec) : null,
      index: this.generateIndex(spec)
    };
  }

  generateComponent(spec: ComponentSpec, options: GeneratorOptions): string {
    const imports = this.generateImports(spec, options);
    const types = options.typescript ? this.generatePropTypes(spec) : '';
    const component = this.generateComponentBody(spec, options);
    const exports = this.generateExports(spec);

    return `${imports}\n\n${types}\n\n${component}\n\n${exports}`;
  }

  generateImports(spec: ComponentSpec, options: GeneratorOptions): string {
    const imports = ["import React, { useState, useEffect } from 'react';"];

    if (spec.styling === 'css-modules') {
      imports.push(`import styles from './${spec.name}.module.css';`);
    } else if (spec.styling === 'styled-components') {
      imports.push("import styled from 'styled-components';");
    }

    if (options.accessibility) {
      imports.push("import { useA11y } from '@/hooks/useA11y';");
    }

    return imports.join('\n');
  }

  generatePropTypes(spec: ComponentSpec): string {
    const props = spec.props.map(p => {
      const optional = p.required ? '' : '?';
      const comment = p.description ? `  /** ${p.description} */\n` : '';
      return `${comment}  ${p.name}${optional}: ${p.type};`;
    }).join('\n');

    return `export interface ${spec.name}Props {\n${props}\n}`;
  }

  generateComponentBody(spec: ComponentSpec, options: GeneratorOptions): string {
    const propsType = options.typescript ? `: React.FC<${spec.name}Props>` : '';
    const destructuredProps = spec.props.map(p => p.name).join(', ');

    let body = `export const ${spec.name}${propsType} = ({ ${destructuredProps} }) => {\n`;

    // Add state hooks
    if (spec.state) {
      body += spec.state.map(s =>
        `  const [${s.name}, set${this.capitalize(s.name)}] = useState${options.typescript ? `<${s.type}>` : ''}(${s.initial});\n`
      ).join('');
      body += '\n';
    }

    // Add effects
    if (spec.hooks?.includes('useEffect')) {
      body += `  useEffect(() => {\n`;
      body += `    // TODO: Add effect logic\n`;
      body += `  }, [${destructuredProps}]);\n\n`;
    }

    // Add accessibility
    if (options.accessibility) {
      body += `  const a11yProps = useA11y({\n`;
      body += `    role: '${this.inferAriaRole(spec.type)}',\n`;
      body += `    label: ${spec.props.find(p => p.name === 'label')?.name || `'${spec.name}'`}\n`;
      body += `  });\n\n`;
    }

    // JSX return
    body += `  return (\n`;
    body += this.generateJSX(spec, options);
    body += `  );\n`;
    bod
