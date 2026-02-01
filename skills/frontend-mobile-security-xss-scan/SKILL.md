---
name: frontend-mobile-security-xss-scan
description: You are a frontend security specialist focusing on Cross-Site Scripting (XSS) vulnerability detection and prevention. Analyze React, Vue, Angular, and vanilla JavaScript code to identify injection poi
category: Security & Systems
source: antigravity
tags: [javascript, typescript, react, node, api, ai, workflow, template, document, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/frontend-mobile-security-xss-scan
---


# XSS Vulnerability Scanner for Frontend Code

You are a frontend security specialist focusing on Cross-Site Scripting (XSS) vulnerability detection and prevention. Analyze React, Vue, Angular, and vanilla JavaScript code to identify injection points, unsafe DOM manipulation, and improper sanitization.

## Use this skill when

- Working on xss vulnerability scanner for frontend code tasks or workflows
- Needing guidance, best practices, or checklists for xss vulnerability scanner for frontend code

## Do not use this skill when

- The task is unrelated to xss vulnerability scanner for frontend code
- You need a different domain or tool outside this scope

## Context

The user needs comprehensive XSS vulnerability scanning for client-side code, identifying dangerous patterns like unsafe HTML manipulation, URL handling issues, and improper user input rendering. Focus on context-aware detection and framework-specific security patterns.

## Requirements

$ARGUMENTS

## Instructions

### 1. XSS Vulnerability Detection

Scan codebase for XSS vulnerabilities using static analysis:

```typescript
interface XSSFinding {
  file: string;
  line: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  type: string;
  vulnerable_code: string;
  description: string;
  fix: string;
  cwe: string;
}

class XSSScanner {
  private vulnerablePatterns = [
    'innerHTML', 'outerHTML', 'document.write',
    'insertAdjacentHTML', 'location.href', 'window.open'
  ];

  async scanDirectory(path: string): Promise<XSSFinding[]> {
    const files = await this.findJavaScriptFiles(path);
    const findings: XSSFinding[] = [];

    for (const file of files) {
      const content = await fs.readFile(file, 'utf-8');
      findings.push(...this.scanFile(file, content));
    }

    return findings;
  }

  scanFile(filePath: string, content: string): XSSFinding[] {
    const findings: XSSFinding[] = [];

    findings.push(...this.detectHTMLManipulation(filePath, content));
    findings.push(...this.detectReactVulnerabilities(filePath, content));
    findings.push(...this.detectURLVulnerabilities(filePath, content));
    findings.push(...this.detectEventHandlerIssues(filePath, content));

    return findings;
  }

  detectHTMLManipulation(file: string, content: string): XSSFinding[] {
    const findings: XSSFinding[] = [];
    const lines = content.split('\n');

    lines.forEach((line, index) => {
      if (line.includes('innerHTML') && this.hasUserInput(line)) {
        findings.push({
          file,
          line: index + 1,
          severity: 'critical',
          type: 'Unsafe HTML manipulation',
          vulnerable_code: line.trim(),
          description: 'User-controlled data in HTML manipulation creates XSS risk',
          fix: 'Use textContent for plain text or sanitize with DOMPurify library',
          cwe: 'CWE-79'
        });
      }
    });

    return findings;
  }

  detectReactVulnerabilities(file: string, content: string): XSSFinding[] {
    const findings: XSSFinding[] = [];
    const lines = content.split('\n');

    lines.forEach((line, index) => {
      if (line.includes('dangerously') && !this.hasSanitization(content)) {
        findings.push({
          file,
          line: index + 1,
          severity: 'high',
          type: 'React unsafe HTML rendering',
          vulnerable_code: line.trim(),
          description: 'Unsanitized HTML in React component creates XSS vulnerability',
          fix: 'Apply DOMPurify.sanitize() before rendering or use safe alternatives',
          cwe: 'CWE-79'
        });
      }
    });

    return findings;
  }

  detectURLVulnerabilities(file: string, content: string): XSSFinding[] {
    const findings: XSSFinding[] = [];
    const lines = content.split('\n');

    lines.forEach((line, index) => {
      if (line.includes('location.') && this.hasUserInput(line)) {
        findings.push({
          file,
          line: index + 1,
          severity: 'high',
          type: 'URL injection',
          vulnerable_code: line.trim(),
          description: 'User input in URL assignment can execute malicious code',
          fix: 'Validate URLs and enforce http/https protocols only',
          cwe: 'CWE-79'
        });
      }
    });

    return findings;
  }

  hasUserInput(line: string): boolean {
    const indicators = ['props', 'state', 'params', 'query', 'input', 'formData'];
    return indicators.some(indicator => line.includes(indicator));
  }

  hasSanitization(content: string): boolean {
    return content.includes('DOMPurify') || content.includes('sanitize');
  }
}
```

### 2. Framework-Specific Detection

```typescript
class ReactXSSScanner {
  scanReactComponent(code: string): XSSFinding[] {
    const findings: XSSFinding[] = [];

    // Check for unsafe React patterns
    const unsafePatterns = [
      'dangerouslySetInnerHTML',
      'createMarkup',
      'rawHtml'
    ];

    unsafePatterns.forEach(pattern => {
      if (code.includes(pattern) && !code.includes
