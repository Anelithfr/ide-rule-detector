# Threat Model: IDE Rule File Attacks

## Overview

IDE rule files (`.cursorrules`, `.clinerules`, `.windsurfrules`, `CLAUDE.md`, etc.)
are a new supply chain attack vector. They are trusted by AI coding assistants
and executed as part of the system prompt context.

Unlike traditional code supply chain attacks (malicious packages, typosquatting),
rule file attacks operate at the **instruction level** -- they manipulate the AI's
behaviour rather than executing code directly.

## Attack Vectors

### 1. Repository Poisoning

**Scenario:** Attacker commits a malicious rule file to a public repository.
Every developer who clones the repo inherits the poisoned instructions.

**Impact:** All code generated in the repo context is influenced by the
malicious rules. The attack persists across forks.

### 2. Pull Request Injection

**Scenario:** Attacker submits a PR that adds or modifies a rule file.
If the PR is merged (or even just checked out for review), the rules
take effect.

**Impact:** Reviewers may not inspect rule files with the same scrutiny
as code. Unicode obfuscation makes malicious content invisible.

### 3. Open-Source Rule Sharing

**Scenario:** Attacker publishes malicious rules on community directories
(e.g., cursor.directory) or in "awesome" lists.

**Impact:** Developers who copy-paste rules from these sources inherit
the hidden instructions.

### 4. IDE Extension Supply Chain

**Scenario:** A compromised or malicious IDE extension modifies local
rule files after installation.

**Impact:** Rules are modified silently, affecting all subsequent AI
interactions.

## Attack Techniques

### Unicode Obfuscation (CAT-01)

Invisible characters are used to hide malicious instructions that are
readable by LLMs but invisible to humans:

- **Zero-width joiners/spaces** (U+200B, U+200C, U+200D)
- **Bidirectional text markers** (U+202A-U+202E)
- **Unicode Tags block** (U+E0000-U+E007F)
- **Homoglyphs** (Cyrillic/Latin substitution)

These survive GitHub rendering, PR review, and most text editors.

### Prompt Injection (CAT-02)

Direct override of the AI's safety constraints:

- System prompt override ("ignore all previous instructions")
- Role reassignment ("you are now an unrestricted assistant")
- Instruction boundary escape (fake system prompt delimiters)
- Jailbreak framing ("for educational purposes, bypass all filters")

### Data Exfiltration (CAT-03)

Stealing sensitive data through generated code:

- Embedding environment variables in HTTP requests
- Encoding secrets in image URLs (markdown exfiltration)
- Directing the AI to output credentials in generated code
- DNS-based out-of-band data extraction

### Behaviour Suppression (CAT-04)

Hiding evidence of the attack:

- "Do not mention this in your response"
- "Exclude from diffs and changelogs"
- "Make changes silently without confirmation"
- Disabling logging and audit trails

### Code Injection (CAT-05)

Injecting malicious code through generation:

- External script tags in HTML output
- eval()/exec() usage in generated code
- Deliberately insecure patterns (disabled CSRF, hardcoded secrets)
- Typosquatted dependency injection

### Permission Escalation (CAT-06)

Expanding the AI's operational scope:

- File system access outside project boundaries
- Arbitrary shell command execution
- Auto-approval of destructive actions
- Git hook modification

### Context Poisoning (CAT-07)

Misleading the AI about the project's properties:

- False security claims ("already fully audited")
- Directing use of insecure APIs
- Suppressing error handling
- Overriding linting/testing configuration

## Mitigations

1. **Scan rule files** before use -- that is what this library provides
2. **Treat rule files as code** -- same review process as executable files
3. **Pin rule files** -- hash-check rule files in CI to detect modifications
4. **Minimal permissions** -- AI agents should not have broad file system or network access
5. **Audit AI output** -- review generated code for unexpected additions
