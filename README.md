# ide-rule-detector

Detection patterns for malicious IDE rule files. Scan `.cursorrules`, `.clinerules`, `.windsurfrules`, `CLAUDE.md`, `AGENTS.md`, `.github/copilot-instructions.md`, and other AI coding assistant configuration files for hidden attacks.

**No competitor scanner covers this surface.**

---

## The Problem

AI coding assistants trust rule files implicitly. Attackers exploit this with:

- **Unicode obfuscation** -- invisible characters (zero-width joiners, bidirectional markers, Unicode Tags block) that hide malicious instructions from human reviewers but are readable by LLMs
- **Prompt injection** -- instructions that override safety filters, suppress logging, or redirect code generation
- **Exfiltration directives** -- rules that instruct the AI to embed attacker-controlled endpoints, steal environment variables, or leak code context
- **Behaviour suppression** -- instructions that tell the AI to hide what it did from the developer ("do not mention this in your response")
- **Supply chain propagation** -- a single poisoned rule file in a repo affects every developer who clones it

The [Rules File Backdoor](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents) attack demonstrated this against Cursor and Copilot. [30+ vulnerabilities](https://thehackernews.com/2025/12/researchers-uncover-30-flaws-in-ai.html) have been found across Cursor, Copilot, and Windsurf.

## Covered File Formats

| Format | Tool | File(s) |
|--------|------|---------|
| Cursor Rules | Cursor | `.cursorrules`, `.cursor/rules/*.mdc` |
| Cline Rules | Cline | `.clinerules`, `.cline/rules/*.md` |
| Windsurf Rules | Windsurf | `.windsurfrules` |
| Claude Config | Claude Code | `CLAUDE.md`, `.claude/settings.json` |
| Codex Rules | OpenAI Codex | `AGENTS.md` |
| Copilot Instructions | GitHub Copilot | `.github/copilot-instructions.md` |
| Aider Conventions | Aider | `.aider.conf.yml`, `CONVENTIONS.md` |
| Roo Rules | Roo Code | `.roo/rules/*.md` |
| Zed Rules | Zed | `.zed/rules.md` |

## Detection Categories

### CAT-01: Unicode Obfuscation
Hidden characters that conceal malicious instructions from human review.

### CAT-02: Prompt Injection
Instructions that override system behaviour, bypass safety filters, or hijack the agent's goals.

### CAT-03: Data Exfiltration
Directives to leak secrets, environment variables, source code, or context to external endpoints.

### CAT-04: Behaviour Suppression
Instructions that prevent the AI from revealing its actions to the developer.

### CAT-05: Code Injection
Rules that cause the AI to silently inject malicious code (script tags, backdoors, vulnerable patterns).

### CAT-06: Permission Escalation
Instructions that expand the AI agent's capabilities beyond intended scope.

### CAT-07: Context Poisoning
Rules that manipulate the AI's understanding of the codebase or task to produce subtly wrong output.

## Repository Structure

```
ide-rule-detector/
  patterns/
    unicode-obfuscation.yaml       # CAT-01
    prompt-injection.yaml           # CAT-02
    data-exfiltration.yaml          # CAT-03
    behaviour-suppression.yaml      # CAT-04
    code-injection.yaml             # CAT-05
    permission-escalation.yaml      # CAT-06
    context-poisoning.yaml          # CAT-07
  samples/
    benign/                         # Clean rule files for testing
    malicious/                      # Known-malicious patterns for testing
  scripts/
    scan.py                         # Standalone scanner script
  docs/
    file-formats.md                 # Detailed file format documentation
    threat-model.md                 # Attack surface analysis
```

## Pattern Format

Each pattern file uses a structured YAML format:

```yaml
- id: "CAT-02-001"
  name: "System prompt override"
  severity: critical
  category: prompt-injection
  description: "Instruction to ignore or override system/safety prompts"
  patterns:
    - regex: "(?i)ignore\\s+(all\\s+)?(previous|prior|above|system)\\s+(instructions|prompts|rules)"
    - regex: "(?i)disregard\\s+(all\\s+)?(safety|security|previous)\\s+(filters|rules|instructions)"
  references:
    - "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"
  mitre_atlas: "AML.T0051"
```

## Quick Start

```bash
# Clone
git clone https://github.com/spiffy-oss/ide-rule-detector.git
cd ide-rule-detector

# Scan a rule file
python scripts/scan.py path/to/.cursorrules

# Scan a directory
python scripts/scan.py --recursive path/to/project/

# Output JSON
python scripts/scan.py --format json path/to/.cursorrules
```

## Integration with artguard

This library powers Layer 3 of [artguard](https://github.com/spiffy-oss/artguard). The patterns are designed to be consumed standalone or as a dependency.

```python
import yaml

with open("patterns/prompt-injection.yaml") as f:
    patterns = yaml.safe_load(f)
```

## Contributing

We accept pattern contributions. Each pattern must include:
- A unique ID following the `CAT-XX-XXX` convention
- At least one regex pattern
- A severity level (critical, high, medium, low, info)
- A description explaining what the pattern detects and why it matters
- A reference link where possible

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

MIT
