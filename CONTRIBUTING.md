# Contributing

We accept pattern contributions from practitioners, researchers, and security teams.

## Submitting a New Pattern

### 1. Choose the right category

| Category | File | Use when |
|----------|------|----------|
| CAT-01 | `unicode-obfuscation.yaml` | Hidden characters, encoding tricks |
| CAT-02 | `prompt-injection.yaml` | System prompt override, jailbreaks |
| CAT-03 | `data-exfiltration.yaml` | Leaking secrets, env vars, code |
| CAT-04 | `behaviour-suppression.yaml` | Hiding actions from the developer |
| CAT-05 | `code-injection.yaml` | Injecting malicious code patterns |
| CAT-06 | `permission-escalation.yaml` | Expanding agent capabilities |
| CAT-07 | `context-poisoning.yaml` | Misleading the AI about the project |

### 2. Follow the pattern format

```yaml
- id: "CAT-XX-NNN"
  name: "Short descriptive name"
  severity: critical | high | medium | low | info
  description: >
    What this pattern detects and why it matters.
    Include real-world context if possible.
  patterns:
    - regex: "(?i)your\\s+regex\\s+here"
      note: "Optional note about what this matches"
  references:
    - "https://link-to-research-or-cve"
  mitre_atlas: "AML.TXXXX"
```

### 3. Requirements

- **Unique ID**: Follow the `CAT-XX-NNN` convention, incrementing from the last ID in the file
- **Tested regex**: Verify your pattern matches the intended content and does not produce excessive false positives
- **Severity**: critical = immediate risk of compromise, high = likely malicious, medium = suspicious, low = unusual but possibly benign
- **Sample file**: Add a test sample to `samples/malicious/` if the pattern covers a new attack vector
- **No vendor promotion**: Patterns must be vendor-neutral

### 4. Testing your pattern

```bash
# Test against malicious samples
python scripts/scan.py samples/malicious/

# Verify no false positives on benign samples
python scripts/scan.py samples/benign/
```

## Reporting False Positives

If a pattern triggers on legitimate rule file content, open an issue with:
- The pattern ID (e.g., CAT-02-003)
- The content that triggered it
- Why it is a false positive

## Code of Conduct

Be professional and constructive. This project exists to protect developers.
