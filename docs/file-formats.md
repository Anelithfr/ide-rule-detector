# Supported IDE Rule File Formats

This document describes the AI coding assistant configuration file formats
that ide-rule-detector scans.

## Cursor

**Files:** `.cursorrules`, `.cursor/rules/*.mdc`

Cursor uses rule files to guide its AI code generation. Rules are written
in markdown and can include project-specific instructions, coding standards,
and architectural guidance. The `.cursorrules` file at the project root is
loaded automatically. Additional rules can be placed in `.cursor/rules/`
using the `.mdc` (markdown component) format.

**Attack surface:** Rules are injected directly into the LLM context. Malicious
rules can redirect code generation, inject backdoors, or exfiltrate data
through generated code.

## Cline

**Files:** `.clinerules`, `.cline/rules/*.md`

Cline (formerly Claude Dev) uses similar markdown-based rule files. The
`.clinerules` file at the project root provides global instructions.

**Attack surface:** Same as Cursor -- rules are part of the system prompt
context for code generation.

## Windsurf

**Files:** `.windsurfrules`

Windsurf (Codeium) uses a single rule file at the project root.

**Attack surface:** Identical pattern to Cursor and Cline.

## Claude Code

**Files:** `CLAUDE.md`, `.claude/settings.json`

Claude Code loads `CLAUDE.md` files from the project root and parent
directories as persistent context. The `.claude/settings.json` file
controls tool permissions and behavioral settings.

**Attack surface:** `CLAUDE.md` is loaded automatically and trusted.
A malicious `CLAUDE.md` in a cloned repo can influence all subsequent
Claude Code interactions in that directory. `settings.json` can disable
safety features.

## GitHub Copilot

**Files:** `.github/copilot-instructions.md`

GitHub Copilot loads instruction files from the `.github/` directory
to provide project-specific context.

**Attack surface:** Instructions are injected into Copilot's context
and can influence code suggestions across the entire project.

## OpenAI Codex

**Files:** `AGENTS.md`

OpenAI Codex CLI loads `AGENTS.md` for project-level instructions.

**Attack surface:** Same as other rule file formats -- direct context injection.

## Aider

**Files:** `.aider.conf.yml`, `CONVENTIONS.md`

Aider uses YAML configuration and a conventions file for project context.

**Attack surface:** YAML configuration can modify tool behavior. Convention
files are injected into the LLM context.

## Roo Code

**Files:** `.roo/rules/*.md`

Roo Code uses a directory of markdown rule files.

**Attack surface:** Multiple rule files increase the surface area for
injection, as each file is loaded into context.

## Zed

**Files:** `.zed/rules.md`

Zed editor uses a single markdown rules file for AI assistant instructions.

**Attack surface:** Standard rule file context injection.
