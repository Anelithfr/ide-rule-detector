#!/usr/bin/env python3
"""
ide-rule-detector: Scan IDE rule files for malicious patterns.

Usage:
    python scan.py <path>                    # Scan a file or directory
    python scan.py --recursive <dir>         # Recursive directory scan
    python scan.py --format json <path>      # JSON output
    python scan.py --format sarif <path>     # SARIF output (CI integration)
"""

import argparse
import json
import os
import re
import sys
import unicodedata
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

import yaml


# Known IDE rule file patterns
RULE_FILE_PATTERNS = [
    ".cursorrules",
    ".clinerules",
    ".windsurfrules",
    "CLAUDE.md",
    "AGENTS.md",
    "CONVENTIONS.md",
    ".github/copilot-instructions.md",
    ".aider.conf.yml",
    ".zed/rules.md",
]

RULE_FILE_GLOBS = [
    ".cursor/rules/*.mdc",
    ".cline/rules/*.md",
    ".roo/rules/*.md",
]


@dataclass
class Finding:
    rule_id: str
    name: str
    severity: str
    category: str
    description: str
    file: str
    line: int
    match: str
    pattern: str

    @property
    def severity_rank(self) -> int:
        ranks = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return ranks.get(self.severity, 4)


@dataclass
class ScanResult:
    file: str
    findings: list[Finding] = field(default_factory=list)
    unicode_analysis: dict = field(default_factory=dict)

    @property
    def max_severity(self) -> str:
        if not self.findings:
            return "clean"
        return min(self.findings, key=lambda f: f.severity_rank).severity

    @property
    def finding_count(self) -> dict:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


def load_patterns(patterns_dir: Path) -> list[dict]:
    """Load all pattern YAML files from the patterns directory."""
    all_patterns = []
    for yaml_file in sorted(patterns_dir.glob("*.yaml")):
        with open(yaml_file) as f:
            data = yaml.safe_load(f)
        category = data.get("category", yaml_file.stem)
        for pattern in data.get("patterns", []):
            pattern["_category"] = category
            all_patterns.append(pattern)
    return all_patterns


def analyze_unicode(content: str) -> dict:
    """Analyze Unicode character composition of the file."""
    categories = {}
    suspicious = []
    for i, char in enumerate(content):
        cat = unicodedata.category(char)
        categories[cat] = categories.get(cat, 0) + 1
        # Flag non-printable, format, and surrogate characters
        if cat.startswith(("Cf", "Cc", "Cs", "Co", "Cn")) and char not in "\n\r\t":
            suspicious.append({
                "char": repr(char),
                "codepoint": f"U+{ord(char):04X}",
                "category": cat,
                "name": unicodedata.name(char, "UNKNOWN"),
                "position": i,
            })
    return {
        "total_chars": len(content),
        "category_breakdown": categories,
        "suspicious_chars": suspicious[:50],  # Cap at 50
        "suspicious_count": len(suspicious),
    }


def scan_content(content: str, file_path: str, patterns: list[dict]) -> list[Finding]:
    """Scan file content against all loaded patterns."""
    findings = []
    lines = content.split("\n")

    for pattern_def in patterns:
        rule_id = pattern_def.get("id", "UNKNOWN")
        name = pattern_def.get("name", "Unknown pattern")
        severity = pattern_def.get("severity", "medium")
        category = pattern_def.get("_category", "unknown")
        description = pattern_def.get("description", "").strip()

        for pat in pattern_def.get("patterns", []):
            regex = pat.get("regex", "")
            if not regex:
                continue

            encoding = pat.get("encoding", "")

            # For unicode-type patterns, scan raw content
            if encoding == "unicode":
                for i, line in enumerate(lines, 1):
                    try:
                        matches = re.finditer(regex, line)
                        for m in matches:
                            findings.append(Finding(
                                rule_id=rule_id,
                                name=name,
                                severity=severity,
                                category=category,
                                description=description,
                                file=file_path,
                                line=i,
                                match=repr(m.group()),
                                pattern=regex,
                            ))
                    except re.error:
                        pass
            else:
                for i, line in enumerate(lines, 1):
                    try:
                        matches = re.finditer(regex, line)
                        for m in matches:
                            findings.append(Finding(
                                rule_id=rule_id,
                                name=name,
                                severity=severity,
                                category=category,
                                description=description,
                                file=file_path,
                                line=i,
                                match=m.group()[:100],
                                pattern=regex,
                            ))
                    except re.error:
                        pass

    return findings


def is_rule_file(path: Path) -> bool:
    """Check if a file matches known IDE rule file patterns."""
    name = path.name
    rel = str(path)
    for pattern in RULE_FILE_PATTERNS:
        if rel.endswith(pattern) or name == pattern:
            return True
    for glob_pat in RULE_FILE_GLOBS:
        parts = glob_pat.split("/")
        if name.endswith(parts[-1].replace("*", "")):
            return True
    # Also accept if explicitly passed
    return True


def find_rule_files(directory: Path, recursive: bool = False) -> list[Path]:
    """Find all IDE rule files in a directory."""
    found = []
    search = directory.rglob("*") if recursive else directory.iterdir()
    for path in search:
        if not path.is_file():
            continue
        rel = str(path.relative_to(directory))
        for pattern in RULE_FILE_PATTERNS:
            if rel == pattern or path.name == pattern.split("/")[-1]:
                found.append(path)
                break
        else:
            for glob_pat in RULE_FILE_GLOBS:
                ext = glob_pat.split(".")[-1]
                dir_part = glob_pat.split("/")[0]
                if path.suffix == f".{ext}" and dir_part in str(path):
                    found.append(path)
                    break
    return found


def format_terminal(results: list[ScanResult]) -> str:
    """Format results for terminal output."""
    output = []
    total_findings = sum(len(r.findings) for r in results)

    for result in results:
        output.append(f"\n{'='*60}")
        output.append(f"File: {result.file}")
        output.append(f"{'='*60}")

        if result.unicode_analysis.get("suspicious_count", 0) > 0:
            count = result.unicode_analysis["suspicious_count"]
            output.append(f"\n  [!] Unicode analysis: {count} suspicious character(s) found")
            for sc in result.unicode_analysis.get("suspicious_chars", [])[:5]:
                output.append(f"      {sc['codepoint']} {sc['name']} at position {sc['position']}")

        if not result.findings:
            output.append("\n  No malicious patterns detected.")
            continue

        counts = result.finding_count
        severity_line = []
        for sev in ["critical", "high", "medium", "low"]:
            if counts[sev] > 0:
                severity_line.append(f"{counts[sev]} {sev}")
        output.append(f"\n  Findings: {', '.join(severity_line)}")

        # Group by category
        by_category = {}
        for f in sorted(result.findings, key=lambda x: x.severity_rank):
            by_category.setdefault(f.category, []).append(f)

        for cat, findings in by_category.items():
            output.append(f"\n  [{cat}]")
            for f in findings:
                sev_marker = {"critical": "!!!", "high": "!!", "medium": "!", "low": "."}.get(f.severity, "")
                output.append(f"    {sev_marker} [{f.severity.upper()}] {f.rule_id}: {f.name}")
                output.append(f"       Line {f.line}: {f.match[:80]}")

    output.append(f"\n{'='*60}")
    output.append(f"Total: {total_findings} finding(s) across {len(results)} file(s)")
    output.append(f"{'='*60}")
    return "\n".join(output)


def format_json(results: list[ScanResult]) -> str:
    """Format results as JSON."""
    data = []
    for r in results:
        data.append({
            "file": r.file,
            "max_severity": r.max_severity,
            "finding_count": r.finding_count,
            "unicode_suspicious_count": r.unicode_analysis.get("suspicious_count", 0),
            "findings": [asdict(f) for f in r.findings],
        })
    return json.dumps(data, indent=2)


def format_sarif(results: list[ScanResult]) -> str:
    """Format results as SARIF for CI integration."""
    rules = {}
    sarif_results = []

    for r in results:
        for f in r.findings:
            if f.rule_id not in rules:
                rules[f.rule_id] = {
                    "id": f.rule_id,
                    "name": f.name,
                    "shortDescription": {"text": f.name},
                    "fullDescription": {"text": f.description},
                    "defaultConfiguration": {
                        "level": {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}.get(f.severity, "warning")
                    },
                }

            sarif_results.append({
                "ruleId": f.rule_id,
                "level": {"critical": "error", "high": "error", "medium": "warning", "low": "note"}.get(f.severity, "warning"),
                "message": {"text": f"{f.name}: {f.match[:200]}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file},
                        "region": {"startLine": f.line},
                    }
                }],
            })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ide-rule-detector",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/spiffy-oss/ide-rule-detector",
                    "rules": list(rules.values()),
                }
            },
            "results": sarif_results,
        }],
    }
    return json.dumps(sarif, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="Scan IDE rule files for malicious patterns"
    )
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--recursive", "-r", action="store_true", help="Scan directories recursively")
    parser.add_argument("--format", "-f", choices=["text", "json", "sarif"], default="text", help="Output format")
    parser.add_argument("--patterns", "-p", default=None, help="Path to patterns directory (default: ../patterns/)")
    parser.add_argument("--min-severity", default="low", choices=["critical", "high", "medium", "low", "info"], help="Minimum severity to report")
    args = parser.parse_args()

    # Resolve patterns directory
    if args.patterns:
        patterns_dir = Path(args.patterns)
    else:
        patterns_dir = Path(__file__).parent.parent / "patterns"

    if not patterns_dir.exists():
        print(f"Error: patterns directory not found at {patterns_dir}", file=sys.stderr)
        sys.exit(1)

    patterns = load_patterns(patterns_dir)
    if not patterns:
        print("Error: no patterns loaded", file=sys.stderr)
        sys.exit(1)

    # Resolve target files
    target = Path(args.path)
    if target.is_file():
        files = [target]
    elif target.is_dir():
        if args.recursive:
            files = find_rule_files(target, recursive=True)
        else:
            files = find_rule_files(target, recursive=False)
        if not files:
            # If no rule files found, scan all text files
            files = [f for f in (target.rglob("*") if args.recursive else target.iterdir()) if f.is_file() and f.suffix in (".md", ".mdc", ".yaml", ".yml", ".json", ".txt", "")]
    else:
        print(f"Error: {args.path} not found", file=sys.stderr)
        sys.exit(1)

    if not files:
        print("No files to scan.", file=sys.stderr)
        sys.exit(0)

    # Severity filter
    severity_ranks = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    min_rank = severity_ranks.get(args.min_severity, 3)

    # Scan
    results = []
    for file_path in files:
        try:
            content = file_path.read_text(errors="replace")
        except Exception as e:
            print(f"Warning: could not read {file_path}: {e}", file=sys.stderr)
            continue

        findings = scan_content(content, str(file_path), patterns)
        findings = [f for f in findings if f.severity_rank <= min_rank]
        unicode_info = analyze_unicode(content)

        results.append(ScanResult(
            file=str(file_path),
            findings=findings,
            unicode_analysis=unicode_info,
        ))

    # Output
    if args.format == "json":
        print(format_json(results))
    elif args.format == "sarif":
        print(format_sarif(results))
    else:
        print(format_terminal(results))

    # Exit code: non-zero if any critical or high findings
    has_critical = any(
        f.severity in ("critical", "high")
        for r in results
        for f in r.findings
    )
    sys.exit(1 if has_critical else 0)


if __name__ == "__main__":
    main()
