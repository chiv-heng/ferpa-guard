#!/usr/bin/env python3
"""
pii_scan_report.py -- Batch PII scanner that walks a directory and prints
a structured report of what's clean, what's blocked, and what was skipped.

Usage:
    python3 pii_scan_report.py /path/to/folder
    python3 pii_scan_report.py /path/to/folder --json    # machine-readable output

Imports detection patterns from shared.pii_engine (project-level package).
No files are modified. Read-only scan.
"""

import json as json_lib
import os
import sys
from pathlib import Path

# Add project root to path so shared package is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.pii_engine import (
    scan_content,
    read_file_content,
    should_scan,
    reader_error_finding,
    scan_incomplete_finding,
    SKIP_DIRS,
    SCANNABLE_EXTENSIONS,
)


# ---------------------------------------------------------------------------
# Severity ordering for display
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2}
CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}


def severity_key(finding: dict) -> int:
    return SEVERITY_ORDER.get(finding["severity"], 99)


def max_confidence(findings: list[dict]) -> str:
    """Return the highest confidence among findings."""
    for conf in ("high", "medium", "low"):
        if any(f.get("confidence") == conf for f in findings):
            return conf
    return "low"


# ---------------------------------------------------------------------------
# Directory walker
# ---------------------------------------------------------------------------

def scan_directory(directory: str) -> dict:
    """Walk a directory and scan every file. Returns categorized results."""
    results = {
        "directory": directory,
        "blocked": [],    # Files with PII findings
        "unscannable": [],  # Files that could not be checked completely
        "clean": [],      # Scannable files with no PII
        "skipped": [],    # Files not in SCANNABLE_EXTENSIONS or in SKIP_DIRS
        "errors": [],     # Files that failed to read
    }

    dir_path = Path(directory)
    if not dir_path.is_dir():
        print(f"Error: '{directory}' is not a directory.", file=sys.stderr)
        sys.exit(1)

    for root, dirs, files in os.walk(directory):
        # Prune skipped directories in-place
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for filename in sorted(files):
            filepath = os.path.join(root, filename)

            if not should_scan(filepath):
                results["skipped"].append(filepath)
                continue

            try:
                scan_input = read_file_content(filepath)
            except Exception as e:
                results["errors"].append({"path": filepath, "error": str(e)})
                continue

            findings = scan_content(scan_input.content, scan_input.header_line_indices)
            if scan_input.reader_error:
                findings.append(reader_error_finding(scan_input.reader_error, filepath))
            if scan_input.truncated:
                findings.append(scan_incomplete_finding(scan_input.truncated, filepath))

            if scan_input.reader_error or scan_input.truncated:
                findings.sort(key=severity_key)
                results["unscannable"].append({
                    "path": filepath,
                    "reader_error": scan_input.reader_error,
                    "truncated": scan_input.truncated,
                    "findings": findings,
                })
            elif findings:
                findings.sort(key=severity_key)
                results["blocked"].append({
                    "path": filepath,
                    "findings": findings,
                })
            else:
                results["clean"].append(filepath)

    return results


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------

def max_severity(findings: list[dict]) -> str:
    """Return the highest severity among findings."""
    for sev in ("critical", "high", "medium"):
        if any(f["severity"] == sev for f in findings):
            return sev
    return "medium"


def format_text_report(results: dict) -> str:
    """Format a human-readable report."""
    lines = []

    lines.append("")
    lines.append("FERPA GUARD SCAN REPORT")
    lines.append(f"Directory: {results['directory']}")
    lines.append(
        f"Scanned: {len(results['blocked']) + len(results['clean']) + len(results['unscannable'])} files | "
        f"Blocked: {len(results['blocked'])} | "
        f"Could not check: {len(results['unscannable'])} | "
        f"Clean: {len(results['clean'])} | "
        f"Skipped: {len(results['skipped'])}"
    )

    # Blocked files
    if results["blocked"]:
        lines.append("")
        lines.append("-" * 60)
        lines.append("BLOCKED (PII detected)")
        lines.append("-" * 60)

        for item in results["blocked"]:
            p = Path(item["path"])
            sev = max_severity(item["findings"]).upper()
            conf = max_confidence(item["findings"]).upper()
            lines.append(f"  [{sev}/{conf}] {p.name}")
            lines.append(f"         {item['path']}")

            for f in item["findings"]:
                f_conf = f.get("confidence", "high").upper()
                lines.append(
                    f"         - {f['description']}: "
                    f"{f['count']} occurrence(s) [{f['severity']}/{f_conf}]"
                )

            # Recovery hint
            ext = p.suffix.lower()
            redactor_supported = ext in {".csv", ".tsv", ".txt", ".json", ".jsonl", ".xml"}
            if redactor_supported:
                redactor_path = str(Path(__file__).parent.parent / "shared" / "pii_redactor.py")
                lines.append(f"         Redact: python3 \"{redactor_path}\" \"{item['path']}\"")
            lines.append("")

    # Files whose readers failed or omitted verified content
    if results["unscannable"]:
        lines.append("-" * 60)
        lines.append("COULD NOT CHECK")
        lines.append("-" * 60)
        for item in results["unscannable"]:
            p = Path(item["path"])
            operational = [
                f for f in item["findings"]
                if f["pattern_name"] in {"SCAN_READER_UNAVAILABLE", "SCAN_INCOMPLETE"}
            ]
            detections = [
                f for f in item["findings"]
                if f["pattern_name"] not in {"SCAN_READER_UNAVAILABLE", "SCAN_INCOMPLETE"}
            ]
            lines.append(f"  {p.name}")
            lines.append(f"         {item['path']}")
            for finding in operational:
                lines.append(f"         - Could not check: {finding['description']}")
            for finding in detections:
                lines.append(
                    f"         - Also detected in checked portion: {finding['description']} "
                    f"({finding['count']} occurrence(s))"
                )

            dependency_commands = {
                "MISSING_DEPENDENCY:openpyxl": "pip install openpyxl",
                "MISSING_DEPENDENCY:pymupdf": "pip install pymupdf",
                "MISSING_DEPENDENCY:python-docx": "pip install python-docx",
            }
            install_command = dependency_commands.get(item["reader_error"])
            if install_command:
                lines.append(f"         1. Install it: `{install_command}`, then retry.")
            elif item["reader_error"] == "ENCRYPTED":
                lines.append("         1. Make an unlocked copy with permission, then retry.")
            else:
                lines.append("         1. Confirm the file is readable and complete, then retry.")
            lines.append("         2. Convert the file to CSV and retry.")
            lines.append(
                "         3. If you verified this exact file is safe, add its full path to "
                "a .pii-guardian-allow file or ~/.claude/ferpa-guard-allow.txt."
            )
            lines.append("")

    # Clean files
    if results["clean"]:
        lines.append("-" * 60)
        lines.append("CLEAN (no PII detected)")
        lines.append("-" * 60)
        for filepath in results["clean"]:
            lines.append(f"  {Path(filepath).name}")
            lines.append(f"         {filepath}")
        lines.append("")

    # Skipped files
    if results["skipped"]:
        lines.append("-" * 60)
        lines.append(f"SKIPPED ({len(results['skipped'])} files -- not scannable type)")
        lines.append("-" * 60)
        # Group by extension
        by_ext = {}
        for filepath in results["skipped"]:
            ext = Path(filepath).suffix.lower() or "(no extension)"
            by_ext.setdefault(ext, []).append(filepath)
        for ext, paths in sorted(by_ext.items()):
            lines.append(f"  {ext}: {len(paths)} file(s)")
        lines.append("")

    # Errors
    if results["errors"]:
        lines.append("-" * 60)
        lines.append("ERRORS")
        lines.append("-" * 60)
        for err in results["errors"]:
            lines.append(f"  {err['path']}: {err['error']}")
        lines.append("")

    # Summary recommendation
    if results["blocked"]:
        lines.append("=" * 60)
        lines.append("NEXT STEPS")
        lines.append("=" * 60)
        redactable = [
            item for item in results["blocked"]
            if Path(item["path"]).suffix.lower() in {".csv", ".tsv", ".txt", ".json", ".jsonl", ".xml"}
        ]
        non_redactable = [
            item for item in results["blocked"]
            if Path(item["path"]).suffix.lower() not in {".csv", ".tsv", ".txt", ".json", ".jsonl", ".xml"}
        ]

        if redactable:
            lines.append(f"  {len(redactable)} file(s) can be auto-redacted. Run the commands above,")
            lines.append(f"  then use the _redacted copies for analysis.")
        if non_redactable:
            exts = sorted(set(Path(i["path"]).suffix for i in non_redactable))
            lines.append(f"  {len(non_redactable)} file(s) ({', '.join(exts)}) need manual redaction")
            lines.append(f"  or export to CSV before the redactor can process them.")
        lines.append("")

    return "\n".join(lines)


def format_json_report(results: dict) -> str:
    """Format a machine-readable JSON report."""
    output = {
        "directory": results["directory"],
        "summary": {
            "scanned": len(results["blocked"]) + len(results["clean"]) + len(results["unscannable"]),
            "blocked": len(results["blocked"]),
            "unscannable": len(results["unscannable"]),
            "clean": len(results["clean"]),
            "skipped": len(results["skipped"]),
            "errors": len(results["errors"]),
        },
        "blocked": results["blocked"],
        "unscannable": results["unscannable"],
        "clean": results["clean"],
        "skipped": results["skipped"],
        "errors": results["errors"],
    }
    return json_lib.dumps(output, indent=2)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 pii_scan_report.py <directory> [--json]")
        print("")
        print("Scans all files in a directory for PII and prints a report.")
        print("No files are modified. Read-only scan.")
        sys.exit(1)

    directory = sys.argv[1]
    json_mode = "--json" in sys.argv

    results = scan_directory(directory)

    if json_mode:
        print(format_json_report(results))
    else:
        print(format_text_report(results))

    # Exit 0 means every scannable file was checked fully and was clean.
    sys.exit(1 if (results["blocked"] or results["unscannable"] or results["errors"]) else 0)


if __name__ == "__main__":
    main()
