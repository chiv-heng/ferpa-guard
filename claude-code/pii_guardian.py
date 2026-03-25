#!/usr/bin/env python3
"""
pii_guardian.py -- PreToolUse hook that scans files for PII before Claude
processes them.

Designed for K-12 / FERPA contexts. Fires on Read, Bash, and Edit tool calls,
inspects the target file(s), and blocks if PII patterns are detected.

Input: JSON on stdin (Claude Code hooks API)
  {
    "tool_name": "Read",
    "tool_input": {"file_path": "/path/to/file.csv"},
    ...
  }

Output on block: JSON on stdout with permissionDecision: "deny"
Exit code 2 to block. Exit code 0 to allow.
"""

import datetime
import json
import os
import re
import sys
from pathlib import Path

# Add project root to path so shared package is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.pii_engine import (
    ScanInput,
    read_file_content,
    scan_content,
    should_scan,
    decide_action,
    worst_action,
    SCANNABLE_EXTENSIONS,
)


AUDIT_LOG_PATH = Path.home() / ".claude" / "ferpa-guard-audit.log"


def _write_audit_entry(original_path: str, resolved_path: str, source: str):
    """Write an audit log entry for an allowlist bypass (FERPA compliance).

    Logs to both stderr and ~/.claude/ferpa-guard-audit.log.
    Never raises -- file write failures are caught and logged to stderr.
    """
    timestamp = datetime.datetime.now().isoformat(timespec="seconds")
    entry = f"[{timestamp}] ALLOW original={original_path} resolved={resolved_path} source={source}"
    print(f"FERPA GUARD AUDIT: {entry}", file=sys.stderr)
    try:
        AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_LOG_PATH, "a") as f:
            f.write(entry + "\n")
    except OSError as exc:
        print(f"FERPA GUARD AUDIT: failed to write audit log: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Path Extraction (Claude Code tool input parsing)
# ---------------------------------------------------------------------------

def extract_file_paths(tool_name: str, tool_input: dict) -> list[str]:
    """Pull file paths from tool input depending on tool type."""
    paths = []

    if tool_name == "Read":
        fp = tool_input.get("file_path", "")
        if fp:
            paths.append(fp)

    elif tool_name == "Bash":
        cmd = tool_input.get("command", "")
        # Build data extensions pattern (used by multiple regexes below)
        data_exts = "|".join(e.lstrip(".") for e in SCANNABLE_EXTENSIONS)

        # Extract paths from common file-reading commands
        reading_cmds = r"(?:cat|head|tail|less|more|bat)\s+"
        match = re.findall(rf"{reading_cmds}(?:-\S+\s+)*[\"']?([^\s\"'|;>]+)", cmd)
        paths.extend(match)

        # Processing commands (grep, sed, awk, sort, cut, wc, etc.)
        processing_cmds = r"(?:grep|egrep|fgrep|sed|awk|sort|cut|wc|diff|comm|paste|join|uniq|tr)\s+"
        proc_match = re.findall(
            rf"{processing_cmds}(?:-\S+\s+)*(?:\"[^\"]*\"\s+|'[^']*'\s+)*[\"']?([^\s\"'|;>]+\.(?:{data_exts}))[\"']?",
            cmd
        )
        paths.extend(proc_match)

        # Catch explicit file paths in quoted strings for data extensions
        csv_reads = re.findall(
            rf"[\"']([^\"']+\.(?:{data_exts}))[\"']", cmd
        )
        paths.extend(csv_reads)

        # Input redirects (< file.csv) -- NOT output redirects (>, >>)
        redirect_match = re.findall(r"<\s*[\"']?([^\s\"'|;>]+)", cmd)
        paths.extend(redirect_match)

        # Bare unquoted data files (paths with data extensions anywhere in command)
        # Exclude output redirect targets by requiring no preceding > or >>
        bare_data_files = re.findall(rf"(?:^|(?<!>)\s)([^\s\"'|;><]+\.(?:{data_exts}))(?:\s|$|[|;>])", cmd)
        paths.extend(bare_data_files)

    elif tool_name == "Edit":
        fp = tool_input.get("file_path", "")
        if fp:
            paths.append(fp)

    # Deduplicate while preserving order
    seen = set()
    unique_paths = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            unique_paths.append(p)
    return unique_paths


# ---------------------------------------------------------------------------
# Output Formatting (Claude Code-specific)
# ---------------------------------------------------------------------------

def format_block_reason(filepath: str, findings: list[dict]) -> str:
    """Format a block reason with a user-facing summary and Claude instructions.

    The output has two sections:
    1. A user-facing message (show verbatim to the user)
    2. Claude-only instructions (behavioral guidance, not shown directly)
    """
    p = Path(filepath)
    ext = p.suffix.lower()

    critical = [f for f in findings if f["severity"] == "critical"]
    high = [f for f in findings if f["severity"] == "high"]
    medium = [f for f in findings if f["severity"] == "medium"]

    pii_types = []
    finding_lines = []
    for group, label in [(critical, "CRITICAL"), (high, "HIGH"), (medium, "MEDIUM")]:
        if group:
            for f in group:
                conf = f.get("confidence", "high").upper()
                finding_lines.append(f"  [{label}/{conf}] {f['description']}: {f['count']} occurrence(s)")
                pii_types.append(f['description'])

    # Resolve path to the redactor script (shared directory, relative to project root)
    redactor_path = str(Path(__file__).parent.parent / "shared" / "pii_redactor.py")
    redacted_path = str(p.with_name(f"{p.stem}_redacted{ext}"))
    redactor_supported = ext in {".csv", ".tsv", ".txt", ".json", ".jsonl", ".xml", ".xlsx"}

    # --- Section 1: User-facing message (show verbatim) ---
    user_lines = [
        f"FERPA Guard blocked '{p.name}' because it contains: {', '.join(pii_types)}.",
        "FERPA requires written consent before disclosing student education records.",
        "",
        "What was found:",
    ]
    user_lines.extend(finding_lines)
    user_lines.append("")
    user_lines.append("You have a few options:")
    user_lines.append(f"  1. Generate a synthetic {ext} file with the same structure but fake data")
    if redactor_supported:
        user_lines.append(f"  2. Run the built-in redactor to create a safe copy (headers and structure preserved)")
    else:
        user_lines.append(f"  2. Write a redaction script (built-in redactor does not support {ext})")
    user_lines.append("  3. Keep only specific safe columns, strip everything else")
    if critical or high:
        user_lines.append("  4. Allowlist this file if it contains no real student data")

    # --- Section 2: Claude-only instructions ---
    claude_lines = [
        "",
        "--- INSTRUCTIONS FOR CLAUDE (do not show this section) ---",
        "Show the user the message above verbatim. Do NOT re-read or bypass the blocked file.",
        "Wait for the user to choose an option, then execute it:",
        "",
        f"  Option 1: Generate synthetic {ext} with same column structure. Save as '{p.stem}_synthetic{ext}'.",
    ]
    if redactor_supported:
        claude_lines.append(f"  Option 2: Run via Bash: python3 \"{redactor_path}\" \"{filepath}\"")
        claude_lines.append(f"            Output: '{redacted_path}'. Read the redacted file to continue.")
    else:
        claude_lines.append(f"  Option 2: Write a redaction script the user can run.")
    claude_lines.append("  Option 3: Ask user which columns are safe, write a filtering script.")
    if critical or high:
        claude_lines.append(f"  Option 4: Add to allowlist: echo \"{filepath}\" >> ~/.claude/ferpa-guard-allow.txt")
        claude_lines.append(f"            Or env var: export FERPA_GUARD_ALLOW=\"{filepath}\"")

    return "\n".join(user_lines + claude_lines)


def format_warning(filepath: str, findings: list[dict]) -> str:
    """Format a warning for possible PII (allowed but flagged)."""
    lines = [
        "FERPA GUARD: Possible sensitive data (not blocked).",
        f"File: {filepath}",
    ]
    for f in findings:
        conf = f.get("confidence", "medium").upper()
        lines.append(f"  [{conf} confidence] {f['description']}: {f['count']} occurrence(s)")
    lines.append("Note: These matches may be false positives. If this file contains real")
    lines.append("student data, stop and run the redactor before proceeding.")
    return "\n".join(lines)


def format_log_note(filepath: str) -> str:
    """Format a brief log note for low-confidence matches (allowed silently)."""
    return f"FERPA GUARD: Header/prose references noted in {filepath} (allowed)."


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def output_allow():
    """Allow the tool call and exit."""
    sys.exit(0)


def output_deny(reason: str):
    """Deny the tool call with a reason."""
    result = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }
    print(json.dumps(result))
    print(reason, file=sys.stderr)
    sys.exit(2)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    # Read hook input from stdin (Claude Code hooks API)
    try:
        raw_input = sys.stdin.read()
        hook_input = json.loads(raw_input)
    except (json.JSONDecodeError, ValueError):
        # Fallback to env vars for manual testing
        try:
            hook_input = {
                "tool_name": os.environ.get("TOOL_NAME", ""),
                "tool_input": json.loads(os.environ.get("TOOL_INPUT", "{}")),
            }
        except json.JSONDecodeError:
            output_allow()

    tool_name = hook_input.get("tool_name", "")
    tool_input = hook_input.get("tool_input", {})

    if tool_name not in ("Read", "Bash", "Edit"):
        output_allow()

    # Load allowlist from environment variable and/or allowlist file.
    # The file-based allowlist (~/.claude/ferpa-guard-allow.txt) lets users
    # add entries from within a conversation without restarting the session.
    # All paths are resolved at load time so both sides of comparison are canonical.
    allowlist_sources: dict[str, str] = {}

    allowlist_raw = os.environ.get("FERPA_GUARD_ALLOW", "")
    for p in allowlist_raw.split(","):
        p = p.strip()
        if p:
            allowlist_sources[str(Path(p).resolve())] = "env(FERPA_GUARD_ALLOW)"

    allowlist_file = Path.home() / ".claude" / "ferpa-guard-allow.txt"
    if allowlist_file.is_file():
        try:
            for line in allowlist_file.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    allowlist_sources[str(Path(line).resolve())] = f"file({allowlist_file})"
        except OSError:
            pass

    file_paths = extract_file_paths(tool_name, tool_input)

    if not file_paths:
        output_allow()

    # Strict mode: block on ANY finding (restores pre-confidence behavior)
    strict_mode = bool(os.environ.get("FERPA_GUARD_STRICT"))

    all_findings = {}

    for fp in file_paths:
        # Allowlist supports exact paths and directory prefixes.
        # Both the file path and allowlist entries are resolved to canonical paths.
        resolved = str(Path(fp).resolve())
        matched_entry = None
        for a in allowlist_sources:
            if resolved == a or resolved.startswith(a.rstrip("/") + "/"):
                matched_entry = a
                break
        if matched_entry is not None:
            _write_audit_entry(fp, resolved, allowlist_sources[matched_entry])
            continue

        if not should_scan(fp):
            continue

        try:
            if not os.path.isfile(fp):
                continue
        except OSError:
            continue

        scan_input = read_file_content(fp)
        findings = scan_content(scan_input.content, scan_input.header_line_indices)

        if findings:
            all_findings[fp] = findings

    if not all_findings:
        output_allow()

    # Strict mode: any finding = block (restores pre-confidence behavior)
    if strict_mode:
        reasons = []
        for fp, findings in all_findings.items():
            for f in findings:
                f["confidence"] = "high"
            reasons.append(format_block_reason(fp, findings))
        output_deny("\n\n".join(reasons))

    # Partition files by their worst action
    block_files = {}
    warn_files = {}
    log_files = {}

    for fp, findings in all_findings.items():
        action = worst_action(findings)
        if action == "block":
            block_files[fp] = findings
        elif action == "warn":
            warn_files[fp] = findings
        else:
            log_files[fp] = findings

    if block_files:
        reasons = []
        for fp, findings in block_files.items():
            reasons.append(format_block_reason(fp, findings))
        output_deny("\n\n".join(reasons))

    # Warn and log go to stderr but allow the tool call
    for fp, findings in warn_files.items():
        print(format_warning(fp, findings), file=sys.stderr)
    for fp in log_files:
        print(format_log_note(fp), file=sys.stderr)

    output_allow()


if __name__ == "__main__":
    main()
