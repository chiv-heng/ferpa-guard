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
import time
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
    collect_allowfile_entries,
    write_audit_event,
)


# JSONL audit trail (block/warn/log/bypass). Deliberately NOT the live MBP
# monolith's pii-guardian-audit.jsonl -- two writers interleaving in one file
# during the re-wire transition would corrupt line-count signals.
AUDIT_LOG_PATH = Path.home() / ".claude" / "logs" / "ferpa-guard-audit.jsonl"
FEEDBACK_LOG_PATH = Path.home() / ".claude" / "ferpa-guard-feedback.log"

# ---------------------------------------------------------------------------
# Scan Result Cache (FIX-02)
# ---------------------------------------------------------------------------
# Keyed by (resolved_path, mtime, size). If the file hasn't changed,
# return the cached findings + action instead of re-scanning.
# Cache TTL: 1 hour max. Disk persistence optional via FERPA_GUARD_CACHE=1.

_CACHE_TTL = 3600  # 1 hour in seconds
_DISK_CACHE_PATH = Path.home() / ".claude" / "ferpa-guard-cache.json"

# In-memory cache: { (path, mtime, size): { "findings": [...], "cached_at": float } }
_scan_cache: dict[tuple, dict] = {}


def _cache_key(resolved_path: str) -> tuple | None:
    """Build a cache key from file stat. Returns None if file can't be stat'd."""
    try:
        st = os.stat(resolved_path)
        return (resolved_path, st.st_mtime, st.st_size)
    except OSError:
        return None


def _cache_get(key: tuple) -> list[dict] | None:
    """Look up cached findings. Returns None on miss or expired entry."""
    entry = _scan_cache.get(key)
    if entry is None:
        return None
    if time.time() - entry["cached_at"] > _CACHE_TTL:
        del _scan_cache[key]
        return None
    return entry["findings"]


def _cache_put(key: tuple, findings: list[dict]) -> None:
    """Store findings in cache."""
    _scan_cache[key] = {"findings": findings, "cached_at": time.time()}


def _load_disk_cache() -> None:
    """Load cache from disk if FERPA_GUARD_CACHE=1 and file exists."""
    if not os.environ.get("FERPA_GUARD_CACHE"):
        return
    if not _DISK_CACHE_PATH.is_file():
        return
    try:
        data = json.loads(_DISK_CACHE_PATH.read_text())
        now = time.time()
        for entry in data:
            key = tuple(entry["key"])
            if now - entry["cached_at"] <= _CACHE_TTL:
                _scan_cache[key] = {
                    "findings": entry["findings"],
                    "cached_at": entry["cached_at"],
                }
    except (json.JSONDecodeError, KeyError, OSError):
        pass


def _save_disk_cache() -> None:
    """Persist cache to disk if FERPA_GUARD_CACHE=1."""
    if not os.environ.get("FERPA_GUARD_CACHE"):
        return
    try:
        now = time.time()
        entries = []
        for key, val in _scan_cache.items():
            if now - val["cached_at"] <= _CACHE_TTL:
                entries.append({
                    "key": list(key),
                    "findings": val["findings"],
                    "cached_at": val["cached_at"],
                })
        _DISK_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _DISK_CACHE_PATH.write_text(json.dumps(entries))
    except OSError:
        pass


def _write_audit_entry(original_path: str, resolved_path: str, source: str):
    """Audit an allowlist bypass: JSONL record + stderr echo. Never raises."""
    print(
        f"FERPA GUARD AUDIT: bypass resolved={resolved_path} source={source}",
        file=sys.stderr,
    )
    write_audit_event(AUDIT_LOG_PATH, "bypass", resolved_path, [], source=source)


# ---------------------------------------------------------------------------
# Path Extraction (Claude Code tool input parsing)
# ---------------------------------------------------------------------------

# Commands that send file content to stdout (and therefore to the LLM context).
# Only files referenced by these commands need PII scanning.
_CONTENT_COMMANDS = {
    "cat", "head", "tail", "less", "more", "bat",
    "grep", "egrep", "fgrep", "rg",
    "sed", "awk",
    "sort", "cut", "paste", "join", "uniq", "tr", "comm",
    "diff",
    "python3", "python", "node",
}

# Commands that only touch file metadata or move files around.
# These never send file content to the LLM, so scanning is unnecessary.
_METADATA_COMMANDS = {
    "ls", "wc", "stat", "file", "du", "find",
    "mv", "cp", "rm", "mkdir", "chmod", "chown", "touch",
    "ln", "readlink", "realpath", "basename", "dirname",
}


def _is_content_command(cmd: str) -> bool:
    """Return True if the Bash command reads file content into stdout.

    Extracts the first token (the command name) and checks it against
    known content-reading vs metadata-only command sets. Unknown commands
    default to True (scan conservatively).
    """
    # Strip leading env assignments (FOO=bar cmd ...) and sudo
    stripped = cmd.lstrip()
    while re.match(r'^[A-Za-z_][A-Za-z0-9_]*=\S+\s+', stripped):
        stripped = re.sub(r'^[A-Za-z_][A-Za-z0-9_]*=\S+\s+', '', stripped)
    if stripped.startswith("sudo "):
        stripped = stripped[5:].lstrip()

    # Get first word (the command)
    first_word = stripped.split()[0] if stripped.split() else ""
    # Strip path prefix (e.g., /usr/bin/cat -> cat)
    cmd_name = first_word.rsplit("/", 1)[-1]

    if cmd_name in _METADATA_COMMANDS:
        return False
    # Content commands and unknown commands both return True (conservative)
    return True


def extract_file_paths(tool_name: str, tool_input: dict) -> list[str]:
    """Pull file paths from tool input depending on tool type."""
    paths = []

    if tool_name == "Read":
        fp = tool_input.get("file_path", "")
        if fp:
            paths.append(fp)

    elif tool_name == "Bash":
        cmd = tool_input.get("command", "")

        # Skip file extraction entirely for metadata-only commands
        if not _is_content_command(cmd):
            return []

        # Build data extensions pattern (used by multiple regexes below)
        data_exts = "|".join(e.lstrip(".") for e in SCANNABLE_EXTENSIONS)

        # Extract paths from common file-reading commands
        reading_cmds = r"(?:cat|head|tail|less|more|bat)\s+"
        match = re.findall(rf"{reading_cmds}(?:-\S+\s+)*[\"']?([^\s\"'|;>]+)", cmd)
        paths.extend(match)

        # Processing commands (grep, sed, awk, sort, cut, etc.)
        processing_cmds = r"(?:grep|egrep|fgrep|sed|awk|sort|cut|diff|comm|paste|join|uniq|tr)\s+"
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
    next_opt = 5 if (critical or high) else 4
    user_lines.append(f"  {next_opt}. Mark as false positive (logs this for pattern tuning, does not bypass)")

    # Build pattern names string for feedback log command
    pattern_names = ",".join(f["pattern_name"] for f in findings)

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
    claude_lines.append(f"  Option {next_opt}: Run via Bash: echo \"$(date -Iseconds) FP path={filepath} patterns={pattern_names}\" >> ~/.claude/ferpa-guard-feedback.log")
    claude_lines.append(f"            Tell user: logged for future pattern tuning. The file stays blocked this time.")

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

    # Load disk cache if enabled
    _load_disk_cache()

    # Load allowlist from environment variable and/or allowlist file.
    # The file-based allowlist (~/.claude/ferpa-guard-allow.txt) lets users
    # add entries from within a conversation without restarting the session.
    # All paths are resolved at load time so both sides of comparison are canonical.
    #
    # Pattern-level skip syntax (allowlist file):
    #   /path/to/file.xlsx SKIP:SSN,SSN_NO_DASHES
    #   /path/to/directory/ SKIP:MEDICAL_INFO
    #
    # Global pattern suppression (env var):
    #   FERPA_GUARD_SKIP_PATTERNS=SSN,SSN_NO_DASHES
    allowlist_sources: dict[str, str] = {}
    # Maps resolved path -> set of pattern names to skip for that path
    path_skip_patterns: dict[str, set] = {}

    allowlist_raw = os.environ.get("FERPA_GUARD_ALLOW", "")
    for p in allowlist_raw.split(","):
        p = p.strip()
        if p:
            allowlist_sources[str(Path(p).resolve())] = "env(FERPA_GUARD_ALLOW)"

    # Global pattern suppression via env var
    global_skip_patterns: set = set()
    skip_env = os.environ.get("FERPA_GUARD_SKIP_PATTERNS", "")
    for pat in skip_env.split(","):
        pat = pat.strip()
        if pat:
            global_skip_patterns.add(pat)

    allowlist_file = Path.home() / ".claude" / "ferpa-guard-allow.txt"
    if allowlist_file.is_file():
        try:
            for line in allowlist_file.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    # Parse pattern-level skip: "/path/to/file SKIP:SSN,DOB"
                    skip_match = re.match(r'^(.+?)\s+SKIP:(.+)$', line)
                    if skip_match:
                        entry_path = skip_match.group(1).strip()
                        skip_names = {s.strip() for s in skip_match.group(2).split(",")}
                        resolved_entry = str(Path(entry_path).resolve())
                        path_skip_patterns[resolved_entry] = skip_names
                        # Source tracking for audit log
                        allowlist_sources.setdefault(resolved_entry, f"file({allowlist_file})")
                    else:
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

        # Check for pattern-level skip first (SKIP entries don't fully bypass)
        file_skip = set(global_skip_patterns)
        for a in path_skip_patterns:
            if resolved == a or resolved.startswith(a.rstrip("/") + "/"):
                file_skip |= path_skip_patterns[a]

        # Check for full bypass (entries without SKIP)
        matched_entry = None
        for a in allowlist_sources:
            # Only full-bypass entries (not SKIP entries) trigger allowlist bypass
            if a not in path_skip_patterns:
                if resolved == a or resolved.startswith(a.rstrip("/") + "/"):
                    matched_entry = a
                    break
        if matched_entry is not None:
            _write_audit_entry(fp, resolved, allowlist_sources[matched_entry])
            continue

        # Ancestor-walk allowfile (.pii-guardian-allow): the no-restart escape
        # hatch. Read fresh each invocation; nearest declaration wins attribution.
        allowfile_entries = collect_allowfile_entries(resolved)
        allowfile_match = None
        for a in allowfile_entries:
            if resolved == a or resolved.startswith(a.rstrip("/") + "/"):
                allowfile_match = a
                break
        if allowfile_match is not None:
            _write_audit_entry(
                fp, resolved, f"allowfile({allowfile_entries[allowfile_match]})"
            )
            continue

        if not should_scan(fp):
            continue

        try:
            if not os.path.isfile(fp):
                continue
        except OSError:
            continue

        # Check cache before scanning (FIX-02)
        cache_key = _cache_key(resolved)
        if cache_key and not file_skip:
            cached = _cache_get(cache_key)
            if cached is not None:
                if cached:
                    all_findings[fp] = cached
                continue

        scan_input = read_file_content(fp)
        findings = scan_content(scan_input.content, scan_input.header_line_indices,
                                early_exit=True,
                                skip_patterns=file_skip if file_skip else None)

        # Cache the result (only when no skip_patterns, since skips change results)
        if cache_key and not file_skip:
            _cache_put(cache_key, findings)

        if findings:
            all_findings[fp] = findings

    if not all_findings:
        _save_disk_cache()
        output_allow()

    # Strict mode: any finding = block (restores pre-confidence behavior)
    if strict_mode:
        reasons = []
        for fp, findings in all_findings.items():
            for f in findings:
                f["confidence"] = "high"
            write_audit_event(
                AUDIT_LOG_PATH, "block", fp, [f["pattern_name"] for f in findings]
            )
            reasons.append(format_block_reason(fp, findings))
        _save_disk_cache()
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

    # Audit every per-file decision BEFORE any deny return -- a mixed
    # invocation (block + warn files) exits on the block, and the lower-tier
    # records must already be on disk by then.
    for action, files in (("block", block_files), ("warn", warn_files), ("log", log_files)):
        for fp, findings in files.items():
            write_audit_event(
                AUDIT_LOG_PATH, action, fp, [f["pattern_name"] for f in findings]
            )

    if block_files:
        reasons = []
        for fp, findings in block_files.items():
            reasons.append(format_block_reason(fp, findings))
        _save_disk_cache()
        output_deny("\n\n".join(reasons))

    # Warn and log go to stderr but allow the tool call
    for fp, findings in warn_files.items():
        print(format_warning(fp, findings), file=sys.stderr)
    for fp in log_files:
        print(format_log_note(fp), file=sys.stderr)

    _save_disk_cache()
    output_allow()


if __name__ == "__main__":
    main()
