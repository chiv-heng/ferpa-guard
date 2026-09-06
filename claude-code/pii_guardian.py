#!/usr/bin/env python3
"""
pii_guardian.py -- PreToolUse hook that scans files for PII before Claude
processes them.

Designed for K-12 / FERPA contexts. Fires on Read and Bash tool calls,
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
import shlex
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
    reader_error_finding,
    scan_incomplete_finding,
    write_audit_event,
)


# JSONL audit trail (block/warn/log/bypass). Deliberately NOT the live MBP
# monolith's pii-guardian-audit.jsonl -- two writers interleaving in one file
# during the re-wire transition would corrupt line-count signals.
AUDIT_LOG_PATH = Path.home() / ".claude" / "logs" / "ferpa-guard-audit.jsonl"
FEEDBACK_LOG_PATH = Path.home() / ".claude" / "ferpa-guard-feedback.log"

def _load_hard_deny_roots() -> tuple[Path, ...]:
    """Read FERPA_GUARD_HARD_DENY: os.pathsep-separated directories that are
    always denied, before any allowlist, cache, reader, or scan runs.

    Empty by default. Set it in the shell profile or the hook's env block for
    directories that must never reach the model regardless of content.
    """
    raw = os.environ.get("FERPA_GUARD_HARD_DENY", "")
    roots = []
    for entry in raw.split(os.pathsep):
        entry = entry.strip()
        if entry:
            roots.append(Path(os.path.expanduser(entry)))
    return tuple(roots)


HARD_DENY_ROOTS = _load_hard_deny_roots()
_HARD_DENY_REASON = "Access to protected private control data is denied."


def _contains_path(root: Path, candidate: Path) -> bool:
    """Return whether candidate is root or a component-safe descendant."""
    return candidate == root or root in candidate.parents


def _lexical_absolute(path: Path) -> Path:
    """Normalize a path lexically without requiring that it exists."""
    return Path(os.path.normpath(os.path.abspath(os.fspath(path))))


def path_is_hard_denied(path: Path) -> bool:
    """Check protected roots by both lexical and best-effort real containment."""
    candidate_lexical = _lexical_absolute(Path(path))

    for configured_root in HARD_DENY_ROOTS:
        root_lexical = _lexical_absolute(configured_root)
        if _contains_path(root_lexical, candidate_lexical):
            return True

        # Resolve separately from the lexical check. A symlink pointing outward
        # cannot undo lexical containment, while an outside symlink pointing
        # inward is caught here. Missing final components are permitted.
        try:
            candidate_resolved = candidate_lexical.resolve(strict=False)
            root_resolved = root_lexical.resolve(strict=False)
        except (OSError, RuntimeError):
            continue
        if _contains_path(root_resolved, candidate_resolved):
            return True

    return False

# ---------------------------------------------------------------------------
# Scan Result Cache (FIX-02)
# ---------------------------------------------------------------------------
# Keyed by (resolved_path, mtime, size). If the file hasn't changed,
# return the cached findings + action instead of re-scanning.
# Cache TTL: 1 hour max. Disk persistence optional via FERPA_GUARD_CACHE=1.

_CACHE_TTL = 3600
# Disk-cache wire format version. Version 3 rejects every pre-fail-closed
# verdict so a previously cached empty result cannot bypass fixed readers.
_CACHE_VERSION = 3
_DISK_CACHE_PATH = Path.home() / ".claude" / "ferpa-guard-cache.json"

# In-memory cache: { (path, mtime, size): { "findings": [...], "cached_at": float } }
_scan_cache: dict[tuple, dict] = {}
_OPERATIONAL_PATTERNS = {"SCAN_READER_UNAVAILABLE", "SCAN_INCOMPLETE"}


def _has_operational_findings(findings: list[dict]) -> bool:
    return any(f.get("pattern_name") in _OPERATIONAL_PATTERNS for f in findings)


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
    findings = entry["findings"]
    if _has_operational_findings(findings):
        del _scan_cache[key]
        return None
    return findings


def _cache_put(key: tuple, findings: list[dict]) -> None:
    """Store findings in cache."""
    if _has_operational_findings(findings):
        return
    _scan_cache[key] = {"findings": findings, "cached_at": time.time()}


def _load_disk_cache() -> None:
    """Load cache from disk if FERPA_GUARD_CACHE=1 and file exists."""
    if not os.environ.get("FERPA_GUARD_CACHE"):
        return
    if not _DISK_CACHE_PATH.is_file():
        return
    try:
        data = json.loads(_DISK_CACHE_PATH.read_text())
        # Wire format v3: {"version": 3, "entries": [...]}. Anything else is
        # ignored wholesale (cold cache, never migrated) because older
        # versions may contain fail-open reader verdicts.
        if not isinstance(data, dict) or data.get("version") != _CACHE_VERSION:
            return
        now = time.time()
        for entry in data.get("entries", []):
            key = tuple(entry["key"])
            if (now - entry["cached_at"] <= _CACHE_TTL
                    and not _has_operational_findings(entry["findings"])):
                _scan_cache[key] = {
                    "findings": entry["findings"],
                    "cached_at": entry["cached_at"],
                }
    except (json.JSONDecodeError, KeyError, TypeError, OSError):
        pass


def _save_disk_cache() -> None:
    """Persist cache to disk if FERPA_GUARD_CACHE=1."""
    if not os.environ.get("FERPA_GUARD_CACHE"):
        return
    try:
        now = time.time()
        entries = []
        for key, val in _scan_cache.items():
            if (now - val["cached_at"] <= _CACHE_TTL
                    and not _has_operational_findings(val["findings"])):
                entries.append({
                    "key": list(key),
                    "findings": val["findings"],
                    "cached_at": val["cached_at"],
                })
        _DISK_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _DISK_CACHE_PATH.write_text(
            json.dumps({"version": _CACHE_VERSION, "entries": entries})
        )
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
        bare_data_files = re.findall(
            rf"(?<!>\s)(?<!\S)([^\s\"'|;><]+\.(?:{data_exts}))(?=\s|$|[|;>])",
            cmd,
        )
        paths.extend(bare_data_files)

    # Deduplicate while preserving order
    seen = set()
    unique_paths = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            unique_paths.append(p)
    return unique_paths


def extract_hard_deny_candidates(tool_name: str, tool_input: dict) -> list[str]:
    """Extract path candidates for protected-root checks, independent of scanning.

    Unlike ``extract_file_paths``, this intentionally considers metadata
    commands, unsupported extensions, and every shell operand. False-positive
    candidates are harmless because component-safe root containment remains the
    deciding check.
    """
    if tool_name in ("Read", "Edit"):
        file_path = tool_input.get("file_path", "")
        return [file_path] if isinstance(file_path, str) and file_path else []
    if tool_name != "Bash":
        return []

    command = tool_input.get("command", "")
    if not isinstance(command, str) or not command:
        return []
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError:
        # An incomplete quote must not hide an otherwise visible protected
        # reference. This fallback does not execute or expand shell syntax.
        tokens = command.split()

    candidates = []
    for token in tokens:
        candidate = token.strip("|&;<>()")
        if not candidate:
            continue
        candidates.append(candidate)
        if "=" in candidate:
            assigned_value = candidate.split("=", 1)[1]
            if assigned_value:
                candidates.append(assigned_value)
    return candidates


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


def _operational_reason(finding: dict) -> str:
    description = finding.get("description", "The scanner could not verify the file")
    return description[:1].lower() + description[1:]


def _operational_recovery_lines(filepath: str, findings: list[dict]) -> list[str]:
    p = Path(filepath)
    codes = {f.get("code", "") for f in findings}
    dependency_commands = {
        "MISSING_DEPENDENCY:openpyxl": "pip install openpyxl",
        "MISSING_DEPENDENCY:pymupdf": "pip install pymupdf",
        "MISSING_DEPENDENCY:python-docx": "pip install python-docx",
    }
    install_command = next(
        (command for code, command in dependency_commands.items() if code in codes),
        None,
    )

    if install_command:
        first = f"1. Install it: `{install_command}`, then retry."
    elif "ENCRYPTED" in codes:
        first = "1. Make an unlocked copy with permission from the file owner, then retry."
    else:
        first = "1. Confirm the file is readable and complete, then retry."

    return [
        first,
        "2. Convert the file to CSV and retry.",
        "3. If you have verified this exact file is safe, add its full path to a "
        f"`.pii-guardian-allow` file in `{p.parent}` (takes effect immediately), or to "
        "`~/.claude/ferpa-guard-allow.txt`.",
    ]


def format_unscannable_reason(filepath: str, findings: list[dict]) -> str:
    """Format an operational-only block without claiming PII was detected."""
    p = Path(filepath)
    reasons = "; ".join(_operational_reason(f) for f in findings)
    codes = {f.get("code", "") for f in findings}
    no_content_codes = {
        "MISSING_DEPENDENCY:openpyxl",
        "MISSING_DEPENDENCY:pymupdf",
        "MISSING_DEPENDENCY:python-docx",
        "OPEN_FAILED",
        "ENCRYPTED",
        "UNREADABLE",
    }
    if codes and codes <= no_content_codes:
        read_status = "No file contents were read."
    else:
        read_status = "Only part of the file may have been checked."

    lines = [
        f"FERPA Guard blocked '{p.name}' because it could not check this file: {reasons}.",
        read_status,
    ]
    lines.extend(_operational_recovery_lines(filepath, findings))
    return "\n".join(lines)


def format_partial_scan_reason(
    filepath: str,
    detection_findings: list[dict],
    operational_findings: list[dict] | None = None,
) -> str:
    """Format a block containing both detections and an incomplete scan."""
    if operational_findings is None:
        all_findings = detection_findings
        detection_findings = [
            f for f in all_findings
            if f.get("pattern_name") not in _OPERATIONAL_PATTERNS
        ]
        operational_findings = [
            f for f in all_findings
            if f.get("pattern_name") in _OPERATIONAL_PATTERNS
        ]

    p = Path(filepath)
    lines = [
        f"FERPA Guard blocked '{p.name}'.",
        "FERPA Guard detected the following in the portion it could check, and could not verify the remainder.",
        "",
        "Detected in the checked portion:",
    ]
    for finding in detection_findings:
        confidence = finding.get("confidence", "high").upper()
        lines.append(
            f"  [{finding['severity'].upper()}/{confidence}] "
            f"{finding['description']}: {finding['count']} occurrence(s)"
        )
    lines.extend(["", "Why the remainder could not be verified:"])
    for finding in operational_findings:
        lines.append(f"  - {_operational_reason(finding)}")
    lines.append("")
    lines.extend(_operational_recovery_lines(filepath, operational_findings))
    return "\n".join(lines)


def _format_block_reason_dispatch(filepath: str, findings: list[dict]) -> str:
    operational = [
        f for f in findings if f.get("pattern_name") in _OPERATIONAL_PATTERNS
    ]
    detections = [
        f for f in findings if f.get("pattern_name") not in _OPERATIONAL_PATTERNS
    ]
    if operational and detections:
        return format_partial_scan_reason(filepath, detections, operational)
    if operational:
        return format_unscannable_reason(filepath, operational)
    return format_block_reason(filepath, detections)


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

    # Hard-deny roots are a directory boundary, not a content scan: they apply
    # to every tool the hook is invoked for, Edit included, and run before the
    # content gate below. (The installer matcher is Read|Bash, so Edit only
    # reaches this check if a settings.json matcher also lists Edit.)
    hard_deny_candidates = extract_hard_deny_candidates(tool_name, tool_input)

    if any(path_is_hard_denied(Path(candidate)) for candidate in hard_deny_candidates):
        output_deny(_HARD_DENY_REASON)

    # Guard the tools that pull file CONTENT into the model's context. Read
    # does; Bash does (cat, grep, head). Edit does not: it pushes content the
    # model already holds, and gating it blocked editing out an offending
    # token -- the guard blocked its own remediation (live parity, spec Q6).
    if tool_name not in ("Read", "Bash"):
        output_allow()

    file_paths = extract_file_paths(tool_name, tool_input)

    if not file_paths:
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
        if scan_input.reader_error:
            findings.append(reader_error_finding(scan_input.reader_error, fp))
        if scan_input.truncated:
            findings.append(scan_incomplete_finding(scan_input.truncated, fp))

        # Cache only complete reader outcomes and only when skip_patterns did
        # not alter the result.
        if cache_key and not file_skip and not _has_operational_findings(findings):
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
            reasons.append(_format_block_reason_dispatch(fp, findings))
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
            reasons.append(_format_block_reason_dispatch(fp, findings))
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
