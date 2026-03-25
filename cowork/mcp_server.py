#!/usr/bin/env python3
"""
PII Guardian MCP Server -- Scan and redact student PII in files.

Wraps the shared detection engine and redactor as MCP tools for use in
Claude Desktop (Cowork projects). Runs over stdio transport.

IMPORTANT: All logging goes to stderr. Never use bare print() -- stdout
is reserved for the MCP JSON-RPC protocol.
"""

import datetime
import logging
import os
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Import path resolution (portable -- no hardcoded paths)
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).parent.parent))

from mcp.server.fastmcp import FastMCP

from shared.pii_engine import (
    ScanInput,
    read_file_content,
    scan_content,
    should_scan,
    decide_action,
    worst_action,
    SCANNABLE_EXTENSIONS,
)
from shared.pii_redactor import (
    SUPPORTED_EXTENSIONS,
    _resolve_output_path,
    redact_csv,
    redact_xlsx,
    redact_text_file,
    redact_json,
    redact_jsonl,
)

# ---------------------------------------------------------------------------
# Logging (stderr only -- stdout is the MCP transport)
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("pii-guardian-mcp")

# ---------------------------------------------------------------------------
# Audit logging (FERPA compliance trail)
# ---------------------------------------------------------------------------
AUDIT_LOG_PATH = Path.home() / ".claude" / "pii-guardian-audit.log"


def _write_audit_entry(entry: str) -> None:
    """Write an audit log entry to the audit log file and stderr.

    Logs to stderr via the logger and appends to AUDIT_LOG_PATH.
    Never raises -- file write failures are logged to stderr only.
    """
    logger.info("AUDIT: %s", entry)
    try:
        AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_LOG_PATH, "a") as f:
            f.write(entry + "\n")
    except OSError as exc:
        logger.warning("AUDIT: failed to write log: %s", exc)


# ---------------------------------------------------------------------------
# Allowlist (bypass scanning for trusted files)
# ---------------------------------------------------------------------------


def _load_allowlist() -> dict[str, str]:
    """Load allowlist from env var and file. Returns dict of resolved_path -> source.

    Reads PII_GUARDIAN_ALLOW env var (comma-separated paths) and
    ~/.claude/pii-guardian-allow.txt (one path per line, # comments).
    Reloaded on every call so changes take effect without server restart.
    """
    allowlist_sources: dict[str, str] = {}

    # From env var
    allowlist_raw = os.environ.get("PII_GUARDIAN_ALLOW", "")
    for p in allowlist_raw.split(","):
        p = p.strip()
        if p:
            allowlist_sources[str(Path(p).resolve())] = "env(PII_GUARDIAN_ALLOW)"

    # From file
    allowlist_file = Path.home() / ".claude" / "pii-guardian-allow.txt"
    if allowlist_file.is_file():
        try:
            for line in allowlist_file.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    allowlist_sources[str(Path(line).resolve())] = f"file({allowlist_file})"
        except OSError:
            pass

    return allowlist_sources


def _check_allowlist(file_path: str) -> str | None:
    """Check if a file is on the allowlist.

    Returns the source string (e.g. "env(PII_GUARDIAN_ALLOW)") if the file
    is allowed, None if not. Supports exact path matches and directory
    prefix matches.
    """
    allowlist_sources = _load_allowlist()
    resolved = str(Path(file_path).resolve())

    for a in allowlist_sources:
        if resolved == a or resolved.startswith(a.rstrip("/") + "/"):
            return allowlist_sources[a]

    return None


# ---------------------------------------------------------------------------
# FastMCP server
# ---------------------------------------------------------------------------
mcp = FastMCP("PII Guardian")

# ---------------------------------------------------------------------------
# Optional dependency pre-check
# ---------------------------------------------------------------------------
_OPTIONAL_DEPS = {
    ".xlsx": ("openpyxl", "pip install openpyxl"),
    ".pdf": ("pymupdf", "pip install pymupdf"),
    ".docx": ("python-docx", "pip install python-docx"),
}

# Import name differs from package name for some deps
_IMPORT_NAMES = {
    "pymupdf": "fitz",
    "python-docx": "docx",
}


def _check_optional_dep(ext: str) -> str | None:
    """Check if the optional dependency for a file extension is installed.

    Returns an error message string if missing, None if available or not needed.
    """
    ext = ext.lower()
    if ext not in _OPTIONAL_DEPS:
        return None

    package_name, install_cmd = _OPTIONAL_DEPS[ext]
    import_name = _IMPORT_NAMES.get(package_name, package_name)

    try:
        __import__(import_name)
        return None
    except ImportError:
        return (
            f"Package '{package_name}' is not installed but required for "
            f"{ext} files. Install with: {install_cmd}"
        )


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@mcp.tool()
def scan_file(file_path: str) -> dict:
    """Scan a file for student PII patterns. Returns findings with severity,
    confidence, pattern type, and count. Advisory only -- does not modify
    the file."""
    path = Path(file_path)

    # Validate file exists
    if not path.exists():
        return {"error": f"File not found: {file_path}"}

    # Validate extension
    ext = path.suffix.lower()
    if ext not in SCANNABLE_EXTENSIONS:
        supported = ", ".join(sorted(SCANNABLE_EXTENSIONS))
        return {"error": f"Unsupported file type '{ext}'. Supported: {supported}"}

    # Check optional dependency
    dep_error = _check_optional_dep(ext)
    if dep_error:
        return {"error": dep_error}

    # Allowlist check (bypass scanning for trusted files)
    allow_source = _check_allowlist(file_path)
    if allow_source is not None:
        timestamp = datetime.datetime.now().isoformat(timespec="seconds")
        _write_audit_entry(
            f"[{timestamp}] SCAN path={file_path} findings=skipped "
            f"action=allow_bypass source={allow_source}"
        )
        return {
            "file_path": file_path,
            "findings": [],
            "action": "allow",
            "summary": "File is on the allowlist. Scan skipped.",
        }

    # Read content
    scan_input = read_file_content(file_path)
    if not scan_input.content:
        return {
            "file_path": file_path,
            "findings": [],
            "action": "allow",
            "summary": "File is empty or could not be read.",
        }

    # Scan
    findings = scan_content(scan_input.content, scan_input.header_line_indices)

    # Determine action
    action = worst_action(findings) if findings else "allow"

    # Build response
    result = {
        "file_path": file_path,
        "findings": [
            {
                "pattern_name": f["pattern_name"],
                "description": f["description"],
                "severity": f["severity"],
                "confidence": f["confidence"],
                "count": f["count"],
            }
            for f in findings
        ],
        "action": action,
        "summary": (
            f"Found {len(findings)} PII pattern type(s). Action: {action}."
            if findings
            else "No PII detected."
        ),
    }

    # Audit entry for scan operation
    pattern_names = ",".join(f["pattern_name"] for f in findings) or "none"
    timestamp = datetime.datetime.now().isoformat(timespec="seconds")
    _write_audit_entry(
        f"[{timestamp}] SCAN path={file_path} "
        f"findings={len(findings)} action={action} patterns={pattern_names}"
    )

    return result


@mcp.tool()
def redact_file(file_path: str) -> dict:
    """Redact PII from a file and save a clean copy alongside the original.
    Headers and file structure are preserved. Returns the path to the
    redacted file."""
    path = Path(file_path)

    # Validate file exists
    if not path.exists():
        return {"error": f"File not found: {file_path}"}

    # Validate extension
    ext = path.suffix.lower()
    if ext not in SUPPORTED_EXTENSIONS:
        supported = ", ".join(sorted(SUPPORTED_EXTENSIONS))
        return {"error": f"File type '{ext}' not supported for redaction. Supported: {supported}"}

    # Check optional dependency
    dep_error = _check_optional_dep(ext)
    if dep_error:
        return {"error": dep_error}

    # Resolve output path
    output_path = _resolve_output_path(path)

    # Dispatch by format
    if ext == ".xlsx":
        count = redact_xlsx(path, output_path)
        unit = "cells"
    elif ext == ".csv":
        count = redact_csv(path, output_path, delimiter=",")
        unit = "rows"
    elif ext == ".tsv":
        count = redact_csv(path, output_path, delimiter="\t")
        unit = "rows"
    elif ext == ".json":
        count = redact_json(path, output_path)
        unit = "values"
    elif ext == ".jsonl":
        count = redact_jsonl(path, output_path)
        unit = "lines"
    else:
        count = redact_text_file(path, output_path)
        unit = "lines"

    result = {
        "output_path": str(output_path),
        "count": count,
        "unit": unit,
        "summary": f"Redacted {count} {unit}. Output: {output_path}",
    }

    # Audit entry for redact operation
    timestamp = datetime.datetime.now().isoformat(timespec="seconds")
    _write_audit_entry(
        f"[{timestamp}] REDACT path={file_path} "
        f"output={output_path} count={count} unit={unit}"
    )

    return result


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    mcp.run(transport="stdio")
