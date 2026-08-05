#!/usr/bin/env python3
"""
PII detection engine for K-12 student data protection.

Single source of truth for patterns, readers, scanning, confidence scoring,
and decision matrix. All surfaces (Claude Code hook, MCP server, redactor)
import from this module.
"""

import datetime
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ScanInput:
    """Content extracted from a file, with optional header metadata."""
    content: str
    header_line_indices: set = field(default_factory=set)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Max bytes to scan per text file (avoid stalling on huge files)
MAX_SCAN_BYTES = 2_000_000  # 2 MB

# Max cells to scan per xlsx sheet (avoid stalling on massive workbooks)
MAX_XLSX_CELLS = 50_000

# Max pages to scan per PDF (avoid stalling on bulk exports)
MAX_PDF_PAGES = 50

# File extensions to scan (data files likely to contain PII)
SCANNABLE_EXTENSIONS = {
    ".csv", ".tsv", ".txt", ".json", ".jsonl", ".xml",
    ".sql", ".log", ".dat",
    ".xls", ".xlsx",
    ".pdf", ".docx",
    ".md", ".html", ".htm",
}

# Directories to always skip (never contain student data)
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".next", ".vercel",
    ".claude", ".planning", ".backups",
}

# Documentation-convention basenames, exempt by exact (case-insensitive) name.
# Naming a column in docs is not disclosing a record; scanning these files
# blocked documentation ABOUT student data and locked files out of their own
# remediation. Exact-name match only -- never substring or glob.
SKIP_FILENAMES = {"claude.md", "readme.md", "agent.md", "agents.md"}

# Directory-walking allowfile: a dotfile dropped in a data directory (or any
# ancestor, up to the depth cap) declares allowed entries. Read fresh on every
# call, so allowing a file takes effect on the very next tool invocation --
# no settings edit, no session restart. This is the escape hatch environment
# variables can never be: the hook inherits Claude Code's environment, which
# a running session cannot change.
ALLOWFILE_NAME = ".pii-guardian-allow"
ALLOWFILE_MAX_DEPTH = 12

# ---------------------------------------------------------------------------
# PII Pattern Registry
# ---------------------------------------------------------------------------

PII_PATTERNS = {
    # --- Standard PII ---
    "SSN": {
        "pattern": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "description": "Social Security Number (XXX-XX-XXXX)",
        "severity": "critical",
    },
    "SSN_NO_DASHES": {
        "pattern": re.compile(r"(?<!\d)\d{9}(?!\d)"),
        "description": "Possible SSN without dashes (9 consecutive digits)",
        "severity": "high",
        "min_context": True,
    },
    "EMAIL": {
        "pattern": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
        "description": "Email address",
        "severity": "medium",
    },
    "PHONE": {
        # Require delimiters between all three groups (dash, space, or parens).
        # Dots are excluded as delimiters to avoid false positives on decimal
        # numbers like 619066.6169 and 430163.2581 in financial data.
        # Matches: (401) 555-1234, 401-555-1234, 401 555 1234, +1 401-555-1234
        # Rejects: 6190666169, 619066.6169, 430163.2581, 401.555.1234
        "pattern": re.compile(
            r"(?<!\d)"                             # no digit before
            r"(?:\+?1[-\s])?"                      # optional country code
            r"(?:"
            r"\(\d{3}\)[-\s]?\d{3}[-\s]?\d{4}"    # (401) 555-1234
            r"|"
            r"\d{3}[-\s]\d{3}[-\s]\d{4}"          # 401-555-1234 or 401 555 1234
            r")"
            r"(?!\d)"                              # no digit after
        ),
        "description": "Phone number",
        "severity": "medium",
    },
    "DOB": {
        # Match MM/DD/YYYY, MM-DD-YYYY, and YYYY-MM-DD (ISO 8601) when near
        # a birth-related keyword. ISO format is common in SIS API exports
        # (PowerSchool, Infinite Campus). This avoids flagging random dates.
        "pattern": re.compile(
            r"\b(?:"
            r"(?:0[1-9]|1[0-2])[/-](?:0[1-9]|[12]\d|3[01])[/-](?:19|20)\d{2}"  # MM/DD/YYYY
            r"|"
            r"(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])"        # YYYY-MM-DD
            r")\b"
        ),
        "description": "Date of birth",
        "severity": "high",
        "min_context": True,
        "context_keywords": {"birth", "dob", "born", "date_of_birth", "date of birth", "birthdate", "bday"},
    },

    # --- Student Identifiers ---
    "SASID": {
        "pattern": re.compile(r"\b(?:SASID|sasid)[\s:=]*\d{6,12}\b"),
        "description": "State-Assigned Student ID (SASID)",
        "severity": "critical",
    },
    "STUDENT_ID_LABELED": {
        "pattern": re.compile(r"(?i)\b(?:student[_\s]?id|pupil[_\s]?id|sis[_\s]?id|ps[_\s]?id|dcid)[\s:=]*\d{4,10}\b"),
        "description": "Labeled student identifier",
        "severity": "critical",
    },
    "LUNCH_PIN": {
        "pattern": re.compile(r"(?i)\b(?:lunch[_\s]?pin|meal[_\s]?pin|cafeteria[_\s]?pin)[\s:=]*\d{4,6}\b"),
        "description": "Lunch/meal PIN",
        "severity": "high",
    },

    # --- FERPA-Protected Fields ---
    "IEP_504_FLAG": {
        "pattern": re.compile(r"(?i)\b(?:iep|504[_\s]?plan|individualized[_\s]?education|accommodation[_\s]?plan)\b"),
        "description": "IEP/504 plan reference (FERPA-protected)",
        "severity": "high",
        "min_context": True,
    },
    "DISCIPLINE_RECORD": {
        "pattern": re.compile(r"(?i)\b(?:suspen(?:sion|ded)|expel(?:led|sion)|disciplin(?:e|ary)[_\s]?(?:record|action|incident)|in[_\s]?school[_\s]?suspension|iss|oss)\b"),
        "description": "Disciplinary record reference",
        "severity": "high",
        "min_context": True,
    },
    "MEDICAL_INFO": {
        "pattern": re.compile(r"(?i)\b(?:diagnos(?:is|ed)|medication|allergy|anaphyla|epinephrine|inhaler|seizure|diabetes|insulin)\b"),
        "description": "Medical information",
        "severity": "high",
        "min_context": True,
    },
    "PARENT_GUARDIAN": {
        "pattern": re.compile(r"(?i)\b(?:parent[_\s]?(?:name|email|phone|address|contact)|guardian[_\s]?(?:name|email|phone|address|contact)|mother[_\s]?(?:name|email)|father[_\s]?(?:name|email)|emergency[_\s]?contact)\b"),
        "description": "Parent/guardian contact information field",
        "severity": "high",
    },
    "HOME_ADDRESS": {
        # Case-insensitive to catch ALL CAPS and lowercase SIS exports.
        # Expanded road types for better coverage of US address formats.
        "pattern": re.compile(r"(?i)\b\d{1,5}\s+(?:[a-z]{2,}\s+){1,3}(?:st(?:reet)?|ave(?:nue)?|blvd|boulevard|dr(?:ive)?|ln|lane|rd|road|ct|court|way|pl(?:ace)?|cir(?:cle)?|ter(?:race)?|pkwy|parkway|hwy|highway|tr(?:ai)?l|loop|run|pike|al(?:le)?y)\b"),
        "description": "Home/street address",
        "severity": "medium",
    },
}

# Default context keywords for min_context patterns (education context)
DEFAULT_CONTEXT_KEYWORDS = {
    "student", "pupil", "child", "minor", "enrollment",
    "grade", "school", "classroom", "teacher", "parent",
    "guardian", "record", "ferpa", "confidential",
}

# ---------------------------------------------------------------------------
# File readers
# ---------------------------------------------------------------------------

def read_text_file(filepath: str) -> str:
    """Read a plain text file up to MAX_SCAN_BYTES."""
    try:
        with open(filepath, "r", errors="replace") as f:
            content = f.read(MAX_SCAN_BYTES)
            # Check if file had more content beyond the limit
            if f.read(1):
                print(
                    f"FERPA GUARD: Scanned first {MAX_SCAN_BYTES} bytes of {filepath}. "
                    "Content beyond that limit was not checked.",
                    file=sys.stderr,
                )
            return content
    except (OSError, PermissionError):
        return ""


def _looks_like_header(row) -> bool:
    """Heuristic: a row looks like a header if all non-empty cells are
    short text strings (no numbers, no PII-like patterns).

    This prevents data rows from being falsely tagged as headers when
    the xlsx has no header row or headers start below row 1.
    """
    non_empty = [cell for cell in row if cell is not None]
    if not non_empty:
        return False

    for cell in non_empty:
        # Numeric cells are data, not headers
        if isinstance(cell, (int, float)):
            return False
        s = str(cell)
        # Very long values are data, not column labels
        if len(s) > 60:
            return False
        # If a cell matches a PII pattern (SSN, email, phone), it's data
        if re.search(r"\b\d{3}-\d{2}-\d{4}\b", s):
            return False
        if re.search(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", s):
            return False
        if re.search(r"\b\d{3}[-\s]\d{3}[-\s]\d{4}\b", s):
            return False

    return True


def read_xlsx_file(filepath: str) -> ScanInput:
    """Extract cell text from an xlsx file using openpyxl.

    Returns a ScanInput with all cell values concatenated with newlines,
    preserving sheet names as context. The first row of each sheet is
    tagged as a header row only if it passes a heuristic check (all short
    text strings, no numeric or PII-like values). Scans up to
    MAX_XLSX_CELLS total.
    """
    try:
        import openpyxl
    except ImportError:
        # openpyxl not installed; fall back to skipping
        return ScanInput(content="")

    try:
        wb = openpyxl.load_workbook(filepath, read_only=True, data_only=True)
    except Exception:
        return ScanInput(content="")

    lines = []
    cell_count = 0
    header_line_indices = set()

    try:
        for sheet_name in wb.sheetnames:
            ws = wb[sheet_name]
            lines.append(f"[Sheet: {sheet_name}]")

            for row_idx, row in enumerate(ws.iter_rows(values_only=True)):
                if cell_count >= MAX_XLSX_CELLS:
                    break
                row_vals = []
                for cell in row:
                    if cell is not None:
                        row_vals.append(str(cell))
                        cell_count += 1
                if row_vals:
                    if row_idx == 0 and _looks_like_header(row):
                        header_line_indices.add(len(lines))
                    lines.append(",".join(row_vals))

            if cell_count >= MAX_XLSX_CELLS:
                lines.append(f"[Scan limit reached: {MAX_XLSX_CELLS} cells]")
                print(
                    f"FERPA GUARD: Scanned first {MAX_XLSX_CELLS} cells of {filepath}. "
                    "Content beyond that limit was not checked.",
                    file=sys.stderr,
                )
                break
    finally:
        wb.close()

    return ScanInput(content="\n".join(lines), header_line_indices=header_line_indices)


def read_pdf_file(filepath: str) -> str:
    """Extract text from a PDF using PyMuPDF (fitz).

    Scans up to MAX_PDF_PAGES. Returns page text concatenated with
    page markers for context.
    """
    try:
        import fitz
    except ImportError:
        # PyMuPDF not installed; skip
        return ""

    try:
        doc = fitz.open(filepath)
    except Exception:
        return ""

    lines = []
    try:
        for i, page in enumerate(doc):
            if i >= MAX_PDF_PAGES:
                lines.append(f"[Scan limit reached: {MAX_PDF_PAGES} pages]")
                print(
                    f"FERPA GUARD: Scanned first {MAX_PDF_PAGES} pages of {filepath}. "
                    "Content beyond that limit was not checked.",
                    file=sys.stderr,
                )
                break
            text = page.get_text()
            if text.strip():
                lines.append(f"[Page {i + 1}]")
                lines.append(text[:MAX_SCAN_BYTES // MAX_PDF_PAGES])
    finally:
        doc.close()

    return "\n".join(lines)


def read_docx_file(filepath: str) -> str:
    """Extract text from a .docx file using python-docx.

    Reads paragraph text and table cell text, capped at MAX_SCAN_BYTES.
    """
    try:
        from docx import Document
    except ImportError:
        # python-docx not installed; skip
        return ""

    try:
        doc = Document(filepath)
    except Exception:
        return ""

    parts = []
    total = 0

    scan_limited = False

    for para in doc.paragraphs:
        text = para.text
        if text.strip():
            parts.append(text)
            total += len(text)
            if total >= MAX_SCAN_BYTES:
                scan_limited = True
                parts.append("[Scan limit reached]")
                break

    if not scan_limited:
        for table in doc.tables:
            for row in table.rows:
                cells = [cell.text for cell in row.cells if cell.text.strip()]
                if cells:
                    line = ",".join(cells)
                    parts.append(line)
                    total += len(line)
                    if total >= MAX_SCAN_BYTES:
                        scan_limited = True
                        parts.append("[Scan limit reached]")
                        break
            if scan_limited:
                break

    if scan_limited:
        print(
            f"FERPA GUARD: Scanned first {MAX_SCAN_BYTES} bytes of {filepath}. "
            "Content beyond that limit was not checked.",
            file=sys.stderr,
        )

    return "\n".join(parts)


def read_file_content(filepath: str) -> ScanInput:
    """Read file content using the appropriate reader for the file type."""
    ext = Path(filepath).suffix.lower()

    if ext == ".xlsx":
        return read_xlsx_file(filepath)
    elif ext == ".pdf":
        return ScanInput(content=read_pdf_file(filepath))
    elif ext == ".docx":
        return ScanInput(content=read_docx_file(filepath))
    elif ext == ".xls":
        # .xls (legacy format) not supported by openpyxl; scan as binary text
        return ScanInput(content=read_text_file(filepath))
    else:
        return ScanInput(content=read_text_file(filepath))


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def write_audit_event(log_path, action: str, file: str, patterns, source: str = None) -> None:
    """Append one JSONL audit record. Never raises; never affects the decision.

    Records pattern NAMES only -- matched values and file content must never
    reach the audit trail. `source` is set on bypass events to attribute the
    allowlist mechanism that granted it (env / user file / ancestor allowfile).
    """
    rec = {
        "v": 1,
        "ts": datetime.datetime.now().isoformat(timespec="seconds"),
        "action": action,
        "file": file,
        "patterns": list(patterns),
    }
    if source:
        rec["source"] = source
    try:
        log_path = Path(log_path)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a") as fh:
            fh.write(json.dumps(rec) + "\n")
    except OSError:
        pass


def collect_allowfile_entries(filepath: str) -> dict:
    """Collect allowed entries from `.pii-guardian-allow` files in the target's
    ancestor directories.

    Returns {resolved_entry_path: declaring_allowfile_path}. Attribution is
    nearest-first-wins: when nested allowfiles declare the same resolved entry,
    the entry maps to the allowfile closest to the target (setdefault), so
    audit provenance always names the nearest declaration.

    Entries are one per line; blank lines and `#` comments are ignored.
    Absolute entries are kept as written; relative entries resolve against the
    declaring allowfile's own directory. The target is resolved first, so the
    walk runs over the real file's ancestors even when read through a symlink.
    """
    entries: dict = {}
    try:
        target = Path(filepath).resolve()
    except OSError:
        return entries

    for parent in list(target.parents)[:ALLOWFILE_MAX_DEPTH]:
        allowfile = parent / ALLOWFILE_NAME
        try:
            if not allowfile.is_file():
                continue
            for line in allowfile.read_text(errors="replace").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                candidate = Path(line) if os.path.isabs(line) else (parent / line)
                try:
                    resolved_entry = str(candidate.resolve())
                except OSError:
                    resolved_entry = str(candidate)
                entries.setdefault(resolved_entry, str(allowfile))
        except OSError:
            continue

    return entries


def should_scan(filepath: str) -> bool:
    """Decide whether a file path is worth scanning."""
    p = Path(filepath)

    if p.suffix.lower() not in SCANNABLE_EXTENSIONS:
        return False

    if p.name.lower() in SKIP_FILENAMES:
        return False

    for part in p.parts:
        if part in SKIP_DIRS:
            return False

    return True


def scan_content(content: str, header_line_indices: set = None,
                  early_exit: bool = False,
                  skip_patterns: set = None) -> list[dict]:
    """Scan text content for PII patterns. Returns list of findings.

    Each finding includes confidence and header_only fields. When
    header_line_indices is provided (from XLSX reader), matches are
    tracked per-line to determine if they appear only in header rows.

    When early_exit=True, returns immediately after the first CRITICAL
    finding (used by the hook for faster blocking on large files).

    When skip_patterns is provided, those pattern names are excluded
    from scanning (e.g., {"SSN", "SSN_NO_DASHES"}).
    """
    if not content:
        return []

    findings = []
    content_lower = content.lower()

    # Check for default education context (used by most min_context patterns)
    has_edu_context = any(kw in content_lower for kw in DEFAULT_CONTEXT_KEYWORDS)

    # Split into lines for per-line matching when header info is available
    lines = content.split("\n") if header_line_indices else None

    for name, spec in PII_PATTERNS.items():
        if skip_patterns and name in skip_patterns:
            continue
        # Handle context requirements
        if spec.get("min_context"):
            # Pattern-specific context keywords override the default set
            pattern_keywords = spec.get("context_keywords")
            if pattern_keywords:
                # This pattern needs its OWN keywords present (e.g., DOB needs "birth"/"dob")
                if not any(kw in content_lower for kw in pattern_keywords):
                    continue
            else:
                # Use default education context
                if not has_edu_context:
                    continue

        compiled = spec["pattern"]
        matches = compiled.findall(content)
        if matches:
            # Determine if all matches are in header lines only
            header_only = False
            if header_line_indices and lines:
                has_data_match = False
                has_header_match = False
                for line_idx, line in enumerate(lines):
                    if compiled.search(line):
                        if line_idx in header_line_indices:
                            has_header_match = True
                        else:
                            has_data_match = True
                header_only = has_header_match and not has_data_match

            findings.append({
                "pattern_name": name,
                "description": spec["description"],
                "severity": spec["severity"],
                "count": len(matches),
                "confidence": "high",
                "header_only": header_only,
            })

            # Early exit: skip remaining patterns once a CRITICAL match is found
            if early_exit and spec["severity"] == "critical":
                return findings

    # Calculate confidence scores based on count, co-occurrence, and position
    if findings:
        total_lines = content.count("\n") + 1 if content else 0
        _calculate_confidence(findings, total_lines=total_lines)

    return findings


# Patterns whose matches are structurally unambiguous (always HIGH confidence)
_HIGH_CONFIDENCE_FLOOR = {"SSN", "SASID", "STUDENT_ID_LABELED"}

# Keyword-only patterns that match common words in non-PII contexts
# (compliance docs, training materials, policy documents, health class assignments).
# These require stronger co-occurrence signals to reach HIGH confidence because
# the keywords alone don't prove student-specific PII is present.
_KEYWORD_AMBIGUITY_PENALTY = {"IEP_504_FLAG", "DISCIPLINE_RECORD", "MEDICAL_INFO"}


def _calculate_confidence(findings: list[dict], total_lines: int = 0) -> None:
    """Compute confidence tier for each finding based on count,
    co-occurrence with other pattern types, header position, and
    pattern reliability.
    Mutates findings in place.
    """
    distinct_types = len(findings)

    for f in findings:
        # Hard floor: structurally unambiguous patterns are always HIGH
        if f["pattern_name"] in _HIGH_CONFIDENCE_FLOOR:
            f["confidence"] = "high"
            continue

        score = 0

        # Signal 1: match count
        if f["count"] >= 5:
            score += 3
        elif f["count"] >= 3:
            score += 2
        elif f["count"] >= 2:
            score += 1

        # Signal 2: co-occurrence with other PII types
        if distinct_types >= 3:
            score += 2
        elif distinct_types >= 2:
            score += 1

        # Signal 3: header position penalty
        if f["header_only"]:
            score -= 3

        # Signal 4: keyword-ambiguity penalty for patterns that match
        # common words (IEP in policy docs, "medication" in health class).
        # These patterns need co-occurrence with structural PII (SSN,
        # student ID, email) to be confident, not just high count alone.
        if f["pattern_name"] in _KEYWORD_AMBIGUITY_PENALTY:
            score -= 1

        # Signal 5: small-file boost
        # In files with fewer than 10 rows, even a single match is
        # proportionally significant. Boost to prevent underweighting.
        if 0 < total_lines < 10:
            score += 2

        # Map score to tier
        if score >= 3:
            f["confidence"] = "high"
        elif score >= 1:
            f["confidence"] = "medium"
        else:
            f["confidence"] = "low"


def decide_action(severity: str, confidence: str) -> str:
    """Map severity x confidence to an action: block, warn, or log.

    | Severity    | HIGH conf | MEDIUM conf | LOW conf |
    |-------------|-----------|-------------|----------|
    | critical    | block     | block       | warn     |
    | high        | block     | warn        | log      |
    | medium      | warn      | log         | log      |
    """
    matrix = {
        ("critical", "high"): "block",
        ("critical", "medium"): "block",
        ("critical", "low"): "warn",
        ("high", "high"): "block",
        ("high", "medium"): "warn",
        ("high", "low"): "log",
        ("medium", "high"): "warn",
        ("medium", "medium"): "log",
        ("medium", "low"): "log",
    }
    return matrix.get((severity, confidence), "block")


_ACTION_ORDER = {"block": 0, "warn": 1, "log": 2}


def worst_action(findings: list[dict]) -> str:
    """Return the most severe action across all findings in a file."""
    worst = "log"
    for f in findings:
        action = decide_action(f["severity"], f["confidence"])
        if _ACTION_ORDER[action] < _ACTION_ORDER[worst]:
            worst = action
    return worst
