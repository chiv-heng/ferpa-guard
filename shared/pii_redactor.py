#!/usr/bin/env python3
"""
pii_redactor.py -- Cell-level PII redaction using patterns from shared.pii_engine

Reads a data file, replaces PII matches with safe synthetic values, and writes
a _redacted copy alongside the original. Works on any file structure without
needing to know column names.

Patterns are sourced from the shared detection engine (pii_engine.PII_PATTERNS).
Replacement functions are redaction-specific logic and live in this module.

Usage:
    python3 pii_redactor.py /path/to/file.csv

Output: /path/to/file_redacted.csv

Supports: .csv, .tsv, .txt, .json, .jsonl, .xml, .xlsx
(PDF and DOCX redaction not supported -- those require format-aware rewriting.)
"""

import csv
import hashlib
import json
import re
import sys
from pathlib import Path

# Ensure project root is importable when running as a script
_project_root = str(Path(__file__).parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from shared.pii_engine import PII_PATTERNS


# ---------------------------------------------------------------------------
# Replacement generators
# ---------------------------------------------------------------------------

def _hash(value: str, length: int = 8) -> str:
    """Deterministic hash so the same input always produces the same output."""
    return hashlib.sha256(value.encode()).hexdigest()[:length]


def _replace_ssn(match: re.Match) -> str:
    return f"XXX-XX-{_hash(match.group(), 4)}"


def _replace_ssn_no_dashes(match: re.Match) -> str:
    return f"XXXXXXXXX"


def _replace_email(match: re.Match) -> str:
    local = _hash(match.group(), 6)
    return f"{local}@redacted.example"


def _replace_phone(match: re.Match) -> str:
    return "000-000-0000"


def _replace_dob(match: re.Match) -> str:
    """Replace DOB with birth quarter (Q1-Q4/YYYY).

    Preserves cohort analysis capability while removing
    re-identification risk. Both US and ISO formats produce
    the same Q{n}/YYYY output.
    """
    parts = re.split(r"[/-]", match.group())
    if len(parts) == 3:
        if len(parts[0]) == 4:
            year, month = parts[0], parts[1]
        else:
            month, year = parts[0], parts[2]
        quarter = (int(month) - 1) // 3 + 1
        return f"Q{quarter}/{year}"
    return "Q1/2000"


def _replace_sasid(match: re.Match) -> str:
    prefix = "SASID: " if ":" in match.group() else "SASID "
    return f"{prefix}REDACTED"


def _replace_student_id(match: re.Match) -> str:
    # Keep the label, replace the number
    label_match = re.match(r"(?i)((?:student|pupil|sis|ps)[_\s]?id|dcid)[\s:=]*", match.group())
    if label_match:
        return f"{label_match.group()}XXXXX"
    return "id: XXXXX"


def _replace_lunch_pin(match: re.Match) -> str:
    label_match = re.match(r"(?i)((?:lunch|meal|cafeteria)[_\s]?pin)[\s:=]*", match.group())
    if label_match:
        return f"{label_match.group()}0000"
    return "pin: 0000"


def _replace_address(match: re.Match) -> str:
    return "123 Redacted St"


def _replace_parent_field(match: re.Match) -> str:
    # Keep the field label, it's metadata not PII
    return match.group()


# ---------------------------------------------------------------------------
# Redaction pipeline
# ---------------------------------------------------------------------------

# Map engine pattern names to replacement functions.
# Not all detection patterns have redaction rules:
# - IEP_504_FLAG, DISCIPLINE_RECORD, MEDICAL_INFO: keyword-only, nothing to redact
# - PARENT_GUARDIAN: field label is metadata, kept as-is
# - SSN_NO_DASHES: 9-digit numbers too ambiguous to safely replace
_REPLACERS = {
    "SSN": _replace_ssn,
    "SASID": _replace_sasid,
    "STUDENT_ID_LABELED": _replace_student_id,
    "LUNCH_PIN": _replace_lunch_pin,
    "DOB": _replace_dob,
    "EMAIL": _replace_email,
    "PHONE": _replace_phone,
    "HOME_ADDRESS": _replace_address,
}

# Priority order for redaction: critical patterns first to avoid partial matches
_SEVERITY_PRIORITY = {"critical": 0, "high": 1, "medium": 2}


def _build_redaction_rules():
    """Build ordered redaction rules from the shared pattern registry.

    Returns list of (pattern_str, replacer_fn) tuples, ordered by severity
    (critical first) to ensure more specific patterns match before general ones.
    """
    rules = []
    for name, replacer in _REPLACERS.items():
        if name in PII_PATTERNS:
            spec = PII_PATTERNS[name]
            priority = _SEVERITY_PRIORITY.get(spec["severity"], 99)
            rules.append((spec["pattern"], replacer, priority))
    rules.sort(key=lambda r: r[2])
    return [(pattern, replacer) for pattern, replacer, _ in rules]


REDACTION_RULES = _build_redaction_rules()


def redact_text(text: str) -> str:
    """Apply all redaction rules to a string."""
    for pattern, replacer in REDACTION_RULES:
        text = re.sub(pattern, replacer, text)
    return text


# ---------------------------------------------------------------------------
# File handlers
# ---------------------------------------------------------------------------

SUPPORTED_EXTENSIONS = {".csv", ".tsv", ".txt", ".json", ".jsonl", ".xml", ".xlsx"}


def redact_xlsx(input_path: Path, output_path: Path) -> int:
    """Redact an XLSX file cell by cell, preserving structure. Returns cell count."""
    try:
        import openpyxl
    except ImportError:
        print("Error: openpyxl is required for XLSX redaction. Install with: pip3 install openpyxl")
        sys.exit(1)

    wb = openpyxl.load_workbook(input_path)
    cell_count = 0

    for ws in wb.worksheets:
        for row_idx, row in enumerate(ws.iter_rows(), start=1):
            for cell in row:
                if cell.value is not None and isinstance(cell.value, str):
                    # Skip header row (row 1) -- column names are metadata
                    if row_idx == 1:
                        continue
                    original = cell.value
                    redacted = redact_text(original)
                    if redacted != original:
                        cell.value = redacted
                        cell_count += 1

    wb.save(output_path)
    wb.close()
    return cell_count


def redact_csv(input_path: Path, output_path: Path, delimiter: str = ",") -> int:
    """Redact a CSV/TSV file cell by cell. Returns row count."""
    with open(input_path, "r", newline="", errors="replace") as infile:
        # Sniff or use provided delimiter
        reader = csv.reader(infile, delimiter=delimiter)
        rows = list(reader)

    if not rows:
        return 0

    with open(output_path, "w", newline="") as outfile:
        writer = csv.writer(outfile, delimiter=delimiter)
        # Keep header row as-is (column names are metadata, not PII)
        writer.writerow(rows[0])
        for row in rows[1:]:
            writer.writerow([redact_text(cell) for cell in row])

    return len(rows) - 1


def redact_text_file(input_path: Path, output_path: Path) -> int:
    """Redact a plain text file line by line. Returns line count."""
    with open(input_path, "r", errors="replace") as infile:
        lines = infile.readlines()

    with open(output_path, "w") as outfile:
        for line in lines:
            outfile.write(redact_text(line))

    return len(lines)


def redact_json(input_path: Path, output_path: Path) -> int:
    """Redact string values in a JSON file. Returns count of values processed."""
    with open(input_path, "r", errors="replace") as infile:
        content = infile.read()

    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        # Fall back to line-by-line text redaction
        return redact_text_file(input_path, output_path)

    count = [0]

    def redact_values(obj):
        if isinstance(obj, str):
            count[0] += 1
            return redact_text(obj)
        elif isinstance(obj, dict):
            return {k: redact_values(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [redact_values(item) for item in obj]
        return obj

    redacted = redact_values(data)

    with open(output_path, "w") as outfile:
        json.dump(redacted, outfile, indent=2)

    return count[0]


def redact_jsonl(input_path: Path, output_path: Path) -> int:
    """Redact a JSONL file line by line. Returns line count."""
    count = 0
    with open(input_path, "r", errors="replace") as infile, \
         open(output_path, "w") as outfile:
        for line in infile:
            line = line.strip()
            if not line:
                outfile.write("\n")
                continue
            try:
                obj = json.loads(line)
                # Recursively redact string values
                def redact_obj(o):
                    if isinstance(o, str):
                        return redact_text(o)
                    elif isinstance(o, dict):
                        return {k: redact_obj(v) for k, v in o.items()}
                    elif isinstance(o, list):
                        return [redact_obj(i) for i in o]
                    return o
                redacted = redact_obj(obj)
                outfile.write(json.dumps(redacted) + "\n")
            except json.JSONDecodeError:
                outfile.write(redact_text(line) + "\n")
            count += 1
    return count


# ---------------------------------------------------------------------------
# Output path resolution
# ---------------------------------------------------------------------------

def _resolve_output_path(input_path: Path) -> Path:
    """Find next available _redacted output path, avoiding overwrites.

    First run: file_redacted.csv
    Second run: file_redacted_2.csv
    Third run: file_redacted_3.csv
    """
    ext = input_path.suffix
    stem = input_path.stem
    parent = input_path.parent

    candidate = parent / f"{stem}_redacted{ext}"
    if not candidate.exists():
        return candidate

    counter = 2
    while True:
        candidate = parent / f"{stem}_redacted_{counter}{ext}"
        if not candidate.exists():
            return candidate
        counter += 1


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 pii-redactor.py <input-file>")
        print("Supported: .csv, .tsv, .txt, .json, .jsonl, .xml, .xlsx")
        sys.exit(1)

    input_path = Path(sys.argv[1])

    if not input_path.exists():
        print(f"Error: File not found: {input_path}")
        sys.exit(1)

    ext = input_path.suffix.lower()
    if ext not in SUPPORTED_EXTENSIONS:
        print(f"Error: Unsupported file type '{ext}'. Supported: {', '.join(sorted(SUPPORTED_EXTENSIONS))}")
        sys.exit(1)

    output_path = _resolve_output_path(input_path)

    if ext == ".xlsx":
        count = redact_xlsx(input_path, output_path)
        unit = "cells"
    elif ext == ".csv":
        count = redact_csv(input_path, output_path, delimiter=",")
        unit = "rows"
    elif ext == ".tsv":
        count = redact_csv(input_path, output_path, delimiter="\t")
        unit = "rows"
    elif ext == ".json":
        count = redact_json(input_path, output_path)
        unit = "values"
    elif ext == ".jsonl":
        count = redact_jsonl(input_path, output_path)
        unit = "lines"
    else:
        count = redact_text_file(input_path, output_path)
        unit = "lines"

    print(f"Redacted {count} {unit} -> {output_path}")


if __name__ == "__main__":
    main()
