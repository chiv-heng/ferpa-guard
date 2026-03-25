#!/usr/bin/env python3
"""
Tests for PII Guardian MCP server tool functions.

Tests call scan_file and redact_file directly as Python functions
(they return dicts), not via MCP protocol.
"""

import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

# Add project root and cowork dir to sys.path
_project_root = str(Path(__file__).parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

import cowork.mcp_server as server
from cowork.mcp_server import scan_file, redact_file, _check_optional_dep


class TestScanFile(unittest.TestCase):
    """Tests for the scan_file MCP tool."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_scan_csv_with_ssn(self):
        """Scanning a CSV with an SSN returns a CRITICAL finding and blocks."""
        csv_path = self.tmp / "students.csv"
        # Include enough rows and education context to ensure detection
        csv_path.write_text(
            "name,ssn,grade\n"
            "Alice,123-45-6789,10\n"
            "Bob,234-56-7890,11\n"
            "Charlie,345-67-8901,12\n"
            "Diana,456-78-9012,10\n"
            "Eve,567-89-0123,11\n"
            "Frank,678-90-1234,12\n"
            "Grace,789-01-2345,10\n"
            "Hank,890-12-3456,11\n"
            "Iris,901-23-4567,12\n"
            "Jack,012-34-5678,10\n"
        )
        result = scan_file(str(csv_path))

        self.assertNotIn("error", result)
        self.assertTrue(len(result["findings"]) > 0)

        ssn_findings = [
            f for f in result["findings"] if "SSN" in f["pattern_name"]
        ]
        self.assertTrue(len(ssn_findings) > 0)
        self.assertEqual(ssn_findings[0]["severity"], "critical")
        self.assertGreaterEqual(ssn_findings[0]["count"], 1)
        self.assertEqual(result["action"], "block")

    def test_scan_clean_file(self):
        """Scanning a file with no PII returns empty findings and allows."""
        csv_path = self.tmp / "grades.csv"
        # 10+ rows of clean data to avoid small-file boost
        csv_path.write_text(
            "Name,Grade\n"
            "Alice,A\n"
            "Bob,B\n"
            "Charlie,C\n"
            "Diana,A\n"
            "Eve,B\n"
            "Frank,C\n"
            "Grace,A\n"
            "Hank,B\n"
            "Iris,C\n"
            "Jack,A\n"
            "Kate,B\n"
        )
        result = scan_file(str(csv_path))

        self.assertNotIn("error", result)
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["action"], "allow")

    def test_scan_file_not_found(self):
        """Scanning a nonexistent file returns an error."""
        result = scan_file("/nonexistent/path/fake.csv")

        self.assertIn("error", result)
        self.assertIn("not found", result["error"].lower())

    def test_scan_unsupported_extension(self):
        """Scanning a file with unsupported extension returns an error."""
        xyz_path = self.tmp / "data.xyz"
        xyz_path.write_text("some data")
        result = scan_file(str(xyz_path))

        self.assertIn("error", result)
        self.assertIn("Unsupported", result["error"])

    def test_scan_empty_file(self):
        """Scanning an empty file returns allow with appropriate summary."""
        csv_path = self.tmp / "empty.csv"
        csv_path.write_text("")
        result = scan_file(str(csv_path))

        self.assertNotIn("error", result)
        self.assertEqual(result["action"], "allow")
        self.assertIn("empty", result["summary"].lower())


class TestRedactFile(unittest.TestCase):
    """Tests for the redact_file MCP tool."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_redact_csv(self):
        """Redacting a CSV with SSN produces a clean output file."""
        csv_path = self.tmp / "roster.csv"
        csv_path.write_text("id,ssn\n1,123-45-6789\n2,234-56-7890\n")
        result = redact_file(str(csv_path))

        self.assertNotIn("error", result)
        self.assertIn("output_path", result)

        output_path = Path(result["output_path"])
        self.assertTrue(output_path.exists())

        # Verify the original SSN is not in the output
        content = output_path.read_text()
        self.assertNotIn("123-45-6789", content)
        self.assertNotIn("234-56-7890", content)

        self.assertGreater(result["count"], 0)
        self.assertEqual(result["unit"], "rows")

    def test_redact_file_not_found(self):
        """Redacting a nonexistent file returns an error."""
        result = redact_file("/nonexistent/path/fake.csv")

        self.assertIn("error", result)

    def test_redact_unsupported_extension(self):
        """Redacting a file with unsupported extension returns an error."""
        xyz_path = self.tmp / "data.xyz"
        xyz_path.write_text("some data")
        result = redact_file(str(xyz_path))

        self.assertIn("error", result)
        self.assertIn("not supported", result["error"].lower())


class TestDependencyCheck(unittest.TestCase):
    """Tests for the optional dependency pre-check."""

    def test_check_known_extensions(self):
        """Known extensions return None (installed) or a helpful message."""
        for ext in [".xlsx", ".pdf", ".docx"]:
            result = _check_optional_dep(ext)
            if result is not None:
                self.assertIn("not installed", result.lower())
                self.assertIn("pip install", result.lower())

    def test_check_standard_extensions(self):
        """Standard extensions (no optional dep) return None."""
        for ext in [".csv", ".txt", ".json", ".tsv"]:
            result = _check_optional_dep(ext)
            self.assertIsNone(result)


# Helper: 10+ row CSV with SSN for reliable detection
_SSN_CSV_10_ROWS = (
    "name,ssn,grade\n"
    "Alice,123-45-6789,10\n"
    "Bob,234-56-7890,11\n"
    "Charlie,345-67-8901,12\n"
    "Diana,456-78-9012,10\n"
    "Eve,567-89-0123,11\n"
    "Frank,678-90-1234,12\n"
    "Grace,789-01-2345,10\n"
    "Hank,890-12-3456,11\n"
    "Iris,901-23-4567,12\n"
    "Jack,012-34-5678,10\n"
)

# Helper: 10+ row clean CSV for no-PII tests
_CLEAN_CSV_10_ROWS = (
    "Name,Grade\n"
    "Alice,A\nBob,B\nCharlie,C\nDiana,A\nEve,B\n"
    "Frank,C\nGrace,A\nHank,B\nIris,C\nJack,A\nKate,B\n"
)


class TestMCPAuditLog(unittest.TestCase):
    """Tests for audit logging in scan_file and redact_file (MCP-06)."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmpdir.name)
        # Create temp audit log path for test isolation
        self.audit_dir = self.tmp / ".claude"
        self.audit_dir.mkdir(parents=True)
        self.audit_path = self.audit_dir / "pii-guardian-audit.log"
        # Monkeypatch AUDIT_LOG_PATH
        self._original_audit_path = server.AUDIT_LOG_PATH
        server.AUDIT_LOG_PATH = self.audit_path
        # Clear any PII_GUARDIAN_ALLOW env var to avoid interference
        self._original_allow = os.environ.pop("PII_GUARDIAN_ALLOW", None)

    def tearDown(self):
        server.AUDIT_LOG_PATH = self._original_audit_path
        if self._original_allow is not None:
            os.environ["PII_GUARDIAN_ALLOW"] = self._original_allow
        self.tmpdir.cleanup()

    def test_scan_writes_audit_entry(self):
        """Scanning a file with PII writes a SCAN audit entry with action=block."""
        csv_path = self.tmp / "students.csv"
        csv_path.write_text(_SSN_CSV_10_ROWS)

        scan_file(str(csv_path))

        self.assertTrue(self.audit_path.exists())
        content = self.audit_path.read_text()
        self.assertIn("SCAN", content)
        self.assertIn(str(csv_path), content)
        self.assertIn("action=block", content)

    def test_scan_clean_file_writes_audit_entry(self):
        """Scanning a clean file writes a SCAN audit entry with findings=0."""
        csv_path = self.tmp / "grades.csv"
        csv_path.write_text(_CLEAN_CSV_10_ROWS)

        scan_file(str(csv_path))

        self.assertTrue(self.audit_path.exists())
        content = self.audit_path.read_text()
        self.assertIn("SCAN", content)
        self.assertIn("findings=0", content)
        self.assertIn("action=allow", content)

    def test_redact_writes_audit_entry(self):
        """Redacting a file writes a REDACT audit entry with output path and count."""
        csv_path = self.tmp / "roster.csv"
        csv_path.write_text(_SSN_CSV_10_ROWS)

        redact_file(str(csv_path))

        self.assertTrue(self.audit_path.exists())
        content = self.audit_path.read_text()
        self.assertIn("REDACT", content)
        self.assertIn(str(csv_path), content)
        self.assertIn("output=", content)
        self.assertIn("count=", content)

    def test_audit_entry_has_timestamp(self):
        """Audit entries start with an ISO timestamp in brackets."""
        csv_path = self.tmp / "data.csv"
        csv_path.write_text(_CLEAN_CSV_10_ROWS)

        scan_file(str(csv_path))

        content = self.audit_path.read_text()
        # Verify ISO timestamp format: [YYYY-MM-DDTHH:MM:SS]
        self.assertRegex(
            content,
            r"\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\]",
        )

    def test_audit_stderr_output(self):
        """Audit entries are also logged to stderr via the logger."""
        csv_path = self.tmp / "data.csv"
        csv_path.write_text(_CLEAN_CSV_10_ROWS)

        import logging
        # Capture log output
        with self.assertLogs("pii-guardian-mcp", level="INFO") as cm:
            scan_file(str(csv_path))

        # At least one log message should contain AUDIT
        audit_messages = [m for m in cm.output if "AUDIT" in m]
        self.assertTrue(len(audit_messages) > 0, "No AUDIT messages in logger output")

    def test_audit_survives_unwritable_path(self):
        """Audit log failure is non-fatal -- scan still returns a result."""
        csv_path = self.tmp / "data.csv"
        csv_path.write_text(_CLEAN_CSV_10_ROWS)

        # Point to an unwritable path (deeply nested non-existent with read-only parent)
        unwritable = Path("/proc/fake/deeply/nested/audit.log")
        server.AUDIT_LOG_PATH = unwritable

        # Should not raise -- audit failure is caught
        result = scan_file(str(csv_path))
        self.assertNotIn("error", result)
        self.assertEqual(result["action"], "allow")


class TestMCPAllowlist(unittest.TestCase):
    """Tests for allowlist bypass in scan_file (MCP-07)."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmpdir.name)
        # Create temp audit log path for test isolation
        self.audit_dir = self.tmp / ".claude"
        self.audit_dir.mkdir(parents=True)
        self.audit_path = self.audit_dir / "pii-guardian-audit.log"
        # Monkeypatch AUDIT_LOG_PATH
        self._original_audit_path = server.AUDIT_LOG_PATH
        server.AUDIT_LOG_PATH = self.audit_path
        # Clear any existing PII_GUARDIAN_ALLOW env var
        self._original_allow = os.environ.pop("PII_GUARDIAN_ALLOW", None)

    def tearDown(self):
        server.AUDIT_LOG_PATH = self._original_audit_path
        if self._original_allow is not None:
            os.environ["PII_GUARDIAN_ALLOW"] = self._original_allow
        else:
            os.environ.pop("PII_GUARDIAN_ALLOW", None)
        self.tmpdir.cleanup()

    def test_allowlisted_file_bypasses_scan(self):
        """A file on the allowlist is not scanned; result has action=allow."""
        csv_path = self.tmp / "students.csv"
        csv_path.write_text(_SSN_CSV_10_ROWS)

        # Put the file on the allowlist via env var
        os.environ["PII_GUARDIAN_ALLOW"] = str(csv_path)

        result = scan_file(str(csv_path))

        self.assertEqual(result["action"], "allow")
        self.assertIn("allowlist", result["summary"].lower())
        self.assertEqual(result["findings"], [])

    def test_allowlisted_dir_bypasses_scan(self):
        """A file in an allowlisted directory is not scanned."""
        subdir = self.tmp / "data"
        subdir.mkdir()
        csv_path = subdir / "roster.csv"
        csv_path.write_text(_SSN_CSV_10_ROWS)

        # Allowlist the directory, not the specific file
        os.environ["PII_GUARDIAN_ALLOW"] = str(subdir)

        result = scan_file(str(csv_path))

        self.assertEqual(result["action"], "allow")
        self.assertIn("allowlist", result["summary"].lower())

    def test_non_allowlisted_file_scans_normally(self):
        """A file not on the allowlist is scanned and findings returned."""
        csv_path = self.tmp / "students.csv"
        csv_path.write_text(_SSN_CSV_10_ROWS)

        # Ensure allowlist is empty
        os.environ.pop("PII_GUARDIAN_ALLOW", None)

        result = scan_file(str(csv_path))

        self.assertTrue(len(result["findings"]) > 0)
        self.assertEqual(result["action"], "block")

    def test_allowlisted_file_can_still_be_redacted(self):
        """An allowlisted file can still be redacted (allowlist only affects scan)."""
        csv_path = self.tmp / "roster.csv"
        csv_path.write_text(_SSN_CSV_10_ROWS)

        # Put the file on the allowlist
        os.environ["PII_GUARDIAN_ALLOW"] = str(csv_path)

        result = redact_file(str(csv_path))

        # Redaction should succeed regardless of allowlist
        self.assertNotIn("error", result)
        self.assertIn("output_path", result)
        output_path = Path(result["output_path"])
        self.assertTrue(output_path.exists())

        # Verify SSNs are actually redacted
        content = output_path.read_text()
        self.assertNotIn("123-45-6789", content)

    def test_allowlist_bypass_writes_audit_entry(self):
        """An allowlist bypass writes an audit entry with allow_bypass and source."""
        csv_path = self.tmp / "students.csv"
        csv_path.write_text(_SSN_CSV_10_ROWS)

        os.environ["PII_GUARDIAN_ALLOW"] = str(csv_path)

        scan_file(str(csv_path))

        self.assertTrue(self.audit_path.exists())
        content = self.audit_path.read_text()
        self.assertIn("allow_bypass", content)
        self.assertIn("env(PII_GUARDIAN_ALLOW)", content)


class TestNoStdoutCorruption(unittest.TestCase):
    """Static analysis guard against stdout corruption in the MCP server."""

    def test_no_bare_print(self):
        """Server file must not contain bare print() calls (stdout corrupts stdio)."""
        server_path = Path(__file__).parent.parent / "cowork" / "mcp_server.py"
        source = server_path.read_text()

        # Find print() calls that are NOT in comments, docstrings, or using file=sys.stderr
        bare_prints = []
        in_docstring = False
        for i, line in enumerate(source.split("\n"), 1):
            stripped = line.lstrip()

            # Track docstring boundaries (toggle on triple-quote lines)
            triple_dq = stripped.count('"""')
            triple_sq = stripped.count("'''")
            triple_count = triple_dq + triple_sq
            if triple_count == 1:
                in_docstring = not in_docstring
                continue
            elif triple_count >= 2:
                # Opening and closing on same line (single-line docstring)
                continue
            if in_docstring:
                continue

            # Skip comments and empty lines
            if stripped.startswith("#") or not stripped:
                continue
            # Look for print( calls
            if re.search(r'\bprint\s*\(', stripped):
                # Allow print(..., file=sys.stderr)
                if "file=sys.stderr" not in stripped:
                    bare_prints.append(f"Line {i}: {stripped}")

        self.assertEqual(
            bare_prints, [],
            f"Found bare print() calls (use logger or file=sys.stderr):\n"
            + "\n".join(bare_prints),
        )


if __name__ == "__main__":
    unittest.main()
