#!/usr/bin/env python3
"""
Test harness for ferpa-guard.py

Tests three layers:
  1. Pattern detection (scan_content) - does each regex find what it should?
  2. File readers (read_pdf_file, read_docx_file, etc.) - does extraction work?
  3. Hook protocol (main via stdin/stdout) - correct exit codes and JSON output?

All test data is synthetic. No real student records.

Run:  python3 scripts/test_pii_guardian.py
      python3 -m pytest scripts/test_pii_guardian.py -v   (if pytest installed)
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

# Add project root to path for shared package imports
_project_root = Path(__file__).parent.parent
sys.path.insert(0, str(_project_root))

# Engine functions (used by pattern detection, file reader, confidence, header awareness tests)
from shared.pii_engine import (
    ScanInput,
    scan_content,
    read_text_file,
    read_xlsx_file,
    read_pdf_file,
    read_docx_file,
    read_file_content,
    should_scan,
    decide_action,
    collect_allowfile_entries,
    ALLOWFILE_NAME,
    METADATA_PATTERNS,
    worst_action,
)

# Hook functions (used by path extraction tests)
_claude_code_dir = _project_root / "claude-code"
sys.path.insert(0, str(_claude_code_dir))
import pii_guardian as pg_hook


# ---------------------------------------------------------------------------
# Layer 1: Pattern Detection
# ---------------------------------------------------------------------------

class TestPatternDetection(unittest.TestCase):
    """Test scan_content against synthetic text for each PII pattern."""

    # --- True positives: patterns that SHOULD match ---

    def test_ssn_with_dashes(self):
        findings = scan_content("SSN: 123-45-6789")
        names = [f["pattern_name"] for f in findings]
        self.assertIn("SSN", names)

    def test_ssn_no_dashes_with_context(self):
        text = "student enrollment record: 123456789"
        findings = scan_content(text)
        names = [f["pattern_name"] for f in findings]
        self.assertIn("SSN_NO_DASHES", names)

    def test_email(self):
        findings = scan_content("contact: parent@school.edu")
        names = [f["pattern_name"] for f in findings]
        self.assertIn("EMAIL", names)

    def test_phone_with_dashes(self):
        findings = scan_content("call 401-555-1234")
        names = [f["pattern_name"] for f in findings]
        self.assertIn("PHONE", names)

    def test_phone_with_parens(self):
        findings = scan_content("call (401) 555-1234")
        names = [f["pattern_name"] for f in findings]
        self.assertIn("PHONE", names)

    def test_dob_with_context(self):
        text = "date of birth: 03/15/2010"
        findings = scan_content(text)
        names = [f["pattern_name"] for f in findings]
        self.assertIn("DOB", names)

    def test_dob_iso_format_with_context(self):
        """ISO 8601 dates (YYYY-MM-DD) should match when birth keywords present."""
        text = "dob: 2010-03-15"
        findings = scan_content(text)
        names = [f["pattern_name"] for f in findings]
        self.assertIn("DOB", names)

    def test_dob_iso_format_without_context(self):
        """ISO dates should NOT match without birth keywords."""
        text = "created_at: 2010-03-15"
        findings = scan_content(text)
        names = [f["pattern_name"] for f in findings]
        self.assertNotIn("DOB", names)

    def test_sasid(self):
        findings = scan_content("SASID: 123456789")
        names = [f["pattern_name"] for f in findings]
        self.assertIn("SASID", names)

    def test_student_id_labeled(self):
        findings = scan_content("student_id: 98765")
        names = [f["pattern_name"] for f in findings]
        self.assertIn("STUDENT_ID_LABELED", names)

    def test_sis_id_labeled(self):
        findings = scan_content("sis_id: 12345")
        names = [f["pattern_name"] for f in findings]
        self.assertIn("STUDENT_ID_LABELED", names)

    def test_lunch_pin(self):
        findings = scan_content("student lunch_pin: 4567")
        names = [f["pattern_name"] for f in findings]
        self.assertIn("LUNCH_PIN", names)

    def test_iep_with_context(self):
        text = "student record shows IEP active"
        findings = scan_content(text)
        names = [f["pattern_name"] for f in findings]
        self.assertIn("IEP_504_FLAG", names)

    def test_504_plan_with_context(self):
        text = "student has 504 plan accommodations"
        findings = scan_content(text)
        names = [f["pattern_name"] for f in findings]
        self.assertIn("IEP_504_FLAG", names)

    def test_discipline_with_context(self):
        text = "student suspension record for March"
        findings = scan_content(text)
        names = [f["pattern_name"] for f in findings]
        self.assertIn("DISCIPLINE_RECORD", names)

    def test_medical_with_context(self):
        text = "student diagnosed with allergy, carries epinephrine"
        findings = scan_content(text)
        names = [f["pattern_name"] for f in findings]
        self.assertIn("MEDICAL_INFO", names)

    def test_parent_guardian_field(self):
        findings = scan_content("parent_email: jane@example.com")
        names = [f["pattern_name"] for f in findings]
        self.assertIn("PARENT_GUARDIAN", names)

    def test_home_address(self):
        findings = scan_content("123 Main Street")
        names = [f["pattern_name"] for f in findings]
        self.assertIn("HOME_ADDRESS", names)

    def test_home_address_lowercase(self):
        """Lowercase addresses from SIS exports should match."""
        findings = scan_content("123 main street")
        names = [f["pattern_name"] for f in findings]
        self.assertIn("HOME_ADDRESS", names)

    def test_home_address_uppercase(self):
        """ALL CAPS addresses from SIS exports should match."""
        findings = scan_content("123 MAIN STREET")
        names = [f["pattern_name"] for f in findings]
        self.assertIn("HOME_ADDRESS", names)

    def test_home_address_expanded_road_types(self):
        """Expanded road types should match."""
        for address in ["456 Oak Terrace", "789 Pine Parkway", "101 Elm Trail"]:
            findings = scan_content(address)
            names = [f["pattern_name"] for f in findings]
            self.assertIn("HOME_ADDRESS", names, f"Failed on: {address}")

    # --- True negatives: patterns that SHOULD NOT match ---

    def test_no_ssn_in_phone(self):
        """Phone numbers should not trigger SSN pattern."""
        findings = scan_content("401-555-1234")
        names = [f["pattern_name"] for f in findings]
        self.assertNotIn("SSN", names)

    def test_no_phone_on_decimals(self):
        """Decimal numbers should not trigger phone pattern."""
        findings = scan_content("amount: 619066.6169")
        names = [f["pattern_name"] for f in findings]
        self.assertNotIn("PHONE", names)

    def test_no_dob_without_birth_keyword(self):
        """Dates without birth context should not trigger DOB."""
        text = "export timestamp: 03/15/2024"
        findings = scan_content(text)
        names = [f["pattern_name"] for f in findings]
        self.assertNotIn("DOB", names)

    def test_no_iep_without_education_context(self):
        """IEP mention in non-education text should not trigger."""
        text = "The IEP protocol was updated for the network."
        findings = scan_content(text)
        names = [f["pattern_name"] for f in findings]
        self.assertNotIn("IEP_504_FLAG", names)

    def test_no_medical_without_education_context(self):
        """Medical terms in non-education text should not trigger."""
        text = "The patient was diagnosed with diabetes."
        findings = scan_content(text)
        names = [f["pattern_name"] for f in findings]
        self.assertNotIn("MEDICAL_INFO", names)

    def test_no_ssn_no_dashes_without_context(self):
        """9-digit numbers without education context should not trigger."""
        text = "order number 123456789"
        findings = scan_content(text)
        names = [f["pattern_name"] for f in findings]
        self.assertNotIn("SSN_NO_DASHES", names)

    def test_clean_code_file_content(self):
        """Typical code content should produce no findings."""
        text = 'def calculate(x, y):\n    return x + y\n\nresult = calculate(10, 20)'
        findings = scan_content(text)
        self.assertEqual(findings, [])

    # --- Severity and count accuracy ---

    def test_severity_is_critical_for_ssn(self):
        findings = scan_content("SSN: 123-45-6789")
        ssn = [f for f in findings if f["pattern_name"] == "SSN"][0]
        self.assertEqual(ssn["severity"], "critical")

    def test_count_multiple_emails(self):
        text = "a@b.com and c@d.org and e@f.net"
        findings = scan_content(text)
        email = [f for f in findings if f["pattern_name"] == "EMAIL"][0]
        self.assertEqual(email["count"], 3)


# ---------------------------------------------------------------------------
# Layer 2: File Readers
# ---------------------------------------------------------------------------

class TestFileReaders(unittest.TestCase):
    """Test text extraction from various file formats."""

    def test_read_text_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("name,ssn\nJane,123-45-6789\n")
            path = f.name
        try:
            content = read_text_file(path)
            self.assertIn("123-45-6789", content)
        finally:
            os.unlink(path)

    def test_read_text_file_nonexistent(self):
        content = read_text_file("/tmp/does_not_exist_pii_test.csv")
        self.assertEqual(content, "")

    def test_read_xlsx_file(self):
        try:
            import openpyxl
        except ImportError:
            self.skipTest("openpyxl not installed")

        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
            path = f.name
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.append(["Name", "SSN"])
        ws.append(["Jane Doe", "123-45-6789"])
        wb.save(path)
        wb.close()

        try:
            scan_input = read_xlsx_file(path)
            self.assertIn("123-45-6789", scan_input.content)
        finally:
            os.unlink(path)

    def test_read_pdf_file(self):
        try:
            import fitz
        except ImportError:
            self.skipTest("PyMuPDF not installed")

        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            path = f.name
        doc = fitz.open()
        page = doc.new_page()
        page.insert_text((72, 72), "Student SSN: 123-45-6789")
        doc.save(path)
        doc.close()

        try:
            content = read_pdf_file(path)
            self.assertIn("123-45-6789", content)
            self.assertIn("[Page 1]", content)
        finally:
            os.unlink(path)

    def test_read_pdf_file_nonexistent(self):
        content = read_pdf_file("/tmp/does_not_exist_pii_test.pdf")
        self.assertEqual(content, "")

    def test_read_docx_file(self):
        try:
            from docx import Document
        except ImportError:
            self.skipTest("python-docx not installed")

        with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as f:
            path = f.name
        doc = Document()
        doc.add_paragraph("Student SSN: 123-45-6789")
        table = doc.add_table(rows=1, cols=2)
        table.cell(0, 0).text = "student_id"
        table.cell(0, 1).text = "99999"
        doc.save(path)

        try:
            content = read_docx_file(path)
            self.assertIn("123-45-6789", content)
            self.assertIn("student_id", content)
            self.assertIn("99999", content)
        finally:
            os.unlink(path)

    def test_read_docx_file_nonexistent(self):
        content = read_docx_file("/tmp/does_not_exist_pii_test.docx")
        self.assertEqual(content, "")

    def test_read_file_content_routes_correctly(self):
        """Verify the router picks the right reader by extension."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("test,data\n")
            path = f.name
        try:
            scan_input = read_file_content(path)
            self.assertIn("test,data", scan_input.content)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Layer 3: Hook Protocol (stdin/stdout/exit codes)
# ---------------------------------------------------------------------------

class TestHookProtocol(unittest.TestCase):
    """Test the full hook flow via subprocess, matching Claude Code's API."""

    SCRIPT = str(_claude_code_dir / "pii_guardian.py") if _claude_code_dir.is_dir() else str(Path(__file__).parent / "pii_guardian.py")

    def _run_hook(self, tool_name, tool_input, env_extra=None):
        """Run ferpa-guard.py as a subprocess with JSON on stdin."""
        payload = json.dumps({"tool_name": tool_name, "tool_input": tool_input})
        env = os.environ.copy()
        if env_extra:
            env.update(env_extra)
        result = subprocess.run(
            [sys.executable, self.SCRIPT],
            input=payload,
            capture_output=True,
            text=True,
            env=env,
        )
        return result

    def test_allow_clean_csv(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("color,count\nred,5\nblue,3\n")
            path = f.name
        try:
            result = self._run_hook("Read", {"file_path": path})
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout.strip(), "")
        finally:
            os.unlink(path)

    def test_readme_md_allowed_despite_blocking_content(self):
        """SKIP_FILENAMES: a readme.md is documentation-by-convention and is
        never scanned, even when its text would otherwise block."""
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "readme.md")
            with open(path, "w") as f:
                f.write("Example row: SSN 123-45-6789, SASID: 1234567890\n")
            result = self._run_hook("Read", {"file_path": path})
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout.strip(), "")

    def test_notreadme_md_still_blocked(self):
        """A near-miss basename gets no exemption."""
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "notreadme.md")
            with open(path, "w") as f:
                f.write("Example row: SSN 123-45-6789, SASID: 1234567890\n")
            result = self._run_hook("Read", {"file_path": path})
            self.assertEqual(result.returncode, 2)

    def test_deny_csv_with_ssn(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("name,ssn\nJane,123-45-6789\n")
            path = f.name
        try:
            result = self._run_hook("Read", {"file_path": path})
            self.assertEqual(result.returncode, 2)
            output = json.loads(result.stdout)
            decision = output["hookSpecificOutput"]["permissionDecision"]
            self.assertEqual(decision, "deny")
            self.assertIn("Social Security", result.stderr)
        finally:
            os.unlink(path)

    def test_deny_includes_recovery_instructions(self):
        """Denial output should include structured recovery options for Claude."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("name,ssn\nJane,123-45-6789\n")
            path = f.name
        try:
            result = self._run_hook("Read", {"file_path": path})
            stderr = result.stderr
            # User-facing section
            self.assertIn("FERPA Guard blocked", stderr)
            self.assertIn("FERPA", stderr)
            self.assertIn("What was found:", stderr)
            # Numbered options in user-facing section
            self.assertIn("1. Generate a synthetic", stderr)
            self.assertIn("2. Run the built-in redactor", stderr)
            self.assertIn("3. Keep only specific safe columns", stderr)
            # Claude-only section
            self.assertIn("INSTRUCTIONS FOR CLAUDE", stderr)
            self.assertIn("Do NOT re-read or bypass", stderr)
            self.assertIn("Option 1", stderr)
            self.assertIn("Option 2", stderr)
            self.assertIn("_synthetic.csv", stderr)
        finally:
            os.unlink(path)

    def test_deny_csv_includes_redactor_command(self):
        """For supported file types, Option 2 should include the redactor command."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("name,ssn\nJane,123-45-6789\n")
            path = f.name
        try:
            result = self._run_hook("Read", {"file_path": path})
            stderr = result.stderr
            self.assertIn("pii_redactor.py", stderr)
            self.assertIn("_redacted.csv", stderr)
            self.assertIn("Run the built-in redactor", stderr)
        finally:
            os.unlink(path)

    def test_deny_critical_includes_bypass_option(self):
        """Critical/high findings should include Option 4 (allowlist bypass)."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("student_id: 12345\n")
            path = f.name
        try:
            result = self._run_hook("Read", {"file_path": path})
            self.assertIn("Option 4", result.stderr)
            self.assertIn("FERPA_GUARD_ALLOW", result.stderr)
        finally:
            os.unlink(path)

    def test_medium_only_low_confidence_allows(self):
        """A single medium-severity match with low confidence should allow (log only)."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("contact: parent@school.edu\n")
            path = f.name
        try:
            result = self._run_hook("Read", {"file_path": path})
            self.assertEqual(result.returncode, 0)
            self.assertNotIn("Option 4", result.stderr)
        finally:
            os.unlink(path)

    def test_allow_code_file(self):
        """Code files (.py) should always be allowed regardless of content."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write('SSN = "123-45-6789"  # test constant\n')
            path = f.name
        try:
            result = self._run_hook("Read", {"file_path": path})
            self.assertEqual(result.returncode, 0)
        finally:
            os.unlink(path)

    def test_allow_nonexistent_file(self):
        result = self._run_hook("Read", {"file_path": "/tmp/no_such_file_pii.csv"})
        self.assertEqual(result.returncode, 0)

    def test_allow_non_matching_tool(self):
        result = self._run_hook("Write", {"file_path": "/tmp/anything.csv"})
        self.assertEqual(result.returncode, 0)

    def test_allowlist_bypass(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("name,ssn\nJane,123-45-6789\n")
            path = f.name
        try:
            result = self._run_hook(
                "Read",
                {"file_path": path},
                env_extra={"FERPA_GUARD_ALLOW": path},
            )
            self.assertEqual(result.returncode, 0)
        finally:
            os.unlink(path)

    def test_allowlist_file_bypass(self):
        """File-based allowlist (~/.claude/ferpa-guard-allow.txt) should bypass.

        Runs against a temporary HOME so the developer's real allowlist is
        never touched (the hook derives the path via Path.home()).
        """
        with tempfile.TemporaryDirectory() as home_dir:
            data_path = os.path.join(home_dir, "students.csv")
            with open(data_path, "w") as f:
                f.write("name,ssn\nJane,123-45-6789\n")

            allowlist_file = Path(home_dir) / ".claude" / "ferpa-guard-allow.txt"
            allowlist_file.parent.mkdir(parents=True, exist_ok=True)
            allowlist_file.write_text(f"{data_path}\n")

            result = self._run_hook(
                "Read", {"file_path": data_path}, env_extra={"HOME": home_dir}
            )
            self.assertEqual(result.returncode, 0)

    def test_allowfile_bypasses_listed_file_only(self):
        """A .pii-guardian-allow dotfile in the data directory bypasses the
        listed basename; an unlisted sibling still blocks (fixture parity)."""
        with tempfile.TemporaryDirectory() as home_dir:
            data_dir = Path(home_dir) / "allowed"
            data_dir.mkdir()
            covered = data_dir / "registration.csv"
            covered.write_text("name,ssn\nJane,123-45-6789\n")
            uncovered = data_dir / "uncovered.csv"
            uncovered.write_text("name,ssn\nJane,123-45-6789\n")
            (data_dir / ".pii-guardian-allow").write_text(
                "# fixture parity\nregistration.csv\n"
            )
            env = {"HOME": home_dir}
            result = self._run_hook("Read", {"file_path": str(covered)}, env_extra=env)
            self.assertEqual(result.returncode, 0)
            result = self._run_hook("Read", {"file_path": str(uncovered)}, env_extra=env)
            self.assertEqual(result.returncode, 2)

    def test_allowfile_no_restart_freshness(self):
        """Writing the allowfile between invocations takes effect immediately."""
        with tempfile.TemporaryDirectory() as home_dir:
            data_dir = Path(home_dir) / "data"
            data_dir.mkdir()
            target = data_dir / "roster.csv"
            target.write_text("name,ssn\nJane,123-45-6789\n")
            env = {"HOME": home_dir}
            result = self._run_hook("Read", {"file_path": str(target)}, env_extra=env)
            self.assertEqual(result.returncode, 2)
            (data_dir / ".pii-guardian-allow").write_text("roster.csv\n")
            result = self._run_hook("Read", {"file_path": str(target)}, env_extra=env)
            self.assertEqual(result.returncode, 0)

    def test_bash_cat_detection(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("student_id: 12345\n")
            path = f.name
        try:
            result = self._run_hook("Bash", {"command": f"cat {path}"})
            self.assertEqual(result.returncode, 2)
        finally:
            os.unlink(path)

    def test_edit_tool_detection(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("ssn: 123-45-6789\n")
            path = f.name
        try:
            result = self._run_hook("Edit", {"file_path": path})
            self.assertEqual(result.returncode, 2)
        finally:
            os.unlink(path)

    def test_invalid_json_allows(self):
        """Malformed stdin should not crash; should allow."""
        result = subprocess.run(
            [sys.executable, self.SCRIPT],
            input="not json",
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0)


# ---------------------------------------------------------------------------
# Layer 4: Path Extraction
# ---------------------------------------------------------------------------

class TestPathExtraction(unittest.TestCase):
    """Test extract_file_paths pulls correct paths from tool inputs."""

    def test_read_tool(self):
        paths = pg_hook.extract_file_paths("Read", {"file_path": "/data/students.csv"})
        self.assertEqual(paths, ["/data/students.csv"])

    def test_edit_tool(self):
        paths = pg_hook.extract_file_paths("Edit", {"file_path": "/data/roster.csv"})
        self.assertEqual(paths, ["/data/roster.csv"])

    def test_bash_cat(self):
        paths = pg_hook.extract_file_paths("Bash", {"command": "cat /data/students.csv"})
        self.assertIn("/data/students.csv", paths)

    def test_bash_head(self):
        paths = pg_hook.extract_file_paths("Bash", {"command": "head -20 /data/file.tsv"})
        self.assertIn("/data/file.tsv", paths)

    def test_bash_quoted_path(self):
        paths = pg_hook.extract_file_paths("Bash", {"command": 'python3 "/data/students.csv"'})
        self.assertIn("/data/students.csv", paths)

    def test_bash_no_data_file(self):
        paths = pg_hook.extract_file_paths("Bash", {"command": "ls -la"})
        self.assertEqual(paths, [])

    def test_unknown_tool(self):
        paths = pg_hook.extract_file_paths("Write", {"file_path": "/data/out.csv"})
        self.assertEqual(paths, [])

    # --- Processing commands ---

    def test_bash_grep(self):
        paths = pg_hook.extract_file_paths("Bash", {"command": 'grep "pattern" /data/students.csv'})
        self.assertIn("/data/students.csv", paths)

    def test_bash_sed(self):
        paths = pg_hook.extract_file_paths("Bash", {"command": "sed 's/old/new/' /data/roster.csv"})
        self.assertIn("/data/roster.csv", paths)

    def test_bash_awk(self):
        paths = pg_hook.extract_file_paths("Bash", {"command": "awk -F, '{print $1}' /data/grades.tsv"})
        self.assertIn("/data/grades.tsv", paths)

    def test_bash_sort(self):
        paths = pg_hook.extract_file_paths("Bash", {"command": "sort /data/names.csv"})
        self.assertIn("/data/names.csv", paths)

    def test_bash_cut(self):
        paths = pg_hook.extract_file_paths("Bash", {"command": "cut -d, -f1 /data/students.csv"})
        self.assertIn("/data/students.csv", paths)

    def test_bash_wc(self):
        # wc is metadata-only (FIX-07), so no paths should be extracted
        paths = pg_hook.extract_file_paths("Bash", {"command": "wc -l /data/roster.csv"})
        self.assertEqual(paths, [])

    # --- Pipe tests ---

    def test_bash_pipe_source(self):
        paths = pg_hook.extract_file_paths("Bash", {"command": "cat /data/students.csv | grep pattern"})
        self.assertIn("/data/students.csv", paths)

    def test_bash_grep_after_pipe(self):
        paths = pg_hook.extract_file_paths("Bash", {"command": "echo test | grep pattern /data/students.csv"})
        self.assertIn("/data/students.csv", paths)

    # --- Input redirect tests ---

    def test_bash_input_redirect(self):
        paths = pg_hook.extract_file_paths("Bash", {"command": "python3 script.py < /data/students.csv"})
        self.assertIn("/data/students.csv", paths)

    def test_bash_input_redirect_quoted(self):
        paths = pg_hook.extract_file_paths("Bash", {"command": 'python3 script.py < "/data/student data.csv"'})
        self.assertIn("/data/student data.csv", paths)

    # --- Bare data file tests ---

    def test_bash_bare_data_file(self):
        paths = pg_hook.extract_file_paths("Bash", {"command": "python3 process.py /data/students.csv"})
        self.assertIn("/data/students.csv", paths)

    # --- Deduplication tests ---

    def test_bash_dedup(self):
        paths = pg_hook.extract_file_paths("Bash", {"command": "cat /data/students.csv | head /data/students.csv"})
        count = paths.count("/data/students.csv")
        self.assertEqual(count, 1, f"Expected 1 occurrence but found {count} in {paths}")

    # --- Negative tests ---

    def test_bash_output_redirect_not_extracted(self):
        paths = pg_hook.extract_file_paths("Bash", {"command": "cat /data/in.csv > /tmp/out.csv"})
        self.assertIn("/data/in.csv", paths)
        self.assertNotIn("/tmp/out.csv", paths)

    def test_bash_no_extension_not_extracted(self):
        paths = pg_hook.extract_file_paths("Bash", {"command": "grep pattern /data/somefile"})
        self.assertNotIn("/data/somefile", paths)


# ---------------------------------------------------------------------------
# Layer 5: Should-Scan Filtering
# ---------------------------------------------------------------------------

class TestShouldScan(unittest.TestCase):
    """Test the should_scan gating function."""

    def test_csv_should_scan(self):
        self.assertTrue(should_scan("/data/students.csv"))

    def test_pdf_should_scan(self):
        self.assertTrue(should_scan("/data/transcript.pdf"))

    def test_docx_should_scan(self):
        self.assertTrue(should_scan("/data/iep_form.docx"))

    def test_py_should_not_scan(self):
        self.assertFalse(should_scan("/src/app.py"))

    def test_js_should_not_scan(self):
        self.assertFalse(should_scan("/src/index.js"))

    def test_git_dir_skipped(self):
        self.assertFalse(should_scan("/project/.git/config.json"))

    def test_node_modules_skipped(self):
        self.assertFalse(should_scan("/project/node_modules/pkg/data.json"))

    def test_claude_dir_skipped(self):
        self.assertFalse(should_scan("/project/.claude/settings.json"))

    # --- SKIP_FILENAMES: doc-convention basenames are exempt (live parity) ---

    def test_readme_md_skipped(self):
        self.assertFalse(should_scan("/data/readme.md"))

    def test_readme_case_insensitive_skipped(self):
        self.assertFalse(should_scan("/data/README.MD"))

    def test_claude_md_skipped(self):
        self.assertFalse(should_scan("/project/CLAUDE.md"))

    def test_agent_md_skipped(self):
        self.assertFalse(should_scan("/project/AGENT.md"))

    def test_agents_md_skipped(self):
        self.assertFalse(should_scan("/project/agents.md"))

    def test_notreadme_still_scanned(self):
        """Exact basename match only -- no substring/glob semantics."""
        self.assertTrue(should_scan("/data/notreadme.md"))

    def test_readme_in_subdir_skipped(self):
        self.assertFalse(should_scan("/data/docs/readme.md"))

    def test_readme_txt_not_exempt(self):
        """The exemption is the exact basename, not the stem."""
        self.assertTrue(should_scan("/data/readme.txt"))


# ---------------------------------------------------------------------------
# Layer 5c: Metadata-vs-value split
# ---------------------------------------------------------------------------

_FLOOD_TEXT = """Student services workstream notes. School compliance review.
IEP caseload and 504 plan coverage. Accommodation plan backlog.
Discipline record review: suspension and expulsion counts.
Medical: allergy and seizure action plans, inhaler storage.
Columns on the parent table: parent_email, guardian_phone, emergency_contact.
IEP meeting cadence. 504 plan renewals. Discipline referral totals.
Medication administration log columns. Guardian consent tracking.
Parent contact policy. IEP goals template. Medical action plan review.
"""


class TestMetadataValueSplit(unittest.TestCase):
    """Metadata findings (topic words, field names) cap at warn unless the
    file also holds a real VALUE match. Naming a column is not disclosing a
    record -- and a blocked doc cannot be edited to fix itself."""

    def test_metadata_constant_contents(self):
        self.assertEqual(
            METADATA_PATTERNS,
            {"IEP_504_FLAG", "DISCIPLINE_RECORD", "MEDICAL_INFO", "PARENT_GUARDIAN"},
        )

    def test_metadata_only_flood_caps_at_warn(self):
        findings = scan_content(_FLOOD_TEXT)
        names = {f["pattern_name"] for f in findings}
        self.assertTrue(names <= METADATA_PATTERNS, f"unexpected value findings: {names}")
        self.assertGreaterEqual(len(names), 3)
        self.assertEqual(worst_action(findings), "warn")

    def test_metadata_plus_email_escalates_to_block(self):
        findings = scan_content(_FLOOD_TEXT + "\ncontact: caregiver@example.com\n")
        self.assertEqual(worst_action(findings), "block")

    def test_ssn_alone_uncapped(self):
        findings = scan_content("SSN: 123-45-6789")
        self.assertEqual(worst_action(findings), "block")

    def test_decide_action_cap_and_backward_compat(self):
        # Cap applies only when metadata and no value finding in the file
        self.assertEqual(decide_action("high", "high", is_metadata=True, has_value_finding=False), "warn")
        self.assertEqual(decide_action("high", "high", is_metadata=True, has_value_finding=True), "block")
        self.assertEqual(decide_action("high", "high", is_metadata=False, has_value_finding=False), "block")
        # Existing two-arg callers (MCP server, __init__) are unaffected
        self.assertEqual(decide_action("high", "high"), "block")

    def test_unknown_pattern_fails_closed_as_value(self):
        """A pattern name outside METADATA_PATTERNS is a VALUE pattern, so a
        newly added pattern blocks rather than silently capping."""
        findings = [
            {"pattern_name": "IEP_504_FLAG", "severity": "high", "confidence": "high"},
            {"pattern_name": "FUTURE_PATTERN", "severity": "high", "confidence": "high"},
        ]
        self.assertEqual(worst_action(findings), "block")

    def test_stale_cached_findings_without_is_metadata_field(self):
        """Findings cached before this change lack is_metadata; worst_action
        folds them by pattern-name membership, not the field."""
        findings = [
            {"pattern_name": "MEDICAL_INFO", "severity": "high", "confidence": "high"},
        ]
        self.assertEqual(worst_action(findings), "warn")

    def test_findings_carry_is_metadata_field(self):
        findings = scan_content(_FLOOD_TEXT)
        for f in findings:
            self.assertIn("is_metadata", f)
            self.assertTrue(f["is_metadata"])

    def test_differential_cap_without_scorer_change(self):
        """One run: metadata fixtures reach warn AND the three detection wins
        are untouched -- the cap landed without touching the fork scorer."""
        # metadata-only -> warn (the two governance fixtures)
        self.assertEqual(worst_action(scan_content(_FLOOD_TEXT)), "warn")
        # ISO DOB detection win -> block-tier finding survives
        dob = scan_content("student dob: 2010-03-15\n" * 6)
        self.assertIn("DOB", {f["pattern_name"] for f in dob})
        self.assertEqual(worst_action(dob), "block")
        # caps-address detection win -> warn survives
        addr_rows = "\n".join(f"{100 + i} MAPLE STREET" for i in range(6))
        addr = scan_content("address\n" + addr_rows + "\n" + "filler\n" * 6)
        self.assertIn("HOME_ADDRESS", {f["pattern_name"] for f in addr})
        self.assertEqual(worst_action(addr), "warn")
        # small-file boost detection win -> single DOB in tiny file warns, not logs
        small = scan_content("name,dob\nJane,03/15/2010\n")
        self.assertEqual(worst_action(small), "warn")


# ---------------------------------------------------------------------------
# Layer 5d: Metadata split at the hook boundary + cache v2 format
# ---------------------------------------------------------------------------

class TestMetadataSplitHook(unittest.TestCase):
    """Hook-level replicas of the two metadata governance fixtures."""

    SCRIPT = str(_claude_code_dir / "pii_guardian.py") if _claude_code_dir.is_dir() else str(Path(__file__).parent / "pii_guardian.py")

    def _run_hook(self, tool_name, tool_input, env_extra=None):
        payload = json.dumps({"tool_name": tool_name, "tool_input": tool_input})
        env = os.environ.copy()
        if env_extra:
            env.update(env_extra)
        return subprocess.run(
            [sys.executable, self.SCRIPT], input=payload,
            capture_output=True, text=True, env=env,
        )

    def test_metadata_flood_warns_not_blocks(self):
        with tempfile.TemporaryDirectory() as home:
            path = os.path.join(home, "flood.txt")
            with open(path, "w") as f:
                f.write(_FLOOD_TEXT)
            result = self._run_hook("Read", {"file_path": path}, env_extra={"HOME": home})
            self.assertEqual(result.returncode, 0)
            self.assertIn("Possible sensitive data", result.stderr)

    def test_metadata_spaced_csv_warns_not_blocks(self):
        content = (
            "student number,iep status,section 504,suspension count,medication notes,allergy list\n"
            "5000000,Y,N,N,N,Y\n5000001,N,N,Y,Y,N\n5000002,N,Y,N,N,Y\n"
            "5000003,Y,N,N,Y,N\n5000004,N,N,Y,N,N\n"
        )
        with tempfile.TemporaryDirectory() as home:
            path = os.path.join(home, "spaced.csv")
            with open(path, "w") as f:
                f.write(content)
            result = self._run_hook("Read", {"file_path": path}, env_extra={"HOME": home})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Possible sensitive data", result.stderr)

    def test_metadata_plus_value_still_blocks(self):
        with tempfile.TemporaryDirectory() as home:
            path = os.path.join(home, "flood_email.txt")
            with open(path, "w") as f:
                f.write(_FLOOD_TEXT + "\ncontact: caregiver@example.com\n")
            result = self._run_hook("Read", {"file_path": path}, env_extra={"HOME": home})
            self.assertEqual(result.returncode, 2)

    def test_strict_mode_blocks_metadata_only(self):
        """FERPA_GUARD_STRICT restores pre-confidence behavior: metadata blocks."""
        with tempfile.TemporaryDirectory() as home:
            path = os.path.join(home, "flood.txt")
            with open(path, "w") as f:
                f.write(_FLOOD_TEXT)
            result = self._run_hook(
                "Read", {"file_path": path},
                env_extra={"HOME": home, "FERPA_GUARD_STRICT": "1"},
            )
            self.assertEqual(result.returncode, 2)


class TestDiskCacheV2(unittest.TestCase):
    """Disk cache wire format v2: {"version": 2, "entries": [...]}."""

    SCRIPT = str(_claude_code_dir / "pii_guardian.py") if _claude_code_dir.is_dir() else str(Path(__file__).parent / "pii_guardian.py")

    def _run_hook(self, tool_name, tool_input, env_extra=None):
        payload = json.dumps({"tool_name": tool_name, "tool_input": tool_input})
        env = os.environ.copy()
        if env_extra:
            env.update(env_extra)
        return subprocess.run(
            [sys.executable, self.SCRIPT], input=payload,
            capture_output=True, text=True, env=env,
        )

    def _cache_path(self, home):
        return Path(home) / ".claude" / "ferpa-guard-cache.json"

    def test_writer_emits_v2(self):
        with tempfile.TemporaryDirectory() as home:
            Path(home, ".claude").mkdir()
            path = os.path.join(home, "emails.csv")
            with open(path, "w") as f:
                f.write("email\n" + "\n".join(f"u{i}@example.com" for i in range(6)) + "\n")
            result = self._run_hook(
                "Read", {"file_path": path},
                env_extra={"HOME": home, "FERPA_GUARD_CACHE": "1"},
            )
            self.assertEqual(result.returncode, 0)
            data = json.loads(self._cache_path(home).read_text())
            self.assertIsInstance(data, dict)
            self.assertEqual(data["version"], 2)
            self.assertIsInstance(data["entries"], list)
            self.assertGreaterEqual(len(data["entries"]), 1)

    def test_legacy_v1_list_ignored_cold(self):
        """A pre-split top-level list is ignored wholesale -- treated as cold
        cache, never migrated -- and the run still succeeds."""
        with tempfile.TemporaryDirectory() as home:
            Path(home, ".claude").mkdir()
            path = os.path.join(home, "roster.csv")
            with open(path, "w") as f:
                f.write("name,ssn\nJane,123-45-6789\n")
            stat = os.stat(path)
            legacy = [{"key": [str(Path(path).resolve()), stat.st_mtime, stat.st_size],
                       "findings": [], "cached_at": 9999999999}]
            self._cache_path(home).write_text(json.dumps(legacy))
            result = self._run_hook(
                "Read", {"file_path": path},
                env_extra={"HOME": home, "FERPA_GUARD_CACHE": "1"},
            )
            # Legacy empty-findings entry must NOT be trusted: the file blocks.
            self.assertEqual(result.returncode, 2)

    def test_malformed_cache_ignored(self):
        with tempfile.TemporaryDirectory() as home:
            Path(home, ".claude").mkdir()
            self._cache_path(home).write_text("{not json")
            path = os.path.join(home, "clean.csv")
            with open(path, "w") as f:
                f.write("color,count\nred,5\n")
            result = self._run_hook(
                "Read", {"file_path": path},
                env_extra={"HOME": home, "FERPA_GUARD_CACHE": "1"},
            )
            self.assertEqual(result.returncode, 0)


# ---------------------------------------------------------------------------
# Layer 5b: .pii-guardian-allow ancestor-walk allowfile (engine functions)
# ---------------------------------------------------------------------------

class TestAllowfileWalk(unittest.TestCase):
    """Directory-walking allowfile: dotfiles in the target's ancestors declare
    allowed entries, read fresh on every call (the no-restart escape hatch)."""

    def _write_allowfile(self, directory, lines):
        af = Path(directory) / ALLOWFILE_NAME
        af.write_text("\n".join(lines) + "\n")
        return af

    def test_allowfile_in_same_directory(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "registration.csv"
            target.write_text("x")
            af = self._write_allowfile(d, ["registration.csv"])
            entries = collect_allowfile_entries(str(target))
            self.assertIn(str(target.resolve()), entries)
            self.assertEqual(entries[str(target.resolve())], str(af.resolve()))

    def test_allowfile_in_grandparent(self):
        with tempfile.TemporaryDirectory() as d:
            sub = Path(d) / "a" / "b"
            sub.mkdir(parents=True)
            target = sub / "data.csv"
            target.write_text("x")
            af = self._write_allowfile(d, ["a/b/data.csv"])
            entries = collect_allowfile_entries(str(target))
            self.assertIn(str(target.resolve()), entries)
            self.assertEqual(entries[str(target.resolve())], str(af.resolve()))

    def test_no_allowfile_returns_empty(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "data.csv"
            target.write_text("x")
            self.assertEqual(collect_allowfile_entries(str(target)), {})

    def test_comments_and_blanks_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "data.csv"
            target.write_text("x")
            self._write_allowfile(d, ["# comment", "", "data.csv"])
            entries = collect_allowfile_entries(str(target))
            self.assertEqual(len(entries), 1)

    def test_absolute_entry_kept(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "data.csv"
            target.write_text("x")
            self._write_allowfile(d, [str(target)])
            entries = collect_allowfile_entries(str(target))
            self.assertIn(str(target.resolve()), entries)

    def test_nearest_declaration_wins_attribution(self):
        """Duplicate declarations in nested allowfiles attribute to the
        NEAREST allowfile (setdefault semantics), never the farther one."""
        with tempfile.TemporaryDirectory() as d:
            sub = Path(d) / "inner"
            sub.mkdir()
            target = sub / "data.csv"
            target.write_text("x")
            near = self._write_allowfile(sub, ["data.csv"])
            self._write_allowfile(d, ["inner/data.csv"])  # same resolved entry, farther
            entries = collect_allowfile_entries(str(target))
            self.assertEqual(entries[str(target.resolve())], str(near.resolve()))

    def test_depth_cap(self):
        """An allowfile beyond ALLOWFILE_MAX_DEPTH ancestors is not consulted."""
        with tempfile.TemporaryDirectory() as d:
            deep = Path(d)
            for i in range(13):
                deep = deep / f"d{i}"
            deep.mkdir(parents=True)
            target = deep / "data.csv"
            target.write_text("x")
            self._write_allowfile(d, [str(target)])  # 13 levels above the target
            entries = collect_allowfile_entries(str(target))
            self.assertEqual(entries, {})

    def test_symlinked_target_resolves_before_walk(self):
        """The walk runs over the REAL path's ancestors, so an allowfile next
        to the real file covers reads through a symlink elsewhere."""
        with tempfile.TemporaryDirectory() as real_d, tempfile.TemporaryDirectory() as link_d:
            target = Path(real_d) / "data.csv"
            target.write_text("x")
            self._write_allowfile(real_d, ["data.csv"])
            link = Path(link_d) / "link.csv"
            link.symlink_to(target)
            entries = collect_allowfile_entries(str(link))
            self.assertIn(str(target.resolve()), entries)


# ---------------------------------------------------------------------------
# Layer 6: Redactor
# ---------------------------------------------------------------------------

# Import the redactor module
_shared_dir = _project_root / "shared"
from shared.pii_redactor import redact_text, redact_csv, redact_xlsx, redact_json, redact_jsonl, redact_text_file
import shared.pii_redactor as redactor
redactor_script = str(_shared_dir / "pii_redactor.py") if _shared_dir.is_dir() else str(Path(__file__).parent / "pii_redactor.py")


class TestRedactorPatterns(unittest.TestCase):
    """Test that redact_text replaces PII correctly."""

    def test_redact_ssn(self):
        result = redactor.redact_text("SSN: 123-45-6789")
        self.assertNotIn("123-45-6789", result)
        self.assertIn("XXX-XX-", result)

    def test_redact_email(self):
        result = redactor.redact_text("email: parent@school.edu")
        self.assertNotIn("parent@school.edu", result)
        self.assertIn("@redacted.example", result)

    def test_redact_phone(self):
        result = redactor.redact_text("call 401-555-1234")
        self.assertNotIn("401-555-1234", result)
        self.assertIn("000-000-0000", result)

    def test_redact_dob(self):
        result = redactor.redact_text("born 03/15/2012")
        self.assertNotIn("03/15/2012", result)
        self.assertIn("Q1/2012", result)

    def test_redact_dob_iso_format(self):
        """ISO dates should be redacted to birth quarter format."""
        result = redactor.redact_text("dob 2012-03-15")
        self.assertNotIn("2012-03-15", result)
        self.assertIn("Q1/2012", result)

    def test_redact_dob_q1_boundary(self):
        """Q1 covers January through March."""
        result_jan = redactor.redact_text("born 01/15/2010")
        self.assertIn("Q1/2010", result_jan)
        result_mar = redactor.redact_text("born 03/31/2010")
        self.assertIn("Q1/2010", result_mar)

    def test_redact_dob_q2(self):
        """Q2 covers April through June."""
        result_apr = redactor.redact_text("born 04/01/2011")
        self.assertIn("Q2/2011", result_apr)
        result_jun = redactor.redact_text("born 06/30/2011")
        self.assertIn("Q2/2011", result_jun)

    def test_redact_dob_q3(self):
        """Q3 covers July through September."""
        result = redactor.redact_text("born 07/15/2012")
        self.assertIn("Q3/2012", result)

    def test_redact_dob_q4(self):
        """Q4 covers October through December."""
        result_oct = redactor.redact_text("born 10/01/2009")
        self.assertIn("Q4/2009", result_oct)
        result_dec = redactor.redact_text("born 12/31/2009")
        self.assertIn("Q4/2009", result_dec)

    def test_redact_dob_iso_q3(self):
        """ISO format should also produce correct quarter."""
        result = redactor.redact_text("dob 2015-09-20")
        self.assertIn("Q3/2015", result)

    def test_redact_student_id(self):
        result = redactor.redact_text("student_id: 98765")
        self.assertNotIn("98765", result)
        self.assertIn("XXXXX", result)

    def test_redact_address(self):
        result = redactor.redact_text("lives at 123 Main Street")
        self.assertNotIn("123 Main Street", result)
        self.assertIn("Redacted St", result)

    def test_preserves_clean_text(self):
        text = "Grade 7, Math, Period 3"
        self.assertEqual(redactor.redact_text(text), text)

    def test_deterministic_hashing(self):
        """Same input should produce same redacted output."""
        r1 = redactor.redact_text("parent@school.edu")
        r2 = redactor.redact_text("parent@school.edu")
        self.assertEqual(r1, r2)

    def test_different_inputs_different_hashes(self):
        r1 = redactor.redact_text("alice@school.edu")
        r2 = redactor.redact_text("bob@school.edu")
        self.assertNotEqual(r1, r2)


class TestRedactorCSV(unittest.TestCase):
    """Test CSV file redaction end-to-end."""

    def test_redact_csv_preserves_headers(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("Name,SSN,Grade\nJane,123-45-6789,7\n")
            input_path = Path(f.name)
        output_path = input_path.with_name(f"{input_path.stem}_redacted.csv")
        try:
            redactor.redact_csv(input_path, output_path)
            with open(output_path) as out:
                lines = out.readlines()
            # Header preserved exactly
            self.assertEqual(lines[0].strip(), "Name,SSN,Grade")
            # SSN redacted in data row
            self.assertNotIn("123-45-6789", lines[1])
            # Grade preserved (no PII)
            self.assertIn("7", lines[1])
        finally:
            input_path.unlink(missing_ok=True)
            output_path.unlink(missing_ok=True)

    def test_redact_csv_row_count_preserved(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("id,email\n1,a@b.com\n2,c@d.com\n3,e@f.com\n")
            input_path = Path(f.name)
        output_path = input_path.with_name(f"{input_path.stem}_redacted.csv")
        try:
            count = redactor.redact_csv(input_path, output_path)
            self.assertEqual(count, 3)
            with open(output_path) as out:
                lines = out.readlines()
            self.assertEqual(len(lines), 4)  # header + 3 rows
        finally:
            input_path.unlink(missing_ok=True)
            output_path.unlink(missing_ok=True)


class TestRedactorXLSX(unittest.TestCase):
    """Test XLSX file redaction."""

    def test_redact_xlsx_preserves_headers(self):
        """XLSX redaction should preserve header row and redact data cells."""
        import openpyxl
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.append(["Name", "SSN", "Grade"])           # header
        ws.append(["Jane Doe", "123-45-6789", "7th"])  # data
        ws.append(["John Smith", "987-65-4321", "8th"])

        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
            input_path = Path(f.name)
        wb.save(input_path)
        wb.close()

        output_path = input_path.with_name(f"{input_path.stem}_redacted.xlsx")
        try:
            count = redactor.redact_xlsx(input_path, output_path)
            self.assertGreater(count, 0)

            wb2 = openpyxl.load_workbook(output_path)
            ws2 = wb2.active
            rows = list(ws2.iter_rows(values_only=True))

            # Headers preserved
            self.assertEqual(rows[0], ("Name", "SSN", "Grade"))
            # SSNs redacted
            self.assertNotIn("123-45-6789", str(rows[1]))
            self.assertNotIn("987-65-4321", str(rows[2]))
            self.assertIn("XXX-XX-", str(rows[1]))
            wb2.close()
        finally:
            input_path.unlink(missing_ok=True)
            output_path.unlink(missing_ok=True)

    def test_redact_xlsx_cli(self):
        """XLSX files should be accepted by the CLI."""
        import openpyxl
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.append(["email"])
        ws.append(["parent@school.edu"])

        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
            input_path = Path(f.name)
        wb.save(input_path)
        wb.close()

        output_path = input_path.with_name(f"{input_path.stem}_redacted.xlsx")
        try:
            result = subprocess.run(
                [sys.executable, redactor_script, str(input_path)],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0)
            self.assertTrue(output_path.exists())
        finally:
            input_path.unlink(missing_ok=True)
            output_path.unlink(missing_ok=True)


class TestRedactorJSON(unittest.TestCase):
    """Test JSON file redaction."""

    def test_redact_json_nested(self):
        data = {"student": {"name": "Jane", "ssn": "123-45-6789", "grade": 7}}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            input_path = Path(f.name)
        output_path = input_path.with_name(f"{input_path.stem}_redacted.json")
        try:
            redactor.redact_json(input_path, output_path)
            with open(output_path) as out:
                result = json.load(out)
            self.assertNotIn("123-45-6789", result["student"]["ssn"])
            self.assertEqual(result["student"]["grade"], 7)  # int preserved
        finally:
            input_path.unlink(missing_ok=True)
            output_path.unlink(missing_ok=True)


class TestRedactorCLI(unittest.TestCase):
    """Test the redactor as a CLI tool via subprocess."""

    SCRIPT = str(_shared_dir / "pii_redactor.py") if _shared_dir.is_dir() else str(Path(__file__).parent / "pii_redactor.py")

    def test_cli_produces_redacted_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("name,ssn\nJane,123-45-6789\n")
            input_path = Path(f.name)
        output_path = input_path.with_name(f"{input_path.stem}_redacted.csv")
        try:
            result = subprocess.run(
                [sys.executable, self.SCRIPT, str(input_path)],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0)
            self.assertIn("Redacted", result.stdout)
            self.assertTrue(output_path.exists())
            with open(output_path) as out:
                content = out.read()
            self.assertNotIn("123-45-6789", content)
        finally:
            input_path.unlink(missing_ok=True)
            output_path.unlink(missing_ok=True)

    def test_cli_rejects_unsupported_extension(self):
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            path = f.name
        try:
            result = subprocess.run(
                [sys.executable, self.SCRIPT, path],
                capture_output=True, text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Unsupported", result.stdout)
        finally:
            os.unlink(path)

    def test_cli_rejects_missing_file(self):
        result = subprocess.run(
            [sys.executable, self.SCRIPT, "/tmp/no_such_file_redact.csv"],
            capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)


# ---------------------------------------------------------------------------
# Layer 7: Confidence Scoring
# ---------------------------------------------------------------------------

class TestConfidenceScoring(unittest.TestCase):
    """Test confidence calculation based on count, co-occurrence, and position."""

    def test_high_confidence_many_ssns(self):
        """10+ dashed SSNs produce HIGH confidence (hard floor)."""
        ssns = "\n".join(f"row{i},123-4{i}-6789" for i in range(10))
        findings = scan_content(ssns)
        ssn = [f for f in findings if f["pattern_name"] == "SSN"][0]
        self.assertEqual(ssn["confidence"], "high")

    def test_dashed_ssn_always_high(self):
        """Even a single dashed SSN is HIGH (structurally unambiguous)."""
        findings = scan_content("SSN: 123-45-6789")
        ssn = [f for f in findings if f["pattern_name"] == "SSN"][0]
        self.assertEqual(ssn["confidence"], "high")

    def test_labeled_id_always_high(self):
        """SASID and student_id are always HIGH (labeled patterns)."""
        findings = scan_content("SASID: 123456789")
        sasid = [f for f in findings if f["pattern_name"] == "SASID"][0]
        self.assertEqual(sasid["confidence"], "high")

    def test_low_confidence_single_email(self):
        """A single email with no co-occurrence in a large file is LOW confidence."""
        # Use 15+ lines so small-file boost does not apply
        lines = ["row %d data" % i for i in range(14)]
        lines.append("info@example.com")
        content = "\n".join(lines)
        findings = scan_content(content)
        email = [f for f in findings if f["pattern_name"] == "EMAIL"][0]
        self.assertEqual(email["confidence"], "low")

    def test_co_occurrence_boosts_confidence(self):
        """Multiple PII types together boost confidence."""
        text = "student record: parent@school.edu, 401-555-1234, 123 Main Street"
        findings = scan_content(text)
        # With 3+ distinct types and education context, all should be medium or high
        for f in findings:
            self.assertIn(f["confidence"], ("medium", "high"),
                         f"{f['pattern_name']} should be medium+ with co-occurrence")

    def test_confidence_field_present(self):
        """Every finding dict has a confidence key."""
        findings = scan_content("SSN: 123-45-6789 and parent@school.edu")
        for f in findings:
            self.assertIn("confidence", f)
            self.assertIn(f["confidence"], ("high", "medium", "low"))

    def test_header_only_field_present(self):
        """Every finding dict has a header_only key."""
        findings = scan_content("SSN: 123-45-6789")
        for f in findings:
            self.assertIn("header_only", f)

    def test_many_medium_patterns_boost(self):
        """5+ emails produce HIGH confidence via count signal."""
        emails = "\n".join(f"user{i}@school.edu" for i in range(6))
        findings = scan_content(emails)
        email = [f for f in findings if f["pattern_name"] == "EMAIL"][0]
        self.assertEqual(email["confidence"], "high")

    def test_keyword_pattern_alone_not_high(self):
        """IEP/medical keywords alone should not reach HIGH even with many matches.
        This prevents policy docs and training materials from being blocked."""
        # Use 10+ lines so small-file boost does not apply
        lines = ["student policy"] + ["IEP review process"] * 6 + ["filler row"] * 4
        text = "\n".join(lines)
        findings = scan_content(text)
        iep = [f for f in findings if f["pattern_name"] == "IEP_504_FLAG"]
        self.assertTrue(len(iep) > 0)
        self.assertNotEqual(iep[0]["confidence"], "high")

    def test_keyword_pattern_high_with_co_occurrence(self):
        """Keyword patterns should reach HIGH when co-occurring with structural PII."""
        text = "student_id: 12345\nstudent_id: 67890\nstudent_id: 11111\n"
        text += "medication: insulin\ndiagnosis: asthma\nallergy: peanuts\n"
        text += "parent@school.edu\n401-555-1234\n"
        findings = scan_content(text)
        medical = [f for f in findings if f["pattern_name"] == "MEDICAL_INFO"]
        self.assertTrue(len(medical) > 0)
        self.assertEqual(medical[0]["confidence"], "high")


# ---------------------------------------------------------------------------
# Layer 8: XLSX Header Awareness
# ---------------------------------------------------------------------------

class TestXlsxHeaderAwareness(unittest.TestCase):
    """Test that header rows in xlsx files get reduced confidence."""

    def setUp(self):
        try:
            import openpyxl
            self.openpyxl = openpyxl
        except ImportError:
            self.skipTest("openpyxl not installed")

    def _create_xlsx(self, sheets):
        """Create a temp xlsx with given sheets. Each sheet is (name, [rows]).
        Returns the file path."""
        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
            path = f.name
        wb = self.openpyxl.Workbook()
        ws = wb.active
        first_sheet = True
        for sheet_name, rows in sheets:
            if first_sheet:
                ws.title = sheet_name
                first_sheet = False
            else:
                ws = wb.create_sheet(sheet_name)
            for row in rows:
                ws.append(row)
        wb.save(path)
        wb.close()
        return path

    def test_header_row_identified(self):
        """First row of each sheet is marked as header."""
        path = self._create_xlsx([
            ("Sheet1", [["Name", "Grade"], ["Jane", "7"]]),
        ])
        try:
            scan_input = read_xlsx_file(path)
            self.assertTrue(len(scan_input.header_line_indices) > 0)
        finally:
            os.unlink(path)

    def test_header_only_match_low_confidence(self):
        """Pattern matching only in header row gets reduced confidence."""
        path = self._create_xlsx([
            ("Roster", [
                ["Student Name", "parent_email", "Grade"],
                ["Jane Doe", "N/A", "7"],
                ["John Smith", "N/A", "8"],
            ]),
        ])
        try:
            scan_input = read_xlsx_file(path)
            findings = scan_content(scan_input.content, scan_input.header_line_indices)
            parent = [f for f in findings if f["pattern_name"] == "PARENT_GUARDIAN"]
            if parent:
                self.assertTrue(parent[0]["header_only"])
                # With header_only and low count, confidence should be low
                self.assertEqual(parent[0]["confidence"], "low")
        finally:
            os.unlink(path)

    def test_data_row_match_not_penalized(self):
        """Pattern matching in data rows (row 2+) is not header-penalized."""
        path = self._create_xlsx([
            ("Roster", [
                ["Name", "SSN"],
                ["Jane Doe", "123-45-6789"],
                ["John Smith", "987-65-4321"],
            ]),
        ])
        try:
            scan_input = read_xlsx_file(path)
            findings = scan_content(scan_input.content, scan_input.header_line_indices)
            ssn = [f for f in findings if f["pattern_name"] == "SSN"][0]
            self.assertFalse(ssn["header_only"])
            self.assertEqual(ssn["confidence"], "high")
        finally:
            os.unlink(path)

    def test_multi_sheet_headers(self):
        """Each sheet's row 1 is independently identified as header."""
        path = self._create_xlsx([
            ("Sheet1", [["Name", "Grade"], ["Jane", "7"]]),
            ("Sheet2", [["ID", "Score"], ["1001", "95"]]),
        ])
        try:
            scan_input = read_xlsx_file(path)
            # Should have 2 header line indices (one per sheet)
            self.assertEqual(len(scan_input.header_line_indices), 2)
        finally:
            os.unlink(path)

    def test_empty_header_no_crash(self):
        """Empty first row is handled gracefully."""
        path = self._create_xlsx([
            ("Sheet1", [[None, None], ["Jane", "7"]]),
        ])
        try:
            scan_input = read_xlsx_file(path)
            # Should not crash; empty row means no header indexed
            self.assertIsInstance(scan_input.content, str)
        finally:
            os.unlink(path)

    def test_data_in_row1_not_tagged_as_header(self):
        """Row 1 with numeric data should NOT be tagged as header."""
        path = self._create_xlsx([
            ("Sheet1", [
                ["Jane Doe", "123-45-6789", 95],
                ["John Smith", "987-65-4321", 88],
            ]),
        ])
        try:
            scan_input = read_xlsx_file(path)
            # Row 1 has a number (95) so it should not be header-tagged
            self.assertEqual(len(scan_input.header_line_indices), 0)
            # SSNs in row 1 should still be HIGH confidence (no header penalty)
            findings = scan_content(scan_input.content, scan_input.header_line_indices)
            ssn = [f for f in findings if f["pattern_name"] == "SSN"][0]
            self.assertFalse(ssn["header_only"])
            self.assertEqual(ssn["confidence"], "high")
        finally:
            os.unlink(path)

    def test_pii_in_row1_not_tagged_as_header(self):
        """Row 1 containing email addresses should NOT be tagged as header."""
        path = self._create_xlsx([
            ("Contacts", [
                ["alice@school.edu", "Bob Parent"],
                ["carol@school.edu", "Dave Parent"],
            ]),
        ])
        try:
            scan_input = read_xlsx_file(path)
            # Row 1 has an email, so heuristic should reject it as header
            self.assertEqual(len(scan_input.header_line_indices), 0)
        finally:
            os.unlink(path)

    def test_real_header_still_tagged(self):
        """Row 1 with short text labels should still be tagged as header."""
        path = self._create_xlsx([
            ("Roster", [
                ["Student Name", "Grade", "Status"],
                ["Jane Doe", "7", "Active"],
            ]),
        ])
        try:
            scan_input = read_xlsx_file(path)
            self.assertEqual(len(scan_input.header_line_indices), 1)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Layer 9: Decision Matrix
# ---------------------------------------------------------------------------

class TestDecisionMatrix(unittest.TestCase):
    """Test the severity x confidence decision matrix."""

    SCRIPT = str(_claude_code_dir / "pii_guardian.py") if _claude_code_dir.is_dir() else str(Path(__file__).parent / "pii_guardian.py")

    def _run_hook(self, tool_name, tool_input, env_extra=None):
        """Run ferpa-guard.py as a subprocess with JSON on stdin."""
        payload = json.dumps({"tool_name": tool_name, "tool_input": tool_input})
        env = os.environ.copy()
        if env_extra:
            env.update(env_extra)
        result = subprocess.run(
            [sys.executable, self.SCRIPT],
            input=payload,
            capture_output=True,
            text=True,
            env=env,
        )
        return result

    def test_decide_action_critical_high(self):
        self.assertEqual(decide_action("critical", "high"), "block")

    def test_decide_action_critical_low(self):
        self.assertEqual(decide_action("critical", "low"), "warn")

    def test_decide_action_high_medium(self):
        self.assertEqual(decide_action("high", "medium"), "warn")

    def test_decide_action_medium_low(self):
        self.assertEqual(decide_action("medium", "low"), "log")

    def test_critical_high_blocks_via_hook(self):
        """Critical severity + HIGH confidence produces exit 2."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("name,ssn\nJane,123-45-6789\n")
            path = f.name
        try:
            result = self._run_hook("Read", {"file_path": path})
            self.assertEqual(result.returncode, 2)
        finally:
            os.unlink(path)

    def test_medium_low_allows_via_hook(self):
        """Medium severity + LOW confidence produces exit 0."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("contact: info@example.com\n")
            path = f.name
        try:
            result = self._run_hook("Read", {"file_path": path})
            self.assertEqual(result.returncode, 0)
        finally:
            os.unlink(path)

    def test_strict_mode_blocks_all(self):
        """FERPA_GUARD_STRICT=1 forces all findings to HIGH confidence = block."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("contact: info@example.com\n")
            path = f.name
        try:
            result = self._run_hook(
                "Read", {"file_path": path},
                env_extra={"FERPA_GUARD_STRICT": "1"},
            )
            # Single email would normally be LOG, but strict mode blocks
            self.assertEqual(result.returncode, 2)
        finally:
            os.unlink(path)

    def test_warn_output_format(self):
        """Warn-level findings produce stderr output with 'not blocked'."""
        # 3+ medium patterns with co-occurrence => at least one should be medium confidence => warn
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("a@b.com,401-555-1234,123 Main Street\n" * 2)
            path = f.name
        try:
            result = self._run_hook("Read", {"file_path": path})
            # Should allow (exit 0) since these are medium severity
            self.assertEqual(result.returncode, 0)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Layer 10: Redactor Collision Resolution
# ---------------------------------------------------------------------------

class TestRedactorCollision(unittest.TestCase):
    """Test _resolve_output_path collision detection."""

    def test_first_run_no_collision(self):
        """First run should produce standard _redacted name."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "data.csv"
            input_path.touch()
            result = redactor._resolve_output_path(input_path)
            self.assertEqual(result.name, "data_redacted.csv")

    def test_second_run_numbered_suffix(self):
        """Second run should produce _redacted_2."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "data.csv"
            input_path.touch()
            (Path(tmpdir) / "data_redacted.csv").touch()
            result = redactor._resolve_output_path(input_path)
            self.assertEqual(result.name, "data_redacted_2.csv")

    def test_third_run_numbered_suffix(self):
        """Third run should produce _redacted_3."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "data.csv"
            input_path.touch()
            (Path(tmpdir) / "data_redacted.csv").touch()
            (Path(tmpdir) / "data_redacted_2.csv").touch()
            result = redactor._resolve_output_path(input_path)
            self.assertEqual(result.name, "data_redacted_3.csv")

    def test_preserves_extension(self):
        """Collision resolution preserves the original file extension."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "roster.xlsx"
            input_path.touch()
            (Path(tmpdir) / "roster_redacted.xlsx").touch()
            result = redactor._resolve_output_path(input_path)
            self.assertEqual(result.name, "roster_redacted_2.xlsx")
            self.assertEqual(result.suffix, ".xlsx")


class TestSmallFileConfidence(unittest.TestCase):
    """Layer 13: Small-file confidence boost.

    Files with fewer than 10 rows get a +2 confidence boost so that PII
    findings are not dismissed as low confidence just because count=1.
    """

    def test_single_email_small_file_medium(self):
        """A single email in a 2-line file with education context scores MEDIUM."""
        findings = scan_content("student record\nparent@school.edu\n")
        email = [f for f in findings if f["pattern_name"] == "EMAIL"][0]
        self.assertEqual(email["confidence"], "medium")

    def test_dob_email_small_file_both_high(self):
        """DOB + email in a 5-line CSV with education context both score HIGH."""
        content = (
            "student_id,name,dob,email,grade\n"
            "1001,Jane Doe,01/15/2012,jane@school.edu,5\n"
            "data row 3\n"
            "data row 4\n"
            "data row 5\n"
        )
        findings = scan_content(content)
        dob = [f for f in findings if f["pattern_name"] == "DOB"][0]
        email = [f for f in findings if f["pattern_name"] == "EMAIL"][0]
        self.assertEqual(dob["confidence"], "high")
        self.assertEqual(email["confidence"], "high")

    def test_ssn_small_file_still_high(self):
        """SSN in a 3-line file stays HIGH (via _HIGH_CONFIDENCE_FLOOR)."""
        content = "student record\n123-45-6789\nend\n"
        findings = scan_content(content)
        ssn = [f for f in findings if f["pattern_name"] == "SSN"][0]
        self.assertEqual(ssn["confidence"], "high")

    def test_large_file_no_boost(self):
        """A single email in a 20-line file with education context is LOW (no boost)."""
        lines = ["student roster row %d" % i for i in range(19)]
        lines.append("parent@school.edu")
        content = "\n".join(lines)
        findings = scan_content(content)
        email = [f for f in findings if f["pattern_name"] == "EMAIL"][0]
        self.assertEqual(email["confidence"], "low")

    def test_keyword_pattern_small_file_not_high(self):
        """IEP keyword alone in a 3-line file scores MEDIUM (not HIGH).

        Score: 0 (count) + 0 (distinct) - 1 (keyword penalty) + 2 (small-file) = 1 -> medium.
        """
        content = "student record\niep\nend\n"
        findings = scan_content(content)
        iep = [f for f in findings if f["pattern_name"] == "IEP_504_FLAG"][0]
        self.assertEqual(iep["confidence"], "medium")

    def test_small_file_threshold_at_10(self):
        """Boundary test: 10 lines gets no boost, 9 lines gets boost."""
        # 10 lines: no boost, single email with education context -> LOW
        lines_10 = ["student roster row %d" % i for i in range(9)]
        lines_10.append("parent@school.edu")
        content_10 = "\n".join(lines_10)
        findings_10 = scan_content(content_10)
        email_10 = [f for f in findings_10 if f["pattern_name"] == "EMAIL"][0]
        self.assertEqual(email_10["confidence"], "low")

        # 9 lines: boost applies, single email with education context -> MEDIUM
        lines_9 = ["student roster row %d" % i for i in range(8)]
        lines_9.append("parent@school.edu")
        content_9 = "\n".join(lines_9)
        findings_9 = scan_content(content_9)
        email_9 = [f for f in findings_9 if f["pattern_name"] == "EMAIL"][0]
        self.assertEqual(email_9["confidence"], "medium")


# ---------------------------------------------------------------------------
# Layer 11: Symlink Resolution
# ---------------------------------------------------------------------------

class TestSymlinkResolution(unittest.TestCase):
    """Test that symlink paths are resolved before allowlist comparison."""

    SCRIPT = str(_claude_code_dir / "pii_guardian.py") if _claude_code_dir.is_dir() else str(Path(__file__).parent / "pii_guardian.py")

    def _run_hook(self, tool_name, tool_input, env_extra=None):
        """Run ferpa-guard.py as a subprocess with JSON on stdin."""
        payload = json.dumps({"tool_name": tool_name, "tool_input": tool_input})
        env = os.environ.copy()
        if env_extra:
            env.update(env_extra)
        result = subprocess.run(
            [sys.executable, self.SCRIPT],
            input=payload,
            capture_output=True,
            text=True,
            env=env,
        )
        return result

    def test_symlink_resolved_real_path_allowlisted(self):
        """Allowlisting the REAL path allows access via a symlink."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("name,ssn\nJane,123-45-6789\n")
            real_path = f.name
        with tempfile.TemporaryDirectory() as tmpdir:
            link_path = os.path.join(tmpdir, "linked_data.csv")
            try:
                os.symlink(real_path, link_path)
                result = self._run_hook(
                    "Read",
                    {"file_path": link_path},
                    env_extra={"FERPA_GUARD_ALLOW": real_path},
                )
                self.assertEqual(result.returncode, 0)
            finally:
                os.unlink(real_path)

    def test_symlink_allowlist_entry_resolves_to_real_path(self):
        """Allowlisting the SYMLINK path works because both sides resolve."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("name,ssn\nJane,123-45-6789\n")
            real_path = f.name
        with tempfile.TemporaryDirectory() as tmpdir:
            link_path = os.path.join(tmpdir, "linked_data.csv")
            try:
                os.symlink(real_path, link_path)
                # Allowlist the symlink path -- it resolves to real path at load time
                result = self._run_hook(
                    "Read",
                    {"file_path": link_path},
                    env_extra={"FERPA_GUARD_ALLOW": link_path},
                )
                self.assertEqual(result.returncode, 0)
            finally:
                os.unlink(real_path)

    def test_no_symlink_regular_file_still_works(self):
        """Regression: regular files still work with resolved path matching."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("name,ssn\nJane,123-45-6789\n")
            path = f.name
        try:
            result = self._run_hook(
                "Read",
                {"file_path": path},
                env_extra={"FERPA_GUARD_ALLOW": path},
            )
            self.assertEqual(result.returncode, 0)
        finally:
            os.unlink(path)

    def test_symlink_to_non_allowlisted_file_blocks(self):
        """A symlink to a non-allowlisted file is still blocked."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("name,ssn\nJane,123-45-6789\n")
            real_path = f.name
        # Use a .csv extension for the symlink so should_scan returns True
        with tempfile.TemporaryDirectory() as tmpdir:
            link_path = os.path.join(tmpdir, "linked_data.csv")
            try:
                os.symlink(real_path, link_path)
                result = self._run_hook(
                    "Read",
                    {"file_path": link_path},
                    env_extra={"FERPA_GUARD_ALLOW": "/tmp/totally_different_file.csv"},
                )
                self.assertEqual(result.returncode, 2)
            finally:
                os.unlink(real_path)


# ---------------------------------------------------------------------------
# Layer 12: Audit Logging
# ---------------------------------------------------------------------------

class TestAuditLogging(unittest.TestCase):
    """JSONL audit trail: block, warn, log, and bypass events are recorded to
    ~/.claude/logs/ferpa-guard-audit.jsonl -- pattern names only, never values."""

    SCRIPT = str(_claude_code_dir / "pii_guardian.py") if _claude_code_dir.is_dir() else str(Path(__file__).parent / "pii_guardian.py")

    def _run_hook(self, tool_name, tool_input, env_extra=None):
        """Run ferpa-guard.py as a subprocess with JSON on stdin."""
        payload = json.dumps({"tool_name": tool_name, "tool_input": tool_input})
        env = os.environ.copy()
        if env_extra:
            env.update(env_extra)
        result = subprocess.run(
            [sys.executable, self.SCRIPT],
            input=payload,
            capture_output=True,
            text=True,
            env=env,
        )
        return result

    @staticmethod
    def _audit_records(home):
        log = Path(home) / ".claude" / "logs" / "ferpa-guard-audit.jsonl"
        if not log.exists():
            return []
        return [json.loads(line) for line in log.read_text().splitlines() if line.strip()]

    def _write(self, home, name, content):
        path = Path(home) / name
        path.write_text(content)
        return str(path)

    def test_bypass_audited_jsonl(self):
        """Env allowlist bypass writes a v1 JSONL record with source attribution."""
        with tempfile.TemporaryDirectory() as home:
            data_path = self._write(home, "students.csv", "name,ssn\nJane,123-45-6789\n")
            result = self._run_hook(
                "Read", {"file_path": data_path},
                env_extra={"FERPA_GUARD_ALLOW": data_path, "HOME": home},
            )
            self.assertEqual(result.returncode, 0)
            records = self._audit_records(home)
            self.assertEqual(len(records), 1)
            rec = records[0]
            self.assertEqual(rec["v"], 1)
            self.assertEqual(rec["action"], "bypass")
            self.assertEqual(rec["source"], "env(FERPA_GUARD_ALLOW)")
            self.assertEqual(rec["patterns"], [])
            self.assertRegex(rec["ts"], r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")

    def test_bypass_audit_to_stderr(self):
        """Bypass still echoes an audit line to stderr."""
        with tempfile.TemporaryDirectory() as home:
            data_path = self._write(home, "students.csv", "name,ssn\nJane,123-45-6789\n")
            result = self._run_hook(
                "Read", {"file_path": data_path},
                env_extra={"FERPA_GUARD_ALLOW": data_path, "HOME": home},
            )
            self.assertEqual(result.returncode, 0)
            self.assertIn("FERPA GUARD AUDIT:", result.stderr)

    def test_bypass_source_file(self):
        """File-based allowlist bypass attributes source=file(...)."""
        with tempfile.TemporaryDirectory() as home:
            data_path = self._write(home, "students.csv", "name,ssn\nJane,123-45-6789\n")
            claude_dir = Path(home) / ".claude"
            claude_dir.mkdir()
            (claude_dir / "ferpa-guard-allow.txt").write_text(data_path + "\n")
            result = self._run_hook("Read", {"file_path": data_path}, env_extra={"HOME": home})
            self.assertEqual(result.returncode, 0)
            records = self._audit_records(home)
            self.assertEqual(len(records), 1)
            self.assertTrue(records[0]["source"].startswith("file("))

    def test_block_audited_with_pattern_names(self):
        """A blocked file writes action=block with the pattern names that fired."""
        with tempfile.TemporaryDirectory() as home:
            data_path = self._write(home, "students.csv", "name,ssn\nJane,123-45-6789\n")
            result = self._run_hook("Read", {"file_path": data_path}, env_extra={"HOME": home})
            self.assertEqual(result.returncode, 2)
            records = self._audit_records(home)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["action"], "block")
            self.assertIn("SSN", records[0]["patterns"])

    def test_warn_audited(self):
        """A warn-tier file writes action=warn."""
        with tempfile.TemporaryDirectory() as home:
            rows = "\n".join(f"user{i}@example.com" for i in range(6))
            data_path = self._write(home, "emails.csv", "email\n" + rows + "\n")
            result = self._run_hook("Read", {"file_path": data_path}, env_extra={"HOME": home})
            self.assertEqual(result.returncode, 0)
            records = self._audit_records(home)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["action"], "warn")
            self.assertIn("EMAIL", records[0]["patterns"])

    def test_log_audited(self):
        """A log-tier file writes action=log (previously an audit blind spot)."""
        with tempfile.TemporaryDirectory() as home:
            filler = "\n".join(f"row {i}, general notes here" for i in range(11))
            data_path = self._write(home, "notes.csv", filler + "\ncall 401-555-1234\n")
            result = self._run_hook("Read", {"file_path": data_path}, env_extra={"HOME": home})
            self.assertEqual(result.returncode, 0)
            records = self._audit_records(home)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["action"], "log")
            self.assertIn("PHONE", records[0]["patterns"])

    def test_mixed_invocation_audits_all_files_before_deny(self):
        """Block + warn files in one Bash call: BOTH records land even though
        the hook exits 2 on the block -- emission precedes the deny return."""
        with tempfile.TemporaryDirectory() as home:
            block_path = self._write(home, "roster.csv", "name,ssn\nJane,123-45-6789\n")
            rows = "\n".join(f"user{i}@example.com" for i in range(6))
            warn_path = self._write(home, "emails.csv", "email\n" + rows + "\n")
            result = self._run_hook(
                "Bash", {"command": f"cat '{block_path}' '{warn_path}'"},
                env_extra={"HOME": home},
            )
            self.assertEqual(result.returncode, 2)
            records = self._audit_records(home)
            actions = sorted(r["action"] for r in records)
            self.assertEqual(actions, ["block", "warn"])

    def test_audit_contains_no_pii_values(self):
        """Audit lines carry pattern NAMES only -- never matched values."""
        with tempfile.TemporaryDirectory() as home:
            data_path = self._write(home, "students.csv", "name,ssn\nJane,123-45-6789\n")
            self._run_hook("Read", {"file_path": data_path}, env_extra={"HOME": home})
            log = Path(home) / ".claude" / "logs" / "ferpa-guard-audit.jsonl"
            content = log.read_text()
            self.assertNotIn("123-45-6789", content)
            self.assertNotIn("Jane", content)


# ---------------------------------------------------------------------------
# Layer 13: Pre-compiled Patterns (FIX-04)
# ---------------------------------------------------------------------------

class TestPreCompiledPatterns(unittest.TestCase):
    """Verify that PII_PATTERNS uses pre-compiled regex objects."""

    def test_patterns_are_compiled(self):
        """Every pattern in PII_PATTERNS should be a compiled regex, not a string."""
        from shared.pii_engine import PII_PATTERNS
        for name, spec in PII_PATTERNS.items():
            self.assertIsInstance(
                spec["pattern"], re.Pattern,
                f"{name} pattern should be re.compile()'d, got {type(spec['pattern'])}",
            )

    def test_compiled_patterns_still_match(self):
        """Compiled patterns produce the same results as before."""
        # SSN
        findings = scan_content("SSN: 123-45-6789")
        self.assertIn("SSN", [f["pattern_name"] for f in findings])
        # Email
        findings = scan_content("contact: parent@school.edu")
        self.assertIn("EMAIL", [f["pattern_name"] for f in findings])
        # Phone
        findings = scan_content("call 401-555-1234")
        self.assertIn("PHONE", [f["pattern_name"] for f in findings])


# ---------------------------------------------------------------------------
# Layer 14: Early Exit on CRITICAL (FIX-05)
# ---------------------------------------------------------------------------

class TestEarlyExit(unittest.TestCase):
    """Verify early_exit mode stops scanning after first CRITICAL finding."""

    def test_early_exit_returns_on_critical(self):
        """With early_exit=True, scanning stops at the first CRITICAL match."""
        # This text has SSN (critical) + email (medium) + phone (medium)
        text = "SSN: 123-45-6789, parent@school.edu, 401-555-1234"
        findings_early = scan_content(text, early_exit=True)
        findings_full = scan_content(text, early_exit=False)

        # Early exit should find SSN (critical) and stop
        early_names = [f["pattern_name"] for f in findings_early]
        self.assertIn("SSN", early_names)
        # Full scan should find more patterns
        self.assertGreater(len(findings_full), len(findings_early))

    def test_early_exit_skips_confidence_scoring(self):
        """Early exit findings skip confidence calculation (stay at default 'high')."""
        text = "SASID: 123456789"
        findings = scan_content(text, early_exit=True)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["confidence"], "high")

    def test_no_early_exit_finds_all(self):
        """Without early_exit, all patterns are checked."""
        text = "student_id: 12345, parent@school.edu, 401-555-1234, 123 Main Street"
        findings = scan_content(text, early_exit=False)
        names = [f["pattern_name"] for f in findings]
        self.assertIn("STUDENT_ID_LABELED", names)
        self.assertIn("EMAIL", names)

    def test_early_exit_no_critical_scans_all(self):
        """With early_exit=True but no CRITICAL patterns, all patterns are checked."""
        text = "student record: parent@school.edu, 401-555-1234"
        findings = scan_content(text, early_exit=True)
        names = [f["pattern_name"] for f in findings]
        self.assertIn("EMAIL", names)
        self.assertIn("PHONE", names)

    def test_early_exit_default_is_false(self):
        """Default early_exit is False (backward compatible)."""
        text = "SSN: 123-45-6789, parent@school.edu"
        findings = scan_content(text)
        names = [f["pattern_name"] for f in findings]
        # Should find both SSN and EMAIL with default
        self.assertIn("SSN", names)
        self.assertIn("EMAIL", names)


# ---------------------------------------------------------------------------
# Layer 15: Pattern-Level Skip (FIX-03)
# ---------------------------------------------------------------------------

class TestPatternLevelSkip(unittest.TestCase):
    """Test skip_patterns parameter in scan_content and allowlist parsing."""

    def test_skip_ssn_keeps_other_findings(self):
        """Skipping SSN still detects email and other patterns."""
        text = "SSN: 123-45-6789, parent@school.edu, student record"
        findings = scan_content(text, skip_patterns={"SSN"})
        names = [f["pattern_name"] for f in findings]
        self.assertNotIn("SSN", names)
        self.assertIn("EMAIL", names)

    def test_skip_multiple_patterns(self):
        """Can skip multiple patterns at once."""
        text = "SSN: 123-45-6789 enrollment 123456789 parent@school.edu"
        findings = scan_content(text, skip_patterns={"SSN", "SSN_NO_DASHES"})
        names = [f["pattern_name"] for f in findings]
        self.assertNotIn("SSN", names)
        self.assertNotIn("SSN_NO_DASHES", names)
        self.assertIn("EMAIL", names)

    def test_skip_none_scans_all(self):
        """skip_patterns=None scans everything (backward compatible)."""
        text = "SSN: 123-45-6789"
        findings = scan_content(text, skip_patterns=None)
        names = [f["pattern_name"] for f in findings]
        self.assertIn("SSN", names)

    def test_skip_empty_set_scans_all(self):
        """Empty skip set scans everything."""
        text = "SSN: 123-45-6789"
        findings = scan_content(text, skip_patterns=set())
        names = [f["pattern_name"] for f in findings]
        self.assertIn("SSN", names)

    def test_skip_all_patterns_returns_empty(self):
        """Skipping every matching pattern returns empty findings."""
        text = "SSN: 123-45-6789"
        findings = scan_content(text, skip_patterns={"SSN"})
        self.assertEqual(findings, [])


class TestPatternLevelSkipHook(unittest.TestCase):
    """Test pattern-level skip via allowlist file and env var in the hook."""

    SCRIPT = str(_claude_code_dir / "pii_guardian.py") if _claude_code_dir.is_dir() else str(Path(__file__).parent / "pii_guardian.py")

    def _run_hook(self, tool_name, tool_input, env_extra=None):
        payload = json.dumps({"tool_name": tool_name, "tool_input": tool_input})
        env = os.environ.copy()
        if env_extra:
            env.update(env_extra)
        result = subprocess.run(
            [sys.executable, self.SCRIPT],
            input=payload,
            capture_output=True,
            text=True,
            env=env,
        )
        return result

    def test_skip_patterns_env_var(self):
        """FERPA_GUARD_SKIP_PATTERNS suppresses specific patterns globally."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            # File has SSN (critical) which would normally block
            f.write("name,ssn\nJane,123-45-6789\n")
            path = f.name
        try:
            result = self._run_hook(
                "Read", {"file_path": path},
                env_extra={"FERPA_GUARD_SKIP_PATTERNS": "SSN"},
            )
            # With SSN skipped, no critical findings remain -> should allow
            self.assertEqual(result.returncode, 0)
        finally:
            os.unlink(path)

    def test_skip_patterns_allowlist_file(self):
        """SKIP:SSN in allowlist file suppresses SSN but keeps other scanning."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            # Has SSN (critical) + SASID (critical)
            f.write("name,ssn,sasid\nJane,123-45-6789,SASID 987654321\n")
            data_path = f.name

        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                claude_dir = Path(tmpdir) / ".claude"
                claude_dir.mkdir()
                allowlist_path = claude_dir / "ferpa-guard-allow.txt"
                # Skip SSN only; SASID should still trigger
                allowlist_path.write_text(f"{data_path} SKIP:SSN\n")

                result = self._run_hook(
                    "Read", {"file_path": data_path},
                    env_extra={"HOME": tmpdir},
                )
                # SASID is still critical -> should still block
                self.assertEqual(result.returncode, 2)
                # But SSN should not appear in the findings
                self.assertNotIn("Social Security", result.stderr)
                # SASID should appear
                self.assertIn("SASID", result.stderr)
            finally:
                os.unlink(data_path)

    def test_skip_patterns_directory_prefix(self):
        """SKIP with directory prefix applies to all files under that directory."""
        with tempfile.TemporaryDirectory() as data_dir:
            data_path = os.path.join(data_dir, "students.csv")
            with open(data_path, "w") as f:
                f.write("name,ssn\nJane,123-45-6789\n")

            with tempfile.TemporaryDirectory() as tmpdir:
                try:
                    claude_dir = Path(tmpdir) / ".claude"
                    claude_dir.mkdir()
                    allowlist_path = claude_dir / "ferpa-guard-allow.txt"
                    # Skip SSN for entire directory
                    allowlist_path.write_text(f"{data_dir}/ SKIP:SSN\n")

                    result = self._run_hook(
                        "Read", {"file_path": data_path},
                        env_extra={"HOME": tmpdir},
                    )
                    # With SSN skipped, no critical findings -> should allow
                    self.assertEqual(result.returncode, 0)
                finally:
                    pass

    def test_full_bypass_still_works_with_skip_entries(self):
        """Full bypass (no SKIP) still works when SKIP entries also exist."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("name,ssn\nJane,123-45-6789\n")
            data_path = f.name

        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                claude_dir = Path(tmpdir) / ".claude"
                claude_dir.mkdir()
                allowlist_path = claude_dir / "ferpa-guard-allow.txt"
                # Both a SKIP entry for some other path and a full bypass for this file
                allowlist_path.write_text(
                    f"/some/other/path SKIP:SSN\n{data_path}\n"
                )

                result = self._run_hook(
                    "Read", {"file_path": data_path},
                    env_extra={"HOME": tmpdir},
                )
                # Full bypass -> exit 0
                self.assertEqual(result.returncode, 0)
            finally:
                os.unlink(data_path)


# ---------------------------------------------------------------------------
# Layer 16: Smarter Bash Filtering (FIX-07)
# ---------------------------------------------------------------------------

class TestBashContentFiltering(unittest.TestCase):
    """Test that metadata-only Bash commands skip file scanning."""

    def test_ls_no_paths_extracted(self):
        """ls should not extract file paths."""
        paths = pg_hook.extract_file_paths("Bash", {"command": "ls /data/students.csv"})
        self.assertEqual(paths, [])

    def test_wc_no_paths_extracted(self):
        """wc should not extract file paths."""
        paths = pg_hook.extract_file_paths("Bash", {"command": "wc -l /data/roster.csv"})
        self.assertEqual(paths, [])

    def test_mv_no_paths_extracted(self):
        """mv should not extract file paths."""
        paths = pg_hook.extract_file_paths("Bash", {"command": "mv old.csv new.csv"})
        self.assertEqual(paths, [])

    def test_cp_no_paths_extracted(self):
        """cp should not extract file paths."""
        paths = pg_hook.extract_file_paths("Bash", {"command": "cp data.csv backup.csv"})
        self.assertEqual(paths, [])

    def test_stat_no_paths_extracted(self):
        """stat should not extract file paths."""
        paths = pg_hook.extract_file_paths("Bash", {"command": "stat /data/students.csv"})
        self.assertEqual(paths, [])

    def test_rm_no_paths_extracted(self):
        """rm should not extract file paths."""
        paths = pg_hook.extract_file_paths("Bash", {"command": "rm /data/old.csv"})
        self.assertEqual(paths, [])

    def test_find_no_paths_extracted(self):
        """find should not extract file paths."""
        paths = pg_hook.extract_file_paths("Bash", {"command": "find /data -name '*.csv'"})
        self.assertEqual(paths, [])

    def test_du_no_paths_extracted(self):
        """du should not extract file paths."""
        paths = pg_hook.extract_file_paths("Bash", {"command": "du -sh /data/students.csv"})
        self.assertEqual(paths, [])

    def test_chmod_no_paths_extracted(self):
        """chmod should not extract file paths."""
        paths = pg_hook.extract_file_paths("Bash", {"command": "chmod 644 /data/students.csv"})
        self.assertEqual(paths, [])

    def test_cat_still_extracts(self):
        """cat (content command) should still extract paths."""
        paths = pg_hook.extract_file_paths("Bash", {"command": "cat /data/students.csv"})
        self.assertIn("/data/students.csv", paths)

    def test_grep_still_extracts(self):
        """grep (content command) should still extract paths."""
        paths = pg_hook.extract_file_paths("Bash", {"command": 'grep "pattern" /data/students.csv'})
        self.assertIn("/data/students.csv", paths)

    def test_head_still_extracts(self):
        """head (content command) should still extract paths."""
        paths = pg_hook.extract_file_paths("Bash", {"command": "head -20 /data/file.tsv"})
        self.assertIn("/data/file.tsv", paths)

    def test_sudo_ls_no_paths(self):
        """sudo ls should also skip scanning."""
        paths = pg_hook.extract_file_paths("Bash", {"command": "sudo ls /data/students.csv"})
        self.assertEqual(paths, [])

    def test_env_prefix_ls_no_paths(self):
        """FOO=bar ls should also skip scanning."""
        paths = pg_hook.extract_file_paths("Bash", {"command": "FOO=bar ls /data/students.csv"})
        self.assertEqual(paths, [])

    def test_unknown_command_scans_conservatively(self):
        """Unknown commands should still extract paths (conservative)."""
        paths = pg_hook.extract_file_paths("Bash", {"command": "mycustomtool /data/students.csv"})
        self.assertIn("/data/students.csv", paths)

    def test_is_content_command_helper(self):
        """Direct test of _is_content_command helper."""
        self.assertTrue(pg_hook._is_content_command("cat file.csv"))
        self.assertTrue(pg_hook._is_content_command("grep pattern file.csv"))
        self.assertFalse(pg_hook._is_content_command("ls file.csv"))
        self.assertFalse(pg_hook._is_content_command("wc -l file.csv"))
        self.assertFalse(pg_hook._is_content_command("mv a.csv b.csv"))


# ---------------------------------------------------------------------------
# Layer 17: Scan Result Caching (FIX-02)
# ---------------------------------------------------------------------------

class TestScanCache(unittest.TestCase):
    """Test mtime-based scan result caching."""

    def test_cache_hit_same_file(self):
        """Scanning the same unchanged file twice uses the cache."""
        hook = pg_hook
        # Clear any existing cache
        hook._scan_cache.clear()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("name,ssn\nJane,123-45-6789\n")
            path = f.name

        try:
            resolved = str(Path(path).resolve())
            key = hook._cache_key(resolved)
            self.assertIsNotNone(key)

            # First call: miss
            self.assertIsNone(hook._cache_get(key))

            # Store findings
            findings = [{"pattern_name": "SSN", "severity": "critical",
                         "count": 1, "confidence": "high"}]
            hook._cache_put(key, findings)

            # Second call: hit
            cached = hook._cache_get(key)
            self.assertIsNotNone(cached)
            self.assertEqual(cached[0]["pattern_name"], "SSN")
        finally:
            os.unlink(path)
            hook._scan_cache.clear()

    def test_cache_miss_after_modification(self):
        """Modifying a file invalidates the cache (different mtime/size)."""
        hook = pg_hook
        hook._scan_cache.clear()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("name,ssn\nJane,123-45-6789\n")
            path = f.name

        try:
            resolved = str(Path(path).resolve())
            key1 = hook._cache_key(resolved)
            hook._cache_put(key1, [{"pattern_name": "SSN"}])

            # Modify the file
            import time as _time
            _time.sleep(0.05)  # Ensure mtime changes
            with open(path, "a") as f:
                f.write("extra row\n")

            key2 = hook._cache_key(resolved)
            # Keys differ because mtime/size changed
            self.assertNotEqual(key1, key2)
            # New key has no cache entry
            self.assertIsNone(hook._cache_get(key2))
        finally:
            os.unlink(path)
            hook._scan_cache.clear()

    def test_cache_ttl_expiry(self):
        """Cache entries expire after TTL."""
        hook = pg_hook
        hook._scan_cache.clear()

        key = ("/tmp/test.csv", 1000.0, 100)
        # Insert with a timestamp in the past (beyond TTL)
        hook._scan_cache[key] = {
            "findings": [{"pattern_name": "SSN"}],
            "cached_at": time.time() - hook._CACHE_TTL - 1,
        }

        # Should return None (expired)
        self.assertIsNone(hook._cache_get(key))
        # Expired entry should be cleaned up
        self.assertNotIn(key, hook._scan_cache)

    def test_cache_empty_findings(self):
        """Empty findings (clean file) are also cached."""
        hook = pg_hook
        hook._scan_cache.clear()

        key = ("/tmp/clean.csv", 2000.0, 50)
        hook._cache_put(key, [])

        cached = hook._cache_get(key)
        self.assertIsNotNone(cached)
        self.assertEqual(cached, [])

    def test_nonexistent_file_no_cache_key(self):
        """Non-existent file produces no cache key."""
        hook = pg_hook
        key = hook._cache_key("/tmp/no_such_file_cache_test.csv")
        self.assertIsNone(key)


class TestScanCacheDisk(unittest.TestCase):
    """Test disk persistence of scan cache."""

    SCRIPT = str(_claude_code_dir / "pii_guardian.py") if _claude_code_dir.is_dir() else str(Path(__file__).parent / "pii_guardian.py")

    def _run_hook(self, tool_name, tool_input, env_extra=None):
        payload = json.dumps({"tool_name": tool_name, "tool_input": tool_input})
        env = os.environ.copy()
        if env_extra:
            env.update(env_extra)
        result = subprocess.run(
            [sys.executable, self.SCRIPT],
            input=payload,
            capture_output=True,
            text=True,
            env=env,
        )
        return result

    def test_disk_cache_created_when_enabled(self):
        """FERPA_GUARD_CACHE=1 creates a cache file on disk."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("name,ssn\nJane,123-45-6789\n")
            data_path = f.name

        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                claude_dir = Path(tmpdir) / ".claude"
                claude_dir.mkdir()
                cache_path = claude_dir / "ferpa-guard-cache.json"

                self._run_hook(
                    "Read", {"file_path": data_path},
                    env_extra={"HOME": tmpdir, "FERPA_GUARD_CACHE": "1"},
                )

                self.assertTrue(cache_path.exists(), "Disk cache file should be created")
                data = json.loads(cache_path.read_text())
                self.assertIsInstance(data, dict)
                self.assertEqual(data["version"], 2)
                self.assertIsInstance(data["entries"], list)
            finally:
                os.unlink(data_path)


# ---------------------------------------------------------------------------
# Layer 18: False Positive Feedback (FIX-06)
# ---------------------------------------------------------------------------

class TestFalsePositiveFeedback(unittest.TestCase):
    """Test that block output includes false positive option."""

    SCRIPT = str(_claude_code_dir / "pii_guardian.py") if _claude_code_dir.is_dir() else str(Path(__file__).parent / "pii_guardian.py")

    def _run_hook(self, tool_name, tool_input, env_extra=None):
        payload = json.dumps({"tool_name": tool_name, "tool_input": tool_input})
        env = os.environ.copy()
        if env_extra:
            env.update(env_extra)
        result = subprocess.run(
            [sys.executable, self.SCRIPT],
            input=payload,
            capture_output=True,
            text=True,
            env=env,
        )
        return result

    def test_block_output_includes_false_positive_option(self):
        """Block output should include 'Mark as false positive' option."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("name,ssn\nJane,123-45-6789\n")
            path = f.name
        try:
            result = self._run_hook("Read", {"file_path": path})
            self.assertEqual(result.returncode, 2)
            self.assertIn("Mark as false positive", result.stderr)
            self.assertIn("ferpa-guard-feedback.log", result.stderr)
        finally:
            os.unlink(path)

    def test_feedback_option_number_with_critical(self):
        """With critical/high findings (option 4 = allowlist), feedback is option 5."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("name,ssn\nJane,123-45-6789\n")
            path = f.name
        try:
            result = self._run_hook("Read", {"file_path": path})
            stderr = result.stderr
            # Option 4 is allowlist, option 5 is false positive
            self.assertIn("4. Allowlist", stderr)
            self.assertIn("5. Mark as false positive", stderr)
        finally:
            os.unlink(path)

    def test_feedback_includes_pattern_names(self):
        """Feedback command in Claude instructions includes pattern names."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("name,ssn\nJane,123-45-6789\n")
            path = f.name
        try:
            result = self._run_hook("Read", {"file_path": path})
            stderr = result.stderr
            self.assertIn("patterns=SSN", stderr)
            self.assertIn("stays blocked", stderr)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
