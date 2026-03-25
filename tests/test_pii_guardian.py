#!/usr/bin/env python3
"""
Test harness for pii-guardian.py

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
import subprocess
import sys
import tempfile
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
        """Run pii-guardian.py as a subprocess with JSON on stdin."""
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
            self.assertIn("PII Guardian blocked", stderr)
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
            self.assertIn("PII_GUARDIAN_ALLOW", result.stderr)
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
                env_extra={"PII_GUARDIAN_ALLOW": path},
            )
            self.assertEqual(result.returncode, 0)
        finally:
            os.unlink(path)

    def test_allowlist_file_bypass(self):
        """File-based allowlist (~/.claude/pii-guardian-allow.txt) should bypass."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("name,ssn\nJane,123-45-6789\n")
            data_path = f.name

        allowlist_file = Path.home() / ".claude" / "pii-guardian-allow.txt"
        had_existing = allowlist_file.exists()
        existing_content = allowlist_file.read_text() if had_existing else ""
        try:
            # Append the test file path to the allowlist
            allowlist_file.parent.mkdir(parents=True, exist_ok=True)
            with open(allowlist_file, "a") as af:
                af.write(f"\n{data_path}\n")

            result = self._run_hook("Read", {"file_path": data_path})
            self.assertEqual(result.returncode, 0)
        finally:
            os.unlink(data_path)
            # Restore original allowlist file state
            if had_existing:
                allowlist_file.write_text(existing_content)
            else:
                allowlist_file.unlink(missing_ok=True)

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
        paths = pg_hook.extract_file_paths("Bash", {"command": "wc -l /data/roster.csv"})
        self.assertIn("/data/roster.csv", paths)

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
        """Run pii-guardian.py as a subprocess with JSON on stdin."""
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
        """PII_GUARDIAN_STRICT=1 forces all findings to HIGH confidence = block."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("contact: info@example.com\n")
            path = f.name
        try:
            result = self._run_hook(
                "Read", {"file_path": path},
                env_extra={"PII_GUARDIAN_STRICT": "1"},
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
        """Run pii-guardian.py as a subprocess with JSON on stdin."""
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
                    env_extra={"PII_GUARDIAN_ALLOW": real_path},
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
                    env_extra={"PII_GUARDIAN_ALLOW": link_path},
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
                env_extra={"PII_GUARDIAN_ALLOW": path},
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
                    env_extra={"PII_GUARDIAN_ALLOW": "/tmp/totally_different_file.csv"},
                )
                self.assertEqual(result.returncode, 2)
            finally:
                os.unlink(real_path)


# ---------------------------------------------------------------------------
# Layer 12: Audit Logging
# ---------------------------------------------------------------------------

class TestAuditLogging(unittest.TestCase):
    """Test that allowlist bypasses produce audit log entries."""

    SCRIPT = str(_claude_code_dir / "pii_guardian.py") if _claude_code_dir.is_dir() else str(Path(__file__).parent / "pii_guardian.py")

    def _run_hook(self, tool_name, tool_input, env_extra=None):
        """Run pii-guardian.py as a subprocess with JSON on stdin."""
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

    def test_audit_log_written_on_allowlist_bypass(self):
        """Allowlist bypass writes structured entry to audit log file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("name,ssn\nJane,123-45-6789\n")
            data_path = f.name
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                claude_dir = Path(tmpdir) / ".claude"
                claude_dir.mkdir()
                result = self._run_hook(
                    "Read",
                    {"file_path": data_path},
                    env_extra={
                        "PII_GUARDIAN_ALLOW": data_path,
                        "HOME": tmpdir,
                    },
                )
                self.assertEqual(result.returncode, 0)
                audit_log = claude_dir / "pii-guardian-audit.log"
                self.assertTrue(audit_log.exists(), "Audit log file should be created")
                content = audit_log.read_text()
                self.assertIn("ALLOW", content)
                self.assertIn(data_path, content)
                self.assertIn("env(PII_GUARDIAN_ALLOW)", content)
                # Check ISO 8601 timestamp format (YYYY-MM-DDTHH:MM:SS)
                self.assertRegex(content, r"\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\]")
            finally:
                os.unlink(data_path)

    def test_audit_log_written_to_stderr(self):
        """Allowlist bypass prints audit entry to stderr."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("name,ssn\nJane,123-45-6789\n")
            data_path = f.name
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                Path(tmpdir, ".claude").mkdir()
                result = self._run_hook(
                    "Read",
                    {"file_path": data_path},
                    env_extra={
                        "PII_GUARDIAN_ALLOW": data_path,
                        "HOME": tmpdir,
                    },
                )
                self.assertEqual(result.returncode, 0)
                self.assertIn("PII GUARDIAN AUDIT:", result.stderr)
                self.assertIn("ALLOW", result.stderr)
            finally:
                os.unlink(data_path)

    def test_audit_log_includes_source_env(self):
        """Audit entry includes env var source."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("name,ssn\nJane,123-45-6789\n")
            data_path = f.name
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                Path(tmpdir, ".claude").mkdir()
                result = self._run_hook(
                    "Read",
                    {"file_path": data_path},
                    env_extra={
                        "PII_GUARDIAN_ALLOW": data_path,
                        "HOME": tmpdir,
                    },
                )
                audit_log = Path(tmpdir) / ".claude" / "pii-guardian-audit.log"
                content = audit_log.read_text()
                self.assertIn("source=env(PII_GUARDIAN_ALLOW)", content)
            finally:
                os.unlink(data_path)

    def test_audit_log_includes_source_file(self):
        """Audit entry includes file-based allowlist source."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("name,ssn\nJane,123-45-6789\n")
            data_path = f.name
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                claude_dir = Path(tmpdir) / ".claude"
                claude_dir.mkdir()
                allowlist_path = claude_dir / "pii-guardian-allow.txt"
                allowlist_path.write_text(data_path + "\n")
                result = self._run_hook(
                    "Read",
                    {"file_path": data_path},
                    env_extra={"HOME": tmpdir},
                )
                self.assertEqual(result.returncode, 0)
                audit_log = claude_dir / "pii-guardian-audit.log"
                content = audit_log.read_text()
                self.assertIn("source=file(", content)
            finally:
                os.unlink(data_path)

    def test_no_audit_log_when_no_bypass(self):
        """No audit log created when file is blocked (no allowlist bypass)."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("name,ssn\nJane,123-45-6789\n")
            data_path = f.name
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                claude_dir = Path(tmpdir) / ".claude"
                claude_dir.mkdir()
                result = self._run_hook(
                    "Read",
                    {"file_path": data_path},
                    env_extra={"HOME": tmpdir},
                )
                self.assertEqual(result.returncode, 2)
                audit_log = claude_dir / "pii-guardian-audit.log"
                self.assertFalse(audit_log.exists(), "No audit log when file is blocked")
            finally:
                os.unlink(data_path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
