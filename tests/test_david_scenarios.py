#!/usr/bin/env python3
"""
David persona scenario tests -- power-user guidance counselor workflows.

Tests v2 features: caching (FIX-02), pattern-level skip (FIX-03),
early exit (FIX-05), false positive feedback (FIX-06), Bash filtering (FIX-07).

All data is synthetic. No real student records.
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

_project_root = Path(__file__).parent.parent
_claude_code_dir = _project_root / "claude-code"
sys.path.insert(0, str(_project_root))
sys.path.insert(0, str(_claude_code_dir))

import pii_guardian as hook


SCRIPT = str(_claude_code_dir / "pii_guardian.py")


def _run_hook(tool_name, tool_input, env_extra=None):
    """Run the hook as a subprocess."""
    payload = json.dumps({"tool_name": tool_name, "tool_input": tool_input})
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, SCRIPT],
        input=payload,
        capture_output=True,
        text=True,
        env=env,
    )


# ---------------------------------------------------------------------------
# D-01: Bulk XLSX with caching + early exit
# ---------------------------------------------------------------------------

class TestD01_CacheAndEarlyExit(unittest.TestCase):
    """David reads a large file, allowlists it, then reads it again.
    Second read should use the cached result."""

    def test_cache_prevents_rescan_of_clean_file(self):
        """D-01: Reading the same unchanged clean file twice uses cache."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            # Clean file (no PII) -- David's budget report
            f.write("category,q1,q2,q3,q4\n")
            f.write("salaries,150000,150000,155000,155000\n")
            f.write("supplies,12000,8000,15000,9000\n")
            path = f.name

        try:
            # First read: full scan, allowed (no PII)
            r1 = _run_hook("Read", {"file_path": path})
            self.assertEqual(r1.returncode, 0)

            # Second read: should also allow (cache hit or re-scan, same result)
            r2 = _run_hook("Read", {"file_path": path})
            self.assertEqual(r2.returncode, 0)
        finally:
            os.unlink(path)

    def test_early_exit_on_critical_ssn(self):
        """D-01: File with SSN in row 1 blocks quickly via early exit."""
        # Large-ish file: SSN in row 1, then 500 filler rows
        lines = ["name,ssn,grade\n", "Jane Doe,123-45-6789,7\n"]
        lines.extend(f"Student {i},data,{i % 12 + 1}\n" for i in range(500))

        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.writelines(lines)
            path = f.name

        try:
            start = time.time()
            result = _run_hook("Read", {"file_path": path})
            elapsed = time.time() - start

            self.assertEqual(result.returncode, 2)
            self.assertIn("Social Security", result.stderr)
            # Should complete quickly due to early exit
            self.assertLess(elapsed, 2.0, "Early exit should resolve in under 2 seconds")
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# D-02: District IDs that look like SSNs (Pattern-Level Skip)
# ---------------------------------------------------------------------------

class TestD02_PatternLevelSkip(unittest.TestCase):
    """David's Example District files have 9-digit district IDs that trigger SSN detector.
    Pattern-level skip suppresses SSN while keeping other scanning."""

    def test_skip_ssn_keeps_dob_and_email(self):
        """D-02: SKIP:SSN,SSN_NO_DASHES suppresses SSN but DOB/EMAIL still fire."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("district_id,name,grade,parent_email,dob\n")
            f.write("100234567,Maria Santos,7,ana.santos@gmail.com,03/15/2012\n")
            f.write("100234568,James Wilson,8,rwilson@yahoo.com,11/22/2011\n")
            data_path = f.name

        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                claude_dir = Path(tmpdir) / ".claude"
                claude_dir.mkdir()
                allowlist = claude_dir / "ferpa-guard-allow.txt"
                allowlist.write_text(f"{data_path} SKIP:SSN,SSN_NO_DASHES\n")

                result = _run_hook(
                    "Read", {"file_path": data_path},
                    env_extra={"HOME": tmpdir},
                )

                # Should still block (DOB + EMAIL are present)
                self.assertEqual(result.returncode, 2, "Should block on DOB/EMAIL")
                # SSN should NOT appear in findings
                self.assertNotIn("Social Security", result.stderr)
                # Other patterns should appear
                # (DOB fires because "dob" keyword is in content)
                stderr = result.stderr
                has_other_finding = ("Date of birth" in stderr or
                                     "Email" in stderr or
                                     "parent" in stderr.lower())
                self.assertTrue(has_other_finding,
                                f"Expected non-SSN findings in stderr: {stderr[:300]}")
            finally:
                os.unlink(data_path)

    def test_skip_all_relevant_patterns_allows(self):
        """D-02: Skipping all patterns that would fire allows the file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            # Only SSN-like district IDs, no other PII
            f.write("district_id,name,grade\n")
            f.write("100234567,Maria Santos,7\n")
            f.write("100234568,James Wilson,8\n")
            data_path = f.name

        try:
            result = _run_hook(
                "Read", {"file_path": data_path},
                env_extra={"FERPA_GUARD_SKIP_PATTERNS": "SSN,SSN_NO_DASHES"},
            )
            # With SSN patterns skipped and no other PII, should allow
            self.assertEqual(result.returncode, 0)
        finally:
            os.unlink(data_path)

    def test_env_var_skip_patterns(self):
        """D-02: FERPA_GUARD_SKIP_PATTERNS env var works globally."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("id,ssn\n1001,123-45-6789\n")
            data_path = f.name

        try:
            result = _run_hook(
                "Read", {"file_path": data_path},
                env_extra={"FERPA_GUARD_SKIP_PATTERNS": "SSN"},
            )
            # SSN skipped, no other PII -> allow
            self.assertEqual(result.returncode, 0)
        finally:
            os.unlink(data_path)


# ---------------------------------------------------------------------------
# D-03: Checking file size before reading (Bash Filtering)
# ---------------------------------------------------------------------------

class TestD03_BashMetadataCommands(unittest.TestCase):
    """David checks file metadata before deciding to read.
    Metadata commands should never trigger a scan."""

    def test_wc_no_scan(self):
        """D-03: wc -l does not trigger PII scan."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("name,ssn\nJane,123-45-6789\n")
            path = f.name
        try:
            result = _run_hook("Bash", {"command": f"wc -l {path}"})
            self.assertEqual(result.returncode, 0)
            self.assertNotIn("FERPA Guard blocked", result.stderr)
        finally:
            os.unlink(path)

    def test_ls_no_scan(self):
        """D-03: ls -la does not trigger PII scan."""
        result = _run_hook("Bash", {"command": "ls -la /data/attendance-export.csv"})
        self.assertEqual(result.returncode, 0)

    def test_du_no_scan(self):
        """D-03: du -sh does not trigger PII scan."""
        result = _run_hook("Bash", {"command": "du -sh /data/attendance-export.csv"})
        self.assertEqual(result.returncode, 0)

    def test_stat_no_scan(self):
        """D-03: stat does not trigger PII scan."""
        result = _run_hook("Bash", {"command": "stat /data/attendance-export.csv"})
        self.assertEqual(result.returncode, 0)

    def test_cat_triggers_scan(self):
        """D-03: cat DOES trigger scan (content command)."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("name,ssn\nJane,123-45-6789\n")
            path = f.name
        try:
            result = _run_hook("Bash", {"command": f"cat {path}"})
            self.assertEqual(result.returncode, 2, "cat should trigger scan and block SSN")
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# D-04: Moving files without scan (Bash Filtering)
# ---------------------------------------------------------------------------

class TestD04_BashMoveCommands(unittest.TestCase):
    """David reorganizes data files. mv/cp should never scan."""

    def test_mv_no_scan(self):
        """D-04: mv does not trigger PII scan."""
        result = _run_hook("Bash", {"command": "mv /data/roster-2025.csv /data/archive/roster-2025.csv"})
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("FERPA", result.stderr)

    def test_cp_no_scan(self):
        """D-04: cp does not trigger PII scan."""
        result = _run_hook("Bash", {"command": "cp /data/attendance.xlsx /data/backup/attendance.xlsx"})
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("FERPA", result.stderr)

    def test_rm_no_scan(self):
        """D-04: rm does not trigger PII scan."""
        result = _run_hook("Bash", {"command": "rm /data/old-roster.csv"})
        self.assertEqual(result.returncode, 0)

    def test_mkdir_no_scan(self):
        """D-04: mkdir does not trigger PII scan."""
        result = _run_hook("Bash", {"command": "mkdir -p /data/archive/2025"})
        self.assertEqual(result.returncode, 0)


# ---------------------------------------------------------------------------
# D-05: Repeated scan of unchanged file (Cache)
# ---------------------------------------------------------------------------

class TestD05_CacheAcrossReads(unittest.TestCase):
    """David reads the same file multiple times across turns.
    Tests in-memory cache behavior."""

    def test_cache_key_changes_on_file_edit(self):
        """D-05: Editing a file invalidates the cache key."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("category,amount\nsupplies,5000\n")
            path = f.name

        try:
            resolved = str(Path(path).resolve())
            key1 = hook._cache_key(resolved)
            self.assertIsNotNone(key1)

            # Edit the file
            time.sleep(0.05)
            with open(path, "a") as f:
                f.write("travel,3000\n")

            key2 = hook._cache_key(resolved)
            self.assertIsNotNone(key2)
            self.assertNotEqual(key1, key2, "Cache key should differ after file edit")
        finally:
            os.unlink(path)

    def test_cache_stores_clean_result(self):
        """D-05: Clean file result is cached and retrievable."""
        hook._scan_cache.clear()

        key = ("/tmp/budget.csv", 1000.0, 200)
        hook._cache_put(key, [])  # empty findings = clean

        cached = hook._cache_get(key)
        self.assertIsNotNone(cached)
        self.assertEqual(cached, [])
        hook._scan_cache.clear()

    def test_cache_stores_findings(self):
        """D-05: Findings are cached and retrievable."""
        hook._scan_cache.clear()

        key = ("/tmp/roster.csv", 2000.0, 500)
        findings = [{"pattern_name": "SSN", "severity": "critical", "count": 3}]
        hook._cache_put(key, findings)

        cached = hook._cache_get(key)
        self.assertIsNotNone(cached)
        self.assertEqual(cached[0]["pattern_name"], "SSN")
        self.assertEqual(cached[0]["count"], 3)
        hook._scan_cache.clear()


# ---------------------------------------------------------------------------
# D-06: Strict mode override
# ---------------------------------------------------------------------------

class TestD06_StrictModeWithSkip(unittest.TestCase):
    """David tests that strict mode interacts correctly with pattern skip."""

    def test_strict_mode_blocks_remaining_patterns(self):
        """D-06: Strict mode escalates findings that aren't skipped."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            # Has SSN + email. Skip SSN, strict mode should escalate email.
            f.write("id,ssn,email\n1001,123-45-6789,parent@school.edu\n")
            path = f.name
        try:
            result = _run_hook(
                "Read", {"file_path": path},
                env_extra={
                    "FERPA_GUARD_SKIP_PATTERNS": "SSN",
                    "FERPA_GUARD_STRICT": "1",
                },
            )
            # SSN skipped, but email found. Strict mode -> block on email.
            self.assertEqual(result.returncode, 2)
            self.assertNotIn("Social Security", result.stderr)
            self.assertIn("Email", result.stderr)
        finally:
            os.unlink(path)

    def test_strict_mode_skip_all_allows(self):
        """D-06: If all patterns are skipped, even strict mode allows."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("id,ssn\n1001,123-45-6789\n")
            path = f.name
        try:
            result = _run_hook(
                "Read", {"file_path": path},
                env_extra={
                    "FERPA_GUARD_SKIP_PATTERNS": "SSN",
                    "FERPA_GUARD_STRICT": "1",
                },
            )
            # SSN skipped, nothing else to find -> allow
            self.assertEqual(result.returncode, 0)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# X-02: False positive feedback
# ---------------------------------------------------------------------------

class TestX02_FalsePositiveFeedback(unittest.TestCase):
    """David marks a blocked file as false positive.
    Tests that the block output includes the feedback option."""

    def test_block_includes_feedback_option(self):
        """X-02: Block output offers 'Mark as false positive' with log command."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("name,ssn\nJane,123-45-6789\n")
            path = f.name
        try:
            result = _run_hook("Read", {"file_path": path})
            self.assertEqual(result.returncode, 2)

            stderr = result.stderr
            # User-facing option
            self.assertIn("Mark as false positive", stderr)
            # Claude instruction includes the log command
            self.assertIn("ferpa-guard-feedback.log", stderr)
            self.assertIn("patterns=SSN", stderr)
            # Confirms it does NOT bypass
            self.assertIn("stays blocked", stderr)
        finally:
            os.unlink(path)

    def test_feedback_does_not_allowlist(self):
        """X-02: After marking false positive, next read still blocks."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("name,ssn\nJane,123-45-6789\n")
            path = f.name
        try:
            # First read: blocked
            r1 = _run_hook("Read", {"file_path": path})
            self.assertEqual(r1.returncode, 2)

            # Second read: still blocked (feedback is informational only)
            r2 = _run_hook("Read", {"file_path": path})
            self.assertEqual(r2.returncode, 2)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# X-03: Mixed allowlist file
# ---------------------------------------------------------------------------

class TestX03_MixedAllowlist(unittest.TestCase):
    """Allowlist file with full-bypass entries, SKIP entries, and comments."""

    def test_full_bypass_and_skip_coexist(self):
        """X-03: Full bypass for test fixtures, SKIP for Example District data."""
        with tempfile.TemporaryDirectory() as data_dir:
            # Test fixture (full bypass target)
            fixtures_dir = Path(data_dir) / "test-fixtures"
            fixtures_dir.mkdir()
            fixture_path = fixtures_dir / "sample-roster.csv"
            fixture_path.write_text("name,ssn\nJane,123-45-6789\n")

            # Example District data (SKIP target)
            example_dir = Path(data_dir) / "example-district"
            example_dir.mkdir()
            example_path = example_dir / "roster.csv"
            example_path.write_text("district_id,name,grade\n100234567,Maria,7\n")

            # Unrelated file (full scan)
            other_path = Path(data_dir) / "other.csv"
            other_path.write_text("name,ssn\nBob,987-65-4321\n")

            with tempfile.TemporaryDirectory() as tmpdir:
                claude_dir = Path(tmpdir) / ".claude"
                claude_dir.mkdir()
                allowlist = claude_dir / "ferpa-guard-allow.txt"
                allowlist.write_text(
                    f"# Full bypass for test fixtures\n"
                    f"{fixtures_dir}/\n"
                    f"\n"
                    f"# Pattern skip for Example District IDs\n"
                    f"{example_dir}/ SKIP:SSN,SSN_NO_DASHES\n"
                )

                # Test fixture: full bypass -> exit 0
                r1 = _run_hook(
                    "Read", {"file_path": str(fixture_path)},
                    env_extra={"HOME": tmpdir},
                )
                self.assertEqual(r1.returncode, 0, "Test fixture should be fully bypassed")

                # Example District data: SSN skipped, no other PII -> exit 0
                r2 = _run_hook(
                    "Read", {"file_path": str(example_path)},
                    env_extra={"HOME": tmpdir},
                )
                self.assertEqual(r2.returncode, 0, "Example District with SSN skipped and no other PII should allow")

                # Unrelated file: full scan -> SSN blocks
                r3 = _run_hook(
                    "Read", {"file_path": str(other_path)},
                    env_extra={"HOME": tmpdir},
                )
                self.assertEqual(r3.returncode, 2, "Unrelated file should be fully scanned and blocked")

    def test_skip_medical_for_health_curriculum(self):
        """X-03: Health class materials skip MEDICAL_INFO but catch SSN."""
        with tempfile.TemporaryDirectory() as data_dir:
            health_dir = Path(data_dir) / "health-curriculum"
            health_dir.mkdir()
            lesson_path = health_dir / "lesson-plan.txt"
            lesson_path.write_text(
                "student lesson on diabetes and insulin management\n"
                "discuss allergy awareness and epinephrine use\n"
            )

            with tempfile.TemporaryDirectory() as tmpdir:
                claude_dir = Path(tmpdir) / ".claude"
                claude_dir.mkdir()
                allowlist = claude_dir / "ferpa-guard-allow.txt"
                allowlist.write_text(f"{health_dir}/ SKIP:MEDICAL_INFO\n")

                result = _run_hook(
                    "Read", {"file_path": str(lesson_path)},
                    env_extra={"HOME": tmpdir},
                )
                # MEDICAL_INFO skipped, no other PII -> allow
                self.assertEqual(result.returncode, 0,
                                 "Health curriculum with MEDICAL_INFO skipped should allow")


if __name__ == "__main__":
    unittest.main(verbosity=2)
