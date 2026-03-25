#!/usr/bin/env python3
"""
Phase 8 integration tests: cross-surface validation.

Verifies that all three delivery surfaces (Claude Code hook, Cowork MCP server,
Chat custom instructions) share the same detection engine and produce consistent
results when scanning identical files.

Automated criteria (tested by this module):
  Criterion 1: Claude Code hook blocks shared PII fixture (exit 2, deny)
  Criterion 2: MCP server scan_file detects same patterns as shared engine
  Criterion 4: Both surfaces write entries to the same audit log file
  Criterion 5: install.sh places files correctly and registers hook in settings.json

Human verification required (cannot be automated):
  Criterion 3: Chat custom instructions flag same PII categories when pasted as text
  See: chat/TEST-SCENARIOS.md for 10 manual test scenarios covering CHAT-01..CHAT-04
  Scenarios to run before marking Phase 8 complete:
    1. Paste grade roster with names+grades -- expect PII warning, 2+ recovery options
    2. Paste SIS row with SSN+DOB -- expect Critical+High flags, no raw PII echoed
    3. Ask IEP policy question (no student data) -- expect no false positive warning
    4. Upload synthetic gradebook screenshot -- expect warning + crop/blur suggestion
    5. Paste parent contact list -- expect phone/email/address flagged
    6. Describe a student discipline scenario in prose -- expect discipline flag
    7. Paste medical accommodation note -- expect medical info flag
    8. Paste data with SASID numbers -- expect critical severity flag
    9. Ask about FERPA compliance (no PII) -- expect no false positive
   10. Paste lunch PIN roster -- expect high severity flag

All test data is synthetic. No real student records.

Run:  python3 tests/test_integration.py -v
"""

import atexit
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# ---------------------------------------------------------------------------
# Path setup (same pattern as test_pii_guardian.py line 25-26)
# ---------------------------------------------------------------------------
_project_root = Path(__file__).parent.parent
sys.path.insert(0, str(_project_root))

# ---------------------------------------------------------------------------
# Engine imports (ground truth baseline)
# ---------------------------------------------------------------------------
from shared.pii_engine import read_file_content, scan_content, worst_action

# ---------------------------------------------------------------------------
# MCP server import (module-level, side effects happen once)
# ---------------------------------------------------------------------------
try:
    import cowork.mcp_server as mcp_srv

    _MCP_AVAILABLE = True
except ImportError:
    mcp_srv = None
    _MCP_AVAILABLE = False

# Suppress MCP server logging to keep test output clean
if _MCP_AVAILABLE:
    logging.getLogger("pii-guardian-mcp").setLevel(logging.CRITICAL)

# ---------------------------------------------------------------------------
# Shared synthetic PII fixture
# ---------------------------------------------------------------------------
_fixture_dir = tempfile.mkdtemp()
FIXTURE_PATH = os.path.join(_fixture_dir, "integration_fixture.csv")
with open(FIXTURE_PATH, "w") as _f:
    _f.write(
        "student_id,name,grade,sasid,parent_email\n"
        "10234,Maria Santos,7,SASID 987654321,ana.santos@gmail.com\n"
        "10235,James Wilson,8,SASID 123456789,rwilson@yahoo.com\n"
    )

atexit.register(shutil.rmtree, _fixture_dir)

# ---------------------------------------------------------------------------
# Hook subprocess helper
# ---------------------------------------------------------------------------
HOOK_SCRIPT = str(_project_root / "claude-code" / "pii_guardian.py")


def _run_hook(tool_name, tool_input, env_extra=None):
    """Run pii_guardian.py as a subprocess with JSON on stdin."""
    payload = json.dumps({"tool_name": tool_name, "tool_input": tool_input})
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, HOOK_SCRIPT],
        input=payload,
        capture_output=True,
        text=True,
        env=env,
    )


# ===========================================================================
# Criterion 1: Claude Code hook blocks the shared PII fixture
# ===========================================================================


class TestClaudeCodeSurface(unittest.TestCase):
    """Verify Claude Code hook blocks the fixture (exit 2, permissionDecision=deny)."""

    def test_fixture_blocked_by_hook(self):
        """Hook returns exit code 2 with deny for PII-containing fixture."""
        result = _run_hook("Read", {"file_path": FIXTURE_PATH})
        self.assertEqual(result.returncode, 2)
        output = json.loads(result.stdout)
        self.assertEqual(
            output["hookSpecificOutput"]["permissionDecision"], "deny"
        )

    def test_hook_detects_sasid(self):
        """Hook stderr output includes SASID pattern detection."""
        result = _run_hook("Read", {"file_path": FIXTURE_PATH})
        self.assertIn("SASID", result.stderr)

    def test_hook_detects_email(self):
        """Hook stderr output includes EMAIL pattern detection."""
        result = _run_hook("Read", {"file_path": FIXTURE_PATH})
        self.assertIn("Email", result.stderr)


# ===========================================================================
# Criterion 2: MCP server scan_file detects same patterns as engine
# ===========================================================================


@unittest.skipUnless(_MCP_AVAILABLE, "MCP SDK not installed; skipping MCP tests")
class TestMCPSurfaceEquivalence(unittest.TestCase):
    """Verify MCP scan_file produces equivalent results to the shared engine."""

    def setUp(self):
        """Compute engine ground truth once per test."""
        scan_input = read_file_content(FIXTURE_PATH)
        self.engine_findings = scan_content(
            scan_input.content, scan_input.header_line_indices
        )
        self.mcp_result = mcp_srv.scan_file(FIXTURE_PATH)

    def test_mcp_detects_same_patterns_as_engine(self):
        """MCP and engine detect the same set of pattern names."""
        engine_patterns = {f["pattern_name"] for f in self.engine_findings}
        mcp_patterns = {f["pattern_name"] for f in self.mcp_result["findings"]}
        self.assertEqual(mcp_patterns, engine_patterns)

    def test_mcp_action_matches_engine(self):
        """MCP action matches the engine worst_action computation."""
        expected_action = worst_action(self.engine_findings)
        self.assertEqual(self.mcp_result["action"], expected_action)

    def test_mcp_severity_matches_engine(self):
        """MCP and engine report the same (pattern_name, severity) tuples."""
        engine_tuples = {
            (f["pattern_name"], f["severity"]) for f in self.engine_findings
        }
        mcp_tuples = {
            (f["pattern_name"], f["severity"]) for f in self.mcp_result["findings"]
        }
        self.assertEqual(mcp_tuples, engine_tuples)


# ===========================================================================
# Criterion 4: Both surfaces write to the same audit log file
# ===========================================================================


class TestAuditLogIntegration(unittest.TestCase):
    """Verify both Claude Code hook and MCP server write to the same audit log."""

    def test_both_surfaces_write_to_same_audit_log(self):
        """Hook allowlist bypass (ALLOW) and MCP scan (SCAN) both appear in audit log."""
        audit_log = Path.home() / ".claude" / "pii-guardian-audit.log"

        # Ensure ~/.claude/ directory exists
        audit_log.parent.mkdir(parents=True, exist_ok=True)

        # Read baseline
        baseline = audit_log.read_text() if audit_log.exists() else ""

        # Hook bypass writes ALLOW entry (set fixture on allowlist via env var)
        _run_hook(
            "Read",
            {"file_path": FIXTURE_PATH},
            env_extra={"PII_GUARDIAN_ALLOW": FIXTURE_PATH},
        )

        # MCP scan writes SCAN entry (only if MCP is available)
        if _MCP_AVAILABLE:
            mcp_srv.scan_file(FIXTURE_PATH)

        # Verify new entries appeared after baseline
        new_content = audit_log.read_text()[len(baseline):]
        self.assertIn("ALLOW", new_content, "Hook allowlist bypass did not write ALLOW entry")

        if _MCP_AVAILABLE:
            self.assertIn("SCAN", new_content, "MCP scan_file did not write SCAN entry")

        # Both entries reference the fixture file path
        self.assertIn(
            os.path.basename(FIXTURE_PATH),
            new_content,
            "Fixture path not found in new audit entries",
        )


# ===========================================================================
# Criterion 5: install.sh places files and registers hook correctly
# ===========================================================================


class TestInstallScript(unittest.TestCase):
    """Verify install.sh works in a clean environment with HOME override."""

    def _run_install(self):
        """Run install.sh with HOME overridden to a tmpdir. Returns (result, fake_home)."""
        fake_home = tempfile.mkdtemp()
        env = os.environ.copy()
        env["HOME"] = fake_home
        result = subprocess.run(
            ["bash", str(_project_root / "install.sh")],
            env=env,
            capture_output=True,
            text=True,
            cwd=str(_project_root),
            timeout=60,
        )
        return result, fake_home

    def test_fresh_install_file_placement(self):
        """install.sh copies hook script, shared engine, and shared __init__.py."""
        result, fake_home = self._run_install()
        try:
            self.assertEqual(result.returncode, 0, f"install.sh failed:\n{result.stderr}")

            dest = Path(fake_home) / ".claude" / "skills" / "pii-guardian"
            self.assertTrue(
                (dest / "scripts" / "pii_guardian.py").exists(),
                "pii_guardian.py not found in install destination",
            )
            self.assertTrue(
                (dest / "shared" / "pii_engine.py").exists(),
                "pii_engine.py not found in install destination",
            )
            self.assertTrue(
                (dest / "shared" / "__init__.py").exists(),
                "shared/__init__.py not found in install destination",
            )
        finally:
            shutil.rmtree(fake_home)

    def test_fresh_install_settings_json(self):
        """install.sh creates settings.json with PII Guardian hook registered."""
        result, fake_home = self._run_install()
        try:
            self.assertEqual(result.returncode, 0, f"install.sh failed:\n{result.stderr}")

            settings_path = Path(fake_home) / ".claude" / "settings.json"
            self.assertTrue(settings_path.exists(), "settings.json not created")

            settings = json.loads(settings_path.read_text())
            hooks = settings.get("hooks", {}).get("PreToolUse", [])
            self.assertTrue(len(hooks) > 0, "No PreToolUse hooks registered")

            commands = [
                h["hooks"][0]["command"]
                for h in hooks
                if h.get("hooks")
            ]
            self.assertTrue(
                any("pii-guardian" in c for c in commands),
                f"No hook command contains 'pii-guardian'. Commands: {commands}",
            )
        finally:
            shutil.rmtree(fake_home)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    unittest.main()
