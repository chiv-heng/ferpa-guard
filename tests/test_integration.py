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
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
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
    logging.getLogger("ferpa-guard-mcp").setLevel(logging.CRITICAL)

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
        """Hook writes JSONL bypass records to ~/.claude/logs/ferpa-guard-audit.jsonl.

        Runs against a temporary HOME so the developer's real logs are never
        touched. The MCP server still writes its legacy plain-text log until
        the re-wire pass unifies it (fork-merge spec, Port 4); its half of
        this criterion is asserted only when MCP is importable.
        """
        with tempfile.TemporaryDirectory() as home:
            _run_hook(
                "Read",
                {"file_path": FIXTURE_PATH},
                env_extra={"FERPA_GUARD_ALLOW": FIXTURE_PATH, "HOME": home},
            )
            audit_log = Path(home) / ".claude" / "logs" / "ferpa-guard-audit.jsonl"
            self.assertTrue(audit_log.exists(), "Hook did not create JSONL audit log")
            records = [
                json.loads(line)
                for line in audit_log.read_text().splitlines()
                if line.strip()
            ]
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["action"], "bypass")
            self.assertEqual(records[0]["v"], 1)
            self.assertIn(
                os.path.basename(FIXTURE_PATH),
                records[0]["file"],
                "Fixture path not found in audit record",
            )

        if _MCP_AVAILABLE:
            # Redirect the MCP legacy log into a temp dir too: this test must
            # never append synthetic records to the operator's real audit log
            # (review finding 2026-09-07).
            with tempfile.TemporaryDirectory() as mcp_home:
                legacy_log = Path(mcp_home) / ".claude" / "ferpa-guard-audit.log"
                with mock.patch.object(mcp_srv, "AUDIT_LOG_PATH", legacy_log):
                    mcp_srv.scan_file(FIXTURE_PATH)
                self.assertTrue(legacy_log.exists(), "MCP scan_file did not write its audit log")
                self.assertIn("SCAN", legacy_log.read_text(), "MCP scan_file did not write SCAN entry")


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

    EXPECTED_MATCHER = "Read|Bash|Grep"

    def test_matcher_literal_consistent_across_all_sites(self):
        """Spec 2.2: the matcher literal is identical at all four sites, so a
        reader of any of them sees the same gate (static check, no execution)."""
        sites = {
            "install.sh": _project_root / "install.sh",
            "install-reference.sh": _project_root / "claude-code" / "install-reference.sh",
            "SKILL.md": _project_root / "claude-code" / "SKILL.md",
        }
        for name, path in sites.items():
            text = path.read_text()
            with self.subTest(site=name):
                self.assertIn(self.EXPECTED_MATCHER, text)
                for stale in ('"Read|Bash"', '"Read|Bash|Edit"', '"Read|Edit|Bash"'):
                    self.assertNotIn(stale, text, f"{name} still carries stale matcher {stale}")
        # install-reference.sh names the literal twice (create and manual branches).
        self.assertGreaterEqual(sites["install-reference.sh"].read_text().count(self.EXPECTED_MATCHER), 2)

    def test_fresh_install_registers_read_bash_grep_matcher(self):
        """A fresh install registers the Read|Bash|Grep matcher (no Edit, no Write)."""
        result, fake_home = self._run_install()
        try:
            self.assertEqual(result.returncode, 0, f"install.sh failed:\n{result.stderr}")
            settings = json.loads(
                (Path(fake_home) / ".claude" / "settings.json").read_text()
            )
            matchers = [
                h.get("matcher") for h in settings["hooks"]["PreToolUse"]
                if any("ferpa-guard" in hk.get("command", "") for hk in h.get("hooks", []))
            ]
            self.assertEqual(matchers, [self.EXPECTED_MATCHER])
        finally:
            shutil.rmtree(fake_home)

    def _reinstall_over_matcher(self, stale_matcher: str) -> str:
        """Install over a settings.json carrying `stale_matcher`; return the
        single resulting matcher for the ferpa-guard entry."""
        fake_home = tempfile.mkdtemp()
        try:
            claude_dir = Path(fake_home) / ".claude"
            claude_dir.mkdir(parents=True)
            hook_command = 'python3 "$HOME/.claude/skills/ferpa-guard/scripts/pii_guardian.py"'
            stale = {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": stale_matcher,
                            "hooks": [{"type": "command", "command": hook_command}],
                        }
                    ]
                }
            }
            (claude_dir / "settings.json").write_text(json.dumps(stale, indent=2))

            env = os.environ.copy()
            env["HOME"] = fake_home
            result = subprocess.run(
                ["bash", str(_project_root / "install.sh")],
                env=env, capture_output=True, text=True,
                cwd=str(_project_root), timeout=60,
            )
            self.assertEqual(result.returncode, 0, f"install.sh failed:\n{result.stderr}")

            settings = json.loads((claude_dir / "settings.json").read_text())
            entries = [
                h for h in settings["hooks"]["PreToolUse"]
                if any("ferpa-guard" in hk.get("command", "") for hk in h.get("hooks", []))
            ]
            self.assertEqual(len(entries), 1, "duplicate hook entry created")
            return entries[0]["matcher"]
        finally:
            shutil.rmtree(fake_home)

    def test_reinstall_reconciles_stale_edit_matcher(self):
        """Reinstalling over a Read|Bash|Edit entry updates the matcher in
        place: no duplicate hook entry, no stale Edit gate left behind."""
        self.assertEqual(self._reinstall_over_matcher("Read|Bash|Edit"), self.EXPECTED_MATCHER)

    def test_reinstall_reconciles_pre_grep_matcher(self):
        """Reinstalling over a Read|Bash entry (installs before 2026-09-06)
        adds Grep in place (Phase 0 acceptance item 3)."""
        self.assertEqual(self._reinstall_over_matcher("Read|Bash"), self.EXPECTED_MATCHER)

    def test_fresh_install_file_placement(self):
        """install.sh copies hook script, shared engine, and shared __init__.py."""
        result, fake_home = self._run_install()
        try:
            self.assertEqual(result.returncode, 0, f"install.sh failed:\n{result.stderr}")

            dest = Path(fake_home) / ".claude" / "skills" / "ferpa-guard"
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
        """install.sh creates settings.json with FERPA Guard hook registered."""
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
                any("ferpa-guard" in c for c in commands),
                f"No hook command contains 'ferpa-guard'. Commands: {commands}",
            )
        finally:
            shutil.rmtree(fake_home)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
class TestMCPDependencyContract(unittest.TestCase):
    def test_declared_sdk_stays_on_verified_fastmcp_line(self):
        declaration = (_project_root / "pyproject.toml").read_text()
        requirement = re.search(r'^mcp\s*=\s*\["([^"]+)"\]', declaration, re.M)
        self.assertIsNotNone(requirement)
        self.assertEqual(requirement.group(1), "mcp>=1.30,<2")
        self.assertTrue(_MCP_AVAILABLE, "The verified MCP SDK must import without skips")


if __name__ == "__main__":
    unittest.main()
