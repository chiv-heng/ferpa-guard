#!/usr/bin/env python3
"""
Hook boundary tests (Phase 0, 2026-09-06): compound Bash commands and the
native Grep tool.

Pins the contract in .planning/phases/11-adoption-phase0/SPEC.md sections
2.1 and 2.2. Every fixture is synthetic.

Run: python3 tests/test_hook_boundary.py
"""

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

_project_root = str(Path(__file__).parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)
_hook_dir = str(Path(__file__).parent.parent / "claude-code")
if _hook_dir not in sys.path:
    sys.path.insert(0, _hook_dir)

import pii_guardian as pg_hook  # noqa: E402

SCRIPT = str(Path(__file__).parent.parent / "claude-code" / "pii_guardian.py")

# Synthetic: an SSN is critical with a hard confidence floor, so this blocks on
# its own regardless of context or file size.
BLOCKING_CSV = "name,ssn\nExample Student,123-45-6789\n"


def run_hook(tool_name, tool_input, env_extra=None, cwd=None, home=None):
    """Run the hook as Claude Code would, with a clean operator environment."""
    env = os.environ.copy()
    for k in ("FERPA_GUARD_ALLOW", "FERPA_GUARD_CACHE", "FERPA_GUARD_STRICT",
              "FERPA_GUARD_SKIP_PATTERNS", "FERPA_GUARD_HARD_DENY"):
        env.pop(k, None)
    if home:
        env["HOME"] = home
    if env_extra:
        env.update(env_extra)
    payload = json.dumps({"tool_name": tool_name, "tool_input": tool_input})
    return subprocess.run(
        [sys.executable, SCRIPT], input=payload, capture_output=True,
        text=True, env=env, cwd=cwd,
    )


# ---------------------------------------------------------------------------
# 2.1 Compound Bash commands
# ---------------------------------------------------------------------------

class TestShellSegments(unittest.TestCase):
    """_split_shell_segments: unquoted control operators split, redirections do not."""

    def split(self, cmd):
        return pg_hook._split_shell_segments(cmd)

    def test_simple_operators(self):
        self.assertEqual(self.split("ls ; cat a.csv"), ["ls", "cat a.csv"])
        self.assertEqual(self.split("ls && cat a.csv"), ["ls", "cat a.csv"])
        self.assertEqual(self.split("cat a.csv || true"), ["cat a.csv", "true"])
        self.assertEqual(self.split("cat a.csv | wc -l"), ["cat a.csv", "wc -l"])
        self.assertEqual(self.split("cat a.csv |& tee x.log"), ["cat a.csv", "tee x.log"])
        self.assertEqual(self.split("ls\ncat a.csv"), ["ls", "cat a.csv"])

    def test_trailing_and_background_ampersand(self):
        self.assertEqual(self.split("cat a.csv &"), ["cat a.csv"])
        self.assertEqual(self.split("sleep 1 & cat a.csv"), ["sleep 1", "cat a.csv"])

    def test_redirection_ampersands_do_not_split(self):
        self.assertEqual(self.split("wc -l 2>&1 /d/r.csv"), ["wc -l 2>&1 /d/r.csv"])
        self.assertEqual(self.split("cat /d/r.csv 2>&1"), ["cat /d/r.csv 2>&1"])
        self.assertEqual(self.split("make &> /d/build.log"), ["make &> /d/build.log"])
        self.assertEqual(self.split("make &>> /d/build.log"), ["make &>> /d/build.log"])
        self.assertEqual(self.split("cmd <&3"), ["cmd <&3"])
        self.assertEqual(self.split("cmd >&2"), ["cmd >&2"])

    def test_quotes_protect_operators(self):
        self.assertEqual(self.split('grep "x;y" /d/r.csv'), ['grep "x;y" /d/r.csv'])
        self.assertEqual(self.split("grep 'a|b' /d/r.csv"), ["grep 'a|b' /d/r.csv"])
        self.assertEqual(self.split('echo "a && b"; ls'), ['echo "a && b"', "ls"])
        self.assertEqual(self.split(r"echo a\;b; ls"), [r"echo a\;b", "ls"])

    def test_substitutions_stay_in_segment(self):
        self.assertEqual(self.split("echo $(cat a.csv; ls) ; ls"), ["echo $(cat a.csv; ls)", "ls"])
        self.assertEqual(self.split("echo `cat a.csv; ls` ; ls"), ["echo `cat a.csv; ls`", "ls"])

    def test_segment_text_preserved(self):
        segs = self.split('cat "/d/student data.csv" ; ls')
        self.assertEqual(segs[0], 'cat "/d/student data.csv"')

    def test_empty_segments_dropped(self):
        self.assertEqual(self.split(";; ls ;"), ["ls"])
        self.assertEqual(self.split(""), [])


class TestCompoundClassification(unittest.TestCase):
    """_is_content_command considers every segment, with wrappers stripped."""

    def test_any_content_segment_is_content(self):
        self.assertTrue(pg_hook._is_content_command("ls ; cat a.csv"))
        self.assertTrue(pg_hook._is_content_command("ls && cat a.csv"))
        self.assertTrue(pg_hook._is_content_command("wc -l a.csv | cat"))

    def test_all_metadata_segments_are_metadata(self):
        self.assertFalse(pg_hook._is_content_command("ls ; wc -l a.csv"))
        self.assertFalse(pg_hook._is_content_command("mv a.csv b.csv && ls"))

    def test_wrappers_are_stripped_per_segment(self):
        self.assertFalse(pg_hook._is_content_command("ls; sudo wc -l a.csv"))
        self.assertFalse(pg_hook._is_content_command("ls; FOO=1 stat a.csv"))
        self.assertFalse(pg_hook._is_content_command("(ls) ; { wc -l a.csv; }"))
        self.assertTrue(pg_hook._is_content_command("ls; time cat a.csv"))
        self.assertTrue(pg_hook._is_content_command("for f in *.csv; do cat \"$f\"; done"))

    def test_existing_single_command_behavior_unchanged(self):
        self.assertTrue(pg_hook._is_content_command("cat file.csv"))
        self.assertTrue(pg_hook._is_content_command("grep pattern file.csv"))
        self.assertFalse(pg_hook._is_content_command("ls file.csv"))
        self.assertFalse(pg_hook._is_content_command("wc -l file.csv"))
        self.assertFalse(pg_hook._is_content_command("mv a.csv b.csv"))
        self.assertTrue(pg_hook._is_content_command("mycustomtool file.csv"))


class TestCompoundExtraction(unittest.TestCase):
    """The pinned table from spec section 2.1."""

    def paths(self, cmd):
        return pg_hook.extract_file_paths("Bash", {"command": cmd})

    def test_pinned_table(self):
        cases = [
            ("ls ; cat /d/r.csv", ["/d/r.csv"]),
            ("ls && cat /d/r.csv", ["/d/r.csv"]),
            ("cat /d/r.csv || true", ["/d/r.csv"]),
            ("cp /d/a.csv /d/b.csv && cat /d/c.csv", ["/d/c.csv"]),
            ("wc -l /d/r.csv | cat", []),
            ("cat /d/r.csv | wc -l", ["/d/r.csv"]),
            ('grep "x;y" /d/r.csv', ["/d/r.csv"]),
            ("echo hi > /d/out.csv; cat /d/in.csv", ["/d/in.csv"]),
            ("cat /d/a.csv; cat /d/b.csv", ["/d/a.csv", "/d/b.csv"]),
            ("wc -l 2>&1 /d/r.csv", []),
            ("cat /d/r.csv 2>&1", ["/d/r.csv"]),
            ("make &> /d/build.log; cat /d/in.csv", ["/d/in.csv"]),
            ("cat /d/r.csv &", ["/d/r.csv"]),
            ("cat /d/r.csv |& tee /d/x.log", ["/d/r.csv"]),
            ('cat "/d/student data.csv" ; ls', ["/d/student data.csv"]),
            ("FOO=1 ls /d/r.csv", []),
            ("mv a.csv b.csv", []),
            ("wc -l r.csv", []),
            ("stat r.csv", []),
        ]
        for cmd, expected in cases:
            with self.subTest(cmd=cmd):
                self.assertEqual(self.paths(cmd), expected)

    def test_variable_indirection_is_a_documented_limit(self):
        # No literal scannable operand: nothing extractable. Documented in README.
        got = self.paths('for f in *.csv; do cat "$f"; done')
        self.assertFalse(any(p.endswith(".csv") and not p.startswith("*") for p in got))

    def test_metadata_segment_contributes_nothing_even_with_data_operands(self):
        self.assertEqual(self.paths("cp /d/roster.csv /d/backup.csv && cat /d/clean.csv"), ["/d/clean.csv"])

    def test_compound_read_is_denied_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            csv = Path(tmp) / "roster.csv"
            csv.write_text(BLOCKING_CSV)
            for cmd in (f"ls ; cat {csv}", f"ls && cat {csv}", f"cat {csv} 2>&1"):
                with self.subTest(cmd=cmd):
                    r = run_hook("Bash", {"command": cmd}, home=tmp)
                    self.assertEqual(2, r.returncode, r.stderr)
            r = run_hook("Bash", {"command": f"wc -l 2>&1 {csv}"}, home=tmp)
            self.assertEqual(0, r.returncode, r.stderr)


# ---------------------------------------------------------------------------
# 2.2 Native Grep tool
# ---------------------------------------------------------------------------

class TestGrepExtraction(unittest.TestCase):
    """extract_file_paths for Grep: only content mode on a file yields a path."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmpdir.name)
        self.csv = self.tmp / "roster.csv"
        self.csv.write_text(BLOCKING_CSV)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_non_content_modes_yield_nothing(self):
        for inp in ({"pattern": "x", "path": str(self.csv)},
                    {"pattern": "x", "path": str(self.csv), "output_mode": "files_with_matches"},
                    {"pattern": "x", "path": str(self.csv), "output_mode": "count"}):
            with self.subTest(inp=inp):
                self.assertEqual([], pg_hook.extract_file_paths("Grep", inp))

    def test_content_mode_on_file_yields_path(self):
        inp = {"pattern": "x", "path": str(self.csv), "output_mode": "content"}
        self.assertEqual([str(self.csv)], pg_hook.extract_file_paths("Grep", inp))

    def test_content_mode_on_directory_yields_no_paths(self):
        # Directories are decided by grep_directory_verdict, never scanned per file.
        inp = {"pattern": "x", "path": str(self.tmp), "output_mode": "content"}
        self.assertEqual([], pg_hook.extract_file_paths("Grep", inp))

    def test_hard_deny_candidates_include_scope(self):
        self.assertEqual([str(self.tmp)], pg_hook.extract_hard_deny_candidates(
            "Grep", {"pattern": "x", "path": str(self.tmp)}))
        with mock.patch("os.getcwd", return_value=str(self.tmp)):
            self.assertEqual([str(self.tmp)], pg_hook.extract_hard_deny_candidates(
                "Grep", {"pattern": "x"}))

    def test_grep_scope_defaults_to_cwd(self):
        with mock.patch("os.getcwd", return_value=str(self.tmp)):
            self.assertEqual(str(self.tmp), pg_hook.grep_scope({"pattern": "x"}))
        self.assertEqual(str(self.csv), pg_hook.grep_scope({"pattern": "x", "path": str(self.csv)}))


class TestGrepDirectoryVerdict(unittest.TestCase):
    """Deny-and-narrow with two provable allow shortcuts."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmpdir.name)

    def tearDown(self):
        # Undo any chmod 000 so cleanup can proceed.
        for root, dirs, _files in os.walk(self.tmp):
            for d in dirs:
                try:
                    os.chmod(Path(root) / d, 0o755)
                except OSError:
                    pass
        self.tmpdir.cleanup()

    def verdict(self, **tool_input):
        tool_input.setdefault("pattern", ".")
        tool_input.setdefault("output_mode", "content")
        tool_input.setdefault("path", str(self.tmp))
        return pg_hook.grep_directory_verdict(str(self.tmp), tool_input)

    def test_directory_with_scannable_file_is_denied(self):
        (self.tmp / "a.csv").write_text("x\n")
        self.assertEqual("deny", self.verdict())

    def test_shortcut_a_single_extension_glob_allows(self):
        (self.tmp / "a.csv").write_text("x\n")
        self.assertEqual("allow", self.verdict(glob="*.py"))
        self.assertEqual("allow", self.verdict(glob="*.ts"))

    def test_shortcut_a_rejects_scannable_extension_glob(self):
        (self.tmp / "a.py").write_text("x\n")
        for g in ("*.csv", "*.md", "*.txt", "*.json", "*.xlsx", "*.log", "*.dat"):
            with self.subTest(glob=g):
                (self.tmp / "z.csv").write_text("x\n")
                self.assertEqual("deny", self.verdict(glob=g))

    def test_shortcut_a_rejects_complex_globs_and_types(self):
        (self.tmp / "a.csv").write_text("x\n")
        for inp in ({"glob": "**/*.py"}, {"glob": "!*.py"}, {"glob": "*.{py,csv}"},
                    {"glob": "src/*.py"}, {"type": "py"}, {"type": "py", "glob": "*.py"}):
            with self.subTest(inp=inp):
                self.assertEqual("deny", self.verdict(**inp))

    def test_shortcut_b_allows_when_no_scannable_file_exists(self):
        (self.tmp / "a.py").write_text("x\n")
        (self.tmp / "sub").mkdir()
        (self.tmp / "sub" / "b.ts").write_text("x\n")
        self.assertEqual("allow", self.verdict())

    def test_shortcut_b_does_not_descend_skip_dirs(self):
        (self.tmp / "a.py").write_text("x\n")
        (self.tmp / "node_modules").mkdir()
        (self.tmp / "node_modules" / "hidden.csv").write_text("x\n")
        self.assertEqual("allow", self.verdict())

    def test_shortcut_b_finds_nested_scannable_file(self):
        (self.tmp / "a.py").write_text("x\n")
        (self.tmp / "deep" / "er").mkdir(parents=True)
        (self.tmp / "deep" / "er" / "c.csv").write_text("x\n")
        self.assertEqual("deny", self.verdict())

    def test_shortcut_b_symlink_named_csv_counts_as_scannable(self):
        (self.tmp / "a.py").write_text("x\n")
        os.symlink(self.tmp / "a.py", self.tmp / "x.csv")
        self.assertEqual("deny", self.verdict())

    def test_shortcut_b_does_not_follow_directory_symlinks(self):
        (self.tmp / "a.py").write_text("x\n")
        outside = Path(tempfile.mkdtemp())
        try:
            (outside / "o.csv").write_text("x\n")
            os.symlink(outside, self.tmp / "linkdir")
            # Not followed (ripgrep default without -L), so nothing scannable is reachable.
            self.assertEqual("allow", self.verdict())
        finally:
            (outside / "o.csv").unlink()
            outside.rmdir()

    def test_shortcut_b_budget_is_enforced_while_consuming(self):
        for i in range(6000):
            (self.tmp / f"f{i}.py").write_text("")
        result = pg_hook.walk_finds_no_scannable(str(self.tmp), budget=5000)
        self.assertIsNone(result.verdict)
        self.assertEqual(5000, result.consumed)
        self.assertEqual("deny", self.verdict())

    def test_shortcut_b_exact_budget_completes(self):
        for i in range(4999):
            (self.tmp / f"f{i}.py").write_text("")
        result = pg_hook.walk_finds_no_scannable(str(self.tmp), budget=5000)
        self.assertTrue(result.verdict)
        self.assertEqual(4999, result.consumed)

    @unittest.skipIf(os.geteuid() == 0, "root can read chmod 000 directories")
    def test_shortcut_b_unreadable_child_fails_closed(self):
        (self.tmp / "a.py").write_text("x\n")
        locked = self.tmp / "locked"
        locked.mkdir()
        os.chmod(locked, 0)
        try:
            result = pg_hook.walk_finds_no_scannable(str(self.tmp), budget=5000)
            self.assertIsNone(result.verdict)
            self.assertEqual("deny", self.verdict())
        finally:
            os.chmod(locked, stat.S_IRWXU)

    def test_shortcut_b_classification_error_fails_closed(self):
        (self.tmp / "a.py").write_text("x\n")

        class Boom:
            name = "weird"
            path = str(self.tmp / "weird")

            def is_dir(self, follow_symlinks=False):
                raise OSError("classification failed")

            def is_symlink(self):
                return False

        real_scandir = os.scandir

        @contextmanager
        def fake_scandir(path):
            with real_scandir(path) as it:
                yield iter([*it, Boom()])

        with mock.patch.object(pg_hook.os, "scandir", fake_scandir):
            result = pg_hook.walk_finds_no_scannable(str(self.tmp), budget=5000)
        self.assertIsNone(result.verdict)

    def test_shortcut_b_enumeration_error_fails_closed(self):
        def broken_scandir(path):
            raise OSError("enumeration failed")
        with mock.patch.object(pg_hook.os, "scandir", broken_scandir):
            result = pg_hook.walk_finds_no_scannable(str(self.tmp), budget=5000)
        self.assertIsNone(result.verdict)

    def test_missing_scope_is_denied(self):
        self.assertEqual("deny", pg_hook.grep_directory_verdict(
            str(self.tmp / "nope"), {"pattern": ".", "output_mode": "content"}))


class TestGrepHookEndToEnd(unittest.TestCase):
    """The hook process: gate, decision, audit, and hard deny for Grep."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmpdir.name)
        self.home = self.tmp / "home"
        self.home.mkdir()
        self.data = self.tmp / "data"
        self.data.mkdir()
        self.csv = self.data / "roster.csv"
        self.csv.write_text(BLOCKING_CSV)

    def tearDown(self):
        self.tmpdir.cleanup()

    def audit_lines(self):
        p = self.home / ".claude" / "logs" / "ferpa-guard-audit.jsonl"
        if not p.is_file():
            return []
        return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]

    def test_content_grep_on_blocking_file_is_denied(self):
        r = run_hook("Grep", {"pattern": "x", "path": str(self.csv), "output_mode": "content"}, home=str(self.home))
        self.assertEqual(2, r.returncode, r.stderr)
        self.assertIn("deny", r.stdout)

    def test_non_content_grep_on_blocking_file_is_allowed(self):
        for inp in ({"pattern": "x", "path": str(self.csv)},
                    {"pattern": "x", "path": str(self.csv), "output_mode": "files_with_matches"},
                    {"pattern": "x", "path": str(self.csv), "output_mode": "count"}):
            with self.subTest(inp=inp):
                r = run_hook("Grep", inp, home=str(self.home))
                self.assertEqual(0, r.returncode, r.stderr)

    def test_content_grep_on_directory_with_data_is_denied_and_audited(self):
        r = run_hook("Grep", {"pattern": "x", "path": str(self.data), "output_mode": "content"}, home=str(self.home))
        self.assertEqual(2, r.returncode, r.stderr)
        self.assertIn("Narrow it", r.stderr)
        self.assertNotIn("123-45-6789", r.stdout + r.stderr)
        recs = [a for a in self.audit_lines() if a.get("action") == "block"]
        self.assertTrue(any(a.get("patterns") == ["GREP_SCOPE"] for a in recs), recs)

    def test_content_grep_on_directory_with_code_glob_is_allowed(self):
        r = run_hook("Grep", {"pattern": "x", "path": str(self.data), "output_mode": "content", "glob": "*.py"}, home=str(self.home))
        self.assertEqual(0, r.returncode, r.stderr)

    def test_content_grep_on_code_only_directory_is_allowed(self):
        code = self.tmp / "code"
        code.mkdir()
        (code / "a.py").write_text("print(1)\n")
        r = run_hook("Grep", {"pattern": "x", "path": str(code), "output_mode": "content"}, home=str(self.home))
        self.assertEqual(0, r.returncode, r.stderr)

    def test_omitted_path_uses_cwd(self):
        r = run_hook("Grep", {"pattern": "x", "output_mode": "content"}, home=str(self.home), cwd=str(self.data))
        self.assertEqual(2, r.returncode, r.stderr)

    def test_hard_deny_parent_scope_any_mode(self):
        root = self.tmp / "protected"
        root.mkdir()
        for inp in ({"pattern": "x", "path": str(self.tmp)},
                    {"pattern": "x", "path": str(self.tmp), "output_mode": "content"},
                    {"pattern": "x", "path": str(root / "inner.csv"), "output_mode": "count"}):
            with self.subTest(inp=inp):
                r = run_hook("Grep", inp, home=str(self.home),
                             env_extra={"FERPA_GUARD_HARD_DENY": str(root)})
                self.assertEqual(2, r.returncode, r.stderr)
                self.assertIn("protected private control data", r.stderr)
                self.assertNotIn(str(root), r.stdout + r.stderr)

    def test_unrelated_tools_still_allowed(self):
        r = run_hook("Glob", {"pattern": "*.csv"}, home=str(self.home))
        self.assertEqual(0, r.returncode, r.stderr)


class TestReviewFindings2026_09_06(unittest.TestCase):
    """Defects confirmed from the Phase 0 multi-model review (Ringer run
    ferpa-phase0-eval): each was probed against the code before this test
    was written."""

    def paths(self, cmd):
        return pg_hook.extract_file_paths("Bash", {"command": cmd})

    def test_case_clause_named_like_metadata_command(self):
        # A clause pattern such as `file)` or `ls)` must not classify the clause body.
        self.assertIn("/d/r.csv", self.paths("case $x in init) ls ;; file) cat /d/r.csv ;; esac"))
        self.assertIn("/d/r.csv", self.paths("case $x in a) wc -l x ;; ls) cat /d/r.csv ;; esac"))
        self.assertIn("/d/r.csv", self.paths("(ls; cat /d/r.csv)"))

    def test_input_redirect_on_block_closing_keyword(self):
        self.assertIn("/d/r.csv", self.paths('while read -r l; do echo "$l"; done < /d/r.csv'))
        self.assertIn("/d/r.csv", self.paths("if true; then cat; fi < /d/r.csv"))
        self.assertEqual([], self.paths("done"))

    def test_metadata_command_wrapping_substitution(self):
        self.assertIn("/d/r.csv", self.paths("ls -la $(cat /d/r.csv)"))
        self.assertIn("/d/r.csv", self.paths("wc -l `cat /d/r.csv`"))
        self.assertIn("/d/r.csv", self.paths("stat $(head -1 /d/r.csv)"))
        # Single quotes suppress substitution, so nothing is recursed into.
        # (The outer segment's regexes may still over-extract the literal,
        # which is the conservative side and unchanged from before.)
        self.assertEqual([], pg_hook._substitution_bodies("echo '$(cat /d/r.csv)'"))
        self.assertEqual(["cat /d/r.csv"], pg_hook._substitution_bodies('echo "$(cat /d/r.csv)"'))
        self.assertEqual(["cat a.csv"], pg_hook._substitution_bodies("wc -l `cat a.csv`"))

    def test_substitution_inside_double_quotes_has_no_trailing_paren(self):
        got = self.paths('echo "$(cat /d/r.csv)"')
        self.assertIn("/d/r.csv", got)
        self.assertFalse(any(p.endswith(")") for p in got), got)

    def test_heredoc_produces_no_junk_operands(self):
        got = self.paths("cat <<EOF /d/r.csv")
        self.assertIn("/d/r.csv", got)
        self.assertFalse(any(p.startswith("<") for p in got), got)

    def test_shortcut_a_glob_is_matched_exactly(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "a.csv").write_text("x\n")
            base = {"pattern": ".", "output_mode": "content", "path": tmp}
            self.assertEqual("allow", pg_hook.grep_directory_verdict(tmp, {**base, "glob": "*.py"}))
            self.assertEqual("deny", pg_hook.grep_directory_verdict(tmp, {**base, "glob": " *.py "}))
            self.assertEqual("deny", pg_hook.grep_directory_verdict(tmp, {**base, "glob": "*.py "}))

    def test_allowlisted_directory_permits_content_grep(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            home.mkdir()
            data = Path(tmp) / "data"
            data.mkdir()
            (data / "roster.csv").write_text(BLOCKING_CSV)
            inp = {"pattern": "x", "path": str(data), "output_mode": "content"}
            denied = run_hook("Grep", inp, home=str(home))
            self.assertEqual(2, denied.returncode, denied.stderr)
            allowed = run_hook("Grep", inp, home=str(home), env_extra={"FERPA_GUARD_ALLOW": str(data)})
            self.assertEqual(0, allowed.returncode, allowed.stderr)
            self.assertIn("bypass", allowed.stderr)
            log = home / ".claude" / "logs" / "ferpa-guard-audit.jsonl"
            recs = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
            self.assertTrue(any(r.get("action") == "bypass" for r in recs), recs)


class TestOperationalMessageForComments(unittest.TestCase):
    """XLSX_COMMENTS messaging: recovery names comment removal only when the
    workbook could be opened; an open failure keeps its own guidance and the
    'nothing was read' status."""

    def test_comments_hold_alone_offers_comment_recovery(self):
        from shared.pii_engine import scan_incomplete_finding
        f = [scan_incomplete_finding("XLSX_COMMENTS", "/d/book.xlsx")]
        msg = pg_hook.format_unscannable_reason("/d/book.xlsx", f)
        self.assertIn("Delete All Comments", msg)
        self.assertIn("built-in redactor", msg)
        self.assertIn("Only part of the file may have been checked.", msg)

    def test_open_failure_with_comments_keeps_open_failure_guidance(self):
        from shared.pii_engine import reader_error_finding, scan_incomplete_finding
        f = [reader_error_finding("OPEN_FAILED", "/d/book.xlsx"),
             scan_incomplete_finding("XLSX_COMMENTS", "/d/book.xlsx")]
        msg = pg_hook.format_unscannable_reason("/d/book.xlsx", f)
        self.assertIn("No file contents were read.", msg)
        self.assertNotIn("Delete All Comments", msg)
        self.assertIn("Confirm the file is readable", msg)


if __name__ == "__main__":
    unittest.main(verbosity=2)
