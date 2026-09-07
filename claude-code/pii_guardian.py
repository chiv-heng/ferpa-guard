#!/usr/bin/env python3
"""
pii_guardian.py -- PreToolUse hook that scans files for PII before Claude
processes them.

Designed for K-12 / FERPA contexts. Fires on Read and Bash tool calls,
inspects the target file(s), and blocks if PII patterns are detected.

Input: JSON on stdin (Claude Code hooks API)
  {
    "tool_name": "Read",
    "tool_input": {"file_path": "/path/to/file.csv"},
    ...
  }

Output on block: JSON on stdout with permissionDecision: "deny"
Exit code 2 to block. Exit code 0 to allow.
"""

import datetime
import json
import os
import re
import shlex
import sys
import time
from pathlib import Path

# Add project root to path so shared package is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.pii_engine import (
    ScanInput,
    read_file_content,
    scan_content,
    should_scan,
    decide_action,
    worst_action,
    SCANNABLE_EXTENSIONS,
    SKIP_DIRS,
    collect_allowfile_entries,
    reader_error_finding,
    scan_incomplete_finding,
    write_audit_event,
)


# JSONL audit trail (block/warn/log/bypass). Deliberately NOT the live MBP
# monolith's pii-guardian-audit.jsonl -- two writers interleaving in one file
# during the re-wire transition would corrupt line-count signals.
AUDIT_LOG_PATH = Path.home() / ".claude" / "logs" / "ferpa-guard-audit.jsonl"
FEEDBACK_LOG_PATH = Path.home() / ".claude" / "ferpa-guard-feedback.log"

def _load_hard_deny_roots() -> tuple[Path, ...]:
    """Read FERPA_GUARD_HARD_DENY: os.pathsep-separated directories that are
    always denied, before any allowlist, cache, reader, or scan runs.

    Empty by default. Set it in the shell profile or the hook's env block for
    directories that must never reach the model regardless of content.
    """
    raw = os.environ.get("FERPA_GUARD_HARD_DENY", "")
    roots = []
    for entry in raw.split(os.pathsep):
        entry = entry.strip()
        if entry:
            roots.append(Path(os.path.expanduser(entry)))
    return tuple(roots)


HARD_DENY_ROOTS = _load_hard_deny_roots()
_HARD_DENY_REASON = "Access to protected private control data is denied."


def _contains_path(root: Path, candidate: Path) -> bool:
    """Return whether candidate is root or a component-safe descendant."""
    return candidate == root or root in candidate.parents


def _lexical_absolute(path: Path) -> Path:
    """Normalize a path lexically without requiring that it exists."""
    return Path(os.path.normpath(os.path.abspath(os.fspath(path))))


def path_is_hard_denied(path: Path, include_ancestors: bool = False) -> bool:
    """Check protected roots by both lexical and best-effort real containment.

    With include_ancestors=True (directory-scoped tools such as Grep), a path
    that is an ANCESTOR of a protected root is denied too: a search over a
    parent directory reaches the protected child.
    """
    candidate_lexical = _lexical_absolute(Path(path))

    def _hit(root: Path, cand: Path) -> bool:
        if _contains_path(root, cand):
            return True
        return include_ancestors and _contains_path(cand, root)

    for configured_root in HARD_DENY_ROOTS:
        root_lexical = _lexical_absolute(configured_root)
        if _hit(root_lexical, candidate_lexical):
            return True

        # Resolve separately from the lexical check. A symlink pointing outward
        # cannot undo lexical containment, while an outside symlink pointing
        # inward is caught here. Missing final components are permitted.
        try:
            candidate_resolved = candidate_lexical.resolve(strict=False)
            root_resolved = root_lexical.resolve(strict=False)
        except (OSError, RuntimeError):
            continue
        if _hit(root_resolved, candidate_resolved):
            return True

    return False

# ---------------------------------------------------------------------------
# Scan Result Cache (FIX-02)
# ---------------------------------------------------------------------------
# Keyed by (resolved_path, mtime, size). If the file hasn't changed,
# return the cached findings + action instead of re-scanning.
# Cache TTL: 1 hour max. Disk persistence optional via FERPA_GUARD_CACHE=1.

_CACHE_TTL = 3600
# Disk-cache wire format version. Version 3 rejects every pre-fail-closed
# verdict so a previously cached empty result cannot bypass fixed readers.
_CACHE_VERSION = 4  # v4 (2026-09-06): flush pre-Phase-0 verdicts that scanned commented workbooks as clean
_DISK_CACHE_PATH = Path.home() / ".claude" / "ferpa-guard-cache.json"

# In-memory cache: { (path, mtime, size): { "findings": [...], "cached_at": float } }
_scan_cache: dict[tuple, dict] = {}
_OPERATIONAL_PATTERNS = {"SCAN_READER_UNAVAILABLE", "SCAN_INCOMPLETE"}


def _has_operational_findings(findings: list[dict]) -> bool:
    return any(f.get("pattern_name") in _OPERATIONAL_PATTERNS for f in findings)


def _cache_key(resolved_path: str) -> tuple | None:
    """Build a cache key from file stat. Returns None if file can't be stat'd."""
    try:
        st = os.stat(resolved_path)
        return (resolved_path, st.st_mtime, st.st_size)
    except OSError:
        return None


def _cache_get(key: tuple) -> list[dict] | None:
    """Look up cached findings. Returns None on miss or expired entry."""
    entry = _scan_cache.get(key)
    if entry is None:
        return None
    if time.time() - entry["cached_at"] > _CACHE_TTL:
        del _scan_cache[key]
        return None
    findings = entry["findings"]
    if _has_operational_findings(findings):
        del _scan_cache[key]
        return None
    return findings


def _cache_put(key: tuple, findings: list[dict]) -> None:
    """Store findings in cache."""
    if _has_operational_findings(findings):
        return
    _scan_cache[key] = {"findings": findings, "cached_at": time.time()}


def _load_disk_cache() -> None:
    """Load cache from disk if FERPA_GUARD_CACHE=1 and file exists."""
    if not os.environ.get("FERPA_GUARD_CACHE"):
        return
    if not _DISK_CACHE_PATH.is_file():
        return
    try:
        data = json.loads(_DISK_CACHE_PATH.read_text())
        # Wire format v4: {"version": 4, "entries": [...]}. Anything else is
        # ignored wholesale (cold cache, never migrated) because older
        # versions may contain fail-open reader verdicts.
        if not isinstance(data, dict) or data.get("version") != _CACHE_VERSION:
            return
        now = time.time()
        for entry in data.get("entries", []):
            key = tuple(entry["key"])
            if (now - entry["cached_at"] <= _CACHE_TTL
                    and not _has_operational_findings(entry["findings"])):
                _scan_cache[key] = {
                    "findings": entry["findings"],
                    "cached_at": entry["cached_at"],
                }
    except (json.JSONDecodeError, KeyError, TypeError, OSError):
        pass


def _save_disk_cache() -> None:
    """Persist cache to disk if FERPA_GUARD_CACHE=1."""
    if not os.environ.get("FERPA_GUARD_CACHE"):
        return
    try:
        now = time.time()
        entries = []
        for key, val in _scan_cache.items():
            if (now - val["cached_at"] <= _CACHE_TTL
                    and not _has_operational_findings(val["findings"])):
                entries.append({
                    "key": list(key),
                    "findings": val["findings"],
                    "cached_at": val["cached_at"],
                })
        _DISK_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _DISK_CACHE_PATH.write_text(
            json.dumps({"version": _CACHE_VERSION, "entries": entries})
        )
    except OSError:
        pass


def _write_audit_entry(original_path: str, resolved_path: str, source: str):
    """Audit an allowlist bypass: JSONL record + stderr echo. Never raises."""
    print(
        f"FERPA GUARD AUDIT: bypass resolved={resolved_path} source={source}",
        file=sys.stderr,
    )
    write_audit_event(AUDIT_LOG_PATH, "bypass", resolved_path, [], source=source)


# ---------------------------------------------------------------------------
# Path Extraction (Claude Code tool input parsing)
# ---------------------------------------------------------------------------

# Commands that send file content to stdout (and therefore to the LLM context).
# Only files referenced by these commands need PII scanning.
_CONTENT_COMMANDS = {
    "cat", "head", "tail", "less", "more", "bat",
    "grep", "egrep", "fgrep", "rg",
    "sed", "awk",
    "sort", "cut", "paste", "join", "uniq", "tr", "comm",
    "diff",
    "python3", "python", "node",
}

# Commands that only touch file metadata or move files around.
# These never send file content to the LLM, so scanning is unnecessary.
_METADATA_COMMANDS = {
    "ls", "wc", "stat", "file", "du", "find",
    "mv", "cp", "rm", "mkdir", "chmod", "chown", "touch",
    "ln", "readlink", "realpath", "basename", "dirname",
    "tee",  # writes its operands, reads only stdin
}


# Tokens that wrap another command; strip them before classifying a segment.
_COMMAND_WRAPPERS = {
    "sudo", "env", "nohup", "time", "command", "builtin", "exec", "nice",
    "xargs", "if", "then", "else", "elif", "do", "while", "until", "for",
}

# Segments that are pure shell syntax with nothing to classify or scan.
_SHELL_NOOP_TOKENS = {"", "done", "fi", "esac", "then", "else", "do"}

_ENV_ASSIGNMENT = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*=\S*\s*')


def _split_shell_segments(cmd: str) -> list[str]:
    """Split a shell command line into simple-command segments.

    Splits on UNQUOTED control operators only: newline, ';', '&&', '||',
    '|', '|&', and a control '&'. Redirection forms that contain '&'
    ('>&', '<&', '&>', '&>>', and 'n>&m') never split. Nothing inside
    single quotes, double quotes, backticks, or $(...) splits. Top-level
    '(', ')', '{', '}' are treated as whitespace so grouped commands are
    still seen. Each segment keeps its original text; empty ones are dropped.
    """
    segments: list[str] = []
    buf: list[str] = []
    n = len(cmd)
    i = 0
    in_single = in_double = in_backtick = False
    subst_depth = 0

    def flush():
        seg = "".join(buf).strip()
        if seg:
            segments.append(seg)
        buf.clear()

    while i < n:
        c = cmd[i]
        nxt = cmd[i + 1] if i + 1 < n else ""

        if in_single:
            buf.append(c)
            if c == "'":
                in_single = False
            i += 1
            continue
        if c == "\\" and not in_single:
            # Escaped character: keep both, never an operator.
            buf.append(c)
            if i + 1 < n:
                buf.append(nxt)
            i += 2
            continue
        if in_double:
            buf.append(c)
            if c == '"':
                in_double = False
            i += 1
            continue
        if in_backtick:
            buf.append(c)
            if c == "`":
                in_backtick = False
            i += 1
            continue
        if c == "'":
            in_single = True
            buf.append(c)
            i += 1
            continue
        if c == '"':
            in_double = True
            buf.append(c)
            i += 1
            continue
        if c == "`":
            in_backtick = True
            buf.append(c)
            i += 1
            continue
        if c == "$" and nxt == "(":
            subst_depth += 1
            buf.append("$(")
            i += 2
            continue
        if subst_depth:
            if c == "(":
                subst_depth += 1
            elif c == ")":
                subst_depth -= 1
            buf.append(c)
            i += 1
            continue

        # Top level, unquoted.
        if c == "\n" or c == ";":
            flush()
            i += 1
            continue
        if c == "|":
            flush()
            i += 2 if nxt in ("|", "&") else 1
            continue
        if c == "&":
            prev = cmd[i - 1] if i > 0 else ""
            if nxt == "&":
                flush()
                i += 2
                continue
            if prev in (">", "<") or nxt == ">":
                buf.append(c)          # redirection, not a control operator
                i += 1
                continue
            flush()                    # background '&'
            i += 1
            continue
        if c in "()":
            # Subshell grouping and `case` clause patterns (`word)`): a
            # separator, so `file) cat x.csv` never classifies as `file`.
            flush()
            i += 1
            continue
        if c in "{}":
            buf.append(" ")
            i += 1
            continue
        buf.append(c)
        i += 1

    flush()
    return segments


def _substitution_bodies(segment: str) -> list[str]:
    """Return the command text inside every `$(...)` and backtick substitution
    in a segment (outside single quotes, where no substitution happens). The
    shell runs these as commands whatever the outer command is, so
    `ls $(cat roster.csv)` still reads the roster."""
    bodies: list[str] = []
    i, n = 0, len(segment)
    in_single = False
    while i < n:
        c = segment[i]
        if c == "\\":
            i += 2
            continue
        if c == "'":
            in_single = not in_single
            i += 1
            continue
        if in_single:
            i += 1
            continue
        if c == "$" and i + 1 < n and segment[i + 1] == "(":
            depth, j = 1, i + 2
            while j < n and depth:
                if segment[j] == "\\":
                    j += 2
                    continue
                if segment[j] == "(":
                    depth += 1
                elif segment[j] == ")":
                    depth -= 1
                j += 1
            bodies.append(segment[i + 2:j - 1] if depth == 0 else segment[i + 2:])
            i = j
            continue
        if c == "`":
            j = segment.find("`", i + 1)
            if j == -1:
                bodies.append(segment[i + 1:])
                break
            bodies.append(segment[i + 1:j])
            i = j + 1
            continue
        i += 1
    return bodies


def _segment_command_name(segment: str) -> str:
    """Return the command name of a segment after stripping wrappers.

    Handles leading env assignments (FOO=bar cmd), sudo/env/time/xargs and
    shell keywords (for/do/if/then ...), leading '!' and path prefixes
    (/usr/bin/cat -> cat). Returns '' for pure-syntax segments.
    """
    rest = segment.strip()
    for _ in range(16):  # bounded: wrappers nest only a few deep in practice
        rest = rest.lstrip("! \t")
        m = _ENV_ASSIGNMENT.match(rest)
        while m:
            rest = rest[m.end():]
            m = _ENV_ASSIGNMENT.match(rest)
        parts = rest.split(None, 1)
        if not parts:
            return ""
        token = parts[0].rsplit("/", 1)[-1]
        if token in _COMMAND_WRAPPERS:
            rest = parts[1] if len(parts) > 1 else ""
            continue
        return token
    return token


# An input redirection (`< file`), excluding heredocs (`<<`) and descriptor
# duplication (`<&`).
_INPUT_REDIRECT = re.compile(r"(?<![<>])<(?![<&])")


def _segment_is_content(segment: str) -> bool:
    """Classify one simple-command segment.

    Pure shell syntax (`done`, `fi`, `esac` ...) is not a command, except
    that a block-closing keyword carrying an input redirection
    (`done < roster.csv`) feeds that file to the whole block and is a read.
    """
    name = _segment_command_name(segment)
    if name in _SHELL_NOOP_TOKENS:
        return bool(_INPUT_REDIRECT.search(segment))
    return name not in _METADATA_COMMANDS


def _is_content_command(cmd: str) -> bool:
    """Return True if ANY segment of the Bash command reads file content.

    Each simple command in a compound line is classified on its own, so
    'ls ; cat roster.csv' is a content command. Metadata-only commands (ls,
    wc, mv, ...) return False; content commands and unknown commands return
    True (scan conservatively).
    """
    return any(_segment_is_content(s) for s in _split_shell_segments(cmd))


_DATA_EXTS = "|".join(e.lstrip(".") for e in SCANNABLE_EXTENSIONS)


def _extract_bash_segment_paths(segment: str) -> list[str]:
    """Run the Bash path regexes over ONE simple-command segment."""
    paths: list[str] = []
    data_exts = _DATA_EXTS

    # Extract paths from common file-reading commands. A quoted operand is
    # taken whole (paths with spaces), an unquoted one up to the next
    # separator; no phantom prefix path is produced for quoted operands.
    # Operand character classes exclude `)` (a substitution or clause
    # boundary) and `<` (a heredoc or redirect operator) so no phantom
    # operand such as `/d/r.csv)` or `<<EOF` is produced.
    reading_cmds = r"(?:cat|head|tail|less|more|bat)\s+"
    for dq, sq, bare in re.findall(
        rf"{reading_cmds}(?:-\S+\s+)*(?:\"([^\"]+)\"|'([^']+)'|([^\s\"'|;><()]+))", segment
    ):
        paths.append(dq or sq or bare)

    # Processing commands (grep, sed, awk, sort, cut, etc.)
    processing_cmds = r"(?:grep|egrep|fgrep|sed|awk|sort|cut|diff|comm|paste|join|uniq|tr)\s+"
    paths.extend(re.findall(
        rf"{processing_cmds}(?:-\S+\s+)*(?:\"[^\"]*\"\s+|'[^']*'\s+)*[\"']?([^\s\"'|;>()]+\.(?:{data_exts}))[\"']?",
        segment,
    ))

    # Catch explicit file paths in quoted strings for data extensions
    paths.extend(re.findall(rf"[\"']([^\"']+\.(?:{data_exts}))[\"']", segment))

    # Input redirects (< file.csv) -- NOT output redirects (>, >>), not the
    # '<&' descriptor-duplication form, and not a heredoc ('<<').
    paths.extend(re.findall(r"(?<![<>])<(?![<&])\s*[\"']?([^\s\"'|;>&<()]+)", segment))

    # Bare unquoted data files (paths with data extensions anywhere in command)
    # Exclude output redirect targets by requiring no preceding > or >>
    paths.extend(re.findall(
        rf"(?<!>\s)(?<!\S)([^\s\"'|;><()]+\.(?:{data_exts}))(?=\s|$|[|;>)])",
        segment,
    ))
    return paths


# ---------------------------------------------------------------------------
# Native Grep tool (Phase 0, spec 2.2)
# ---------------------------------------------------------------------------

# Bound on directory entries consumed by the existence walk (Shortcut B).
GREP_WALK_BUDGET = 5000

# Shortcut A: a glob of exactly one non-scannable extension. Anything richer
# (directories, **, braces, ! exclusions) is not emulated; ripgrep's glob
# semantics are not reproduced here. Verified premise: the bundled Grep tool
# runs its embedded ripgrep with --no-config, so no configuration can widen
# the glob.
_SINGLE_EXT_GLOB = re.compile(r"^\*\.([A-Za-z0-9]+)$")

_GREP_SCOPE_REASON = (
    "FERPA Guard blocked this search. It would read every matching line from a "
    "folder that contains spreadsheet or data files. Narrow it to one file, or "
    "add glob: \"*.py\" (or another code file type), or use the default output "
    "mode, which lists file names only."
)


def grep_scope(tool_input: dict) -> str:
    """The path Grep searches: its `path`, else the working directory."""
    return tool_input.get("path") or os.getcwd()


class WalkResult:
    """verdict: True = no scannable file and complete; False = a scannable
    file was found; None = unknown (error or budget exhausted). consumed:
    directory entries consumed before returning."""

    __slots__ = ("verdict", "consumed")

    def __init__(self, verdict, consumed: int):
        self.verdict = verdict
        self.consumed = consumed


def walk_finds_no_scannable(scope: str, budget: int = GREP_WALK_BUDGET) -> WalkResult:
    """Incremental, fail-closed existence walk (Shortcut B).

    Uses os.scandir over an explicit stack, never os.walk (which swallows
    enumeration errors and materializes whole directories). Every entry
    counts toward the budget as it is consumed. Symlinks are not followed,
    matching ripgrep's default, but a symlink whose NAME passes should_scan
    counts as a scannable file. Any OSError, or budget exhaustion, is an
    unknown outcome, never an allow.
    """
    consumed = 0
    stack = [scope]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    if consumed >= budget:
                        return WalkResult(None, consumed)
                    consumed += 1
                    try:
                        is_link = entry.is_symlink()
                        is_dir = (not is_link) and entry.is_dir(follow_symlinks=False)
                    except OSError:
                        return WalkResult(None, consumed)
                    if is_dir:
                        if entry.name in SKIP_DIRS:
                            continue
                        stack.append(entry.path)
                        continue
                    if should_scan(entry.path):
                        return WalkResult(False, consumed)
        except OSError:
            return WalkResult(None, consumed)
    return WalkResult(True, consumed)


def grep_directory_verdict(scope: str, tool_input: dict) -> str:
    """Decide a content-mode Grep over a directory: 'allow' or 'deny'.

    Deny-and-narrow, with two provable allow shortcuts:
      A. glob is exactly '*.<ext>' with a non-scannable extension and no type;
      B. the bounded existence walk completes and finds no scannable file.
    Everything else, including a missing scope, is denied.
    """
    try:
        if not os.path.isdir(scope):
            return "deny"
    except OSError:
        return "deny"

    glob = tool_input.get("glob")
    ftype = tool_input.get("type")
    if glob and not ftype:
        m = _SINGLE_EXT_GLOB.match(glob)  # exact match; whitespace is not stripped (spec 2.2)
        if m and ("." + m.group(1).lower()) not in SCANNABLE_EXTENSIONS:
            return "allow"

    if walk_finds_no_scannable(scope).verdict is True:
        return "allow"
    return "deny"


_MAX_SUBSTITUTION_DEPTH = 3


def extract_file_paths(tool_name: str, tool_input: dict, _depth: int = 0) -> list[str]:
    """Pull file paths from tool input depending on tool type."""
    paths = []

    if tool_name == "Read":
        fp = tool_input.get("file_path", "")
        if fp:
            paths.append(fp)

    elif tool_name == "Bash":
        cmd = tool_input.get("command", "")

        # Compound commands: classify and extract per simple-command segment,
        # on the segment's original text. Metadata segments (ls, wc, mv ...)
        # contribute no paths; 'ls ; cat roster.csv' still scans roster.csv.
        for segment in _split_shell_segments(cmd):
            if _segment_is_content(segment):
                paths.extend(_extract_bash_segment_paths(segment))
            # Command substitutions run regardless of the outer command:
            # `ls $(cat roster.csv)` reads the roster. Recurse into each body
            # as its own command line, bounded in depth.
            if _depth < _MAX_SUBSTITUTION_DEPTH:
                for body in _substitution_bodies(segment):
                    paths.extend(extract_file_paths("Bash", {"command": body}, _depth + 1))

    elif tool_name == "Grep":
        # Only output_mode "content" returns matching lines to the model;
        # the default (files_with_matches) and "count" disclose paths and
        # counts only. A file scope is scanned like a Read. A directory
        # scope is decided by grep_directory_verdict() in main(), never
        # expanded into per-file scans here.
        if tool_input.get("output_mode") == "content":
            scope = grep_scope(tool_input)
            try:
                if os.path.isfile(scope):
                    paths.append(scope)
            except OSError:
                pass

    # Deduplicate while preserving order
    seen = set()
    unique_paths = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            unique_paths.append(p)
    return unique_paths


def extract_hard_deny_candidates(tool_name: str, tool_input: dict) -> list[str]:
    """Extract path candidates for protected-root checks, independent of scanning.

    Unlike ``extract_file_paths``, this intentionally considers metadata
    commands, unsupported extensions, and every shell operand. False-positive
    candidates are harmless because component-safe root containment remains the
    deciding check.
    """
    if tool_name in ("Read", "Edit"):
        file_path = tool_input.get("file_path", "")
        return [file_path] if isinstance(file_path, str) and file_path else []
    if tool_name == "Grep":
        # The searched scope, in every output mode; ancestor containment is
        # applied by the caller via path_is_hard_denied(include_ancestors=True).
        scope = grep_scope(tool_input)
        return [scope] if isinstance(scope, str) and scope else []
    if tool_name != "Bash":
        return []

    command = tool_input.get("command", "")
    if not isinstance(command, str) or not command:
        return []
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError:
        # An incomplete quote must not hide an otherwise visible protected
        # reference. This fallback does not execute or expand shell syntax.
        tokens = command.split()

    candidates = []
    for token in tokens:
        candidate = token.strip("|&;<>()")
        if not candidate:
            continue
        candidates.append(candidate)
        if "=" in candidate:
            assigned_value = candidate.split("=", 1)[1]
            if assigned_value:
                candidates.append(assigned_value)
    return candidates


# ---------------------------------------------------------------------------
# Output Formatting (Claude Code-specific)
# ---------------------------------------------------------------------------

def format_block_reason(filepath: str, findings: list[dict]) -> str:
    """Format a block reason with a user-facing summary and Claude instructions.

    The output has two sections:
    1. A user-facing message (show verbatim to the user)
    2. Claude-only instructions (behavioral guidance, not shown directly)
    """
    p = Path(filepath)
    ext = p.suffix.lower()

    critical = [f for f in findings if f["severity"] == "critical"]
    high = [f for f in findings if f["severity"] == "high"]
    medium = [f for f in findings if f["severity"] == "medium"]

    pii_types = []
    finding_lines = []
    for group, label in [(critical, "CRITICAL"), (high, "HIGH"), (medium, "MEDIUM")]:
        if group:
            for f in group:
                conf = f.get("confidence", "high").upper()
                finding_lines.append(f"  [{label}/{conf}] {f['description']}: {f['count']} occurrence(s)")
                pii_types.append(f['description'])

    # Resolve path to the redactor script (shared directory, relative to project root)
    redactor_path = str(Path(__file__).parent.parent / "shared" / "pii_redactor.py")
    redacted_path = str(p.with_name(f"{p.stem}_redacted{ext}"))
    redactor_supported = ext in {".csv", ".tsv", ".txt", ".json", ".jsonl", ".xml", ".xlsx"}

    # --- Section 1: User-facing message (show verbatim) ---
    user_lines = [
        f"FERPA Guard blocked '{p.name}' because it contains: {', '.join(pii_types)}.",
        "FERPA requires written consent before disclosing student education records.",
        "",
        "What was found:",
    ]
    user_lines.extend(finding_lines)
    user_lines.append("")
    user_lines.append("You have a few options:")
    user_lines.append(f"  1. Generate a synthetic {ext} file with the same structure but fake data")
    if redactor_supported:
        user_lines.append(f"  2. Run the built-in redactor to create a safe copy (headers and structure preserved)")
    else:
        user_lines.append(f"  2. Write a redaction script (built-in redactor does not support {ext})")
    user_lines.append("  3. Keep only specific safe columns, strip everything else")
    if critical or high:
        user_lines.append("  4. Allowlist this file if it contains no real student data")
    next_opt = 5 if (critical or high) else 4
    user_lines.append(f"  {next_opt}. Mark as false positive (logs this for pattern tuning, does not bypass)")

    # Build pattern names string for feedback log command
    pattern_names = ",".join(f["pattern_name"] for f in findings)

    # --- Section 2: Claude-only instructions ---
    claude_lines = [
        "",
        "--- INSTRUCTIONS FOR CLAUDE (do not show this section) ---",
        "Show the user the message above verbatim. Do NOT re-read or bypass the blocked file.",
        "Wait for the user to choose an option, then execute it:",
        "",
        f"  Option 1: Generate synthetic {ext} with same column structure. Save as '{p.stem}_synthetic{ext}'.",
    ]
    if redactor_supported:
        claude_lines.append(f"  Option 2: Run via Bash: python3 \"{redactor_path}\" \"{filepath}\"")
        claude_lines.append(f"            Output: '{redacted_path}'. Read the redacted file to continue.")
    else:
        claude_lines.append(f"  Option 2: Write a redaction script the user can run.")
    claude_lines.append("  Option 3: Ask user which columns are safe, write a filtering script.")
    if critical or high:
        claude_lines.append(f"  Option 4: Add to allowlist: echo \"{filepath}\" >> ~/.claude/ferpa-guard-allow.txt")
        claude_lines.append(f"            Or env var: export FERPA_GUARD_ALLOW=\"{filepath}\"")
    claude_lines.append(f"  Option {next_opt}: Run via Bash: echo \"$(date -Iseconds) FP path={filepath} patterns={pattern_names}\" >> ~/.claude/ferpa-guard-feedback.log")
    claude_lines.append(f"            Tell user: logged for future pattern tuning. The file stays blocked this time.")

    return "\n".join(user_lines + claude_lines)


def _operational_reason(finding: dict) -> str:
    description = finding.get("description", "The scanner could not verify the file")
    return description[:1].lower() + description[1:]


# Reader outcomes under which nothing of the file was read.
_NO_CONTENT_CODES = {
    "MISSING_DEPENDENCY:openpyxl",
    "MISSING_DEPENDENCY:pymupdf",
    "MISSING_DEPENDENCY:python-docx",
    "OPEN_FAILED",
    "ENCRYPTED",
    "UNREADABLE",
}


def _operational_recovery_lines(filepath: str, findings: list[dict]) -> list[str]:
    p = Path(filepath)
    codes = {f.get("code", "") for f in findings}
    dependency_commands = {
        "MISSING_DEPENDENCY:openpyxl": "pip install openpyxl",
        "MISSING_DEPENDENCY:pymupdf": "pip install pymupdf",
        "MISSING_DEPENDENCY:python-docx": "pip install python-docx",
    }
    install_command = next(
        (command for code, command in dependency_commands.items() if code in codes),
        None,
    )

    allowlist_line = (
        "3. If you have verified this exact file is safe, add its full path to a "
        f"`.pii-guardian-allow` file in `{p.parent}` (takes effect immediately), or to "
        "`~/.claude/ferpa-guard-allow.txt`."
    )

    # An open failure takes precedence: advising comment removal for a file
    # that will not open is wrong. Only when the workbook was otherwise
    # readable is the comment hold the reason to act on.
    open_failure = bool(codes & _NO_CONTENT_CODES)
    if "XLSX_COMMENTS" in codes and not open_failure:
        # Phase 0 (spec 2.3): comments are held, never read. Two ways forward
        # that keep the original out of the model, then the allowlist.
        return [
            "1. Remove the comments in Excel (Review > Delete All Comments in Workbook), "
            "save a copy, and open that.",
            "2. Or run the built-in redactor on the file: it removes all comments and "
            "creates a `_redacted` copy, but it only masks values its patterns detect, "
            "so review the copy before use.",
            allowlist_line,
        ]

    if install_command:
        first = f"1. Install it: `{install_command}`, then retry."
    elif "ENCRYPTED" in codes:
        first = "1. Make an unlocked copy with permission from the file owner, then retry."
    else:
        first = "1. Confirm the file is readable and complete, then retry."

    return [
        first,
        "2. Convert the file to CSV and retry.",
        allowlist_line,
    ]


def format_unscannable_reason(filepath: str, findings: list[dict]) -> str:
    """Format an operational-only block without claiming PII was detected."""
    p = Path(filepath)
    reasons = "; ".join(_operational_reason(f) for f in findings)
    codes = {f.get("code", "") for f in findings}
    # XLSX_COMMENTS never reads content by itself, so it must not turn an
    # open failure into "part of the file may have been checked".
    content_codes = codes - {"XLSX_COMMENTS"}
    if content_codes and content_codes <= _NO_CONTENT_CODES:
        read_status = "No file contents were read."
    else:
        read_status = "Only part of the file may have been checked."

    lines = [
        f"FERPA Guard blocked '{p.name}' because it could not check this file: {reasons}.",
        read_status,
    ]
    lines.extend(_operational_recovery_lines(filepath, findings))
    return "\n".join(lines)


def format_partial_scan_reason(
    filepath: str,
    detection_findings: list[dict],
    operational_findings: list[dict] | None = None,
) -> str:
    """Format a block containing both detections and an incomplete scan."""
    if operational_findings is None:
        all_findings = detection_findings
        detection_findings = [
            f for f in all_findings
            if f.get("pattern_name") not in _OPERATIONAL_PATTERNS
        ]
        operational_findings = [
            f for f in all_findings
            if f.get("pattern_name") in _OPERATIONAL_PATTERNS
        ]

    p = Path(filepath)
    lines = [
        f"FERPA Guard blocked '{p.name}'.",
        "FERPA Guard detected the following in the portion it could check, and could not verify the remainder.",
        "",
        "Detected in the checked portion:",
    ]
    for finding in detection_findings:
        confidence = finding.get("confidence", "high").upper()
        lines.append(
            f"  [{finding['severity'].upper()}/{confidence}] "
            f"{finding['description']}: {finding['count']} occurrence(s)"
        )
    lines.extend(["", "Why the remainder could not be verified:"])
    for finding in operational_findings:
        lines.append(f"  - {_operational_reason(finding)}")
    lines.append("")
    lines.extend(_operational_recovery_lines(filepath, operational_findings))
    return "\n".join(lines)


def _format_block_reason_dispatch(filepath: str, findings: list[dict]) -> str:
    operational = [
        f for f in findings if f.get("pattern_name") in _OPERATIONAL_PATTERNS
    ]
    detections = [
        f for f in findings if f.get("pattern_name") not in _OPERATIONAL_PATTERNS
    ]
    if operational and detections:
        return format_partial_scan_reason(filepath, detections, operational)
    if operational:
        return format_unscannable_reason(filepath, operational)
    return format_block_reason(filepath, detections)


def format_warning(filepath: str, findings: list[dict]) -> str:
    """Format a warning for possible PII (allowed but flagged)."""
    lines = [
        "FERPA GUARD: Possible sensitive data (not blocked).",
        f"File: {filepath}",
    ]
    for f in findings:
        conf = f.get("confidence", "medium").upper()
        lines.append(f"  [{conf} confidence] {f['description']}: {f['count']} occurrence(s)")
    lines.append("Note: These matches may be false positives. If this file contains real")
    lines.append("student data, stop and run the redactor before proceeding.")
    return "\n".join(lines)


def format_log_note(filepath: str) -> str:
    """Format a brief log note for low-confidence matches (allowed silently)."""
    return f"FERPA GUARD: Header/prose references noted in {filepath} (allowed)."


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def output_allow():
    """Allow the tool call and exit."""
    sys.exit(0)


def output_deny(reason: str):
    """Deny the tool call with a reason."""
    result = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }
    print(json.dumps(result))
    print(reason, file=sys.stderr)
    sys.exit(2)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _load_allowlists() -> tuple[dict, dict, set]:
    """Load allowlist sources, pattern-level skips, and global skips.

    Sources: FERPA_GUARD_ALLOW (comma-separated paths), the user allowlist
    file ~/.claude/ferpa-guard-allow.txt (one path per line, optional
    `SKIP:PATTERN,...` suffix for pattern-level skips), and
    FERPA_GUARD_SKIP_PATTERNS. All paths are resolved so comparisons are
    canonical. Read on every invocation so edits take effect immediately.
    """
    allowlist_sources: dict[str, str] = {}
    path_skip_patterns: dict[str, set] = {}
    global_skip_patterns: set = set()

    for p in os.environ.get("FERPA_GUARD_ALLOW", "").split(","):
        p = p.strip()
        if p:
            allowlist_sources[str(Path(p).resolve())] = "env(FERPA_GUARD_ALLOW)"

    for pat in os.environ.get("FERPA_GUARD_SKIP_PATTERNS", "").split(","):
        pat = pat.strip()
        if pat:
            global_skip_patterns.add(pat)

    allowlist_file = Path.home() / ".claude" / "ferpa-guard-allow.txt"
    if allowlist_file.is_file():
        try:
            for line in allowlist_file.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    skip_match = re.match(r'^(.+?)\s+SKIP:(.+)$', line)
                    if skip_match:
                        entry_path = skip_match.group(1).strip()
                        skip_names = {s.strip() for s in skip_match.group(2).split(",")}
                        resolved_entry = str(Path(entry_path).resolve())
                        path_skip_patterns[resolved_entry] = skip_names
                        allowlist_sources.setdefault(resolved_entry, f"file({allowlist_file})")
                    else:
                        allowlist_sources[str(Path(line).resolve())] = f"file({allowlist_file})"
        except OSError:
            pass
    return allowlist_sources, path_skip_patterns, global_skip_patterns


def _full_bypass_source(resolved: str, allowlist_sources: dict, path_skip_patterns: dict):
    """Return the allowlist source that fully bypasses `resolved`, or None.

    Exact path or directory-prefix match against full-bypass entries (SKIP
    entries are pattern-level, not bypasses), then the ancestor-walk
    `.pii-guardian-allow` file.
    """
    for a in allowlist_sources:
        if a in path_skip_patterns:
            continue
        if resolved == a or resolved.startswith(a.rstrip("/") + "/"):
            return allowlist_sources[a]
    allowfile_entries = collect_allowfile_entries(resolved)
    for a in allowfile_entries:
        if resolved == a or resolved.startswith(a.rstrip("/") + "/"):
            return f"allowfile({allowfile_entries[a]})"
    return None


def main():
    # Read hook input from stdin (Claude Code hooks API)
    try:
        raw_input = sys.stdin.read()
        hook_input = json.loads(raw_input)
    except (json.JSONDecodeError, ValueError):
        # Fallback to env vars for manual testing
        try:
            hook_input = {
                "tool_name": os.environ.get("TOOL_NAME", ""),
                "tool_input": json.loads(os.environ.get("TOOL_INPUT", "{}")),
            }
        except json.JSONDecodeError:
            output_allow()

    tool_name = hook_input.get("tool_name", "")
    tool_input = hook_input.get("tool_input", {})

    # Hard-deny roots are a directory boundary, not a content scan: they apply
    # to every tool the hook is invoked for, Edit included, and run before the
    # content gate below. (The installer matcher is Read|Bash, so Edit only
    # reaches this check if a settings.json matcher also lists Edit.)
    hard_deny_candidates = extract_hard_deny_candidates(tool_name, tool_input)

    # A directory-scoped search (Grep) also reaches protected roots BELOW its
    # scope, so ancestors of a root are denied for it as well.
    include_ancestors = tool_name == "Grep"
    if any(path_is_hard_denied(Path(candidate), include_ancestors=include_ancestors)
           for candidate in hard_deny_candidates):
        output_deny(_HARD_DENY_REASON)

    # Guard the tools that pull file CONTENT into the model's context. Read
    # does; Bash does (cat, grep, head); Grep does in output_mode "content".
    # Edit does not: it pushes content the model already holds, and gating it
    # blocked editing out an offending token -- the guard blocked its own
    # remediation (live parity, spec Q6).
    if tool_name not in ("Read", "Bash", "Grep"):
        output_allow()

    file_paths = extract_file_paths(tool_name, tool_input)

    # Allowlists (env, user file, ancestor allowfile). Loaded before the Grep
    # directory verdict so an allowlisted directory permits a content-mode
    # search, consistent with "allowlisted paths are not scanned".
    allowlist_sources, path_skip_patterns, global_skip_patterns = _load_allowlists()

    # Content-mode Grep over a directory: deny-and-narrow unless provably
    # safe (spec 2.2). Never expanded into per-file scans.
    if tool_name == "Grep" and tool_input.get("output_mode") == "content" and not file_paths:
        scope = grep_scope(tool_input)
        resolved_scope = str(Path(scope).resolve())
        bypass = _full_bypass_source(resolved_scope, allowlist_sources, path_skip_patterns)
        if bypass is not None:
            _write_audit_entry(scope, resolved_scope, bypass)
            output_allow()
        if grep_directory_verdict(scope, tool_input) == "deny":
            write_audit_event(AUDIT_LOG_PATH, "block", scope, ["GREP_SCOPE"])
            output_deny(_GREP_SCOPE_REASON)
        output_allow()

    if not file_paths:
        output_allow()

    # Load disk cache if enabled
    _load_disk_cache()

    # Strict mode: block on ANY finding (restores pre-confidence behavior)
    strict_mode = bool(os.environ.get("FERPA_GUARD_STRICT"))

    all_findings = {}

    for fp in file_paths:
        # Allowlist supports exact paths and directory prefixes.
        # Both the file path and allowlist entries are resolved to canonical paths.
        resolved = str(Path(fp).resolve())

        # Check for pattern-level skip first (SKIP entries don't fully bypass)
        file_skip = set(global_skip_patterns)
        for a in path_skip_patterns:
            if resolved == a or resolved.startswith(a.rstrip("/") + "/"):
                file_skip |= path_skip_patterns[a]

        # Check for full bypass (entries without SKIP)
        matched_entry = None
        for a in allowlist_sources:
            # Only full-bypass entries (not SKIP entries) trigger allowlist bypass
            if a not in path_skip_patterns:
                if resolved == a or resolved.startswith(a.rstrip("/") + "/"):
                    matched_entry = a
                    break
        if matched_entry is not None:
            _write_audit_entry(fp, resolved, allowlist_sources[matched_entry])
            continue

        # Ancestor-walk allowfile (.pii-guardian-allow): the no-restart escape
        # hatch. Read fresh each invocation; nearest declaration wins attribution.
        allowfile_entries = collect_allowfile_entries(resolved)
        allowfile_match = None
        for a in allowfile_entries:
            if resolved == a or resolved.startswith(a.rstrip("/") + "/"):
                allowfile_match = a
                break
        if allowfile_match is not None:
            _write_audit_entry(
                fp, resolved, f"allowfile({allowfile_entries[allowfile_match]})"
            )
            continue

        # Gate on the requested name OR the resolved target: a symlink with no
        # extension that points at roster.csv is still a read of roster.csv
        # (review finding 2026-09-07). An extensionless regular file stays
        # ungated by design (V2 criterion 3; documented in Coverage boundary).
        if not should_scan(fp) and not should_scan(resolved):
            continue

        try:
            if not os.path.isfile(fp):
                continue
        except OSError:
            continue

        # Check cache before scanning (FIX-02)
        cache_key = _cache_key(resolved)
        if cache_key and not file_skip:
            cached = _cache_get(cache_key)
            if cached is not None:
                if cached:
                    all_findings[fp] = cached
                continue

        scan_input = read_file_content(fp)
        findings = scan_content(scan_input.content, scan_input.header_line_indices,
                                early_exit=True,
                                skip_patterns=file_skip if file_skip else None)
        if scan_input.reader_error:
            findings.append(reader_error_finding(scan_input.reader_error, fp))
        if scan_input.truncated:
            findings.append(scan_incomplete_finding(scan_input.truncated, fp))

        # Cache only complete reader outcomes and only when skip_patterns did
        # not alter the result.
        if cache_key and not file_skip and not _has_operational_findings(findings):
            _cache_put(cache_key, findings)

        if findings:
            all_findings[fp] = findings

    if not all_findings:
        _save_disk_cache()
        output_allow()

    # Strict mode: any finding = block (restores pre-confidence behavior)
    if strict_mode:
        reasons = []
        for fp, findings in all_findings.items():
            for f in findings:
                f["confidence"] = "high"
            write_audit_event(
                AUDIT_LOG_PATH, "block", fp, [f["pattern_name"] for f in findings]
            )
            reasons.append(_format_block_reason_dispatch(fp, findings))
        _save_disk_cache()
        output_deny("\n\n".join(reasons))

    # Partition files by their worst action
    block_files = {}
    warn_files = {}
    log_files = {}

    for fp, findings in all_findings.items():
        action = worst_action(findings)
        if action == "block":
            block_files[fp] = findings
        elif action == "warn":
            warn_files[fp] = findings
        else:
            log_files[fp] = findings

    # Audit every per-file decision BEFORE any deny return -- a mixed
    # invocation (block + warn files) exits on the block, and the lower-tier
    # records must already be on disk by then.
    for action, files in (("block", block_files), ("warn", warn_files), ("log", log_files)):
        for fp, findings in files.items():
            write_audit_event(
                AUDIT_LOG_PATH, action, fp, [f["pattern_name"] for f in findings]
            )

    if block_files:
        reasons = []
        for fp, findings in block_files.items():
            reasons.append(_format_block_reason_dispatch(fp, findings))
        _save_disk_cache()
        output_deny("\n\n".join(reasons))

    # Warn and log go to stderr but allow the tool call
    for fp, findings in warn_files.items():
        print(format_warning(fp, findings), file=sys.stderr)
    for fp in log_files:
        print(format_log_note(fp), file=sys.stderr)

    _save_disk_cache()
    output_allow()


if __name__ == "__main__":
    main()
