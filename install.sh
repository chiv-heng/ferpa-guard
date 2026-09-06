#!/bin/bash
# install.sh -- Install FERPA Guard as a Claude Code hook
#
# Usage:
#   ./install.sh              Install globally (~/.claude/settings.json)
#   ./install.sh --project    Install for current project only (.claude/settings.local.json)
#
# Project-scoped (--project) is recommended. The hook only fires in projects
# that contain student data, reducing latency and false positives everywhere else.
#
# What it does:
#   1. Copies pii_guardian.py, pii_scan_report.py, and shared/ to ~/.claude/skills/ferpa-guard/
#   2. Registers the PreToolUse hook in the chosen settings file
#   3. Installs openpyxl (for xlsx scanning) with graceful fallback
#   4. Runs a 5-step self-test
#
# What it does NOT do:
#   - Overwrite existing hooks in settings.json (it merges)
#   - Require sudo

set -euo pipefail

# ---------------------------------------------------------------
# Step 0: Define helper functions (before any path resolution)
# ---------------------------------------------------------------
FAILURES=0
INSTALL_MODE="global"

pass() { echo "  [ok] $1"; }
fail() { echo "  [FAIL] $1"; FAILURES=$((FAILURES+1)); }
header() { echo ""; echo "==> $1"; }

# Parse arguments
for arg in "$@"; do
    case "$arg" in
        --project) INSTALL_MODE="project" ;;
        --global)  INSTALL_MODE="global" ;;
        --help|-h)
            echo "Usage: ./install.sh [--project | --global]"
            echo ""
            echo "  --project  Install hook for the current project only (recommended)"
            echo "             Writes to .claude/settings.local.json in the current directory"
            echo "  --global   Install hook for all projects (default)"
            echo "             Writes to ~/.claude/settings.json"
            exit 0
            ;;
        *) echo "Unknown option: $arg. Use --help for usage."; exit 1 ;;
    esac
done

# ---------------------------------------------------------------
# Step 1: Resolve paths portably
# ---------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="$HOME/.claude/skills/ferpa-guard"

if [ "$INSTALL_MODE" = "project" ]; then
    SETTINGS="$(pwd)/.claude/settings.local.json"
else
    SETTINGS="$HOME/.claude/settings.json"
fi

# ---------------------------------------------------------------
# Step 2: Copy hook + shared engine
# ---------------------------------------------------------------
header "Installing FERPA Guard"

mkdir -p "$DEST/scripts"

cp "$SCRIPT_DIR/claude-code/pii_guardian.py" "$DEST/scripts/pii_guardian.py"
pass "Copied pii_guardian.py to $DEST/scripts/"

cp "$SCRIPT_DIR/claude-code/pii_scan_report.py" "$DEST/scripts/pii_scan_report.py"
pass "Copied pii_scan_report.py to $DEST/scripts/"

cp -r "$SCRIPT_DIR/shared/" "$DEST/shared/"
pass "Copied shared/ engine to $DEST/shared/"

chmod +x "$DEST/scripts/pii_guardian.py"
pass "Set pii_guardian.py executable"

# ---------------------------------------------------------------
# Step 3: Merge hook into settings.json using Python json stdlib
# ---------------------------------------------------------------
header "Registering PreToolUse hook ($INSTALL_MODE mode)"

mkdir -p "$(dirname "$SETTINGS")"

python3 - "$SETTINGS" << 'PYEOF'
import sys, json, os

settings_path = sys.argv[1]
hook_command = "python3 \"$HOME/.claude/skills/ferpa-guard/scripts/pii_guardian.py\""
# Read and Bash pull file content into context; Grep does in output_mode
# "content". Edit and Write are allow-by-design (they push content the model
# already holds). Reinstalls reconcile older matchers (Read|Bash, Read|Bash|Edit).
hook_matcher = "Read|Bash|Grep"
hook_entry = {
    "matcher": hook_matcher,
    "hooks": [{"type": "command", "command": hook_command}]
}

settings = {}
if os.path.exists(settings_path):
    try:
        with open(settings_path) as f:
            settings = json.load(f)
    except json.JSONDecodeError:
        print(f"  [ERROR] {settings_path} contains invalid JSON. Please fix it manually or delete it to start fresh.")
        sys.exit(1)

settings.setdefault("hooks", {}).setdefault("PreToolUse", [])
ours = [
    h for h in settings["hooks"]["PreToolUse"]
    if any(hk.get("command") == hook_command for hk in h.get("hooks", []))
]
if not ours:
    settings["hooks"]["PreToolUse"].append(hook_entry)
    with open(settings_path, "w") as f:
        json.dump(settings, f, indent=2)
    print(f"  [ok] Hook registered in {settings_path}")
elif any(h.get("matcher") != hook_matcher for h in ours):
    # Reconcile a stale matcher from an earlier install (Read|Bash or Read|Bash|Edit)
    for h in ours:
        h["matcher"] = hook_matcher
    with open(settings_path, "w") as f:
        json.dump(settings, f, indent=2)
    print(f"  [ok] Hook matcher updated to {hook_matcher} in {settings_path}")
else:
    print("  [ok] Hook already registered (idempotent)")
PYEOF

# ---------------------------------------------------------------
# Step 4: Install optional dependencies
# ---------------------------------------------------------------
header "Checking dependencies"

if python3 -c "import openpyxl" 2>/dev/null; then
    pass "openpyxl already installed (xlsx scanning ready)"
else
    echo "  Installing openpyxl..."
    pip3 install openpyxl --quiet 2>/dev/null \
        || pip3 install openpyxl --break-system-packages --quiet 2>/dev/null \
        || echo "  [warn] Could not install openpyxl. xlsx files will be skipped. Try: pip3 install openpyxl"
fi

# ---------------------------------------------------------------
# Step 5: Self-test (5 checks)
# ---------------------------------------------------------------
header "Running self-test"

# Disable exit-on-error for tests (we check exit codes explicitly)
set +e

# Test 1: Clean file should pass (exit 0)
echo '{"tool_name":"Read","tool_input":{"file_path":"/dev/null"}}' | python3 "$DEST/scripts/pii_guardian.py" > /dev/null 2>&1
CLEAN_EXIT=$?
if [ "$CLEAN_EXIT" = "0" ]; then
    pass "Clean file: allowed (exit 0)"
else
    fail "Clean file should exit 0, got $CLEAN_EXIT"
fi

# Test 2: Non-file tool should pass (exit 0)
echo '{"tool_name":"Glob","tool_input":{"pattern":"*.py"}}' | python3 "$DEST/scripts/pii_guardian.py" > /dev/null 2>&1
SKIP_EXIT=$?
if [ "$SKIP_EXIT" = "0" ]; then
    pass "Non-file tool (Glob): allowed (exit 0)"
else
    fail "Non-file tool should exit 0, got $SKIP_EXIT"
fi

# Test 3: PII file should be blocked (exit 2)
TEMP_PII=$(mktemp /tmp/pii-test-XXXXXX.csv)
cat > "$TEMP_PII" << 'PIIEOF'
student_id,name,grade,sasid,parent_email
10234,Maria Santos,7,SASID 987654321,ana.santos@gmail.com
10235,James Wilson,8,SASID 123456789,rwilson@yahoo.com
PIIEOF

BLOCK_OUTPUT=$(echo "{\"tool_name\":\"Read\",\"tool_input\":{\"file_path\":\"$TEMP_PII\"}}" | python3 "$DEST/scripts/pii_guardian.py" 2>/dev/null)
BLOCK_EXIT=$?
rm -f "$TEMP_PII"

if [ "$BLOCK_EXIT" = "2" ]; then
    pass "PII file: blocked (exit 2)"
else
    fail "PII file should exit 2, got $BLOCK_EXIT"
fi

# Test 4: Block output should be valid JSON with permissionDecision=deny
if echo "$BLOCK_OUTPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['hookSpecificOutput']['permissionDecision']=='deny'" 2>/dev/null; then
    pass "Block output: valid JSON with permissionDecision=deny"
else
    fail "Block output is not valid hook protocol JSON"
fi

# Test 5: Verify shared/ import path works for pii_scan_report.py
python3 -c "import sys; sys.path.insert(0, '$DEST'); from shared import pii_engine" 2>/dev/null
IMPORT_EXIT=$?
if [ "$IMPORT_EXIT" = "0" ]; then
    pass "shared/ import works from install location"
else
    fail "shared/ import failed from install location"
fi

# Re-enable exit-on-error
set -e

# ---------------------------------------------------------------
# Done
# ---------------------------------------------------------------
header "Installation complete"
echo ""
if [ "$FAILURES" -gt 0 ]; then
    echo "  WARNING: $FAILURES self-test(s) failed. Check output above."
    echo ""
fi
echo "  FERPA Guard installed at: ~/.claude/skills/ferpa-guard/"
echo "  Hook registered in: $SETTINGS"
echo ""
if [ "$INSTALL_MODE" = "project" ]; then
    echo "  Mode: PROJECT-SCOPED (hook only fires in this project)"
    echo "  To add to another project, run ./install.sh --project from that directory."
else
    echo "  Mode: GLOBAL (hook fires in all projects)"
    echo "  To limit to specific projects, reinstall with: ./install.sh --project"
fi
echo ""
echo "  It will automatically scan files before Claude reads them."
echo "  To bypass a specific file: export FERPA_GUARD_ALLOW=\"/path/to/file\""
echo ""
echo "  Optional file type support:"
echo "    xlsx: pip3 install openpyxl"
echo "    pdf:  pip3 install pymupdf"
echo "    docx: pip3 install python-docx"
echo ""
echo "  To verify in a Claude session, try reading a CSV with student data."
echo ""
