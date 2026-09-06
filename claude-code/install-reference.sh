#!/bin/bash
# install-reference.sh -- REFERENCE for Stage 2 published installer
#
# This is NOT the active installer. It was saved from the Cowork-generated
# ferpa-guard-install/ prototype (2026-03-15) as a reference for building
# the real distribution installer. Key patterns to reuse:
#   - Merging hooks into existing settings.json without overwriting
#   - Graceful openpyxl install with fallback
#   - Self-test smoke tests on install
#
# When building Stage 2, adapt this to use the canonical scanner (with rich
# recovery instructions, PDF/DOCX support) and include the redactor.
#
# Original header below:
# install.sh -- Install FERPA Guard as a user-level Claude Code hook
#
# What it does:
#   1. Copies ferpa-guard.py and SKILL.md to ~/.claude/skills/ferpa-guard/
#   2. Registers the PreToolUse hook in ~/.claude/settings.json
#   3. Installs openpyxl (for xlsx scanning)
#   4. Runs a quick self-test
#
# What it does NOT do:
#   - Modify any project-level settings
#   - Overwrite existing hooks in settings.json (it merges)
#   - Require sudo

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEST="$HOME/.claude/skills/ferpa-guard"
SETTINGS="$HOME/.claude/settings.json"

header() { echo ""; echo "=== $1 ==="; }
pass()   { echo "  [ok] $1"; }
fail()   { echo "  [FAIL] $1"; exit 1; }

# ---------------------------------------------------------------
# Step 1: Copy files
# ---------------------------------------------------------------
header "Installing FERPA Guard"

mkdir -p "$DEST/scripts"

cp "$SCRIPT_DIR/scripts/ferpa-guard.py" "$DEST/scripts/ferpa-guard.py"
chmod +x "$DEST/scripts/ferpa-guard.py"
pass "Copied ferpa-guard.py to $DEST/scripts/"

cp "$SCRIPT_DIR/SKILL.md" "$DEST/SKILL.md"
pass "Copied SKILL.md to $DEST/"

# ---------------------------------------------------------------
# Step 2: Register hook in settings.json
# ---------------------------------------------------------------
header "Registering PreToolUse hook"

mkdir -p "$HOME/.claude"

if [ ! -f "$SETTINGS" ]; then
    # No settings file exists yet; create one
    cat > "$SETTINGS" << 'SETTINGSEOF'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Read|Bash|Grep",
        "hooks": [
          {
            "type": "command",
            "command": "python3 ~/.claude/skills/ferpa-guard/scripts/ferpa-guard.py"
          }
        ]
      }
    ]
  }
}
SETTINGSEOF
    pass "Created $SETTINGS with FERPA Guard hook"
else
    # Settings file exists; check if hook is already registered
    if grep -q "ferpa-guard" "$SETTINGS" 2>/dev/null; then
        pass "Hook already registered in $SETTINGS"
        echo "  Check that its matcher is \"Read|Bash|Grep\" (older installs used \"Read|Bash\";"
        echo "  this script does not rewrite an existing entry, install.sh does)."
    else
        echo ""
        echo "  ~/.claude/settings.json exists but does not contain the FERPA Guard hook."
        echo "  Please add this block manually inside the \"hooks\" object:"
        echo ""
        echo '    "PreToolUse": ['
        echo '      {'
        echo '        "matcher": "Read|Bash|Grep",'
        echo '        "hooks": ['
        echo '          {'
        echo '            "type": "command",'
        echo '            "command": "python3 ~/.claude/skills/ferpa-guard/scripts/ferpa-guard.py"'
        echo '          }'
        echo '        ]'
        echo '      }'
        echo '    ]'
        echo ""
        echo "  If you already have a PreToolUse array, add the matcher object to it."
    fi
fi

# ---------------------------------------------------------------
# Step 3: Install dependencies
# ---------------------------------------------------------------
header "Checking dependencies"

if python3 -c "import openpyxl" 2>/dev/null; then
    pass "openpyxl already installed"
else
    echo "  Installing openpyxl (needed for .xlsx scanning)..."
    pip3 install openpyxl --quiet 2>/dev/null || pip3 install openpyxl --break-system-packages --quiet 2>/dev/null
    if python3 -c "import openpyxl" 2>/dev/null; then
        pass "openpyxl installed"
    else
        echo "  [warn] Could not install openpyxl. xlsx files will be skipped."
        echo "         Try: pip3 install openpyxl"
    fi
fi

# ---------------------------------------------------------------
# Step 4: Self-test
# ---------------------------------------------------------------
header "Running self-test"

# Disable exit-on-error for tests (we check exit codes explicitly)
set +e

# Test 1: Clean file should pass
echo '{"tool_name":"Read","tool_input":{"file_path":"/dev/null"}}' | python3 "$DEST/scripts/ferpa-guard.py" > /dev/null 2>&1
CLEAN_EXIT=$?
if [ "$CLEAN_EXIT" = "0" ]; then
    pass "Clean file: allowed (exit 0)"
else
    fail "Clean file should exit 0, got $CLEAN_EXIT"
fi

# Test 2: Non-file-reading tool should pass
echo '{"tool_name":"Glob","tool_input":{"pattern":"*.py"}}' | python3 "$DEST/scripts/ferpa-guard.py" > /dev/null 2>&1
SKIP_EXIT=$?
if [ "$SKIP_EXIT" = "0" ]; then
    pass "Non-file tool (Glob): allowed (exit 0)"
else
    fail "Non-file tool should exit 0, got $SKIP_EXIT"
fi

# Test 3: Create a temp file with PII and verify it blocks
TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/pii-test-XXXXXX")   # dir template: a suffix after the X's defeats mktemp on macOS
TEMP_PII="$TEMP_DIR/pii-test.csv"
cat > "$TEMP_PII" << 'PIIEOF'
student_id,name,grade,sasid,parent_email
10234,Maria Santos,7,SASID 987654321,ana.santos@gmail.com
10235,James Wilson,8,SASID 123456789,rwilson@yahoo.com
PIIEOF

BLOCK_OUTPUT=$(echo "{\"tool_name\":\"Read\",\"tool_input\":{\"file_path\":\"$TEMP_PII\"}}" | python3 "$DEST/scripts/ferpa-guard.py" 2>/dev/null)
BLOCK_EXIT=$?
rm -rf "$TEMP_DIR"

if [ "$BLOCK_EXIT" = "2" ]; then
    pass "PII file: blocked (exit 2)"
else
    fail "PII file should exit 2, got $BLOCK_EXIT"
fi

# Test 4: Verify the block output is valid JSON with permissionDecision
if echo "$BLOCK_OUTPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['hookSpecificOutput']['permissionDecision']=='deny'" 2>/dev/null; then
    pass "Block output: valid JSON with permissionDecision=deny"
else
    fail "Block output is not valid hook protocol JSON"
fi

# Re-enable exit-on-error
set -e

# ---------------------------------------------------------------
# Done
# ---------------------------------------------------------------
header "Installation complete"
echo ""
echo "  FERPA Guard is installed at: ~/.claude/skills/ferpa-guard/"
echo "  Hook registered in: ~/.claude/settings.json"
echo ""
echo "  It will automatically scan files before Claude reads them."
echo "  To bypass a specific file: export FERPA_GUARD_ALLOW=\"/path/to/file\""
echo ""
echo "  To verify in a Claude session, try reading a CSV with student data."
echo ""
