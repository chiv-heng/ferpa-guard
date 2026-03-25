# FERPA Guard

K-12 AI safety layer that detects and blocks student PII before it enters LLM context windows. Protects against accidental FERPA/COPPA violations across AI tools that school staff already use.

## What it does

FERPA Guard is a Python script that runs **before** the AI model sees anything. When a user tries to read a file containing student data (roster CSVs, SIS exports, xlsx workbooks), the script intercepts the request, scans for sensitive patterns using regex-based detection, and blocks access before the data enters the LLM context window. No AI is involved in the scanning. It then offers safe alternatives: synthetic data generation, built-in redaction, or column-level filtering.

## Delivery surfaces

| Surface | Audience | Mechanism | Status |
|---------|----------|-----------|--------|
| **Claude Code** | IT/data directors, devs | PreToolUse hook (settings.json) | Done |
| **Claude Projects** | School ops, admin staff | MCP server + project instructions | Done |
| **Claude Chat** | Teachers, general staff | Custom instructions / project knowledge | Done |

Each surface uses the same shared detection engine (`shared/pii_engine.py`), so patterns and behavior are consistent everywhere.

## Setup

Choose the surface that matches how your team uses Claude:

### Claude Code (IT staff, data directors, developers)

The strongest protection. A Python hook runs before every file read and **programmatically blocks** access to files with PII. The LLM never sees the data.

```bash
git clone https://github.com/chiv-heng/ferpa-guard.git
cd ferpa-guard
./install.sh
```

The install script copies the hook to `~/.claude/skills/ferpa-guard/`, registers it in `~/.claude/settings.json`, and runs a self-test. To verify, try reading a CSV with student data in a Claude Code session.

### Claude Desktop (school ops, admin staff)

Two options, depending on your comfort level:

**Option A: MCP server (recommended)** -- Adds `scan_file` and `redact_file` tools directly to Claude Desktop.

1. Clone this repo and install the MCP dependency: `pip install "mcp[cli]"`
2. Add to your Claude Desktop config (`claude_desktop_config.json`):
   ```json
   {
     "mcpServers": {
       "ferpa-guard": {
         "command": "python3",
         "args": ["/path/to/ferpa-guard/cowork/mcp_server.py"]
       }
     }
   }
   ```
3. Restart Claude Desktop. The tools appear in your tool list.

**Option B: Project instructions (no install)** -- Copy the contents of `cowork/PROJECT-INSTRUCTIONS.md` into a Claude Desktop Project's custom instructions. This is instruction-based (Claude follows the rules because the instructions tell it to), not a programmatic block.

### Claude Chat (teachers, general staff)

No software to install. Paste instructions into a Claude project:

1. Go to [claude.ai](https://claude.ai) > **Projects** > **Create a Project**
2. Open `chat/CUSTOM-INSTRUCTIONS.md` from this repo, copy everything
3. Paste into the project's custom instructions and save

Any conversation started inside that project has PII protection active. Conversations outside it do not.

### Any other AI tool (ChatGPT, Gemini, Copilot, etc.)

Open `UNIVERSAL-INSTRUCTIONS.md` from this repo, copy the prompt, and paste it into your AI tool's custom instructions or system prompt. Works with any LLM that supports custom instructions. This is instruction-based (the AI follows the rules because you asked it to), not a programmatic block.

### Protection strength by surface

| Surface | Mechanism | Strength |
|---------|-----------|----------|
| Claude Code | Python hook blocks tool calls before the LLM sees the file | Hard block -- data never enters context |
| Claude Desktop (MCP) | Tools scan and redact files on demand | Tool-level -- user invokes scan explicitly |
| Claude Desktop / Chat (instructions) | Project instructions tell Claude to check for PII | Instruction-based -- strong but not guaranteed |

## What it detects

**Critical** -- SSN (formatted), state-assigned student IDs (SASID), labeled K-12 identifiers (student_id, sis_id, ps_id, dcid)

**High (education context required)** -- Dates of birth, meal PINs, IEP/504 plan references, disciplinary records, medical information, parent/guardian contact fields

**Medium** -- Email addresses, phone numbers, home/street addresses

Context-aware gating reduces false positives: education-specific patterns only fire when education keywords are present. DOB only fires near "birth"/"dob"/"born". This prevents blocking financial spreadsheets and policy documents.

## Recovery model

When PII is detected, the tool:
1. Blocks access to the file
2. Lists what was found, grouped by severity and confidence
3. Offers numbered alternatives:
   - **Option 1:** Generate synthetic data with the same structure
   - **Option 2:** Run the built-in redactor to create a safe copy
   - **Option 3:** Column-level filtering (keep only safe columns)
   - **Option 4:** Allowlist bypass (if confirmed no real student data)
4. Waits for the user to choose

## Redaction

The built-in redactor creates `_redacted` copies alongside originals. It uses deterministic hashing (not reversible to original values) and preserves file structure and headers.

**Text formats** (csv, tsv, txt, json, jsonl, xml):
```bash
python3 shared/pii_redactor.py /path/to/file.csv
# Output: /path/to/file_redacted.csv
```

**Excel workbooks** (.xlsx):
```bash
python3 shared/pii_redactor.py /path/to/file.xlsx
# Or redact all xlsx files in a folder:
python3 shared/pii_redactor.py /path/to/folder/
```

## Batch scanning

Scan an entire directory and generate a report:

```bash
python3 claude-code/pii_scan_report.py /path/to/folder
python3 claude-code/pii_scan_report.py /path/to/folder --json  # machine-readable
```

## Bypassing (when needed)

For known-safe false positives (templates, test data):

**Environment variable:**
```bash
export FERPA_GUARD_ALLOW="/path/to/safe-template.csv,/path/to/other.json"
```

**Allowlist file** (`~/.claude/ferpa-guard-allow.txt`):
```
# One path per line
/path/to/safe-template.csv
/path/to/test-data/
```

All bypasses are logged to `~/.claude/ferpa-guard-audit.log` for FERPA compliance.

## Project structure

```
ferpa-guard/
  shared/             # Platform-agnostic detection engine and redactor
    pii_engine.py     # Patterns, readers, scanning, confidence scoring
    pii_redactor.py   # Cell-level redaction for text and xlsx files
  claude-code/        # PreToolUse hook for Claude Code
    pii_guardian.py   # Hook entry point (reads stdin, outputs JSON)
    pii_scan_report.py# Batch directory scanner
    SKILL.md          # Claude Code skill documentation
  chat/               # Custom instructions for Claude Chat
  cowork/             # MCP server for Claude Projects
  tests/              # Test suite (111 tests across 9 layers)
  install.sh          # One-command installer for Claude Code
```

## Dependencies

**Required:** Python 3.10+

**Optional (per file type):**
- `openpyxl` for .xlsx scanning and redaction: `pip install openpyxl`
- `pymupdf` for .pdf scanning: `pip install pymupdf`
- `python-docx` for .docx scanning: `pip install python-docx`

All optional dependencies degrade gracefully. If not installed, those file types are skipped.

## Testing

```bash
python3 -m pytest tests/
# Or run directly:
python3 tests/test_pii_guardian.py
```

111 tests across 9 layers: pattern detection, file readers, hook protocol, path extraction, should-scan filtering, redactor (text, CSV, XLSX, JSON), confidence scoring, XLSX header awareness, and decision matrix.

## Strict mode

To block on any PII finding regardless of confidence scoring:

```bash
export FERPA_GUARD_STRICT=1
```

## Privacy

- Never uses real student data in code, tests, or documentation
- All test data is synthetic
- The redactor uses one-way hashing (SHA-256, not reversible)
- No data is sent to external services. All scanning runs locally.

## Legal context

K-12 education records are protected under FERPA (20 U.S.C. 1232g). Disclosure requires written consent from the family or eligible student. This tool helps enforce that boundary by catching PII before it enters AI context windows.

## Disclaimer

FERPA Guard is a detection aid, not a compliance certification. It reduces the risk of accidental PII exposure but cannot guarantee complete protection. Regex-based scanning does not catch all forms of sensitive data (for example, unlabeled student names in free text). Always review data handling practices with your district's legal counsel.

## License

MIT
