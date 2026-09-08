# FERPA Guard

K-12 AI safety layer that detects student PII in files before an AI tool reads them and denies the read when scanning produces a block-level finding. It reduces accidental FERPA/COPPA disclosures across AI tools school staff already use. See **Coverage boundary** below for exactly what it gates and what it does not.

## What it does

FERPA Guard is a Python script that runs **before** a covered tool call reads a file. When a user tries to read a file containing student data (roster CSVs, SIS exports, xlsx workbooks), the script intercepts the request and scans it for sensitive patterns using regex-based detection. For supported tool calls and files, the hook denies access when scanning produces a block-level finding. Detection limits, exemptions, and warning-only outcomes still apply. No AI is involved in the scanning. When it denies a read, it offers safe alternatives: synthetic data generation, built-in redaction, or column-level filtering.

## How to use it

The strongest version of FERPA Guard requires [Claude Code](https://docs.anthropic.com/en/docs/claude-code/overview) (Anthropic's developer CLI). If your team is comfortable with command-line tools, start there -- it's the only option that **programmatically denies** a covered read when scanning produces a block-level finding.

Not everyone is comfortable setting up a CLI tool, and that's okay. There are lighter options that work inside the AI tools your staff already use. These are instruction-based -- the AI follows the rules because you asked it to. They check content the AI service has already received, so they are guidance and education, not prevention of disclosure. Still far better than nothing.

| Option | Who it's for | Protection level |
|--------|-------------|-----------------|
| **Claude Code hook** | IT staff, data directors, developers | **Programmatic denial** -- covered reads are denied on block-level findings |
| **Claude Desktop MCP server** | School ops, admin staff | **Tool-level** -- Claude can scan files on demand |
| **Claude project instructions** | Teachers, general staff | **Instruction-based** -- AI follows rules you set |
| **Universal prompt** | Anyone using ChatGPT, Gemini, Copilot, etc. | **Instruction-based** -- paste and go |

All options use the same detection patterns, so the safety rules are consistent everywhere.

## Setup

Choose the option that fits your team:

### Claude Code (IT staff, data directors, developers)

The strongest option. A Python hook runs before every covered file read. For supported tool calls and files, it **denies access when scanning produces a block-level finding**. Detection limits, exemptions, and warning-only outcomes still apply; the Coverage boundary section lists them.

```bash
git clone https://github.com/chiv-heng/ferpa-guard.git
cd ferpa-guard
./install.sh
```

The install script copies the hook to `~/.claude/skills/ferpa-guard/`, registers it in `~/.claude/settings.json`, and runs a self-test. To verify, try reading a CSV with student data in a Claude Code session.

### Claude Desktop (school ops, admin staff)

Two options, depending on your comfort level:

**Option A: MCP server (recommended)** -- Adds `scan_file` and `redact_file` tools directly to Claude Desktop.

1. Clone this repo and install the compatible MCP dependency: `pip install "mcp[cli]>=1.30,<2"`. This adapter uses the official SDK's v1 FastMCP API; SDK v2 requires a separate migration.
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
| Claude Code | Python hook checks covered tool calls before the file is read | Programmatic denial on block-level findings; see Coverage boundary |
| Claude Desktop (MCP) | Tools scan and redact files on demand | Tool-level -- user invokes scan explicitly; nothing intercepts other reads |
| Claude Desktop / Chat (instructions) | Project instructions tell Claude to check for PII | Instruction-based -- checks content the service already received; guidance, not prevention |

## Coverage boundary

The hook is a PreToolUse hook in Claude Code. It can only see the tool calls listed in its matcher (`Read|Bash|Grep`) and can only act on what it can parse.

**Gated**

- `Read` of a file with a scannable extension (csv, tsv, txt, json, jsonl, xml, sql, log, dat, xls, xlsx, pdf, docx, md, html, htm).
- `Bash` commands that read file content (`cat`, `head`, `grep`, `sed`, `awk`, interpreters given a literal data-file operand, and unknown commands), including every part of a compound command such as `ls ; cat roster.csv`. Metadata-only commands (`ls`, `wc`, `stat`, `mv`, `cp`, `tee`) are not scanned.
- `Grep` with `output_mode: "content"` on a single file, scanned like a Read. On a directory it is **denied** unless the directory provably holds no scannable file, the `glob` is exactly one code extension such as `*.py`, or the directory is allowlisted; the default output mode (file names only) and `count` are allowed.
- Command substitutions inside a Bash command (`ls $(cat roster.csv)`) are scanned as commands in their own right, whatever the outer command is, and an input redirection on a loop or block (`done < roster.csv`) is a read.
- Files the scanner cannot read fully (missing library, corrupt, encrypted, past a scan limit, or an xlsx workbook that has cell comments) are held as unscannable, not treated as clean.

**Not gated, by name**

- `Edit` and `Write`. By design: they push content the model already holds, and gating them blocked the guard's own remediation.
- File reads by MCP tools, `WebFetch`, subagents, and worker processes.
- Shell variable indirection (`f=roster.csv; cat "$f"`) and paths built at runtime. Only literal operands are seen.
- Files without a scannable extension, including extensionless copies and `.bak` files.
- Any tool not in the matcher.
- Paths on an allowlist are not scanned at all, and a content-mode Grep over an allowlisted directory is allowed. Directories the scanner exempts by name (`.git`, `node_modules`, `.claude`, `.planning`, `__pycache__`, and the rest of its skip list) are exempt for Grep as well, so keep student data out of them. Medium-severity findings (email, phone, street address) warn and never deny. `FERPA_GUARD_STRICT=1` escalates every finding to a denial.

Treat this list as the control's edge. Anything outside it is covered by policy and training, not by this tool.

## What it detects

**Critical** -- SSN (formatted), state-assigned student IDs (SASID), labeled K-12 identifiers (student_id, sis_id, ps_id, dcid)

**High (education context required)** -- Dates of birth, meal PINs, IEP/504 plan references, disciplinary records, medical information, parent/guardian contact fields

**Medium** -- Email addresses, phone numbers, home/street addresses

IEP, discipline and medical metadata labels also match underscore boundaries, such as `iep_status` and `medication_notes`, when education context is present. Metadata alone retains its warning cap; a value finding in the same file can lift that cap. These labels do not establish that a student record was disclosed.

The metadata vocabulary includes `504` and `sped`, so `section_504` and `sped_status` are detected in education context. These words can also occur in ordinary prose; the context gate and metadata cap reduce that ambiguity but cannot eliminate it when other values co-occur.

CSV, TSV and XLSX scans also bind numeric cells to recognized identifier headers. Only the first logical CSV/TSV record, or the first XLSX row when it passes the existing header heuristic, supplies schema context. Supported aliases are `sasid`, `state_studentnumber`, `student_id`, `pupil_id`, `sis_id`, `ps_id`, `student_number`/`studentNumber`, and `lunch_pin`/`meal_pin`/`cafeteria_pin`. Header lookup ignores ASCII case, spaces, underscores and hyphens. Generic `dcid`, `personID` and `stateID` require an independent student-specific identifier header in the same table or sheet; a school name, teacher field or sheet title is insufficient. `lunch_id`, names and arbitrary prefixed aliases are not supported.

Whole-cell numeric domains are 6-12 digits for state student identifiers, 4-10 for local student identifiers and 4-6 for lunch PINs. XLSX integer and finite integral float cells can qualify; booleans, dates, fractions and formulas without cached values do not. These are limited detection rules, not vendor certification. A header-only file remains metadata. Bound state/local identifiers inherit their existing high-confidence floors; a single lunch PIN retains normal scoring and can warn.

Regex and bound counts are merged by physical occurrence: subtract an overlap only when an actual regex match's numeric tail is contained in the qualifying cell's source interval. Equal text in different cells still counts separately. CSV attribution keeps only the current row's intervals and lazy regex cursors. XLSX attribution temporarily uses at most 50,000 compact interval pairs (800,000 payload bytes) and returns only aggregate counts. It adds a lazy regex pass; performance is not inferred from these memory bounds.

CSV/TSV admission checks quoting and decoded lengths before allocating a parsed row: at most 4,096 columns, 1,000,000 logical records, 65,536 raw header characters and the smaller of 1,048,576 decoded characters per field or the interpreter's existing CSV field limit. The existing 32,000,000-character text limit remains. XLSX preflights worksheet XML before bounded row production, including sparse gaps and missing or understated dimensions: at most 4,096 columns, 1,000,000 visited rectangular cells/rows across sheets, and the existing 50,000 nonempty-cell extraction cap. Malformed, ragged or over-limit structures discard supplemental evidence and hold the file. Existing comment and reader holds remain. These bounds do not cover all ZIP, shared-string or openpyxl allocations.


Context-aware gating reduces false positives: education-specific patterns only fire when education keywords are present. DOB only fires near "birth"/"dob"/"born". This prevents blocking financial spreadsheets and policy documents.

## Recovery model

When scanning produces a block-level finding, the tool:
1. Denies access to the file (medium-severity findings such as email, phone, or street address warn instead and the read proceeds)
2. Lists what was found, grouped by severity and confidence
3. Offers numbered alternatives:
   - **Option 1:** Generate synthetic data with the same structure
   - **Option 2:** Run the built-in redactor to create a safe copy
   - **Option 3:** Column-level filtering (keep only safe columns)
   - **Option 4:** Allowlist bypass (if confirmed no real student data)
4. Waits for the user to choose

## Redaction

The built-in redactor creates `_redacted` copies alongside originals. It preserves file structure and headers, removes every cell comment from xlsx workbooks (and refuses to write output it cannot verify is comment-free), and replaces the values its patterns detect with deterministic hashes.

Redaction is pattern-bound. Values no pattern detects are left as they are: student names, bare numeric IDs, free-text notes, and numeric cells. The output is **pseudonymized, not de-identified**: deterministic hashing keeps rows linkable, which is a re-identification risk under the Department of Education's reasonable-person standard. A `_redacted` filename is not evidence of anything. For work that must not carry student data at all, build a derivative from approved columns instead of redacting a full export.

**Text formats** (csv, tsv, txt, json, jsonl, xml):
```bash
python3 shared/pii_redactor.py /path/to/file.csv
# Output: /path/to/file_redacted.csv
```

**Excel workbooks** (.xlsx):
```bash
python3 shared/pii_redactor.py /path/to/file.xlsx
```

The redactor takes one file per invocation; loop in the shell to redact a folder.

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

Every scan-based decision — blocks, warnings, log notes, denied directory searches, and allowlist bypasses — is recorded as JSON lines in `~/.claude/logs/ferpa-guard-audit.jsonl` as an audit trail. Hard-deny denials are deliberately not recorded, so a protected directory's path never reaches a log. Records carry pattern names and the file path, never the matched values. The path can itself be identifying (an IEP export named after a student), so treat the log as local to the machine.

## Hard-deny directories (optional)

For directories that should be denied whatever they contain, list them in `FERPA_GUARD_HARD_DENY` (separated by `:` on macOS and Linux). For the tool calls the hook sees (Read, Bash, Grep), every operand under those directories, and every Grep scope that contains one of them, is denied before any allowlist, cache, or scan runs, including metadata commands like `ls` and `wc`. Reads by MCP tools, WebFetch, subagents, and worker processes are not gated (see Coverage boundary). The denial message never echoes the path. Edit calls are also denied under these roots when the hook matcher includes Edit (the default installer matcher is Read, Bash, and Grep).

```bash
export FERPA_GUARD_HARD_DENY="$HOME/.local/share/private-control:/srv/protected"
```

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
- The redactor uses one-way hashing (SHA-256, not reversible); this is pseudonymization, not de-identification
- No data is sent to external services. All scanning runs locally.

## Legal context

K-12 education records are protected under FERPA (20 U.S.C. 1232g). FERPA generally requires written consent before disclosing personally identifiable information from education records unless an exception applies. This tool cannot determine whether an exception applies, whether a vendor agreement meets the school-official exception, or whether an output is de-identified. Those are decisions for the district, with counsel. The tool reduces accidental disclosure for the tool paths it covers; it does not establish compliance.

FERPA Guard is about student education records. Staff confidentiality (HR data, evaluations, credentials) is a separate obligation that this engine does not cover.

## Disclaimer

FERPA Guard is a detection aid, not a compliance certification. It reduces the risk of accidental PII exposure but cannot guarantee complete protection. Regex-based scanning does not catch all forms of sensitive data (for example, unlabeled student names in free text). Instruction-based options check content the AI service has already received; they are guidance, not prevention. Always review data handling practices with your district's legal counsel.

## License

MIT
