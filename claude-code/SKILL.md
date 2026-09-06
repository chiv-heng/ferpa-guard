---
name: ferpa-guard
description: PreToolUse hook that scans data files for PII and FERPA-protected fields before Claude processes them. Use when the user says "scan for PII", "check this file for sensitive data", "why was my file blocked", "add a PII pattern", "skip this file for PII", or when working with K-12 data exports, PowerSchool files, or roster CSVs.
---

# /ferpa-guard -- Block PII Before Claude Processes It

PreToolUse hook that scans data files for personally identifiable information
(PII) and protected education fields before Claude reads or processes them.

## How It Works

The hook fires automatically on every **Read**, **Bash**, and **Grep** tool call
(Edit and Write are allow-by-design: they push content the model already holds).
It extracts file paths from the tool input, including every part of a compound
Bash command, scans data files for PII patterns, and **denies the tool call**
when scanning produces a block-level finding. A Grep in `output_mode: "content"`
over a directory is denied unless the directory provably holds no scannable
file or the glob names a single code extension. Files it cannot check fully
(missing library, corrupt, encrypted, past a scan limit, xlsx with cell
comments) are held, not treated as clean. See the README's Coverage boundary
for what is not gated.

The executable script lives at `~/.claude/skills/ferpa-guard/scripts/pii_guardian.py`.
It reads JSON on stdin (Claude Code hooks API) and returns a JSON
`permissionDecision` on stdout.

No configuration needed. It runs silently when files are clean.

## What It Detects

### Critical severity
- **SSN** (formatted as three-two-four digit groups with dashes)
- **State-assigned IDs** (labeled SASID followed by 6-12 digits)
- **Labeled K-12 identifiers** (fields like student_id, sis_id, ps_id, dcid followed by numbers)

### High severity (education context required)
- **Dates of birth** -- only flagged when the file contains birth-related keywords
- **Meal PINs** -- cafeteria access codes
- **Special-ed service plan references** -- individualized learning plans, Section 504 accommodations
- **Behavioral action records** -- removals, incidents, time out of building
- **Health information** -- conditions, treatments, devices, allergic risks
- **Family contact fields** -- caregiver names, emails, phones labeled by relationship

### Medium severity
- **Emails** -- any address matching standard format
- **Phone numbers** -- requires at least one delimiter (dash, space, parens) to avoid false positives on decimal numbers
- **Home/street addresses** -- number + street name + road type

Context-dependent patterns only trigger when the file also contains relevant
keywords. Education-gated patterns need words associated with K-12 contexts.
Birth-date patterns specifically need birth-related keywords nearby. This reduces
false positives on financial spreadsheets and data export timestamps.

## Confidence Scoring

Each finding gets a confidence tier (HIGH, MEDIUM, LOW) based on three signals:

- **Match count** -- 5+ matches of the same pattern scores higher than a single match
- **Co-occurrence** -- Multiple distinct PII types in the same file increases confidence
- **Header position** -- Matches found only in xlsx header rows (row 1) get reduced confidence

Some patterns are always HIGH confidence regardless of scoring:
- Dashed SSNs (XXX-XX-XXXX) are structurally unambiguous
- SASID and labeled student IDs include their own identifying labels

The hook uses a **severity x confidence matrix** to decide what to do:

| Severity / Confidence | HIGH | MEDIUM | LOW |
|----------------------|------|--------|-----|
| Critical | Block | Block | Warn |
| High | Block | Warn | Log |
| Medium | Warn | Log | Log |

- **Block** -- denies the tool call with full recovery instructions (exit code 2)
- **Warn** -- allows the tool call but prints a notice to stderr
- **Log** -- allows silently with a one-line note to stderr

## File Types Scanned

`.csv`, `.tsv`, `.txt`, `.json`, `.jsonl`, `.xml`, `.sql`, `.log`, `.dat`,
`.xls`, `.xlsx`, `.md`, `.html`, `.htm`

**xlsx files** are scanned using openpyxl to extract cell text across all sheets.
This is critical for K-12 contexts where the highest-risk files (routing
trackers, roster exports) are multi-tab Excel workbooks.

Code files (`.py`, `.js`, `.ts`, etc.) are intentionally skipped.

## Dependencies

- **Python 3** (standard library only for text files)
- **openpyxl** (required for `.xlsx` scanning): `pip install openpyxl`

## Directories Skipped

`.git`, `node_modules`, `__pycache__`, `.next`, `.vercel`, `.claude`,
`.planning`, `.backups`

## When It Blocks

The hook outputs a structured denial message with:
1. Which file triggered the block
2. What PII types were found, grouped by severity
3. How many occurrences of each type
4. **Recovery instructions** with numbered options:
   - **Option 1:** Generate a synthetic file with the same column structure but fake values
   - **Option 2:** Run the built-in redactor (`pii_redactor.py`) to create a safe copy with hashed/synthetic replacements. Column headers and structure are preserved. The redactor runs locally and does NOT send data to any AI model.
   - **Option 3:** Ask the user to identify safe columns, then strip everything else
   - **Option 4:** (Critical/high only) Allowlist bypass if the user confirms no real data is present

**Always wait for the user to choose a recovery option before proceeding.**

## Bypassing (When Needed)

If a file is a known-safe false positive (e.g., a template with field labels
but no real data), add its path to the `FERPA_GUARD_ALLOW` environment
variable as a comma-separated list. Supports both exact file paths and
directory prefixes:

```bash
export FERPA_GUARD_ALLOW="/path/to/safe-template.csv,/path/to/clean-folder/"
```

To restore pre-confidence block-everything behavior (any match = block):

```bash
export FERPA_GUARD_STRICT=1
```

## User Commands

| Intent | Action |
|--------|--------|
| "scan this folder for PII" | Run `python3 ~/.claude/skills/ferpa-guard/scripts/pii_scan_report.py "/path/to/folder"` via Bash. Prints a full report of blocked, clean, and skipped files with severity breakdowns and redaction commands. Add `--json` for machine-readable output. |
| "scan this file for PII" | Run the scanner manually via stdin JSON pipe |
| "why was my file blocked?" | Explain the PII output and offer the numbered recovery options |
| "redact this file" | Run `pii_redactor.py` from the shared/ directory on the target file |
| "add a PII pattern" | Edit `PII_PATTERNS` dict in the scanner script |
| "skip this file" | Add path to `FERPA_GUARD_ALLOW` env var |

## Hook Configuration

Registered at user level in `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Read|Bash|Grep",
        "hooks": [
          {
            "type": "command",
            "command": "python3 \"$HOME/.claude/skills/ferpa-guard/scripts/pii_guardian.py\""
          }
        ]
      }
    ]
  }
}
```

## Maintenance

- **Add patterns:** Edit the `PII_PATTERNS` dictionary in the scanner script
- **Per-pattern context:** Set `context_keywords` on a pattern to require specific keywords
- **Default context:** Set `min_context: True` without `context_keywords` to use the default education keyword set
- **Change scanned extensions:** Edit `SCANNABLE_EXTENSIONS` set
- **Performance:** Text files are read whole up to 32 million characters; xlsx files scan up to 50,000 cells; PDFs up to 50 pages. Past a limit, or when a file cannot be read, the file is held as unscannable rather than treated as clean. Adjust constants if needed.

## Legal Context

K-12 education records are protected under FERPA (20 U.S.C. 1232g). FERPA
generally requires written consent before disclosing personally identifiable
information from education records unless an exception applies. This hook
cannot determine whether an exception applies, whether a vendor agreement
meets the school-official exception, or whether an output is de-identified;
those are decisions for the district, with counsel. For supported tool calls
and files, the hook denies access when scanning produces a block-level
finding; detection limits, exemptions, and warning-only outcomes still apply.
Student-record protection is distinct from staff confidentiality (HR data,
credentials), which this hook does not cover.

## Disclaimer

FERPA Guard is a detection aid, not a compliance certification. It reduces the risk of accidental PII exposure but cannot guarantee complete protection. Regex-based scanning does not catch all forms of sensitive data (for example, unlabeled student names in free text). Always review data handling practices with your district's legal counsel.
