# FERPA Guard

K-12 AI safety layer that detects and blocks student PII before it enters LLM context windows. Protects against accidental FERPA/COPPA violations across AI tools teachers and school staff already use.

## Project Structure

```
ferpa-guard/
  shared/           # Platform-agnostic detection engine and redactor
  claude-code/      # PreToolUse hook for Claude Code users (IT/data staff)
  cowork/           # Project instructions + MCP server for Claude Desktop/Cowork (ops/admin); MCP needs custom-MCP rights
  chat/             # Custom instructions for Claude Chat users (teachers)
  tests/            # Test harness covering all layers
```

## Delivery Surfaces

| Surface | Audience | Mechanism | Status |
|---------|----------|-----------|--------|
| Claude Code | IT/data directors, devs | PreToolUse hook (settings.json) | **Done** (the only programmatic surface) |
| Claude Cowork / Desktop | School ops, admin staff | Project instructions + MCP server | Built, deferred (2026-08-05 reclassification) |
| Claude Chat | Teachers, general staff | Custom instructions / project knowledge | Built, deferred; manual test only (2026-03-25) |
| Claude K12 / Enterprise seat (admin-managed tenant) | Staff on an admin-managed seat | Project instructions + Skill, instruction-only | Assessed 2026-09-06, not built |
| ChatGPT | Teachers | Custom GPT instructions | Future |
| Gemini | Teachers | Gem instructions | Future |
| Copilot | Teachers | System prompt | Future |

**Status as of 2026-09-06.** FERPA Guard is internal infrastructure, not a product (decision 2026-08-05). Multi-surface work is deferred, not scheduled. An admin-managed K12 or Enterprise seat (a district's or charter network's managed Claude tenant, for example) typically has no Claude Code, no Cowork, and no custom MCP, so the `cowork/` surface cannot install there; a port to such a seat is instruction-only (Project instructions or a Skill) and must be written to the organization's policy, not to the engine's pattern list. Never run the engine inside a Skill's code sandbox: the file has already entered provider infrastructure. Any instruction surface needs an executed eval harness before deployment; none exists yet. Assessment (private Notion workspace): "FERPA Guard: K12 Seat Port Assessment (2026-09-06)" under R&D / FERPA Guard -- Project Summary.

## Repo State

As of 2026-09-06 evening, `origin/public-release` is at f2c18a7: the Mac Studio's fork merge, JSONL audit, and fail-closed readers are pushed. Gitignored `.planning/` phases 09 and 10 still exist only on the Studio and are unbacked. One MacBook commit (hard-deny roots for a private data directory) is being reconciled on a branch with the hardcoded home-directory path moved to the `FERPA_GUARD_HARD_DENY` environment variable. Blind spots 1 (snake_case), 2 (columnar headers), and 4 (names, airlock tier) remain open; blind spot 3 (fail-closed readers) shipped 2026-08-07. The MCP test suite passes only on a stale virtualenv; the version pin needs fixing.

## Design Principles

- **Meet users where they are.** No new tools to install. Plug into what they already use.
- **Protect by default.** The safety layer should be on before the user starts, not after they remember.
- **Teach in the moment.** When PII is caught, explain why in plain language. Not compliance jargon.
- **Offer a path forward.** Never just block. Always provide a safe alternative the user can act on immediately.
- **Accommodate all skill levels.** An IT director and a first-year teacher both get protected. The experience adapts to the surface.

## Shared Detection Patterns

All surfaces use the same PII pattern knowledge:
- **Critical:** SSN, SASID, labeled student IDs
- **High:** DOB (with birth-keyword context), lunch PINs, IEP/504 references, discipline records, medical info, parent/guardian contacts
- **Medium:** Email addresses, phone numbers, home addresses

Context-aware gating reduces false positives: education patterns only fire when education keywords are present. DOB only fires near "birth"/"dob"/"born".

## Dependencies

Shared:
- Python 3 (standard library for text files)

Optional (per file type):
- `openpyxl` for .xlsx scanning
- `pymupdf` for .pdf scanning
- `python-docx` for .docx scanning

Readers fail closed: if an optional library is missing, a file is corrupt or
encrypted, or content extends past a scan limit, the file is blocked as
unscannable rather than silently allowed. "Could not check" is never treated
as "clean." The block message names the fix in plain language (install the
library, convert the file, or allowlist a verified-safe path).

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[all]"   # editable install with mcp/xlsx/pdf/docx extras
```

Install as a Claude Code hook (project-scoped recommended):

```bash
./install.sh --project    # registers PreToolUse hook in .claude/settings.local.json
./install.sh              # global (~/.claude/settings.json); merges, never overwrites
```

## Recovery Model

When PII is detected, the tool:
1. Blocks access to the file/content
2. Lists what was found, grouped by severity
3. Offers numbered alternatives appropriate to the surface:
   - Generate synthetic data with the same structure
   - Run the built-in redactor (Claude Code / Cowork)
   - Column-level filtering
   - Allowlist bypass for known-safe templates
4. Waits for the user to choose

## Testing

Each suite is standalone-runnable (no pytest dependency).

```bash
# all suites
for f in tests/test_*.py; do python3 "$f"; done

# a single suite
python3 tests/test_pii_guardian.py
```

Suites: `test_pii_guardian` (pattern detection, file readers, hook protocol, path extraction, should-scan filtering, redactor), `test_integration`, `test_mcp_tools`, `test_failclosed_readers` (unscannable-file blocking: missing dependencies, corrupt/encrypted files, scan limits, cache non-poisoning, formatter truthfulness, scan-report exit contract), and `test_david_scenarios` (persona scenarios; see `tests/PERSONA-SCENARIOS.md`).

## Privacy

- Never use real student data in code, tests, or documentation
- All test data is synthetic
- The redactor uses one-way hashing (not reversible to original values)

## Conventions

- No em dashes in any output
- Commit messages: `feat(scope): description`. Disclose AI assistance via the global CLAUDE.md template (`AI-assisted` / `AI contribution` / `Human review`). No `Co-Authored-By` trailer.
- Plain language in user-facing messages. Save technical terms for developer docs.
