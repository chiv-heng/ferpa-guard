# FERPA Guard

K-12 AI safety layer that detects student PII in files before an AI tool reads them. For supported tool calls and files, the hook denies access when scanning produces a block-level finding; detection limits, exemptions, and warning-only outcomes still apply. It reduces accidental FERPA/COPPA disclosures across AI tools teachers and school staff already use; it does not establish compliance.

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

**Status as of 2026-09-06.** FERPA Guard is internal infrastructure, not a product (decision 2026-08-05). Multi-surface work is deferred, not scheduled. An admin-managed K12 or Enterprise seat (a district's or charter network's managed Claude tenant, for example) typically has no Claude Code, no Cowork, and no custom MCP, so the `cowork/` surface cannot install there. On such a seat the instruction layer (Project instructions or a Skill, written to the organization's policy, not to the engine's pattern list) is the education tier only; it inspects content the service already holds. Programmatic protection for that seat comes from a local prep tool outside it: Inspect, Transform, Release, where Transform builds a derivative from an approved-column allowlist and only the derivative is pasted or uploaded. Never run the engine inside a Skill's code sandbox: the file has already entered provider infrastructure. Any instruction surface needs an executed eval harness before deployment; none exists yet. Assessments (private Notion workspace): "FERPA Guard: K12 Seat Port Assessment (2026-09-06)" and "FERPA Guard: Codex Adoption Review, Assessment and Phased Plan (2026-09-06)", both under R&D / FERPA Guard -- Project Summary.

**Adoption review, 2026-09-06.** A Codex review for district adoption was verified against the 2026-09-06 `public-release` tip (fail-closed readers plus the docs update above). Finding 1 (failed or partial scans allow) was already closed by the fail-closed readers. Closed by Phase 0 (merged 2026-09-06, follow-ups on `fix/phase0-eval-findings`): native `Grep` gating, compound-command extraction including `case` clauses, block-closing redirects and command substitutions, the xlsx comment hold (the scanner still cannot read comment text; it holds the file instead), redactor comment stripping with verified output and Excel-valid titles, and the README overstatements. Still open: plain rosters and snake_case exports produce no findings (blind spots 1, 2, 4, Phase 1); numeric cells are not redacted by design (the derivative path is the answer); medium severity never blocks (policy floor, Phase 1); extensionless regular files are not gated (V2 criterion 3; symlinks to data files are). Phases 2 and 3 are gated on six scope decisions recorded in Open Brain `ferpa-guard-pilot-scope-decisions-pending`.

## Repo State

As of 2026-09-06 evening, `origin/public-release` carries the reconciled three clone lineages: the Mac Studio's fork merge, JSONL audit, and fail-closed readers; the MacBook's hard-deny commit with its path moved to the `FERPA_GUARD_HARD_DENY` environment variable; and the docs update. Gitignored `.planning/` phases 09 and 10 still exist only on the Studio and are unbacked. Blind spots 1 (snake_case), 2 (columnar headers), and 4 (names, airlock tier) remain open; blind spot 3 (fail-closed readers) shipped 2026-08-07. The MCP test suite passes only on a stale virtualenv; the version pin needs fixing. **Phase 0 of the adoption review is merged into `public-release`** (2026-09-06: compound Bash commands, Grep gating, xlsx comment hold, redactor verification, coverage-boundary docs; spec and Codex round log under `.planning/phases/11-adoption-phase0/`, mirrored on the Studio). Open after the merge: the manual Grep interception smoke test in a live Claude Code session after project-scoped install, and the companion field-test changes in `~/dev/pii-fieldtest`, which are uncommitted there and need a private remote. Next: Phase 1 (snake_case boundary, columnar header binding, per-severity release floor), gated on the six scope decisions in Open Brain `ferpa-guard-pilot-scope-decisions-pending`.

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

When scanning produces a block-level finding, the tool:
1. Denies access to the file/content (medium-severity findings warn and the read proceeds; `FERPA_GUARD_STRICT=1` escalates every finding)
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

Suites: `test_pii_guardian` (pattern detection, file readers, hook protocol, path extraction, should-scan filtering, redactor), `test_integration` (cross-surface parity, installer matcher on fresh install and reinstall), `test_mcp_tools`, `test_failclosed_readers` (unscannable-file blocking: missing dependencies, corrupt/encrypted files, scan limits, cache non-poisoning, formatter truthfulness, scan-report exit contract), `test_hook_boundary` (compound Bash commands, the native Grep tool: output modes, directory deny-and-narrow, the fail-closed existence walk, hard-deny ancestors), `test_xlsx_comments` (comment hold, workbook properties, redactor comment stripping and title validity, poisoned-cache rejection), and `test_david_scenarios` (persona scenarios; see `tests/PERSONA-SCENARIOS.md`).

Acceptance gate for hook and engine changes: `~/dev/pii-fieldtest/harness/compare_matrix.py` against the 2026-09-06 baseline TSVs (no row less protective, no missing required row). The matrix runner's own divergence count is a characterization, not the gate.

## Privacy

- Never use real student data in code, tests, or documentation
- All test data is synthetic
- The redactor uses one-way hashing (not reversible to original values)

## Conventions

- No em dashes in any output
- Commit messages: `feat(scope): description`. Disclose AI assistance via the global CLAUDE.md template (`AI-assisted` / `AI contribution` / `Human review`). No `Co-Authored-By` trailer.
- Plain language in user-facing messages. Save technical terms for developer docs.
