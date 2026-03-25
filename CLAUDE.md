# FERPA Guard

K-12 AI safety layer that detects and blocks student PII before it enters LLM context windows. Protects against accidental FERPA/COPPA violations across AI tools teachers and school staff already use.

## Project Structure

```
ferpa-guard/
  shared/           # Platform-agnostic detection engine and redactor
  claude-code/      # PreToolUse hook for Claude Code users (IT/data staff)
  cowork/           # Project config + MCP server for Claude Cowork users (ops/admin)
  chat/             # Custom instructions for Claude Chat users (teachers)
  tests/            # Test harness covering all layers
```

## Delivery Surfaces

| Surface | Audience | Mechanism | Status |
|---------|----------|-----------|--------|
| Claude Code | IT/data directors, devs | PreToolUse hook (settings.json) | **Done** |
| Claude Cowork | School ops, admin staff | Project instructions + MCP server | Planned |
| Claude Chat | Teachers, general staff | Custom instructions / project knowledge | Planned |
| ChatGPT | Teachers | Custom GPT instructions | Future |
| Gemini | Teachers | Gem instructions | Future |
| Copilot | Teachers | System prompt | Future |

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

```bash
python3 tests/test_pii_guardian.py
```

76 tests across 6 layers: pattern detection, file readers, hook protocol, path extraction, should-scan filtering, and redactor.

## Privacy

- Never use real student data in code, tests, or documentation
- All test data is synthetic
- The redactor uses one-way hashing (not reversible to original values)

## Conventions

- No em dashes in any output
- Commit messages: `feat(scope): description` with `Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>`
- Plain language in user-facing messages. Save technical terms for developer docs.
