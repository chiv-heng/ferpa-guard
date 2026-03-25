# PII Guardian -- Cowork Setup

## Quick Start (Instructions-Only Mode)

1. Open [claude.ai](https://claude.ai) and create a new Project (or open an existing one)
2. Go to **Project Settings > Custom Instructions**
3. Copy everything below the `---` line in `PROJECT-INSTRUCTIONS.md` and paste it in
4. Start a conversation in that project -- PII protection is now active

## MCP Server Setup (Tool Mode)

The MCP server provides `scan_file` and `redact_file` tools directly in Claude Desktop.

### 1. Install dependencies

```bash
pip install mcp
```

Optional (extend file type support):
```bash
pip install openpyxl     # .xlsx scanning and redaction
pip install pymupdf      # .pdf scanning
pip install python-docx  # .docx scanning
```

### 2. Configure Claude Desktop

Add to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "pii-guardian": {
      "command": "python3",
      "args": ["<project-root>/cowork/mcp_server.py"]
    }
  }
}
```

Replace `<project-root>` with the absolute path to your PII-Guardian clone.

### 3. Verify

After restarting Claude Desktop, the `scan_file` and `redact_file` tools should appear in your tool list.

## What This Does

Claude will scan any file content, uploads, or pasted data for student PII before processing it. When PII is found, it explains what was detected and offers recovery options (redact, generate synthetic data, column filtering, or confirm safe).

## What This Does NOT Do

- This is **instruction-based**, not programmatic. Claude follows the rules because the instructions tell it to. There is no hard block like the Claude Code PreToolUse hook.
- It does not intercept file uploads at the transport layer. Claude sees the content and is instructed not to process it further.
- It relies on Claude's compliance with project instructions, which is strong but not guaranteed like a code-level hook.

## For the AFRI Analysis

The redactor lives at:
```
<project-root>/shared/pii_redactor.py
```

For AFRI files that are XLSX (routing tracker), you'll need to:
1. Export the relevant tabs to CSV first (the redactor supports CSV but not XLSX)
2. Run the redactor on the CSV exports
3. Upload the redacted CSVs to the Cowork project

Or: describe the column structure to Claude and have it generate synthetic data with the same shape.

## Limitations (Internal Version)

- XLSX/PDF/DOCX files need manual export to CSV before redaction (unless optional deps installed)
- No automated allowlisting (user confirms verbally if data is safe)
