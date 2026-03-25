# FERPA Guard -- Claude Desktop Setup

## Quick Start (Instructions-Only Mode)

1. Open [claude.ai](https://claude.ai) and create a new Project (or open an existing one)
2. Go to **Project Settings > Custom Instructions**
3. Copy everything below the `---` line in `PROJECT-INSTRUCTIONS.md` and paste it in
4. Start a conversation in that project -- PII protection is now active

## MCP Server Setup (Tool Mode)

The MCP server provides `scan_file` and `redact_file` tools directly in Claude Desktop.

### 1. Install dependencies

```bash
pip install "mcp[cli]"
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
    "ferpa-guard": {
      "command": "python3",
      "args": ["<project-root>/cowork/mcp_server.py"]
    }
  }
}
```

Replace `<project-root>` with the absolute path to your ferpa-guard clone.

The config file location depends on your operating system:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

### 3. Verify

After restarting Claude Desktop, the `scan_file` and `redact_file` tools should appear in your tool list.

## What This Does

Claude will scan any file content, uploads, or pasted data for student PII before processing it. When PII is found, it explains what was detected and offers recovery options (redact, generate synthetic data, column filtering, or confirm safe).

## What This Does NOT Do

- The MCP server provides tools (`scan_file`, `redact_file`) that Claude calls on demand. It does **not** automatically intercept every file read like the Claude Code hook does.
- The user must ask Claude to scan a file, or Claude must decide to use the tool based on context. There is no automatic interception at the transport layer.
- For automatic, programmatic blocking of every file access, use the Claude Code hook instead (see `claude-code/SKILL.md`).

## Disclaimer

FERPA Guard is a detection aid, not a compliance certification. It reduces the risk of accidental PII exposure but cannot guarantee complete protection. Regex-based scanning does not catch all forms of sensitive data (for example, unlabeled student names in free text). Always review data handling practices with your district's legal counsel.

