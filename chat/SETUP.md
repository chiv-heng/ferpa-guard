# FERPA Guard -- Chat Setup

## What This Does

Claude will check any data you share for sensitive student information before processing it. When it finds something, it explains what was found and helps you handle it safely. No software to install. Just paste the instructions into a Claude project.

## Quick Start

1. Go to [claude.ai](https://claude.ai) and sign in
2. Click **Projects** in the left sidebar, then **Create a Project**
3. Name the project (for example, "School Work" or "Classroom Helper")
4. Click the project settings icon, then **Set custom instructions**
5. Open the file `CUSTOM-INSTRUCTIONS.md` from this folder, copy everything, and paste it into the custom instructions field
6. Click **Save**
7. Start a conversation inside that project. PII protection is now active.

## What This Does NOT Do

- This is **instruction-based**, not a programmatic block. Claude follows these rules because the instructions tell it to.
- It provides a strong safety layer but is not guaranteed like the Claude Code hook, which blocks at the tool level.
- It works best when teachers are aware it exists and cooperate with the guidance.

## Tips for Teachers

- **Use this project for any work involving student data.** Starting a conversation inside the project activates the protection. Conversations outside the project do not have it.
- **When in doubt, describe what you need instead of pasting actual data.** For example, say "I have a spreadsheet with 30 students, columns for name, grade, and attendance" instead of pasting the spreadsheet.
- **If Claude warns about sensitive data, follow its suggestions.** It will always offer at least two ways to continue safely.
- **Images count too.** If you upload a screenshot of a gradebook or roster, Claude will check for visible student information.
