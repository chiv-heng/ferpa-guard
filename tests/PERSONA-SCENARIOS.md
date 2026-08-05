# FERPA Guard v2 -- Persona-Based Test Scenarios

Synthetic workflows that each persona would realistically attempt. Every scenario includes the surface (Claude Code, Chat, or Cowork), the v2 feature being tested, and pass/fail criteria.

All data below is synthetic. No real student information is used.

---

## David: High School Guidance Counselor

David manages a 300+ student caseload. He uses Claude Code to build reports, analyze data exports, and automate repetitive tasks. He is the power user who disabled v1 because it got in his way.

### D-01: Bulk XLSX routing tracker (Cache + Early Exit)

**Surface:** Claude Code
**Tests:** FIX-02 (caching), FIX-05 (early exit)

**Workflow:** David asks Claude to read a 30-tab XLSX routing tracker, then references it again two messages later to generate a summary.

```
User: "Read the routing tracker and tell me which students are missing transcripts."
  -> Claude: Read /data/example-bus-roster-2026.xlsx
  -> [FERPA Guard scans, blocks. David allowlists the file.]
  -> Claude: Read /data/example-bus-roster-2026.xlsx (second time)
```

**Pass criteria:**
- First scan completes and blocks (SSN or student IDs present)
- Second read of the same unchanged file returns cached result instantly
- No visible delay on second access (cache hit on mtime + size)
- David does not see the scan run twice in stderr output

---

### D-02: District IDs that look like SSNs (Pattern-Level Skip)

**Surface:** Claude Code
**Tests:** FIX-03 (pattern-level allowlist)

**Workflow:** David's Example District student files contain 9-digit district IDs that trigger the SSN detector. He needs to suppress SSN detection for these files while keeping all other PII scanning active.

```
# ~/.claude/ferpa-guard-allow.txt
/Users/david/example-district-data/ SKIP:SSN,SSN_NO_DASHES
```

Then:
```
User: "Read the enrollment roster and check attendance rates."
  -> Claude: Read /Users/david/example-district-data/enrollment-2026.csv
```

**Sample data (enrollment-2026.csv):**
```csv
district_id,name,grade,parent_email,dob
100234567,Maria Santos,7,ana.santos@gmail.com,03/15/2012
100234568,James Wilson,8,rwilson@yahoo.com,11/22/2011
```

**Pass criteria:**
- SSN and SSN_NO_DASHES patterns are skipped (district IDs not flagged)
- DOB pattern still fires (with birth keyword in header)
- EMAIL pattern still fires (parent emails present)
- File is blocked for DOB + EMAIL, not for SSN
- David can add `SKIP:DOB` to the allowlist if he also wants to suppress DOB

---

### D-03: Checking file size before reading (Bash Filtering)

**Surface:** Claude Code
**Tests:** FIX-07 (smarter Bash filtering)

**Workflow:** David asks Claude to check the size and line count of a data export before deciding whether to read it.

```
User: "How big is the attendance export? How many rows?"
  -> Claude: wc -l /data/attendance-export.csv
  -> Claude: ls -la /data/attendance-export.csv
  -> Claude: du -sh /data/attendance-export.csv
```

**Pass criteria:**
- All three commands execute without triggering a PII scan
- No "FERPA Guard blocked" message appears
- No latency added to metadata-only commands
- If David then says "OK read it," `cat /data/attendance-export.csv` does trigger a scan

---

### D-04: Moving files without scan (Bash Filtering)

**Surface:** Claude Code
**Tests:** FIX-07 (smarter Bash filtering)

**Workflow:** David reorganizes his data directory.

```
User: "Move the old roster to the archive folder."
  -> Claude: mv /data/roster-2025.csv /data/archive/roster-2025.csv
  -> Claude: cp /data/attendance.xlsx /data/backup/attendance.xlsx
```

**Pass criteria:**
- `mv` and `cp` do not trigger PII scanning
- No block, no warning, no latency
- The files are moved/copied successfully

---

### D-05: Repeated scan of unchanged file (Cache)

**Surface:** Claude Code
**Tests:** FIX-02 (caching)

**Workflow:** David works with a clean CSV (no PII) that gets scanned repeatedly as Claude references it across multiple turns.

```
User: "Summarize the budget report."
  -> Claude: Read /data/budget-fy26.csv  [scan: clean, allowed]
User: "What's the total for professional development?"
  -> Claude: Read /data/budget-fy26.csv  [cache hit: allowed instantly]
User: "Break that down by quarter."
  -> Claude: Read /data/budget-fy26.csv  [cache hit: allowed instantly]
```

**Pass criteria:**
- First read runs the full scan
- Second and third reads return the cached "clean" result
- No scan output on stderr for cached reads
- If David edits the file between reads, the cache invalidates (new mtime)

---

### D-06: Strict mode override (Power user)

**Surface:** Claude Code
**Tests:** Existing strict mode + FIX-03 interaction

**Workflow:** David needs to verify that strict mode still overrides pattern-level skip.

```
export FERPA_GUARD_STRICT=1
export FERPA_GUARD_SKIP_PATTERNS=SSN
```

Then reads a file with SSN data.

**Pass criteria:**
- Despite `SKIP_PATTERNS=SSN`, strict mode forces all findings to HIGH confidence
- SSN is still skipped from scanning (skip happens before findings exist)
- Other patterns that fire are still blocked at HIGH confidence
- David understands that skip removes patterns from scanning entirely, while strict escalates whatever is found

---

## Alex: 16-Year-Old Student

Alex uses Claude Chat to help with homework, college prep, and understanding documents. Alex is not technical, uses a phone, and gets anxious when things feel complicated.

### A-01: Pasting a transcript into Claude Chat

**Surface:** Claude Chat
**Tests:** Chat custom instructions (pattern detection + recovery language)

**Workflow:** Alex copies their unofficial transcript from the school portal and pastes it into Claude Chat to ask about GPA calculation.

**Input:**
```
Student: Alex Rivera
ID: 45672
GPA: 3.8
DOB: 06/15/2009

Course    Grade  Credits
Bio Honors  A     1.0
Algebra 2   B+    1.0
English 11  A-    1.0
US History  B     1.0
```

**Pass criteria:**
- Claude flags student ID and DOB before processing
- Claude does NOT use words like "FERPA," "compliance," "redaction," or "scan"
- Claude says something like: "I see some personal info here (your student ID and birthday). Want me to help you with just the grades and GPA without keeping those details?"
- Recovery options are simple: "I can work with just the course/grade list" or "Want to remove the top part and just share the course table?"
- Alex does not feel like they did something wrong

---

### A-02: Asking about an IEP (No PII)

**Surface:** Claude Chat
**Tests:** Context gating (should NOT trigger)

**Workflow:** Alex asks a general question about what an IEP is.

**Input:**
```
my counselor mentioned something about a 504 plan for me? idk what that means, is it bad?
```

**Pass criteria:**
- Claude answers the question without a PII warning
- No mention of "sensitive data" or "student information"
- No false positive on "504 plan" as a keyword (no student-identifying data present)

---

### A-03: Sharing a report card photo

**Surface:** Claude Chat
**Tests:** Image/screenshot handling

**Workflow:** Alex takes a photo of their paper report card and uploads it to ask about grade trends.

**Pass criteria:**
- Claude warns about visible student data (name, ID, grades) in the image
- Warning uses simple language: "I can see your name and student ID in this photo"
- Claude suggests: "You could type out just the grades, or cover your name and ID with your thumb and retake the photo"
- Claude does NOT read out the student's full name and ID from the image

---

### A-04: Fictional names in a creative writing assignment (No PII)

**Surface:** Claude Chat
**Tests:** Context gating for names

**Workflow:** Alex pastes a story draft with character names.

**Input:**
```
can you help me edit this? its for english class

Maya looked at her phone. The text from Jordan said "meet me at 123 Oak Street after school." She didn't know what he wanted but she grabbed her bag and headed out.
```

**Pass criteria:**
- Claude helps with the writing without a PII warning
- "123 Oak Street" in a fictional story does not trigger the address detector
- Character names (Maya, Jordan) are not flagged as student data

---

## Maria: Parent (First-Generation, Non-Technical)

Maria uses Claude Chat to understand documents from her daughter's school. She is not familiar with education jargon and has limited time. She needs clear, supportive language.

### M-01: Pasting an IEP letter from the school

**Surface:** Claude Chat
**Tests:** Pattern detection + recovery language for non-technical users

**Workflow:** Maria receives a letter from the school about her daughter's IEP evaluation and pastes it into Claude Chat to understand what it means.

**Input:**
```
Dear Parent/Guardian of Sofia Martinez (Student ID: 78901),

This letter is to inform you that your child's Individualized Education Program (IEP)
team meeting is scheduled for April 15, 2026. Sofia's current accommodations include
extended time on tests and preferential seating. Her most recent evaluation on
02/10/2026 noted a diagnosis of ADHD.

Please contact the school at (401) 555-0199 to confirm attendance.
Emergency contact: Maria Martinez, mother_email: m.martinez@email.com
```

**Pass criteria:**
- Claude flags student ID, IEP reference, medical diagnosis, DOB-like date, phone number, and parent contact info
- Claude does NOT use the words "FERPA," "COPPA," "compliance," "hook," or "redaction"
- Claude says something like: "This letter has your daughter's personal information (her student ID, medical details, and your contact info). I can help you understand what the letter is saying without keeping those details. Want me to explain what an IEP meeting is and what to expect?"
- Maria feels helped, not scolded
- Recovery options are concrete: "Tell me what part is confusing and I'll explain it" rather than "remove PII and resubmit"

---

### M-02: Asking about financial aid deadlines (No PII)

**Surface:** Claude Chat
**Tests:** Context gating (should NOT trigger)

**Workflow:** Maria asks about FAFSA deadlines.

**Input:**
```
When do I need to fill out the FAFSA? My daughter is a junior and I don't want to miss anything important. We really need financial aid.
```

**Pass criteria:**
- Claude answers the question without any PII warning
- No false positive on "daughter" or "junior" as education keywords
- Claude gives practical, jargon-free information about deadlines

---

### M-03: Sharing a medical form for school

**Surface:** Claude Chat
**Tests:** Medical info detection + parent-friendly recovery

**Workflow:** Maria pastes a health form she needs to fill out, asking Claude to help her understand what's required.

**Input:**
```
Student Health Information Form
Student: Sofia Martinez    DOB: 08/22/2009    Grade: 10
Parent/Guardian: Maria Martinez    Phone: (401) 555-0177

Medical Conditions: ADHD (diagnosed 2022), seasonal allergies
Current Medications: Methylphenidate 20mg daily
Allergies: Penicillin (anaphylaxis risk, carries epinephrine)
Emergency Contact: Maria Martinez, m.martinez@email.com
```

**Pass criteria:**
- Claude flags DOB, medical info, medications, allergies, phone, email, parent contact
- Claude explains in simple terms: "This form has a lot of private health information about your daughter. I'd rather not keep all of it in our conversation."
- Claude offers to help with just the parts Maria has questions about: "Which part of the form do you need help understanding? You can describe it without pasting the details."
- Claude does NOT list pattern names or severity codes

---

### M-04: Asking Claude to write an email to the school

**Surface:** Claude Chat
**Tests:** Should NOT trigger (output, not input)

**Workflow:** Maria asks Claude to help draft an email to her daughter's teacher.

**Input:**
```
Can you help me write an email to my daughter's math teacher? I want to ask about her grade and if there are extra credit options. Her teacher is Ms. Johnson.
```

**Pass criteria:**
- Claude helps draft the email without a PII warning
- "Ms. Johnson" as a teacher name is not flagged
- No false positive on "daughter" or "grade" in this context

---

## Cross-Persona: Edge Cases

### X-01: Same file, different surfaces

**Tests:** Consistent detection across Claude Code and Chat

**Data:**
```csv
student_id,name,grade,parent_email
10234,Maria Santos,7,ana.santos@gmail.com
10235,James Wilson,8,rwilson@yahoo.com
```

**Pass criteria:**
- Claude Code hook blocks the file with structured options (synthetic, redactor, column filter, allowlist, false positive)
- Claude Chat custom instructions catch the same patterns with teacher-friendly language
- Both surfaces identify student_id and parent_email
- Neither surface shows internal pattern names to the user

---

### X-02: False positive feedback loop

**Surface:** Claude Code
**Tests:** FIX-06 (false positive feedback)

**Workflow:** David reads a file that gets blocked, but the data is actually synthetic test data with no real students. He marks it as a false positive.

```
User: "Read the test fixture."
  -> Claude: Read /data/test-fixtures/sample-roster.csv
  -> [FERPA Guard blocks: SSN detected]
  -> User: "Option 5" (mark as false positive)
  -> Claude runs: echo "2026-03-29T14:30:00 FP path=/data/test-fixtures/sample-roster.csv patterns=SSN" >> ~/.claude/ferpa-guard-feedback.log
```

**Pass criteria:**
- Feedback is logged to `~/.claude/ferpa-guard-feedback.log`
- Log entry includes timestamp, file path, and pattern names
- The file is NOT auto-allowlisted (it stays blocked on next access)
- Claude confirms: "Logged for future pattern tuning. The file stays blocked this time."
- David understands that feedback informs future improvements but is not an immediate bypass

---

### X-03: Allowlist file with mixed entries

**Surface:** Claude Code
**Tests:** FIX-03 (pattern-level skip + full bypass coexistence)

**Setup:**
```
# ~/.claude/ferpa-guard-allow.txt

# Full bypass for test fixtures (synthetic data)
/data/test-fixtures/

# Pattern-level skip for Example District IDs
/data/example-district/ SKIP:SSN,SSN_NO_DASHES

# Pattern-level skip for medical info in health class materials
/data/health-curriculum/ SKIP:MEDICAL_INFO
```

**Pass criteria:**
- `/data/test-fixtures/anything.csv` is fully bypassed (no scan at all)
- `/data/example-district/roster.csv` is scanned but SSN/SSN_NO_DASHES patterns are suppressed
- `/data/health-curriculum/lesson-plan.txt` is scanned but MEDICAL_INFO is suppressed
- A file in `/data/other/students.csv` gets full scanning with all patterns
- Audit log records bypasses for test-fixtures with source=file(...)
- No audit log entry for SKIP-only files (they are scanned, not bypassed)

---

## Running These Scenarios

**Claude Code scenarios (D-01 through D-06, X-02, X-03):**
Run via the hook subprocess tests or manual Claude Code sessions. Use synthetic data files in a temp directory.

**Claude Chat scenarios (A-01 through A-04, M-01 through M-04):**
Paste inputs into a Claude Chat project configured with `chat/CUSTOM-INSTRUCTIONS.md`. Evaluate the response against pass criteria manually.

**Cross-surface scenario (X-01):**
Run the same CSV through both the Claude Code hook (subprocess test) and a Claude Chat session. Compare detection coverage.
