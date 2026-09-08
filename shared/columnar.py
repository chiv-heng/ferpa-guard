"""Bounded structural evidence for numeric student identifiers.

No values or raw headers leave this module: evidence is pattern-name counts.
CSV rows are admitted before parser allocation; XLSX rows require XML preflight.
"""
from array import array
from dataclasses import dataclass
import csv
import io
import math
import re
from xml.parsers import expat

MAX_COLUMNS = 4096
MAX_RECORDS = 1_000_000
MAX_HEADER_CHARS = 65_536
MAX_FIELD_CHARS = 1_048_576
MAX_VISITED_CELLS = 1_000_000
MAX_VISITED_ROWS = 1_000_000


class ColumnarError(ValueError):
    """Structural failure. Never include source text in this exception."""


def _invalid():
    raise ColumnarError('Table structure could not be checked completely')


# Provenance and deliberately limited numeric domains are documented in README.
_SPECIFIC = {
    'sasid': 'SASID', 'statestudentnumber': 'SASID',
    'studentid': 'STUDENT_ID_LABELED', 'pupilid': 'STUDENT_ID_LABELED',
    'sisid': 'STUDENT_ID_LABELED', 'psid': 'STUDENT_ID_LABELED',
    'studentnumber': 'STUDENT_ID_LABELED',
    'lunchpin': 'LUNCH_PIN', 'mealpin': 'LUNCH_PIN', 'cafeteriapin': 'LUNCH_PIN',
}
_GENERIC = {'dcid': 'STUDENT_ID_LABELED', 'personid': 'STUDENT_ID_LABELED', 'stateid': 'SASID'}
_STUDENT_CONTEXT = {key for key, value in _SPECIFIC.items() if value != 'LUNCH_PIN'}
_VALIDATORS = {'SASID': re.compile(r'\d{6,12}'), 'STUDENT_ID_LABELED': re.compile(r'\d{4,10}'), 'LUNCH_PIN': re.compile(r'\d{4,6}')}
_ASCII_CASE = str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')


def bindings(header):
    if len(header) > MAX_COLUMNS:
        _invalid()
    names = [re.sub(r'[ _-]', '', str(cell).strip().translate(_ASCII_CASE)) if cell is not None else '' for cell in header]
    student = any(name in _STUDENT_CONTEXT for name in names)
    return {index: _SPECIFIC[name] if name in _SPECIFIC else _GENERIC[name]
            for index, name in enumerate(names)
            if name in _SPECIFIC or (student and name in _GENERIC)}


DIGIT_WIDTHS = {'SASID': 12, 'STUDENT_ID_LABELED': 10, 'LUNCH_PIN': 6}


@dataclass(frozen=True)
class BoundEvidence:
    """Only per-pattern aggregate counts cross the reader boundary."""
    bound_count: int
    regex_overlap_count: int


def qualifying(pattern, cell, *, rendered=None):
    if isinstance(cell, bool):
        return False
    if isinstance(cell, float):
        if not math.isfinite(cell) or not cell.is_integer():
            return False
        cell = int(cell)
        rendered = str(cell)  # Canonical integer validation, not output rendering.
    if not isinstance(cell, (str, int)):
        return False
    text = str(cell) if rendered is None else rendered
    return bool(_VALIDATORS[pattern].fullmatch(text.strip()))


def numeric_tail(content, match, maximum):
    """Terminal Unicode decimal run of an actual, unchanged identifier match.

    The three supported patterns end in their identifier digits. Inspect no
    more than the pattern's maximum width, never a reconstructed alias regex.
    """
    end = match.end()
    start = end
    if not 0 <= match.start() < end <= len(content):
        _invalid()
    while start > match.start() and end - start < maximum and content[start-1].isdecimal():
        start -= 1
    if start == end:
        _invalid()
    return start, end


class TailCursor:
    """One pending numeric tail; no match list or file-wide span collection."""
    def __init__(self, content, pattern, maximum):
        self.content = content
        self.matches = iter(pattern.finditer(content))
        self.maximum = maximum
        self.pending = None
        self.exhausted = False
        self.previous_end = 0

    def _next(self):
        match = next(self.matches, None)
        self.pending = None if match is None else numeric_tail(self.content, match, self.maximum)
        self.exhausted = match is None

    def accept(self, start, end):
        if (type(start) is not int or type(end) is not int
                or not self.previous_end <= start < end <= len(self.content)):
            _invalid()
        self.previous_end = end
        if self.pending is None and not self.exhausted:
            self._next()
        while self.pending is not None:
            tail_start, tail_end = self.pending
            if tail_end > end:
                return 0  # A later or crossing tail stays pending.
            self.pending = None
            if start <= tail_start and tail_end <= end:
                # Consume exactly this occurrence. Advance lazily at next cell.
                return 1
            self._next()
        return 0


def _cursors(content, patterns):
    return {name: TailCursor(content, pattern, DIGIT_WIDTHS[name])
            for name, pattern in patterns.items() if name in DIGIT_WIDTHS}


class IntervalStore:
    """XLSX-only compact temporary intervals, capped before every append."""
    def __init__(self, limit):
        self.limit = min(limit, 50_000)
        self.intervals = {}
        self.count = 0
        self.previous_end = 0

    @property
    def payload_bytes(self):
        return sum(len(offsets) * offsets.itemsize for offsets in self.intervals.values())

    def add(self, name, start, end):
        if (name not in DIGIT_WIDTHS or self.count >= self.limit
                or type(start) is not int or type(end) is not int
                or not self.previous_end <= start < end < (1 << 64)):
            _invalid()
        offsets = self.intervals.setdefault(name, array('Q'))
        if offsets.itemsize != 8:
            _invalid()
        offsets.extend((start, end))
        self.count += 1
        self.previous_end = end

    def clear(self):
        self.intervals.clear()
        self.count = 0

    def reduce(self, content, patterns):
        evidence = {}
        try:
            for name, offsets in self.intervals.items():
                cursor = TailCursor(content, patterns[name], DIGIT_WIDTHS[name])
                overlaps = 0
                for i in range(0, len(offsets), 2):
                    overlaps += cursor.accept(offsets[i], offsets[i+1])
                evidence[name] = BoundEvidence(len(offsets)//2, overlaps)
            return evidence
        finally:
            self.clear()


def _copy_record(content, start, end):
    """Allocation seam, invoked only after the complete record is admitted."""
    return content[start:end]


def _parse_record(content, start, end, delimiter):
    data = _copy_record(content, start, end)
    reader = csv.reader(io.StringIO(data, newline=''), delimiter=delimiter,
                        quotechar='"', doublequote=True, escapechar=None,
                        skipinitialspace=False, strict=True)
    row = next(reader)
    if next(reader, None) is not None:
        _invalid()
    return row


def _field_spans():
    """Allocation seam for proving each prior record trace is released."""
    return []


def validated_rows(content, delimiter, *, with_spans=False):
    """Yield authoritative rows after bounded syntax/decoded-length admission.

    Ordinary character runs are counted without slicing. Regex searches are
    restricted to the remaining budget plus one character, so an excessive
    field/header cannot cause a scan to the distant end of the record.
    """
    if delimiter not in (',', '\t'):
        _invalid()
    field_limit = min(MAX_FIELD_CHARS, csv.field_size_limit())
    if field_limit <= 0:
        _invalid()
    n = len(content)
    index = 1 if content.startswith('\ufeff') else 0
    record = 0
    special = re.compile('[' + re.escape(delimiter) + '"\r\n\ufffd]')
    while index < n:
        record += 1
        if record > MAX_RECORDS:
            _invalid()
        start = index
        raw_start = 0 if record == 1 else start
        state = 'start'
        lengths = []
        spans = _field_spans()
        field_start = index
        decoded = 0
        active = False
        while True:
            if index >= n:
                if state == 'quoted':
                    _invalid()
                if active:
                    lengths.append(decoded)
                    spans.append((field_start, index))
                end = index
                break
            ch = content[index]
            if ch == '\ufffd':
                _invalid()
            terminator = ch in '\r\n' and state != 'quoted'
            if terminator:
                if active:
                    lengths.append(decoded)
                    spans.append((field_start, index))
                end = index + (2 if ch == '\r' and index + 1 < n and content[index+1] == '\n' else 1)
                index = end
                break
            if record == 1 and index - raw_start >= MAX_HEADER_CHARS:
                _invalid()
            if state == 'after':
                if ch == '"':
                    decoded += 1
                    state = 'quoted'
                elif ch == delimiter:
                    if len(lengths) + 1 >= MAX_COLUMNS:
                        _invalid()
                    lengths.append(decoded)
                    spans.append((field_start, index))
                    field_start = index + 1
                    decoded = 0
                    state = 'start'
                else:
                    _invalid()
                active = True
                index += 1
            elif state == 'quoted':
                if ch == '"':
                    state = 'after'
                    index += 1
                elif ch in (delimiter, '\r', '\n'):
                    decoded += 1
                    index += 1
                else:
                    # Count an ordinary run without constructing its text.
                    stop = min(n, index + field_limit - decoded + 1)
                    if record == 1:
                        stop = min(stop, raw_start + MAX_HEADER_CHARS + 1)
                    match = special.search(content, index, stop)
                    end_run = match.start() if match else stop
                    decoded += end_run - index
                    index = end_run
            elif ch == delimiter:
                if len(lengths) + 1 >= MAX_COLUMNS:
                    _invalid()
                lengths.append(decoded)
                spans.append((field_start, index))
                field_start = index + 1
                decoded = 0
                active = True
                state = 'start'
                index += 1
            elif ch == '"':
                active = True
                if state == 'start':
                    state = 'quoted'
                else:
                    decoded += 1  # A quote in an unquoted field is literal.
                index += 1
            else:
                active = True
                state = 'unquoted'
                stop = min(n, index + field_limit - decoded + 1)
                if record == 1:
                    stop = min(stop, raw_start + MAX_HEADER_CHARS + 1)
                match = special.search(content, index, stop)
                end_run = match.start() if match else stop
                decoded += end_run - index
                index = end_run
            if decoded > field_limit or (record == 1 and index - raw_start > MAX_HEADER_CHARS):
                _invalid()
        try:
            row = _parse_record(content, start, end, delimiter)
        except (csv.Error, StopIteration):
            _invalid()
        if len(row) != len(lengths) or any(len(cell) != size for cell, size in zip(row, lengths)):
            _invalid()
        yield (row, spans) if with_spans else row
        del row, spans, lengths


def csv_evidence(content, delimiter, patterns=None):
    rows = validated_rows(content, delimiter, with_spans=True)
    admitted = next(rows, None)
    if admitted is None:
        return {}
    header, spans = admitted
    mapping = bindings(header)
    width = len(header)
    del admitted, header, spans
    cursors = _cursors(content, patterns or {})
    totals = {}
    for row, spans in rows:
        if len(row) != width:
            _invalid()
        for index, pattern in mapping.items():
            if qualifying(pattern, row[index]):
                if pattern not in cursors:
                    _invalid()
                overlap = cursors[pattern].accept(*spans[index])
                bound, shared = totals.get(pattern, (0, 0))
                totals[pattern] = (bound + 1, shared + overlap)
        # Neither the consumer nor generator retains the previous record
        # while the next one is admitted and copied.
        del row, spans
    return {name: BoundEvidence(*counts) for name, counts in totals.items()}


_SHEET_NS = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main}'


def _row_number(token):
    if not isinstance(token, str) or len(token) > 7 or not re.fullmatch(r'[1-9][0-9]*', token):
        _invalid()
    number = int(token)
    if number > MAX_VISITED_ROWS:
        _invalid()
    return number


def _coordinate(token):
    if not isinstance(token, str) or len(token) > 10:
        _invalid()
    match = re.fullmatch(r'([A-Z]{1,3})([1-9][0-9]{0,6})', token)
    if not match:
        _invalid()
    column = 0
    for letter in match[1]:
        column = column * 26 + ord(letter) - ord('A') + 1
        if column > MAX_COLUMNS:
            _invalid()
    return _row_number(match[2]), column


def xlsx_bounds(workbook, worksheet, budget):
    """Preflight a complete member before openpyxl allocates source/padded rows.

    budget carries only cumulative row/cell counts. Values, headers and XML
    character data are never retained by the preflight.
    """
    parser = expat.ParserCreate(namespace_separator='}')
    stack = []
    row_index = column_index = 0
    max_row = max_column = 0
    rows_seen = cells_seen = 0
    dimension_seen = False

    def check_budget():
        if (max_column > MAX_COLUMNS or max_row + budget.get('rows', 0) > MAX_VISITED_ROWS
                or max_row * max_column + budget.get('cells', 0) > MAX_VISITED_CELLS
                or rows_seen + budget.get('rows', 0) > MAX_VISITED_ROWS
                or cells_seen + budget.get('cells', 0) > MAX_VISITED_CELLS):
            _invalid()

    def start(tag, attrs):
        nonlocal row_index, column_index, max_row, max_column, rows_seen, cells_seen, dimension_seen
        parent = stack[-1] if stack else None
        if len(stack) >= 128:
            _invalid()
        if parent == _SHEET_NS + 'row' and tag != _SHEET_NS + 'c':
            _invalid()
        stack.append(tag)
        if tag == _SHEET_NS + 'dimension':
            if dimension_seen or parent != _SHEET_NS + 'worksheet':
                _invalid()
            dimension_seen = True
            token = attrs.get('ref', '')
            if len(token) > 21:
                _invalid()
            pair = token.split(':')
            if len(pair) not in (1, 2):
                _invalid()
            first = _coordinate(pair[0]); last = _coordinate(pair[-1])
            if first[0] > last[0] or first[1] > last[1]:
                _invalid()
            max_row = max(max_row, last[0]); max_column = max(max_column, last[1])
        elif tag == _SHEET_NS + 'row':
            if parent != _SHEET_NS + 'sheetData':
                _invalid()
            new_row = _row_number(attrs['r']) if 'r' in attrs else row_index + 1
            if new_row <= row_index:
                _invalid()
            row_index = new_row; column_index = 0; rows_seen += 1
            max_row = max(max_row, row_index)
        elif tag == _SHEET_NS + 'c':
            if parent != _SHEET_NS + 'row':
                _invalid()
            actual_row, new_column = _coordinate(attrs['r']) if 'r' in attrs else (row_index, column_index + 1)
            if actual_row != row_index or new_column <= column_index:
                _invalid()
            column_index = new_column; cells_seen += 1
            max_column = max(max_column, column_index)
        check_budget()

    def end(tag):
        stack.pop()

    def forbid(*args):
        _invalid()

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.StartDoctypeDeclHandler = forbid
    parser.EntityDeclHandler = forbid
    parser.ExternalEntityRefHandler = forbid
    try:
        with workbook._archive.open(worksheet._worksheet_path) as source:
            while True:
                chunk = source.read(65_536)
                parser.Parse(chunk, not chunk)
                if not chunk:
                    break
    except Exception:
        _invalid()
    check_budget()
    budget['rows'] = budget.get('rows', 0) + max_row
    budget['cells'] = budget.get('cells', 0) + max_row * max_column
    return max_row, max_column
