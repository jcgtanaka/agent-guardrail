"""Quote-aware shell tokenizer.

Splits a command line into simple commands (segments) on ; && || | |& & and
newline, recognises redirects, and collects nested command text ($(...),
backticks, <(...), >(...)) for recursive analysis. It is a conservative
approximation of POSIX shell syntax, not a full parser: anything it cannot
parse is reported as failure so the caller can fail safe.
"""
import os
import re

_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# On Windows a backslash is a path separator, not an escape character.
POSIX_ESCAPES = os.name != "nt"


class Word(object):
    __slots__ = ("text", "dynamic", "quoted")

    def __init__(self, text, dynamic=False, quoted=False):
        self.text = text
        self.dynamic = dynamic
        self.quoted = quoted


class Segment(object):
    def __init__(self, sep):
        self.sep = sep
        self.words = []
        self.redirects = []  # (operator, Word)
        self.heredocs = []   # raw heredoc bodies


class Parsed(object):
    def __init__(self, segments, nested, ok):
        self.segments = segments
        self.nested = nested
        self.ok = ok


class _Fail(Exception):
    pass


def _dq_end(text, i):
    n = len(text)
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == '"':
            return i
        i += 1
    return -1


def _bt_end(text, i):
    n = len(text)
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == "`":
            return i
        i += 1
    return -1


def find_close(text, i):
    """text[i] is '('. Return the index of the matching ')' or -1."""
    depth = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == "'":
            j = text.find("'", i + 1)
            if j < 0:
                return -1
            i = j + 1
            continue
        if c == '"':
            j = _dq_end(text, i + 1)
            if j < 0:
                return -1
            i = j + 1
            continue
        if c == "`":
            j = _bt_end(text, i + 1)
            if j < 0:
                return -1
            i = j + 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


class _Parser(object):
    def __init__(self, text, home):
        self.t = text
        self.n = len(text)
        self.i = 0
        self.home = home
        self.segments = []
        self.nested = []
        self.seg = Segment("")
        self.buf = []
        self.in_word = False
        self.dyn = False
        self.quoted = False
        self.pending = None
        self.hd_queue = []

    # -- word / segment bookkeeping ---------------------------------------

    def _add(self, s):
        self.buf.append(s)
        self.in_word = True

    def _end_word(self):
        if not self.in_word:
            return
        w = Word("".join(self.buf), self.dyn, self.quoted)
        self.buf, self.in_word, self.dyn, self.quoted = [], False, False, False
        if self.pending is not None:
            op = self.pending
            self.pending = None
            if op in ("<<", "<<-"):
                self.hd_queue.append((self.seg, w.text, op == "<<-"))
            self.seg.redirects.append((op, w))
        else:
            self.seg.words.append(w)

    def _end_segment(self, sep):
        self._end_word()
        self.pending = None
        if self.seg.words or self.seg.redirects:
            self.segments.append(self.seg)
        self.seg = Segment(sep)

    def _read_heredocs(self):
        t = self.t
        while self.hd_queue:
            seg, delim, strip = self.hd_queue.pop(0)
            body = []
            while self.i < self.n:
                j = t.find("\n", self.i)
                line = t[self.i:j] if j >= 0 else t[self.i:]
                self.i = j + 1 if j >= 0 else self.n
                if (line.lstrip("\t") if strip else line) == delim:
                    break
                body.append(line)
            seg.heredocs.append("\n".join(body))

    # -- expansions ---------------------------------------------------------

    def _dollar(self):
        t, i = self.t, self.i
        nxt = t[i + 1] if i + 1 < self.n else ""
        if nxt == "(":
            j = find_close(t, i + 1)
            if j < 0:
                raise _Fail()
            self.nested.append(t[i + 2:j])
            self._add(t[i:j + 1])
            self.dyn = True
            self.i = j + 1
        elif nxt == "{":
            j = t.find("}", i + 2)
            if j < 0:
                raise _Fail()
            if t[i + 2:j] == "HOME":
                self._add(self.home)
            else:
                self._add(t[i:j + 1])
                self.dyn = True
            self.i = j + 1
        else:
            m = _NAME.match(t, i + 1)
            if m:
                if m.group(0) == "HOME":
                    self._add(self.home)
                else:
                    self._add(t[i:m.end()])
                    self.dyn = True
                self.i = m.end()
            elif nxt and (nxt.isdigit() or nxt in "@*#?$!-"):
                self._add(t[i:i + 2])
                self.dyn = True
                self.i = i + 2
            else:
                self._add("$")
                self.i = i + 1

    def _backtick(self):
        j = _bt_end(self.t, self.i + 1)
        if j < 0:
            raise _Fail()
        self.nested.append(self.t[self.i + 1:j])
        self._add(self.t[self.i:j + 1])
        self.dyn = True
        self.i = j + 1

    def _single(self):
        j = self.t.find("'", self.i + 1)
        if j < 0:
            raise _Fail()
        self._add(self.t[self.i + 1:j])
        self.quoted = True
        self.i = j + 1

    def _double(self):
        t = self.t
        self.i += 1
        self.in_word = True
        self.quoted = True
        while True:
            if self.i >= self.n:
                raise _Fail()
            c = t[self.i]
            if c == '"':
                self.i += 1
                return
            if c == "\\" and self.i + 1 < self.n and t[self.i + 1] in '"\\$`\n':
                if t[self.i + 1] != "\n":
                    self._add(t[self.i + 1])
                self.i += 2
            elif c == "$":
                self._dollar()
            elif c == "`":
                self._backtick()
            else:
                self._add(c)
                self.i += 1

    def _operator(self, c):
        t = self.t
        if c == "&" and self.i + 1 < self.n and t[self.i + 1] == ">":
            self._end_word()
            op = "&>>" if t[self.i:self.i + 3] == "&>>" else "&>"
            self.i += len(op)
            self.pending = op
            return
        # A bare number directly before < or > is a file descriptor prefix.
        if self.in_word and not self.quoted and "".join(self.buf).isdigit():
            self.buf, self.in_word, self.dyn = [], False, False
        else:
            self._end_word()
        op = c
        self.i += 1
        nxt = t[self.i] if self.i < self.n else ""
        if c == ">":
            if nxt in (">", "|", "&"):
                op += nxt
                self.i += 1
        else:
            if nxt == "<":
                op += nxt
                self.i += 1
                if self.i < self.n and t[self.i] == "<":
                    op += "<"
                    self.i += 1
                elif self.i < self.n and t[self.i] == "-":
                    op += "-"
                    self.i += 1
            elif nxt in ("&", ">"):
                op += nxt
                self.i += 1
        if op in (">", "<") and self.i < self.n and t[self.i] == "(":
            j = find_close(t, self.i)
            if j < 0:
                raise _Fail()
            self.nested.append(t[self.i + 1:j])
            self.seg.words.append(Word(op + t[self.i:j + 1], True, False))
            self.i = j + 1
            return
        self.pending = op

    # -- main loop ------------------------------------------------------------

    def run(self):
        t = self.t
        try:
            while self.i < self.n:
                c = t[self.i]
                if c in " \t\r":
                    self._end_word()
                    self.i += 1
                elif c == "\n":
                    self._end_segment("\n")
                    self.i += 1
                    self._read_heredocs()
                elif c == ";":
                    self._end_segment(";")
                    self.i += 1
                elif c == "&" and not (self.i + 1 < self.n and t[self.i + 1] == ">"):
                    if t[self.i:self.i + 2] == "&&":
                        self._end_segment("&&")
                        self.i += 2
                    else:
                        self._end_segment("&")
                        self.i += 1
                elif c == "|":
                    if t[self.i:self.i + 2] == "||":
                        self._end_segment("||")
                        self.i += 2
                    elif t[self.i:self.i + 2] == "|&":
                        self._end_segment("|&")
                        self.i += 2
                    else:
                        self._end_segment("|")
                        self.i += 1
                elif c in "()":
                    self._end_segment("(")
                    self.i += 1
                elif c == "#" and not self.in_word:
                    j = t.find("\n", self.i)
                    self.i = self.n if j < 0 else j
                elif c in "<>" or c == "&":
                    self._operator(c)
                elif c == "$":
                    self._dollar()
                elif c == "`":
                    self._backtick()
                elif c == "'":
                    self._single()
                elif c == '"':
                    self._double()
                elif c == "\\" and POSIX_ESCAPES:
                    if self.i + 1 < self.n:
                        if t[self.i + 1] != "\n":
                            self._add(t[self.i + 1])
                            self.quoted = True
                        self.i += 2
                    else:
                        self.i += 1
                else:
                    self._add(c)
                    self.i += 1
            self._end_segment("")
        except _Fail:
            return Parsed([], [], False)
        return Parsed(self.segments, self.nested, True)


def parse(text, home):
    return _Parser(text, home).run()
