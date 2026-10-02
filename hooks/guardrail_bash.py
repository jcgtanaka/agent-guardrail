"""Bash command analysis: turn a command line into guardrail findings.

Order of decisions per simple command: unwrap wrappers (sudo, env, xargs,
...), recurse into shell -c / eval / substitutions, check OS-level verbs,
then dispatch on the verb class (read-only, write-ish, interpreter, unknown).
Real output redirects are checked for every segment.
"""
import glob
import os
import re

import guardrail_defaults as defaults
import guardrail_shell as shell
from guardrail_matcher import Finding

MAX_DEPTH = 6
NT = os.name == "nt"
_GLOB = re.compile(r"[*?\[]")
_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "ash", "fish"}
DOWNLOADERS = {"curl", "wget", "fetch"}
KEYWORDS = {"if", "then", "else", "elif", "fi", "do", "done", "while", "until",
            "!", "{", "}", "time"}
CONTROL = {"for", "case", "select", "in", "esac", "function"}

READ_ONLY = set("""
ls cat head tail less more rg grep egrep fgrep stat file wc diff cmp md5sum
sha1sum sha224sum sha256sum sha384sum sha512sum shasum du df pwd echo printf
true false : test [ [[ type which whoami id uname hostname basename dirname
realpath readlink cut tr tree jq sleep read export unset set declare local
readonly alias wait exit return break continue
""".split())
READ_ONLY_GIT = {"status", "log", "diff", "show", "blame", "grep", "ls-files",
                 "ls-tree", "rev-parse", "describe", "shortlog", "cat-file",
                 "diff-tree", "show-branch", "reflog"}

ALL_ARGS = {"rm", "rmdir", "shred", "truncate", "unlink", "touch", "mkdir",
            "mv", "tee", "patch", "chattr"}
DEST_LAST = {"cp", "install", "rsync", "ln"}
OWNER_FIRST = {"chmod", "chown", "chgrp"}
OPT_ARG = {
    "truncate": {"-s", "--size", "-r", "--reference"},
    "touch": {"-d", "-t", "-r", "--date", "--reference"},
    "mkdir": {"-m", "--mode"},
    "shred": {"-n", "-s"},
    "patch": {"-p", "-i", "-d", "-o", "-r"},
    "cp": {"-t", "--target-directory", "-S", "--suffix"},
    "mv": {"-t", "--target-directory", "-S", "--suffix"},
    "install": {"-t", "--target-directory", "-m", "-o", "-g", "-S"},
    "rsync": {"-e", "--exclude", "--include", "--exclude-from", "--include-from",
              "--filter", "-f", "--rsh"},
    "ln": {"-t", "--target-directory", "-S", "--suffix"},
    "tee": set(),
    "chmod": {"--reference"},
    "chown": {"--reference"},
    "chgrp": {"--reference"},
}
WRAP_ARG = {
    "sudo": {"-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U", "-r", "-t"},
    "doas": {"-u", "-C"},
    "env": {"-u", "-C", "-S", "--unset", "--chdir"},
    "nice": {"-n", "--adjustment"},
    "stdbuf": {"-i", "-o", "-e"},
    "timeout": {"-s", "-k", "--signal", "--kill-after"},
    "xargs": {"-n", "-I", "-P", "-d", "-L", "-s", "-E", "-a", "-R", "-S"},
    "time": {"-f", "-o"},
    "exec": {"-a"},
    "nohup": set(),
    "command": set(),
    "builtin": set(),
}
_PYTHON = re.compile(r"^(python|pypy)[0-9.]*$")
_NODE = {"node", "nodejs", "deno", "bun"}


def _verb_name(text):
    base = os.path.basename(text.replace("\\", "/")) if (NT or "/" in text) else text
    return base.lower() if NT else base


def _is_flag(w):
    return w.text.startswith("-") and len(w.text) > 1


def _positional(words, takes_arg=()):
    """Non-flag words, honouring '--' and options that consume a value."""
    out, i, after = [], 0, False
    while i < len(words):
        w = words[i]
        if not after and w.text == "--":
            after = True
        elif not after and _is_flag(w):
            if w.text in takes_arg:
                i += 1
        else:
            out.append(w)
        i += 1
    return out


def _skip_opts(words, takes_arg):
    i = 0
    while i < len(words):
        t = words[i].text
        if t == "--":
            return i + 1
        if t.startswith("-") and len(t) > 1:
            i += 2 if t in takes_arg else 1
            continue
        break
    return i


class Checker(object):
    def __init__(self, matcher, cfg, fulltext):
        self.m = matcher
        self.os_on = cfg["builtin_os_protection"]
        self.full = fulltext
        self.findings = []

    # ---- finding constructors ---------------------------------------------

    def _add(self, f):
        self.findings.append(f)

    def _path_hit(self, rule, what, resolved):
        tier = rule.tier
        alt = ("Do not do this from the agent. Make the change by hand, or ask the user to adjust the config."
               if tier == "deny" else
               "A human can approve this exact action out-of-band; otherwise work on a copy outside the protected location."
               if tier == "approve" else
               "Confirm the exact target; prefer a path outside the protected location.")
        self._add(Finding(
            tier, "path",
            "%s targets %s, which is protected by agent-guardrail" % (what, resolved),
            "%s (tier %s): %s" % (rule.root, tier, rule.reason),
            "Files at or under that location could be overwritten, deleted or altered.",
            alt))

    def _ask(self, kind, detail, rule, damage, alt):
        self._add(Finding("ask", kind, detail, rule, damage, alt))

    def _approve_os(self, verb, reason, detail=None):
        self._add(Finding(
            "approve", "os-command",
            detail or "%s is an operating-system level command" % verb,
            "built-in OS command table: %s" % reason,
            "It can change system state, install software or alter privileges outside the project.",
            "A human can approve this exact command out-of-band; otherwise avoid system-level changes."))

    def _dynamic(self, verb):
        self._ask("dynamic", "'%s' has a target built from a variable or command substitution" % verb,
                  "write-ish command with a dynamic argument",
                  "The real target is only known at runtime and could be a protected path.",
                  "Use an explicit literal path so the target can be checked.")

    # ---- path helpers --------------------------------------------------------

    def _check_path(self, text, cwd, what):
        if not text:
            return None
        cands = [text]
        if _GLOB.search(text):
            pat = os.path.expanduser(text)
            if not os.path.isabs(pat):
                pat = os.path.join(cwd, pat)
            try:
                cands += glob.glob(pat)[:200]
            except (OSError, ValueError):
                pass
        for c in cands:
            rule = self.m.classify(c, cwd)
            if rule:
                self._path_hit(rule, what, self.m.resolve(c, cwd)[0])
                return rule
        return None

    def _implicit(self, cwd, what):
        rule = self.m.classify(cwd, cwd)
        if rule:
            self._path_hit(rule, what, self.m.resolve(cwd, cwd)[0])

    def _targets(self, verb, words, cwd, dyn_check=True):
        any_dyn = False
        for w in words:
            self._check_path(w.text, cwd, verb)
            any_dyn = any_dyn or w.dynamic
        if any_dyn and dyn_check:
            self._dynamic(verb)

    # ---- entry ------------------------------------------------------------------

    def check_text(self, text, cwd, depth=0):
        if depth > MAX_DEPTH:
            self._ask("nesting", "command nesting is deeper than %d levels" % MAX_DEPTH,
                      "analysis depth limit",
                      "Deeply nested shell code cannot be checked reliably.",
                      "Run the inner commands separately.")
            return
        res = shell.parse(text, self.m.home)
        if not res.ok:
            rule = self.m.mention(text, cwd)
            if rule:
                self._ask("parse", "the command could not be parsed and it mentions %s" % rule.root,
                          "unparseable command mentioning a protected location",
                          "Because the command cannot be analysed, it might modify %s." % rule.root,
                          "Rewrite it as simple commands with balanced quotes.")
            return
        for inner in res.nested:
            self.check_text(inner, cwd, depth + 1)
        pipeline = []
        for seg in res.segments:
            if seg.sep not in ("|", "|&"):
                pipeline = []
            cwd = self._segment(seg, cwd, pipeline, depth)

    # ---- one simple command -----------------------------------------------------

    def _segment(self, seg, cwd, pipeline, depth):
        words = list(seg.words)
        while words:
            t = words[0].text
            if (_ASSIGN.match(t) and not words[0].quoted) or t in KEYWORDS:
                words.pop(0)
            else:
                break
        new_cwd = cwd
        if words:
            new_cwd, verb = self._command(words, seg, cwd, pipeline, depth, False)
            if verb:
                pipeline.append(verb)
        self._redirects(seg, cwd)
        return new_cwd

    def _redirects(self, seg, cwd):
        for op, w in seg.redirects:
            if op in ("<", "<<", "<<-", "<<<", "<&"):
                continue
            if op == ">&" and (w.text.isdigit() or w.text == "-"):
                continue
            if w.text == "/dev/null" and not w.dynamic:
                continue
            self._check_path(w.text, cwd, "redirect '%s'" % op)
            if w.dynamic:
                self._dynamic("redirect '%s'" % op)

    def _command(self, words, seg, cwd, pipeline, depth, via_xargs):
        """Analyse one command (after wrapper unwrapping). Returns (cwd, verb)."""
        first_verb = None
        for _ in range(12):
            if not words:
                return cwd, first_verb
            verb = _verb_name(words[0].text)
            if first_verb is None:
                first_verb = verb
            rest = words[1:]
            if verb in ("sudo", "doas"):
                if self.os_on:
                    self._approve_os(verb, defaults.OS_COMMANDS[verb]["reason"])
                words = rest[_skip_opts(rest, WRAP_ARG[verb]):]
            elif verb == "env":
                k = _skip_opts(rest, WRAP_ARG["env"])
                while k < len(rest) and _ASSIGN.match(rest[k].text):
                    k += 1
                words = rest[k:]
            elif verb == "timeout":
                k = _skip_opts(rest, WRAP_ARG["timeout"])
                words = rest[k + 1:]
            elif verb == "xargs":
                via_xargs = True
                words = rest[_skip_opts(rest, WRAP_ARG["xargs"]):]
            elif verb in ("nohup", "time", "command", "exec", "builtin", "nice", "stdbuf"):
                if verb == "command" and any(w.text in ("-v", "-V") for w in rest):
                    return cwd, first_verb
                words = rest[_skip_opts(rest, WRAP_ARG.get(verb, ())):]
            else:
                break
        else:
            return cwd, first_verb
        if not words:
            return cwd, first_verb
        verb = _verb_name(words[0].text)
        args = words[1:]
        if verb in CONTROL:
            return cwd, first_verb
        return self._dispatch(verb, args, seg, cwd, pipeline, depth, via_xargs), first_verb

    # ---- verb classes -------------------------------------------------------------

    def _dispatch(self, verb, args, seg, cwd, pipeline, depth, via_xargs):
        texts = [a.text for a in args]
        if self.os_on:
            self._os_command(verb, args, texts, pipeline)
        if verb in ("cd", "pushd"):
            pos = _positional(args)
            if pos and not pos[0].dynamic and pos[0].text != "-":
                target = os.path.expanduser(pos[0].text)
                return os.path.normpath(os.path.join(cwd, target))
            return cwd
        if verb in SHELLS or verb in ("su", "eval", "source", "."):
            self._shell_like(verb, args, texts, seg, cwd, depth)
            return cwd
        if verb == "git":
            self._git(args, cwd, via_xargs)
        elif verb == "find":
            self._find(args, cwd, pipeline, depth)
        elif verb in ("curl", "wget"):
            self._download(verb, args, cwd)
        elif verb == "sed" and any(re.match(r"^-[A-Za-z]*i", t) or t.startswith("--in-place") for t in texts):
            self._sed(args, cwd)
        elif verb in ("perl",) and any(re.match(r"^-[A-Za-z]*i", t) for t in texts):
            self._perl_inplace(args, cwd)
        elif verb in ("awk", "gawk") and self._awk_inplace(texts):
            self._awk(args, cwd)
        elif verb == "dd":
            self._targets("dd", [Word_of(t[3:], a) for a, t in zip(args, texts) if t.startswith("of=")], cwd)
        elif verb in OWNER_FIRST:
            self._owner_first(verb, args, cwd)
        elif verb in ALL_ARGS or verb == "install" and "-d" in texts:
            self._all_args(verb, args, cwd, via_xargs)
        elif verb in DEST_LAST:
            self._dest_last(verb, args, texts, cwd)
        elif verb in READ_ONLY:
            pass
        elif self._interpreter(verb, texts):
            if self.m.mention(" ".join(texts), cwd) or self.m.cwd_rule(cwd):
                rule = self.m.mention(" ".join(texts), cwd) or self.m.cwd_rule(cwd)
                self._ask("interpreter",
                          "%s runs inline code while %s is in scope" % (verb, rule.root),
                          "interpreter with inline code near a protected location",
                          "Inline code can write or delete files in ways the guard cannot analyse statically.",
                          "Write the script to a file outside the protected location and review it first, or use explicit file tools.")
        elif verb in defaults.OS_COMMANDS or verb.startswith("mkfs") or verb in ("pip", "pip3"):
            pass
        else:
            rule = self.m.mention(" ".join(texts), cwd)
            if rule:
                self._ask("unknown-verb",
                          "'%s' is not a recognised command and its arguments mention %s" % (verb, rule.root),
                          "unknown command naming a protected location",
                          "The guard cannot tell whether '%s' reads or modifies %s." % (verb, rule.root),
                          "Use a known read-only command, or explicit file tools, on that location.")
        if via_xargs and (verb in ALL_ARGS or verb in DEST_LAST or verb in OWNER_FIRST):
            self._xargs_unknown_targets(verb, cwd)
        return cwd

    def _xargs_unknown_targets(self, verb, cwd):
        rule = self.m.mention(self.full, cwd) or self.m.cwd_rule(cwd)
        if rule:
            self._ask("xargs",
                      "xargs feeds '%s' targets that are only known at runtime, and %s is in scope" % (verb, rule.root),
                      "xargs with a write-ish command near a protected location",
                      "Piped file names could point into %s." % rule.root,
                      "List the exact files and run the command on them explicitly.")

    # ---- OS commands -----------------------------------------------------------------

    def _os_command(self, verb, args, texts, pipeline):
        lower = [t.lower() for t in texts]
        spec = defaults.OS_COMMANDS.get(verb)
        if spec and verb not in ("sudo", "doas") and self._os_needs_approval(spec, args, lower):
            self._approve_os(verb, spec["reason"])
        elif verb.startswith(tuple(defaults.OS_COMMAND_PREFIXES)):
            for prefix, reason in defaults.OS_COMMAND_PREFIXES.items():
                if verb.startswith(prefix):
                    self._approve_os(verb, reason)
        if "--break-system-packages" in texts and (verb in ("pip", "pip3") or _PYTHON.match(verb) or "pip" in texts):
            self._approve_os("pip", "bypasses the distribution's protection of system Python packages",
                             "pip --break-system-packages modifies the system Python installation")
        if verb in SHELLS and any(p in DOWNLOADERS for p in pipeline):
            self._approve_os(verb, "executes a script piped from the network",
                             "a downloaded script is piped into %s" % verb)
        if verb in SHELLS | {"eval", "source", "."}:
            blob = " ".join(texts)
            if re.search(r"\b(curl|wget)\b", blob) and re.search(r"[$`<]\(?", blob):
                self._approve_os(verb, "executes a script fetched from the network",
                                 "%s executes the output of a network download" % verb)

    @staticmethod
    def _os_needs_approval(spec, args, lower):
        pos = [t for t, a in zip(lower, args) if not t.startswith("-") and not (NT and t.startswith("/"))]
        if "trigger" in spec:
            return bool(pos) and pos[0] in spec["trigger"]
        if "safe" in spec and ((pos and pos[0] in spec["safe"]) or "--version" in lower
                               or (lower and lower[0] in spec["safe"])):
            return False
        if "safe_flags" in spec and args and any(args[0].text.startswith(f) for f in spec["safe_flags"]):
            return False
        if "safe_last" in spec and lower and lower[-1] in spec["safe_last"]:
            return False
        if "safe_any" in spec and any(t in spec["safe_any"] for t in lower):
            return False
        if spec.get("safe_noargs") and not lower:
            return False
        return True

    # ---- shells / eval ------------------------------------------------------------------

    def _shell_like(self, verb, args, texts, seg, cwd, depth):
        if verb in ("eval",):
            self.check_text(" ".join(texts), cwd, depth + 1)
            return
        if verb in ("source", "."):
            # The sourced file's contents are invisible here, and a script can do
            # anything the shell can, so a protected location is a reason to ask.
            for t in texts:
                rule = None if t.startswith("-") else self.m.classify(t, cwd)
                if rule:
                    self._ask("source", "'%s' runs a file inside %s, whose contents cannot be checked" % (verb, rule.root),
                              "sourcing a file from a protected location",
                              "A sourced script can write or delete anything the shell can reach.",
                              "Read the file first, or run its commands directly so they can be checked.")
            return
        for i, t in enumerate(texts):
            if re.match(r"^-[A-Za-z]*c$", t) and i + 1 < len(texts):
                self.check_text(texts[i + 1], cwd, depth + 1)
                return
        if verb in SHELLS:
            for body in seg.heredocs:
                self.check_text(body, cwd, depth + 1)

    # ---- git -------------------------------------------------------------------------------

    def _git(self, args, cwd, via_xargs):
        eff, i = cwd, 0
        while i < len(args):
            t = args[i].text
            if t == "-C" and i + 1 < len(args):
                eff = os.path.normpath(os.path.join(eff, os.path.expanduser(args[i + 1].text)))
                i += 2
            elif t in ("-c", "--exec-path", "--namespace") and i + 1 < len(args):
                i += 2
            elif t.startswith("-"):
                i += 1
            else:
                break
        if i >= len(args):
            return
        sub, rest = args[i].text, args[i + 1:]
        texts = [w.text for w in rest]
        if sub in READ_ONLY_GIT:
            return
        if sub == "clean":
            self._implicit(eff, "git clean")
            self._targets("git clean", _positional(rest), eff)
        elif sub == "reset" and "--hard" in texts:
            self._implicit(eff, "git reset --hard")
        elif sub == "checkout" and ("--" in texts or "." in texts):
            self._implicit(eff, "git checkout") if "." in texts else None
            after = rest[texts.index("--") + 1:] if "--" in texts else []
            self._targets("git checkout --", after, eff)
        elif sub == "restore":
            self._targets("git restore", _positional(rest), eff)
        elif sub == "rm":
            self._targets("git rm", _positional(rest), eff)
        else:
            rule = self.m.mention(" ".join(w.text for w in args), cwd)
            if rule:
                self._ask("unknown-verb", "'git %s' mentions %s" % (sub, rule.root),
                          "git subcommand naming a protected location",
                          "The guard cannot tell whether this git command modifies %s." % rule.root,
                          "Use read-only git commands (status, log, diff, show) there.")

    # ---- find ----------------------------------------------------------------------------------

    def _find(self, args, cwd, pipeline, depth):
        texts = [a.text for a in args]
        actions = ("-delete", "-fprint", "-fprint0", "-fprintf", "-fls", "-exec", "-execdir", "-ok", "-okdir")
        if not any(t in actions for t in texts):
            return
        starts = []
        for a in args:
            if a.text.startswith("-") or a.text in ("(", "!", ")"):
                break
            starts.append(a)
        if not starts:
            self._implicit(cwd, "find")
        self._targets("find", starts, cwd)
        for i, t in enumerate(texts):
            if t in ("-fprint", "-fprint0", "-fprintf", "-fls") and i + 1 < len(args):
                self._targets("find %s" % t, [args[i + 1]], cwd)
            if t in ("-exec", "-execdir", "-ok", "-okdir"):
                inner = []
                for w in args[i + 1:]:
                    if w.text in (";", "+"):
                        break
                    inner.append(w)
                if inner:
                    self._command(inner, shell.Segment(""), cwd, [], depth, False)

    # ---- targeted write-ish handlers --------------------------------------------------------------

    def _all_args(self, verb, args, cwd, via_xargs):
        self._targets(verb, _positional(args, OPT_ARG.get(verb, ())), cwd)
        if verb == "patch":
            self._implicit(cwd, "patch")

    def _dest_last(self, verb, args, texts, cwd):
        takes = OPT_ARG.get(verb, ())
        pos = _positional(args, takes)
        dest = None
        for i, t in enumerate(texts):
            if t in ("-t", "--target-directory") and i + 1 < len(args):
                dest = [args[i + 1]]
            elif t.startswith("--target-directory="):
                dest = [shell.Word(t.split("=", 1)[1], args[i].dynamic)]
        if verb == "rsync" and "--remove-source-files" in texts:
            dest = pos
        if dest is None:
            dest = pos[-1:]
        self._targets(verb, dest, cwd)

    def _owner_first(self, verb, args, cwd):
        pos = _positional(args, OPT_ARG.get(verb, ()))
        if not any(a.text.startswith("--reference") for a in args):
            pos = pos[1:]
        self._targets(verb, pos, cwd)

    def _sed(self, args, cwd):
        texts = [a.text for a in args]
        script_flag = any(t in ("-e", "-f", "--expression", "--file") or t.startswith("--expression=")
                          for t in texts)
        pos = _positional(args, {"-e", "-f", "--expression", "--file", "-l"})
        self._targets("sed -i", pos if script_flag else pos[1:], cwd)

    @staticmethod
    def _awk_inplace(texts):
        for i, t in enumerate(texts):
            if t.startswith("-iinplace") or (t == "-i" and i + 1 < len(texts) and texts[i + 1].startswith("inplace")):
                return True
        return False

    def _awk(self, args, cwd):
        texts = [a.text for a in args]
        has_f = "-f" in texts
        pos = _positional(args, {"-f", "-v", "-i", "-F", "-e"})
        self._targets("awk -i inplace", pos if has_f else pos[1:], cwd)

    def _perl_inplace(self, args, cwd):
        out, i = [], 0
        while i < len(args):
            t = args[i].text
            if t.startswith("-") and len(t) > 1:
                if re.match(r"^-[A-Za-z]*e$", t) and "i" not in t:
                    i += 1
            else:
                out.append(args[i])
            i += 1
        self._targets("perl -i", out, cwd)

    def _download(self, verb, args, cwd):
        texts = [a.text for a in args]
        out = []
        for i, t in enumerate(texts):
            if verb == "curl" and t in ("-o", "--output", "--output-dir") and i + 1 < len(args):
                out.append(args[i + 1])
            elif verb == "wget" and t in ("-O", "-P", "--output-document", "--directory-prefix") and i + 1 < len(args):
                out.append(args[i + 1])
            elif t.startswith("--output="):
                out.append(shell.Word(t.split("=", 1)[1], args[i].dynamic))
        self._targets(verb, out, cwd)

    @staticmethod
    def _interpreter(verb, texts):
        if _PYTHON.match(verb):
            return any(re.match(r"^-[A-Za-z]*c$", t) for t in texts)
        if verb in _NODE:
            return any(t in ("-e", "-p", "--eval", "--print") for t in texts)
        if verb == "perl":
            return any(re.match(r"^-[A-Za-z]*[eE]$", t) for t in texts)
        if verb == "ruby":
            return any(re.match(r"^-[A-Za-z]*e$", t) for t in texts)
        return False


def Word_of(text, like):
    return shell.Word(text, like.dynamic, like.quoted)


def check_command(command, cwd, matcher, cfg):
    checker = Checker(matcher, cfg, command)
    checker.check_text(command, cwd)
    return checker.findings
