"""Path resolution and protected-path matching.

Every comparison is done on realpaths of BOTH sides, with path-component
boundaries (never a bare string prefix) and, on Windows, case-insensitively.
A bare prefix check is the bug class behind CVE-2025-53110.
"""
import glob
import os
import re
import sys

import guardrail_config as gconfig
import guardrail_defaults as defaults

SEVERITY = {"ask": 1, "approve": 2, "deny": 3}
_GLOB_CHARS = re.compile(r"[*?\[]")


class Finding(object):
    def __init__(self, tier, kind, detail, rule, damage, alternative):
        self.tier = tier
        self.kind = kind
        self.detail = detail
        self.rule = rule
        self.damage = damage
        self.alternative = alternative


class PathRule(object):
    def __init__(self, tier, reason, root, self_protect=False):
        self.tier = tier
        self.reason = reason
        self.root = root
        self.self_protect = self_protect


def norm(path):
    return os.path.normcase(path)


def within(path, root):
    if path == root:
        return True
    prefix = root if root.endswith(os.sep) else root + os.sep
    return path.startswith(prefix)


def glob_to_regex(pattern):
    pat = pattern.replace("\\", "/") if os.sep == "\\" else pattern
    if not (pat.startswith("/") or pat.startswith("**") or re.match(r"^[A-Za-z]:/", pat)):
        pat = "**/" + pat
    out = []
    i = 0
    while i < len(pat):
        if pat.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pat.startswith("**", i):
            out.append(".*")
            i += 2
        elif pat[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pat[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pat[i]))
            i += 1
    flags = re.DOTALL | (re.IGNORECASE if os.sep == "\\" else 0)
    return re.compile("".join(out) + r"\Z", flags)


def _posix(path):
    return path.replace(os.sep, "/") if os.sep != "/" else path


def _components(path):
    return [p for p in norm(path).replace("\\", "/").split("/") if p]


def _has_subsequence(parts, seq):
    n = len(seq)
    return any(tuple(parts[i:i + n]) == seq for i in range(len(parts) - n + 1))


def real(path):
    return norm(os.path.realpath(path))


def expand_user(path):
    return os.path.expanduser(path)


class Matcher(object):
    def __init__(self, cfg, platform=None, environ=None):
        self.cfg = cfg
        self.home = gconfig.home_dir()
        self._environ = os.environ if environ is None else environ
        self.roots = []
        self.components = []
        self.globs = []
        self.allow_prefix = []
        self.allow_globs = []
        self.content = []
        self.literal_exempt = set()
        self._build(platform or sys.platform)

    # ---- construction -------------------------------------------------

    def _add_root(self, path, tier, reason, exceptions=(), self_protect=False):
        expanded = expand_user(path)
        paths = [expanded]
        if _GLOB_CHARS.search(expanded):
            paths = glob.glob(expanded)
        for p in paths:
            exc = []
            for e in exceptions:
                e = expand_user(e)
                exc.append(norm(os.path.normpath(e)))
                exc.append(real(e))
                # /dev/stdout and friends are symlinks into /proc/<pid>/fd, which is
                # itself a protected root, so only an exact match on the symlink
                # can be exempted. A directory exception stays resolved-path based
                # so a symlink planted inside it cannot smuggle a write out.
                if os.path.islink(e):
                    self.literal_exempt.add(norm(os.path.abspath(e)))
            self.roots.append({
                "real": real(p), "raw": norm(os.path.abspath(p)),
                "rule": PathRule(tier, reason, p, self_protect), "except": exc,
            })

    def _build(self, platform):
        cfg = self.cfg
        # Self-protection first: independent of allow_paths and of the OS layer.
        for path in self_paths(cfg):
            self._add_root(path, "deny", "agent-guardrail's own files (script, config, state)",
                           self_protect=True)
        for comp in defaults.SELF_COMPONENTS:
            self.components.append((tuple(c.lower() if os.sep == "\\" else c for c in comp["components"]),
                                    PathRule("deny", comp["reason"], "/".join(comp["components"]), True)))
        for entry in cfg["protected_paths"]:
            self._add_root(entry["path"], entry["tier"], entry["reason"])
        if cfg["builtin_os_protection"]:
            for e in defaults.os_entries(platform, self.home, self._environ):
                self._add_root(e["path"], "approve", e["reason"], e["except"])
            for comp in defaults.CROSS_PLATFORM_COMPONENTS:
                self.components.append((tuple(comp["components"]),
                                        PathRule("approve", comp["reason"],
                                                 "/".join(comp["components"]))))
        for g in cfg["sensitive_globs"]:
            self.globs.append((glob_to_regex(expand_user(g)),
                               PathRule("approve", "sensitive file pattern '%s'" % g, g)))
        for a in cfg["allow_paths"]:
            a = expand_user(a)
            if _GLOB_CHARS.search(a):
                self.allow_globs.append(glob_to_regex(a))
            else:
                self.allow_prefix.append(real(a))
        for pattern, label in defaults.DEFAULT_CONTENT_PATTERNS:
            self.content.append((re.compile(pattern), label))
        for pattern in cfg["sensitive_content_patterns"]:
            self.content.append((re.compile(pattern), "text matching a user-defined sensitive pattern"))

    # ---- resolution -----------------------------------------------------

    def resolve(self, path_str, cwd):
        path_str = expand_user(path_str)
        if not os.path.isabs(path_str):
            path_str = os.path.join(cwd, path_str)
        # realpath resolves every symlink in the existing part of the chain
        # even when the final component does not exist yet.
        return norm(os.path.realpath(path_str)), norm(os.path.normpath(path_str))

    def _allowed(self, resolved, raw):
        for root in self.allow_prefix:
            if within(resolved, root):
                return True
        for rx in self.allow_globs:
            if rx.match(_posix(resolved)) or rx.match(_posix(raw)):
                return True
        return False

    def classify(self, path_str, cwd):
        """Return the most severe PathRule for a path, or None."""
        try:
            resolved, raw = self.resolve(path_str, cwd)
        except (OSError, ValueError):
            return None
        if raw in self.literal_exempt:
            return None

        hits = []
        for root in self.roots:
            if not within(resolved, root["real"]):
                continue
            if any(within(resolved, e) or within(raw, e) for e in root["except"]):
                continue
            hits.append(root["rule"])
        for pair in (_components(resolved), _components(raw)):
            for seq, rule in self.components:
                if _has_subsequence(pair, seq):
                    hits.append(rule)
        for rx, rule in self.globs:
            if rx.match(_posix(resolved)) or rx.match(_posix(raw)):
                hits.append(rule)
        if not hits:
            return None
        if self._allowed(resolved, raw):
            hits = [h for h in hits if h.self_protect]
        if not hits:
            return None
        return max(hits, key=lambda h: SEVERITY[h.tier])

    # ---- textual mentions ------------------------------------------------

    def _mention_regex(self):
        if getattr(self, "_mrx", None) is not None:
            return self._mrx
        strings = set()
        home = self.home
        for root in self.roots:
            for s in (root["real"], root["raw"]):
                strings.add(s)
                if home and within(s, norm(home)):
                    rel = s[len(norm(home)):].replace("\\", "/")
                    strings.update(["~" + rel, "$HOME" + rel, "${HOME}" + rel])
        for seq, _ in self.components:
            strings.add("/".join(seq))
        strings = sorted((s for s in strings if s), key=len, reverse=True)
        flags = re.IGNORECASE if os.sep == "\\" else 0
        if not strings:
            self._mrx = re.compile(r"(?!x)x")
        else:
            body = "|".join(re.escape(s) for s in strings)
            self._mrx = re.compile(
                r"(?<![\w.\-])(?:" + body + r")(?=$|[/\\\s'\"`;|&()<>:,=*?])", flags)
        return self._mrx

    def mention(self, text, cwd):
        """Return a PathRule if text names a protected location, else None."""
        text_n = text.replace("\\", "/") if os.sep == "\\" else text
        for m in self._mention_regex().finditer(text_n if os.sep == "\\" else text):
            run = re.match(r"[^\s'\"`;|&()<>]*", (text_n if os.sep == "\\" else text)[m.start():]).group(0)
            run = run.replace("${HOME}", self.home).replace("$HOME", self.home)
            rule = self.classify(run, cwd)
            if rule:
                return rule
        return None

    def cwd_rule(self, cwd):
        return self.classify(cwd, cwd)

    # ---- content -----------------------------------------------------------

    def oversize(self, text):
        return len(text) > defaults.MAX_SCAN_CHARS

    def scan_content(self, text):
        if self.oversize(text):
            # Keep the start and the end, where headers and appended secrets
            # usually sit; the caller raises a separate warning about this.
            half = defaults.MAX_SCAN_CHARS // 2
            text = text[:half] + "\n" + text[-half:]
        found = []
        for rx, label in self.content:
            if rx.search(text) and label not in found:
                found.append(label)
        return found


def self_paths(cfg):
    paths = [gconfig.HOOKS_DIR, gconfig.state_dir()]
    paths.extend(gconfig.config_candidates())
    paths.append(os.path.join(gconfig.home_dir(), ".config", "agent-guardrail"))
    return paths
