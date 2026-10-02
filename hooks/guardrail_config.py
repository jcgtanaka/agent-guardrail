"""Config discovery, validation and state-dir location."""
import json
import os
import re
import sys

import guardrail_defaults as defaults

CONFIG_ENV_VAR = "AGENT_GUARDRAIL_CONFIG"
STATE_ENV_VAR = "AGENT_GUARDRAIL_STATE_DIR"
TIERS = ("deny", "approve", "ask")
HOOKS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_DIR = os.path.dirname(HOOKS_DIR)


class ConfigError(Exception):
    pass


def home_dir():
    return os.path.expanduser("~")


def config_candidates():
    env_path = os.environ.get(CONFIG_ENV_VAR)
    if env_path:
        return [env_path]
    return [
        os.path.join(home_dir(), ".config", "agent-guardrail", "protected_paths.json"),
        os.path.join(REPO_DIR, "config", "protected_paths.json"),
    ]


def state_dir():
    override = os.environ.get(STATE_ENV_VAR)
    if override:
        return override
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.join(home_dir(), "AppData", "Local")
        return os.path.join(base, "agent-guardrail")
    if sys.platform == "darwin":
        return os.path.join(home_dir(), "Library", "Application Support", "agent-guardrail")
    base = os.environ.get("XDG_STATE_HOME") or os.path.join(home_dir(), ".local", "state")
    return os.path.join(base, "agent-guardrail")


def _require(cond, msg):
    if not cond:
        raise ConfigError(msg)


def _str_list(data, key):
    value = data.get(key, [])
    _require(isinstance(value, list) and all(isinstance(v, str) for v in value),
             "'%s' must be a list of strings" % key)
    return value


_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _no_control(value, label):
    # A newline or tab in a path can start a new line in generated scripts and
    # makes the path ambiguous in messages, so refuse it up front.
    _require(not _CONTROL.search(value),
             "%s contains a control character (such as a newline or tab)" % label)


def default_config():
    return {
        "content_scan_timeout_seconds": defaults.DEFAULT_SCAN_TIMEOUT_SECONDS,
        "protected_paths": [],
        "sensitive_globs": list(defaults.DEFAULT_SENSITIVE_GLOBS),
        "sensitive_content_patterns": [],
        "allow_paths": [],
        "builtin_os_protection": True,
        "ttl_seconds": defaults.DEFAULT_TTL_SECONDS,
        "found": False,
        "path": None,
    }


def parse_config(data):
    _require(isinstance(data, dict), "top level must be a JSON object")
    cfg = default_config()
    entries = data.get("protected_paths", [])
    _require(isinstance(entries, list), "'protected_paths' must be a list")
    for i, entry in enumerate(entries):
        _require(isinstance(entry, dict), "protected_paths[%d] must be an object" % i)
        _require(isinstance(entry.get("path"), str) and entry["path"],
                 "protected_paths[%d].path must be a non-empty string" % i)
        _no_control(entry["path"], "protected_paths[%d].path" % i)
        tier = entry.get("tier", "deny")
        _require(tier in TIERS, "protected_paths[%d].tier must be one of %s" % (i, TIERS))
        reason = entry.get("reason", "")
        _require(isinstance(reason, str), "protected_paths[%d].reason must be a string" % i)
        cfg["protected_paths"].append({"path": entry["path"], "tier": tier,
                                       "reason": reason or "protected by user config"})
    if "sensitive_globs" in data:
        cfg["sensitive_globs"] = _str_list(data, "sensitive_globs")
        for g in cfg["sensitive_globs"]:
            _no_control(g, "sensitive_globs entry %r" % g)
    patterns = _str_list(data, "sensitive_content_patterns")
    for p in patterns:
        try:
            re.compile(p)
        except re.error as exc:
            raise ConfigError("invalid regex in sensitive_content_patterns: %s" % exc)
    cfg["sensitive_content_patterns"] = patterns
    cfg["allow_paths"] = _str_list(data, "allow_paths")
    for a in cfg["allow_paths"]:
        _no_control(a, "allow_paths entry %r" % a)
    if "content_scan_timeout_seconds" in data:
        secs = data["content_scan_timeout_seconds"]
        _require(isinstance(secs, int) and not isinstance(secs, bool) and secs > 0,
                 "'content_scan_timeout_seconds' must be a positive integer")
        cfg["content_scan_timeout_seconds"] = secs
    if "builtin_os_protection" in data:
        _require(isinstance(data["builtin_os_protection"], bool),
                 "'builtin_os_protection' must be true or false")
        cfg["builtin_os_protection"] = data["builtin_os_protection"]
    approval = data.get("approval", {})
    _require(isinstance(approval, dict), "'approval' must be an object")
    if "ttl_seconds" in approval:
        ttl = approval["ttl_seconds"]
        _require(isinstance(ttl, int) and not isinstance(ttl, bool) and ttl > 0,
                 "'approval.ttl_seconds' must be a positive integer")
        cfg["ttl_seconds"] = ttl
    return cfg


def load_config():
    """Return the parsed config. A missing file yields defaults (built-in
    protection still applies); a present but invalid file raises ConfigError."""
    for path in config_candidates():
        if path and os.path.isfile(path):
            try:
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
            except (OSError, ValueError) as exc:
                raise ConfigError("cannot read config %s: %s" % (path, exc))
            try:
                cfg = parse_config(data)
            except ConfigError as exc:
                raise ConfigError("invalid config %s: %s" % (path, exc))
            cfg["found"] = True
            cfg["path"] = path
            return cfg
    return default_config()
