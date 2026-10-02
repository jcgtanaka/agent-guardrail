"""Built-in protection tables (data only, no logic beyond path templating).

These lists are this project's own compilation from general operating-system
knowledge. No authoritative, agent-oriented catalog of "paths an agent must
not write" exists, so review them before relying on them and trim or extend
them for your machines (see docs/DESIGN_RATIONALE.md).
"""

DEFAULT_TTL_SECONDS = 600

# Content scanning is bounded in size and time so a huge write or a
# catastrophic user regex cannot hang the hook (a hook timeout may fail open).
MAX_SCAN_CHARS = 1000000
DEFAULT_SCAN_TIMEOUT_SECONDS = 5

DEFAULT_SENSITIVE_GLOBS = [
    "**/.env",
    "**/.env.*",
    "**/*.pem",
    "**/id_rsa*",
    "**/id_ed25519*",
    "**/credentials",
    "**/.netrc",
    "**/.npmrc",
    "**/.pgpass",
    "**/*.kdbx",
]

# Each content pattern is (regex, human description). The description is what
# the warning shows; the matched text is never echoed back.
DEFAULT_CONTENT_PATTERNS = [
    (r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----", "a PEM private key block"),
    (r"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])", "an AWS access key id"),
    (r"(?<![A-Za-z0-9])(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}", "a GitHub token"),
    (r"(?<![A-Za-z0-9])github_pat_[A-Za-z0-9_]{22,}", "a GitHub fine-grained token"),
    (r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_\-]{20,}", "an sk- prefixed API key"),
    (r"(?<![A-Za-z0-9])xox[abprs]-[A-Za-z0-9\-]{10,}", "a Slack token"),
]

# Paths below are templates: "~" is the user's home, "%NAME%" is a Windows
# environment variable (resolved with the fallback in WINDOWS_ENV_DEFAULTS).
# "except" lists subtrees inside the entry that stay writable.
_E = ()

LINUX_PATHS = [
    ("/etc", "system configuration", _E),
    ("/usr", "installed system software", _E),
    ("/bin", "system binaries", _E),
    ("/sbin", "system administration binaries", _E),
    ("/lib*", "system libraries (lib, lib32, lib64, libx32)", _E),
    ("/boot", "bootloader and kernel images", _E),
    ("/sys", "kernel interface", _E),
    ("/proc", "kernel and process interface", _E),
    ("/dev", "device nodes (raw disks can be overwritten)",
     ("/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty")),
    ("/var/lib/dpkg", "package manager database", _E),
    ("/var/spool/cron", "cron jobs (persistence)", _E),
    ("/etc/sudoers", "sudo policy", _E),
    ("/etc/sudoers.d", "sudo policy", _E),
    ("/etc/systemd", "systemd units (persistence)", _E),
    ("/lib/systemd", "systemd units (persistence)", _E),
    ("/usr/lib/systemd", "systemd units (persistence)", _E),
    ("~/.config/autostart", "desktop autostart (persistence)", _E),
    ("~/.config/systemd", "user systemd units (persistence)", _E),
]

MACOS_PATHS = [
    ("/System", "sealed system volume", _E),
    ("/Library", "system-wide libraries, daemons and settings", _E),
    ("/usr", "system software", ("/usr/local",)),
    ("/Applications", "installed applications", _E),
    ("/private/etc", "system configuration (/etc is a symlink to it)", _E),
    ("/Library/LaunchDaemons", "launchd daemons (persistence)", _E),
    ("~/Library/LaunchAgents", "launchd agents (persistence)", _E),
    ("~/Library/Keychains", "keychains", _E),
]

WINDOWS_ENV_DEFAULTS = {
    "SystemRoot": "C:\\Windows",
    "ProgramFiles": "C:\\Program Files",
    "ProgramFiles(x86)": "C:\\Program Files (x86)",
    "ProgramData": "C:\\ProgramData",
}

WINDOWS_PATHS = [
    ("%SystemRoot%", "Windows system directory", _E),
    ("%ProgramFiles%", "installed programs", _E),
    ("%ProgramFiles(x86)%", "installed 32-bit programs", _E),
    ("%ProgramData%", "machine-wide application data", _E),
    ("%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
     "per-user startup folder (persistence)", _E),
    ("%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
     "all-users startup folder (persistence)", _E),
    ("~\\Documents\\WindowsPowerShell", "Windows PowerShell profiles (persistence)", _E),
    ("~\\Documents\\PowerShell", "PowerShell profiles (persistence)", _E),
]

CROSS_PLATFORM_PATHS = [
    ("~/.ssh", "SSH keys and config", _E),
    ("~/.aws", "cloud credentials", _E),
    ("~/.gnupg", "GPG keys", _E),
    ("~/.kube", "Kubernetes credentials", _E),
    ("~/.docker/config.json", "container registry credentials", _E),
    ("~/.gitconfig", "global git configuration (hooks and credential helpers)", _E),
    ("~/.bashrc", "shell startup file (persistence)", _E),
    ("~/.bash_profile", "shell startup file (persistence)", _E),
    ("~/.bash_login", "shell startup file (persistence)", _E),
    ("~/.profile", "shell startup file (persistence)", _E),
    ("~/.zshrc", "shell startup file (persistence)", _E),
    ("~/.zshenv", "shell startup file (persistence)", _E),
    ("~/.zprofile", "shell startup file (persistence)", _E),
    ("~/.config/fish/config.fish", "shell startup file (persistence)", _E),
]

# Directory-component patterns match anywhere in a path, in any repository.
CROSS_PLATFORM_COMPONENTS = [
    {"components": (".git", "hooks"), "reason": "git hooks run arbitrary code (persistence)"},
    {"components": (".git", "config"), "reason": "repository git config (hooks, credential helpers)"},
]

# Self-protection: tier deny, never narrowed by allow_paths.
SELF_COMPONENTS = [
    {"components": (".claude", "settings.json"),
     "reason": "Claude Code settings (hook registration lives here)"},
    {"components": (".claude", "settings.local.json"),
     "reason": "Claude Code local settings (hook registration lives here)"},
]

# OS-level command verbs, tier approve. Keys: reason; optional
#   trigger: only these subcommands need approval (others are allowed)
#   safe:    these subcommands are read-only and allowed
#   safe_flags: first-flag prefixes that are read-only
OS_COMMANDS = {
    "sudo": {"reason": "privilege escalation"},
    "doas": {"reason": "privilege escalation"},
    "su": {"reason": "switch user / privilege escalation"},
    "visudo": {"reason": "edits sudo policy"},
    "apt": {"reason": "system package manager", "safe": ("list", "show", "search", "policy", "depends", "--version")},
    "apt-get": {"reason": "system package manager", "safe": ("--version", "check", "changelog", "download")},
    "dpkg": {"reason": "system package manager", "safe_flags": ("-l", "-L", "-s", "-S", "-p", "--list", "--listfiles", "--status", "--search", "--version")},
    "snap": {"reason": "system package manager", "safe": ("list", "info", "find", "version")},
    "yum": {"reason": "system package manager", "safe": ("list", "info", "search", "repolist", "--version")},
    "dnf": {"reason": "system package manager", "safe": ("list", "info", "search", "repolist", "--version")},
    "pacman": {"reason": "system package manager", "safe_flags": ("-Q", "-Ss", "-Si", "--version")},
    "brew": {"reason": "package manager changing the system", "trigger": ("install", "uninstall", "upgrade", "reinstall", "remove")},
    "systemctl": {"reason": "service manager", "safe": ("status", "is-active", "is-enabled", "is-failed", "list-units", "list-unit-files", "list-timers", "show", "cat")},
    "service": {"reason": "service manager", "safe_last": ("status",)},
    "launchctl": {"reason": "macOS service manager", "safe": ("list", "print", "blame", "help")},
    "defaults": {"reason": "macOS preferences writer", "trigger": ("write", "delete", "import", "rename")},
    "systemsetup": {"reason": "macOS system settings", "safe_flags": ("-get", "-list")},
    "scutil": {"reason": "macOS system configuration", "safe_flags": ("--get", "--dns", "--proxy", "--nwi")},
    "reg": {"reason": "Windows registry editor", "trigger": ("add", "delete", "import")},
    "regedit": {"reason": "Windows registry editor"},
    "schtasks": {"reason": "Windows scheduled tasks (persistence)", "safe": ("/query",)},
    "sc": {"reason": "Windows service control", "trigger": ("create", "config", "delete")},
    "netsh": {"reason": "Windows network configuration", "safe_any": ("show",)},
    "bcdedit": {"reason": "Windows boot configuration"},
    "fdisk": {"reason": "partition tables"},
    "parted": {"reason": "partition tables"},
    "mount": {"reason": "mounts filesystems", "safe_noargs": True},
    "umount": {"reason": "unmounts filesystems"},
    "chattr": {"reason": "changes file attributes (immutability)"},
    "crontab": {"reason": "cron jobs (persistence)", "safe_any": ("-l",)},
}

OS_COMMAND_PREFIXES = {"mkfs": "creates a filesystem (destroys data)"}

# PowerShell registry cmdlets (matched when an argument names a registry hive).
POWERSHELL_REGISTRY_VERBS = ("set-itemproperty", "new-itemproperty", "remove-itemproperty",
                             "remove-item", "new-item")
REGISTRY_HIVE_PREFIXES = ("hklm:", "hkcu:", "hkcr:", "hku:", "hkey_")


def _norm_platform(plat):
    if plat.startswith("linux"):
        return "linux"
    if plat == "darwin":
        return "darwin"
    if plat in ("win32", "cygwin", "msys"):
        return "win32"
    return "linux"


def _expand(template, home, environ, win):
    out = template
    if out.startswith("~"):
        sep = "\\" if win else "/"
        out = home.rstrip("/\\") + out[1:].replace("/", sep) if win else home.rstrip("/") + out[1:]
    if "%" in out:
        for name in list(WINDOWS_ENV_DEFAULTS) + ["APPDATA"]:
            token = "%" + name + "%"
            if token in out:
                if name == "APPDATA":
                    default = home + "\\AppData\\Roaming"
                else:
                    default = WINDOWS_ENV_DEFAULTS[name]
                out = out.replace(token, environ.get(name) or default)
    return out


def os_entries(plat, home, environ):
    """Return built-in protected path entries for one platform.

    Each entry is {"path", "reason", "except"}; cross-platform items are
    included for every platform.
    """
    plat = _norm_platform(plat)
    win = plat == "win32"
    table = {"linux": LINUX_PATHS, "darwin": MACOS_PATHS, "win32": WINDOWS_PATHS}[plat]
    entries = []
    for path, reason, exc in list(table) + list(CROSS_PLATFORM_PATHS):
        entries.append({
            "path": _expand(path, home, environ, win),
            "reason": reason,
            "except": [_expand(e, home, environ, win) for e in exc],
        })
    return entries
