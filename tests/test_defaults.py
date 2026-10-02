"""The built-in OS tables are data: check their shape per platform."""
import guardrail_defaults as d

HOME = "/home/u"


def paths(entries):
    return [e["path"] for e in entries]


def test_every_entry_has_a_reason_on_every_platform():
    for plat in ("linux", "darwin", "win32"):
        entries = d.os_entries(plat, HOME, {})
        assert entries
        for e in entries:
            assert e["reason"].strip(), (plat, e)
    for c in d.CROSS_PLATFORM_COMPONENTS + d.SELF_COMPONENTS:
        assert c["reason"].strip()


def test_linux_table():
    ents = d.os_entries("linux", HOME, {})
    ps = paths(ents)
    for p in ("/etc", "/usr", "/bin", "/sbin", "/boot", "/sys", "/proc", "/dev",
              "/var/lib/dpkg", "/var/spool/cron", HOME + "/.config/autostart",
              HOME + "/.config/systemd", HOME + "/.bashrc"):
        assert p in ps, p
    dev = [e for e in ents if e["path"] == "/dev"][0]
    for ok in ("/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty"):
        assert ok in dev["except"]


def test_macos_table():
    ents = d.os_entries("darwin", HOME, {})
    ps = paths(ents)
    for p in ("/System", "/Library", "/usr", "/Applications", "/private/etc",
              HOME + "/Library/LaunchAgents", HOME + "/Library/Keychains",
              "/Library/LaunchDaemons"):
        assert p in ps, p
    usr = [e for e in ents if e["path"] == "/usr"][0]
    assert "/usr/local" in usr["except"]


def test_windows_table_uses_environment():
    ents = d.os_entries("win32", "C:\\Users\\u", {"SystemRoot": "D:\\Win", "ProgramData": "D:\\PD"})
    ps = paths(ents)
    assert "D:\\Win" in ps and "D:\\PD" in ps
    assert any("Startup" in p for p in ps)
    assert any("profile" in p.lower() for p in ps)


def test_cross_platform_entries_apply_everywhere():
    for plat in ("linux", "darwin", "win32"):
        ps = paths(d.os_entries(plat, HOME, {}))
        for sub in (".ssh", ".aws", ".gnupg", ".kube", ".gitconfig"):
            assert any(p.endswith(sub) for p in ps), (plat, sub)
        assert any(p.endswith("config.json") and ".docker" in p for p in ps)


def test_component_patterns_cover_git_and_settings():
    comps = [tuple(c["components"]) for c in d.CROSS_PLATFORM_COMPONENTS]
    assert (".git", "hooks") in comps and (".git", "config") in comps
    selfc = [tuple(c["components"]) for c in d.SELF_COMPONENTS]
    assert (".claude", "settings.json") in selfc
    assert (".claude", "settings.local.json") in selfc


def test_default_sensitive_globs():
    for g in ("**/.env", "**/.env.*", "**/*.pem", "**/id_rsa*", "**/id_ed25519*",
              "**/credentials", "**/.netrc", "**/.npmrc", "**/.pgpass", "**/*.kdbx"):
        assert g in d.DEFAULT_SENSITIVE_GLOBS


def test_os_command_table_has_required_verbs():
    for v in ("sudo", "doas", "su", "apt", "apt-get", "dpkg", "snap", "yum", "dnf",
              "pacman", "brew", "systemctl", "service", "launchctl", "defaults",
              "systemsetup", "scutil", "reg", "regedit", "schtasks", "sc", "netsh",
              "bcdedit", "fdisk", "parted", "mount", "umount", "chattr", "visudo",
              "crontab"):
        assert v in d.OS_COMMANDS, v
        assert d.OS_COMMANDS[v]["reason"]
