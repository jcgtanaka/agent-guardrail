# Changelog

## Unreleased

### Added
- Three enforcement tiers: `deny`, `approve` (out-of-band human approval) and
  `ask` (distinctive warning), on top of a silent allow for everything else.
- Built-in OS-level protection tables for Linux, macOS and Windows, plus
  OS-level command verbs (privilege escalation, package managers, services,
  scheduled tasks, registry edits).
- Sensitive globs and credential-pattern scanning of Write/Edit content.
- Self-protection: the guard's own files, config, state directory and the
  Claude Code `settings.json` files are hard-denied.
- `hooks/guardrail_cli.py` with `approve`, `list`, `revoke` and `doctor`.
- `tools/gen_sandbox.py`, which prints bubblewrap, Seatbelt and
  Windows/WSL2 starting points from the same config.
- Shell-aware Bash analysis: compound commands, newlines, `bash -c`,
  command substitution and common wrappers.
- CI workflow running the tests on Linux, macOS and Windows.

### Changed
- A missing config no longer disables the hook: built-in OS-level and
  self protection still apply.
- Block decisions use exit code 2 instead of a JSON deny with exit 0.
- Corrupt config, malformed input and internal errors now fail closed.
- Harmless redirects (`2>/dev/null`, `>/dev/null`, `2>&1`) are ignored, while
  a real redirect to a protected path is still caught.
- Relative paths and bare filenames are resolved against the working
  directory, so `rm file` inside a protected directory is caught.

### Fixed
- `2>/dev/null` no longer triggers a false positive on read-only commands.
