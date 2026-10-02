# agent-guardrail

A small, dependency-free PreToolUse hook for Claude Code (and any harness
that speaks the same hook protocol). It lets an AI coding agent work freely
on your files, and stops it at two kinds of line:

1. **OS-level changes** on Ubuntu, macOS and Windows (system directories,
   privilege escalation, package managers, services, scheduled tasks).
2. **Sensitive things you define** in a config file (paths, globs such as
   `.env`, and credential-looking content).

It is permissive by default: everything else is allowed silently, so the
agent is not stalled by prompts it does not need.

**What it is not:** a sandbox. It reads command text, and command text cannot
bound what a shell or interpreter will do. Treat it as accident prevention
and a first line of defence. For an actual boundary, pair it with an
OS-level layer; `tools/gen_sandbox.py` generates a starting point from the
same config. Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before
relying on it.

## Disclaimer

This project is provided as-is, MIT licensed: no warranty, and the author
is not liable for any damages arising from its use, including data loss or
file corruption. See [LICENSE](LICENSE). Test it in your own environment
before relying on it for anything that matters. It reduces risk; it does not
eliminate it, and it is not a substitute for backups.

## The three tiers

| Tier | What happens | Used for |
|---|---|---|
| **deny** | Hard block (exit 2). No override from inside the session. | The guard's own script, config and state directory, Claude Code `settings.json` files (where the hook is registered), and any user path with `"tier": "deny"` (the default). |
| **approve** | Blocked (exit 2) until a human approves that exact action in their own terminal. | OS-level paths and commands, sensitive globs such as `.env` and `*.pem`. |
| **ask** | Claude Code shows a permission prompt with a distinctive warning, **only in Manual (`default`) mode**. In every other mode, or if the mode is unknown, it is escalated to the `approve` flow (see below). | Uncertain cases: unparseable commands, interpreters (`python -c`), `source` of a protected file, `$VAR` in a write, credential-looking content. |
| *(none)* | Silent allow. | Everything else. |

The `ask` text is deliberately unlike Claude Code's routine prompts, so it
is not clicked through on reflex:

```
=== AGENT-GUARDRAIL WARNING (not a routine permission prompt) ===
Detected: <what the command or write does>
Rule: <which rule fired>
Could be damaged: <what is at risk>
Safer alternative: <what to do instead>
```

Every block message tells the agent what to do next, so a denial redirects
it instead of stalling it.

### Approving a blocked action

When an `approve` rule fires, the hook prints an approval id. In your **own
terminal** (not through the agent):

```bash
python hooks/guardrail_cli.py approve <id>
```

The CLI shows the full request, requires an interactive terminal and a typed
`yes`, then allows that exact action once. The approval expires after
`ttl_seconds` (default 600) and is consumed on use. Approvals are signed with
a key in the state directory. Other commands: `list`, `revoke <id>`, `doctor`.

Limit, stated plainly: a same-user agent that finds any unguarded way to write
a file, or to read the signing key, could forge an approval. An OS layer
(separate user, root-owned files, sandbox) closes that gap.

## Install

1. Clone this repository somewhere stable on disk. Python 3.8+, standard
   library only.
2. Create your config. Keep it outside the repository so real paths are
   never committed:

   ```bash
   mkdir -p ~/.config/agent-guardrail
   cp config/protected_paths.example.json ~/.config/agent-guardrail/protected_paths.json
   ```

3. Register the hook by hand in `~/.claude/settings.json` (all projects) or
   `<project>/.claude/settings.json`. See `config/settings.snippet.json`;
   replace the placeholder with the absolute path to
   `hooks/pretooluse_path_guard.py`. The guard protects those files from the
   agent, so it will not edit them for you.
4. Start a new Claude Code session, then run
   `python hooks/guardrail_cli.py doctor` to confirm the config is valid and
   the hook is registered and not paused.

With no config at all, the built-in OS-level and self protection still apply.

## Configuration reference

```json
{
  "protected_paths": [
    { "path": "~/critical/project", "reason": "why", "tier": "deny" }
  ],
  "sensitive_globs": ["**/.env", "**/*.pem"],
  "sensitive_content_patterns": ["internal-token-[a-z0-9]{16}"],
  "allow_paths": ["~/critical/project/docs"],
  "builtin_os_protection": true,
  "approval": { "ttl_seconds": 600 }
}
```

- `protected_paths`: `path` is expanded and resolved to its real path.
  `tier` is `deny` (default), `approve` or `ask`.
- `sensitive_globs`: tier `approve`. Setting it replaces the defaults
  (`.env*`, `*.pem`, `id_rsa*`, `id_ed25519*`, `credentials`, `.netrc`,
  `.npmrc`, `.pgpass`, `*.kdbx`).
- `sensitive_content_patterns`: extra regexes, tier `ask`, checked against
  the content of Write and Edit calls. Built-in patterns cover PEM private
  keys, AWS key ids and common provider token prefixes. There are no entropy
  rules and no network calls.
- `allow_paths`: narrows protection for a subtree. It never overrides the
  self-protection tier.
- `content_scan_timeout_seconds` (default 5): the time limit for scanning a
  write's content. If a pattern takes longer, the call is blocked (fail
  closed), which protects against a catastrophic user regex. It uses
  `SIGALRM`, so it is not available on Windows. Content over 1,000,000
  characters is only scanned at its start and end, and raises an `ask`
  saying so.
- Paths and globs in the config may not contain control characters (newline,
  tab and similar); such a config is rejected.
- `builtin_os_protection`: the per-OS tables in
  [hooks/guardrail_defaults.py](hooks/guardrail_defaults.py).
- Config lookup order: `AGENT_GUARDRAIL_CONFIG`, then
  `~/.config/agent-guardrail/protected_paths.json`, then
  `config/protected_paths.json` in this repository (git-ignored).
- `AGENT_GUARDRAIL_STATE_DIR` overrides where pending requests and approvals
  are stored.

A present but invalid config, malformed hook input, or any internal error
**fails closed** (exit 2). It never silently allows.

The built-in OS tables are this project's own compilation from general
operating-system knowledge: no authoritative, agent-oriented catalog exists.
Review them for your machines.

## Bash analysis

For `Bash` calls the hook splits compound commands (including newlines),
looks inside `bash -c` and command substitutions, unwraps `sudo`, `env`,
`xargs` and similar, strips harmless redirects such as `2>/dev/null`, and
resolves the target arguments of **recognised** write commands (`rm`, `mv`,
`cp`, `tee`, `sed -i`, redirects and similar) to their real path before
checking containment. Prefix matching uses path-component boundaries on real
paths, so `/protected-evil` does not match `/protected`.

Commands the hook does not recognise are only caught when their text names a
protected location, and then they raise an `ask`. That includes interpreter
one-liners (`python -c`), and `source` or `.` of a file inside a protected
location. The contents of a sourced script are never inspected.

This is best-effort. No static analysis can list every way a shell or
interpreter can write a file.

### Which tools are checked

Any tool call that carries a `file_path`, `notebook_path` or `path` field is
treated as a file write, so `MultiEdit` and MCP write tools are covered, and
the contents of `MultiEdit` edits are scanned for credentials. `Read`,
`Glob`, `Grep` and `LS` are not. The hook only runs for tools your
`settings.json` matcher lists, so widen the matcher (see
`config/settings.snippet.json`) to include `MultiEdit` and the MCP tools you
use. `python hooks/guardrail_cli.py doctor` warns when the matcher covers none
of the guarded tools.

## OS layer

```bash
python tools/gen_sandbox.py bwrap      # Linux (bubblewrap)
python tools/gen_sandbox.py seatbelt   # macOS (sandbox-exec)
python tools/gen_sandbox.py windows    # WSL2 advice and icacls recipe
```

The tool only prints text and never runs anything. Output is a starting
point that is **not tested on your system**: review it before use.

## Testing

```bash
pip install pytest
python -m pytest
```

Tests run the hook as a subprocess against an isolated HOME, config and state
directory, so they never touch your real environment. The suite has been run
on Linux only; macOS and Windows behaviour is covered by CI configuration but
has not been verified by hand.

## Evidence and verification status

The design choices (fail closed, OS layer as the boundary, command text as
accident prevention, self-protection) rest on a literature and vendor-docs
review. [docs/DESIGN_RATIONALE.md](docs/DESIGN_RATIONALE.md) lists what is
primary-source verified, what is a preprint, and which figures are vendor
claims without methodology. The older source list is in
[REFERENCES.md](REFERENCES.md).

## License

MIT. See [LICENSE](LICENSE).
