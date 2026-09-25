# agent-guardrail

A small, dependency-free PreToolUse hook for Claude Code (and any harness
that speaks the same hook protocol) that hard-blocks an AI agent from
editing or deleting files inside paths you mark as protected, even if a
permissive `settings.json` rule, a permission mode, or a bypass flag would
otherwise allow it.

It exists for one specific problem: an agent with broad, legitimate access
to your home directory should still never be able to touch the handful of
directories where a mistake would actually hurt (your OS files, a
production strategy, a client's codebase), no matter what else is
configured or approved in the moment.

Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before relying on this.
It states plainly what this tool does and does not protect against.

## Disclaimer

This project is provided as-is, MIT licensed: no warranty, and the author
is not liable for any damages arising from its use, including data loss or
file corruption. See [LICENSE](LICENSE) for the full terms. Test it in
your own environment against your own use case before relying on it for
anything that matters. It reduces risk; it does not eliminate it, and it
is not a substitute for backups.

## Why a hook and not just a settings.json deny rule

A `settings.json` deny rule is easy to add and easy to lose: it can be
overridden by a later rule, skipped in a permission mode, or bypassed
entirely by a bypass-permissions flag. Every AI coding agent examined
while designing this tool (Claude Code, Cursor, Devin, OpenHands)
independently converged on the same structural answer: put the real
protection in a layer that sits below configuration and cannot be turned
off by it. Claude Code's own hooks run before its allow/deny/ask
evaluation, which is exactly the property this tool relies on.

A naive path check is also not enough on its own. CVE-2025-53109 and
CVE-2025-53110 ("EscapeRoute", found in Anthropic's own filesystem MCP
server) show that a literal string-prefix comparison can be defeated by a
symlink created inside an allowed directory that points at the protected
one. This tool resolves every path to its real, symlink-free target before
checking containment, and the test suite includes that exact symlink
scenario as a required case, not an afterthought.

## What it does

For every `Edit`, `Write`, `NotebookEdit`, or `Bash` tool call:

1. Resolve the real target path (or, for `Bash`, every path-like token in
   the command) to its canonical, symlink-free form.
2. If it falls inside a configured protected path, deny the call outright.
3. For a destructive `Bash` command whose target cannot be statically
   resolved (it depends on a shell variable or command substitution, such
   as `rm -rf "$DIR"/*`), ask for human confirmation instead of guessing.
4. Otherwise, say nothing and exit cleanly, leaving the decision to Claude
   Code's normal permission flow.

If no protected paths are configured, the hook is a silent no-op. See
docs/THREAT_MODEL.md for what "protected" does and does not cover.

## Install

1. Copy or clone this repository somewhere stable on disk.
2. Create your own protected-paths config. It is deliberately kept outside
   the repository so your real paths are never accidentally committed:

   ```bash
   mkdir -p ~/.config/agent-guardrail
   cp config/protected_paths.example.json ~/.config/agent-guardrail/protected_paths.json
   ```

   Edit that file and list the absolute paths (`~` is expanded) you never
   want an agent to write to or delete.

3. Register the hook in Claude Code's settings. Use
   `~/.claude/settings.json` if you want protection across every project
   on this machine, or `<project>/.claude/settings.json` for a single
   project only. See `config/settings.snippet.json` for the exact shape;
   replace the placeholder command path with the real, absolute path to
   `hooks/pretooluse_path_guard.py` on your machine.

4. Restart Claude Code (or start a new session) so it picks up the hook.

## Configuration reference

`protected_paths.json`:

```json
{
  "protected_paths": [
    { "path": "~/some/critical/project", "reason": "why this is protected" }
  ]
}
```

- `path` is expanded (`~` becomes your home directory) and resolved to its
  real path at check time, so a symlinked path still resolves correctly.
- `reason` is for your own documentation; it is not used by the hook logic.
- The config is looked up in this order: the `AGENT_GUARDRAIL_CONFIG`
  environment variable if set, then `~/.config/agent-guardrail/protected_paths.json`,
  then `config/protected_paths.json` inside this repository (not shipped,
  and git-ignored, so you can use it as a local alternative to the
  home-directory location if you prefer keeping it next to the hook).

## Testing

```bash
pip install pytest
pytest tests/ -v
```

Every protected-path test has a matching disguised-access test (a symlink,
for the filesystem tools). If you extend this tool, extend both together:
a rule that only has a positive test can silently regress.

## Scope

This tool answers one question: does this specific tool call touch a path
I marked protected? It does not replace Claude Code's own `ask` permission
tier for judgment calls that are not about a fixed path (a force-push, an
unfamiliar `curl` call, and so on): configure those directly in
`settings.json`. It also does not scope credentials or API tokens; that is
a separate, equally necessary layer covered in
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## References

This design is grounded in a literature and industry review, not a single
source. See [REFERENCES.md](REFERENCES.md) for the full source list in APA
format, including a table mapping each design decision in this repository
to the source that drove it.

## License

MIT. See [LICENSE](LICENSE).
