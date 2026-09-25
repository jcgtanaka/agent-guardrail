# Threat model

This document says plainly what agent-guardrail protects against, and what
it does not. Publishing a security tool without this section is how people
end up trusting a config more than it deserves. If you only read one file
before using this project, read this one.

## What it protects against

- An AI coding agent (Claude Code, or any tool that speaks the same
  PreToolUse hook protocol) using `Edit`, `Write`, or `NotebookEdit` to
  modify a file inside a path you marked protected.
- The same agent deleting, moving, or overwriting a file inside a
  protected path through a `Bash` command (`rm`, `mv`, `dd`, `shred`,
  `truncate`, `unlink`, an overwrite redirect, `git clean`, or
  `git reset --hard`).
- A symlink created inside an allowed directory that points at a
  protected directory (the class of bug behind CVE-2025-53109 and
  CVE-2025-53110, "EscapeRoute", in Anthropic's own filesystem MCP
  server). Paths are resolved to their real, symlink-free target before
  any containment check.
- A destructive Bash command whose target cannot be statically resolved
  because it depends on a shell variable or command substitution
  (`rm -rf "$DIR"/*`). Rather than guess, the hook asks for human
  confirmation instead of silently allowing it.

## What it does NOT protect against

- **Destructive API or credential misuse.** This tool only inspects
  filesystem-facing tool calls. If an agent has a broadly-scoped API
  token (cloud provider, database, trading broker) and uses it to delete
  or corrupt something remotely, this hook never sees it. Two real 2025
  and 2026 production incidents (a Replit agent deleting a production
  database, and a Cursor agent deleting a Railway database and its
  backups) were both credential-scoping failures, not filesystem
  failures. Scope your credentials separately and narrowly; this tool is
  not a substitute for that.
- **Tools outside the PreToolUse hook flow.** If you give a local model
  (Ollama, or any other agent) its own script with direct filesystem
  access, outside of Claude Code's tool-call flow, this hook never runs.
  It only fires for tool calls that go through a harness that invokes it
  as a PreToolUse hook.
- **Context and intent.** A rule that blocks writes to a directory blocks
  ALL writes to it, including ones you would have wanted. This tool
  cannot tell a throwaway test repo from a production one if you protect
  the wrong path, and it cannot tell "this edit is fine" from "this edit
  is dangerous" within a path you did not mark protected. It enforces a
  boundary you drew; it does not draw the boundary for you.
- **Multi-agent composition.** If you run several agents or sub-agents
  together, each individually configured safely, their combination can
  still exceed what any single one was meant to do (for example, one
  agent hands a capability to another that then uses it outside the
  first agent's intended scope). This tool checks each tool call in
  isolation; it does not reason about a multi-agent system as a whole.
- **A determined, adversarial agent operating outside its own harness.**
  This is a guardrail for an agent that is fundamentally cooperating
  with its own tool-call protocol, not a sandbox boundary enforced by
  the operating system. If you need that stronger guarantee, pair this
  tool with OS-level or container-level sandboxing (a restricted user
  account, a container with a read-only bind mount, gVisor, Firecracker,
  or similar).
- **Read access.** By design, this tool only inspects writing and
  deleting tools. It does not block an agent from reading a protected
  path.

## Design principle

Protection lives in the hook, which runs before Claude Code's own
allow/deny/ask rules and cannot be overridden by a permissive rule, a
permission mode, or a bypass-permissions flag. A `settings.json` rule
alone is not enough: it can be disabled, forgotten, or bypassed by
whatever mode is active. See the main README for the reasoning and
sources behind this design.

If a protected path is not configured (no `protected_paths.json` file is
found), this tool does nothing. It is not a default-on system boundary;
it only protects what you explicitly tell it to.
