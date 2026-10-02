# Design rationale and evidence status

This explains why the guard is built the way it is, and how much each
supporting claim should be trusted. Claims are graded:

- **Primary-verified**: read on the primary page (vendor docs, NVD, GitHub
  advisory, arXiv abstract page).
- **Preprint**: an arXiv paper with no peer-review venue shown on its page.
- **Vendor claim**: a statistic published by a vendor without methodology.
- **Own compilation**: written by this project from general knowledge, with
  no authoritative source.

## Decisions and their support

### Command text is accident prevention, not a boundary
- Anthropic's Claude Code permissions documentation states that a Bash deny
  or ask rule is not a security boundary around the program, and lists forms
  that slip past it (`/bin/rm`, `bash -c`, `git -C`). *Primary-verified.*
- ShellSieve (arXiv 2606.15549, "One Goal, Many Commands: Characterizing
  Denylist Fragility in AI Agents") reports that 69.0 to 98.6 percent of
  1,709 real agent denylists miss at least one validated bypass. *Preprint.*
  The paper is internally inconsistent about the count: 1,709 appears in the
  abstract and most places, 1,731 once in the introduction. Both are paired
  with 13,332 rules; this project cites 1,709.
- CARE (arXiv 2607.21642), a pre-execution command verifier, reports far
  better results than regex guards and says it complements sandboxing rather
  than replacing it. Accepted at ISSRE 2026 per its arXiv comments. Part of
  its gain comes from an LLM judge, so it does not transfer to a purely
  static guard.

Consequence: the hook never claims to be a sandbox, uncertain commands raise
an `ask` instead of being allowed, and `tools/gen_sandbox.py` exists.

### An OS layer is the actual boundary
- Vendors, security firms and the papers above agree that kernel-level
  enforcement (bubblewrap, Seatbelt, ACLs, containers) is what bounds
  behaviour, and that parsing and hooks are friction reduction and defence
  in depth. No source found argues that a parser alone suffices against an
  adversary.
- Landlock is allow-list only and cannot express "write everywhere except X"
  as a deny rule; bubblewrap can, by mounting protected paths read-only on
  top. *The Landlock point is derived from the allow-list model in the kernel
  documentation; the bubblewrap mount ordering was not verified on a live
  system, which is why the generator output is labelled untested.*
- Claude Code's built-in sandbox covers Bash but not its file-edit tools, and
  is not supported on native Windows (WSL2 only), per its documentation.
  *Primary-verified.*

### Fail closed
- A guard that crashes or cannot parse must deny. The CVE-class evidence:
  CVE-2025-53109's symlink check failed open when `realpath` raised, and
  Claude Code once skipped deny rules after 50 subcommands. *The first is
  primary-verified via NVD and the GitHub advisory; the second rests on a
  single security-firm write-up.*

### Path checks: real paths and component boundaries
- CVE-2025-53110 was a plain string prefix check on the allowed directory,
  so `/allowed-evil` matched `/allowed`. CVE-2025-54794 repeated the pattern
  in Claude Code. Fixed in 2025.7.1 for the filesystem server (NVD says
  0.6.4 where GitHub and the researchers say 0.6.3 for the npm package; the
  `2025.7.1` figure is consistent across all three). *Primary-verified.*
- CVSS scores differ by scorer: GitHub's CVSS 4.0 scores sit lower than NVD's
  CVSS 3.1 scores for the same CVEs. Always name the scorer and version.

### Self-protection of the guard
- Observed in practice: Claude Code's auto-mode classifier refused an agent
  edit of the guard's own config as "Self-Modification", even though the user
  had approved the edit in chat; the change had to be made by the user in
  their own terminal.
- Protecting the guard from the same surface the agent can write is fragile:
  hooks can fail open, and their registration lives in a file the agent can
  write. Robust options keep the config out of the agent's reach (managed
  settings, root-owned files, OS read-only paths, out-of-band human edits).
  The guard therefore denies writes to its own files and to the Claude Code
  settings files, and tells you to edit them by hand. Closing the gap fully
  needs the OS layer.
- Progent (arXiv) makes the same asymmetry: narrowing a policy is automatic,
  expanding one needs a human. *Preprint.*

### Three tiers and out-of-band approval
- Vendors report that users approve about 93 percent of permission prompts,
  and that sandboxing reduced prompts by 84 percent. *Vendor claims, no
  methodology or sample size published.*
- A 113-participant preprint found user-authored policies blocked less
  overreach than per-action approval because users wrote mostly "ask" rules.
  *Preprint.*
- Both camps converge on the practical point that approval works when it is
  rare and attached to a specific privilege expansion. Hence: hard deny for
  the guard itself, human approval of one exact action for OS-level and
  sensitive cases, and a distinctive `ask` for genuine uncertainty.

### Content-level protection
- Scanning the incoming Write and Edit text with a small high-precision
  pattern set is practical in a pre-write hook. Entropy rules are excluded
  because they flag hashes and fixtures, and verifying scanners are excluded
  because verification sends the candidate secret over the network. It
  cannot catch encoded or split secrets, Bash exfiltration or reads.
  *Reasoned from scanner documentation; false-positive figures come from
  vendor blogs and repo-history scans, not agent diffs.*

### Default protected sets
- Claude Code protects `.git`, `.claude`, shell rc files and similar by
  default, but ships no OS-level path list such as `/etc`. *Primary-verified.*
- The per-OS lists in `hooks/guardrail_defaults.py` are an **own
  compilation**. Apple and Microsoft document their protected areas (SIP and
  the sealed system volume; Controlled Folder Access), but no authoritative
  agent-oriented catalog exists. Review the lists for your machines.

## What remains unverified

- The full text of the Five Eyes agentic-AI adoption guidance, NIST SP
  800-53 AC-6 mapping, and CIS control lists were not opened.
- Behaviour on macOS and Windows: the test suite has been run on Linux only.
- What a hook's JSON `ask` does outside Manual mode is not stated in the
  documentation (the hooks reference lists `permission_mode` and its values
  but does not say how `ask` interacts with `auto` or `bypassPermissions`).
  Observed once, on one machine: in `auto` mode a Write containing a
  credential-looking string went through with no prompt, although the hook
  had returned `ask`. The guard therefore trusts a native `ask` only in
  `default` mode, escalates it to the out-of-band `approve` flow in every
  other or unknown mode, and uses exit 2 (documented as unconditional) for
  every block.
- The bubblewrap mount ordering and Seatbelt rule precedence in the generated
  output.

See also [REFERENCES.md](../REFERENCES.md) for the original source list.
