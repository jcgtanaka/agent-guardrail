# References

This design was built on a literature and industry review, not a single
source. The full research process ran five parallel, independent research
threads (capability theory, formal verification, shipped-product sandboxing,
documented bypass and incident cases, and open-source framework practice),
then a synthesis pass that looked specifically for where sources disagreed
and where they converged despite that disagreement. The convergent points,
not any single source, drove the concrete decisions in this repository (see
the table below).

Where an individual author could not be confirmed from the underlying
research notes, the organization is cited as author instead, per APA style
for corporate authorship. Sources marked "not independently verified" were
found only by title or abstract during research and could not be confirmed
against their full text; they are listed for completeness, not relied on for
any specific claim in this repository.

## Design decisions and their sources

| Design decision in this repository | Source |
|---|---|
| A hard, non-configurable deny layer runs before the configurable allow/deny/ask rules | Anthropic (n.d.-a); Anysphere (n.d.-a); *ScopeGate* (2026) |
| Every path is resolved to its real, symlink-free target before a containment check | Cymulate (2025) |
| A destructive Bash command with an unresolvable shell-variable target is asked about, not silently allowed or silently blocked | Anthropic (n.d.-b); Watson (2026) |
| The real protected-paths config lives outside the published repository | endolith (2023) |
| docs/THREAT_MODEL.md states plainly that credential and API misuse is out of scope | The Register (2025, 2026); Zenity (2026) |
| Every protected-path test has a matching disguised-access (symlink) test | Open Policy Agent (n.d.) |

## Formal verification and capability theory

Miller, M. S. (2006). *Robust composition: Towards a unified approach to
access control and concurrency control* [Doctoral dissertation, Johns
Hopkins University]. http://erights.org/talks/thesis/markm-thesis.pdf

*Risk-aware capability gating for LLM agent tool use* [RACG]. (2026). arXiv.
https://arxiv.org/html/2606.13884v1

*ScopeGate: A five-stage policy decision and enforcement point for AI agent
authorization*. (2026). arXiv. https://arxiv.org/html/2606.28679v1

*MI9: Just-in-time authorization for autonomous agents*. (2025). arXiv.
https://arxiv.org/pdf/2508.03858

*VeriGuard: Enhancing LLM agent safety via verified code generation*.
(2025). arXiv. https://arxiv.org/abs/2510.05156

*ActGov: Formally verified action governance for AI agents*. (2026). arXiv.
https://arxiv.org/html/2609.24446

*Solver-aided verification of AI agent access policies*. (2026). arXiv.
https://arxiv.org/html/2603.20449v1

*CAPMAS: Capability-based, attenuation-only delegation for multi-agent
systems*. (2026). arXiv. https://arxiv.org/pdf/2609.06500

Cook, B., et al. (2018). *Semantic-based automated reasoning for AWS access
policies using SMT* [Zelkova]. Amazon Science.
https://www.amazon.science/publications/semantic-based-automated-reasoning-for-aws-access-policies-using-smt

Watson, A. (2026, September 10). *What we have learned applying formal
methods to control AI agents*. OpenShell Research, NVIDIA.
https://nvidia.github.io/OpenShell-Research/dev-notes/posts/2026-09-10-learning-formal-methods-agent-policy-prover/

## Shipped coding-agent products

Anthropic. (n.d.-a). *Configure permissions*. Claude Code Documentation.
https://code.claude.com/docs/en/agent-sdk/permissions

Anthropic. (n.d.-b). *Choose a permission mode*. Claude Code Documentation.
https://code.claude.com/docs/en/permission-modes

Anthropic. (n.d.-c). *How we contain Claude*. Anthropic Engineering.
https://www.anthropic.com/engineering/how-we-contain-claude

Anysphere. (n.d.-a). *sandbox.json reference*. Cursor Documentation.
https://cursor.com/docs/reference/sandbox

Anysphere. (n.d.-b). *Agent sandboxing*. Cursor Blog.
https://cursor.com/blog/agent-sandboxing

Cognition AI. (n.d.). *Sandbox*. Devin Documentation.
https://docs.devin.ai/cli/sandbox

All Hands AI. (n.d.). *Docker sandbox*. OpenHands Documentation.
https://docs.openhands.dev/openhands/usage/sandboxes/docker

Aider. (n.d.). *FAQ*. https://aider.chat/docs/faq.html

Cosmonic. (n.d.). *AI sandbox guide*. Cosmonic Blog.
https://cosmonic.com/blog/ai-sandbox-guide/

## Real incidents and red-teaming

AI Incident Database. (2025). *Incident 1152: Replit AI agent deletes
production database*. https://incidentdatabase.ai/cite/1152/

The Register. (2025, July 21). *Replit's AI coding assistant deleted a
production database mid code freeze*.
https://www.theregister.com/2025/07/21/replit_saastr_vibe_coding_incident/

The Register. (2026, April 27). *Cursor's Opus agent snuffs out PocketOS
database and backups*.
https://www.theregister.com/2026/04/27/cursoropus_agent_snuffs_out_pocketos/

Zenity. (2026). *AI agent database deletion: The PocketOS incident*.
https://zenity.io/blog/current-events/ai-agent-database-deletion-pocketos

*Red-teaming the agentic red-team*. (2026). arXiv.
https://arxiv.org/html/2606.24496

Cymulate. (2025). *CVE-2025-53109 and CVE-2025-53110: EscapeRoute in
Anthropic's filesystem MCP server*. Cymulate Blog.
https://cymulate.com/blog/cve-2025-53109-53110-escaperoute-anthropic/

## Open-source framework practice

Open Policy Agent. (n.d.). *Conftest* [Software repository]. GitHub.
https://github.com/open-policy-agent/conftest

endolith. (2023). *safe_mode setting silently overridden by argparse
defaults* (Issue No. 312) [GitHub issue]. Open Interpreter.
https://github.com/endolith/open-interpreter/issues/312

Emergentmind. (n.d.). *Automated permission management for AI agents*.
https://www.emergentmind.com/topics/automated-permission-management-for-ai-agents

## Not independently verified

Found by title or abstract only during research; not fetched or confirmed
in full text, and not the basis for any specific claim in this repository.

*Fundamental limits of runtime policy enforcement in multi-agent AGI
systems*. (n.d.). ACM.

*Open challenges in multi-agent security*. (2025). arXiv:2505.02077.

*Agent safety should be a runtime contract*. (2026). arXiv:2608.11274.

*Why formal monitors fail*. (2026). arXiv:2608.01388.
