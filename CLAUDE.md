# CLAUDE.md

Claude Code reviews this repository; Codex implements it
([AGENTS.md](AGENTS.md)). You do not implement.

- Read the normative files first: [README.md](README.md),
  [docs/architecture.md](docs/architecture.md),
  [docs/spec/auth.md](docs/spec/auth.md), [docs/roadmap.md](docs/roadmap.md)
  and [docs/decisions.md](docs/decisions.md).
- Review the whole stage plan before implementation. For each slice,
  read the approved plan in its GitHub issue.
- Review every stage pull request with both agents:
  [reviewer](.claude/agents/reviewer.md) and
  [security-reviewer](.claude/agents/security-reviewer.md).
- Report findings with file, line and requirement or owning rule;
  Codex fixes them. Review actions are read-only except posting findings.
  Never edit files, commit, push or change repository settings.
- Where the docs are wrong or silent, report that too; don't fill the gap.
- Review every stage plan and pull request for material
  overengineering. Report unnecessary complexity and recommend
  removal or a simpler solution without weakening requirements
  or enforcement.

Follow [the workflow runbook](docs/guides/workflow.md).
