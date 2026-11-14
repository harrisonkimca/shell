# AGENTS.md

Shell is a forkable, passwordless authentication and database foundation.
Its only normative design files are [README.md](README.md),
[docs/architecture.md](docs/architecture.md),
[docs/spec/auth.md](docs/spec/auth.md), [docs/roadmap.md](docs/roadmap.md)
and [docs/decisions.md](docs/decisions.md); where anything else disagrees,
they win. Files under `docs/evidence/` are historical records, not active
design requirements, completion evidence or mandatory agent reading.

## Rules

- Plan the whole stage first: dependency-ordered slices, requirement IDs
  and verification parts, files, tests, CI checks and exit criteria.
  Stop for owner approval. The approved plan lives in the stage's
  GitHub issue.
- One slice per branch, `stage-N/<slice>`, the last `stage-N/exit`.
  Build only the approved slice. Plan changes need owner approval.
- Tests first, tagged with their requirement IDs as described in
  [Requirement tests](docs/guides/requirement-test.md).
- Small commits. Never bypass the commit hooks: no `--no-verify`.
- Imports follow [arch §14](docs/architecture.md#14-import-rules),
  errors [arch §10](docs/architecture.md#10-error-model). No secrets in code.
- Push implementation branches and open pull requests. Never merge,
  change repository rules, create completion or correction tags.
- Plan and build the simplest solution that satisfies the
  requirements. Prefer existing tools and direct solutions.
  Add abstractions, dependencies and mechanisms only when
  needed. Minimize maintenance and operational burden without
  weakening correctness, security, verification or enforcement.

## What you may change

| Group | Files | You |
|---|---|---|
| Design and agent rules | `README.md`, `docs/`, `AGENTS.md`, `CLAUDE.md`, `.claude/`, `.codex/` | Never edit, except the guide below. Report any needed change to the owner. |
| Repository governance | `.github/` apart from `.github/workflows/` | Never edit. |
| Gates | `.github/workflows/`; `.pre-commit-config.yaml`; tool and test settings in `pyproject.toml`; quality-gate and requirement-trace scripts, inventories and tests; scanner configuration; dependency, tool and action pins | Build and extend as the stage requires. |
| Fork guide | `docs/guides/adding-a-feature.md` | Build in stage 6 and maintain with its tested example. |
| Everything else | Code, tests, configuration, routine lockfile updates | As the stage requires. |

## Gate changes

- Add each CI check in the slice that makes it runnable. No check passes
  without testing something. Every applicable check, including a new one,
  must be covered by the aggregate required CI gate; missing, skipped or
  failed required checks fail it.
- List every gate change in the pull request, with its reason.
- Any weakening of coverage or enforcement, including through code or
  test changes, needs explicit owner approval. Green CI is not approval.
- A design requirement cannot be relaxed by approving a gate change.

## Stage loop

Follow [the workflow runbook](docs/guides/workflow.md). Read the approved
stage plan before building each slice. Stop when a prerequisite fails or
the design needs a change; do not work around it.

## Guides

- [Requirement tests](docs/guides/requirement-test.md)
- [New use case](docs/guides/new-use-case.md)
- [Alembic migration](docs/guides/alembic-migration.md)
