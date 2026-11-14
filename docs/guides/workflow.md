# Workflow runbook

How each roadmap stage is planned, built, checked and completed. Codex
builds; Claude Code reviews; I approve plans, run owner checks, manage
branches and repository rules, merge and tag.

Rules for the agents: [AGENTS.md](../../AGENTS.md), [CLAUDE.md](../../CLAUDE.md).

## The loop

Steps 1–3 run once per stage, steps 4–8 once per slice, step 9 once
after the last slice.

| # | Who | Model, effort | Step |
|---|---|---|---|
| 1 | Me | — | Update `main`. Open a stage issue and confirm the preceding stage is complete. |
| 2 | Codex | High | Plan the whole stage; stop for approval. |
| 3 | Claude Code | Fable, High | Plan review. Problems → Codex revises. None → I record and approve the plan in the stage issue. |
| 4 | Me; Codex | High for stages 1–3, 5–6, 8; Medium for 0, 4, 7 | I branch from current `main`. Codex builds the approved slice tests-first, adds runnable CI checks, runs tests, pushes and opens the PR. Owner checks run when needed. |
| 5 | Claude Code | see below | Review the PR with both agents; post findings with `gh pr comment`. |
| 6 | Codex | as step 4 | Fix findings and push; CI reruns. |
| 7 | Claude Code | Opus 5.5, Medium | Check the fixes and latest CI results. Repeat review and fixes until clear. |
| 8 | Me | — | Confirm review, CI and any explicit gate-weakening approval. Merge and update `main`. |
| 9 | Me | last slice only | Verify stage completion on the exact final `main` revision, tag it `stage-N`, confirm tag CI passes and sync the project context. |

Step 5 reviews (switch with `/model` in Claude Code):

| Stages | reviewer | security-reviewer |
|---|---|---|
| 1, 2, 3, 5, 6, 8 | Opus 5.5, High | Fable, High |
| 0, 4, 7 | Opus 5.5, Medium | Opus 5.5, High |

## Stage plan

The approved plan lives in one GitHub issue per stage. It assigns
requirements, deferred verification parts, checks and exit criteria
to dependency-ordered slices, including owner-run prerequisites.
Each slice PR links to it. Only I approve and amend the plan.

Branches are `stage-N/<slice>`, the last `stage-N/exit`, which contains
the stage's remaining work. Start each from current `main`:

    git checkout main
    git pull --ff-only
    git checkout -b stage-N/<slice>

## Prompts

**Step 2 (Codex):** Plan roadmap stage N following AGENTS.md.
Choose the simplest sufficient implementation.
Split it into small, coherent slices in dependency order, each with
requirement IDs and parts, files, tests, CI checks and prerequisites.
Assign every exit criterion. Stop for approval.

**Step 3 (Claude Code):** Review the stage N plan against the normative
files and agent rules. Check scope, dependency order, requirement coverage,
verification timing, risks and overengineering. Recommend simpler solutions
where possible without weakening requirements or enforcement.
List problems only: [plan]

**Step 4 (Codex):** Build slice <name> of stage N following the approved
plan in [issue] and AGENTS.md. Stop at any unmet prerequisite.

**Step 5 (Claude Code):** Review [PR] against the approved plan in [issue].
Run `gh pr checks` and `gh pr diff`. Use both reviewer agents. Post findings
with `gh pr comment`.

**Step 6 (Codex):** Fix these review findings and push: [findings]

**Step 7 (Claude Code):** Check that the latest revision resolves both
reviews and CI is green. Report anything still open: [findings]

## Verification and completion

I run spikes and other owner checks before dependent work or the review
that needs their results. Record the result, tested revision or artifact,
environment and evidence in the stage issue. Re-run a check when a
change invalidates its result. A failed spike follows the design's stated
fallback or stops the dependent work.

Before merging, confirm the aggregate required check `ci` covers and
passes every applicable check on the latest revision, including new checks.
Missing, skipped or failed required checks fail the aggregate. Gate
weakening needs my explicit recorded approval before review can clear it.

    gh pr merge --merge --delete-branch
    git checkout main
    git pull --ff-only

After the last slice, run CI's stage-completion check for stage N on the
exact final `main` revision; CI enforces cumulative automated verification,
including deferred parts due now. Separately, I confirm every required
owner-run check and exit criterion in the stage issue, including the tested
revision/artifact, environment and evidence. Missing, skipped or failed
required verification blocks completion. I confirm owner-run results remain
valid for the final revision and rerun anything invalidated; CI does not
ingest these records. Only then:

    git tag stage-N
    git push origin stage-N

If completion fails, fix it through another `stage-N/exit` PR and
repeat verification. Never move or delete tags; if a tagged revision
needs fixing, use `stage-N-r2`, `stage-N-r3`, and so on. A stage is
complete only after my owner-run confirmation and its completion tag passes
the aggregate CI gate and automated stage-completion verification.
Correction tags meet the same requirements.

## Where things happen

- Codex and Claude Code: fresh sessions, using the approved stage issue.
- Questions, decisions and interpreting findings: the Shell_Build chat.
- Design or governance changes: I make them through a `docs-` PR, or
  on the slice branch when code and design must change together. Then
  sync the project context and amend affected plans.

## Gates

- Commit hooks (`pre-commit install`, once per clone): fast checks.
- CI: all implemented checks on every push and pull request, including
  merges to `main`; cumulative automated stage verification on completion tags.
- `main` ruleset: PR required, merge commits only, no force push or
  deletion. Only I merge. Once stage 0 introduces it, I require the single
  aggregate check `ci`; adding checks thereafter does not change the ruleset.
  It covers every applicable check and runs on pushes, PRs, `main`, exact
  revision completion runs and completion/correction tags. Validate that
  new checks are included; required checks must run and pass.
- Only I change rulesets or create immutable completion and correction
  tags. Never move or delete a completion tag.
