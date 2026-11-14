# Requirement tests

Every row in [spec/auth.md](../spec/auth.md) is proved by its required
verification kinds, identified by its requirement ID.

1. Read the row. *Acceptance* is what must be proved; *Verification*
   is where it is proved:
   - unit test: on fakes, mirroring the module;
   - integration suite: against the real stack, with real Ory from stage 1;
   - configuration check: a test of settings, startup or grants, or
     an inspection of the deployed environment;
   - hands-on check or load test: owner-run verification.
2. Write the automated test, see it fail for the right reason, then build.
3. Tag it. Pytest uses `req` markers; other runners associate their test
   names with the requirement IDs in test metadata. Results identify the
   ID, verification kind and any named verification part. Reuse the
   runner's standard reports (for example JUnit XML); add only metadata
   needed to associate results. Do not build a custom reporting framework.

```python
@pytest.mark.req("AUTH-CODE-004")
async def test_resend_within_60_seconds_sends_nothing(sender, clock, outbox) -> None:
    await sender.send_code(to=ADDRESS, purpose="sign_in", code="123456", locale="en")
    clock.advance(seconds=59)
    await sender.send_code(to=ADDRESS, purpose="sign_in", code="654321", locale="en")
    assert outbox.count(to=ADDRESS) == 1
```

- Assert the Acceptance line's exact values. For elapsed-time checks,
  use an injected clock in Shell or controlled provider time. If the
  provider's time cannot be controlled, check its exact production
  settings and exercise the same behaviour with shorter test-only
  lifetimes against the real provider.
- One behaviour per test, named for the behaviour, not the ID.
- Synthetic data only (NFR-010).
- Name separately verified parts, including those due in later stages.
  Requirements covering a growing set are checked as members are added.
- Keep only the inventory needed for named parts, due stages, deferred
  work and owner-run inspections that cannot be derived from the spec,
  roadmap and approved plan. Check every due ID, kind and part, including
  earlier-stage deferred parts and growing sets.
- Every required test must execute and pass. Missing reports, uncollected
  tests, skips, expected failures and failures cannot satisfy verification,
  even if another test for the same ID passes. Unknown IDs fail the check.
- CI enforces the automated parts on the final slice, exact completion
  revision and completion or correction tag, through the aggregate gate.
  Configuration checks are automated unless the approved plan assigns a
  part as an owner-run deployment inspection.
- Record owner-run checks in the stage issue with ID, named part or exit
  criterion, result, revision/artifact, environment and evidence. The owner
  confirms completeness and validity before tagging. Missing, skipped or
  failed required owner-run checks block tagging and completion; CI does
  not ingest or validate their records.
- Never skip or weaken a tagged test to turn CI green.
