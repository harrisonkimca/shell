# Roadmap

The order in which Shell's baseline is built and proved. The
[README](../README.md) owns principles, [architecture.md](architecture.md)
the mechanisms, and [spec/auth.md](spec/auth.md) behaviour, values and the
requirement IDs; this file only sequences them. "arch §n" is section n of
architecture.md, "spec §n" section n of spec/auth.md.

## How the stages work

- A stage starts once the preceding stage is complete.
- Each stage writes the integration-suite tests ([arch §13](architecture.md#13-operations-baseline))
  for what it builds, and a contract-test suite
  ([arch §5](architecture.md#5-ports-and-adapters)) for ports with more than
  one plausible implementation, starting in stage 1.
- Every requirement ID in the spec is listed in exactly one stage: the one
  that builds it or, for a property of the whole system, the one that
  proves it. A later stage that builds on a requirement, or runs a part of
  its check that couldn't run earlier, names it without listing it again.
- **Exit criteria**, for every stage: each requirement passes every
  Verification kind due by that stage, including deferred parts of
  earlier requirements; CI and the stage's own checks pass.
  Requirements covering a growing set are checked as members are added.
  The final slice and the completion check on `main` verify the stage
  cumulatively, before it is tagged.
- **Spikes** run as soon as their prerequisites exist, before the work
  that relies on them. Where arch §15 gives a fallback, it applies
  without relaxing the spec. Otherwise a failed spike stops the
  dependent work until the owning design file is updated.
- Shell is built and proved once, on one reference deployment (stage 7).
  The deployment decisions, and what each fork's deployment repeats, stay
  in the files that own them (end of stage 8).

| Stage | Delivers | IDs |
|---|---|---|
| 0 | Foundation and workflow | 4 |
| 1 | Ory in production mode, configured as code | 29 |
| 2 | Auth adapters and the signed-in session | 38 |
| 3 | Identity context, gates and staff | 24 |
| 4 | Our sign-in screen | 24 |
| 5 | Account settings, devices and deactivation | 28 |
| 6 | Administration | 9 |
| 7 | Shell is deployment-ready | 11 |
| 8 | Launch hardening | 8 |

## Stage 0. Foundation and workflow

**Goal.** A repository whose tooling, CI and local environment enforce the
architecture's rules from the first commit.

**Builds.**

- The repository layout in the [README](../README.md#repository-layout),
  with `main.py`, `worker.py`, `core/` and `shared/` in their four layers.
- uv, Ruff, Pyright strict, pytest and pre-commit, and the import-linter
  contracts of [arch §14](architecture.md#14-import-rules), with a
  common quality-check script used locally and in CI.
- The CI foundation of arch §13: lint, types, tests, integration
  against Compose, image build with digest pinning and scans, and
  migration checks. Existing build/scanning tooling generates the SBOM
  from each built image (NFR-024), retained with its image digest.
  Each check starts in the slice that makes it
  runnable; checks needing later features arrive with those features.
- Automated requirement verification using the runners' existing reports
  and minimal metadata, following the requirement-test guide. Record only
  named parts and due stages, deferred parts and deployment inspections
  that cannot be derived from the spec, roadmap and approved plans. No
  custom reporting framework. CI checks automated parts due through
  completed stages and stage N on `stage-N/exit`, exact `main` completion
  and its tag. Configuration checks are automated unless the approved plan
  assigns a part as an owner-run deployment inspection. Owner-run results
  stay in the stage issue, confirmed by the owner before tagging; CI does
  not ingest them.
- One aggregate required CI check, `ci`, always scheduled and covering
  every applicable check. Validate coverage from workflow definitions so
  newly added checks cannot be omitted. Missing, skipped or failed required
  CI checks or automated verification fail it; a green aggregate with missing reports
  cannot satisfy completion. Use the existing runners and CI results.
- The development stack in Docker Compose, started by one command:
  Caddy with a local CA, PostgreSQL with the `shell` database and its
  app and migrator roles, Redis and Mailpit, bound to `127.0.0.1`,
  with a git-ignored `.env`. Synthetic seed data arrives with its tables.
- Migration tooling and the initial schema revision; the app skeleton
  with settings, startup checks, Unit of Work, error handler
  ([arch §10](architecture.md#10-error-model)), correlation IDs, JSON
  logs, basic metrics and internal health and readiness probes.
  Readiness covers the database and schema; signing keys join it
  in stage 2.

**Requirements.** AUTH-ERROR-001; NFR-011, NFR-013, NFR-024.

**Exit criteria.**

- Guardrail check: a deliberate breach of each of the nine import rules,
  a Pyright strict error and a Ruff error each fail their checks.
- The requirement-trace check's tests prove that missing, skipped or
  failed automated verification, an unknown ID and a missing required
  automated kind or part fail CI's stage-completion check.
- Aggregate-gate tests prove missing, skipped and failed checks fail and a
  newly added check cannot be left outside the aggregate.
- Component-inventory checks prove a missing inventory or unapproved source
  fails CI; extend coverage as images are added.
- The integration job runs meaningful tests against the Compose stack;
  its first Ory tests arrive in stage 1.
- Readiness fails without the database or a compatible schema, and
  probes and metrics cannot be reached through the public edge.

**Depends on.** Nothing.

## Stage 1. Ory in production mode, configured as code

**Goal.** Both realms run in production mode in development, configured
only from files in the repository, with email codes delivered by Shell,
so every later stage builds against the real provider.

**Builds.**

- Each realm's Kratos and Hydra in Compose, in production mode, with HTTPS
  issuers and Secure cookies through Caddy's local CA, and their own
  databases and roles ([arch §6](architecture.md#6-data-ownership-and-database-layout));
  their admin APIs on an internal network that only `api`, `worker` and
  the deploy job join ([arch §1](architecture.md#1-system-and-deployment)).
- The customer realm: email codes and Google for sign-up and sign-in;
  no subscriber passkeys or recovery flow; profile editing off; the
  provider-side windows and lifetimes the spec sets. No stage builds any way to give a subscriber a new address.
- The workforce realm ([arch §3](architecture.md#3-identity-realms),
  [§9](architecture.md#9-administration)): passkey sign-in only, no
  registration, and the recovery flow on solely for operator-issued
  enrollment codes, with no recovery role on staff addresses.
- Hydra per realm: ES256 signing keys, token lifetimes, refresh rotation,
  PKCE and `private_key_jwt`.
- The client registry, `config/clients/<realm>.yaml`, each client with its
  type, applied on every deploy.
- The reference UI for each realm, in development only.
- Workforce passkey RP ID and allowed origin.
- `EmailSender` behind the provider's HTTP courier, with English and Korean
  code templates, its email adapter and limits, sending to Mailpit. Its
  contract suite runs on the fake and real adapter. Notification delivery
  arrives in stage 3.
- The edge: each realm's host routed to its public paths only, per-IP
  limits on flow submissions, and the client IP it sets
  ([arch §11](architecture.md#11-security-controls-rate-limiting-and-threat-model));
  the provider's enumeration mitigation left off; baseline security headers on each
  host, including the reference UI's CSP and `no-store` on sign-in and token responses
  (arch §11).
- Startup checks refusing realms that share an issuer, key URL or audience.

**Requirements.** AUTH-ASSURE-001; AUTH-IDP-002, AUTH-IDP-005, AUTH-IDP-011–012,
AUTH-IDP-014, AUTH-IDP-020, AUTH-IDP-024, AUTH-IDP-029; AUTH-CODE-001–006;
AUTH-LIMIT-001–005; AUTH-PASSKEY-013, AUTH-PASSKEY-018; AUTH-SESSION-004;
AUTH-CLIENT-002–003, AUTH-CLIENT-011; AUTH-STAFF-008; AUTH-ADMIN-008; AUTH-ERROR-004.

**Exit criteria.**

- Configuration-as-code check: from empty volumes, one command brings up
  both realms with their clients and keys, and each serves discovery with
  its exact issuer, with no manual step.
- Provider-only integration tests use test fixtures; complete application
  sign-ins wait for Shell's consent step in stage 2.
- Spike: user verification. Record whether the workforce provider refuses
  a passkey response without the user-verified flag in its browser and API
  flows. If not, build and prove Shell's unavoidable server-side check in
  stage 2 before dependent passkey tests (arch §5). Use test-only provider
  flows for the spike. If the check cannot be enforced, stop until the
  design is corrected.
- Spike: the provider's own account linking at sign-in can be turned off
  (AUTH-SIGN-009, arch §15).

**Depends on.** Stage 0.

## Stage 2. Auth adapters and the signed-in session

**Goal.** Subscribers and test-fixture staff sign in and call the API with
tokens Shell verifies locally, using the reference UI where supported.
Staff fixtures are test-only, never seed data.

**Builds.**

- The remaining ports of arch §5 per realm: `TokenVerifier`, `OidcClient`,
  `IdentityAdmin`, with fakes and contract suites on fakes
  per commit and on real adapters in integration CI.
- If the stage 1 user-verification spike requires it, Shell's server-side
  passkey check, before staff sign-in is tested.
- The `users`, `staff` and `devices` tables, keyed by Shell's UUID, never
  holding an address. They are built here because the consent step and the
  per-request check below need them.
- Token acceptance: `verify_token`, the key cache, the per-request lookup
  of the account and its device record, the principal, and one router per
  realm. Idle and absolute session limits on requests and token issuance;
  readiness covers the signing keys. Each Shell route declares its scopes
  and gate; startup refuses undeclared routes. Stage 3 adds the fresh
  sign-in gate and catalogue check.
- The audit log, its port and append-only roles, including the purge role;
  consent audits sign-ins, report hooks audit sign-ups, and sign-out
  writes its own entry.
- The `tasks` table and arq worker's unfinished-device cleanup, using the
  stored ten-minute deadline so cleanup can resume after interruption.
- Our consent step: it grants first-party clients at once, stamps the
  sign-in ID and creates the device record. It runs from the
  first sign-in, because every user token must carry the sign-in ID; the
  reference UI keeps the sign-in screens until stage 4.
- The token-claims hook (`auth_time`, `amr` and the sign-in ID in every
  access token, refreshes included, failing closed), built before any
  account change because every gate reads its claims.
- The BFF on both browser hosts: sign-in, callback, serialized refresh and
  sign-out, with the cookies and CSRF protection of
  [arch §7](architecture.md#7-token-and-cookie-flow); bearer tokens only on
  `api.`.
- The customer profile read route, returning the caller's name, language
  and timezone under `profile:read`.
- The first substantive OpenAPI contract, with CI validation and
  compatibility checks once a published baseline exists.
- The React web shell, with its frontend tooling, English and Korean
  FormatJS catalogues, missing-key check, refresh handling, CSRF protection
  and sign-out. CSP for `app.` and `no-store` on sign-in, token and account responses.
- The provider's hook routes on the private network, receiving sign-up
  and sign-in reports.
- Behaviour with the provider down (arch §10).
- Two CI checks that every later stage passes: a scan of the integration
  suite's logs for personal data, and a schema check for personal fields.

**Requirements.** AUTH-IDP-009, AUTH-IDP-015–017, AUTH-IDP-030; AUTH-LIMIT-011;
AUTH-ACCT-017; AUTH-DEVICE-002–003; AUTH-SESSION-001–003, AUTH-SESSION-005–006;
AUTH-TOKEN-001–007, AUTH-TOKEN-009–010; AUTH-WEB-001–004, AUTH-WEB-006–007;
AUTH-CLIENT-007–008; AUTH-AUDIT-002–004, AUTH-AUDIT-006; AUTH-PRIVACY-008; NFR-002,
NFR-010.

**Exit criteria.**

- Spike, first: the sign-in ID our consent step stamps survives every
  refresh ([arch §15](architecture.md#15-to-verify-before-launch)). Pass:
  across a chain of ten refreshes, every access token carries the sign-in
  ID stamped at sign-in. If it fails, arch §15 says what follows.
- AUTH-SCOPE-001: `hook-secret` unit tests refuse missing and wrong secrets;
  `hook-edge` integration tests prove public-edge isolation even with a valid
  secret. Extend both checks as hooks are added.
- Runs the parts that couldn't run earlier: AUTH-IDP-012 (code reuse),
  NFR-013 (keys). Verify the workforce sign-in path with test fixtures.
  Run complete application token flows here, not in stage 1.

**Depends on.** Stage 1.

## Stage 3. Identity context, gates and staff

**Goal.** Every route declares who may call it and how recent a sign-in it
needs, every security-relevant action is audited, and an operator can
manage staff, all before the first account change.

**Builds.**

- The `admin` role, referencing staff only, and the admin guard on
  `/v1/admin`, with its first route: reading one's own staff record.
- Shell's full scope set, with the own-session sign-out route for mobile apps.
- Gates ([arch §4](architecture.md#4-clients-scopes-and-the-principal)):
  `require_gate` on every route, the fresh-sign-in check reading the latest
  step from the last `amr` entry, the RFC 9470 challenge and gate error
  handling.
- A test-only route with a 15-minute fresh-sign-in gate, to prove the
  gate before the account-management routes arrive.
- Signing in again through the reference UI, the web client's handler for
  the sign-in-again challenge, and continuation codes, so only the device
  holding a session can continue it.
- Mobile protocol tests in the existing integration suite: public-client
  PKCE, bearer calls, rotation, own-session sign-out and fresh-sign-in
  continuation. Physical platform verification follows in stage 5.
- The CI check of the route catalogue
  ([spec §9](spec/auth.md#9-clients-scopes-and-route-gates)) against the
  code, which every later stage's routes pass.
- Audit retention purge.
- Durable work: extend the task mechanism with the remaining sweeps and
  coordinated disable and enable (arch §9), ahead of the console's
  disable and enable actions and self-service deactivation.
- Notices queued as tasks, with their templates. The staff script is the
  first change that sends one.
- The staff provisioning script (`add`, `re-enroll`, `change-email`,
  `remove`), with staff enrolling and signing in through the workforce
  realm's reference UI. The workforce realm and the script come before the
  console.

**Requirements.** AUTH-ASSURE-002; AUTH-IDP-025–026; AUTH-FRESH-002, AUTH-FRESH-004,
AUTH-FRESH-010–011, AUTH-FRESH-013; AUTH-TOKEN-008; AUTH-CLIENT-012; AUTH-SCOPE-001,
AUTH-SCOPE-004–005; AUTH-STAFF-001–007; AUTH-ADMIN-001; AUTH-NOTIFY-006,
AUTH-NOTIFY-009; AUTH-ERROR-005.

**Exit criteria.**

- Spike, first (arch §15): Google can be made to ask again. Pass: signing
  in again through Google makes Google ask the user, and the tokens carry a
  fresh `auth_time`. If it fails, arch §15 says what follows.
- Prove ordered latest authentication claims for enabled methods before
  gates; prove staff passkey sign-in and restricted enrollment with software
  authenticators before using the provisioning script. Physical-device
  checks run in stage 5.
- Runs the parts that couldn't run earlier: AUTH-SESSION-001–003 (fresh
  sign-in without extending the absolute limit); AUTH-AUDIT-004 (purge);
  AUTH-ACCT-017 (own-session sign-out); AUTH-TOKEN-007 and AUTH-TOKEN-009
  (mobile protocol behavior; platform storage waits for stage 5).

**Depends on.** Stage 2.

## Stage 4. Our sign-in screen

**Goal.** Our own screens take over every sign-in step from the reference
UI, so deployed environments can serve them.

**Builds.**

- The sign-in module in `web/`, on each realm's auth host: the customer
  entry screen (the email step and "Continue with Google"), code entry,
  sign-up; signing in again; staff sign-in with
  passkeys and staff enrollment; the provider's settings steps, used from
  stage 5; the message for a disabled account.
- Google sign-up rules: our claims mapper and sign-up hook, each refusal
  with its message, and each method finding the account by its own key.
- CSP for each auth host. The terms page on the app host, after the BFF
  callback: items configured at deployment, placeholders only in
  development, the API refusing the account until the required ones are
  accepted, and a record of each item. Mobile clients accept terms through
  the API. All terms responses carry `no-store`.
- Our app takes over the sign-out step: our clients' sign-outs are accepted
  at once, any other request is confirmed, and Hydra then ends its sign-in
  session and the Kratos session.
- Every passkey ceremony requires user verification and accepts security
  keys; screens answer alike for known and unknown addresses.
- Extend the English and Korean FormatJS catalogues to the sign-in screens
  and error codes, with CI failing on a missing key. Screens are built to WCAG 2.2 AA, with
  the automated checks of AUTH-A11Y-002 on each.
- The reference UI kept to development.

**Requirements.** AUTH-IDP-006, AUTH-IDP-019, AUTH-IDP-027; AUTH-SIGN-001,
AUTH-SIGN-003–013, AUTH-SIGN-015; AUTH-PASSKEY-011–012; AUTH-ACCT-011; AUTH-ERROR-003;
AUTH-PRIVACY-001; AUTH-I18N-001–002, AUTH-I18N-004.

**Exit criteria.**

- Hands-on check (arch §15): the provider doesn't reveal a disabled account
  before its code is entered. Pass: a disabled account's address gets the
  same screen and response as any other until the code is entered. If it
  fails, arch §15 says what follows.
- Runs the parts that couldn't run earlier: AUTH-FRESH-004 (screen);
  AUTH-ACCT-017 (our sign-out step); AUTH-IDP-025 (our screen).

**Depends on.** Stage 3: the terms step relies on route declarations,
signing in again on the sign-in checks, and the disabled-account message on
coordinated disable.

## Stage 5. Account settings, devices and deactivation

**Goal.** A subscriber manages their account, sees and ends their sessions
and deactivates the account, each change behind the gate the spec sets and
announced as the spec lists.

**Builds.**

- The settings page ([arch §8](architecture.md#8-account-management-and-sign-out)),
  showing the address without any way to edit it.
- Name, language and timezone, and the optional terms items.
- Staff passkey settings: several credentials, addition, removal and
  renaming through Shell labels. The hook enforces fresh-passkey windows,
  protects the last credential and allows restricted initial enrollment.
- Linking and unlinking Google, in settings only. Provider settings-change
  report hooks; `no-store` on account responses.
- "Where you're signed in": the ordinary device list;
  logging out another device or all devices.
- New-device notices for subscribers and staff: the browser ID hashed per
  account in `known_browsers`, and the install ID that apps report,
  verified by integration tests and physical mobile checks.
- Deactivation: every-time sign-in challenge and explicit confirmation,
  reusing coordinated disablement, all-device revocation and audit.
- Notices for Google changes and staff passkeys; sign-out on every page
  and "Log out all devices" after sign-in-method changes.

**Requirements.** AUTH-IDP-028; AUTH-PASSKEY-014–017; AUTH-FRESH-012,
AUTH-FRESH-014–015; AUTH-ACCT-002–006, AUTH-ACCT-012, AUTH-ACCT-014–016;
AUTH-DEVICE-004, AUTH-DEVICE-008–009; AUTH-SCOPE-002; AUTH-NOTIFY-002–004,
AUTH-NOTIFY-008; AUTH-PRIVACY-004, AUTH-PRIVACY-009; AUTH-I18N-003.

**Exit criteria.**

- Spike, first (arch §15): settings hooks distinguish staff passkey
  additions/removals and Google links/unlinks, naming the credential; a
  stopped or refusing hook leaves each identity unchanged (AUTH-IDP-027).
- Hands-on devices and browsers (arch §15): staff registration and sign-in
  work on iOS, Android, macOS and Windows with autofill, cross-device phone
  and security key, requiring UV; code entry works on phones and Google in
  Safari, Chrome and Firefox. This completes hands-on AUTH-IDP-025,
  AUTH-PASSKEY-011–012 and AUTH-SIGN-012.
- Mobile readiness: on physical iOS and Android prove AUTH-CLIENT-012's
  browser return, secure storage, serialized refresh, sign-out, continuation,
  terms, Google settings and install-ID report. Use minimal temporary
  clients if needed, without permanent clients or dedicated CI. Missing or
  failed platform evidence prevents mobile readiness and stage completion.
- Complete the deferred parts of AUTH-IDP-009 (settings reports),
  AUTH-DEVICE-003 (visible list), AUTH-ACCT-017 (no new-device notice after
  sign-out), AUTH-TOKEN-008 (device revocations and deactivation),
  AUTH-PASSKEY-011–012 (staff registration), AUTH-NOTIFY-009 (templates),
  AUTH-SCOPE-004–005 (routes), AUTH-FRESH-004 (account changes),
  AUTH-FRESH-010 (visible list), and AUTH-TOKEN-007 and AUTH-TOKEN-009
  (mobile refresh and storage).

**Depends on.** Stage 4.

## Stage 6. Administration

**Goal.** Staff support subscribers and manage exposed resources from the
console, with the fresh passkey sign-ins, confirmation steps and audit the
spec requires.

**Builds.**

- The React-admin console in `apps/admin/` on the admin host, with its own
  translation provider, sign-out on every page and the strictest CSP.
- The admin endpoints of arch §9: subscribers listed, searched and viewed
  with their audit entries and devices; created and edited; disabled,
  enabled through stage 3's coordinated use cases; all sessions and grants
  of a subscriber ended.
- A fresh passkey sign-in before each high-risk action, a `confirm` field on
  destructive ones, and an audit entry for every request, reads included.
- Staff's own "Where you're signed in", with logging out, and the reminder
  to add a second passkey.
- The notices for support actions.
- The Data section (arch §9), using explicit routes and standard React-admin
  components for the resources and fields the spec permits.
- `docs/guides/adding-a-feature.md`, whose tested example adds
  a small resource with explicit routes, components, scope/gate declarations,
  field restrictions and audit. CI exercises the example on every change.

**Requirements.** AUTH-STAFF-012; AUTH-ADMIN-004, AUTH-ADMIN-006–007,
AUTH-ADMIN-015–019.

**Exit criteria.**

- Guide check. Pass: following only the guide, someone who didn't build the
  Data section adds a small feature with explicit routes and standard
  components, and its permitted pages pass guard, scope, gate, field
  restriction and audit tests. The example stays test-only.
- Runs the parts that couldn't run earlier: AUTH-ACCT-004 for admin routes;
  AUTH-ACCT-012 and AUTH-ADMIN-008 for the console; AUTH-FRESH-012 for staff
  high-risk actions; AUTH-NOTIFY-008 for support actions;
  AUTH-SCOPE-004–005 for the workforce routes; AUTH-TOKEN-008 for admin
  revocations.

**Depends on.** Stage 5.

## Stage 7. Shell is deployment-ready

**Goal.** Prove that Shell deploys to a non-local environment in an
explicit region, with a component swapped for a managed service by
configuration alone and every connection encrypted.

**Builds.**

- A reference deployment on the default compute platform
  ([README](../README.md#deployment-decisions)), starting empty, with our
  sign-in module, the email relay and a secrets manager; its first admin is
  added with `add`.
- Internal TLS with this first deployment
  ([arch §13](architecture.md#13-operations-baseline)): a private CA made
  for the deployment, each service's certificate issued and renewed by the
  deploy job, and the startup checks that refuse plaintext.
- Public TLS on every host; verify security headers on all deployed hosts.
- Backups of every database, the providers' included.
- Logs shipped off the host, metrics with their alerts, the sending
  domain's mail records, and the app's least-privilege workload identity.

**Requirements.** AUTH-WEB-005; AUTH-STAFF-011; AUTH-ADMIN-009; AUTH-NOTIFY-007;
AUTH-PRIVACY-010; NFR-006, NFR-008, NFR-012, NFR-014–015, NFR-023.

**Exit criteria.**

- **Deployment-ready test.** Pass: the deployment starts only once its
  region is set; PostgreSQL is swapped for a managed service in the same
  region by configuration alone, with no change to domain or application
  code, and sign-in, settings and the console then work on it; each startup
  refusal in arch §5's table is exercised, the deployment refusing to start
  with each faulty setting; and with the private CA, no internal endpoint
  accepts plaintext.
- Runs on the deployment the parts that couldn't run earlier:
  AUTH-SIGN-001 and AUTH-SIGN-011 (no reference UI, no placeholder terms);
  from outside the private network, NFR-013; and from outside it and from
  the edge, metrics and datastores, AUTH-ADMIN-008.

**Depends on.** Stage 6.

## Stage 8. Launch hardening

**Goal.** Prove on the reference deployment that the baseline is secure,
recoverable and fast enough before any fork launches from it.

**Builds.**

- At least two admins, each with two passkeys.
- The rehearsals and reviews below.

**Requirements.** AUTH-STAFF-009–010; NFR-001, NFR-004–005, NFR-007, NFR-022;
AUTH-A11Y-002.

**Exit criteria.**

- Load test (arch §15) on the reference deployment. Pass: the targets of
  NFR-022, NFR-004 and NFR-005 are met, and stopping one `api` replica fails only its
  in-flight requests (NFR-001).
- Restore rehearsal. Pass: a full restore of every database permits a
  restored account to sign in; record the duration (NFR-007).
- Signing-key rotation rehearsal, by the procedure in arch §13. Pass:
  tokens signed by either key verify throughout (AUTH-TOKEN-010), and no
  key set is ever emptied.
- Break-glass rehearsal (AUTH-STAFF-010).
- WCAG 2.2 AA review, in English and Korean, of every screen AUTH-A11Y-002
  lists.
- Threat-model review. Pass: every threat in arch §11 meets a mitigation
  that is built and tested, or a residual risk the file accepts; a threat
  found in the review is added to arch §11 before launch.
- ASVS 5.0 Level 2 checklist. Pass: each applicable requirement is proved,
  except the subscriber single-factor relaxation and named internal client
  authentication deviation (ASVS 13.2.1) in
  [spec §1](spec/auth.md#1-conventions-and-assurance); non-applicable items
  have recorded reasons. The deviation's retained controls and NFR-024
  inventory pass their verification. Completion does not establish
  unqualified Level 2 compliance.
- External review: an independent security review of the code and the
  reference deployment ends with no open critical or high finding.

**Depends on.** Stage 7.

**What each deployment repeats.** A fork's own deployment makes the choices
in the README's [Deployment Decisions](../README.md#deployment-decisions)
and repeats what the owning files set out for every deployment: its private
CA, backups and key rotation
([arch §13](architecture.md#13-operations-baseline)), and the admins,
backups and availability figures of the
[spec](spec/auth.md#14-non-functional-requirements). This roadmap doesn't
repeat them.

## Later

Nothing Later is a stage; an item is planned when its trigger appears. The
items and their triggers are in the README's
[Planned Evolution](../README.md#planned-evolution),
[arch §16](architecture.md#16-later) and [spec §15](spec/auth.md#15-later).
