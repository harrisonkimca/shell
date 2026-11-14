# Decisions

Durable baseline choices and their trade-offs. The linked files own behavior,
values and mechanisms. Record IDs are stable and never reused; gaps remain reserved. Forks append
after the highest ID.

### DEC-001 Shell is a starter each project forks

Each fork operates its own data, deployment and security boundary, adding
contexts beside identity and setting project values in configuration. A shared
service would couple outages and breaches; fixes reach forks only when pulled.

[Details](../README.md#project-overview).

### DEC-002 Tools enforce types and boundaries

Pyright strict and import-linter enforce the layer and context boundaries
locally and in CI. Convention alone erodes; forks accept the same contracts.

[Details](architecture.md#14-import-rules).

### DEC-003 Authentication is delegated

The provider owns identities, credentials, addresses, flow state and all token
issuance; Shell verifies. This avoids a duplicate credential model. Every
provider behavior used by Shell must pass real-stack tests; provider outages
stop new sign-ins.

[Details](architecture.md#5-ports-and-adapters).

### DEC-004 Self-hosted Ory is the default

Each realm uses Kratos for identities and flows and Hydra for tokens.
Self-hosting avoids choosing a managed vendor or region for every fork; forks
may swap providers at deployment. Operating the pairs and enforcing UV and the
resend gap are Shell costs. The capability checklist must be proved, not
inferred from configuration schema.

[Details](architecture.md#5-ports-and-adapters).

### DEC-005 Ory runs in production mode everywhere

Development uses HTTPS issuers and Secure cookies through a local CA. This costs
local certificate setup but prevents relaxed development checks hiding
deployment defects.

[Details](architecture.md#13-operations-baseline).

### DEC-006 Subscribers and staff are separated by issuer

Independent realms have their own issuer, keys, audience, cookies, host and
storage; routes trust exactly one. Roles reference staff only. A shared realm
would leave a role flag between subscribers and admin rights. Cloud IAM is a
separate plane. Two realms cost two provider pairs and separate accounts for
staff who are also subscribers.

[Details](architecture.md#3-identity-realms).

### DEC-007 Subscriber sign-in is also the way back in

Email codes and Google are the only subscriber methods, without passwords,
separate recovery or assurance tiers. The mailbox or Google account is the
security ceiling; the spec documents the ASVS relaxation and retained
mitigations. Shell claims no subscriber NIST AAL and uses AAL1 session limits. A
mailbox takeover remains an account takeover.

[Details](spec/auth.md#1-conventions-and-assurance).

### DEC-008 Email uses codes, never sign-in links

Codes entered in the current window avoid URLs, scanners and cross-device link
handling. Accessible typing and paste are required.

[Details](spec/auth.md#5-email-codes-and-rate-limits).

### DEC-009 Subscriber addresses stay fixed; tables use Shell UUIDs

Neither users nor admins change subscriber addresses. This prevents a mailbox
thief keeping access by changing the address, but losing a mailbox loses access
to the account data. Provider IDs and issuers map to Shell UUIDs; business
tables keep no address copy.

[Details](spec/auth.md#7-account-settings-devices-and-deactivation).

### DEC-011 Staff passkey verification is enforced by the server

The screen requires UV and accepts security keys; the server refuses every
response without UV, including direct API submissions. If provider configuration
cannot enforce it, Shell checks the submission path without a public bypass.
Relying on the screen would let a stolen key and tampered client bypass its PIN;
the server check is maintenance Shell accepts.

[Details](spec/auth.md#4-staff-passkeys).

### DEC-012 Accounts are never linked on matching addresses

Each method uses its own key: address for email, subject ID for Google. An
unknown Google identity with an unverified or already-used address cannot sign
up; linking is explicit in settings. This closes silent takeover at the cost of
a settings step for existing email users.

[Details](spec/auth.md#3-sign-up-sign-in-and-linking).

### DEC-013 Provider code enumeration is an accepted risk

Shell screens answer generically; Kratos code sign-in still reveals unknown
addresses to API callers. Its experimental mitigation does not cover that path
and stays off. Rate limits slow enumeration; leaving the provider flow to hide
it is outside the baseline.

[Details](spec/auth.md#12-errors-and-privacy).

### DEC-014 Sign-up terms are deployment data

The fork supplies versioned terms, privacy policy and required confirmations;
the API blocks use until required acceptance. Hard-coded ages or countries fit
only one fork. Deployment cannot start with placeholders.

[Details](spec/auth.md#3-sign-up-sign-in-and-linking).

### DEC-015 Only operators manage staff

Staff use passkeys, with no self-registration or self-service recovery.
Operators use cloud IAM with MFA and the provisioning script; all commands are
audited and announced. This keeps a stolen admin session from creating staff,
but lost passkeys require an operator. Enrollment codes need a restricted
provider recovery flow that no staff address can start.

[Details](spec/auth.md#10-staff-and-administration).

### DEC-016 Browsers use a BFF and Strict token cookies

FastAPI holds browser tokens in HttpOnly, Secure, host-only Strict cookies, with
CSRF protection. Sign-in and browser-ID cookies are Lax for cross-site returns.
Mobile uses system-browser PKCE and the bearer API. Browser storage would expose
tokens to scripts. The BFF adds a request hop; cross-site cookie behavior is
tested in each engine. Mobile protocol tests use the integration suite, with
hands-on iOS and Android checks before readiness.

[Details](architecture.md#7-token-and-cookie-flow).

### DEC-017 Confidential clients use signed assertions

Private-key JWT authentication avoids shared secrets and makes each assertion
single-use. Client keys still need storage and rotation.

[Details](spec/auth.md#9-clients-scopes-and-route-gates).

### DEC-018 Refresh rotation has zero grace

Replay ends the whole chain. The BFF serializes per-session refreshes across
replicas and mobile keeps one in flight. Lost refresh responses may sign users
out; a grace window would permit replay and stays Later.

[Details](architecture.md#7-token-and-cookie-flow).

### DEC-019 Authlib runs the browser code flow

Use low-level AsyncOAuth2Client rather than hand-written protocol or an auth
framework with its own user model and routes. HTTPX calls provider admin APIs;
Google runs inside the provider.

[Details](architecture.md#5-ports-and-adapters).

### DEC-020 PyJWT verifies access tokens

Shell needs verification, not issuance. PyJWT provides that small boundary; a
consolidated signing library offers little gain here.

[Details](architecture.md#3-identity-realms).

### DEC-021 Routes declare authorization explicitly

One principal carries realm, identity, client, scopes and audience. Every
route declares scopes or an access classification and its gate; omissions stop
startup. The OpenAPI catalogue check prevents drift. Fork routes must supply
these declarations.

[Details](architecture.md#4-clients-scopes-and-the-principal).

### DEC-022 API versions and OpenAPI protect mobile clients

Published versions grow additively, retain superseded versions for a deprecation
window and generate web/admin clients from OpenAPI. Mobile apps cannot be forced
to update; breaking changes cost a parallel version.

[Details](architecture.md#4-clients-scopes-and-the-principal).

### DEC-023 Shell runs consent and sign-out steps

Consent stamps the sign-in ID and device record from the first sign-in and
grants only first-party clients. The reference UI is development-only; Shell
handles deployed sign-out, confirming requests its clients did not start. This
prevents unwanted sign-outs, and means development sign-in needs Shell running.

[Details](architecture.md#7-token-and-cookie-flow).

### DEC-024 Every user token carries authentication time, steps and sign-in ID

The token hook copies claims on issuance and refresh and refuses gone or expired
device records; hook failure issues nothing. Gates and immediate device refusal
need these claims. The refresh-ID spike is a prerequisite, and no fallback may
relax required token claims.

[Details](architecture.md#5-ports-and-adapters).

### DEC-025 A session is a device record continued by its holder

Each request checks sign-in and last-active times; fresh sign-in continues the
original absolute limit through a single-use continuation code. Provider
sessions are brief and sign-out ends them; concurrent sessions are uncapped.
This adds one indexed lookup and may leave two records when continuation is
abandoned.

[Details](architecture.md#8-account-management-and-sign-out).

### DEC-026 Each route declares a fresh-sign-in gate or none

A route checks auth_time and the latest amr step; unknown methods fail closed.
Zero means every time, bound to a session-and-route challenge. This protects
sensitive actions from a copied session while keeping one client challenge
handler. Assurance tiers would add no protection under the email ceiling.

[Details](spec/auth.md#6-fresh-sign-ins).

### DEC-028 New devices use random IDs hashed per account

A browser cookie or reported app install ID identifies unseen sign-ins. Keyed
hashes avoid linking accounts; IDs never enter URLs or logs. A cleared cookie or
reinstalled app produces another notice. Forks verify the security-cookie
treatment in their privacy policy.

[Details](architecture.md#8-account-management-and-sign-out).

### DEC-029 Self-service deactivation reuses disablement

Deactivation requires a fresh sign-in every time, explicit confirmation,
immediate disablement, all-session and grant revocation and audit. Reuse the
durable disable task; no separate lifecycle framework. It retains data.
Permanent deletion and associated policy and restore handling are Later, and
deletion is a fork launch prerequisite wherever applicable.

[Details](spec/auth.md#7-account-settings-devices-and-deactivation).

### DEC-030 Cross-system work uses durable tasks

A use case records tasks atomically with its database changes; arq retries
provider effects and a sweep recovers lost work. Lifecycle state stays on its
entity; no workflow library is needed. Provider effects may lag local refusal.
An outbox can be added when needed.

[Details](architecture.md#6-data-ownership-and-database-layout).

### DEC-031 External systems use ports and contract tests

Application or domain contracts isolate adapters; plausible alternatives share
contract tests. Managed-compatible data features and configuration keep vendor
swaps bounded, at the cost of maintaining adapters and their tests.

[Details](architecture.md#5-ports-and-adapters).

### DEC-032 Provider email goes through EmailSender

HTTP delivery lets Shell enforce per-address and per-IP limits, the resend gap
and localized templates regardless of provider. Codes depend on Shell; the
provider retries failures. Direct provider SMTP would lose these controls.

[Details](architecture.md#11-security-controls-rate-limiting-and-threat-model).

### DEC-033 React-admin has its own app and host

The console calls only guarded Shell admin routes and audits every request,
reads included. This avoids shipping admin code to subscribers and permits later
network restriction.

[Details](architecture.md#9-administration).

### DEC-034 The Data section uses explicit routes and standard components

Each resource gets explicit use cases, field allowlists, scopes, gates, staff
guards and audit. Standard React-admin components provide permitted pages. This
avoids a custom registration and generation framework while retaining one
controlled data path; every resource needs its own wiring and tests. Raw
database tools, schema changes and export are excluded.

[Details](architecture.md#9-administration).

### DEC-035 Languages and timezones are data

Catalogues and UTC timestamps support new languages and timezones without
application-code changes. Clients translate stable error codes; EmailSender
renders localized mail.

[Details](architecture.md#12-internationalization).

### DEC-036 Every deployed connection is encrypted

Public hosts use trusted TLS; internal hops use a private CA or declared
platform encryption, and data services use verified TLS. Private networking
alone would leave tokens readable after a foothold. Certificate issuance and
renewal are deployment costs. Stronger internal client authentication is
Later; [spec §1](spec/auth.md#1-conventions-and-assurance) names the ASVS
13.2.1 deviation without weakening these controls.

[Details](architecture.md#13-operations-baseline).

### DEC-037 Hosting choices belong to each deployment

Forks choose region, compute, managed services, secrets, edge and email when
deploying. Configuration or tested adapters permit swaps; no default region is
assumed. Shell proves operability once on a reference deployment; forks repeat
applicable deployment and launch checks.

[Details](../README.md#deployment-decisions).

### DEC-038 Fork guides carry tested examples

A concise feature guide demonstrates explicit APIs, standard admin components
and boundaries. CI tests its example so the guide cannot silently drift; no
generator is needed.

[Details](roadmap.md#stage-6-administration).
