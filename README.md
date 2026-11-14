# Shell

## Project Overview

Shell is a forkable, passwordless authentication and database foundation. Each
project forks it, adds bounded contexts beside identity and configures its own
names, hosts, issuers and clients. It is a starter, operated independently by
each fork.

The baseline targets OWASP ASVS Level 2 with the subscriber single-factor
relaxation and named internal client authentication deviation in
[spec §1](docs/spec/auth.md#1-conventions-and-assurance); it does not claim
unqualified Level 2 compliance. Staff passkeys require server verification
and use AAL2 session limits; subscriber sessions use AAL1 limits with no
claimed NIST authentication level. Subscriber accounts are only as strong as
their mailbox or Google account. Privacy law, including Korea's PIPA and GDPR
where applicable, constrains each fork's launch; account deactivation retains
data and does not satisfy permanent deletion obligations. Formal certification
is Later.

## Vision

- Passwordless subscriber sign-up and sign-in by email code or Google.
- Separate subscriber and staff realms; staff use passkeys.
- Mobile-first authentication and a web BFF, with scopes and audiences.
- Locally verified short-lived tokens, refresh rotation and device revocation.
- Self-service profile, Google linking, terms, device management and deactivation.
- React-admin support and Data pages, with explicit authorization and audit.
- Languages and timezones added as data.

## Architecture Philosophy

### Modular Monolith First

One stateless application scales horizontally with shared state in PostgreSQL
and Redis. Identity providers run beside it. Contexts can later be extracted
into services; events, CQRS and distribution are added only when needed.

### Domain-Driven Design

Each bounded context owns domain, application, infrastructure and presentation
layers. Dependencies point inward; domain and application code import no
framework, SDK or database driver. Contexts communicate through application
interfaces, never each other's internals or tables. Identity is the only
baseline context. CI enforces these boundaries ([arch
§14](docs/architecture.md#14-import-rules)).

### Authentication Philosophy

Delegate identities, credentials, flows and token issuance to the provider;
Shell verifies tokens and owns the surrounding application. The defaults are
self-hosted Ory Kratos and Hydra in production mode in every environment.
Subscriber and staff realms have separate issuers, keys, storage and hosts.
Cloud infrastructure uses the cloud provider's IAM with MFA.

Use email codes entered in the current window, never sign-in links. Never link
accounts automatically on a matching address. Fresh-sign-in gates protect
sensitive actions. [The spec](docs/spec/auth.md) owns behavior and values; [the
architecture](docs/architecture.md) owns provider integration, token and cookie
flows, data placement and controls.

### Clients, Scopes and Audiences

Web BFFs and public mobile clients use registered grants, scopes and one realm's
audience. Browser script cannot read tokens; mobile uses the system browser and
the bearer-token API. Every route declares access and its gate. One principal is
the application's authorization input. API versions and the OpenAPI contract let
mobile clients evolve independently (arch §4).

### Identity Model

Credentials and addresses belong to the provider. Shell keys users by its own
UUID and keeps the provider issuer and identity ID as a mapping. Roles reference
staff only. Contexts own their tables and migrations; schema changes expand
before contracting. The provider's databases are never read or written directly.
Arch §6 owns fields and retention.

### Ports and Adapters

External systems sit behind ports owned by domain or application code and
implemented in infrastructure. Vendor details stay in adapters and
configuration. Ports with multiple plausible implementations carry contract
tests that every adapter passes. Use managed-compatible PostgreSQL and Redis
features without superuser rights. Deployment choices remain per fork.

### Unit of Work and Workflows

A use case is the entry point to a context. One Unit of Work commits its
database changes, audit and durable tasks atomically. Provider operations retry
as durable work; authentication flow state remains in the provider. Lifecycle
state stays on its entity. No baseline workflow needs a state-machine library
(arch §§6, 9).

### Administration

React-admin is a separate app and host. Its explicit API routes call use cases
under workforce guards; standard components provide the Data section. Arch §9
and spec §10 own capabilities, field restrictions and auditing.

### Internationalization

User-visible strings come from catalogues, errors use stable translated codes,
and timestamps are UTC, displayed in the user's timezone. English and Korean
prove the setup from the start (arch §12).

### Operations

Development uses Compose, local certificates, a git-ignored `.env`, Mailpit and
synthetic data. Deployment starts empty and uses the same configuration as code,
encrypted connections and managed or self-hosted components. Arch §13 owns
deployment, backups, restore verification, observability and key rotation.
Provider behavior is proved against the real stack.

### Planned Evolution

Add complexity only when its trigger appears. Use cases, Unit of Work, ports,
realm boundaries, scopes, versioned APIs and enforced context boundaries permit
later evolution without preparatory frameworks.

| Later | Trigger |
|---|---|
| Domain events, CQRS, sagas | A real need appears |
| Service extraction, multi-region | A real need appears |
| Apple sign-in | iOS users or product demand (one social-login entry in the provider and an Apple developer account; no app-code change) |
| Opt-in advanced protection: sign-in needs the email code and a passkey, with recovery codes | A fork serves people at higher risk of targeted attacks, or holds money or sensitive data |
| Third-party clients and a consent screen | A partner or third-party app needs access |
| Token exchange, device authorization flow | An agent, CLI or TV client needs them |
| Dynamic client registration | Many external clients |
| Changing a subscriber's address, by an operator after a check that doesn't rely on the mailbox | Users must keep their data after losing a mailbox, or a customer's email domain changes |
| More admin roles | Support staff join |
| Staff sign-in through a fork's own identity provider, and managed devices for the console | A fork with a company identity provider, or ASVS Level 3 |
| Staging environment | Regular releases or a team |
| Tracing and SLO alerts | Several services or on-call |
| RPO/RTO targets and disaster-recovery drills | Paying customers |
| SOC 2 or ISO 27001 certification | An enterprise customer requires it |
| Stronger internal client authentication, including mTLS | Shared infrastructure or compliance requiring full ASVS 13.2.1 conformance |
| Data export, incident runbooks | GDPR scope or a team |

`docs/roadmap.md` owns the implementation sequence.

## Technology Direction

The technologies below define the intended project stack; substitutions require
a deliberate change to the project's architectural direction.

| Technology | Purpose | Note |
|---|---|---|
| Python 3.13 | Language and runtime | Pinned in `.python-version` and `pyproject.toml`; installed by uv |
| FastAPI | Backend-for-frontend and resource server | Publishes the OpenAPI contract |
| Pydantic v2 | Validation and data models | |
| pydantic-settings | Application settings | Same code reads `.env` or the secrets manager |
| SQLAlchemy 2.x | ORM | |
| PostgreSQL | Primary database | Self-hosted by default; a managed service is a deployment decision |
| Redis | Rate limiting, refresh serialization, job queue, every-time sign-in challenges and continuation codes | Self-hosted by default; a managed service is a deployment decision |
| asyncpg | Async PostgreSQL driver | |
| redis-py | Async Redis client | |
| arq | Background job queue | |
| PyJWT | Local access-token verification | Verification only; the provider issues tokens |
| Authlib | OAuth 2.0 client for the browser code flow with PKCE | Low-level `AsyncOAuth2Client` only, not a framework |
| HTTPX | HTTP client for identity-provider admin APIs | |
| Jinja2, Babel | Localized email templates | Rendered by `EmailSender` |

Identity provider

| Technology | Purpose | Note |
|---|---|---|
| Ory Kratos | Identities, credentials, sign-in flows | Default; one per realm, production mode |
| Ory Hydra | OAuth 2.0/OIDC tokens, signing keys, JWKS | Default; one per realm, production mode |
| Ory reference UI | Sign-in, sign-up, sign-out and settings screens | Development only; replaced by our own screen before launch. Our app runs the consent step in every environment |
| Managed identity provider | Optional replacement for Ory | A deployment decision, scored against the capability checklist |

Frontend

| Technology | Purpose | Note |
|---|---|---|
| Node.js (current LTS) | Frontend build and tooling | Pinned in `.nvmrc` |
| React | UI framework | |
| TypeScript | Static typing | API client generated from OpenAPI |
| React Router | Client-side routing | |
| FormatJS (`react-intl`) | Message catalogues, ICU plurals, formatting | |
| React-admin | Administration console, including the Data section | Own app and host; its own translation provider |

Infrastructure

| Technology | Purpose | Note |
|---|---|---|
| Docker | Containerization | Images pinned by digest |
| Docker Compose | Local orchestration | Also the default deployment platform |
| Caddy | TLS proxy and edge rate limits | Built with a rate-limit module; a cloud edge may replace it at deployment |
| Mailpit | Email capture | Development only |
| Google Workspace (SMTP relay) | Production email | Interim; dedicated provider later |
| Secrets manager | Secrets in deployed environments | A deployment decision |

Tooling

| Technology | Purpose | Note |
|---|---|---|
| uv | Package/environment management | |
| Ruff | Linting and formatting | |
| Pyright | Static type checking | Strict mode |
| import-linter | Layer and context boundary checks | Runs in pre-commit and CI |
| Alembic | Database migrations | Our database only; run as a CI job |
| pytest | Testing | |
| pre-commit | Git hook framework | |
| GitHub Actions | Continuous integration | |

## Deployment Decisions

Each fork chooses these when it deploys, developing on the defaults until then.
Swaps use configuration or an adapter passing the port's contract tests, without
changes to domain or application code.

There is no default region; deployed startup requires one. The fork's operator
must assess privacy and cross-border obligations for its users, write accurate
terms and a privacy policy, and implement permanent deletion where applicable
before launch. Shell's reference deployment proves operability; it does not
certify a fork for production or privacy compliance.

| Decision | Default | Any choice must | Plugs in through |
|---|---|---|---|
| Region | None; required | Hold every component in the same region | Configuration |
| Sign-up terms | None; required (placeholders in development only) | Include the operator's own terms, privacy policy and required confirmations, such as a minimum age | Configuration |
| Compute platform | Docker Compose on one VM | Run the image with health probes, a private network whose connections are encrypted, and at least two `api` replicas | Configuration |
| Identity provider, per realm | Self-hosted Ory Kratos and Hydra | Pass the capability checklist, including region availability; then chosen on cost | Configuration for Ory Network; otherwise new adapters and sign-in module |
| PostgreSQL | Self-hosted | Support the features we use, require TLS, need no superuser | Configuration |
| Redis | Self-hosted | Require TLS and authentication | Configuration |
| Secrets manager | None; required (`.env` in development only) | Be the only source of secrets outside development | Settings source |
| Edge | Caddy with a rate-limit module | Terminate TLS, apply rate limits and security headers | Configuration |
| Email | Mailpit (development); Google Workspace relay | Send from our domain with SPF, DKIM and DMARC | `EmailSender` adapter |

How each component plugs in is described in `docs/architecture.md`.

## Repository Layout

The repository is organized by architectural responsibility rather than
technical framework.

```
apps/
    api/
        src/
            shell_api/
                contexts/
                shared/
                core/
    web/
    admin/

docs/

scripts/

tests/

docker/
```

The exact contents of each directory may evolve over time while preserving the
overall architectural organization.

`apps/` contains the application source code. `contexts/` holds business
capabilities organized as bounded contexts, each owning its own domain,
application, infrastructure, and presentation layers; the identity context's
identity-provider adapters are the only code that calls the provider. `shared/`
holds abstractions intentionally reusable across bounded contexts. `core/` holds
cross-cutting application configuration and bootstrapping. `web/` holds the
React frontend, with the sign-in screen in its own module. `admin/` holds the
React-admin console. Both call the backend's API, and both are distinct from
each bounded context's own backend-side presentation layer above, despite the
shared name. Production mobile apps live in forks. Shell's mobile contract is
verified through its integration suite and hands-on platform checks (arch §15).

`docs/` holds project documentation: vision, architecture, specification,
roadmap, decisions and guides.

`scripts/` holds repository tooling that CI runs, such as the quality-gate
script, and the staff provisioning script. `tests/` mirrors the application
architecture. `docker/` holds local development infrastructure, including Caddy
and Ory configuration.

## Documentation

| Document | Owns |
|---|---|
| `README.md` | Vision, principles, stack, deployment choices and repository layout |
| `docs/architecture.md` | Mechanisms and architectural boundaries |
| `docs/spec/auth.md` | Behavior, values and stable requirement IDs |
| `docs/roadmap.md` | Stages, requirement assignments and exit criteria |
| `docs/decisions.md` | Durable choices and rationale |
| `docs/guides/` | Workflow, requirement tests and concise fork examples |
| `docs/evidence/` | Historical snapshots; no active requirements, completion evidence or required agent reading |

## Development Philosophy

Prefer maintainability, explicit contracts, strong typing, simple abstractions,
clear boundaries, incremental evolution and documentation that removes
ambiguity. Every dependency must justify its maintenance cost. Use the simplest
solution that preserves correctness, security and verification; add mechanisms
only when requirements need them.
