# Ory trial results

## Assessment

2026-10-21: Docker Compose setup **PASS** on Docker Desktop 4.79.0,
Engine 29.5.3, Compose v5.1.4, Linux/arm64 containers on macOS.
All six checks are assessed, including the user's completed Google authorization
and independent verification of the resulting fresh, active Google OIDC session.
This is trial evidence, not a production certification.

## Six-check results

| Check | Status | Evidence / remaining work |
| --- | --- | --- |
| 1. Sign-in: passkey / WebAuthn | PASS | Chromium virtual CTAP2 authenticator registered a credential and signed in after logout; Kratos reported `webauthn` and the same identity. [Evidence](evidence/check-1.md). |
| 1. Sign-in: email code | PASS | Real registration and subsequent login using separate Mailpit-delivered codes; Kratos reported `code` and the same identity. [Evidence](evidence/check-1.md). |
| 1. Sign-in: Google | PASS | User completed real Google authorization and returned to Ory welcome. Private Kratos verification confirms a fresh, active, unexpired `oidc` session with provider `google` and mapped email, authenticated after the pre-login baseline. [Actual session evidence](evidence/google-readiness.md). |
| 2. Cookies | PASS | Real PKCE flow sets HttpOnly, Secure, SameSite=Lax host-only cookies: ES256 access JWT and opaque refresh token. Forged/missing CSRF, cross-origin refresh, and invalid state rejected. [Evidence](evidence/check-2.md). |
| 3. Stateless | PASS | Real ten-minute outage: `/me` stays 200 with Kratos/Hydra stopped, then 401 after actual exp; signed invalid claim/algorithm cases rejected. 2 tests passed in 608.28s. [Evidence](evidence/check-3.md). |
| 4. Rotation | PASS | Two rotations change both tokens; replay of the original returns 401 and the newest descendant then also fails. Local access JWT remains valid until expiry. [Evidence](evidence/check-4.md). |
| 5. Admin | PASS | Protected listing/disable/revoke and CSRF logout tested. Disablement or Kratos-only revocation leaves Hydra refresh valid; coordinated consent/token + login revocation makes refresh fail. [Evidence](evidence/check-5.md). |
| 6. Magic links | PASS (assessment) | No native `link` login method in the tested version. Actual verification link updates the address without a session; actual recovery link creates `link_recovery` and opens settings. [Evidence](evidence/check-6.md). |

## Setup evidence

Commands executed successfully:

```sh
.venv/bin/python scripts/prepare_runtime.py
docker compose config --quiet
docker compose -f compose.yaml -f compose.google.yaml config --quiet
docker compose up -d --build --wait --wait-timeout 120
docker compose exec -T bff python provision.py
python3 scripts/check_setup.py
```

The final smoke check passed every assertion against the running services:

- PostgreSQL, Kratos, Hydra, reference UI, Mailpit, FastAPI, and TLS proxy healthy.
- Both migrations exited with code 0, including subsequent runs on the same volume.
- Every published port binds to `127.0.0.1`; no host mappings for ports
  4434, 4445, 5432, or 1025.
- FastAPI `/health`, Mailpit API, Hydra discovery, and a nonempty public JWKS respond.
  Discovery reports issuer `https://localhost:4444/` after HTTPS setup.
- Browser-style requests through the reference UI follow real redirects and render
  both login and registration. Each flow includes code, WebAuthn, and a CSRF token;
  neither contains password nodes.

`scripts/check_setup.py` reproduces this evidence without creating identities,
submitting credentials, or logging flow tokens. The pytest/HTTPX/Playwright tests
exercise real identities, sessions, signing, token exchange, and revocation.
Checks 2–5 run with one command documented in README. The outage test passed in
608.28s with real exp; other targeted runs are recorded in each evidence file.
Final complete non-outage regression: **13 passed, 1 deselected in 31.37s**;
setup smoke check passed again after the link fixture restored the configuration.
See [final validation](evidence/final-validation.md) for the exact command split.

## Pinned versions

All upstream image references use explicit version tags. Downloaded repository
digests below record the exact images used for this run. The local BFF image is
built from the pinned Python base with FastAPI 0.116.1, Uvicorn 0.35.0,
HTTPX 0.28.1, and PyJWT 2.10.1. Tests pin pytest 8.4.2 and Playwright 1.56.0
(Chromium 141.0.7390.37). Application/test dependency files record these versions.

| Image | Downloaded digest |
| --- | --- |
| `postgres:17.6-alpine` | `sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94` |
| `oryd/kratos:v26.2.0` | `sha256:2a13bb8d362c7a7ae33bd7c0f5168aee46921f15c916a06346db91c06dc76643` |
| `oryd/hydra:v26.2.0` | `sha256:ff67c7fb5f95074fa53374d41151713554960504b340cd3f95b09e65deaea2a9` |
| `oryd/kratos-selfservice-ui-node:v26.2.0` | `sha256:46a7bac1ad0c67c692b37d0380613fd4618fd751afac2c5314aa8d3ae77ef1f0` |
| `axllent/mailpit:v1.27.8` | `sha256:6abc8e633df15eaf785cfcf38bae48e66f64beecdc03121e249d0f9ec15f0707` |
| `python:3.13.7-slim` | `sha256:5f55cdf0c5d9dc1a415637a5ccc4a9e18663ad203673173b8cda8f8dcacef689` |
| `caddy:2.10.2-alpine` | `sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d` |

## Official references and configuration gotchas

Version-specific sources consulted:

- [Kratos v26.2.0 release](https://github.com/ory/kratos/releases/tag/v26.2.0)
  and [Hydra v26.2.0 release](https://github.com/ory/hydra/releases/tag/v26.2.0).
- [Kratos v26.2.0 configuration schema](https://github.com/ory/kratos/blob/v26.2.0/embedx/config.schema.json):
  passwordless email requires `selfservice.methods.code.passwordless_enabled`;
  WebAuthn first-factor login requires `webauthn.config.passwordless`;
  `oauth2_provider.url` points at Hydra admin for login-challenge integration.
- [Hydra v26.2.0 configuration schema](https://github.com/ory/hydra/blob/v26.2.0/.schema/config.schema.json):
  use `strategies.access_token: jwt`, `ttl.access_token: 10m`, enforced PKCE,
  and `oauth2.grant.refresh_token.rotation_grace_period: 0s`.
- [Reference UI configuration](https://github.com/ory/kratos-selfservice-ui-node/tree/v26.2.0)
  and [pinned consent implementation](https://github.com/ory/kratos-selfservice-ui-node/blob/v26.2.0/src/routes/consent.ts):
  internal Kratos API address differs from its browser address;
  consent uses private `HYDRA_ADMIN_URL` and dedicated CSRF configuration.
- [Official passkey documentation source](https://github.com/ory/docs/blob/master/src/components/Shared/kratos/passwordless/05_passkeys.mdx):
  distinguishes passwordless WebAuthn from the dedicated passkey strategy.
  Schema presence alone does not establish open-source feature availability.
- [JWT access tokens](https://www.ory.com/docs/oauth2-oidc/jwt-access-token):
  refresh tokens remain opaque; local JWT validation cannot provide immediate
  revocation without additional state or introspection.
- [Hydra 2.0 algorithm support](https://www.ory.com/blog/oauth2-server-openid-ory-hydra-v2):
  ES256 is supported for JWT access tokens. This trial provisioned the real key
  and verified issued access JWTs cryptographically, rather than using ID tokens.
- [Link strategy in v26.2.0](https://github.com/ory/kratos/blob/v26.2.0/selfservice/strategy/link/strategy.go),
  [recovery guide](https://www.ory.com/docs/kratos/self-service/flows/account-recovery-password-reset),
  and [verification guide](https://www.ory.com/docs/kratos/self-service/flows/verify-email-account-activation):
  link flows serve recovery/verification, matching actual `link_recovery` behavior.

Observed gotchas:

1. Kratos v26.2.0 defaults to `registration.style: profile_first`. The initial
   form only exposes profile fields. Set the documented `style: unified` to
   expose the configured credential methods together, matching the manual steps.
2. Reference UI `/login` returns HTTP 303 to the Kratos browser URL. A health
   check inside the UI container must inspect this redirect without following
   it to `localhost:4433`, which refers to the UI container itself.
3. Public API base URLs, redirects, and RP origin consistently use `localhost`.
   Mixing `127.0.0.1` and `localhost` changes browser cookies and WebAuthn origins.
4. Migrations precede Ory service startup; PostgreSQL creates separate `kratos`
   and `hydra` databases on the first volume initialization.
5. The existing `.env` was preserved. Git ignores secrets, and the BFF build
   context is limited to `bff/`; Google secrets are passed only by the optional
   configuration. Base startup does not enable Google automatically.
6. Kratos's Hydra admin base URL must omit the trailing slash; otherwise its SDK
   builds a double-slash route and gets 404. The reference UI also needs exact
   browser/internal URLs and CORS for Kratos's WebAuthn script.
7. OAuth can require reauthentication after registration. The reference consent
   form must grant `openid`/`offline_access` explicitly to obtain the corresponding
   tokens. Tests complete these real screens rather than auto-accepting challenges.
8. Hydra subject-wide consent revocation needs `all=true`; revoking only Kratos
   sessions or deactivating an identity does not stop previously issued refresh.

## Production implications and licensing

**JWT validation:** ES256 only for access tokens, with signature, issuer, API
audience, expiry, required claims, and known key ID enforced locally. Signed
negative cases cover each claim, not just signature tampering. A background
five-minute JWKS refresh retains the last good set on network failure; `/me`
does no Ory call. Cold start with no keys fails closed. Plan production key
rollover/retention and stale-cache policy explicitly.

**Rotation/revocation:** zero-grace refresh replay invalidates the tested family.
Serialize refresh requests to avoid accidental reuse. Disablement, Kratos session
revocation, Hydra login-session revocation, and consent/token revocation are
different operations. The coordinator explicitly covers both systems. A copied
JWT remains locally valid until expiry (roughly ten minutes) after logout,
disablement, or token-family revocation. Immediate revocation requires state or
introspection, changing the stateless design. The trial's logout is deliberately
subject-wide; per-device logout needs additional session/grant mapping. Partial
cross-service failures need operational retries and auditability.

**Integration:** the stock reference UI handles credential screens and consent;
Kratos handles the Hydra challenge. Custom code is confined to a small FastAPI
BFF, key/client provisioning, and cross-service admin coordination. There is no
custom login UI. Expect multiple services, migrations, careful URLs, TLS, PKCE
state/nonce, consent scopes, key lifecycle, and revocation coordination rather
than a single turnkey identity server. The admin bearer credential is a disposable
operator gate, not a production role/authorization system. Cookies use secure
host-only flags; use separate production service hosts and reviewed cookie scope.

**Open source boundary:** all measured WebAuthn, code, ES256 issuance, refresh
rotation/replay detection, state disablement, subject-wide revocation, and link
flows ran in stock v26.2.0 images with no Ory Network endpoint or enterprise
license. Tagged repositories have Apache-2.0 licenses. Dedicated passkey strategy,
conditional UI, device synchronization, and fine-grained per-consent token-chain
APIs are not established by this trial; do not equate schema presence with a
licensed feature guarantee. Ory's
[per-consent token-chain announcement](https://changelog.ory.com/announcements/revoke-token-chains-by-consent-request-id)
specifically mentions Network/OEL, whereas this trial uses subject-wide operations.

**Remaining limits:** Google authorization/callback and the direct Kratos session
are now verified. A Google-specific end-to-end BFF token exchange was not observed;
the BFF's real PKCE/consent/token tests use email-code authentication.
Physical passkey UX, recovery-link replay/scanner behavior, multi-instance races,
production TLS/secrets, HA, audit, and load were not tested. Infrastructure defaults
are disposable, runtime credentials are generated locally, and Ory still uses
development mode behind local HTTPS. No production deployment was attempted.

## Verdict

**Adopt Ory for this design.**
The tested open-source stack provides WebAuthn, email-code, and Google sign-in,
real ES256 access JWTs, secure BFF cookies, local validation through a full outage,
refresh rotation with replay-family revocation, and coordinated administration
without custom login screens. Its costs are operating multiple components and
explicitly coordinating session/grant revocation; copied access JWTs remain valid
until expiry, which is intrinsic to this stateless design. Email-link sign-in is
not a first-class login method in the tested version, but verification/recovery
links are available and were not repurposed as login. If turnkey per-device
administration or first-class email-link login becomes mandatory, try Keycloak
next and validate those exact requirements separately. No Keycloak capability or
comparison is inferred from this Ory-only trial.
