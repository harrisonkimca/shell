# Security design review: Shell authentication baseline

Independent review of the design, before any code is written. Date: 8 November 2026.

**Inputs.** Paths follow the repository layout; in this project the files are stored as shown in brackets.

- `README.md` [`claude/README.md`]
- `docs/architecture.md` [`claude/architecture.md`], cited as "arch §n"
- `docs/spec/auth.md` [`claude/spec/auth.md`], cited as "spec §n" or by requirement ID
- `docs/roadmap.md` [`claude/roadmap.md`]
- `docs/decisions.md`, DEC-001 to DEC-038 [`claude/decisions.md`]; the project keeps all ADRs in this one file
- `input/trial-results.md` [`trial-results.md`], cited as "trial"

The working notes (`design-decisions.md`, `handoff-notes.md`) and the `OLD-*` files were read for context only; no finding rests on them.

**Standards, with the versions used.**

| Standard | Version used |
|---|---|
| OWASP ASVS, Level 2 | 5.0.0, May 2025, the latest release (tag `v5.0.0_release`). Level 2 = 253 requirements (70 at L1, 183 at L2) |
| NIST SP 800-63B | 800-63B-4, final, 31 July 2025 |
| OAuth 2.0 Security BCP | RFC 9700 (BCP 240), January 2025 |
| JWT BCP | RFC 8725 (BCP 225), February 2020; no successor RFC |
| JWT access tokens | RFC 9068, October 2021 |
| WebAuthn | W3C Web Authentication Level 3, Recommendation of 25 August 2026 |
| OWASP cheat sheets | Cross-Site Request Forgery Prevention, Session Management, HTML5 Security (its CORS section; there is no separate CORS sheet) and Logging, as published in November 2026 |

**How to read this file.** Severity follows the brief: Critical (takeover, bypass or exposure of all users' data by a realistic attacker), High (the same under plausible conditions, or a missing core control), Medium (a weakened control, or a gap needing a specific condition), Low (hardening or clarity). "Baseline (stage n)" means: change the documents now, build it in roadmap stage n. "To verify" marks what neither the documents nor the trial settle. Where the trial does not cover an Ory behaviour the design relies on, this file says so instead of assuming it.

## 1. Verdict

**Not ready to implement as written. Ready once the four blocking findings below are resolved in the documents.** None of them adds infrastructure: three are requirement or configuration changes, one is a corrected fallback.

| Blocking | Why it blocks | Must be fixed before |
|---|---|---|
| SEC-001 | The providers' admin APIs are protected by network placement alone, and every internal component, the internet-facing edge included, can reach them. One foothold means staff takeover through an enrollment code. | Stage 1 (Compose networking and provider configuration) |
| SEC-002 | The provider doesn't enforce user verification, and for staff the passkey is the whole sign-in: a stolen security key plus custom software is single-factor admin access. The design accepts this risk without saying what it means for staff. | Stage 1 spike; compensating control decided before stage 3 |
| SEC-003 | No realm-wide limit on code emails: about 21 IP addresses can exhaust the relay's daily quota and stop every code sign-in, and distributed guessing across many addresses goes unseen. | Stage 2 (`EmailSender` and limits) |
| SEC-004 | Per-device sign-out rests on two provider behaviours the trial didn't cover, and the documented fallback would relax AUTH-TOKEN-003, leaving a "logged-out" device's refresh chain alive. | Stage 2 spike |

**Counts.** 0 Critical, 4 High, 17 Medium, 22 Low (2 of the Low are Later).

**What is already sound.** Realms separated by issuer, keys, audience, cookies and host (DEC-006); a BFF holding tokens in `HttpOnly`, `__Host-` cookies (DEC-016); ES256-only local verification with keys from configuration only and a fail-closed cache (AUTH-TOKEN-001–003); a per-request device-record and disabled-user check that makes sign-out and disabling take effect at once despite self-contained tokens (AUTH-TOKEN-004); `private_key_jwt` instead of client secrets (DEC-017); zero-grace refresh rotation with serialization (DEC-018); codes, never links, in email (DEC-008); no automatic linking and no address change (DEC-012, DEC-009); the deletion delay and support freeze (DEC-029); audited admin reads (AUTH-ADMIN-007); and a roadmap that lists every requirement ID exactly once (checked: 194 IDs, none missing or repeated). These match RFC 9700 and ASVS Level 2, and the trial supports the parts it exercised.

**The largest uncertainty.** The trial ran Ory in development mode (trial, "Remaining limits"), and many behaviours the design depends on were not exercised: `webauthn` as a second factor, the `passkey` strategy, `amr` order, the token hook, refusing hooks, per-session revocation, enrollment codes, `private_key_jwt`, multi-instance refresh, and the absence of the provider's own account linking. The integration suite is planned to prove each one (arch §13); SEC-020 adds a production-mode re-run of the trial at stage 1, and §6 lists the tests.

## 2. Findings

Each fix names the change; the ready-to-paste wording is in §7 under the same ID. New requirement IDs follow the spec's rule that a changed meaning gets a new ID; acceptance lines that only sharpen a test are edited in place.

| ID | Severity | Area | Issue | Where | Standard | Fix | Baseline or Later |
|---|---|---|---|---|---|---|---|
| SEC-001 | High | Admin APIs, internal network | The design protects the providers' admin APIs by network placement alone (arch §3: "Internal network only"); callers authenticate with nothing. Nothing keeps any internal component from reaching them: the edge, which faces the internet, must reach the providers' public ports and so their containers, and metrics and the datastores share the network. A foothold in any of them reaches the workforce realm's admin API, which issues enrollment codes (arch §5, `issue_enrollment_code`) that register a passkey and lead to an admin session, and the token provider's admin API, which accepts login and consent challenges. AUTH-ADMIN-008's acceptance tests only "from outside". | arch §1 (Internal), §5, §9 (Security); spec AUTH-ADMIN-008, AUTH-IDP-018; README (Administration; Planned Evolution, mTLS row) | ASVS 13.2.1, 13.2.2 | New AUTH-ADMIN-013: admin listeners reachable only from `api`, `worker` and the deploy job, enforced by the platform and tested from every other container. Record ASVS 13.2.1's missing client authentication as a named deviation (SEC-019); mTLS stays Later with a sharper trigger. | Baseline (stage 1; proved again on the deployment in stage 8) |
| SEC-002 | High | Passkeys, staff sign-in | The design states that neither Kratos passkey method requires user verification and that only our screen asks for it (arch §5; DEC-011). The trial doesn't cover this: it used a Chromium virtual authenticator. For subscribers the passkey only stands in beside a device-key proof, so the accepted risk is small. For staff the passkey is the whole sign-in: custom software with a stolen security key can produce an assertion without the PIN, and the admin session follows. NIST says an assertion whose flag shows no activation factor SHALL be treated as single-factor. Spec §1's relaxation covers subscribers only, and arch §11's residual-risk row ("may skip its PIN") understates the consequence. | arch §5 (Done by Shell instead), §11 (threat table: stolen device or security key); spec §1 (Assurance), AUTH-PASSKEY-001; DEC-011; README (NIST claim for staff) | ASVS 6.3.3; NIST SP 800-63B-4 §3.1.7; WebAuthn L3 §7.2 (the relying party checks the UV flag when it required verification) | Stage 1 spike: does each realm's provider refuse an assertion without the UV flag after a ceremony that required it? New AUTH-PASSKEY-010: if the workforce provider doesn't, no workforce realm launches without a server-side control, preferably an edge allowlist for `staff-auth.` and `admin.` (the README's Later "Admin host behind a VPN or allowlist" row, whose trigger this meets). Update arch §11's row and DEC-011's trade-offs. | Baseline (spike stage 1; control by stage 8) |
| SEC-003 | High | Email codes, availability | Code limits are per address and per IP only (arch §11). Nothing caps codes realm-wide. Google Workspace's relay allows 10,000 messages per user per 24 hours when the sender is a Workspace user; at the per-IP limit of 20 code requests an hour (480 a day), about 21 addresses exhaust it, after which nobody receives a code, the only way back into an email-only account. The email step sends a code to any address (AUTH-SIGN-003), so a flood can also target non-existent addresses and damage the sender's reputation. Separately, 5 attempts per code and 10 codes a day give 50 guesses per address per day, about 1 in 20,000 per day against 6 digits; with enumeration accepted (DEC-013), expected takeovers grow with the number of codes sent, and no alert would show it. At NFR-005's 5 sign-ins a second, a daily quota of 10,000 lasts about 33 minutes. arch §16's trigger for a dedicated provider, "Production traffic", is met at launch. | arch §11 (rate-limit table), §16 (email provider row); spec AUTH-LIMIT-001–004, AUTH-CODE-003, AUTH-SIGN-003, NFR-004, NFR-005, §15 (CAPTCHA row); README (Technology Direction: Workspace relay) | ASVS 2.1.3, 2.4.1, 6.3.1, 6.6.3; NIST SP 800-63B-4 §3.1.3 (a new secret doesn't reset the failure count), §3.2.2 | New AUTH-LIMIT-007 (realm-wide hourly and daily code budget below the relay's quota, alerts at 50% and 80%) and AUTH-LIMIT-008 (failed entries counted per address across flows and realm-wide, with an alert and a documented response). Use 8-digit codes if the provider allows it (To verify). Give CAPTCHA and the dedicated email provider measurable triggers. | Baseline (stage 2) |
| SEC-004 | High | Sign-out, revocation | Logging out another device needs the sign-in ID to survive every refresh and the token hook to run at each refresh; the trial covered neither, used only subject-wide revocation, and notes that per-device logout needs extra mapping and that per-consent token-chain revocation isn't established for the open-source build. arch §15's fallback is wrong: AUTH-TOKEN-003 requires the sign-in ID in every user token, so if it doesn't survive, every refreshed token is refused. The fallback's wording ("its copied access tokens live until they expire") invites relaxing AUTH-TOKEN-003, after which a logged-out device's refresh chain keeps working while the user believes it is gone. | arch §15 (third bullet), §5 (token hook), §7 (Sign-out and limits); spec AUTH-DEVICE-004, AUTH-SESSION-006, AUTH-TOKEN-003; DEC-024; README (Authentication Philosophy: "or its device is logged out"); trial (Production implications; Open source boundary) | ASVS 7.4.1, 7.5.2, 10.4.9 | Rewrite arch §15's bullet: if the spike fails, either the hook finds another per-sign-in value the provider passes at every refresh (To verify), or logging out another device becomes logging out all devices; AUTH-TOKEN-003 is never relaxed. Update DEC-024's trade-off. AUTH-DEVICE-004's acceptance adds a direct refresh at the provider's token endpoint. | Baseline (documents before stage 2; spike at stage 2) |
| SEC-005 | Medium | Cookies, subdomains | Shell's cookies are fully specified (arch §7), the providers' are not: the domain, names and SameSite of Kratos's and Hydra's session, remembered-sign-in and flow cookies are unstated, and AUTH-IDP-002's acceptance checks only issuer, key URL and audience. A `Domain` set to the registrable domain would send provider session cookies to every host; two realms on default names would collide. The customer RP ID is the registrable domain (AUTH-PASSKEY-009), and nothing keeps third-party or user content off other subdomains (cookie tossing into provider flows, dangling CNAMEs). `__Host-` already protects Shell's own cookies. | arch §3 (Cookies; WebAuthn RP ID), §7; spec AUTH-IDP-002, AUTH-PASSKEY-009, AUTH-WEB-001 | ASVS 3.3.1–3.3.4, 3.5.4, 7.1.3; NIST SP 800-63B-4 session cookies ("minimum practical hostnames") | New AUTH-WEB-008 (provider cookies host-only on their auth host, distinct names per realm, `Secure`, Lax or stricter) and NFR-016 (no untrusted content and no dangling DNS under the registrable domain). | Baseline (stage 1; DNS check stage 8) |
| SEC-006 | Medium | OAuth consent, public clients | Our consent step grants first-party clients at once (AUTH-CLIENT-007), public clients included. Mobile apps use claimed HTTPS redirects, which give some assurance of the client's identity, but the agent-acting-for-a-user client has no stated redirect type. Software impersonating that client (its ID is public) can open a sign-in in the user's browser and, within the provider's 15-minute remembered sign-in (AUTH-SESSION-004), receive tokens with no user action. What a claimed HTTPS redirect URL serves when the app isn't installed is also unstated. | README (Clients, Scopes and Audiences); arch §4, §7 (Agents); spec AUTH-CLIENT-004, AUTH-CLIENT-006, AUTH-CLIENT-007 | ASVS 10.7.1, 7.6.2; RFC 9700 §4.1.1 (no automatic approval for public clients) | New AUTH-CLIENT-009: public clients register only claimed HTTPS or loopback redirects; our consent step refuses an agent-for-user authorization that didn't demand a new sign-in; rules for the fallback page. | Baseline (stage 3) |
| SEC-007 | Medium | Sign-out, tokens in URLs | arch §7 sends the browser through Hydra's sign-out step "with the ID-token hint", which puts an ID token in a URL, against AUTH-TOKEN-009, and into edge and provider access logs and browser history. The mechanics also clash with AUTH-WEB-003: a top-level navigation can't carry `X-CSRF-Token`, so an implementation must either exempt sign-out from the check or hand the ID token to script. The order of steps and what happens when the provider is down are unstated. | arch §7 (cookie table, `-id`; Sign-out and limits); spec AUTH-TOKEN-009, AUTH-WEB-003, AUTH-ACCT-010, AUTH-ACCT-011, AUTH-IDP-019 | ASVS 14.2.1, 10.1.1, 3.5.1, 16.5.3 | End the provider sessions server-side by the login session ID our consent step recorded, as already planned for other devices and mobile; drop the `__Host-shell-id` cookie; delete the device record first and run the provider steps as a retried task (new AUTH-ACCT-013). If per-session ending fails its check, use a form POST, never a GET URL. | Baseline (stage 2; sign-out step stage 4) |
| SEC-008 | Medium | Provider hooks, audit | Only the token hook must fail closed (AUTH-IDP-016). The sign-up and settings hooks that refuse changes have no stated failure mode; if the provider proceeds when Shell's hook is down, the 5-minute passkey window, the refusal of a passkey as latest step and the Google sign-up refusal all disappear. Sign-in audit entries come from reporting hooks, yet AUTH-AUDIT-001's acceptance ("a failed audit write rolls the action back") can't hold for a provider-side event. The trial doesn't cover webhook behaviour. | arch §5 (hooks); spec AUTH-IDP-008, AUTH-IDP-009, AUTH-AUDIT-001 | ASVS 16.5.3, 16.3.1 | New AUTH-IDP-022 (refusing hooks fail closed); our consent step, which runs in Shell, writes the sign-in and fresh-sign-in audit entries; sharpen AUTH-AUDIT-001's acceptance. | Baseline (stages 2–5) |
| SEC-009 | Medium | Account linking | DEC-012 notes that the provider "would link at sign-in before Shell's hooks run", but no requirement or test names the provider's own linking path (a sign-in that links a new method after the user proves the existing account). Linking that way skips settings, its 15-minute window and the "Google linked" notice. design-decisions.md listed linking without silent merge as unproven, and the trial doesn't cover it. | spec AUTH-SIGN-008, AUTH-SIGN-009, AUTH-ACCT-005, AUTH-NOTIFY-001; arch §8 (Across sign-in methods); DEC-012 | ASVS 6.8.1 | New AUTH-SIGN-014: the provider's own linking is unavailable through our screens and the provider's public API; the test walks every step that API offers (whether one exists is To verify). | Baseline (stage 4) |
| SEC-010 | Medium | Rate limits | No per-IP limit says how IPv6 clients are keyed. Keyed per address, one client holding a /64 (2^64 addresses) escapes the edge's 30 submissions per 15 minutes and `EmailSender`'s 20 code requests and 10 sign-ups an hour. | arch §11; spec AUTH-LIMIT-002, AUTH-LIMIT-003, AUTH-LIMIT-005 | ASVS 2.4.1, 15.3.4 | New AUTH-LIMIT-009: IPv6 keyed by /64 everywhere a per-IP limit applies. | Baseline (stages 1–2) |
| SEC-011 | Medium | Rate limits, lockout | Anyone can spend an address's 10 codes a day, so an email-only subscriber can be kept from starting a session for up to a day. AUTH-LIMIT-006 says limits never lock an account, but its acceptance tests only Google sign-in and existing sessions, and the documents don't record this residual risk, which ASVS 6.1.1 asks them to explain. | spec AUTH-LIMIT-001, AUTH-LIMIT-006; arch §11 | ASVS 6.1.1 | Record the accepted lockout with its bounds in arch §11; rolling windows; an alert on addresses repeatedly at their cap; fix AUTH-LIMIT-006's acceptance. | Baseline (stage 2) |
| SEC-012 | Medium | Refresh, Redis | The refresh lock waits 5 s and a provider call may take 5 s (arch §10), but the documents don't say what a waiting request does when its wait ends, how long the lock lives, or what refresh does with Redis down. If a waiter redeems the token itself, two replicas redeem one token and zero-grace reuse detection signs the user out. Gate challenges and continuation codes also live in Redis with no stated failure mode. The trial didn't test several instances. | arch §7 (Refresh, step 2), §10; spec AUTH-TOKEN-007; README (Technology Direction, Redis row); trial (Remaining limits) | ASVS 16.5.3, 2.3.4 | New AUTH-TOKEN-011: the lock outlives the provider timeout; a waiter answers 409 and never redeems; with Redis down, refresh answers 503 and keeps the cookies, and gates refuse. | Baseline (stage 2) |
| SEC-013 | Medium | Staff sessions | The staff idle limit (30 minutes) is the refresh-token lifetime, which restarts at each rotation. A console that polls or refreshes in the background renews it for ever, defeating AAL2's inactivity limit; nothing forbids background renewal. | spec AUTH-SESSION-002; arch §7 (Sign-out and limits) | ASVS 7.3.1; NIST SP 800-63B-4 §2.2.3 | New AUTH-SESSION-007: no token renewal without a user action since the last one, in the console and the web app. | Baseline (stage 7; web app stage 2) |
| SEC-014 | Medium | Admin, incident response | ASVS 7.4.5 (L2) asks that administrators can end sessions for one user or for all users. The design ends one subscriber's sessions; ending everyone's is Later (spec §15), yet a stolen signing key or a session-theft bug needs it at once. Deleting every device record would already refuse every token. | spec AUTH-ADMIN-002, §15 (Later: signing every subscriber out); arch §9 | ASVS 7.4.5 | New AUTH-STAFF-013: an operator command, `end-all-sessions --realm`, that deletes every device record, then runs both revocations as a task, audited and announced to admins. The console button stays Later. | Baseline (stage 3) |
| SEC-015 | Medium | Audit-log integrity | Append-only rests on the app's database role (AUTH-AUDIT-004). The migrator role used by CI, the purge role and database operators can still change or drop entries, and unlike application logs (NFR-008) the audit log isn't copied off the host. Admin accountability and PIPA's access record depend on it. | spec AUTH-AUDIT-004, AUTH-ADMIN-007, NFR-008; arch §6 | ASVS 16.4.2, 16.4.3 | New AUTH-AUDIT-005: every entry is also written to the shipped log store the app can't change, a daily count comparison alerts on gaps, and the migrator's credentials exist only in the CI migration job. | Baseline (stage 3; shipping stage 8) |
| SEC-016 | Medium | Backups | Backups hold every user's data, the providers' databases and Hydra's encrypted signing keys included. "Encrypted" is stated (NFR-006, arch §13), but not who may read, restore or delete backups, where the backup key lives, whether backups are immutable, or where the recovery kit is kept. A kit stored beside the backups would make the encryption pointless. | spec NFR-006, NFR-007, AUTH-PRIVACY-005; arch §13 (Backups and keys) | ASVS 14.2.4, 13.3.1, 13.3.2 | New NFR-017: backup key in the secrets manager and never beside the backups; operator-only access with MFA, logged; immutable for the retention period; the recovery kit in the secrets manager plus an offline copy. | Baseline (stage 9) |
| SEC-017 | Medium | Privacy, provider data | Retention and deletion cover Shell's tables and "the provider identity" (AUTH-ACCT-009, AUTH-PRIVACY-003), not the providers' flows, sessions, sent messages, login and consent records or expired tokens. Nothing shows that deleting a Kratos identity removes Hydra's records for that subject; the trial showed the two systems' state is independent (gotcha 8). Whether Kratos keeps sent messages, and so codes, isn't covered by the trial. | spec AUTH-ACCT-009, AUTH-PRIVACY-003; arch §6, §9 (Deletion), §13 | ASVS 14.2.4 (L2), 14.2.7 (L3); PIPA | New AUTH-PRIVACY-007: the providers' expired data purged daily; a deletion leaves no provider row naming the identity beyond a listed set; message storage To verify. | Baseline (stage 8) |
| SEC-018 | Medium | Secrets and keys | Rotation is set for the signing keys and, generically, "secrets list the active value first" (arch §13). There is no inventory: client assertion keys (DEC-017 says they rotate, with no period), the providers' secrets, the sign-in cookie's encryption key and algorithm, the CSRF and browser-ID hashing keys, the hook secrets (static values, which ASVS 13.2.1 counts as unchanging credentials), the internal CA key, the DKIM key and Google's client secret. | arch §1 (hooks), §6 (keyed hashes), §7 (encrypted sign-in cookie), §13 (Backups and keys); spec NFR-012; DEC-017 | ASVS 11.1.1, 11.1.2, 13.3.1, 13.3.2, 13.2.1 | New NFR-018 and a key and secret inventory in arch §13: purpose, algorithm, store, rotation period and procedure for each. | Baseline (documents now; stage 8) |
| SEC-019 | Medium | Compliance consistency | Roadmap stage 9 passes only if every ASVS L2 requirement is met, is the 6.3.3 relaxation, or doesn't apply. Two L2 requirements are deferred to Later in the README: 15.1.2 (an inventory such as an SBOM) and 13.2.1 (authenticated internal communication; mTLS is Later). Stage 9 would fail, or the deferrals would be dropped silently. | README (Planned Evolution: SBOM, mTLS); roadmap stage 9 (ASVS checklist); spec §1 (Assurance), NFR-011 | ASVS 15.1.2, 13.2.1 | New NFR-019: an SBOM from the scanner already in CI (baseline). A named "deviation" category in spec §1 and stage 9, holding only 13.2.1's client authentication, with SEC-001's control. | Baseline (stage 0; wording now) |
| SEC-020 | Medium | Proof of provider behaviour | The trial states that Ory still ran in development mode, while the design requires production mode everywhere (DEC-005). Much of arch §5's "Ory v26.2.0 provides" list wasn't exercised (see the verdict). The integration suite will prove those items, but stage 1's exit doesn't re-prove the trial's own results in production mode, and arch §5 reads as if all items were proven. | arch §5 (capability checklist), §13 (integration suite); roadmap stage 1; DEC-004, DEC-005; trial (Remaining limits; Open source boundary) | Method | Stage 1 exit: the trial's six checks pass again in production mode. arch §5 marks which items the trial proved and which wait for the integration suite. | Baseline (stage 1) |
| SEC-021 | Medium | Supply chain, CI | NFR-011 pins images and locks dependencies but says nothing about CI itself, which holds the deploy role, the migrator credentials, signing-key creation and internal certificates (arch §13). An unpinned third-party action or a broad workflow token would hand all of that to whoever compromises the action. | spec NFR-011; arch §13 (CI/CD); README (Tooling, GitHub Actions) | ASVS 15.1.1, 15.2.1, 13.3.2 | New NFR-020: actions pinned by commit SHA, least-privilege workflow tokens, deployment in a protected environment run only from the main branch and never for pull requests from forks. | Baseline (stage 0) |
| SEC-022 | Low | Cookies, SameSite | Strict token cookies are the right choice (the trial used Lax), but AUTH-WEB-002's acceptance ("the first request after the callback carries the token cookies") is ambiguous. After a return through Google the redirect chain starts cross-site, so in some engines the navigation that lands on the return path won't carry Strict cookies, while the app's own API calls from that page will. A failing test invites a downgrade to Lax. | spec AUTH-WEB-002; arch §7 (Browser, step 3), §13 (integration suite); DEC-016; trial check 2 | ASVS 3.3.2 | The callback answers with a small same-origin page that navigates to the return path; the acceptance measures the app's first API call and forbids downgrading. | Baseline (stage 2) |
| SEC-023 | Low | Token checks | AUTH-TOKEN-003 doesn't check the `typ` header; RFC 9068 §4 has the resource server accept only `at+jwt`. Whether Hydra sets it isn't covered by the trial. Audience and required claims already separate ID tokens, which meets RFC 8725 §3.12 if written down. | spec AUTH-TOKEN-003; arch §3 (Accepting a token) | RFC 9068 §4; RFC 8725 §3.11–3.12; ASVS 9.2.2 | New AUTH-TOKEN-012. | Baseline (stage 2) |
| SEC-024 | Low | Principal | How a token is classed as a service or a user isn't stated; a client-credentials token carries the client ID as `sub`. | arch §4 (The principal); spec AUTH-CLIENT-005, AUTH-TOKEN-004 | RFC 9700 §4.15; ASVS 10.3.3 | New AUTH-CLIENT-010: kind comes from the client registry and the grant, never from claims alone. | Baseline (stage 3) |
| SEC-025 | Low | Identifiers, randomness | Entropy is set for `state`, nonce, verifier, gate challenges and the browser ID, not for sign-in IDs or continuation codes. How the device list names a record isn't stated; if it uses the sign-in ID, any session learns every other device's sign-in ID. | spec AUTH-FRESH-010, AUTH-DEVICE-001, AUTH-SESSION-006; arch §6, §8 | ASVS 11.5.1 | New AUTH-DEVICE-007. | Baseline (stage 5) |
| SEC-026 | Low | CSRF | The CSRF token is a plain double-submit value; OWASP now recommends an HMAC bound to the session ("signed double-submit") and discourages the plain form. The CSRF cookie "expires with its contents", which is unclear once the access token has expired and the app must refresh. The public BFF routes (refresh, sign-out) aren't explicitly kept under the check, and "a same-origin `Sec-Fetch-Site`" should say that `same-site` is refused, since sibling hosts are same-site. | arch §4, §7; spec AUTH-WEB-003, AUTH-SCOPE-001 | ASVS 3.5.1; OWASP CSRF Prevention CS (Signed Double-Submit Cookie; Fetch Metadata) | New AUTH-WEB-009. | Baseline (stage 2) |
| SEC-027 | Low | Redirects | AUTH-WEB-006 bounds the BFF's `return_to`, but the providers' redirect targets (Kratos's return URLs, Hydra's post-sign-out URIs) have no allowlist requirement, and clients' response types aren't limited to `code`. | spec AUTH-WEB-006, AUTH-CLIENT-001; arch §4 | ASVS 3.7.2, 10.6.1; RFC 9700 §4.11 | New AUTH-WEB-010. | Baseline (stage 1) |
| SEC-028 | Low | Recovery, verification flows | The workforce realm keeps the recovery flow on for enrollment codes, and the trial shows the link method creates a `link_recovery` session that opens settings; the method isn't specified. Nor is whether any verification flow runs (the trial's verification link changed an address without a session). AUTH-CODE-005 governs Shell's templates, not the provider's flow settings. | spec AUTH-IDP-001, AUTH-STAFF-008, AUTH-CODE-005; arch §9; DEC-008; trial check 6 | ASVS 6.3.4 | New AUTH-IDP-023: code method only, link method off, in both realms. | Baseline (stage 1) |
| SEC-029 | Low | Transport | NFR-014 redirects plain HTTP to HTTPS on every public host, `api.` included. API endpoints shouldn't redirect, so a client sending a bearer token over HTTP fails visibly instead of silently. | spec NFR-014 | ASVS 4.1.2 | New NFR-021, replacing NFR-014. | Baseline (stage 8) |
| SEC-030 | Low | Caching | `no-store` covers sign-in, token and account responses only (AUTH-WEB-005); admin and Data-section responses carry subscribers' personal data. | spec AUTH-WEB-005 | ASVS 14.3.2, 14.2.2 | New AUTH-WEB-011: `no-store` on every authenticated response. | Baseline (stage 7) |
| SEC-031 | Low | Email codes, phishing | Email codes aren't phishing-resistant. Notices have content rules (AUTH-NOTIFY-005); code emails don't: nothing says staff never ask for a code, where it may be entered, or what requested it. | spec AUTH-CODE-005, AUTH-NOTIFY-005 | NIST SP 800-63B-4 §3.2.5; ASVS 6.3.5 (L3, advisory) | New AUTH-CODE-007. | Baseline (stage 2) |
| SEC-032 | Low | Support process | Lifting the support freeze waits for the owner to "write from the account's address" (AUTH-ADMIN-005, DEC-029); a sender address is easy to forge. | spec AUTH-ADMIN-005; DEC-029 | ASVS 6.4.4 (by analogy) | New AUTH-ADMIN-014: proof by receiving a reference sent to the address. | Baseline (stage 7) |
| SEC-033 | Low | Trusted devices | Challenges are bound to the account, not to the session or the route, and the device key's algorithm and validation aren't stated. | spec AUTH-TRUST-004, AUTH-TRUST-005; arch §8 (Trusted devices) | ASVS 6.7.2, 11.6.1 | New AUTH-TRUST-008. | Baseline (stage 6) |
| SEC-034 | Low | Deletion | AUTH-FRESH-007 needs "a sign-in made for the challenge", but how the new session proves that link, across the continuation-code hand-over that ends the old session, isn't described. | spec AUTH-FRESH-007, AUTH-ACCT-007; arch §4 (Gates) | ASVS 2.3.1 | One sentence in arch §4: the challenge's ID travels through the sign-in onto the new device record. | Baseline (stage 5) |
| SEC-035 | Low | Signing-key rotation | On compromise the old key is deleted at once (arch §13), but each replica keeps cached keys for up to 5 minutes, or 1 hour when the key URL is unreachable (arch §10); no step drops them, and the stage 9 rehearsal covers only planned rotation. | arch §10 (Timeouts and retries), §13 (Backups and keys); spec AUTH-TOKEN-010; roadmap stage 9 | ASVS 11.1.1 | Emergency steps in arch §13 (delete, restart every `api` replica, rotate the system secret if the key store may be exposed, audit), rehearsed. | Baseline (stage 9) |
| SEC-036 | Low | Logging | NFR-010's scan covers "the integration suite's logs", which may not include the providers and the edge. Access logs record query strings: the authorization code and `state` at the callback, provider challenges, and today the sign-out hint (SEC-007). Nothing requires the providers' option to log sensitive values to stay off. | spec NFR-008, NFR-010, AUTH-AUDIT-003; arch §13 (Observability) | ASVS 16.2.5; OWASP Logging CS ("Data to exclude") | Edit NFR-010's acceptance; one sentence in arch §13. | Baseline (stage 2; stage 8) |
| SEC-037 | Low | Injection, deserialization | `EmailSender` renders Jinja2 templates containing user-supplied names, with autoescaping unstated. arq serializes jobs with pickle by default (Verify), so anyone who can write to Redis could run code in the worker, which holds provider admin access. | arch §5 (EmailSender), §6 (Durable work); README (Technology Direction: arq, Jinja2) | ASVS 1.2.1, 1.3.11, 1.5.2 | One sentence in arch §6: autoescaping on, user values only in message bodies, arq jobs carry IDs and serialize as JSON. | Baseline (stages 2–3) |
| SEC-038 | Low | Data protection, configuration | AUTH-PRIVACY-002 lists stored data but assigns no protection levels. Outbound connections aren't listed as an allowlist. Whether the OpenAPI document and interactive docs are served on deployed hosts isn't stated (FastAPI serves them by default). | spec AUTH-PRIVACY-002, NFR-013; arch §1, §6; README (Technology Direction: FastAPI publishes OpenAPI) | ASVS 14.1.1, 14.1.2, 13.1.1, 13.2.4, 13.2.5, 13.4.5 | A classification table in arch §6, an egress list in arch §1, and NFR-013's acceptance extended to docs. | Baseline (documents now; stage 8) |
| SEC-039 | Low | Database, identity schema | One PostgreSQL server holds every database, and PostgreSQL grants `CONNECT` to `PUBLIC` by default, so each role can connect to the others' databases. The identity schema's traits aren't restricted, and nothing says Shell ignores provider traits for authorization. | arch §6 (Layout); README (Identity Model) | ASVS 13.2.2, 8.3.1 | One sentence in arch §6. | Baseline (stage 1) |
| SEC-040 | Low | Anti-automation | Only flow submissions are limited at the edge; authenticated routes (gate challenges, continuation codes, admin search) have no limit, and nothing alerts on a burst of high-risk admin actions by a rogue or phished admin. | arch §11 (rate-limit table), §16 (per-user quotas Later); spec NFR-009 | ASVS 2.4.1, 15.1.3, 15.2.2 | New AUTH-LIMIT-010 (coarse per-IP limit on Shell's hosts; per-session caps on open challenges and codes); NFR-009 alerts on high-risk admin actions. Per-user quotas stay Later. | Baseline (stage 6) |
| SEC-041 | Low | Consistency | DEC-016 says only the sign-in cookie is Lax; arch §7 also makes the browser-ID cookie Lax. The README says no table stores the address; AUTH-AUDIT-002 keeps masked addresses in the audit log. | DEC-016; arch §7; README (Identity Model); spec AUTH-AUDIT-002 | — | Wording fixes. | Baseline (documents now) |
| SEC-042 | Low | Email deliverability | SPF, DKIM and DMARC at `quarantine` (AUTH-NOTIFY-007) are adequate for launch; `reject` and MTA-STS would better protect code emails from spoofing. | spec AUTH-NOTIFY-007; arch §11 | — | Later row with its trigger. | Later: 30 days of DMARC aggregate reports with no legitimate failures |
| SEC-043 | Low | Trusted devices | Sign-out keeps the device key and browser ID by design (AUTH-ACCT-010, AUTH-TRUST-007), so a shared computer stays trusted for up to 30 days. | spec AUTH-ACCT-010, AUTH-TRUST-007; arch §7 | ASVS 14.3.1 | Later row: "Forget this device" at sign-out. | Later: users sign in on shared or public computers |

**Contradictions between files:** SEC-003 (arch §16's email trigger already met at launch), SEC-004 (arch §15 against AUTH-TOKEN-003), SEC-007 (arch §7 against AUTH-TOKEN-009 and AUTH-WEB-003), SEC-019 (README's Later list against roadmap stage 9), SEC-041.

**Acceptance lines that don't prove their requirement:** AUTH-ADMIN-008 (tests only from outside; SEC-001), AUTH-PASSKEY-001 (shows the provider accepts verified ceremonies, not that it refuses unverified ones; SEC-002), AUTH-DEVICE-004 (no direct refresh at the provider; SEC-004), AUTH-IDP-002 (no cookies or hosts; SEC-005), AUTH-AUDIT-001 (provider-side events; SEC-008), AUTH-LIMIT-006 (email-only accounts; SEC-011), AUTH-AUDIT-004 (only the app's role; SEC-015), NFR-006 (backup age only; SEC-016), AUTH-WEB-002 (which request; SEC-022), NFR-010 (which logs; SEC-036).

## 3. ASVS 5.0.0 Level 2 coverage, by chapter

Every L1 and L2 requirement (253) is placed in one row. **Covered**: a spec requirement, or a stated mechanism in the named file, meets it. **Gap**: a finding. **N/A**: doesn't apply, with the reason. **Code**: a coding-level control the design can't show; it belongs to the implementation review and the stage 9 checklist. L3 requirements the spec cites (6.3.5–6.3.8, 6.5.6, 6.7.2, 7.5.3, 8.2.4, 8.3.2, 8.4.2, 14.2.7) are beyond the target and not scored.

**V1 Encoding and Sanitization**

| ASVS | Status | Where, or why |
|---|---|---|
| 1.2.4 | Covered | SQLAlchemy ORM (README); the Data section runs no SQL (AUTH-ADMIN-010) |
| 1.3.7, 1.3.11 | Gap | SEC-037 (template autoescaping; user values out of mail headers) |
| 1.5.2 | Gap | SEC-037 (arq's pickle) |
| 1.1.1, 1.1.2, 1.2.1–1.2.3, 1.2.9, 1.3.2, 1.3.3, 1.3.10 | Code | React and JSON encoding, no `eval`, Data-section search without user regexes |
| 1.2.5–1.2.8, 1.3.1, 1.3.4, 1.3.5, 1.3.6, 1.3.8, 1.3.9, 1.4.1–1.4.3, 1.5.1 | N/A | No OS commands, LDAP, XPath, LaTeX, rich-text, SVG or markup input, user-supplied URLs, JNDI, memcache or XML; memory-safe languages |

**V2 Validation and Business Logic**

| ASVS | Status | Where, or why |
|---|---|---|
| 2.3.1 | Covered | AUTH-SIGN-010, AUTH-FRESH-007, AUTH-ACCT-007 |
| 2.3.2 | Covered | AUTH-LIMIT-001–006 |
| 2.3.3 | Covered | Unit of Work (README); AUTH-NOTIFY-006, AUTH-AUDIT-001 |
| 2.3.4 | Covered | AUTH-TOKEN-007 (serialized refresh), AUTH-CODE-001 (simultaneous submissions); SEC-012 |
| 2.1.3 | Gap | No realm-wide limits documented: SEC-003, SEC-040 |
| 2.4.1 | Gap | Partly AUTH-LIMIT-001–003; SEC-003, SEC-010, SEC-040 |
| 2.1.1, 2.1.2, 2.2.1–2.2.3 | Code | Pydantic models and OpenAPI schemas at the server (README, DEC-022) |

**V3 Web Frontend Security**

| ASVS | Status | Where, or why |
|---|---|---|
| 3.3.1–3.3.4 | Covered for Shell; gap for providers | AUTH-WEB-001 (arch §7); provider cookies SEC-005 |
| 3.4.1–3.4.6 | Covered | AUTH-WEB-004, AUTH-WEB-005 |
| 3.5.1 | Covered | AUTH-WEB-003; SEC-007, SEC-026 |
| 3.5.3 | Covered | Unsafe methods for changes (AUTH-WEB-003); the consent step's GET is bound to a single-use provider challenge (AUTH-SCOPE-001) |
| 3.5.4 | Covered | Separate hosts per app and realm (arch §1; AUTH-ADMIN-008); SEC-005 |
| 3.7.2 | Covered for the BFF; gap for providers | AUTH-WEB-006; SEC-027 |
| 3.2.1 | Code | JSON `Content-Type` and `nosniff` (AUTH-WEB-005) |
| 3.2.2, 3.5.5, 3.7.1 | Code | Safe rendering in React and React-admin; no `postMessage` handlers; supported frameworks |
| 3.5.2 | N/A | No reliance on CORS preflight; CORS is closed (AUTH-WEB-004) |

**V4 API and Web Service**

| ASVS | Status | Where, or why |
|---|---|---|
| 4.1.3 | Covered | AUTH-LIMIT-005 |
| 4.1.2 | Gap | SEC-029 |
| 4.1.1, 4.2.1 | Code | `Content-Type` with charset; consistent message framing between the edge and the app server |
| 4.3.1, 4.3.2, 4.4.1–4.4.4 | N/A | No GraphQL, no WebSockets |

**V5 File Handling**: 5.1.1, 5.2.1–5.2.3, 5.3.1, 5.3.2, 5.4.1–5.4.3 N/A. The baseline accepts and serves no files; a fork adding uploads takes on V5.

**V6 Authentication**

| ASVS | Status | Where, or why |
|---|---|---|
| 6.1.1 | Covered, with a gap | AUTH-LIMIT-001–006, arch §11; malicious lockout not documented: SEC-011 |
| 6.1.3, 6.3.4 | Covered | AUTH-ASSURE-001/002, AUTH-IDP-001, AUTH-PASSKEY-004, spec §1; SEC-009, SEC-028 |
| 6.3.1 | Covered, with a gap | AUTH-LIMIT-001–003; SEC-003 |
| 6.3.2 | Covered | AUTH-STAFF-011 |
| 6.3.3 | Subscribers: documented relaxation (spec §1), as 6.3.3 allows with a full rationale and mitigating controls. Staff: gap | SEC-002 |
| 6.4.1 | Covered | AUTH-STAFF-003 |
| 6.4.4 | Covered | AUTH-STAFF-004 (staff); subscribers have no factor whose loss locks them out |
| 6.5.1, 6.5.3–6.5.5 | Covered | AUTH-CODE-001, AUTH-CODE-002, AUTH-STAFF-003 (6 digits ≈ 20 bits meets 6.5.4's minimum; SEC-003 suggests 8) |
| 6.6.2 | Covered | AUTH-CODE-001, AUTH-IDP-005 |
| 6.6.3 | Covered, with a gap | AUTH-CODE-003, AUTH-LIMIT-001; SEC-003 |
| 6.8.1 | Covered | AUTH-SIGN-006, AUTH-SIGN-009; SEC-009 |
| 6.8.2 | Covered | AUTH-IDP-006 (the provider validates Google's ID token; the trial showed only that a Google session was created: To verify) |
| 6.8.4 | Covered | AUTH-FRESH-002, AUTH-FRESH-005, AUTH-IDP-007 |
| 6.1.2, 6.2.1–6.2.12, 6.4.3 | N/A | No passwords (AUTH-IDP-001) and no subscriber recovery flow |
| 6.4.2 | N/A | No hints or secret questions anywhere |
| 6.5.2 | N/A | No lookup secrets |
| 6.6.1 | N/A | No SMS or voice |
| 6.8.3 | N/A | No SAML |

**V7 Session Management**

| ASVS | Status | Where, or why |
|---|---|---|
| 7.1.1 | Covered | AUTH-SESSION-001/002 with spec §1's rationale |
| 7.1.2 | Covered | AUTH-SESSION-005 |
| 7.1.3 | Covered, with a gap | AUTH-SESSION-004, AUTH-IDP-019, arch §7; provider cookies SEC-005 |
| 7.2.1, 7.2.2 | Covered | AUTH-TOKEN-001–004 |
| 7.2.3 | N/A for tokens | Self-contained tokens; Shell's own single-use values: SEC-025 |
| 7.2.4 | Covered | New tokens at every sign-in and fresh sign-in, old session ended (arch §7; AUTH-FRESH-010) |
| 7.3.1 | Covered, with a gap | AUTH-SESSION-001/002; SEC-013 |
| 7.3.2 | Covered | AUTH-SESSION-003 |
| 7.4.1 | Covered, conditional | AUTH-ACCT-010, AUTH-DEVICE-003/004, AUTH-TOKEN-004; depends on SEC-004 |
| 7.4.2 | Covered | AUTH-ACCT-008, AUTH-ADMIN-004, AUTH-STAFF-006, AUTH-TOKEN-008 |
| 7.4.3, 7.4.4 | Covered | AUTH-ACCT-012 |
| 7.4.5 | Gap | One user only (AUTH-ADMIN-002): SEC-014 |
| 7.5.1 | Covered | AUTH-FRESH-003, AUTH-FRESH-008, AUTH-IDP-010, AUTH-PASSKEY-006/008, AUTH-ACCT-005/006 |
| 7.5.2 | Covered | AUTH-DEVICE-001, AUTH-DEVICE-004, AUTH-DEVICE-005 |
| 7.6.1 | Covered | AUTH-IDP-019, AUTH-SESSION-004 |
| 7.6.2 | Covered, with a gap | AUTH-SESSION-004; agent clients SEC-006 |

**V8 Authorization**

| ASVS | Status | Where, or why |
|---|---|---|
| 8.1.1 | Covered | Route catalogue (spec §9), AUTH-SCOPE-004 |
| 8.1.2, 8.2.3 | Covered | AUTH-ADMIN-011 |
| 8.2.1 | Covered | AUTH-SCOPE-001/003, AUTH-ADMIN-001, AUTH-TOKEN-005 |
| 8.2.2 | Covered | AUTH-SCOPE-002 |
| 8.3.1 | Covered | Server-side guard and gates (arch §4); SEC-039 |
| 8.4.1 | N/A | One tenant per fork; realms are separated by issuer (DEC-006) |

**V9 Self-contained Tokens**

| ASVS | Status | Where, or why |
|---|---|---|
| 9.1.1, 9.1.2 | Covered | AUTH-TOKEN-001 |
| 9.1.3 | Covered | AUTH-TOKEN-002 |
| 9.2.1 | Covered | AUTH-TOKEN-003 |
| 9.2.2 | Covered, with a gap | AUTH-TOKEN-003; SEC-023 |
| 9.2.3 | Covered | AUTH-TOKEN-003, AUTH-TOKEN-005 |
| 9.2.4 | Covered | AUTH-IDP-002, AUTH-IDP-014 |

**V10 OAuth and OIDC**

| ASVS | Status | Where, or why |
|---|---|---|
| 10.1.1 | Covered, with a gap | AUTH-TOKEN-009; SEC-007 |
| 10.1.2, 10.2.1, 10.5.1, 10.5.4 | Covered | AUTH-WEB-007 |
| 10.2.2, 10.5.3 | Covered | AUTH-CLIENT-008 (one issuer per client, so no mix-up) |
| 10.3.1 | Covered | AUTH-TOKEN-003, AUTH-TOKEN-005 |
| 10.3.2 | Covered | AUTH-SCOPE-001, AUTH-SCOPE-003 |
| 10.3.3, 10.5.2 | Covered | (`iss`, `sub`) mapping (arch §3; AUTH-TOKEN-004); SEC-024 |
| 10.3.4 | Covered | AUTH-FRESH-002, AUTH-FRESH-005, AUTH-TOKEN-006 |
| 10.4.1–10.4.3 | Covered | AUTH-IDP-012, AUTH-CLIENT-001 |
| 10.4.4, 10.4.11 | Covered | AUTH-IDP-013, AUTH-CLIENT-001, AUTH-CLIENT-006 |
| 10.4.5 | Covered | AUTH-IDP-015, AUTH-TOKEN-007 (proved by the trial, check 4) |
| 10.4.6 | Covered | AUTH-IDP-012, AUTH-CLIENT-002 |
| 10.4.8 | Covered, conditional | AUTH-SESSION-003, enforced by the token hook: SEC-004 |
| 10.4.9 | Covered | The device list ends grants (AUTH-DEVICE-004/005) |
| 10.4.10 | Covered | AUTH-CLIENT-002 |
| 10.6.1 | Gap | Response types not limited: SEC-027 |
| 10.6.2 | Covered | AUTH-ACCT-011 |
| 10.7.1 | Covered, with a gap | AUTH-CLIENT-007; public clients SEC-006 |
| 10.4.7 | N/A | Dynamic registration is off (AUTH-CLIENT-001) |
| 10.5.5 | N/A | No back-channel logout |
| 10.7.2, 10.7.3 | N/A | No consent screen and first-party grants only; third-party consent is Later (README) |

**V11 Cryptography**

| ASVS | Status | Where, or why |
|---|---|---|
| 11.1.1, 11.1.2 | Gap | SEC-018, SEC-035 |
| 11.2.3, 11.4.3, 11.6.1 | Covered | ES256 on P-256 (AUTH-TOKEN-001, AUTH-CLIENT-002); device keys SEC-033 |
| 11.5.1 | Covered, with a gap | AUTH-WEB-007, AUTH-TRUST-005, AUTH-NOTIFY-002; SEC-025 |
| 11.2.2 | Covered | Algorithms and key sets are configuration |
| 11.3.1–11.3.3, 11.4.1 | Gap (naming) | Sign-in cookie encryption and keyed hashes have no named algorithm: SEC-018 |
| 11.2.1 | Code | PyJWT and its crypto backend, Web Crypto, platform keystores |
| 11.4.2, 11.4.4 | N/A | No passwords |

**V12 Secure Communication**

| ASVS | Status | Where, or why |
|---|---|---|
| 12.1.1, 12.1.2, 12.2.1, 12.2.2 | Covered | NFR-014 (NFR-021 after SEC-029) |
| 12.3.1–12.3.4 | Covered | NFR-015, DEC-036 |
| 12.1.3 | N/A | No mTLS in the baseline |

**V13 Configuration**

| ASVS | Status | Where, or why |
|---|---|---|
| 13.2.2 | Covered | Separate database roles (arch §6), AUTH-ADMIN-009; SEC-039 |
| 13.3.1 | Covered | NFR-012 |
| 13.4.2 | Covered | AUTH-IDP-020 (providers); Shell's debug mode: Code |
| 13.4.5 | Covered, with a gap | NFR-013, AUTH-ADMIN-008; API docs SEC-038 |
| 13.1.1, 13.2.4, 13.2.5 | Gap | SEC-038 |
| 13.2.1 | Gap (named deviation proposed) | SEC-001, SEC-018, SEC-019 |
| 13.3.2 | Gap | SEC-018, SEC-021 |
| 13.2.3, 13.4.1, 13.4.3, 13.4.4 | Code | No default credentials; no `.git` in images; no directory listing or TRACE at the edge |

**V14 Data Protection**

| ASVS | Status | Where, or why |
|---|---|---|
| 14.2.1 | Covered, with a gap | AUTH-CODE-005, AUTH-TOKEN-009, AUTH-PRIVACY-004; SEC-007 |
| 14.2.2, 14.3.2 | Covered, with a gap | AUTH-WEB-005; SEC-030 |
| 14.2.3 | Covered | Per-host CSP allowlists (AUTH-WEB-005); no trackers stated: SEC-038 |
| 14.3.1 | Covered | AUTH-ACCT-010 (the device key and browser ID are kept on purpose; SEC-043) |
| 14.3.3 | Covered | AUTH-TOKEN-009 |
| 14.1.1, 14.1.2 | Gap | SEC-038 |
| 14.2.4 | Gap | SEC-016, SEC-017 |

**V15 Secure Coding and Architecture**

| ASVS | Status | Where, or why |
|---|---|---|
| 15.1.1, 15.2.1 | Covered | NFR-011; SEC-021 |
| 15.3.1, 15.3.3 | Covered | AUTH-ADMIN-011 |
| 15.3.4 | Covered, with a gap | AUTH-LIMIT-005, AUTH-IDP-011; SEC-010 |
| 15.2.3 | Covered | AUTH-SIGN-001 (reference UI); the test-only route ships in test builds only (spec §9) |
| 15.1.2 | Gap | SEC-019 |
| 15.1.3, 15.2.2 | Gap | SEC-040 |
| 15.3.2, 15.3.5–15.3.7 | Code | No redirect following on outbound calls; strict types (Pyright strict, DEC-002); no prototype pollution; no parameter pollution |

**V16 Security Logging and Error Handling**

| ASVS | Status | Where, or why |
|---|---|---|
| 16.1.1, 16.2.2–16.2.4 | Covered | NFR-008 |
| 16.2.1 | Covered | AUTH-AUDIT-002, NFR-008 |
| 16.2.5 | Covered, with a gap | AUTH-AUDIT-002, NFR-010; SEC-036 |
| 16.3.1 | Covered, with a gap | AUTH-AUDIT-001, AUTH-AUDIT-003; SEC-008 |
| 16.3.2, 16.3.3 | Covered | AUTH-AUDIT-003, AUTH-ADMIN-001 |
| 16.3.4 | Covered, partly | Unexpected errors (AUTH-ERROR-001); internal TLS failures are not named: add to NFR-009 when SEC-018 is done |
| 16.4.2, 16.4.3 | Covered for logs; gap for the audit log | NFR-008, AUTH-AUDIT-004; SEC-015 |
| 16.5.1 | Covered | AUTH-ERROR-001 |
| 16.5.2 | Covered | NFR-002 |
| 16.5.3 | Covered, with a gap | AUTH-LIMIT-004, AUTH-IDP-016; SEC-008, SEC-012 |
| 16.4.1 | Code | JSON log encoding |

**V17 WebRTC**: 17.1.1, 17.2.1–17.2.4, 17.3.1, 17.3.2 N/A. No WebRTC.

## 4. Threat model

### Assets

| Asset | Why it matters |
|---|---|
| Subscriber accounts and their mailboxes or Google accounts | The email ceiling: whoever holds the mailbox holds the account (spec §1, arch §11) |
| Staff accounts and the admin capability | Act on every subscriber; staff are above the email ceiling (DEC-015) |
| Access JWTs, refresh tokens, ID tokens | Bearer credentials (arch §7) |
| Provider sessions (Kratos session, Hydra remembered sign-in, flow cookies) | Start new sessions and reach the provider's settings screens |
| Signing keys per realm, Hydra's system secret, client assertion keys | Forge or obtain tokens |
| Email codes and staff enrollment codes | Sign in or enroll a passkey |
| Device keys, browser and install IDs | Trusted-device proofs; new-device notices |
| The provider admin APIs | Create identities, issue enrollment codes, accept login and consent |
| Audit log, personal data (addresses in the provider; names, device records, IPs in the audit log), backups | Accountability, privacy law (PIPA, GDPR) |
| CI/CD, the secrets manager, the internal CA | Everything else derives from them |
| The relay's sending quota and reputation | The only way back into an email-only account |

### Trust boundaries

| ID | Boundary |
|---|---|
| B1 | Internet ↔ edge (TLS, headers, per-IP limits; public paths only) |
| B2 | Edge ↔ Shell, and edge ↔ each realm's public provider endpoints |
| B3 | Shell ↔ provider admin APIs (private network; no client authentication today: SEC-001) |
| B4 | Providers → Shell's hooks, consent and email routes (private network; per-call secret) |
| B5 | Shell and providers ↔ PostgreSQL and Redis |
| B6 | `EmailSender` → relay → the user's mailbox (outside our control) |
| B7 | Customer Kratos ↔ Google |
| B8 | Browser origins: `app.`, `api.`, `admin.`, `auth.`, `staff-auth.` (same site, different origins) and other subdomains |
| B9 | Mobile app ↔ system browser (claimed HTTPS redirect) |
| B10 | Customer realm ↔ workforce realm (issuer, keys, audience, cookies, host) |
| B11 | Operators and CI ↔ cloud IAM, secrets manager, deployment |

### Flows

STRIDE letters: S spoofing, T tampering, R repudiation, I information disclosure, D denial of service, E elevation of privilege. "Residual" names the accepted risk or the finding that leaves the threat open.

**Registration (email code or Google)**

| | Threat | Mitigated by | Residual |
|---|---|---|---|
| S | Sign up with someone else's address | Code proves mailbox control: AUTH-SIGN-004, AUTH-CODE-001–003 | Email ceiling (accepted) |
| S | Google sign-up with an unverified or already-used address | AUTH-IDP-006, AUTH-SIGN-007, AUTH-SIGN-008 | SEC-009 (provider's own linking) |
| T | Extra identity traits set at sign-up | — | SEC-039 |
| R | Sign-up without a record | AUTH-AUDIT-001 via the provider's report | SEC-008 |
| I | Learn whether an address has an account | AUTH-SIGN-003, AUTH-ERROR-003 | Provider's code sign-in reveals it (AUTH-ERROR-004, DEC-013, accepted) |
| D | Code floods to arbitrary or non-existent addresses | AUTH-LIMIT-002, AUTH-LIMIT-003 | SEC-003, SEC-010 |
| E | Use the API before accepting terms | AUTH-SIGN-010 | — |

**Sign-in by email code**

| | Threat | Mitigated by | Residual |
|---|---|---|---|
| S | Guess a code | AUTH-CODE-001–003, AUTH-LIMIT-001 | Distributed guessing: SEC-003 |
| S | Phished or relayed code ("read me the code"; a proxy site) | — (codes aren't phishing-resistant) | Email ceiling; SEC-031 |
| S | Use a code in another flow | AUTH-CODE-001, AUTH-IDP-005 | — |
| T | Forge the client IP to dodge per-IP limits | AUTH-LIMIT-005 | SEC-010 |
| R | Failed and successful sign-ins unrecorded | AUTH-AUDIT-001, AUTH-AUDIT-003 | SEC-008 |
| I | Enumeration through the provider's API | Accepted (AUTH-ERROR-004) | — |
| D | Mail bombing; targeted lockout; relay quota | AUTH-CODE-004, AUTH-LIMIT-001 | SEC-011, SEC-003 |
| E | A disabled account signs in | AUTH-SIGN-013, AUTH-TOKEN-004 | Arch §15 (provider reveals before the code: To verify) |

**Sign-in by Google**

| | Threat | Mitigated by | Residual |
|---|---|---|---|
| S | A Google account holding the victim's address (unverified, or an expired domain) | AUTH-SIGN-006–009; accounts found by Google's ID | Email ceiling (arch §11) |
| S | Forged or replayed Google ID token | AUTH-IDP-006 (provider validates) | To verify: the trial showed only that a Google session was created |
| T | Provider links Google to an existing account outside settings | DEC-012, AUTH-SIGN-009 | SEC-009 |
| R | — | AUTH-AUDIT-001 | SEC-008 |
| I | AUTH-SIGN-008's message confirms an address has an account | Order the checks: unverified first | Low; holder of a verified Google address controls that address |
| E | Google step accepted as a fresh sign-in before Google re-prompts | AUTH-FRESH-004 | Arch §15 check |

**Sign-in by passkey (staff), and passkey confirmation (subscribers)**

| | Threat | Mitigated by | Residual |
|---|---|---|---|
| S | Stolen security key used without its PIN | AUTH-PASSKEY-001 (screen only) | SEC-002 |
| S | Phishing on a look-alike origin; customer pages exercising staff passkeys | WebAuthn origin binding; AUTH-PASSKEY-009 | SEC-005 (subdomain hygiene) |
| S | Passkey confirmation without the trusted device | AUTH-FRESH-006, AUTH-TRUST-005 | SEC-033 |
| T | Misread `amr` letting an older step vouch for a newer one | AUTH-IDP-007, AUTH-FRESH-005 | `amr` order not covered by the trial (§6) |
| R | Staff sign-ins from new devices unseen | AUTH-NOTIFY-004, AUTH-AUDIT-001 | — |
| D | Lost passkeys | Staff: AUTH-STAFF-004, AUTH-STAFF-009; subscribers keep codes (AUTH-ASSURE-003) | — |
| E | Enrollment-code session used as an admin | AUTH-STAFF-001, AUTH-ADMIN-001 | — |

**The BFF callback (with sign-in start and the consent step)**

| | Threat | Mitigated by | Residual |
|---|---|---|---|
| S | Code injection, login CSRF | PKCE, `state`, `nonce`: AUTH-WEB-007, AUTH-IDP-012 | — |
| S | Mix-up between authorization servers | One issuer per client: AUTH-CLIENT-008 | — |
| S | Software impersonating a public client gets tokens silently | AUTH-CLIENT-007 | SEC-006 |
| T | Open redirect after sign-in or sign-out | AUTH-WEB-006 | SEC-027 |
| R | Sign-in not audited | — | SEC-008 (audit from the consent step) |
| I | Code and `state` in logs or `Referer` | Strict referrer policy, `no-store` (AUTH-WEB-005) | SEC-036 |
| D | Landing request without Strict cookies after a cross-site return | — | SEC-022 |
| E | Tokens issued without the sign-in ID or claims | AUTH-IDP-016, AUTH-TOKEN-003 | — |

**Per-request verification**

| | Threat | Mitigated by | Residual |
|---|---|---|---|
| S | `none`, HS256 confusion, `jwk`/`jku` injection, unknown `kid` | AUTH-TOKEN-001, AUTH-TOKEN-002 | — |
| S | ID token or another audience's token used as an access token | AUTH-TOKEN-003 | SEC-023 |
| S | Service token treated as a user | AUTH-CLIENT-005 | SEC-024 |
| T | Expired or not-yet-valid tokens; clock skew | AUTH-TOKEN-003 (60 s) | — |
| R | Refused tokens unrecorded | AUTH-AUDIT-003 | — |
| I | Tokens in URLs or logs | AUTH-TOKEN-009, NFR-010 | SEC-007, SEC-036 |
| D | Key fetch storms; key URL down | Unknown-`kid` refetch at most every 30 s; 1-hour stale limit, then refuse (arch §10; NFR-002) | — |
| E | Customer token on admin routes; logged-out device or disabled user | AUTH-TOKEN-005, AUTH-TOKEN-004 | SEC-004 |

**Refresh (BFF and mobile)**

| | Threat | Mitigated by | Residual |
|---|---|---|---|
| S | Replay of a stolen refresh token | Rotation, family revocation (AUTH-IDP-015, AUTH-TOKEN-007; trial check 4) | — |
| S | Cross-site request triggers a refresh | AUTH-WEB-003 and Strict cookies | SEC-026 |
| T | Two replicas redeem one token | Redis lock (arch §7) | SEC-012 |
| R | Reuse unrecorded | AUTH-TOKEN-007 (logged and counted) | — |
| I | Refresh token exposed | `HttpOnly` cookies; keychain (AUTH-TOKEN-009) | — |
| D | Lost response signs the user out; Redis down | DEC-018 (accepted, counted) | SEC-012 |
| E | Refresh past the absolute limit or after sign-out | AUTH-SESSION-003, AUTH-SESSION-006 | SEC-004 |

**Sign-out (this device, another device, all devices)**

| | Threat | Mitigated by | Residual |
|---|---|---|---|
| S | Another site forces a sign-out | AUTH-ACCT-011 (confirmation) | — |
| T | CSRF on sign-out | AUTH-WEB-003 | SEC-007 (navigation can't carry the header) |
| R | — | AUTH-AUDIT-001 | — |
| I | ID token in the sign-out URL | — | SEC-007 |
| E | A logged-out device carries on through refresh or a remembered provider sign-in | AUTH-ACCT-010, AUTH-DEVICE-004, AUTH-SESSION-004, AUTH-TOKEN-008 | SEC-004 |
| E | Provider down during sign-out leaves its sessions alive | — | SEC-007 (AUTH-ACCT-013) |

**Recovery, by tier.** The design has no subscriber recovery flow: re-entry is a normal sign-in (DEC-007). The tiers are: T1 subscriber re-entry by code or Google; T2 a lost mailbox; T3 staff re-enrollment; T4 break-glass. Recovery links don't exist (DEC-008), so link replay and mail-scanner consumption don't apply, except for the provider flow settings in SEC-028.

| Tier | | Threat | Mitigated by | Residual |
|---|---|---|---|---|
| T1 | S, E | Mailbox holder signs in, adds a passkey, removes the owner's, unlinks Google, enrolls a device, turns the switch off, logs everyone out, starts deletion | Fresh sign-in windows (AUTH-FRESH-003); notices (AUTH-NOTIFY-001); deletion delay and support freeze (AUTH-ACCT-008, AUTH-ADMIN-005) | Email ceiling: the notices reach the same mailbox; a second notice address is Later (spec §15). SEC-032 |
| T1 | S | Copied session (no mailbox) changes how the account signs in | Fresh sign-in by code or Google (AUTH-FRESH-008); provider screens refuse a passkey as latest step | SEC-008 (hook failure) |
| T2 | S | Someone moves the account to a new address | No address change at all (AUTH-ACCT-004, DEC-009) | Data loss for the owner (accepted) |
| T3 | S | Social engineering of the operator (including a faked video call) | Identity check through contact details on record, audit note (AUTH-STAFF-004); code valid 1 hour, out of band (AUTH-STAFF-003); every admin notified (AUTH-STAFF-007) | Operator judgement |
| T3 | E | Self-service recovery reaches a staff address | No recovery role on staff addresses (AUTH-STAFF-008) | SEC-028 |
| T4 | S | Misuse of the emergency cloud identity | Hardware MFA, offline credentials, alert to all, review (AUTH-STAFF-010) | — |

**Admin actions** (every row also relies on AUTH-ADMIN-001: workforce token, admin audience, scope, `admin` role, passkey session, CSRF)

| Action | Main threats | Mitigated by | Residual |
|---|---|---|---|
| List, search, view subscribers and their devices | I: bulk browsing of personal data | Audit of reads (AUTH-ADMIN-007); field allowlists (AUTH-ADMIN-011) | SEC-015, SEC-030 |
| Create a subscriber | S: account created for someone else's address | Unverified address and terms at first sign-in (AUTH-ADMIN-006) | — |
| Edit name, language, timezone | T: mass assignment | AUTH-ADMIN-011 | — |
| Disable or enable | E, D: misuse by a rogue or phished admin | Passkey within 5 min, `confirm` (AUTH-ADMIN-003); notice (AUTH-NOTIFY-001) | SEC-040 (no burst alert) |
| Delete | D: malicious deletion | As above; 24-hour delay (AUTH-ADMIN-005) | — |
| Cancel a deletion; the support freeze | S: forged request to lift a freeze | AUTH-ADMIN-005 | SEC-032 |
| End all of a subscriber's sessions | D | AUTH-ADMIN-003; both revocations (AUTH-TOKEN-008) | — |
| Data section | T, I: writes or reads beyond the declaration | AUTH-ADMIN-010–012 | — |
| Staff's own devices | S: stolen console session | Fresh passkey within 15 min (AUTH-STAFF-012) | SEC-013 |
| Operator commands (`add`, `re-enroll`, `change-email`, `remove`) | E: a stolen admin session creates admins | Only operators through cloud IAM with MFA (AUTH-STAFF-002); audit and notices (AUTH-STAFF-007) | — |
| All admin actions | E: going around the console to the provider admin APIs; R: altering the audit log | AUTH-ADMIN-008 | SEC-001, SEC-015 |

**Account deletion**

| | Threat | Mitigated by | Residual |
|---|---|---|---|
| S | A copied session deletes the account | Every-time sign-in after a single-use challenge (AUTH-FRESH-007, AUTH-ACCT-007) | SEC-034 |
| S | The mailbox holder deletes it | Disable at once, notice, 24-hour delay, support freeze (AUTH-ACCT-008, AUTH-ADMIN-005) | Email ceiling |
| T | A forged request cancels or lifts the freeze | — | SEC-032 |
| R | — | Every step audited (AUTH-AUDIT-001) | — |
| I | Data left behind after deletion | AUTH-ACCT-009, AUTH-PRIVACY-003, AUTH-PRIVACY-005 | SEC-017 (provider rows), SEC-016 (backups) |
| D | The deletion task fails | Retries, audit, alert (arch §9) | — |
| E | The disabled user's tokens keep working | AUTH-TOKEN-004 (refused at once) | — |

**Signing-key rotation (planned and emergency)**

| | Threat | Mitigated by | Residual |
|---|---|---|---|
| S | A compromised key keeps verifying | Delete at once (arch §13) | SEC-035 (cached keys) |
| S | A rogue key added through Hydra's admin API | Device-record check limits forged tokens to live sign-in IDs (AUTH-TOKEN-004) | SEC-001 |
| T | An emptied key set makes Hydra generate an RS256 key | Never empty a set (arch §13; AUTH-TOKEN-010); Shell refuses RS256 (AUTH-TOKEN-001) | — |
| R | Rotation steps unrecorded | — | SEC-018 (procedure in the inventory) |
| I | Private keys in backups | Keys encrypted by the system secret (arch §13) | SEC-016 (recovery kit) |
| D | New key's tokens refused before the cache refreshes | Refetch on unknown `kid` (arch §10) | — |
| E | Keys from the ID-token set accepted for access tokens | Both sets ES256; audience and claims separate the token kinds (AUTH-TOKEN-003) | SEC-023 |

## 5. Recommendations for decisions

**The spec has no DECISION NEEDED items.** Spec §16 and every other file end with "Open questions: None", and a search of the project finds the marker nowhere in the current files. The questions earlier drafts left open (SameSite, the refresh grace window, per-device sign-out, the JWT library, the sign-in screen, hosting, compliance scope, the email provider) are now decided in the documents. Table A gives this review's view of those decisions; table B lists the decisions this review asks the owners to take.

**A. Decisions already made**

| Decision | Made in | Recommendation | Security reason |
|---|---|---|---|
| SameSite for token cookies: Strict; sign-in and browser-ID cookies Lax | arch §7, DEC-016 | Keep, with SEC-022's landing page and acceptance line | Strict cookies never travel on a cross-site request, and the API never needs them to; only the two cookies read during the cross-site return need Lax |
| Refresh grace window: 0 s, refreshes serialized | arch §7, DEC-018 | Keep, with SEC-012's lock rules | Any grace window lets a replay through; serialization removes the races that motivate one. The Later trigger (unexpected sign-outs) is measurable already |
| Per-device sign-out through device records and the token hook | arch §7–8, DEC-024, DEC-025 | Keep, conditional on the stage 2 spike, with SEC-004's fallback | The device-record check is what makes sign-out immediate despite self-contained tokens; its fallback must never weaken AUTH-TOKEN-003 |
| JWT library: PyJWT, verification only | DEC-020 | Keep | Explicit algorithm list and no header-supplied keys are already required (AUTH-TOKEN-001, AUTH-TOKEN-002) |
| Our own sign-in screen before launch; reference UI in development only | AUTH-SIGN-001, DEC-023 | Keep. The screen should drive the same browser flows the trial exercised, each of which carried a CSRF token (trial, Setup evidence); any other flow type needs its own CSRF review, which the trial doesn't cover | The provider's own CSRF token is what protects its flows from cross-site submission |
| Hosting, compliance scope, email provider: per-fork deployment decisions | README (Deployment Decisions), DEC-037 | Keep, but give the email provider a measurable trigger (SEC-003) | The relay's quota is a security property: it bounds the only re-entry path |

**B. Decisions this review needs**

| # | Finding | Options | Recommendation | Security reason |
|---|---|---|---|---|
| D1 | SEC-002 | If the workforce provider accepts assertions without user verification: (a) edge allowlist or VPN for `staff-auth.` and `admin.`; (b) a check in front of the provider that refuses workforce assertions without the UV flag; (c) patch the provider | (a); (b) only for forks whose staff have no stable networks | Configuration only, and it shrinks the whole admin surface, not just this path; (c) means maintaining a provider fork |
| D2 | SEC-004 | If the sign-in ID doesn't survive refreshes: (a) another per-sign-in value given to the hook at every refresh; (b) "log out another device" becomes subject-wide revocation | (b), unless (a) is proven by the same spike | Correct revocation matters more than per-device convenience; (b) is proven by the trial (check 5) |
| D3 | SEC-007 | Ending the provider sessions at sign-out: (a) server-side by the recorded login session ID; (b) front-channel through Hydra's sign-out step | (a); (b) only as a form POST if (a) fails its check | No ID token in the browser or in a URL, and the same path already planned for other devices and mobile |
| D4 | SEC-006 | Agent-for-user clients: (a) claimed HTTPS or loopback redirects and a forced new sign-in; (b) a minimal consent screen; (c) drop the client type from the baseline | (a) | Configuration plus one rule in the consent step; a consent screen stays Later with third-party clients |
| D5 | SEC-003 | Email transport at launch: (a) Workspace relay with a realm-wide budget; (b) a dedicated transactional provider | (a) for the reference deployment; (b) for any fork whose expected daily codes exceed half the relay's quota | The budget is needed either way; a larger quota without a budget only scales the guessing attack |
| D6 | SEC-003 | Code length: 6 or 8 digits | 8, if the provider lets us set it (To verify) | A hundredfold fewer successful guesses; with paste and one-time-code autofill (AUTH-SIGN-012) the cost to users is small |
| D7 | SEC-001, SEC-019 | Internal service authentication: (a) segmentation now, client certificates Later as a named deviation; (b) client certificates now | (a) | The private CA already exists, so (b) is configuration when its trigger comes; segmentation closes the path from the edge today |
| D8 | SEC-019 | SBOM: Later (README) or baseline | Baseline | One CI step from the scanner already in place; ASVS 15.1.2 is Level 2 |

## 6. Verify during implementation

What the documents and the trial can't prove, with the test that would. "Trial" says whether the trial covered it.

| # | To verify | Test that proves it | Stage | Trial |
|---|---|---|---|---|
| V1 | The trial's results hold with Ory in production mode | Re-run the six trial checks against the stage 1 stack (SEC-020) | 1 | Development mode only |
| V2 | Each provider refuses an assertion without the UV flag after a ceremony that required it | A software authenticator that returns user presence without verification attempts a staff sign-in and a subscriber confirmation (SEC-002) | 1 | No |
| V3 | The workforce admin listener is unreachable except from `api`, `worker` and the deploy job | Connection attempts from the edge, metrics, PostgreSQL and Redis containers (SEC-001) | 1, 8 | No |
| V4 | Provider cookies are host-only, `Secure`, Lax or stricter, and named differently per realm | Inspect every `Set-Cookie` from both auth hosts (SEC-005) | 1 | Partly (cookies were host-only for the BFF) |
| V5 | Whether the provider lets us set the code length | Configuration and a sign-in with an 8-digit code (SEC-003) | 1 | No |
| V6 | Recovery and verification run on codes only | No provider message carries a URL; the link method is off (SEC-028) | 1 | Links observed (check 6) |
| V7 | Hydra sets `typ` on access tokens, and its value | Decode an issued access token's header (SEC-023) | 1 | No |
| V8 | The sign-in ID survives refreshes and the token hook runs at each one | Ten-refresh chain, plus a direct refresh at the token endpoint after deleting the device record (SEC-004; already a stage 2 spike) | 2 | No |
| V9 | One sign-in's provider sessions can be ended by ID | End one device's Hydra login session and Kratos session; its next sign-in shows the sign-in screen, other devices unaffected (SEC-004, SEC-007) | 2 | No (subject-wide only) |
| V10 | Two replicas refresh at once without a reuse sign-out, including when the provider is slow | Concurrent refreshes with a 4 s provider delay; Redis stopped (SEC-012) | 2 | No |
| V11 | Per-IP limits group IPv6 /64s | Requests from two addresses in one /64 (SEC-010) | 2 | No |
| V12 | The code budget and alerts fire | Synthetic burst against a lowered budget (SEC-003) | 2 | No |
| V13 | Logs carry no codes, tokens, challenges or addresses | Scan Shell, provider and edge logs from the integration suite; provider sensitive-value logging off (SEC-036) | 2, 8 | No |
| V14 | Strict cookies after a cross-site return | Google sign-in in Chromium, Firefox and WebKit, measuring the app's first API call (SEC-022) | 2 | No (trial used Lax) |
| V15 | arq runs with a JSON serializer; email templates autoescape | Configuration check and a template test with markup in a name (SEC-037) | 2–3 | No |
| V16 | The consent step can tell whether an agent-for-user request demanded a new sign-in | Our consent step reads the original request and refuses one without `prompt=login` or `max_age=0` (SEC-006) | 3 | No |
| V17 | Refusing hooks fail closed | Stop the hook route, then add a passkey, link Google and sign up with Google (SEC-008) | 4–5 | No |
| V18 | The provider offers no linking outside settings | Walk every step the provider's public API offers after a Google sign-in whose address matches an existing account (SEC-009) | 4 | No |
| V19 | Settings hooks tell adding from removing; Google re-prompts; a disabled account isn't revealed before its code; `amr` order | Already in arch §15 and the integration suite | 4–5 | No |
| V20 | Provider data after deletion, and whether sent messages (codes) are stored | Test-only query of both provider databases after a deletion and the next purge (SEC-017) | 5, 8 | No |
| V21 | Trusted-device keys survive restarts and updates; proofs are bound to session and route | Already in arch §15; plus a proof replayed from another session (SEC-033) | 6 | No |
| V22 | The console renews no tokens without user input | Leave the console idle 31 minutes and inspect its requests (SEC-013) | 7 | No |
| V23 | API docs aren't served on deployed hosts | Request `/docs`, `/redoc` and `/openapi.json` on every host (SEC-038) | 8 | No |
| V24 | Each database refuses connections from other roles | Connect to `shell` as a provider role and the reverse (SEC-039) | 1, 8 | No |
| V25 | Backups are unreadable and undeletable by the app identity and CI, and a restore re-applies deletions | Access attempts with both identities; the restore rehearsal (SEC-016, AUTH-PRIVACY-005) | 9 | No |
| V26 | Emergency key revocation works | Rehearse: delete the key, restart replicas, confirm tokens signed by it fail (SEC-035) | 9 | No |
| V27 | Load at peak, multi-instance behaviour, device UX | Already in arch §15 and NFR-001–005 | 9 | No |

## 7. Proposed text

Ready-to-paste wording, grouped by file. New rows use the spec's columns; IDs continue each series and none is reused. Each block names the finding it resolves.

### 7.1 `docs/spec/auth.md`

**§1 Conventions and assurance.** Replace the paragraph's last two sentences ("Staff sign in with passkeys... AAL2 time limits.") with (SEC-002, SEC-019):

> Staff sign in with passkeys, with user verification required by our sign-in screen; where the workforce realm's provider doesn't refuse an assertion without user verification, AUTH-PASSKEY-010's compensating control applies before launch. Staff sessions follow AAL2 time limits.
>
> **Deviations.** One ASVS Level 2 requirement is knowingly not met in the baseline: internal connections authenticate the server but not the client (ASVS 13.2.1). The mitigating controls are AUTH-ADMIN-013 (only `api`, `worker` and the deploy job can reach the providers' admin APIs), per-call secrets on the providers' calls to Shell, rotated under NFR-018, and TLS on every internal hop (NFR-015). Client certificates are Later ([README](../../README.md#planned-evolution)).

**§2 Identity provider capabilities**, new rows:

| ID | Requirement | Acceptance | Verification | Owner | ASVS |
|---|---|---|---|---|---|
| AUTH-IDP-022 | Every provider hook that can refuse (sign-up, settings changes, the token hook) MUST fail closed: if Shell's hook times out, errors or can't be reached, the provider refuses the sign-up, change or token. Reporting hooks may fail open, so anything Shell must not miss about a sign-in (its audit entry, the new-device notice) is written by our consent step. | With the hook route stopped, adding a passkey, linking Google and a Google sign-up each fail, and a sign-in still leaves its audit entry from the consent step. | Integration suite | Provider configuration; app | 16.5.3 |
| AUTH-IDP-023 | Every provider email flow MUST use codes, never links: the workforce realm's recovery flow, kept only for enrollment codes, and any verification flow in either realm MUST run the code method with the link method off. | Both realms' configuration has the link method off, and no message the provider hands `EmailSender` carries a recovery or verification URL. | Configuration check; integration suite | Provider configuration | 6.3.4 |

**§3 Sign-up, sign-in and linking**, new row:

| ID | Requirement | Acceptance | Verification | Owner | ASVS |
|---|---|---|---|---|---|
| AUTH-SIGN-014 | The provider's own linking of a sign-in method to an existing identity, outside settings, MUST be unavailable in the customer realm, through our screens and through the provider's public API alike, so every link passes AUTH-ACCT-005's fresh sign-in, the settings hook and its notice. | After a Google sign-in whose verified address matches an existing account, completing every step the provider's public API offers leaves that identity with no Google credential (whether the provider offers such steps: To verify). | Integration suite | Provider configuration | 6.8.1 |

**§4 Passkeys**, new row:

| ID | Requirement | Acceptance | Verification | Owner | ASVS |
|---|---|---|---|---|---|
| AUTH-PASSKEY-010 | The integration suite MUST record, for each realm, whether the provider refuses a passkey assertion without the user-verified flag after a ceremony that required verification. If the workforce realm's provider accepts it, no workforce realm may be deployed without a server-side compensating control: the edge accepts requests to the workforce auth host and the admin host only from an operator-configured allowlist of networks, or a check in front of the provider refuses workforce assertions without the flag. | An assertion from a software authenticator that reports presence without verification is refused by the provider, or, where the provider accepts it, a request to the workforce auth host from outside the allowlist gets 403 at the edge. | Integration suite; configuration check | Provider configuration; operations | 6.3.3 |

**§5 Email codes and rate limits.** Edit AUTH-LIMIT-006's acceptance (SEC-011):

> With its address at the daily limit, an account still signs in with Google and its other sessions keep working; an email-only account can't start a new session until the window passes, the accepted lockout recorded in arch §11.

New rows:

| ID | Requirement | Acceptance | Verification | Owner | ASVS |
|---|---|---|---|---|---|
| AUTH-CODE-007 | Every code email MUST say what the code is for (sign-up, sign-in, signing in again), that staff will never ask for it, the one host where it may be entered, and when and from which city the request came; it MUST NOT carry the code in the subject. | Each code template renders those parts in English and Korean, with no code in the subject. | Unit test | App | 6.3.5 (L3, advisory) |
| AUTH-LIMIT-007 | `EmailSender` MUST keep a realm-wide budget of code emails per hour and per day, set below the relay's quota with headroom for notices; it MUST alert at 50% and 80% of either budget and, past it, send no code (answering the provider 2xx, logged and counted) while notices keep going. Each deployment records the relay's quota and its budget. | With the hourly budget set to 100, the 51st and 81st codes raise the two alerts, the 101st isn't sent, and a notice still goes out. | Unit test; configuration check | App; operations | 2.1.3, 2.4.1, 6.6.3 |
| AUTH-LIMIT-008 | Shell MUST count failed code entries per address across flows and realm-wide, from the provider's logs or metrics (which signal is available: To verify), and alert past configured rates (starting values: 20 failures for one address in 24 hours; three times the trailing week's hourly average realm-wide). The documented response is to turn on the edge's challenge for code requests (CAPTCHA, §15) and review the addresses involved. | Twenty-one wrong codes for one address over three flows raise the per-address alert, and a synthetic burst raises the realm-wide one. | Unit test; configuration check | App; operations | 6.3.1, 6.6.3, 16.3.3 |
| AUTH-LIMIT-009 | Every per-IP limit, at the edge and in `EmailSender`, MUST key IPv4 clients by address and IPv6 clients by their /64 prefix. | Requests from two addresses in one IPv6 /64 share one counter; two IPv4 addresses don't. | Unit test; integration suite | App; operations | 2.4.1, 15.3.4 |
| AUTH-LIMIT-010 | The edge MUST apply a coarse per-IP limit to every Shell host (starting value: 600 requests a minute), and Shell MUST cap each session's open gate challenges and continuation codes (starting value: 5 of each). | The 601st request in a minute from one IP gets 429 with `Retry-After`, and a session's 6th open challenge is refused. | Integration suite; unit test | Operations; app | 2.4.1, 15.2.2 |

**§6 Fresh sign-ins and trusted devices**, new row:

| ID | Requirement | Acceptance | Verification | Owner | ASVS |
|---|---|---|---|---|---|
| AUTH-TRUST-008 | A trusted-device challenge MUST be bound to the session (its sign-in ID) and the route it was issued for, and device keys MUST be ECDSA P-256, the public key validated at enrollment. | A proof made for another route, or with a challenge issued to another session, is refused, and enrolling a malformed or non-P-256 key gets 422. | Unit test | App | 6.7.2, 11.6.1 |

**§7 Account settings, devices and deletion.** Edit AUTH-DEVICE-004's acceptance (SEC-004):

> After device A logs out device B, B's next request gets 401, its refresh fails, its refresh token presented directly at the provider's token endpoint yields no token, and its next sign-in shows the sign-in screen.

New rows:

| ID | Requirement | Acceptance | Verification | Owner | ASVS |
|---|---|---|---|---|---|
| AUTH-ACCT-013 | Signing out MUST succeed for the user whatever the provider's state: the request deletes the device record first and clears the session's cookies; revoking the refresh token and ending the provider sessions run as a retried task in the same commit, whose final failure alerts. No ID token is kept in the browser or sent in a URL. | With the provider stopped, sign-out answers 204, the old access token gets 401 at once, and the provider sessions end once the provider is back. | Integration suite | App | 7.4.1, 14.2.1, 16.5.3 |
| AUTH-DEVICE-007 | Sign-in IDs, continuation codes and gate challenges MUST each be at least 128 random bits from a CSPRNG, and the device list MUST name each record by a separate random ID, never by the sign-in ID that tokens carry. | The device-list response contains no sign-in ID, and each value comes from 16 or more bytes of the operating system's CSPRNG. | Unit test | App | 11.5.1 |

**§8 Sessions, tokens and cookies.** Edit AUTH-TOKEN-009's last sentence (SEC-007): "The BFF keeps no ID token after the callback has validated it." Edit AUTH-WEB-002's acceptance (SEC-022):

> In Chromium, Firefox and WebKit, after a sign-in that returned through Google, the callback lands the browser on a same-origin page and the app's first API call from it carries the token cookies; no token cookie is made Lax to pass this test.

New rows:

| ID | Requirement | Acceptance | Verification | Owner | ASVS |
|---|---|---|---|---|---|
| AUTH-SESSION-007 | Idle limits MUST follow the user's activity: the web app and the console MUST NOT renew tokens from timers, polling or background tabs without a user action since the previous renewal. | A console left without input for 31 minutes must sign in again at its next action, and no request in that time renewed its tokens. | Integration suite | App | 7.3.1 |
| AUTH-TOKEN-011 | The refresh lock MUST outlive the provider call's total timeout (arch §10) with margin; a request that waits out the lock MUST answer 409 `auth.refresh_retry` and never redeem the token itself. With Redis unavailable, refresh MUST answer 503 and keep the cookies, gate challenges and continuation codes MUST be refused, and no step runs without its lock. | With the provider delayed 4 s, the second of two concurrent refreshes gets 409 and the chain survives; with Redis stopped, refresh answers 503 with cookies unchanged and a gated route refuses. | Integration suite | App | 16.5.3, 2.3.4 |
| AUTH-TOKEN-012 | If the provider sets `typ` on access tokens (To verify), Shell MUST accept only `at+jwt` or `application/at+jwt`; otherwise arch §3 records that access and ID tokens are told apart by audience and the required `client_id`, scopes and `jti`, which no ID token carries together. | A correctly signed ID token presented as an access token gets 401, and, where the provider sets `typ`, so does a token with any other value. | Unit test; integration suite | App | 9.2.2 |
| AUTH-WEB-008 | Each realm's provider cookies (sign-in session, remembered sign-in, flow CSRF) MUST be host-only on that realm's auth host, with no `Domain` attribute, `Secure`, `SameSite=Lax` or stricter, and named differently in the two realms, so no provider cookie reaches `app.`, `api.` or `admin.`. | No `Set-Cookie` from either auth host has a `Domain` attribute or lacks `Secure`, and the two realms' cookie names differ. | Integration suite | Provider configuration | 3.3.1, 3.3.2, 7.1.3 |
| AUTH-WEB-009 | The CSRF token MUST be an HMAC, under a server-side key, of the session's sign-in ID and a random value (signed double-submit), set at sign-in and each refresh, living as long as the refresh cookie and cleared at sign-out. Every unsafe method on a cookie host is checked, the BFF's public refresh and sign-out routes included, and `Sec-Fetch-Site` MUST be `same-origin` when present: `same-site` is refused. | A token from another session, a request with `Sec-Fetch-Site: same-site`, and a refresh without the header each get 403. | Unit test | App | 3.5.1 |
| AUTH-WEB-010 | The providers' redirect targets MUST be exact allowlists: the identity provider's return URLs only paths on the realm's own hosts, and the token provider's post-sign-out redirects only each client's registered URIs. Every client MUST be registered with the `code` response type only. | A sign-in flow started with `return_to=https://example.net/` and a sign-out naming an unregistered redirect are each refused, and the registry check finds only `code`. | Integration suite; configuration check | Provider configuration | 3.7.2, 10.6.1 |
| AUTH-WEB-011 | Every response to an authenticated request, the admin and Data-section routes included, MUST carry `Cache-Control: no-store`. | A header check of every authenticated route in the OpenAPI contract finds `no-store`. | Unit test | App | 14.3.2, 14.2.2 |

**§9 Clients, scopes and route gates**, new rows:

| ID | Requirement | Acceptance | Verification | Owner | ASVS |
|---|---|---|---|---|---|
| AUTH-CLIENT-009 | Public clients MUST register only claimed HTTPS redirect URIs on a domain the deployment controls or, for agents on the user's own machine, loopback URIs; private-use schemes MUST NOT be registered. Since a public client can't prove its identity, our consent step MUST refuse an agent-for-user authorization whose request didn't demand a new sign-in (`prompt=login` or `max_age=0`), so a remembered sign-in can't complete one. A claimed HTTPS redirect URL MUST serve, when the app isn't installed, a page with no third-party resources and `Referrer-Policy: no-referrer`. | An agent-for-user request without `prompt=login`, from a browser signed in 2 minutes earlier, is refused; a registration with a private-use scheme fails the registry check. | Integration suite; configuration check | App; operations | 10.7.1, 7.6.2 |
| AUTH-CLIENT-010 | The principal's kind MUST come from the client registry and the grant, never from claims alone: a token is a service token only when its client is registered as an agent acting as itself and its `sub` equals its `client_id`; a user token's `sub` MUST NOT equal any registered client ID and MUST carry a sign-in ID. | A client-credentials token on a user route is refused, and a user token whose `sub` equals a client ID gets 401. | Unit test | App | 10.3.3 |

**§10 Staff and administration**, new rows:

| ID | Requirement | Acceptance | Verification | Owner | ASVS |
|---|---|---|---|---|---|
| AUTH-STAFF-013 | The staff script MUST offer `end-all-sessions --realm <realm>`, run only by an operator: it deletes every device record in the realm, so every access token is refused at once, then runs both revocations for every identity as a retried task, writes an audit entry and notifies every admin. | After the command every subscriber's next request gets 401 and every refresh fails, and the audit entry names the operator. | Integration suite; hands-on check | Operations | 7.4.5 |
| AUTH-ADMIN-013 | The providers' admin listeners, in both realms, MUST accept connections only from `api`, `worker` and the deploy job while it runs; the edge, metrics, the datastores and any other component MUST be unable to reach them. Until internal hops authenticate their clients (Later), this is the only control on these APIs, so the platform enforces it (network attachment or interface binding), not convention. | From the edge, metrics, PostgreSQL and Redis containers a connection to every admin port fails, while `api` and `worker` connect. | Integration suite; configuration check | Operations | 13.2.1 (partial), 13.2.2 |
| AUTH-ADMIN-014 | Lifting the support freeze MUST rest on proof of receiving mail at the account's address, never on a message's sender: support sends a one-time reference to the address and acts only when the requester quotes it back, and the console's lift action requires a note of that check, written to its audit entry. | The console refuses to lift a freeze without the note, and the audit entry carries it. | Unit test | App; operations | 6.4.4 |

**§11 Notifications and audit log.** Edit AUTH-AUDIT-001's acceptance (SEC-008):

> Each listed action leaves exactly one entry. For actions Shell performs, a failed audit write rolls the action back; sign-ins and fresh sign-ins are written by the consent step in the same transaction as the device record.

Edit AUTH-AUDIT-004's acceptance (SEC-015): "As the app's role, updating or deleting an entry fails, and the migrator role's credentials are available only to the CI migration job." New row:

| ID | Requirement | Acceptance | Verification | Owner | ASVS |
|---|---|---|---|---|---|
| AUTH-AUDIT-005 | Every audit entry MUST also be written, in the same request, as a structured log line shipped to the store the app identity can write but not change (NFR-008), and a daily comparison of the table's and the store's counts MUST alert on any difference. | Deleting an entry as the migrator leaves its shipped copy, and the next comparison alerts. | Configuration check | App; operations | 16.4.2, 16.4.3 |

**§12 Errors and privacy**, new row:

| ID | Requirement | Acceptance | Verification | Owner | ASVS |
|---|---|---|---|---|---|
| AUTH-PRIVACY-007 | The providers' expired data (flows, codes, stored messages, sessions, login and consent records, revoked and expired tokens) MUST be purged daily, and an account's deletion MUST leave no row in either provider's databases that names its identity, apart from a list kept per provider version of what the provider can't remove. Whether the provider stores sent messages, and so codes, is To verify; if it does, they go within a day. | After a deletion and the next purge, a test-only query of each provider database finds only the listed rows for the identity, and no stored message older than a day. | Integration suite | Operations | 14.2.4, 14.2.7 |

**§14 Non-functional requirements.** Retire NFR-014 (its ID isn't reused); NFR-021 carries its text with the narrower redirect rule. Edit NFR-009 to add "and on high-risk admin actions above a configured hourly rate" to its alerts (SEC-040). Edit NFR-010's acceptance (SEC-036): "A scan of every component's logs from the integration suite, Shell's, both providers' and the edge's, finds none of these, nor an authorization code, `state`, provider challenge or ID token." Edit NFR-013's acceptance (SEC-038): "From outside, neither path answers, no deployed host serves the OpenAPI document or interactive docs, and with keys missing readiness fails." New rows:

| ID | Requirement | Acceptance | Verification | Owner | ASVS |
|---|---|---|---|---|---|
| NFR-016 | No host under the deployment's registrable domain may serve user-generated or third-party-controlled content (help desks, status pages, marketing tools behind a CNAME), and DNS MUST hold no dangling records, because customer passkeys are scoped to the registrable domain and cookies set for it reach every host. Such services use another registrable domain. | Before launch, a DNS inventory lists every host under the domain, each run by the deployment, with no CNAME to an unclaimed resource. | Configuration check | Operations | 3.5.4 |
| NFR-017 | Backups MUST be encrypted with a key held in the secrets manager, never beside them; readable and restorable only by the operator role (cloud IAM with MFA), each access logged; and immutable for their 30 days, so neither the app identity nor CI can change or delete them. The recovery kit (the providers' key-encryption secrets, the backup key, the internal CA key) is kept in the secrets manager and as an offline copy held by the fork owner. | The app identity and the CI role are each refused when reading or deleting a backup, and an operator's restore appears in the cloud audit log. | Configuration check; hands-on check | Operations | 14.2.4, 13.3.1, 13.3.2 |
| NFR-018 | Every key and secret MUST appear in arch §13's inventory with its purpose, algorithm, store, rotation period and procedure, and MUST rotate on that schedule and at once on suspected compromise; static per-call secrets rotate at least every 90 days, with two values accepted during the switch. | A check against the secrets manager finds every listed item and none older than its period. | Configuration check | Operations | 11.1.1, 11.1.2, 13.3.1, 13.3.2 |
| NFR-019 | Every image build MUST produce an SBOM (CycloneDX or SPDX) with the scanner already in CI, covering Python, JavaScript and operating-system packages, kept with the image digest. | Each released image digest has an SBOM listing the locked dependencies. | Configuration check | Operations | 15.1.2 |
| NFR-020 | CI MUST pin every third-party action and tool by commit SHA or digest, give each workflow's token only the permissions it uses (read by default), and run deployment, migrations, signing-key creation and certificate issuance only in a protected environment, from the main branch, never for pull requests from forks. | A workflow lint finds no unpinned action and no write-all permission, and a pull request from a fork can't reach the deploy environment. | Configuration check | Operations | 15.1.1, 15.2.1, 13.3.2 |
| NFR-021 | Public TLS: outside development, every public host MUST answer only over TLS 1.2 or 1.3, preferring 1.3, with only recommended cipher suites and a publicly trusted certificate. Plain HTTP MUST redirect to HTTPS only on hosts people open in a browser (`app.`, `admin.` and the auth hosts); `api.` MUST refuse plain HTTP without redirecting, so a client sending a bearer token over HTTP fails visibly. Replaces NFR-014. | A TLS scan of every public host finds only TLS 1.2 and 1.3, recommended suites and a publicly trusted certificate; a plain-HTTP request to `app.` gets a redirect and one to `api.` gets none. | Configuration check | Operations | 12.1.1, 12.1.2, 12.2.1, 12.2.2, 4.1.2 |

**§15 Later.** Replace two rows and add two:

| Later | Trigger |
|---|---|
| CAPTCHA at sign-up and on code requests | An AUTH-LIMIT-007 or AUTH-LIMIT-008 alert, or abuse observed |
| Signing every subscriber out at once from the console | Support needs it without an operator (the operator command, AUTH-STAFF-013, covers breach response) |
| DMARC at `reject`, with MTA-STS and TLS reporting | 30 days of DMARC aggregate reports with no legitimate failures |
| "Forget this device" at sign-out, removing its device key and browser ID | Users sign in on shared or public computers |

### 7.2 `docs/architecture.md`

**§1, the "Internal" bullet** (SEC-001, SEC-038), replace with:

> - **Internal:** Shell, the providers, PostgreSQL, Redis and metrics on a private network. The providers' admin APIs listen where only `api`, `worker` and the deploy job can reach them (AUTH-ADMIN-013): the edge, which faces the internet, never can. Shell's hook routes (per-call secret, constant-time check) are reachable only from the providers. Outside development every connection there is encrypted (section 13). Outbound, Shell reaches only the providers, the email relay and the DB-IP download; the customer realm's Kratos reaches only Google; the platform blocks anything else where it can.

**§4, Gates, the "Fresh sign-in" bullet** (SEC-034), append:

> The challenge travels with the sign-in: the BFF keeps its ID in the sign-in cookie and an app sends it with its continuation code, our consent step writes it on the new device record, and the route accepts the new session only if its record carries the open challenge and its `auth_time` is later than the challenge.

**§4, The principal** (SEC-024), append: "Its `kind` comes from the client registry and the grant (AUTH-CLIENT-010), never from claims alone."

**§5, Capability checklist** (SEC-020), replace "Ory v26.2.0 provides:" with:

> Ory v26.2.0 provides the following, according to its source and documentation. The trial, run in development mode, proved only code, Google and passwordless `webauthn` sign-in, ES256 access tokens, zero-grace rotation with family revocation, subject-wide revocation and link-only recovery; every other item is proved by the integration suite in the stage that relies on it, and a failure stops that stage (roadmap). Where the provider accepts a passkey assertion without user verification, AUTH-PASSKEY-010 applies.

**§6, Layout** (SEC-039), append: "Each database revokes `CONNECT` from `PUBLIC` and grants it only to its own roles. The identity schema holds only the email trait, and Shell never reads authorization from the provider's traits or metadata." **§6, Durable work** (SEC-037), append: "`EmailSender` renders HTML templates with autoescaping on and puts user-supplied values, such as names, only in message bodies. arq jobs carry only IDs and serialize as JSON, never pickle, so a write to Redis can't run code in the worker." **§6**, add after Layout (SEC-038):

> **Classification.** *Secret*: keys, secrets, tokens, email and enrollment codes; never logged, never stored by Shell outside their holder. *Personal*: addresses (in the provider only), names, IPs and user agents (audit log), device records, cities, keyed browser and install IDs; kept in the region, masked in logs, deleted on the schedules in AUTH-PRIVACY-003. *Ordinary*: language, timezone, terms records. No page loads third-party scripts or trackers.

**§7, cookie table** (SEC-007): replace the first row with "`__Host-shell-access`, `-refresh` | Access and refresh token | `HttpOnly`; Strict", and delete "The ID token is kept only for the hint that sign-out sends."

**§7, Browser, step 3** (SEC-022), replace with:

> 3. `/v1/auth/callback` checks `state`, redeems the code with the client assertion and verifier, validates both tokens (the ID token's `nonce` included), keeps no ID token, sets the cookies and answers with a small same-origin page (no third-party resources, `no-store`) that navigates to the return path, so that request is same-site even after a cross-site return; the terms step comes first until it is done (section 8).

**§7, Refresh, step 2** (SEC-012), append: "The lock lives longer than the provider call's timeout; a request that waits it out answers 409 and never redeems the token itself; with Redis unavailable, refresh answers 503 and keeps the cookies (AUTH-TOKEN-011)."

**§7, Sign-out and limits**, replace the first two sentences, up to "(To verify: the sign-in ID survives refreshes).", with (SEC-007):

> `POST /v1/auth/logout`, CSRF-checked like every unsafe method, deletes the device record first, so the per-request check refuses the device's access tokens at once, then clears the session's cookies and the app's cached data, keeping the browser ID and the device key so the device stays known and trusted, and answers 204. A `tasks` row written in the same commit revokes the refresh token and ends the sign-in's provider sessions by the login session ID our consent step recorded (`revoke_session`), retrying like a coordinated disable (AUTH-ACCT-013). Apps and agents use the same route. No ID token is kept in the browser or sent in a URL. Our sign-out step, which runs from launch, handles only sign-out requests that reach the provider from elsewhere, and ends nothing until the user confirms. If ending one sign-in's provider sessions by ID fails its check (section 15), the browser instead reaches the provider's sign-out through a form POST, never a GET URL.

**§11, Baseline controls**: add to the rate-limit table (SEC-003, SEC-010, SEC-040):

| Rate-limit layer | Keyed by | Limits (values in the spec) |
|---|---|---|
| Edge | IP (IPv6 by /64) | Every Shell host, coarse (AUTH-LIMIT-010) |
| `EmailSender` | Realm | Codes per hour and per day (AUTH-LIMIT-007) |
| Shell | Session | Open gate challenges and continuation codes (AUTH-LIMIT-010) |
| Shell, from provider logs or metrics | Address and realm | Failed code entries; alert only (AUTH-LIMIT-008) |

**§11**, add after the paragraph that follows the table (SEC-003, SEC-010, SEC-011):

> **Abuse at realm scale.** Per-IP and per-address limits bound one source and one account, not an attacker using many of each. A realm-wide budget on code emails (AUTH-LIMIT-007) keeps a flood from exhausting the relay's quota and stopping every code sign-in, and an alert on failed code entries (AUTH-LIMIT-008) shows distributed guessing: with 5 attempts per code and 10 codes a day, one address allows 50 guesses a day, about 1 in 20,000 per day against 6 digits, so expected takeovers grow with the codes sent. If the provider lets us set the code length (To verify), codes are 8 digits. Every per-IP limit keys IPv6 by /64 (AUTH-LIMIT-009); values for IPv4 are tuned from metrics, since carrier-grade NAT puts many users behind one address.
>
> **Accepted lockout.** Anyone can spend an address's code budget, so an email-only user can be kept from starting a new session for up to a day; existing sessions, Google sign-in and support are unaffected. Counters are rolling windows, and an address held at its daily limit on three days in a week raises an alert.

**§11, threat table**, replace the "Stolen device or security key" row (SEC-002):

| Threat | Mitigation | Residual risk |
|---|---|---|
| Stolen device or security key | Device lock; user verification required by our screen; for staff, AUTH-PASSKEY-010 | If the provider accepts assertions without user verification, custom software with a stolen staff security key signs in without its PIN, a single factor for admin access, which AUTH-PASSKEY-010's control closes before launch |

**§13, Observability** (SEC-036), append: "The edge logs request paths without query strings, and both providers run with their option to log sensitive values off (setting names To verify)."

**§13, Backups and keys** (SEC-018, SEC-035), append the inventory and the emergency steps:

> **Keys and secrets** (NFR-018):
>
> | Key or secret | Purpose | Algorithm | Held in | Rotation |
> |---|---|---|---|---|
> | Signing keys, per realm | Access and ID tokens | ES256 | Hydra, encrypted by its system secret | 90 days; emergency steps below |
> | Hydra system secret, per realm | Encrypts Hydra's keys | Provider's | Secrets manager; recovery kit | Yearly: prepend, deploy, drop |
> | Kratos secrets, per realm | Provider cookies, stored provider tokens | Provider's | Secrets manager; recovery kit | Yearly: prepend, deploy, drop |
> | Client assertion keys | `private_key_jwt` for the BFFs and agents | ES256 | Secrets manager; public keys in the client registry | 180 days: register the new key, switch, remove the old |
> | Sign-in cookie key | Encrypts the sign-in cookie | AES-256-GCM | Secrets manager | 90 days; the old key accepted for 10 minutes |
> | CSRF key | Signs CSRF tokens (AUTH-WEB-009) | HMAC-SHA-256 | Secrets manager | 90 days; two keys during the switch |
> | Browser and install ID key | Keyed hashes (AUTH-PRIVACY-004) | HMAC-SHA-256 | Secrets manager | On compromise only: rotating makes every browser new and notifies every account |
> | Hook and email-hook secrets | The providers' calls to Shell | 256 random bits, constant-time check | Secrets manager; provider configuration | 90 days; two values during the switch |
> | Internal CA key | Internal certificates | ECDSA P-256 | Secrets manager; recovery kit | 2 years; certificates 90 days |
> | Database and Redis credentials | Service access | — | Secrets manager | 90 days |
> | Google client secret | Customer realm ↔ Google | — | Secrets manager | On compromise, or as Google requires |
> | DKIM key | Signs outgoing mail | The relay's | The relay | Yearly |
> | Backup key | Backups (NFR-017) | The platform's | Secrets manager; recovery kit | Yearly; old keys kept while their backups exist |
>
> **Key compromise.** The operator deletes the key, then restarts every `api` replica so no cached copy survives (a cold start fetches fresh keys and refuses everything if it can't), rotates the realm's system secret if the key store itself may be exposed, and records each step in the audit log. The rotation rehearsal (roadmap, stage 9) includes this path.

**§15**, replace the third bullet (SEC-004):

> - The sign-in ID our consent step stamps survives every refresh, and the token hook runs at every refresh with it. If either fails, refreshed tokens lack the sign-in ID and AUTH-TOKEN-003 refuses them, so the design can't ship as written. Before stage 2 continues, either the hook finds another per-sign-in value the provider passes at every refresh (which one is To verify), or logging out another device becomes logging out all devices (both revocations): the list keeps its entries but loses per-device sign-out, and the README's "or its device is logged out" goes. AUTH-TOKEN-003 is never relaxed to accept a user token without a sign-in ID.

**§15**, add bullets (SEC-002, SEC-007, SEC-009, SEC-003, SEC-023, SEC-017):

> - Each provider refuses a passkey assertion without the user-verified flag after a ceremony that required it; if the workforce realm's doesn't, AUTH-PASSKEY-010's control is chosen before stage 3.
> - One sign-in's provider sessions, the token provider's and the identity provider's, can be ended by ID without ending the account's others.
> - The provider offers no way to link a sign-in method outside settings (AUTH-SIGN-014).
> - Whether the provider lets us set the code length, whether it sets `typ` on access tokens (AUTH-TOKEN-012), and whether it stores sent messages (AUTH-PRIVACY-007).

**§16**, replace two rows (SEC-002, SEC-003):

| Later | Trigger |
|---|---|
| Admin host behind a VPN or allowlist | Fixed staff networks, compliance, or AUTH-PASSKEY-010 (the provider accepts unverified staff assertions) |
| Dedicated transactional email provider | The code budget (AUTH-LIMIT-007) is reached in normal traffic, the relay's limits or reputation restrict sending, or a fork expects more daily codes than half the relay's quota |

### 7.3 `README.md`

- **Project Overview** (SEC-019): "OWASP ASVS Level 2, with single-factor subscriber sign-in as a documented relaxation" becomes "OWASP ASVS Level 2, with single-factor subscriber sign-in as a documented relaxation and one named deviation (`docs/spec/auth.md`)".
- **Identity Model** (SEC-041): "keys a user by that UUID and never stores the address" becomes "keys a user by that UUID and never stores the address in clear; the audit log keeps it only masked".
- **Planned Evolution** (SEC-001, SEC-019): delete the row "SBOM | A customer or compliance request", and replace the mTLS row with "| Client certificates (mTLS) between services | Shared infrastructure, a compliance demand, or a claim of full ASVS 13.2.1 conformance (until then, the spec names the deviation) |".
- **Technology Direction**, Google Workspace row (SEC-003): note becomes "Interim, under a realm-wide code budget; a dedicated provider when `docs/architecture.md`'s trigger is met".

### 7.4 `docs/roadmap.md`

**Requirement lists** (new IDs, each in one stage; NFR-014 retired):

| Stage | Add | New count |
|---|---|---|
| 0 | NFR-019, NFR-020 | 5 |
| 1 | AUTH-ADMIN-013, AUTH-WEB-008, AUTH-WEB-010, AUTH-IDP-023 | 25 |
| 2 | AUTH-CODE-007, AUTH-LIMIT-007–009, AUTH-TOKEN-011–012, AUTH-WEB-009 | 43 |
| 3 | AUTH-CLIENT-009–010, AUTH-STAFF-013 | 33 |
| 4 | AUTH-SIGN-014, AUTH-ACCT-013 | 27 |
| 5 | AUTH-IDP-022, AUTH-DEVICE-007 | 40 |
| 6 | AUTH-LIMIT-010, AUTH-TRUST-008 | 12 |
| 7 | AUTH-SESSION-007, AUTH-WEB-011, AUTH-ADMIN-014 | 14 |
| 8 | AUTH-PASSKEY-010, AUTH-AUDIT-005, AUTH-PRIVACY-007, NFR-016, NFR-018, NFR-021 (NFR-014 removed) | 15 |
| 9 | NFR-017 | 11 |

Total: 225 IDs.

**Stage 1, Exit criteria**, add (SEC-020, SEC-002, SEC-003):

> - Trial re-run. Pass: the trial's six checks (email-code, Google and passkey sign-in; cookies; local verification through a provider outage; rotation and replay; coordinated revocation; no sign-in by link) pass again with both realms in production mode.
> - Spike: user verification (AUTH-PASSKEY-010). Pass: for each realm, the suite records whether the provider refuses an assertion without the user-verified flag; if the workforce realm's doesn't, the compensating control is chosen before stage 3 and built by stage 8.
> - Spike: code length. Pass: whether the provider lets us set it is recorded; if it does, a requirement for 8-digit codes replaces AUTH-CODE-001 under a new ID.

**Stage 2, the existing spike** (SEC-004): its pass line becomes "across a chain of ten refreshes, every access token carries the sign-in ID stamped at sign-in, and after the device record is deleted the refresh token, presented directly at the provider's token endpoint, yields no token; one sign-in's provider sessions can be ended by ID."

**Stage 8, Exit criteria** (SEC-001): add "AUTH-ADMIN-013 from every container on the reference deployment" to "Runs on the deployment the parts that couldn't run earlier".

**Stage 9, Exit criteria** (SEC-019, SEC-035): the ASVS line's pass becomes "every Level 2 requirement is met by a passing spec requirement, is the relaxation or the deviation named in spec §1, or is recorded as not applicable with its reason"; the rotation rehearsal's pass adds "and the emergency path in arch §13 leaves no replica accepting the deleted key".

### 7.5 `docs/decisions.md`

**DEC-011, Trade-offs** (SEC-002), replace with: "A tampered client could skip verification. For subscribers that is accepted, since a passkey only stands in beside a device-key proof. For staff the passkey is the whole sign-in, so a workforce realm whose provider accepts unverified assertions is deployed only behind AUTH-PASSKEY-010's compensating control."

**DEC-016, Why** (SEC-022, SEC-041), replace with: "Browser script never sees a token, and Strict cookies travel on no cross-site request. Two cookies are Lax because they are read during the cross-site return: the sign-in transaction cookie and the browser-ID cookie our consent step reads. The callback then lands the browser on a same-origin page, so the app's first request carries the Strict cookies."

**DEC-024, Trade-offs** (SEC-004), replace with: "Issuing tokens depends on Shell's hook. Per-device sign-out rests on the sign-in ID surviving every refresh and on the hook running at each one (To verify; the provider's open-source revocation is per subject, not per device); architecture §15 sets what changes if it doesn't, and AUTH-TOKEN-003 is never relaxed."

New records (the next free IDs):

> ### DEC-039 Provider admin APIs are reachable only from Shell's api and worker
>
> **Decision.** The providers' admin listeners accept connections only from `api`, `worker` and the deploy job, enforced by the platform. Internal connections authenticate the server (the private CA) but not the client, a deviation from ASVS 13.2.1 that spec §1 names.
>
> **Why.** The admin APIs are protected only by where they listen, and they can issue staff enrollment codes; keeping the internet-facing edge and every other component away from them needs no new infrastructure.
>
> **Trade-offs.** A foothold in `api` or `worker` still reaches them, as it reaches the database; client certificates close that when their trigger comes.
>
> **Considered.** Client certificates on every internal hop now: the CA exists, but every client gains certificate handling before any trigger. A shared token at a proxy: an unchanging credential, which ASVS 13.2.1 rules out.
>
> **See.** [architecture §1](architecture.md#1-system-and-deployment); [spec §10](spec/auth.md#10-staff-and-administration) (AUTH-ADMIN-013), [§1](spec/auth.md#1-conventions-and-assurance).
>
> ### DEC-040 Sign-out ends the provider sessions from the server
>
> **Decision.** Signing out deletes the device record and clears the cookies in the request; a retried task then revokes the refresh token and ends the sign-in's provider sessions by the login session ID our consent step recorded, for browsers, apps and agents alike. No ID token is kept in the browser or sent in a URL; our sign-out step handles only requests that reach the provider from elsewhere, asking the user to confirm.
>
> **Why.** An ID-token hint in a sign-out URL lands in logs and history, and a top-level navigation can't carry the CSRF header; the server-side path is already needed for logging out other devices.
>
> **Trade-offs.** Depends on ending one sign-in's provider sessions by ID (To verify); if that fails, browsers reach the provider's sign-out by a form POST, never a GET URL.
>
> **Considered.** Front-channel sign-out with the ID-token hint: a token in a URL, and either a CSRF exemption or an ID token handed to script.
>
> **See.** [architecture §7](architecture.md#7-token-and-cookie-flow); [spec §7](spec/auth.md#7-account-settings-devices-and-deletion) (AUTH-ACCT-013), [§8](spec/auth.md#8-sessions-tokens-and-cookies) (AUTH-TOKEN-009).

## References

- OWASP ASVS 5.0.0: <https://github.com/OWASP/ASVS/tree/v5.0.0_release/5.0/en>
- NIST SP 800-63B-4 (final, 31 July 2025): <https://csrc.nist.gov/pubs/sp/800/63/b/4/final>; session and authenticator sections at <https://pages.nist.gov/800-63-4/sp800-63b/session> and <https://pages.nist.gov/800-63-4/sp800-63b/authenticators>
- RFC 9700: <https://www.rfc-editor.org/rfc/rfc9700.html>; RFC 8725: <https://datatracker.ietf.org/doc/rfc8725/>; RFC 9068: <https://rfc-editor.org/rfc/rfc9068.html>
- W3C WebAuthn Level 3 (Recommendation, 25 August 2026): <https://www.w3.org/TR/2026/REC-webauthn-3-20260825/>
- OWASP Cheat Sheet Series (CSRF Prevention, Session Management, HTML5 Security, Logging): <https://cheatsheetseries.owasp.org/>
- Google Workspace SMTP relay limits: <https://knowledge.workspace.google.com/admin/gmail/advanced/route-outgoing-smtp-relay-messages-through-google>