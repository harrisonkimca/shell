# Security design confirmation: Shell authentication baseline

Bounded check of the design before the first production release. Date: 8 November 2026.
Inputs: `docs/spec/auth.md` (cited by ID or "spec §n"), `docs/architecture.md` ("arch §n"),
`docs/decisions.md` (DEC-nnn), `docs/roadmap.md`, `docs/security-review.md` (SEC-nnn). The README
was not needed.

## 1. Verdict: SUFFICIENT

The design defends against the realistic threats to a passwordless platform with the established
patterns: a confidential BFF holding tokens in `HttpOnly`, `Secure`, `__Host-`, Strict cookies;
PKCE S256, `state` and `nonce` with exact redirects; ES256-only local verification with a per-request
device-record check that makes sign-out and disabling immediate; zero-grace refresh rotation
serialised across replicas; and no silent account linking. Six of the seven accepted findings are
fixed in the documents; SEC-003 is partly fixed, but its remaining gap is availability (a distributed
flood can still use up the realm-wide code cap) and detection detail, not takeover or bypass. No
Critical or High issue remains. The main residual risk, the email ceiling (an account is as strong
as its mailbox or Google account), is a documented, deliberate trade-off (spec §1, DEC-007, arch §11),
and the design's correctness still rests on the provider behaviours in the "Verify in tests" list.

## 2. Part 1 — Real-world threats and established patterns

| # | Threat / pattern | Result | Covered by | Reason |
|---|---|---|---|---|
| 1 | Credential stuffing, phishing | Pass | AUTH-ASSURE-001, AUTH-IDP-001, AUTH-PASSKEY-001 | No passwords anywhere; every passkey ceremony requires UV and the server refuses a response without the flag. Email codes stay phishable: accepted email ceiling. |
| 2 | Code brute force, inbox flooding | Pass | AUTH-CODE-001–004, AUTH-LIMIT-001–003, -005 | 10-min single-use codes, 5 attempts per flow, 60 s gap, 5/h and 10/day per address, 20/h per IP, edge 30/15 min, realm-wide cap. |
| 3 | Account enumeration | Pass (accepted exception) | AUTH-SIGN-003, AUTH-ERROR-003, AUTH-ERROR-004, DEC-013 | Shell's screens answer identically with timing bound; the provider's code API revealing unknown addresses is a recorded, rate-limited risk. |
| 4 | Takeover via email access | Pass | AUTH-NOTIFY-001, AUTH-PASSKEY-006, AUTH-ACCT-004, AUTH-ACCT-008, AUTH-STAFF-008 | Notice on every credential, device and switch change; no subscriber recovery flow and no address change; 24 h deletion delay and support freeze. |
| 5 | Account linking | Pass | AUTH-IDP-006, AUTH-SIGN-008–009, AUTH-ACCT-005, DEC-012 | Each method finds the account by its own key; Google links only in settings after a fresh sign-in; provider linking off (verify). |
| 6 | Session theft | Pass | arch §7, AUTH-WEB-001, AUTH-TOKEN-009, DEC-016 | Token cookies `HttpOnly`, `Secure`, `__Host-`, Strict; no token in script storage; mobile keychain plus memory. |
| 7 | CSRF on every state-changing route | Pass | AUTH-WEB-003, AUTH-ADMIN-001, AUTH-ACCT-011 | Header plus same-origin fetch metadata on every unsafe method of cookie hosts, so refresh, logout and admin are covered; foreign sign-outs need confirmation. |
| 8 | Token forgery | Pass | AUTH-TOKEN-001–003, AUTH-TOKEN-010, arch §10 | ES256-only, `kid` from the configured key set only, exact `iss`/`aud`, `exp`/`nbf`/`iat` with 60 s; stale keys refused after 1 h. |
| 9 | Code interception and injection | Pass | AUTH-WEB-007, AUTH-IDP-012–013, AUTH-CLIENT-001–002, -008 | S256 required and `plain` refused, single-use `state` and `nonce`, exact redirects, no implicit grant, one issuer per client (RFC 9700). |
| 10 | Refresh-token theft | Pass | AUTH-IDP-015, AUTH-TOKEN-007, arch §7 | Rotation with 0 s grace and chain revocation; Redis lock and 409 retry define behaviour across replicas (verify under a slow provider). |
| 11 | Revocation gaps | Pass | AUTH-TOKEN-004, -008, AUTH-SESSION-001–002, arch §9 | Both Kratos and Hydra revocations on every account-wide action, as a retried task; the per-request check refuses at once; 10-min access tokens. |
| 12 | Admin abuse | Pass | AUTH-ADMIN-001, -003, -007, -008, arch §1 | Provider admin APIs on a network only `api`, `worker` and deploy join; workforce token, `admin` role, passkey session and CSRF; audit on every request; `confirm` on destructive actions. |
| 13 | Data leakage | Pass | AUTH-TOKEN-009, AUTH-CODE-005, AUTH-AUDIT-002, NFR-010, AUTH-ERROR-001 | No tokens, codes or device IDs in logs; masked addresses; RFC 9457 errors without internals (edge access logs: verify). |
| 14 | Infrastructure | Pass | NFR-014, NFR-015, AUTH-WEB-004–005, NFR-012, arch §6 | TLS 1.2+ at the edge and internally, HSTS a year, empty CORS allowlist, secrets manager only, a database role per component. |
| 15 | Supply chain, backups | Pass | NFR-011, NFR-006–007, AUTH-PRIVACY-005 | Images pinned by digest and scanned, CI failing on fixable high/critical; daily encrypted backups; restore rehearsed and re-applying deletions. |
| 16 | Pattern fit | Pass | DEC-016, arch §4, §7; spec §1 | BFF as a confidential client (IETF browser-apps BCP); RFC 9700 controls above; staff passkeys with UV and AAL2 time limits, no AAL claimed for subscribers (800-63B-4); ASVS L2 with the documented 6.3.3 relaxation and items decided Later (SEC-014, SEC-019). |

## 3. Part 2 — Accepted findings

| Finding | Result | Resolving text and reason |
|---|---|---|
| SEC-001 Admin APIs reachable by any internal component | Fixed | arch §1: admin APIs on a separate network only `api`, `worker` and the deploy job join, so the edge can't reach them; AUTH-ADMIN-008 tests from the edge. |
| SEC-002 Unverified passkey assertion for staff | Fixed | AUTH-PASSKEY-001 and DEC-011: the server refuses any response without the UV flag (provider setting or Shell's check); arch §11 row updated; stage 1 spike. |
| SEC-003 No realm-wide code limit; distributed guessing unseen | Partly fixed | AUTH-LIMIT-001 adds a realm cap below the relay quota with an 80% alert, NFR-009 a realm-wide failed-entry alert, spec §15 and arch §16 measurable triggers. Not added: failed entries per address across flows. A flood can still spend the realm cap and stop code sign-ins (availability only). |
| SEC-004 Per-device sign-out rests on unproven behaviour; unsafe fallback | Fixed | arch §15: the fallback is both revocations and AUTH-TOKEN-003 is never relaxed; DEC-024 matches; AUTH-DEVICE-004 tests a refresh sent straight to the provider. |
| SEC-008 Refusing hooks' failure mode; sign-in audit | Fixed | AUTH-IDP-008: the provider refuses when the hook fails, tested with the hook stopped; AUTH-AUDIT-001: sign-ins audited by our consent step. |
| SEC-009 Provider's own linking path | Fixed | AUTH-SIGN-009: any provider linking outside settings is off, tested through the public API too; arch §15 lists it to verify. |
| SEC-010 IPv6 keying of per-IP limits | Fixed | AUTH-LIMIT-005: every per-IP limit counts IPv6 by /64; arch §11 table matches. |

## 4. Part 3 — Remaining serious gaps

None. No issue found meets the Critical or High bar. SEC-003's residual is availability and
detection, not takeover or bypass. No finding decided Later or Rejected was found to meet the bar
with a realistic attack; the closest (SEC-006, SEC-007) need malware on the user's machine or yield
an ID token that can't call the API.

## 5. Verify in tests

Carry into the roadmap stages; each is a design assumption that only the real provider or deployment can confirm.

| Stage | Check |
|---|---|
| 1 | UV refusal on every passkey submission path the provider exposes (browser and API flows), both realms; a software authenticator without UV fails (AUTH-PASSKEY-001). |
| 1, 8 | Provider admin ports unreachable from the edge, metrics, PostgreSQL and Redis containers, reachable from `api` and `worker` (AUTH-ADMIN-008). |
| 1 | A recovery request for a staff address sends nothing; the customer realm answers no recovery request (AUTH-STAFF-008, AUTH-IDP-001). |
| 2 | Spike: the sign-in ID survives ten refreshes. If it fails, refreshed tokens are refused (fail closed), so this is a go/no-go for per-device sign-out (arch §15). |
| 2 | Two replicas refreshing at once with a provider delayed ~4 s rotate once; the lock outlives the provider timeout; behaviour with Redis down (AUTH-TOKEN-007). |
| 2 | CSRF check on refresh and logout, and the CSRF cookie is still present when the access token has expired (AUTH-WEB-003). |
| 2 | Strict token cookies on the app's first request after a cross-site return, in three engines (AUTH-WEB-002). |
| 2 | Stale-key limit: with the key URL down past 1 h every token is refused (AUTH-TOKEN-002). |
| 2, 8 | Realm-wide code cap and its alert; realm-wide failed-entry alert; IPv6 /64 grouping at the edge and in `EmailSender` (AUTH-LIMIT-001, -005, NFR-009). |
| 2, 8 | Edge and provider access logs carry no ID-token hint, code, `state` or challenge (NFR-010). |
| 4 | Provider validates Google's ID token incl. `nonce`; no provider linking through its public API; Google re-prompt; disabled account not revealed before its code (AUTH-IDP-006, AUTH-SIGN-009, arch §15). |
| 5 | Refusing hooks fail closed with the hook stopped; settings hooks tell add from remove; a logged-out device's refresh fails at the provider's token endpoint (AUTH-IDP-008, AUTH-DEVICE-004). |
| 9 | Restore rehearsal re-applies deletions; signing-key rotation leaves no gap (NFR-007, AUTH-PRIVACY-005, AUTH-TOKEN-010). |