# Authentication and account requirements

What Shell's sign-in, accounts, sessions and administration must do, each
as a requirement with a stable ID and a test. The [README](../../README.md)
owns principles and [architecture.md](../architecture.md) the mechanisms;
this file owns behaviour and values. Hostnames are examples.

## 1. Conventions and assurance

**IDs.** `AUTH-<AREA>-NNN` for functional requirements, `NFR-NNN` for
non-functional ones. An ID is never reused or renumbered; a requirement
whose meaning changes gets a new ID.

**Reserved IDs.** Removed requirements retain their IDs, unavailable for reuse:
AUTH-A11Y-001;
AUTH-ACCT-001, AUTH-ACCT-007–010;
AUTH-ADMIN-002–003, AUTH-ADMIN-005, AUTH-ADMIN-010–012;
AUTH-ASSURE-003;
AUTH-AUDIT-001;
AUTH-CLIENT-001, AUTH-CLIENT-004–006;
AUTH-DEVICE-001, AUTH-DEVICE-005–006;
AUTH-ERROR-002;
AUTH-FRESH-001, AUTH-FRESH-003, AUTH-FRESH-005–009;
AUTH-I18N-005;
AUTH-IDP-001, AUTH-IDP-003–004, AUTH-IDP-007–008, AUTH-IDP-010, AUTH-IDP-013, AUTH-IDP-018, AUTH-IDP-021;
AUTH-LIMIT-006;
AUTH-NOTIFY-001, AUTH-NOTIFY-005;
AUTH-PASSKEY-001–009;
AUTH-PRIVACY-002–003, AUTH-PRIVACY-005–006;
AUTH-SCOPE-003;
AUTH-SIGN-002;
AUTH-TRUST-001–007;
NFR-003, NFR-009.

**Columns.** *Requirement*, in MUST wording. *Acceptance*, one testable
line. *Verification*: unit test; integration suite (against the real
provider, arch §13); configuration check (settings, startup checks, grants
or DNS inspected); hands-on check (by hand once its subject exists, arch
§15); load test. *Owner*: provider configuration; app (Shell's backend, web
app and console, and the mobile-client contract forks follow); sign-in
screen (our sign-in module in `web/`); operations. *ASVS*: the OWASP ASVS
5.0 requirements that clearly apply, blank if none; "To verify" marks an
uncertain mapping. "arch §n" is section n of
[architecture.md](../architecture.md).

**Words.** *Realm*: customer (subscribers) or workforce (staff). *Fresh
sign-in*: signing in again within a session, by an email code or Google
for subscribers and a passkey for staff; it sets the session's
`auth_time`. *Window*: how old a fresh sign-in may be for a route; zero
means every time. *Device record*: one entry of "Where you're signed in",
one per sign-in, named by its *sign-in ID*.

**Assurance.** Shell targets ASVS Level 2 with the following relaxation and
named deviation; it does not claim unqualified Level 2 compliance.
Subscribers use a single factor: an email code or Google,
whose own MFA Shell cannot see. Accepting this at ASVS Level 2 deliberately
relaxes ASVS 6.3.3. Signing in again is also the way back in, so an account
is only as strong as its mailbox or Google account (arch §11). Retained
mitigations are fresh sign-ins before Google changes and logging out other
devices, an every-time sign-in and explicit confirmation for deactivation,
new-device and Google-change notices, the device list and revocation, code
rate limits, 10-minute access tokens and immediate refusal of disabled
accounts and logged-out devices. These do not prevent mailbox takeover.
Shell claims no NIST AAL for subscriber sign-in; subscriber sessions follow
AAL1 time limits. Staff passkeys require server-checked user verification,
and staff sessions follow AAL2 limits. ASVS Level 3 is outside the baseline.

**Named deviation: internal client authentication (ASVS 13.2.1).**
Provider admin APIs rely on private-network restrictions; hooks and some
data-service connections use static secrets instead of short-lived or
certificate-based client authentication, leaving [ASVS 13.2.1](https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x22-V13-Configuration.md#v132-backend-communication-configuration) unmet on those paths.
Verified internal TLS, restricted provider-admin network access, per-call
hook secrets and least-privilege service accounts remain required
(arch §§1, 6, 13). They limit exposure but do not prevent a compromised
authorized component from using those connections. Stronger internal client
authentication is Later; this deviation waives no other control.

Deactivation retains account data. Shell completion is not a claim of
privacy-law compliance; applicable forks must implement permanent deletion
and verify their retention and privacy obligations before launch.

**Owned elsewhere.** Token acceptance and realm hosts, arch §3; clients, the
principal, the gate mechanism and API versioning, arch §4; how the default
provider meets section 2, arch §5; data placement, tables, audit-log columns
and retention, and residency, arch §6; cookie attributes and the refresh
flow, arch §7; account changes, the device list and continuation codes, arch §8; administration, the console's Data
section and the staff script, arch §9; the error-code scheme, key cache,
timeouts and retries, arch §10; rate-limit layers, security headers, the
threat model and the email ceiling, arch §11; environments, internal TLS,
CI/CD, the integration suite, observability, backups and key rotation, arch
§13; deployment decisions,
[README](../../README.md#deployment-decisions).

| ID | Requirement | Acceptance | Verification | Owner | ASVS |
|---|---|---|---|---|---|
| AUTH-ASSURE-001 | The customer realm MUST offer exactly two ways to sign up and sign in, an email code and Google, and the workforce realm exactly one, a passkey. No other path (passwords, sign-in links, SMS, authenticator-app or lookup codes, self-service recovery) may start a session, apart from a staff enrollment code's session, which can only register passkeys (AUTH-STAFF-001). | Each realm's provider configuration enables only these, and apart from that enrollment session, no flow in the integration suite starts a session any other way. | Configuration check; integration suite | Provider configuration | 6.1.3, 6.3.4 |
| AUTH-ASSURE-002 | Every subscriber session MUST be treated the same, whatever method started it, and the principal carries no assurance level: what a route needs is its scopes and its gate alone (section 6). | An email-code session and a Google session reach the same routes with the same scopes and gates. | Unit test | App | 6.3.4 |

## 2. Identity provider capabilities

A realm's provider must meet every row: a candidate lacking one is out, and
cost decides among the rest
([README](../../README.md#deployment-decisions)). How the default provider
meets each row is in arch §5. Requiring user verification and accepting
security keys in passkey ceremonies are done by our sign-in screen and
checked by the server (section 4).

| ID | Requirement | Acceptance | Verification | Owner | ASVS |
|---|---|---|---|---|---|
| AUTH-IDP-024 | The customer realm MUST enable only email codes and Google for sign-up and sign-in; the workforce realm only passkey sign-in and AUTH-IDP-030's enrollment codes. Passwords, sign-in links, authenticator-app codes, lookup codes and SMS MUST be off in both, subscriber passkeys MUST be off, and the customer realm MUST run no recovery flow. | Both configurations enable only their methods, no flow offers a password, subscriber passkey or sign-in link, and customer recovery requests fail (Ory: customer `code` and `oidc`; workforce `passkey`). | Configuration check | Provider configuration | 6.3.4 |
| AUTH-IDP-002 | Each realm MUST be its own provider instance or tenant, with its own issuer, signing keys, audience, cookies, host and storage. | Startup refuses two realms that share an issuer, key URL or audience. | Configuration check | Provider configuration | |
| AUTH-IDP-025 | The workforce provider MUST support discoverable passkey sign-in and browser autofill without first looking up an address, a configured RP ID and allowed origins, attestation `none`, required user verification and security keys. | Staff sign in from autofill without an address step; a passkey on a device and one on a security key complete ceremonies with required verification (arch §15). | Integration suite; hands-on check | Provider configuration |  |
| AUTH-IDP-005 | The provider MUST support email codes for sign-up and sign-in, entered in the current window and never sent as links, each usable once and only in the flow that sent it, with a lifetime and an attempt limit (per code or per flow) that we set. | A code works once and only in its own flow, and fails after its lifetime or the attempt limit. | Integration suite | Provider configuration | 6.5.1, 6.6.2 |
| AUTH-IDP-006 | The provider MUST support Google sign-in that validates Google's ID token (signature, issuer, audience, expiry and `nonce`) before using any claim, finds the account by Google's subject ID, runs a claims mapper we write that can refuse an unverified address, and never links accounts on a matching address. | A new Google account with an existing account's address neither signs in to that account nor links to it, and a Google ID token failing any of those checks is refused. | Integration suite | Provider configuration | 6.8.1, 6.8.2 |
| AUTH-IDP-026 | The provider MUST report authentication steps in order in every user token, with the latest step last, for gate checks (AUTH-FRESH-013). | Fresh sign-ins by each enabled method leave that method last in `amr`, and refreshes preserve the latest step and its time. | Integration suite | Provider configuration | 6.8.4 |
| AUTH-IDP-027 | Before saving, the provider MUST call a refusing hook for sign-ups and settings changes (staff passkeys and Google links), passing authentication steps and times and identifying the change and credential. Unreachable or failing hooks MUST refuse the operation. | With a refusing or stopped hook, a Google sign-up, Google link and staff passkey addition each fail; hook payloads identify each change, its credential and the latest sign-in. | Integration suite; hands-on check | Provider configuration |  |
| AUTH-IDP-009 | The provider MUST report each successful sign-up and sign-in with its method, and each settings change, to a hook of ours, with the identity and the client IP. | Each event reaches Shell's hook route once with those fields. | Integration suite | Provider configuration | 16.3.1 |
| AUTH-IDP-028 | The provider's settings screens MUST enforce a configurable recent-sign-in window, and address editing MUST be disabled. | With the window at 15 minutes, unlinking Google or removing a staff passkey at 16 minutes requires sign-in again; an address edit is rejected (Ory: `privileged_session_max_age`). | Integration suite | Provider configuration | 7.5.1 |
| AUTH-IDP-011 | The provider MUST hand every email to Shell's sender over HTTP with its purpose, code, recipient, identity ID, language and the client IP set by the edge, and retry when the sender answers 5xx. | Every code reaches `EmailSender` with those fields, and a 5xx answer is retried. | Integration suite | Provider configuration | 15.3.4 |
| AUTH-IDP-012 | The provider MUST run the authorization-code flow with PKCE `S256` required and `plain` refused, exact redirect-URI matching, and codes usable once within 10 minutes; reusing a code MUST revoke the tokens it issued. | A `plain` challenge, an unregistered redirect URI and a reused code are each refused. | Integration suite | Provider configuration | 10.4.1, 10.4.2, 10.4.3, 10.4.6 |
| AUTH-IDP-029 | The provider MUST register clients with their grants, scopes, audience and first-party flag, authenticate confidential clients by `private_key_jwt` with ES256, and offer only authorization-code and refresh grants. | Unregistered grants, scopes and audiences are refused, as is a confidential client without a valid assertion. | Integration suite | Provider configuration | 10.4.4, 10.4.10, 10.4.11 |
| AUTH-IDP-014 | The provider MUST issue ES256 JWT access tokens carrying issuer, audience, scopes, `client_id`, `jti` and `kid`, publish its keys behind OIDC discovery with an exact issuer, and roll keys over by signing with a new key at once while still publishing the old one. | After a key is added, new tokens carry its `kid` and tokens signed with the old key still verify. | Integration suite | Provider configuration | 9.2.4 |
| AUTH-IDP-015 | The provider MUST rotate the refresh token on every use with no grace period, end the whole chain when a rotated token is reused, and let us set access- and refresh-token lifetimes per realm. | A reused refresh token is refused, and its newest descendant then fails too. | Integration suite | Provider configuration | 10.4.5 |
| AUTH-IDP-016 | The provider MUST let a hook of ours set claims on every access token, refreshes included, and refuse to issue one, and MUST issue no token when that hook fails. | With the hook down, token and refresh requests fail; with it up, each access token carries `auth_time`, `amr` and the sign-in ID, and a refusal stops the refresh. | Integration suite | Provider configuration | |
| AUTH-IDP-017 | The provider MUST hand consent to a step we run, which sees the sign-in session's ID, can add claims to the tokens that follow and can grant first-party clients at once. | A first-party sign-in completes without a consent screen, and its ID token carries the sign-in ID our step added. | Integration suite | Provider configuration | 10.7.1 |
| AUTH-IDP-030 | The provider MUST expose an admin API only privately or, if managed, with strong credentials, supporting identity creation, disablement and enablement, staff address changes, session listing and revocation (all or one by ID), all-refresh-grant revocation and one-time enrollment codes with configurable lifetimes. Staff addresses MUST NOT start self-service recovery. | Disablement and both revocations prevent sign-in and refresh; ending one session leaves others; an enrollment code registers staff passkeys and staff recovery requests send nothing. | Integration suite | Provider configuration | 7.4.2, 7.4.5 |
| AUTH-IDP-019 | The provider MUST let us set how long its own sign-in session lasts, remembered sign-ins included, end that session through a sign-out step we run, and accept sign-out requests carrying an ID-token hint. | After sign-out, a new sign-in from the same browser shows the sign-in screen. | Integration suite | Provider configuration | 7.6.1 |
| AUTH-IDP-020 | The provider MUST run in production mode in every environment, development included, and be deployable in the fork's region: self-hosted anywhere, or as a managed tenant in that region. | Every environment's provider runs in production mode, and a managed candidate lists the chosen region. | Configuration check | Provider configuration | 13.4.2 |

## 3. Sign-up, sign-in and linking

Customer realm unless a row says otherwise. Mobile apps show the same provider pages in the system-browser sheet
(AUTH-CLIENT-012). Browsers accept terms on the app host; mobile clients
accept them through the API.

| ID | Requirement | Acceptance | Verification | Owner | ASVS |
|---|---|---|---|---|---|
| AUTH-SIGN-001 | Deployed environments MUST serve our own sign-in screen for sign-in, sign-up, signing in again, staff enrollment and the provider's settings steps, with our app running the consent and sign-out steps; the provider's reference UI MUST run only in development. | No deployed environment serves the reference UI. | Configuration check | Operations | |
| AUTH-SIGN-015 | Customer sign-in and sign-up MUST show only an email step and "Continue with Google", side by side; signing in again follows AUTH-FRESH-004. Staff sign-in MUST offer passkeys only. | Customer entry pages render exactly those two options; staff entry offers no code, Google or sign-up. | Unit test | Sign-in screen | 6.3.4 |
| AUTH-SIGN-003 | The email step MUST send a code whether or not the address has an account, accounts made with Google included, and MUST look and answer the same, in comparable time, either way. | A new address, an existing one and a Google-made one get the same screen and response, and each gets a code; over 100 requests each, their median response times differ by less than 50 ms. | Integration suite | Sign-in screen | 6.3.8 |
| AUTH-SIGN-004 | For an address with no account, entering the code MUST confirm the address, create the account and sign the user in, followed by the terms step. | A new address ends signed in with a verified address, after the terms step. | Integration suite | Sign-in screen | |
| AUTH-SIGN-005 | For an address with an account, however it was made, entering the code MUST sign the user in. | Codes sign in accounts made by email and with Google. | Integration suite | Sign-in screen | |
| AUTH-SIGN-006 | "Continue with Google" MUST send no code, Google's verified answer being the proof, and an already-linked Google account MUST sign in to its account, found by the Google account's ID whatever its address at Google. | A linked Google account given a new address at Google signs in to the same account. | Integration suite | Provider configuration | 6.8.1 |
| AUTH-SIGN-007 | A Google account not seen before, whose address Google has verified and no account uses, MUST create an account linked to it, with Google's address as its verified address, followed by the terms step. | Such a sign-in creates one linked account whose address is verified. | Integration suite | Provider configuration | |
| AUTH-SIGN-008 | A Google account not seen before MUST NOT create or reach an account when Google hasn't verified its address ("Continue with email instead.") or when an account, made by email or with another Google account, already uses the address ("This email already has an account. Sign in with an email code, then link Google in Settings."). | Each case shows its message and creates, signs in and links nothing. | Integration suite | Provider configuration | |
| AUTH-SIGN-009 | Each method MUST find the account by its own key (an email code by the address, Google by the Google account's ID) and never by a matching address; Google is linked only in settings (AUTH-ACCT-005), one Google account per account. Any linking the provider itself offers outside settings MUST be off. | No sign-in or sign-up combination in the integration suite links or merges accounts on a matching address, including through any linking step the provider offers at sign-in, tried through its public API as well as our screens. | Integration suite | Provider configuration | 6.8.1 |
| AUTH-SIGN-010 | A new account MUST complete the terms step before the API serves it: every customer route except the terms step and sign-out MUST answer 403 `auth.terms_required` until every required item is accepted. A new version of a required item MUST follow that item's setting: re-acceptance brings the 403 back until the new version is accepted, while a notice shows the new version once in the terms step without blocking. | A new account gets 403 `auth.terms_required` on the profile route, then 200 after accepting; a new terms-of-service version brings the 403 back, and a new privacy-policy version only shows a notice. | Unit test | App | 2.3.1 |
| AUTH-SIGN-011 | The terms step MUST show the items written at deployment (terms of service, privacy policy and required confirmations such as a minimum age), each with a version, text per language and, for a required item, a setting for new versions: re-acceptance by default, a notice by default for the privacy policy. No age or country rule may be in code; a deployed environment MUST refuse to start with development placeholders; optional items MUST be declinable and changeable later. | Startup with placeholder items outside development fails, an item without a setting takes its default, and a declined optional item is recorded as declined. | Configuration check | App | |
| AUTH-SIGN-012 | Code entry MUST allow paste, use `autocomplete="one-time-code"` and a numeric keyboard, offer a resend once the 60-second gap has passed, announce errors to screen readers, and set no timeout shorter than the code's 10-minute life. | A pasted code signs in, and the screen still accepts a code 9 minutes after it was sent. | Unit test; hands-on check | Sign-in screen | |
| AUTH-SIGN-013 | A disabled account MUST get no session, and after its code or Google step MUST be told that it's disabled and how to reach support at the contact address set at deployment. | A disabled account's code sign-in shows that message and issues no tokens (whether the provider tells it apart before the code: To verify). | Integration suite | Sign-in screen | |

## 4. Staff passkeys

Passkeys belong to the workforce realm only.

| ID | Requirement | Acceptance | Verification | Owner | ASVS |
|---|---|---|---|---|---|
| AUTH-PASSKEY-011 | Every staff passkey ceremony MUST require user verification (face, fingerprint or PIN): the screen requests it and the server refuses responses without the user-verified flag, through browser and API flows alike. | Registration and staff sign-in require verification; software-authenticator responses without UV fail on every submission path, and physical devices ask for verification (arch §15). | Integration suite; hands-on check | Sign-in screen | 6.3.3 |
| AUTH-PASSKEY-012 | Staff ceremonies MUST accept device passkeys, phones through the browser's cross-device flow and security keys without restricting authenticator type. | A phone and a security key each register and sign staff in. | Integration suite; hands-on check | Sign-in screen |  |
| AUTH-PASSKEY-013 | Staff registration MUST request attestation `none` and a discoverable credential. | Workforce registration options require a resident key and no attestation. | Integration suite | Provider configuration |  |
| AUTH-PASSKEY-014 | Staff MUST be able to hold several passkeys, listed in settings with name and date added. | A staff account signs in with each of three passkeys and lists all three. | Integration suite | Provider configuration |  |
| AUTH-PASSKEY-015 | After initial enrollment (AUTH-STAFF-003), staff passkeys MUST be added only from settings after a passkey sign-in within 5 minutes, notifying the staff member. | A staff sign-in 4 minutes ago permits adding a passkey and sends a notice; at 6 minutes the settings hook refuses. Outside enrollment and settings no screen offers registration. | Integration suite | App | 7.5.1 |
| AUTH-PASSKEY-016 | Staff MUST be able to rename a passkey without fresh sign-in or notice, using Shell's label keyed by provider credential ID; settings and notices use that label and the change is audited. | Renaming changes settings and the next relevant notice and writes an audit entry. | Unit test | App |  |
| AUTH-PASSKEY-017 | Removing a staff passkey MUST require a passkey sign-in within 15 minutes and notify the staff member; the last passkey MUST NOT be removable. | Removal at 16 minutes requires sign-in again, removal within the window notifies, and the last credential cannot be removed. | Integration suite | App | 7.5.1, 6.5.6 |
| AUTH-PASSKEY-018 | The workforce RP ID MUST be `staff-auth.<domain>` with only that host as an allowed origin. | A workforce ceremony from `auth.<domain>` fails. | Integration suite | Provider configuration |  |

## 5. Email codes and rate limits

Each layer counts its own limit (arch §11): the edge counts flow
submissions per IP; `EmailSender` counts codes per address, and code
requests and sign-ups per IP; the provider counts attempts per flow. The
values are starting values in configuration, tuned from the metrics.

| ID | Requirement | Acceptance | Verification | Owner | ASVS |
|---|---|---|---|---|---|
| AUTH-CODE-001 | Every email code MUST be 6 digits from a cryptographically secure generator, usable once and only in the flow that asked for it, even when submitted twice at once. | Of two simultaneous submissions of one valid code, one succeeds, and a code from another flow is refused. | Integration suite | Provider configuration | 6.5.1, 6.5.3, 6.5.4, 6.6.2 |
| AUTH-CODE-002 | A code MUST stop working 10 minutes after it was sent. | The right code at 10 minutes 1 second is refused. | Integration suite | Provider configuration | 6.5.5 |
| AUTH-CODE-003 | Five wrong entries MUST invalidate the code, counted per sign-in flow across resends. | After five wrong entries the right code is refused, after a resend in the same flow too. | Integration suite | Provider configuration | 6.6.3 |
| AUTH-CODE-004 | `EmailSender` MUST send no new code to an address within 60 seconds of the last, whatever its purpose. | A resend at 59 seconds sends nothing; one at 61 seconds sends. | Unit test | App | 2.4.1 |
| AUTH-CODE-005 | Codes MUST travel only in an email's body and in request bodies, never in a URL, and no email may carry a link that signs in or verifies. | Every email template carries its code and no such link, and no route takes a code in its query string. | Unit test | App | 14.2.1 |
| AUTH-CODE-006 | A successful code sign-in MUST mark its address verified. | After a code sign-in to an unverified address, the provider shows it verified. | Integration suite | Provider configuration | |
| AUTH-LIMIT-001 | `EmailSender` MUST send at most 5 codes per hour and 10 per day to one address, across all purposes, and, across the realm, at most a set number of codes per hour and per day, kept below the email relay's quota and alerting at 80% of it. | The 6th code in an hour and the 11th in a day aren't sent; with the realm-wide hourly cap at 100, the 81st code raises an alert and the 101st isn't sent. | Unit test | App | 6.6.3 |
| AUTH-LIMIT-002 | `EmailSender` MUST accept at most 20 code requests and 10 sign-ups per hour from one client IP, using the IP the edge set and the provider forwarded. | From one IP, the 21st code request and the 11th sign-up in an hour aren't sent. | Unit test | App | 2.4.1 |
| AUTH-LIMIT-003 | The provider's public endpoints MUST be reachable only through the edge, which MUST allow at most 30 flow submissions per 15 minutes from one IP and answer 429 with `Retry-After` beyond that. | The 31st submission from one IP within 15 minutes gets 429, and the provider's ports don't answer directly. | Integration suite | Operations | 2.4.1, 6.3.1 |
| AUTH-LIMIT-004 | Over a limit, `EmailSender` MUST send nothing, log and count it, and answer the provider 2xx so the screen stays generic; with its counters unavailable, it MUST send nothing and answer 5xx so the provider retries. | An over-limit request shows the usual screen and sends nothing; with Redis down, no code is sent and the provider retries. | Unit test | App | 16.5.3 |
| AUTH-LIMIT-005 | Client IPs and correlation IDs MUST be trusted only from configured proxies, and the edge MUST overwrite any value a client sends. Every per-IP limit MUST count an IPv6 client by its /64 network. | A client-sent `True-Client-Ip` doesn't change the IP that is counted or logged, and two addresses in one IPv6 /64 share one count at the edge and in `EmailSender`. | Integration suite | Operations | 4.1.3, 15.3.4 |
| AUTH-LIMIT-011 | Code and submission limits MUST NOT disable accounts or affect Google sign-in, staff passkeys or existing sessions; an email-only user may have to wait for the code window to pass. | With an address at its daily code limit, Google sign-in and existing sessions still work; email-code requests resume when the window passes. | Unit test | App | 6.1.1 |

## 6. Fresh sign-ins

Every route declares a fresh-sign-in window or explicitly no gate (arch §4).
Shell's actions are listed in section 9; forks declare each action they add.

| ID | Requirement | Acceptance | Verification | Owner | ASVS |
|---|---|---|---|---|---|
| AUTH-FRESH-011 | Every route MUST declare its fresh-sign-in window or explicitly no gate beside its scopes; startup MUST refuse a route with no declaration. | A scoped route without a gate declaration stops startup. | Unit test | App |  |
| AUTH-FRESH-002 | A fresh-sign-in gate MUST pass only a token whose `auth_time` is within the route's window, checked on every request and never cached; otherwise the route answers 401 `auth.recent_sign_in_required` with an RFC 9470 `insufficient_user_authentication` challenge whose `max_age` is the window in seconds. | On a 15-minute route, a token signed in 15 minutes 1 second ago gets that 401 with `max_age=900`, and after signing in again the request succeeds. | Unit test | App | 6.8.4, 10.3.4 |
| AUTH-FRESH-012 | Windows MUST be 15 minutes for Google linking or unlinking, removing a staff passkey and logging out other devices or all; 5 minutes for adding a staff passkey and staff high-risk actions (AUTH-ADMIN-016); every time for deactivation; and none for profile changes, terms, passkey renaming and signing out the device in use. Initial staff enrollment follows AUTH-STAFF-003. | The catalogue matches these windows, and each gated route refuses an older sign-in. | Unit test | App | 7.5.1, 7.5.2 |
| AUTH-FRESH-004 | A subscriber's fresh sign-in MUST be an email code or Google, and a staff member's a passkey. Google counts only once the provider can be made to ask again (arch §15); until then, Google users sign in again by email code, and a Google step doesn't meet a fresh-sign-in gate. | The sign-in-again screen offers an email code, and Google once arch §15's check passes; until then, a token whose latest step is Google fails a 15-minute route. | Integration suite; hands-on check | Sign-in screen; app | 6.8.4 |
| AUTH-FRESH-013 | Gates MUST read only the last `amr` entry: email code or eligible Google for subscribers (AUTH-FRESH-004), passkey for staff. Unknown or missing latest methods pass no gate; user tokens missing `auth_time` or `amr` are refused; provider assurance labels are ignored. | A recent customer token ending in `code` passes; one ending in `webauthn` or an unknown method does not; a workforce token ending in `passkey` passes and an enrollment-code token does not; no `amr` gets 401. | Unit test | App | 6.8.4, 10.3.4 |
| AUTH-FRESH-014 | An every-time gate MUST require a sign-in after a single-use challenge bound to the session and route, valid 10 minutes; confirmation MUST arrive within 5 minutes of that sign-in. A missing, reused, expired or unrelated challenge MUST fail. | Deactivation with an unrelated 1-minute-old sign-in fails; one answering its challenge succeeds within 5 minutes, fails afterwards and cannot be replayed. | Unit test | App | 7.5.3, 2.3.1 |
| AUTH-FRESH-015 | Provider settings changes MUST enforce fresh sign-in: email code or eligible Google for customer Google changes, passkey for staff credentials. The provider window is 15 minutes; the refusing hook MUST apply the 5-minute window for staff passkey additions, except initial enrollment (AUTH-STAFF-001). | Unlinking Google at 16 minutes and adding a staff passkey at 6 minutes fail; valid initial enrollment can register passkeys. | Integration suite | App | 7.5.1 |
| AUTH-FRESH-010 | Only the device holding a session MUST be able to continue it: before a fresh sign-in, the client gets a continuation code from Shell with its current session (single-use, valid 10 minutes) and hands it back with the new session afterwards. Shell then moves the old device record's "Signed in" time to the new record and ends the old session; a code that never comes back leaves both sessions to their own limits. | After signing in again, the device list shows one entry with the original "Signed in" time and the old refresh token fails; a continuation code that is reused, older than 10 minutes or presented with another session is refused. | Unit test; integration suite | App | 7.2.4 |

## 7. Account settings, devices and deactivation

Every action here writes an audit entry (AUTH-AUDIT-006), and its gate is
in the route catalogue (section 9).

| ID | Requirement | Acceptance | Verification | Owner | ASVS |
|---|---|---|---|---|---|
| AUTH-ACCT-014 | Subscriber settings MUST show address, Google link, "Where you're signed in", terms and optional items, name, language, timezone and "Deactivate account". | Seeded settings show each item and no address-edit control. | Unit test | App |  |
| AUTH-ACCT-002 | Name, language and timezone MUST be changeable at any time, with no fresh sign-in and no notice. | A 20-day-old session changes its timezone. | Unit test | App | |
| AUTH-ACCT-003 | Settings MUST let the user change their optional terms items. | A declined optional item can be accepted later, and the change is recorded. | Unit test | App | |
| AUTH-ACCT-004 | A subscriber's address MUST NOT be changeable, by the user or by admins: the provider's profile editing is off and no Shell route takes a new address. A lost mailbox means a new account. | An address edit on the provider's settings screen is rejected, and no customer or admin route accepts a new address. | Integration suite | Provider configuration; app | |
| AUTH-ACCT-005 | Linking Google MUST happen only in settings, after a fresh sign-in within 15 minutes (AUTH-FRESH-015), and only when the account has no Google account and the Google account isn't linked to another; it notifies the account's address. | Linking a Google account already linked elsewhere is refused, and a successful link sends its notice. | Integration suite | App | 7.5.1 |
| AUTH-ACCT-006 | Unlinking Google MUST need a fresh sign-in within 15 minutes, leave the account its address and email codes, and notify the account's address. | An unlink 16 minutes after the last sign-in asks for a new one; after an unlink, an email code still signs in. | Integration suite | App | 7.5.1 |
| AUTH-ACCT-015 | "Deactivate account" MUST request a fresh sign-in every time (AUTH-FRESH-014), then explicit "Are you sure?" confirmation within 5 minutes of that sign-in. | A user signed in 1 minute ago is asked again; missing that sign-in or confirming after 5 minutes 1 second fails. | Unit test | App | 7.5.3, 2.3.1 |
| AUTH-ACCT-016 | Confirmed deactivation MUST immediately disable the account, revoke every session and grant and write an audit entry, reusing coordinated disablement and revocation (arch §9). Local refusal is immediate; provider revocations are durable retried work. | Immediately every device's next API call gets 401 and refresh fails, even before provider tasks run; afterwards all provider sessions and grants are revoked, including direct refresh at the provider; the deactivation audit entry is present. | Integration suite | App | 7.4.2 |
| AUTH-ACCT-017 | Signing out the device in use MUST revoke its refresh token, delete its device record, clear token cookies and app cached data, and end its provider sign-in session, keeping the browser ID. Other devices stay signed in and copied access tokens are refused at once (arch §15). | This browser's refresh and old access token fail, its next sign-in shows the screen without a new-device notice, and another device still refreshes. | Integration suite | App | 7.4.1, 14.3.1 |
| AUTH-ACCT-011 | Our sign-out step MUST end the provider session at once for sign-outs our clients start, which carry a valid ID-token hint, and MUST ask the user to confirm any other sign-out request. | A sign-out request without an ID-token hint ends nothing until the user confirms. | Integration suite | App | 10.6.2 |
| AUTH-ACCT-012 | Every signed-in page of the web app and the console MUST offer sign-out, and the confirmation of a staff passkey added or removed, or Google linked or unlinked, MUST offer "Log out all devices". | Every signed-in route renders sign-out, and the passkey-added confirmation offers "Log out all devices". | Unit test | App | 7.4.3, 7.4.4 |
| AUTH-DEVICE-008 | Settings MUST list each live session with browser and platform or app name, "Signed in" (first sign-in), approximate "Last active" ("Active now" within the 10-minute token renewal), marking the current device. | Two devices show two entries, the current one marked, with "Active now" for a refresh in the last 10 minutes. | Unit test | App | 7.5.2 |
| AUTH-DEVICE-002 | Our consent step MUST create a device record for every sign-in, sign-up included, under its sign-in ID; the record counts and shows only once its first tokens are issued, and one whose sign-in never reached the callback is gone after 10 minutes. A record goes when its session ends. | A sign-in abandoned after the consent step never appears and is gone after 10 minutes, and a signed-out device's record is deleted. | Unit test | App | |
| AUTH-DEVICE-003 | The list and every per-request check MUST judge a record by its "Signed in" and "Last active" times against the session limits (AUTH-SESSION-001, AUTH-SESSION-002), so an expired session is neither listed nor accepted, whether or not a sweep has deleted its row yet. | A session idle for 7 days and 1 minute is neither listed nor accepted while its row still exists. | Unit test | App | 7.4.1 |
| AUTH-DEVICE-004 | Logging out another device MUST need a fresh sign-in within 15 minutes, delete its record, revoke its refresh grant and end its provider sign-in session, so its tokens are refused at once (To verify: arch §15) and the provider's remembered sign-in can't start a new session there. | After device A logs out device B, B's next request gets 401, its refresh fails, including when sent straight to the provider, and its next sign-in shows the sign-in screen. | Integration suite | App | 7.5.2, 7.4.1, 7.6.2 |
| AUTH-DEVICE-009 | "Log out all devices" MUST require confirmation and a fresh sign-in within 15 minutes, then end every session and refresh grant, including the one in use. | Every device's refresh fails and the device in use is signed out. | Integration suite | App | 7.5.2, 7.4.1 |

## 8. Sessions, tokens and cookies

The flow is in arch §7.

| ID | Requirement | Acceptance | Verification | Owner | ASVS |
|---|---|---|---|---|---|
| AUTH-SESSION-001 | Subscriber sessions MUST use a 10-minute access token, a 7-day idle limit (the refresh-token lifetime, restarting at each rotation) and a 30-day absolute limit from the session's first sign-in: NIST AAL1 limits (SP 800-63B-4 §2.1.3). | A session idle for 7 days and 1 minute must sign in again, and an active one ends 30 days after its first sign-in, though it signed in again the day before. | Integration suite | Provider configuration; app | 7.1.1, 7.3.1, 7.3.2 |
| AUTH-SESSION-002 | Staff sessions MUST use a 10-minute access token, a 30-minute idle limit and a 12-hour absolute limit from the session's first sign-in, within NIST AAL2's 24 hours overall and 1 hour idle (§2.2.3). | A console idle for 31 minutes must sign in again, and an active one ends 12 hours after its first sign-in. | Integration suite | Provider configuration; app | 7.1.1, 7.3.1, 7.3.2 |
| AUTH-SESSION-003 | Shell MUST enforce the absolute limit itself from the device record's "Signed in" time, which neither refreshes nor fresh sign-ins move: the token hook issues nothing past it, and a request from an older session gets 401 `auth.signed_out`, after which the BFF clears the session's cookies. | A session first signed in 30 days and 1 minute ago is refused though its `auth_time` is a day old, and its refresh fails. | Unit test | App | 7.3.2, 10.4.8 |
| AUTH-SESSION-004 | A new session MUST start only from a sign-in made within the last 15 minutes: the provider's own sign-in session, remembered sign-ins included, lasts at most 15 minutes and ends at sign-out. | 16 minutes after a sign-in, starting a new session in the same browser shows the sign-in screen (Ory: Kratos `session.lifespan` and the remembered login it hands Hydra). | Integration suite | Provider configuration | 7.1.3, 7.6.1 |
| AUTH-SESSION-005 | Shell MUST NOT cap concurrent sessions: each device or client has its own session, refresh chain and device record. | Five devices stay signed in at once, and logging out one leaves the other four. | Integration suite | App | 7.1.2 |
| AUTH-SESSION-006 | Our consent step MUST give each sign-in an ID, carried in the ID token and, by the token hook, in every access token, refreshes included; the hook MUST issue nothing for a sign-in whose device record is gone or expired, and note the record's last activity at each issuance. | Every refreshed token carries its sign-in's ID, a refresh after the record is deleted fails, and "Last active" moves at each refresh (the ID surviving every refresh: To verify, arch §15). | Integration suite | App | 7.4.1, 8.3.2 |
| AUTH-TOKEN-001 | Shell MUST accept only ES256 access tokens with a valid signature by a key in the realm's key set; any other algorithm, `none` included, and any unknown `kid` MUST be refused. | Tokens signed with RS256, HS256, `none` or an unknown key get 401. | Unit test | App | 9.1.1, 9.1.2 |
| AUTH-TOKEN-002 | Keys MUST come only from the realm's configured key URL, never from a token's own headers, and with no usable keys every token MUST be refused (cache and refetch rules: arch §10). | A token carrying its own key in `jwk` or `jku` is refused, and with keys unavailable past the stale limit, requests get 401. | Unit test | App | 9.1.3 |
| AUTH-TOKEN-003 | Shell MUST require the realm's exact issuer and API audience, `exp`, `nbf` and `iat` with at most 60 seconds' leeway, and `sub`, `jti`, `client_id` and scopes, plus `auth_time`, `amr` and the sign-in ID, so ID tokens and tokens for other audiences are refused. | A foreign issuer or audience, an `exp` 61 seconds past, a missing `jti`, a token without a sign-in ID and an ID token each get 401. | Unit test | App | 9.2.1, 9.2.2, 9.2.3, 10.3.1 |
| AUTH-TOKEN-004 | Verification MUST be local, with no provider call, plus one indexed lookup that maps (`iss`, `sub`) to our ID and the sign-in ID to its device record; it adds a subscriber row on first sight and refuses unknown staff, disabled users and logged-out or expired devices at once. | With the provider stopped, valid tokens still work; a disabled user's unexpired token and a logged-out device's unexpired token each get 401 at once. | Unit test | App | 7.2.1, 10.3.3, 8.3.2 |
| AUTH-TOKEN-005 | Each route MUST trust exactly one realm: customer routes only customer tokens, admin routes only workforce tokens with the admin audience, so another realm's token fails before any role check. | A customer token on an admin route and a workforce token on a customer route both get 401. | Unit test | App | 10.3.1 |
| AUTH-TOKEN-006 | Every access token, refreshes included, MUST carry `auth_time`, `amr` and the sign-in ID from the sign-in's ID-token claims, and no token may be issued when that copy fails. | Every refreshed token carries the latest `auth_time` and `amr`, and with the hook down, refresh fails. | Integration suite | Provider configuration | 10.3.4 |
| AUTH-TOKEN-007 | Refresh tokens MUST rotate on every use, and reusing a rotated one MUST end the whole chain with no grace period; refreshes are serialised per session in the BFF and kept to one in flight on mobile (arch §7), and every reuse is logged and counted. If the lock store is unavailable, the BFF MUST refuse refresh with a 503 Problem Details response and keep the cookies, as when the provider is down (NFR-002). | Replaying a rotated token ends the chain; two replicas refreshing at once rotate once, even with the provider slowed to just under its timeout; and with Redis down, refresh gets 503 and keeps the cookies. | Integration suite | Provider configuration | 10.4.5 |
| AUTH-TOKEN-008 | Every account-wide revocation (logging out all devices, disablement, deactivation, staff removal) MUST cover both the provider's sign-in sessions and its refresh grants, and logging out one device MUST cover that device's grant and provider session. | After each, neither the old provider session nor any affected refresh token works. | Integration suite | App | 7.4.1, 7.4.2 |
| AUTH-TOKEN-009 | Tokens MUST reach only the component that uses them: in browsers only `HttpOnly` cookies, on mobile the keychain or keystore for the refresh token and memory for the access token, and never script-readable storage, URLs or logs. The ID token is kept only for sign-out's hint. | After sign-in, browser storage and logs hold no token. | Unit test | App | 10.1.1, 14.3.3 |
| AUTH-TOKEN-010 | A key rotation MUST never refuse a valid token: a new key signs at once while the old one stays published until its last token expires, and no key set is ever emptied (procedure and period: arch §13). | During a rotation, tokens signed by either key verify. | Integration suite | Operations | |
| AUTH-WEB-001 | Every cookie, the admin host's included, MUST carry exactly the name and attributes that arch §7 sets out. | Every `Set-Cookie` header matches arch §7. | Unit test | App | 3.3.1, 3.3.2, 3.3.3, 3.3.4 |
| AUTH-WEB-002 | `Strict` token cookies MUST work after the cross-site return from the provider or Google. | In Chromium, Firefox and WebKit, the first request after the callback carries the token cookies. | Integration suite | App | |
| AUTH-WEB-003 | Unsafe methods on cookie hosts MUST need an `X-CSRF-Token` header matching the CSRF cookie and a same-origin `Sec-Fetch-Site` or `Origin`; cookie hosts MUST accept no bearer token, and `api.` no cookie. | A POST without the header, with a mismatched token or from another site gets 403, refresh and logout included; a refresh with the header passes after the access token has expired; and a bearer token on `app.` is refused. | Unit test | App | 3.5.1 |
| AUTH-WEB-004 | Shell responses MUST NOT carry `Access-Control-Allow-Origin`: the CORS allowlist is empty, since browsers call only their own origin. | A cross-origin preflight to any Shell host gets no CORS headers. | Unit test | App | 3.4.2 |
| AUTH-WEB-005 | Every response MUST carry the headers in arch §11: HSTS for a year with subdomains; a per-host CSP with `object-src 'none'`, `base-uri 'none'` and `frame-ancestors 'none'`; `nosniff`; a strict referrer policy; and `Cache-Control: no-store` on sign-in, token and account responses. | A header check of every host finds them all. | Configuration check | Operations | 3.4.1, 3.4.3, 3.4.4, 3.4.5, 3.4.6, 14.3.2 |
| AUTH-WEB-006 | The BFF's `return_to` MUST be a relative path on the app's own host, anything else sending the user to the app's home page. | The `return_to` values `https://example.net/`, `//example.net/` and `/\example.net/` each land on `/`. | Unit test | App | 3.7.2 |
| AUTH-WEB-007 | The BFF's sign-in MUST bind a single-use `state`, an S256 PKCE verifier and a `nonce`, each of at least 128 random bits, to the sign-in cookie; its callback MUST refuse a missing, mismatched, expired or reused `state`, and validate the ID token (signature, issuer, audience equal to the client ID, expiry and `nonce`) before using any claim. | Each faulty `state` and ID token in the contract tests is refused. | Unit test | App | 10.1.2, 10.2.1, 10.5.1, 10.5.4, 11.5.1 |

## 9. Clients, scopes and route gates

Clients are configuration (arch §4). Customer scopes are for the API
audience; workforce scopes are for the admin audience and also need the
`admin` role. Every user-facing client also asks for `openid` and
`offline_access`.

| ID | Requirement | Acceptance | Verification | Owner | ASVS |
|---|---|---|---|---|---|
| AUTH-CLIENT-011 | Clients MUST be registered from configuration per realm on every deploy with type (web or mobile), exact redirect URIs, only needed grants and scopes, their realm's audience and a first-party flag; dynamic registration MUST be off. | Deployed clients match `config/clients/<realm>.yaml` exactly, including types. | Configuration check | Operations | 10.4.1, 10.4.4, 10.4.11 |
| AUTH-CLIENT-002 | Every code flow MUST use PKCE with S256, and every confidential client MUST authenticate with `private_key_jwt` (ES256, the token URL as `aud`, a fresh `jti`); no client may hold a shared secret. | A token request with a client secret, or with an assertion whose `jti` was used before, is refused. | Integration suite | Provider configuration | 10.4.6, 10.4.10 |
| AUTH-CLIENT-003 | The web and admin BFFs MUST be confidential first-party clients of the customer and workforce realms, each redirecting only to its own host's callback and holding only the code and refresh grants and its realm's scopes. | Each BFF's registration lists one redirect URI, two grants and its realm's scopes. | Configuration check | Operations | |
| AUTH-CLIENT-012 | Mobile clients MUST use system-browser sign-in and settings, S256 PKCE and a claimed HTTPS redirect, never an embedded web view; keep refresh tokens and a random install ID in the platform keychain or keystore and access tokens in memory; serialize refresh and store the replacement before use; sign out through Shell then revoke and delete the refresh token; use continuation codes for fresh sign-in; and report install IDs in a signed-in request body just after sign-in. | Protocol tests prove PKCE, refresh reuse revocation, own-session sign-out, continuation and install-ID reporting against the real stack. Hands-on iOS and Android checks prove browser return, secure storage, rotation, sign-out and one device entry across fresh sign-in before mobile readiness. | Integration suite; hands-on check | App | 10.4.5, 14.2.1 |
| AUTH-CLIENT-007 | Our consent step MUST grant first-party clients `openid`, `offline_access` and their registered scopes at once, and refuse every other client until third-party consent exists ([README](../../README.md#planned-evolution)). | A first-party sign-in shows no consent screen, and a client without the first-party flag is refused. | Integration suite | App | 10.7.1 |
| AUTH-CLIENT-008 | Each client MUST trust exactly one issuer, set in configuration, and refuse discovery metadata, ID tokens and token responses naming another. | The BFF refuses an ID token from the other realm's issuer. | Unit test | App | 10.2.2, 10.5.3 |
| AUTH-SCOPE-001 | Every route MUST declare its scopes or be marked own-session, public or internal; startup MUST refuse a route that does none of these, and a token lacking a declared scope MUST get 403. An own-session route takes any valid user token and acts only on that token's session; Shell's one such route signs out the device in use for mobile apps. Shell's only public application routes are the BFF's sign-in, callback, refresh and sign-out, and our consent and sign-out steps, which the provider's challenge authenticates instead of a token. Passkey submissions forwarded through Shell follow arch §5. Hook routes and probes stay internal, the hooks behind a per-call secret (arch §1). | Startup fails with an undeclared route; a token without the route's scope gets 403; a token with no Shell scope signs out its own session and no other; and a consent or sign-out step without a valid challenge from the provider is refused. `hook-secret`: calls with a missing or wrong hook secret are refused (unit test). `hook-edge`: the public edge cannot reach a hook, even with its valid secret (integration suite). | Unit test; integration suite | App | 8.2.1, 10.3.2 |
| AUTH-SCOPE-002 | Account routes MUST act only on the caller's own account and take no account ID from the request. | No `/v1/account` route accepts an account ID, and no test user reaches another's data. | Unit test | App | 8.2.2 |
| AUTH-SCOPE-005 | Shell's scopes MUST be exactly these. Customer: `profile:read`, `profile:write`, `account:read` and `account:write`. Workforce: `users:read`, `users:write`, `sessions:read`, `sessions:revoke`, `audit:read`, `profile:read` and `profile:write`. Each grants only the actions the route catalogue lists for it. | A token lacking an action's catalogue scope gets 403 on that action, for every scoped row. | Unit test | App | 8.2.1 |
| AUTH-SCOPE-004 | The route catalogue MUST match the code: each implemented application route's scopes or access classification and gate are checked against it in CI, through the OpenAPI contract. Every catalogue route due by the current stage MUST exist. | Changing a route's window or scope without changing its catalogue row, adding an uncatalogued application route or omitting a route due now fails CI. | Unit test | App | |

**Route catalogue.** Gates follow section 6: "Fresh sign-in, N min" is a
fresh-sign-in gate with that window; "—" means no gate. Actions on the provider's settings screens run on the
provider's session, not a Shell scope. Internal routes and provider submission
forwarding are checked against their own access rules, outside the application
catalogue. Test-only routes are checked in test builds and absent from deployed builds.

| Action | Realm | Scope | Gate |
|---|---|---|---|
| Sign-in, callback, refresh | Customer | Public (BFF) | — |
| Consent and sign-out steps | Customer | Public (provider challenge) | — |
| Read one's profile (name, language, timezone) | Customer | `profile:read` | — |
| Change name, language or timezone | Customer | `profile:write` | — |
| Read settings: address, Google link, terms | Customer | `account:read` | — |
| Accept terms; change optional items | Customer | `account:write` | — |
| Link or unlink Google (provider's settings screen) | Customer | — | Fresh sign-in, 15 min, email code or Google |
| List "Where you're signed in" | Customer | `account:read` | — |
| Log out another device | Customer | `account:write` | Fresh sign-in, 15 min |
| Log out all devices | Customer | `account:write` | Fresh sign-in, 15 min |
| Sign out the device in use | Customer | Public (BFF) | — |
| Sign out the device in use (mobile apps) | Customer | None: own session | — |
| Report an app's install ID | Customer | `account:write` | — |
| Get a continuation code before signing in again (apps) | Customer | `account:write` | — |
| Hand back a continuation code after signing in again (apps) | Customer | `account:write` | — |
| Start deactivation (issues its challenge) | Customer | `account:write` | — |
| Confirm deactivation ("Are you sure?") | Customer | `account:write` | Fresh sign-in, every time, then within 5 min |
| Fresh-sign-in test route (test builds only) | Customer | `account:read` | Fresh sign-in, 15 min |
| Sign-in, callback, refresh | Workforce | Public (BFF) | — |
| Consent and sign-out steps | Workforce | Public (provider challenge) | — |
| Rename a passkey | Workforce | `profile:write` | — |
| List own passkeys (provider's settings screen) | Workforce | — | — |
| Add a passkey (provider's settings screen) | Workforce | — | Fresh sign-in, 5 min (passkey) |
| Remove a passkey, never the last (provider's settings screen) | Workforce | — | Fresh sign-in, 15 min (passkey) |
| List, search and view subscribers, with recent audit entries | Workforce | `users:read` | — |
| Create a subscriber; edit name, language or timezone | Workforce | `users:write` | — |
| Disable or enable a subscriber | Workforce | `users:write` | Fresh sign-in, 5 min (passkey) |
| View a subscriber's device list and grants | Workforce | `sessions:read` | — |
| End all of a subscriber's sessions and grants | Workforce | `sessions:revoke` | Fresh sign-in, 5 min (passkey) |
| Read audit entries | Workforce | `audit:read` | — |
| Data section: browse `users` | Workforce | `users:read` | — |
| Data section: browse `staff`, `tasks` and `audit_log` (read-only) | Workforce | `audit:read` | — |
| Data section: a fork's explicit resource | Workforce | The scopes it declares | The gate it declares |
| Read one's own staff record and devices | Workforce | `profile:read` | — |
| Log out another of one's own devices, or all | Workforce | `profile:write` | Fresh sign-in, 15 min (passkey) |
| Sign out the device in use | Workforce | Public (BFF) | — |

## 10. Staff and administration

| ID | Requirement | Acceptance | Verification | Owner | ASVS |
|---|---|---|---|---|---|
| AUTH-STAFF-001 | Staff MUST sign in only with passkeys; a session started with an enrollment code, which carries the recovery method, can only register passkeys, and AUTH-ADMIN-001 refuses it everywhere else. | An enrollment-code session registers a passkey and is refused on every admin route. | Unit test | App | 6.3.3 |
| AUTH-STAFF-002 | Only an operator, signed in to the cloud provider's IAM with MFA, MUST manage staff, through `scripts/provision_staff.py`; no page, the console included, can add, re-enroll or remove staff or change roles, and roles MUST reference staff only. | The admin API has no route that changes staff or roles, and the schema lets no role reference a subscriber. | Unit test | App | |
| AUTH-STAFF-003 | `add` MUST create the workforce identity and `staff` row with the `admin` role and print a one-time enrollment code, valid for 1 hour and good only for registering passkeys, which the operator hands over out of band and never by email. | A new staff member registers two passkeys with the code, which then fails, and no email contains it. | Integration suite | Operations | 6.4.1 |
| AUTH-STAFF-004 | `re-enroll` MUST run only after the operator has confirmed who is asking, in person or on a live video call with someone they recognise, reached through contact details already on record and never on the strength of the request alone. The script MUST require a note saying how, write it to the audit entry, remove the person's existing passkeys and end their sessions, then issue a new code as `add` does. | Without a note the script refuses, and afterwards the passkeys the script removed can't sign in. | Unit test | Operations | 6.4.4 |
| AUTH-STAFF-005 | `change-email` MUST replace a staff member's address and notify the old and new addresses. | After the command the provider holds the new address, and both addresses got the notice. | Integration suite | Operations | 6.3.7 |
| AUTH-STAFF-006 | `remove` MUST mark the staff row disabled, so the API refuses the person at once, then disable the identity and revoke its sessions and grants like a coordinated disable; the script MUST ask for explicit confirmation before removing one of the last two admins. | A removed admin's unexpired token gets 401 at once, and removing one of two admins asks for confirmation. | Integration suite | Operations | 7.4.2 |
| AUTH-STAFF-007 | Every command MUST write an audit entry naming the operator's cloud identity and notify every admin. | Each command leaves one audit entry and one notice per admin. | Unit test | Operations | |
| AUTH-STAFF-008 | Staff MUST have no self-service recovery: their addresses have no recovery role, so a recovery request for one sends nothing, and lost passkeys go through `re-enroll`. | A recovery request for a staff address sends no email. | Integration suite | Provider configuration | |
| AUTH-STAFF-009 | Every deployed workforce realm MUST keep at least two admins, each with at least two passkeys, and the console MUST remind staff with a single passkey to add another. The operations guide is to give each admin two security keys, kept apart, so losing a phone or laptop never leaves an admin without a passkey. | Before launch and after each `remove`, the provider's identity list shows two or more enabled admins with two or more passkeys each. | Configuration check | Operations | |
| AUTH-STAFF-010 | Break-glass: if no admin can sign in, an operator MUST re-enroll one admin under AUTH-STAFF-004; if no operator can reach the cloud account, the fork owner's emergency cloud identity (its own hardware MFA, credentials kept offline) is used, every use alerting all operators and admins and being reviewed afterwards. The procedure MUST be rehearsed before launch. | The rehearsal restores one admin from zero working passkeys, and the alert fires. | Hands-on check | Operations | |
| AUTH-STAFF-011 | The workforce realm MUST start empty, with no default or seeded admin; the first admin is added with `add`. | A fresh deployment's workforce realm holds no identity. | Configuration check | Operations | 6.3.2 |
| AUTH-STAFF-012 | The console MUST show staff their own "Where you're signed in", as AUTH-DEVICE-008 describes; logging out another of their devices, or all, needs a passkey sign-in within 15 minutes. | A staff member sees both of their sessions and logs out the other after a passkey sign-in. | Unit test | App | 7.5.2 |
| AUTH-ADMIN-001 | Every admin route MUST need a workforce token with the admin audience and the route's scope, a session signed in with a passkey, the `admin` role and the CSRF check; forks' `/v1/admin/<context>` routes sit behind the same guard. | A request missing any one of these, an enrollment-code session included, gets 401 or 403 and leaves an audit entry. | Unit test | App | 8.2.1 |
| AUTH-ADMIN-015 | Admins MUST list, search and view subscribers with recent audit entries and device lists; create them; edit name, language and timezone; disable or enable them; and end all their sessions and grants, but not one device's. No admin route may change subscriber addresses or staff. | Each capability works from the console; no route changes an address or staff record. | Unit test | App | 7.4.5 |
| AUTH-ADMIN-016 | Disabling or enabling a subscriber and ending their sessions MUST require a passkey sign-in within 5 minutes. These and all other destructive actions MUST require confirmation with a `confirm` field naming the target. | Disablement at 6 minutes gets 401 `auth.recent_sign_in_required`, `max_age=300`; a wrong `confirm` gets 422. | Unit test | App | 7.5.3, 8.4.2 To verify |
| AUTH-ADMIN-004 | Disabling MUST refuse the subscriber at once, then disable the identity and revoke its sessions and grants as a retried task (arch §9); enabling reverses it. | A disabled user's next request gets 401, and refresh fails once the task has run. | Integration suite | App | 7.4.2 |
| AUTH-ADMIN-006 | A subscriber created by an admin MUST start with an unverified address and complete the terms step at first sign-in. | The created account's first call before the terms gets 403 `auth.terms_required`. | Unit test | App | |
| AUTH-ADMIN-007 | Every admin request, reads included, MUST write an audit entry, as PIPA's access record. | Viewing one subscriber leaves one audit entry. | Unit test | App | 16.3.2 |
| AUTH-ADMIN-008 | The console MUST be its own app on the admin host, calling only Shell's admin routes, and the providers' admin APIs and database tools MUST be reachable only from the private network. | From outside and from the edge, metrics, PostgreSQL and Redis, provider admin paths don't answer; from outside, database ports don't answer; and `app.` serves no console code. | Configuration check | Operations | 3.5.4, 13.4.5 |
| AUTH-ADMIN-009 | Admin operations MUST NOT change cloud infrastructure: cloud consoles use the cloud provider's IAM with MFA, and the app runs with a least-privilege workload identity. | The app identity's policy allows no infrastructure change. | Configuration check | Operations | 13.2.2 |
| AUTH-ADMIN-017 | The React-admin Data section MUST use explicit admin API routes and standard components for each exposed resource's permitted list, search, view, add, edit and delete actions. Routes MUST use AUTH-ADMIN-001's guard, declared scopes and gates, use cases and auditing. No route may run user SQL, change schema, expose provider data or export. | A tested example resource has permitted pages and routes; guard, scopes, gates and audit tests pass; its catalogue rows are required; unsupported actions are refused. | Unit test | App | 8.2.1 |
| AUTH-ADMIN-018 | Each Data API route MUST explicitly allowlist response and writable fields; unlisted fields MUST never leave it, noneditable writes MUST fail, read-only resources MUST refuse writes and deletes MUST name the record in `confirm`. | An unlisted field never appears, noneditable writes get 422, read-only writes get 403 and a wrong delete confirmation gets 422. | Unit test | App | 8.2.3 To verify |
| AUTH-ADMIN-019 | The Data section MUST expose `users` with only name, language and timezone editable and no delete; `staff`, `tasks` and `audit_log` read-only. Disablement stays in support actions. Device records and known browsers appear only on account views; staff passkey labels only on staff views. | Exactly these four resources appear, none can disable or delete a subscriber or change staff, and account details remain restricted to their views. | Unit test | App |  |

## 11. Notifications and audit log

| ID | Requirement | Acceptance | Verification | Owner | ASVS |
|---|---|---|---|---|---|
| AUTH-NOTIFY-008 | Subscriber notices MUST cover only new-device sign-ins, Google links and unlinks, and support actions (disablement, enablement and ending sessions). Sign-up, profile changes, device sign-out and self-service deactivation send none. | Each listed event sends one notice; sign-up, all-device sign-out and self-service deactivation send none. | Integration suite | App | 6.3.5, 6.3.7 |
| AUTH-NOTIFY-002 | Our consent step MUST read the browser ID cookie (a random ID of at least 128 bits, set if missing), compare its hash with the account's known browsers and, when it's new, record it and send the new-device notice; the first sign-in of a new account records its browser without a notice. | A sign-in from a second browser sends the notice, the same browser after sign-out sends none, and a new account's first sign-in sends none. | Unit test; integration suite | App | 6.3.5 |
| AUTH-NOTIFY-003 | An app's install ID (AUTH-CLIENT-012) MUST decide its new-device notice: an unknown ID, or no known report within 10 minutes of the sign-in, sends it. | A reinstalled app's sign-in sends the notice, an app reporting a known ID within 10 minutes sends none, and one that never reports triggers it at 10 minutes. | Unit test | App | 6.3.5 |
| AUTH-NOTIFY-004 | Every operator command MUST notify every admin, and `change-email` also the old and new address; a staff member's passkey added or removed, and a sign-in to their account from a new device, MUST notify that staff member. | Adding a staff member notifies each existing admin, and a staff sign-in from a new browser notifies that staff member. | Unit test | Operations; app | 6.3.5, 6.3.7 |
| AUTH-NOTIFY-009 | Notices MUST state what happened, when in the recipient's language and timezone, device and IP, and what to do if unexpected: log out that device and secure the mailbox, or use the deployment contact address (the only route while disabled). Codes, tokens and sign-in links MUST NOT appear. | Every notice template renders those parts in English and Korean. | Unit test | App |  |
| AUTH-NOTIFY-006 | Notices MUST be queued as durable tasks in the change's own transaction, retried, and raise an alert if they finally fail; a failed notice never undoes its change. | With email down, the change completes and its notice is sent once email returns. | Unit test | App | |
| AUTH-NOTIFY-007 | Deployed environments MUST send from `no-reply@` on the deployment's own domain with SPF, DKIM and DMARC at `quarantine` or stricter, refuse to start with a Mailpit host, and alert on the relay's quota errors. | A DNS check of the sending domain passes, and startup with a Mailpit host fails. | Configuration check | Operations | |
| AUTH-AUDIT-006 | Every successful sign-up, sign-in or fresh sign-in (with method), sign-out, device revocation, account or staff-passkey action, terms acceptance, admin request or refusal and operator command MUST write an audit entry. Shell actions audit in the same transaction; consent audits sign-ins and provider report hooks audit sign-ups and settings changes. | Each listed action leaves exactly one entry despite retries; failed audit writes roll back Shell actions and lost sign-in reports lose no entry. | Unit test | App | 16.3.1, 16.3.3 |
| AUTH-AUDIT-002 | Each entry MUST hold the actor (realm and ID, an operator's cloud identity, or none), client ID, token ID (`jti`), action, target, outcome with its error code, correlation ID, IP, user agent and UTC time; addresses MUST appear only masked, and codes, tokens, secrets, keys, and browser and install IDs never. | A contract test checks every entry type's fields and finds no address, code, token or device ID in clear. | Unit test | App | 16.2.1, 16.2.2, 16.2.5 |
| AUTH-AUDIT-003 | Failed sign-in attempts MUST stay in the provider's logs and metrics, and Shell MUST log and count failed token checks, refused requests, refused gate checks and refresh reuse, with no audit entry apart from refused admin requests. | A wrong code shows in the provider's logs and metrics and nowhere in the audit log. | Configuration check | Operations | 16.3.1, 16.3.2 |
| AUTH-AUDIT-004 | The audit log MUST be append-only: the app's database role may only insert and read, and only the purge role deletes, and only entries past retention (arch §6). | As the app's role, updating or deleting an entry fails. | Configuration check | App | 16.4.2 |

## 12. Errors and privacy

| ID | Requirement | Acceptance | Verification | Owner | ASVS |
|---|---|---|---|---|---|
| AUTH-ERROR-001 | Shell's errors MUST be RFC 9457 Problem Details with a stable code and no internals (scheme: arch §10). | An unexpected exception returns 500 `internal.unexpected` with no stack trace or query. | Unit test | App | 16.5.1 |
| AUTH-ERROR-005 | A required fresh sign-in MUST return 401 `auth.recent_sign_in_required` with an RFC 9470 challenge carrying the route's `max_age` (0 for deactivation). Clients MUST share one sign-in-again handler across gated routes. | Each gated route returns its status, code and challenge, and the web client recovers without route-specific screens. | Unit test | App | 10.3.4 |
| AUTH-ERROR-003 | Shell's screens and routes MUST answer the same for addresses with and without an account, except to someone who has just proved control of the address (a code, or Google's verified answer). | The email step and Shell's routes answer identically for known and unknown addresses. | Integration suite | Sign-in screen | 6.3.8 |
| AUTH-ERROR-004 | The provider's code sign-in, which tells API callers when an address has no account, is an accepted risk slowed by the per-IP and per-address limits; the provider's experimental mitigation MUST stay off, and generic answers there are Later (arch §16). | A configuration check finds the mitigation off (Ory: Kratos's account-enumeration mitigation). | Configuration check | Provider configuration | 6.3.8 |
| AUTH-PRIVACY-001 | For each account, Shell MUST record every terms item accepted or declined and every notice shown, with its version and UTC time, keep the record while the account exists, and write an audit entry for each acceptance. | Accepting the terms stores item IDs, versions and times, plus an audit entry. | Unit test | App | |
| AUTH-PRIVACY-008 | Shell MUST hold no credentials or address copies. Personal fields are limited to Shell ID, provider identity ID and issuer, name, locale, timezone, terms and disable time; staff passkey labels; device records (sign-in ID, provider login-session ID, browser and platform, signed in and last active; no IP); known browsers (keyed hashes and first/last seen); and audit entries (arch §6). | The schema contains no other personal field in Shell tables. | Configuration check | App | 14.1.1 |
| AUTH-PRIVACY-009 | Device records MUST go when sessions end, known browsers after 400 days unseen, audit entries at their retention limit and backups as they age out (NFR-006). Deactivation MUST retain account data. | An ended session's device record and a browser unseen 400 days are gone; deactivation retains the disabled account. | Integration suite | App | |
| AUTH-PRIVACY-004 | Browser and install IDs MUST be random, stored only as hashes keyed per account, so one browser can't link two accounts, and never logged or sent in a URL. The privacy policy MUST name the browser ID, a security cookie that needs no consent (To verify per fork). | Two accounts signed in on one browser store different hashes, and no log line holds a browser or install ID. | Unit test | App | 14.2.1, 16.2.5 |
| AUTH-PRIVACY-010 | All personal-data stores, backups included, MUST run in the configured region; deployed startup MUST require a region. The fork's privacy policy MUST name the region, Google, email relay and browser ID, and accurately describe retention and deactivation. | Startup without `SHELL_REGION` outside development fails; launch review checks the policy against the deployment's actual data handling. | Configuration check | Operations |  |

## 13. Accessibility and internationalization

Mechanics are in arch §12.

| ID | Requirement | Acceptance | Verification | Owner | ASVS |
|---|---|---|---|---|---|
| AUTH-A11Y-002 | Sign-in, sign-up, sign-in-again, staff enrollment and passkey settings, terms, subscriber settings, device management and deactivation screens MUST meet WCAG 2.2 AA in English and Korean, code entry included. | Automated checks pass on every screen and pre-launch screen-reader review finds no AA failure. | Unit test; hands-on check | Sign-in screen; app |  |
| AUTH-I18N-001 | Every user-visible string, emails included, MUST come from a message catalogue; English and Korean MUST ship complete, with CI failing on a missing key, and a new language MUST need only catalogues and one configuration entry. | CI fails when a Korean key is removed. | Unit test | App | |
| AUTH-I18N-002 | The language MUST be the profile's `locale` (BCP 47) or, before sign-in, the screen's choice, then `Accept-Language`, then English; emails use the recipient's language. | A user whose profile is Korean gets Korean notices, and a first visit with `Accept-Language: ko` shows Korean. | Unit test | App | |
| AUTH-I18N-003 | Times MUST be stored and sent in UTC as ISO 8601 with an offset, and shown in the profile's `timezone` (IANA), emails included. | A new-device notice to a user in `Asia/Seoul` gives the sign-in time in Korean time. | Unit test | App | |
| AUTH-I18N-004 | Clients MUST translate errors by their stable code; the backend sends no interface text. | Every error code in the OpenAPI contract has an English and a Korean string. | Unit test | App | |

## 14. Non-functional requirements

Baseline only: RPO/RTO targets, SLO alerts, tracing and stronger internal
client authentication are Later ([README](../../README.md#planned-evolution)).

| ID | Requirement | Acceptance | Verification | Owner | ASVS |
|---|---|---|---|---|---|
| NFR-001 | Availability: sign-in and the API MUST run on at least two `api` replicas, so that one can fail without an outage. After launch, each deployment tracks availability from edge metrics against 99.5% of each month outside announced maintenance. | Stopping one replica during the load test fails only its in-flight requests. | Load test | Operations | |
| NFR-002 | Degradation: with the provider down, valid access tokens MUST keep working until they expire, refresh MUST answer 503 and keep the cookies, and signing in or signing in again MUST show the edge's "unavailable" page (arch §10). | With the provider stopped, an API call with a valid token succeeds and refresh returns 503. | Integration suite | App | 16.5.2 |
| NFR-022 | At NFR-005 load, server-side p95 MUST be at most 10 ms for token verification with subject and device lookup, 300 ms for refresh and 500 ms for each code, Google and staff passkey step. | Load-test p95 meets each target. | Load test | App |  |
| NFR-004 | Email: `EmailSender` MUST hand each code to the relay within 10 seconds of the request at p95. | The load test's code hand-over p95 is at most 10 seconds. | Load test | Operations | |
| NFR-005 | Capacity: on the default platform (one VM, two `api` replicas), Shell MUST sustain 5 sign-ins, 50 refreshes and 500 authenticated requests per second for 15 minutes with under 0.1% errors. | The pre-launch load test on the default platform (arch §15) meets these; each fork's deployment re-runs it on its chosen platform. | Load test | Operations | |
| NFR-006 | Backups: every database, the providers' included, MUST be backed up at least daily, with point-in-time recovery where offered, encrypted, in the region and kept 30 days; the provider's key-encryption secret belongs to the recovery kit. | Every database's last backup is less than 24 hours old. | Configuration check | Operations | |
| NFR-007 | Restore: one full restore of every database MUST be rehearsed before launch, recording how long it took. | After the rehearsal a restored account signs in, and the duration is recorded. | Hands-on check | Operations | |
| NFR-008 | Logs: every component MUST write JSON logs in UTC from synchronised clocks, Shell's with correlation ID, realm, user ID, route, status and duration (arch §13); application and edge logs are kept 30 days and shipped off the host to a store the app can write but not change. The inventory: provider logs (flows and failed sign-ins), Shell's logs, edge logs and the audit log (arch §6). | Every log line parses as JSON with a correlation ID, and the app identity can't delete shipped logs. | Configuration check | Operations | 16.1.1, 16.2.2, 16.4.3 |
| NFR-023 | Metrics MUST cover routes, provider calls, keys, refreshes, unexpected sign-outs, gate refusals, emails, limits and tasks; alerts MUST cover error rates, stale keys, failed tasks, email quota and a realm-wide rise in failed code entries (arch §13). | Each alert fires in a staged test. | Configuration check | Operations |  |
| NFR-010 | Privacy: logs and metrics MUST NOT contain addresses, codes, tokens, secrets, keys, or browser or install IDs; development and CI use synthetic data only, and a deployed environment starts empty. | A scan of the integration suite's logs, the edge's and both providers' included, finds none of these. | Unit test | App | 16.2.5 |
| NFR-011 | Supply chain: images MUST be pinned by digest and scanned on every CI build, a fixable high or critical finding failing CI; dependencies are locked with hashes; known vulnerabilities are fixed within 7 days if critical and 30 days if high. | CI fails on an image with a fixable critical finding. | Configuration check | Operations | 15.1.1, 15.2.1 |
| NFR-012 | Secrets: outside development, secrets MUST come only from the secrets manager, startup refusing any other source, and signing keys and other secrets MUST rotate as arch §13 sets out. | Startup outside development with a secret in `.env` fails. | Configuration check | Operations | 13.3.1 |
| NFR-013 | Probes: `/healthz` and `/readyz` MUST be reachable only internally, readiness covering the database, schema and keys (arch §13). | From outside neither path answers, and with keys missing readiness fails. | Configuration check | Operations | 13.4.5 |
| NFR-014 | Public TLS: outside development, every public host MUST answer only over TLS 1.2 or 1.3, preferring 1.3, with only recommended cipher suites and a publicly trusted certificate; plain HTTP MUST only redirect to HTTPS. | A TLS scan of every public host finds only TLS 1.2 and 1.3, recommended suites and a publicly trusted certificate, and a plain-HTTP request gets only a redirect. | Configuration check | Operations | 12.1.1, 12.1.2, 12.2.1, 12.2.2 |
| NFR-015 | Internal encryption: outside development, every connection between components MUST be encrypted, with no fallback to plaintext: TLS with a validated certificate to PostgreSQL, Redis, the email relay and managed services; and between Shell, the providers, the edge and metrics, TLS under the deployment's private CA, which clients trust only for internal hosts, or a declared platform that encrypts that traffic itself (arch §13). | Startup outside development fails on a database or Redis URL that skips certificate validation and, unless the platform's encryption is declared, on a plain-HTTP internal URL; with the private CA, no internal endpoint accepts plaintext. | Configuration check | Operations | 12.3.1, 12.3.2, 12.3.3, 12.3.4 |
| NFR-024 | CI MUST generate a standard component inventory (CycloneDX or SPDX SBOM) from each built image using existing build/scanning tooling, listing its third-party libraries and versions, including Python, JavaScript and OS packages. Sources MUST be verified against predefined trusted, maintained repositories in dependency and image configuration; keep the inventory with each image digest. No custom inventory system or additional service. | Each built image has its generated inventory; a missing inventory or unapproved source fails CI. | Configuration check | Operations | 15.1.2 |

## 15. Later

Project-wide items are in the README's
[Planned Evolution](../../README.md#planned-evolution), and items for the
mechanisms in arch §16. Specific to this file:

| Later | Trigger |
|---|---|
| Trusted devices and subscriber passkeys | A fork needs additional account protection |
| User-agent and service-agent clients | A fork needs agent access |
| Permanent account deletion, notifications, cooling-off, support cancellation or freeze, independent deletion audit storage and restore replay | A fork needs permanent deletion; deletion and lawful retention are launch prerequisites wherever applicable, not Shell completion prerequisites |
| CAPTCHA at sign-up and code requests | The realm-wide code cap or the failed-entry alert fires |
| Guardian consent for users under the minimum age | A fork targets children |
| Per-country sign-up terms and minimum ages: the user's country asked in the terms step, one item set per country with a default, and the country in the record | One set, at the strictest age, stops fitting the countries a fork serves |
| Security activity page | User demand |
| NIST AAL2 time limits for subscriber sessions (24 hours overall, 1 hour idle) | A fork needs AAL2 sessions |
| Notices of unusual sign-ins beyond new devices (a new country, many failed attempts) | Takeovers through email codes |
| A second address for notices | Mailbox takeovers go unnoticed |
| A cap on concurrent sessions | Account sharing, or per-seat pricing |
| Ending a single subscriber device from the console | Support needs it |
| Signing every subscriber out at once from the console | A breach response needs it faster than per-user revocation |
| Attestation and an authenticator allowlist for staff passkeys | Compliance asks for device-bound staff keys |
