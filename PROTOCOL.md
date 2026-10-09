# tavrn protocol (draft v1)

License: CC-BY-4.0 (this text; schemas, test vectors and permission tables Apache-2.0, see `LICENSE.md`). This document is the normative description of what nodes and clients may expect from
each other. The OpenAPI specification (`openapi.json`, generated from the server) describes the routes in
detail; this document covers the concepts and rules that span individual routes.

## 1. Identity and addresses

- **Nodes** are identified by their domain (`node.example`, always lowercase, no port), the **identity
  domain**. Its discovery document `https://<domain>/.well-known/tavrn` (§2) names where the node is served:
  by default `https://<domain>` itself, otherwise another host (**delegation**, e.g. identity `tavrn.org`,
  node at `https://app.tavrn.org`). All services (API, WebSocket, media signaling, web client, blobs) live
  under that one public base URL; identities, addresses, tokens and keys always use the identity domain.
- **Users**: `<username>@<domain>`. `username` is 2–32 characters of `[a-z0-9_.-]`, starts with a letter or
  digit, is immutable and unique on the home node. Display names are free text.
- **Applications (bots)** are users with `kind = "bot"` and an `owner` (user address), `APPLICATIONS.md`. `kind`
  takes `user`, `bot` or `webhook` (`APPLICATIONS.md` §6.1); clients treat every kind except `user` like `bot`
  (BOT badge, bot rules). `User` objects of bots carry `owner` (the owner's address) and `application_id` (the
  application ULID on the bot's home node, or the reference `<domain>/<ULID>` for bots of other nodes); both are
  null for users.
- **Rooms, channels, conversations, messages, blobs** have node-local ULIDs (26 characters, Crockford
  base32, time-sortable). They are globally unique combined with the node domain:
  `tavrn://node.example/rooms/01J…`, `tavrn://node.example/conversations/01J…`.
- **Devices** have a node-local ULID and their own key pair.

## 2. Discovery: `/.well-known/tavrn`

`GET https://<domain>/.well-known/tavrn` → `application/json`, cacheable for at least 5 minutes and at most 24 hours.

```json
{
  "tavrn": 1,
  "domain": "node.example",
  "name": "Example node",
  "description": "…",
  "api": "https://node.example/api/v1",
  "ws": "wss://node.example/api/v1/ws",
  "web": "https://node.example",
  "software": { "name": "tavrn-node", "version": "0.3.0" },
  "capabilities": ["content.v1", "e2ee.mls1", "voice", "screenshare", "forum", "federation"],
  "keys": [ { "kid": "2026-10-04", "alg": "EdDSA", "crv": "Ed25519", "x": "<base64url>" } ],
  "registration": "invite",
  "email": "optional",
  "policies": {
    "uploads_enabled": true,
    "upload_max_bytes": 26214400,
    "voice_enabled": true,
    "voice_max_bitrate_kbps": 96,
    "voice_max_participants": 50,
    "screenshare": { "enabled": true, "max_resolution": "1080p", "max_fps": 30 },
    "camera": { "enabled": true, "max_resolution": "720p", "max_fps": 30 }
  },
  "directory_listing": true,
  "webauthn": { "rp_id": "node.example" },
  "age": { "self_declared": true, "gates": ["adults_only"], "minimum_age": 16 }
}
```

- `tavrn` is the protocol major version. A client that does not know it must not connect.
- `age` (nodes announcing `age.v1`, §5e): how the node handles ages: `self_declared` (the date of birth is the
  user's own statement), the room and channel `gates` it enforces, and the `minimum_age` for registration.
- The voice policies (`voice_*`, `screenshare`, `camera`) and the voice API are specified in `VOICE.md`.
- Per-user and per-room limits above these policies (plans, grants, admin API tokens, attachment retention) are
  node-local and specified in `ENTITLEMENTS.md`; clients read their effective values from
  `GET /users/me/entitlements`, and an attachment whose file retention deleted is listed with `expired: true`.
- Files channels (channel kind `files`: folders and files instead of messages, end-to-end encrypted by default
  with `files.e2ee`, optional external WebDAV/S3 storage) are specified in `FILES.md`.
- `web` is the origin of the node's web client (`TAVRN_WEBAUTHN_ORIGIN`, default the public URL). The connect
  flow of `FEDERATION.md` §8 redirects to `<web>/connect`; native apps open the same page with an app session
  (`connect.app`).
- **Delegation**: `domain` is always the identity domain (`TAVRN_DOMAIN`); `api`, `ws` and `web` point to the
  host that serves the node (`TAVRN_PUBLIC_URL`, default `https://<domain>`), which may be any host:
  `{"domain": "tavrn.org", "api": "https://app.tavrn.org/api/v1", "ws": "wss://app.tavrn.org/api/v1/ws",
  "web": "https://app.tavrn.org"}`. The identity domain serves this document itself (a reverse-proxy rule to
  the node, or a static copy from `tavrn-node well-known` that must be refreshed whenever keys change); the
  node also serves it on its own host. A document whose `domain` differs from the queried domain is invalid
  (`federation.peer_invalid`); endpoints must be `https`/`wss` (plain `http`/`ws` only in development) and are
  subject to the same SSRF rules as the domain. Endpoints are cached together with the document (and its keys);
  a cached endpoint that fails at the transport level (or with `502`/`503`/`504`) is resolved again at once, at
  most once a minute per domain (`FEDERATION.md` §1.3).
- **Resolution order: well-known → SRV → direct domain** (`FEDERATION.md` §1.3 has the full decision table).
  An operator needs EITHER the document on the identity domain OR a `_tavrn._tcp.<domain>` SRV record:

  | `https://<domain>/.well-known/tavrn` | Next step | Result |
  |---|---|---|
  | `200`, valid, names `domain` | – | its endpoints |
  | `200`, invalid or another `domain` | – | `federation.peer_invalid` |
  | `404`, or no HTTPS server (refused, DNS, TLS, timeout) | SRV `_tavrn._tcp.<domain>` (`TAVRN_FEDERATION_SRV_FALLBACK`, default on): `https://<target>:<port>/.well-known/tavrn` | the target's endpoints; its document must name `domain` (else `federation.peer_invalid`) |
  | `404` and no usable SRV record | direct attempt, the last one | `https://<domain>/api/v1` |
  | no HTTPS server and no usable SRV record | – | `federation.peer_unreachable` |
  | any other status | – | `federation.peer_unreachable` |

  SRV targets: lowest priority first, then highest weight, at most 3; domain names only, vetted like any other
  host. Browsers cannot query SRV records: web clients fetch the well-known themselves and otherwise ask the
  node they were loaded from (`GET /federation/resolve/{domain}`), which runs this order for them, so SRV-only
  setups also work for the connect flow.
- `keys` lists all currently valid signing keys. Key rotation: a new key is added, the old one stays listed
  for at least 7 days.
- Other nodes cache a peer's keys for at most 1 hour and never verify with stale keys; an unknown `kid`
  triggers one refetch (`FEDERATION.md` §1.4).

## 3. Capabilities instead of version comparison

Nodes and clients announce a list of capability strings. A feature is used only when both sides list it.
The client sends its list in the WebSocket hello and in the header
`Tavrn-Client: <name>/<version> (<cap>, <cap>, …)`; the node stores it per device.

Reserved capabilities in v1: `content.v1`, `e2ee.mls1`, `voice`, `screenshare`, `forum`, `announcement`,
`threads`, `reactions`, `attachments`, `pins`, `emojis`, `gifs`, `federation`, `push.webpush`, `soundboard`,
`content.signed1`, `apps.v1`, `commands.v1`, `webhooks.v1` (`APPLICATIONS.md` §10.1; every node announces `apps.v1`
since phase 5 step 2 and `commands.v1` since step 3; clients announce `commands.v1` in their WebSocket `hello`), `sso.oidc` (single sign-on, §5a.6, announced while `TAVRN_OIDC_ISSUER` is set), `reports.v1` and `automod.v1`
(reports and auto-moderation, `MODERATION.md`, announced by every node that implements them), `connect.app` (app
sessions of the connect flow for native apps, `FEDERATION.md` §8 step 3, announced by every node that implements
them), `age.v1` (date of birth, private age status and age gates, §5e, announced by every node that implements it), `history.restore` (history restore after a key reset by request and approval, `ENCRYPTION.md` §7b, announced
by every node that implements it), `files.e2ee` (end-to-end encrypted files channels, `FILES.md` §8, announced by every node that implements
them).
Custom capabilities of third-party clients carry a reverse-domain prefix (for example `org.example.feature`).

`threads`, `forum` and `announcement` (threads, forum posts and announcement channels, §7e) are announced by every
node that implements §7e; `threads.client_ids` by every node that takes the client-chosen thread id of §7e (clients
send `id` only to those: an older node would ignore it, and the first message's signature would not match).

`voice` (voice channels, `VOICE.md`), `screenshare` (screen sharing allowed) and `soundboard` (room clips) are
announced by nodes while `TAVRN_VOICE_ENABLED` (and for `screenshare` also `TAVRN_SCREENSHARE_ENABLED`) is on.
`unfurl` (link previews for the node's own users, §7b) is announced while `TAVRN_UNFURL` is on. `webhooks.v1`
(incoming webhooks, event subscriptions, hook tokens and embeds, `APPLICATIONS.md` §6) is announced while
`TAVRN_WEBHOOKS_ENABLED` is on. `push.webpush` (web push to browsers, §6d) is announced while `TAVRN_PUSH` is on.

`content.signed1` is a client capability (FEDERATION.md §10.3): a client announcing it signs every plaintext
message it sends with its device key, and a node MAY then refuse unsigned plaintext messages of that device
(`400 message.signature_missing`). The reference web client signs best-effort (whenever the device has a
key) and does not announce it yet.

Compatibility rules:

1. Fields are never removed or reinterpreted. New fields are optional.
2. Unknown fields, event types and message types are ignored or shown as placeholders.
3. Breaking changes create `/api/v2` with at least 12 months of parallel operation.

## 4. API conventions

- Base `/api/v1`, JSON (UTF-8), timestamps as RFC 3339 in UTC, IDs as ULID strings.
- Authentication: `Authorization: Bearer <token>`. No cookies. CORS is open for all origins.
- Pagination: `?limit=50&before=<id>` or `?after=<id>`; the response contains `items` and `next`.
- Idempotency: an `Idempotency-Key` header on `POST` is stored for 24 hours.
- Rate limits respond with `429` and `Retry-After`.
- **Errors** are always RFC 9457 Problem Details, `Content-Type: application/problem+json`:

```json
{
  "type": "https://tavrn.dev/errors/upload.too_large",
  "title": "File too large",
  "status": 413,
  "detail": "This node allows at most 25 MB per file.",
  "code": "upload.too_large",
  "request_id": "01J…",
  "meta": { "max_bytes": 26214400 }
}
```

`code` is stable and machine-readable (`<area>.<error>`); `title`/`detail` are for humans and may be
localized (`Accept-Language`). Clients should map known codes to their own translations and fall back to `detail`.

### 4.1 Commands (client registry, design note 4.11)

Slash commands are a client feature on top of the normal API. Clients keep a **registry** of command definitions
in the shape of `APPLICATIONS.md` §5.1/§5.4, so that phase 5 application commands and built-ins share one format:

```json
{ "id": "", "name": "timeout", "description": "Time out a member",
  "args": [ { "name": "user", "description": "Member", "type": "user", "required": true },
            { "name": "duration", "description": "10m, 2h, 1d", "type": "string", "required": true },
            { "name": "reason", "description": "Reason", "type": "string", "required": false } ],
  "permission": "8192", "default_permissions": null, "dm_allowed": false, "source": "builtin" }
```

- `name` and arg names `^[a-z0-9_-]{1,32}$`; arg `type` one of `string`, `integer`, `number`, `boolean`, `user`,
  `channel`, `role`; optional `options` (choices), `min`/`max`, `max_length` as in `APPLICATIONS.md` §5.1.
- `permission`: the decimal mask the user must hold in the current channel; clients show only the commands that
  pass (built-ins: their own mask; applications: the node-computed mask of `GET /conversations/{id}/commands`).
- `source`: `builtin` (executed by the client through the normal routes: kick, ban, timeout, voice mute and move,
  purge with its preview and confirmation, slowmode, topic, nickname, …) or `app`.
- Built-ins of the reference client: `/kick`, `/ban`, `/timeout`, `/mute`, `/unmute`, `/move`, `/purge`,
  `/slowmode`, `/topic`, `/nick`, `/me` (content type `action`, §7), `/shrug`, `/whiteboard`, `/poll` (reserved
  until phase 5), `/help`. Destructive ones (kick, ban, purge) ask for confirmation.

**Announce flow for applications (phase 5, `commands.v1`, normative in `APPLICATIONS.md` §5).** An application
announces its commands to its home node (`PUT /applications/{id}/commands`, or `/applications/me/commands` with an
app token); nodes optionally require admin approval of each definition hash; room managers enable, restrict or
disable commands per room and channel; clients fetch the invocable ones with `GET
/conversations/{conversation_id}/commands`, merge them after their built-ins (name clashes qualified by the
application name, selection bound to the command id) and invoke them with `POST
/conversations/{conversation_id}/interactions`. The reference client (implemented in phase 5 step 3) announces
`commands.v1` in its WebSocket `hello`, shows the BOT badge and the application's name on application commands,
offers `options` as a pick list (and `true`/`false` for booleans), sends `user` arguments as addresses and
`channel`/`role` arguments as ids, encrypts the arguments in encrypted conversations (`command.args`, §7) and shows
replies, ephemeral replies ("only you can see this", dropped on reload), "… is thinking" for deferred interactions
and error notices. A node without `commands.v1` gets no palette request; the client then offers built-ins only.

## 5. Tokens

All tokens are JWTs with `alg = EdDSA` (Ed25519). The kinds are distinguished by `typ`:

| `typ` | Issuer | Purpose | Lifetime |
|---|---|---|---|
| `session` | the node holding the session | access to this node (home or foreign node) | `TAVRN_SESSION_ACCESS_MINUTES` (default 60 min); refresh token sliding `TAVRN_SESSION_REFRESH_DAYS` (default 90 days) per device (§5b) |
| `preauth` | home node | password accepted, second factor pending (§5a); opens only the enrollment and verification routes | 10 min, single use |
| `federation` | home node | proof of "I am alice@home" towards a foreign node | 10 min |
| `s2s` | a node | signed server-to-server request | 5 min |
| `app` | home node | long-lived token of an application (bot) with scopes, bound to one bot device (`APPLICATIONS.md` §2.1) | ≤ `TAVRN_APP_TOKEN_MAX_DAYS` (default 365 days), revocable; rotation with 24 h overlap |
| `devnonce` | a node | single-use login nonce for a device proof (§5b) | 5 min, single use |
| `reauth` | home node | proof of a fresh re-authentication for sensitive changes, bound to one session (§5c) | 5 min |
| `hook` | a node | signature of a request the node sends to an application's URL (`Tavrn-Signature` header, `APPLICATIONS.md` §6.3) | ≤ 5 min |

Claims of the `federation` token: `iss` (home domain), `sub` (`alice@home`), `aud` (target domain),
`exp`, `iat`, `jti`, `device` (device ID), `kind` (`user`/`bot`), and for bots `owner`, `app` (application ULID)
and `scopes` (the effective scopes; absent from older home nodes = all scopes).

Claims of the `app` token: `iss` = `aud` (home domain), `sub` (bot user ULID), `typ = "app"`, `iat`, `exp`, `jti`,
`dev` (bot device), `app` (application ULID), `owner` (owner address), `scp` (scopes). The node stores only
`SHA-256(token)` and checks every use against it; the app token is accepted wherever a session token is, but a
bot's request must pass the route table and scopes of `APPLICATIONS.md` §2.5 (`403 app.bot_forbidden`,
`403 app.scope_missing`).

The foreign node verifies: signature against a key from the `.well-known` of `iss` (cached per `kid`, reloaded
once on an unknown `kid`), `aud` equals its own domain, `exp`, `jti` not reused, domain and user not blocked.
It then issues its own `session` token.

`s2s` tokens carry `iss`, `aud`, `exp`, `jti` and `body_sha256` (base64url of the request body).

`hook` tokens carry `iss` = `sub` (the node's domain), `aud = "app:<application id>"`, `typ = "hook"`, `iat`, `exp`
(`exp − iat ≤ 300`), `jti` (a ULID per attempt), `htu` (the exact target URL) and `body_sha256` (base64url SHA-256 of
the exact body). Applications verify them against the keys of the node's `.well-known` (cached at most one hour,
refetched once for an unknown `kid`): `typ`, `aud`, `iat` within ±5 minutes, `exp`, `htu`, the body hash before
parsing the body, and `jti` unseen until `exp` + 5 minutes (`verifyHookRequest()` of `@tavrn/sdk`).

## 5a. Authentication and the second factor

Every password account has a second factor (design note 4.2a): TOTP (RFC 6238) or WebAuthn (passkeys,
security keys). Operators cannot switch this off. Bots have no password login (app tokens) and SSO
logins are authenticated by the identity provider (§5a.6); both are exempt. Passwords are sent as typed
(over TLS) and hashed with Argon2id on the node.

### 5a.1 States

```
                 password ok, no factor                    first factor confirmed
 POST /auth/login ─────────────────────► enrollment_required ───────────────────────┐
 POST /auth/register ──────────────────►  (pre-auth, stage enroll)                  ▼
                 password ok, has factor                     factor verified      session
 POST /auth/login ─────────────────────► second_factor_required ───────────────► (status ok)
                                          (pre-auth, stage verify)                  ▲
 POST /auth/webauthn/login/* without pre-auth token (discoverable passkey + UV) ────┘
```

A **pre-auth token** (`typ = "preauth"`, claims `sub` = user id, `stage` = `enroll` | `verify`, `dn` =
device name, `jti`) is valid for 10 minutes and completes exactly one login; the node records its
`jti` when the session is issued. It is accepted only by the routes in §5a.3; every other route
answers `401 auth.second_factor_required` (the WebSocket closes with `4001`). A stage `verify` token cannot
enroll factors (`401 auth.second_factor_required`), a stage `enroll` token cannot verify (`401
auth.preauth_invalid`), and a stage `enroll` token stops working as soon as the account has a factor
(`401 auth.preauth_invalid`), so a second party that knows the password cannot add its own factor
after the owner enrolled. The device and its session are created only when the session is issued.

Responses of the password step (`POST /auth/login` → `200`, `POST /auth/register` → `201`):

```json
{ "status": "enrollment_required", "preauth_token": "<jwt>", "methods": ["totp", "webauthn"], "expires_in": 600 }
{ "status": "second_factor_required", "preauth_token": "<jwt>", "methods": ["totp", "webauthn", "recovery_code"], "expires_in": 600 }
```

For `second_factor_required`, `methods` lists what the account has. A session response:

```json
{ "status": "ok", "user": { …UserPrivate }, "access_token": "<jwt>", "refresh_token": "…", "expires_in": 3600,
  "device_id": "01J…", "recovery_code_used": false }
```

Sessions that existed before the second factor became mandatory were revoked by the upgrade; accounts
without a factor land in `enrollment_required` at their next login.

### 5a.2 TOTP and recovery codes

- TOTP: SHA-1, 6 digits, 30-second steps, ±1 step tolerance, 160-bit secret. A code is accepted once per
  account (the node stores the step of the last accepted code and only accepts newer steps). The secret
  is stored encrypted with a key derived from the node's at-rest secret (reference node:
  `<data_dir>/keys/secrets.key`, `HKDF-SHA256(info = "tavrn totp at rest v1")`, AAD = user id).
- Recovery codes: ten single-use codes `xxxx-xxxx-xxxx` (Crockford base32 lower case, 60 bits each;
  case, spaces and dashes are ignored on input), shown once when the **first** factor is enrolled and
  when they are regenerated (which invalidates the old set). Stored as salted SHA-256 hashes. Using one
  is audited and the response carries `recovery_code_used: true`; clients then suggest new codes or a
  new factor.
- Rate limits for every second-factor attempt (TOTP, recovery code, WebAuthn assertion, TOTP
  confirmation): 5 per 5 minutes per account and 20 per 5 minutes per client IP (`429`, `Retry-After`).
  Wrong codes of every kind fail with the same `401 auth.second_factor_invalid`.

### 5a.3 Routes

`Bearer` = `Authorization: Bearer <token>`; "session or enroll" = a full session or a pre-auth token in
stage `enroll`. Bodies are JSON; errors are Problem Details (§4) with the codes listed.

| Route | Auth | Body → response | Errors |
|---|---|---|---|
| `POST /auth/login` | – | `{ username, password, device_name?, captcha_token?, device? }` → pre-auth response (`device`: device proof, §5b) | `401 auth.invalid_credentials`, `401 auth.account_disabled`, `403 auth.email_unverified`, `429` |
| `POST /auth/register` | – | (unchanged request) → `201` pre-auth response, stage `enroll` | as before |
| `POST /auth/second-factor/verify` | pre-auth token in body (stage `verify`) | `{ preauth_token, totp_code? , recovery_code? }` → session | `400 auth.second_factor_missing`, `401 auth.preauth_invalid`, `401 auth.second_factor_invalid`, `429` |
| `POST /auth/totp/enroll` | Bearer: session or enroll | – → `{ secret (base32), otpauth_url, issuer }` | `401 auth.second_factor_required`, `401 auth.preauth_invalid`, `409 auth.totp_exists` |
| `POST /auth/totp/confirm` | Bearer: session or enroll | `{ code }` → `{ recovery_codes: [10] \| null, session: <session> \| null }` (session only with a pre-auth token) | `401 auth.second_factor_invalid`, `404 auth.totp_not_found`, `409 auth.totp_exists`, `429` |
| `DELETE /auth/totp` | Bearer: session | `{ code? , password? }` → `204` (without the password: a reauth token and a current code, §5c) | `400 auth.proof_required`, `401 auth.invalid_credentials`, `401 auth.second_factor_invalid`, `404 auth.totp_not_found`, `409 auth.last_factor` |
| `GET /auth/factors` | Bearer: session | → `{ totp: bool, webauthn: [credential], recovery_codes_left: n }` | |
| `POST /auth/recovery-codes/regenerate` | Bearer: session | `{ password }` (or a reauth token, §5c) → `{ recovery_codes: [10] }` | `401 auth.invalid_credentials`, `429` |
| `POST /auth/webauthn/register/start` | Bearer: session or enroll | – → `{ challenge_id, options }` | `409 webauthn.limit` (10 credentials) |
| `POST /auth/webauthn/register/finish` | Bearer: session or enroll | `{ challenge_id, name (1–64), response }` → `{ credential, recovery_codes, session }` | `400 validation.*`, `400 webauthn.challenge_invalid`, `400 webauthn.registration_failed`, `400 webauthn.prf_output_sent`, `409 webauthn.limit`, `409 webauthn.credential_exists`, `413 request.too_large` |
| `GET /auth/webauthn/credentials` | Bearer: session | → `[credential]` | |
| `DELETE /auth/webauthn/credentials/{credential_id}` | Bearer: session | → `204` (also deletes its secret storage entry) | `404 webauthn.not_found`, `409 auth.last_factor` |
| `POST /admin/users/{user_id}/second-factor/reset` | Bearer: session of a node admin | – → `204`: removes TOTP, all WebAuthn credentials (and their passkey secret storage entries) and recovery codes, revokes all sessions; the `recovery` entry stays; audited as `admin.second_factor_reset` | `403 auth.node_admin_required`, `404 user.not_found`, `409 admin.second_factor_self` |
| `POST /auth/webauthn/login/start` | – | `{ preauth_token? }` → `{ challenge_id, options }` | `400 webauthn.no_credentials`, `401 auth.preauth_invalid`, `429` |
| `POST /auth/webauthn/login/finish` | – | `{ challenge_id, response, preauth_token?, device_name?, device? }` → session | `400 webauthn.challenge_invalid`, `400 webauthn.response_invalid`, `400 webauthn.prf_output_sent`, `401 auth.second_factor_invalid`, `401 auth.invalid_credentials`, `401 webauthn.counter_mismatch`, `401 auth.account_disabled`, `403 auth.email_unverified`, `429` |

A credential is `{ id (base64url credential id), name, created_at, last_used_at, prf_supported }`.
Secret storage routes: `ENCRYPTION.md` §2.4.

### 5a.4 WebAuthn

- Relying party id = `TAVRN_WEBAUTHN_RP_ID`, default the identity domain; origin = the public URL
  (`TAVRN_WEBAUTHN_ORIGIN` overrides it for development). The relying party id must be the origin's host or a
  registrable parent domain of it (WebAuthn rule; the node refuses to start otherwise), so with delegation
  (`tavrn.org` served at `app.tavrn.org`) passkeys stay bound to `tavrn.org` and survive a move of the app host. Attestation `none`, user verification **required** (the webauthn-rs passkey policy;
  security keys need a PIN), resident key preferred, algorithms as listed in `pubKeyCredParams`.
- The node publishes its relying party id as `webauthn.rp_id` in `GET /api/v1/node` and in
  `/.well-known/tavrn`. Clients that build an assertion themselves (the local secret storage PRF evaluation,
  `ENCRYPTION.md` §2.4, which never involves the node) MUST pass it as `rpId`: without it the browser uses the
  page's host, which differs from the relying party id under delegation, and the assertion fails.
- `options` is the JSON form of `PublicKeyCredentialCreationOptions` / `…RequestOptions` wrapped in
  `{ "publicKey": … }` with binary values in base64url, suitable for
  `PublicKeyCredential.parseCreationOptionsFromJSON` / `parseRequestOptionsFromJSON`. The node adds
  `extensions.prf.eval.first` (the secret storage PRF input, `ENCRYPTION.md` §2.4). `response` is
  `PublicKeyCredential.toJSON()`; clients MUST remove `clientExtensionResults.prf.results` first.
  `clientExtensionResults.prf.enabled` at registration sets `prf_supported`.
- Challenges are stored on the node, expire after 5 minutes and are consumed by the first finish
  attempt, successful or not. A second-factor challenge belongs to the user of the pre-auth token it
  was started with.
- `login/start` with a pre-auth token (stage `verify`) returns the user's credentials as
  `allowCredentials` (second factor). Without it, the request is for a **passkey-only login**: no
  allow-list, the authenticator chooses a discoverable credential and returns the user handle (the
  user's 16-byte ULID). Passkey-only logins require user verification and count as two factors.
  Clients MAY add `mediation: "conditional"` for autofill UI.
- Signature counters: if the counter of a credential does not increase, the assertion is refused with
  `401 webauthn.counter_mismatch` and audited (possibly cloned authenticator).
- Up to 10 credentials per account, each with a user-chosen name; each can be removed unless it is the
  account's last factor.

### 5a.5 Client flows

- **Registration**: `POST /auth/register` (with the `date_of_birth`, §5e) → pre-auth (enroll) → enroll TOTP (`totp/enroll`, show QR code
  of `otpauth_url` and the base32 secret, `totp/confirm` with a code) **or** a passkey
  (`webauthn/register/start`, `navigator.credentials.create`, `webauthn/register/finish`) → the
  response carries the session and the recovery codes (show once, user confirms) → end-to-end
  encryption setup: recovery key, master secret, identity key, wrapped copy, device attestation
  (`ENCRYPTION.md` §2.4 flow 1) → usable.
- **Login**: `POST /auth/login` → `second_factor_required` → TOTP or recovery code
  (`second-factor/verify`) or passkey (`webauthn/login/start` with the pre-auth token, `get()`,
  `webauthn/login/finish` with it) → session. `enrollment_required` → enrollment as at registration.
  On a device without the master secret: unlock it from the secret storage (`ENCRYPTION.md` §2.4 flow 2).
- **Passkey-only login**: `webauthn/login/start {}` → `get()` (with the PRF input, so the same ceremony
  can unlock the secret storage) → `webauthn/login/finish { challenge_id, response, device_name }` →
  session.
- **Managing factors** (settings, full session): `GET /auth/factors`; add TOTP or passkeys as above
  with the session token (no new session, `recovery_codes` is null unless the account had none);
  remove them (`DELETE …`, never the last one); regenerate recovery codes with the password.
- **Locked out** (no factor, no recovery code left): a node admin resets the second factor
  (`POST /admin/users/{user_id}/second-factor/reset`); the next login lands in `enrollment_required`
  and the user enrolls again. The master secret is unlocked with the recovery key as usual.
- **Password change and password reset** do not touch factors or the secret storage; a password reset
  by email still requires the second factor at the next login.

### 5a.6 Single sign-on (OpenID Connect)

Normative: `APPLICATIONS.md` §8 (capability `sso.oidc`). A node with `TAVRN_OIDC_ISSUER` announces `sso.oidc`, and
`GET /node` carries `sso: { label, only } | null` (`label` null = the client's own "Sign in with SSO").

| Route | Auth | Body → response | Errors |
|---|---|---|---|
| `POST /auth/oidc/start` | – (`login`); Bearer: session of a local user (`link`, `reauth`) | `{ purpose: "login" \| "link" \| "reauth", code_challenge (S256), client_state (16–128 of [A-Za-z0-9_-]), device_name? }` → `{ authorization_url, expires_in: 600 }` | `400 validation.code_challenge`, `400 validation.client_state`, `401 auth.required`, `403 federation.local_only`, `404 sso.disabled`, `409 sso.already_linked` (link), `409 sso.not_linked` (reauth), `429`, `502 sso.idp_unreachable` |
| `GET /auth/oidc/callback` | – (the provider's redirect) | `?code&state` or `?error&state` → always `303 <web>/sso/callback?code=…&state=<client_state>` or `?error=<code>[&idp_error=…]&state=…`, `Cache-Control: no-store` | redirected: `sso.state_invalid`, `sso.idp_error`, `sso.idp_unreachable`, `sso.token_invalid` |
| `POST /auth/oidc/token` | – (`login`); Bearer: the session that started `link`/`reauth` | `{ code, code_verifier }` → session response (§5a.1, `status: "ok"`, no second factor) \| `{ linked: true }` \| `{ reauth_token, expires_in: 300 }` | `400 sso.code_invalid`, `401 auth.account_disabled`, `403 sso.not_provisioned`, `403 sso.email_unverified`, `403 sso.session_mismatch`, `403 sso.identity_mismatch` (reauth), `409 sso.identity_linked`, `409 sso.already_linked`, `429` |
| `GET /auth/oidc/identity` | Bearer: session (local) | → `{ issuer, linked_at, last_login_at } \| null` | `404 sso.disabled` |
| `DELETE /auth/oidc/identity` | Bearer: session (local) | → `204` | `409 sso.not_linked`, `409 sso.last_login_method` |
| `GET` / `PUT /admin/sso/group-map` | Bearer: node admin | `{ map }` → `{ map, fixed, sync }` | `400 sso.group_map_invalid`, `403 auth.node_admin_required`, `409 sso.group_map_fixed` |

- Codes and state are single use; the one-time code lives 60 s and is bound to the start request's
  `code_challenge`. The account is resolved, provisioned or linked, and the group map applied, only at the
  exchange, so a callback URL replayed in another browser has no effect.
- SSO sessions end at the latest after `TAVRN_OIDC_SESSION_DAYS` (`max_expires_at`). `POST /auth/logout` of an
  SSO session answers `200 { end_session_url }` when the provider has an end-session endpoint (otherwise `204`
  as before); clients offer "also sign out at the provider".
- `UserPrivate.has_password` is `false` for SSO-only accounts: they cannot set a password
  (`409 sso.password_unavailable` at `POST /users/me/password` and the password reset) and confirm an identity
  reset with a `reauth_token` (`ENCRYPTION.md` §9).
- With `TAVRN_OIDC_ONLY`, `POST /auth/register`, `POST /auth/login` and passkey-only logins
  (`POST /auth/webauthn/login/finish` without pre-auth token) answer `403 auth.password_login_disabled`,
  except for the usernames in `TAVRN_ADMIN_USERS` (break-glass).

## 5b. Sessions, refresh and devices

**Refresh.** `POST /auth/refresh { refresh_token }` → token pair. Refresh tokens are random, stored only as SHA-256
hashes, and rotate on every use; the session's lifetime slides by `TAVRN_SESSION_REFRESH_DAYS` with every refresh
(SSO sessions keep `TAVRN_OIDC_SESSION_DAYS`, federated sessions their 7 days as hard end). The rotation is atomic
(`UPDATE … WHERE id = ? AND refresh_token_hash = <presented>`). The new refresh token is derived from the presented
one with a node secret (`HKDF-SHA256(secrets.key, "tavrn refresh rotation v1\0" || token)`), so parallel refreshes
with the same token all get the same pair. Presenting the **immediately previous** token within **30 seconds** of
its rotation answers with the current pair as well (two tabs, a request in flight); later, or an older token, is
treated as theft: the previous token revokes the session (`401 auth.refresh_invalid`), older ones are refused. The
grace never yields a newer token than the current one, so a stolen token gains nothing beyond those 30 seconds.
A refresh also counts as "seen" for the device (`last_seen_at`).

**Clients** run one refresh at a time per node and session, coordinated across tabs (Web Locks plus the shared
storage: a tab adopts tokens another tab stored instead of refreshing again). Only a definitive answer to the
refresh itself (`400`/`401`) ends the session; network errors, `429` and `5xx` keep it (requests fail, the UI stays
usable, a later request tries again). The WebSocket closes with `4001` and the error code as reason
(`auth.token_expired`, `auth.token_invalid`, …); clients refresh once (shared with the API client) and reconnect,
and give up only when the refresh is refused or `4001` repeats right after a refresh.

**Device proof.** A login normally creates a new device. `POST /auth/device-nonce` → `{ nonce, expires_in }` gives a
single-use nonce (a short JWT `typ = devnonce`, 5 minutes); a client that still holds the keys of one of the
account's devices sends `device: { id, nonce, proof }` with `POST /auth/login`, `POST /auth/webauthn/login/finish`
(passkey-only) or `POST /auth/oidc/token` (login), where `proof` is the Ed25519 signature of the device key over
`"tavrn device login v1\0" || str16(device_id) || str16(user_address) || str16(nonce)` (`ENCRYPTION.md` §3.4).
The node spends the nonce, checks that the device is a local device **of the authenticated user** with a key attested
under the current identity key, and verifies the signature; the new session then continues that device (its other
sessions end). Any failure silently means a new device, as before; a proof never makes a login fail. The password
flow carries the proven device inside the pre-auth token (`rd` claim) to the session issued after the second factor.

**Devices.** `GET /users/me/devices` → `[{ id, name, client, created_at, last_seen_at, current, stale, stale_at }]`
(`stale`: not seen for half of `TAVRN_DEVICE_STALE_DAYS`; `stale_at`: when housekeeping deletes it). Housekeeping
deletes devices not seen for `TAVRN_DEVICE_STALE_DAYS` (default 180, `0` = never), never the only device of a
user and never one with a live session. `POST /auth/logout?forget_device=true` (the client deleted its keys) also
deletes the device. Deleting a device keeps its attested key as **retired** (`ENCRYPTION.md` §2.3) and records its
MLS leaves as pending removals (`ENCRYPTION.md` §4.7).

| Route | Auth | Body → response | Errors |
|---|---|---|---|
| `POST /auth/device-nonce` | – | → `{ nonce, expires_in }` | `429` |
| `POST /auth/logout?forget_device=true` | Bearer | → `204` / `200 { end_session_url }` | |
| `GET /conversations/{id}/mls/pending-removals` | Bearer (member) | → `{ items: [{ conversation_id, identity, reason, created_at }] }` (`reason`: `deleted`, `unattested`, `not_member`; only leaves still in the group) | `403`, `404` |
| `GET /mls/pending-removals` | Bearer | → the same list for the caller's own leaves in every conversation of this node | |
| `POST /users/me/devices/retired` | Bearer | `{ device_id, public_key, identity_signature }` → `204` (re-attest a deleted own device from its leaf key, `ENCRYPTION.md` §5.2) | `400 e2ee.attestation_invalid`, `409 device.active`, `409 device.retired_conflict`, `409 e2ee.identity_missing` |

Development nodes (`--dev`) also have `POST /dev/expire-access-tokens` (every access token issued so far counts as
expired) for the end-to-end tests of these paths; production nodes do not route it.

## 5c. Re-authentication for sensitive changes ("sudo mode")

A session alone does not allow changes that would let a thief lock the owner out or replace their keys. These need
a **reauth token** from the last five minutes in the `Tavrn-Reauth` header: deleting a device, adding or removing
passkeys and their secret storage entries, enrolling TOTP with a session, replacing the recovery key entry
(`PUT /users/me/secret-storage/recovery` when one exists) and the identity reset. `DELETE /auth/totp` and
`POST /auth/recovery-codes/regenerate` accept the password in the body as before or a reauth token; the password
change keeps asking for the current password. The identity key rotation (`POST /users/me/identity/rotate`,
`ENCRYPTION.md` §9a) needs the header as well. Without a valid token the routes answer
`403 auth.reauth_required` with `meta.methods` (`password`, `webauthn`, `sso`).

- Every login response (`AuthResponse.reauth_token`) carries one: the login was a fresh proof. Clients keep it in
  memory only.
- `POST /auth/reauth { password }` or `{ challenge_id, response }` (an assertion of `POST /auth/reauth/webauthn/start`)
  → `{ reauth_token, expires_in }`; a wrong proof is `403 auth.reauth_failed` (never `401`: the session is fine).
- SSO accounts re-run the provider login (`POST /auth/oidc/start`, purpose `reauth`); the exchange returns the same
  kind of token.

The token is a JWT `typ = reauth` with `sub`, `dev` and `sid` (the session); it is valid for five minutes, for any
number of requests of that session only, and dies with the session. Clients answer `auth.reauth_required` with a
confirmation dialog and repeat the request once.

## 5d. Legal pages, terms and data rights (design note 4.14)

The full description is `LEGAL.md`; the parts every client needs:

- `GET /node` carries `legal: { notices: { enabled, contact }, pages: { imprint, privacy, terms, cookies }, terms_mode }`.
  `contact` is `{ name, address, email }` or null; every page is `{ version, published_at, url }` or null.
  `terms_mode` is `notice` or `require` (`TAVRN_LEGAL_TERMS_MODE`).
- `GET /legal/pages` and `GET /legal/pages/{kind}` (public) serve the documents (`markdown`, sanitized `html`,
  `version`, `lang`); `/legal/{kind}` outside `/api/v1` is the same document as a standalone HTML page.
- Registration sends `accept_terms: <version>` when the node publishes terms; anything else is
  `400 legal.terms_not_accepted` (`meta.version`). `GET /users/me/terms` →
  `{ current_version, accepted_version, accepted_at, pending, mode }`; `POST /users/me/terms/accept { version }`
  (`409 legal.terms_version_mismatch` for an outdated version). Clients show the acceptance dialog once per version
  while `pending`. With `mode = require` the node answers `403 legal.terms_required` (`meta.version`) on every
  authenticated route except the terms routes, `POST /auth/logout` and `/legal/*`, and closes WebSockets with `4002`
  and the reason `legal.terms_required`, until the user accepted.
- `GET /users/me/data` (summary), `GET /users/me/export` (JSON archive, reauth token) and `DELETE /users/me`
  (`{ confirm: <username>, delete_messages }`, reauth token) are the data rights; a deleted account's messages carry
  `author_deleted: true` and `author` is the tombstone address `deleted-<hex>@<domain>`. Clients show "Deleted user"
  without avatar, profile or link, and `{"type":"system.deleted"}` content as "message deleted". A deleted account's
  password login answers `401 auth.account_deleted`.

## 5e. Date of birth, age status and age gates (`age.v1`)

Every node that implements this section announces `age.v1`; `GET /node` and the discovery document (§2) carry
`age: { self_declared: true, gates: ["adults_only"], minimum_age }`. This is the self-declared slice of the age
design: the date of birth is the user's own statement, never a verification, and the node uses it only for its
minimum age and for the age gates below.

**Date of birth at registration.** `POST /auth/register` requires `date_of_birth`, an ISO 8601 calendar date
`YYYY-MM-DD`, on every registration path (password and passkey registration both start there; clients that
register for a native app on the connect page send it the same way). The node checks it before anything is
stored:

| Check | Error |
|---|---|
| missing, not `YYYY-MM-DD`, not a real calendar date, after today (UTC) or before `1900-01-01` | `400 validation.date_of_birth` |
| the age on today's UTC date is below the node's `minimum_age` (`TAVRN_MINIMUM_AGE`, default 16, 13–99) | `403 age.below_minimum` with `meta.minimum_age`; the detail names the minimum ("You must be at least 16 years old to register on this node") |

The age is counted in whole years: a person is `n` years old from the `n`th birthday on; a birthday on 29 February
counts on 1 March in common years.

**Accounts without a date of birth** (created before `age.v1`, or provisioned by single sign-on, §5a.6) complete
it with `PUT /users/me/date-of-birth { date_of_birth }` (same checks; `200` with the own account as in
`GET /users/me`). Until then every authenticated route answers `403 age.status_required`, except `/users/me`
itself, `PUT /users/me/date-of-birth`, `POST /auth/logout`, the terms and legal routes of §5d (`/legal/*`,
`/users/me/terms`, `/users/me/terms/accept`), the data rights (`GET /users/me/data`, `GET /users/me/export`) and
the re-authentication they need (`POST /auth/reauth`, `POST /auth/reauth/webauthn/start`); a WebSocket closes with
`4002` and the reason `age.status_required`. Clients answer `age.status_required` with a blocking "add your date of
birth" dialog. Bots and users of other nodes are never asked (bots follow their owner, remote users the claim of
their home node). A date below the minimum age is refused with `403 age.below_minimum` here too, and the account
stays blocked.

**Corrections.** A user sets the date of birth once; a second `PUT` answers `409 age.date_of_birth_set`. The node
operator corrects it on request: `PUT /admin/users/{user_id}/date-of-birth { date_of_birth }` (node admin, local
users; `null` removes it, so the user is asked again), audited as `admin.date_of_birth` without the date itself.

**The age status is private.** The node derives it on every use from the date of birth and today's UTC date:

| `tier` | When |
|---|---|
| `adult` | 18 years or older |
| `minor` | younger than 18 |
| `unknown` | no date of birth (accounts that have not completed it) |

`GET /users/me` of a local user carries `date_of_birth` (or null) and `age_status: { tier, method }` (`method`
`self` for a self-declared date, `none` for `unknown`). Nothing else ever does: no profile (local or federated),
member list, search result, event, audit entry or response about another user carries the date of birth or the
status, and a refusal never reveals another user's status (a direct invite to a minor is created like any other;
only the invitee's own join fails). The date of birth stays on the home node; other nodes learn only the signed
"18 or older: yes/no/unknown" claim of `FEDERATION.md` §2.2 when the user acts there. **`unknown` counts as `minor`
everywhere.**

**Age gates.** Rooms and channels carry `age_gate`: `none` (default) or `adults_only`. A channel's effective gate is
`adults_only` when the room's or the channel's own gate says so (the room's gate is the channel's minimum: a channel
can be stricter than its room, never looser); `Channel` objects carry their own `age_gate` and the
`age_gate_effective`.

| Route | Permission | |
|---|---|---|
| `PATCH /rooms/{room_id}` `{ age_gate }` | `manage_room` | audited `room.age_gate`, event `room.update` and `channel.update` for the room's channels |
| `POST /rooms/{room_id}/channels`, `PATCH /rooms/{room_id}/channels/{channel_id}` `{ age_gate }` | `manage_channels` | audited `channel.age_gate`, event `channel.update` |

Only an adult can switch a gate to `adults_only` (`403 age.restricted`), so nobody locks themselves out by
accident; any value other than `none` and `adults_only` is `400 validation.age_gate`.

**Enforcement** on the hosting node, for its own users by their status and for users of other nodes by the claim of
their home node (`FEDERATION.md` §2.2); every refusal is `403 age.restricted` with `meta: { age_gate:
"adults_only" }`:

- **Discover and public lists.** `GET /rooms/discover` and `GET /directory/rooms` list rooms with a gate only to
  requests that carry the session of an adult (the `Authorization` header is optional on both routes); for
  everybody else gated rooms are absent. Listed rooms carry `age_gate`. Other nodes fetch the directory without a
  session, so gated rooms never enter other nodes' directories.
- **Joining.** `POST /rooms/{room_id}/join` and `POST /invites/{code}/join` (also with an invite bound to the user,
  `FEDERATION.md` §3.4) refuse users below the room's gate. The invite preview `GET /invites/{code}` stays public
  and carries `room.age_gate`, so clients can explain the refusal before the user tries.
- **Gated channels** stay in the channel list (`GET /rooms/{room_id}`) with their gate, but users below it have no
  permission in them (the permission evaluation of `permissions.md` yields 0): messages, history, threads and forum
  posts, pins, reactions, attachments and files, search, read markers, unread and mention counts, link previews
  (they live in the message content), notifications and web push, whiteboard, commands, calls and voice are refused
  (the conversation routes answer `age.restricted`); the channel's events (`message.*`, `typing`, `thread.*`,
  `voice.state`, `files.update`, …) are not delivered to them; and they are not entitled to the channel's MLS group
  (`ENCRYPTION.md` §4.5).
- **Existing members.** A room that becomes gated keeps its members; for members below the gate every channel of
  the room is locked until they are 18 or leave.

Clients show a gated channel to users below the gate as locked ("This channel is for adults only") without
messages, composer or previews, explain `age.restricted` at joins and invite links, offer the gate selectors in the
room and channel settings, and never show another user's age or status.

## 6. Realtime (WebSocket `/api/v1/ws`)

1. The client connects and sends `{"op":"hello","token":"…","capabilities":[…],"last_event_id":"…"}`.
2. The node replies `{"op":"ready","session_id":"…","capabilities":[…]}`. A `last_event_id` is answered with
   `{"op":"resync"}` and the client reloads state (the node keeps no ring buffer of past events to replay; a node
   with several instances could not replay another instance's events anyway; see the scaling guide of `tavrn-node`).
   `{"op":"resync"}` may also arrive later on an open connection whenever the node may have dropped events for
   it: the connection lagged behind, or (several instances) the shared event bus was interrupted. Clients treat
   it like a reconnect: reload rooms, conversations and the open views, keep the connection.
3. Events: `{"op":"event","id":"<ulid>","type":"message.create","data":{…}}`. Unknown `type` values are ignored.
4. Client operations: `typing` (`{ room_id, channel_id }` in room channels, `{ conversation_id }` in DMs and
   group DMs; the node forwards it to the room or to the members and drops typing operations of one connection
   less than a second apart), `ack` `{ conversation_id, message_id }` (read up to; the same checks and effect as
   `PUT …/read` below, errors are ignored). Everything else goes through REST, presence too (§6a).
5. Heartbeat: the node sends `ping` every 30 s, the client answers `pong`; two missed answers close the connection.
6. Close code `4000` means "node restarting, reconnect immediately", `4001` "token invalid", `4002` "protocol version not supported", `4004` "replaced by a newer connection of the same app token, do not reconnect" (`APPLICATIONS.md` §2.6).
7. App tokens (`APPLICATIONS.md` §2.6): `ready` also carries `application_id`; at most two connections per token;
   events are filtered by the token's scopes (an event a scope does not cover is dropped); a revoked, reset or
   expired token closes the connection with `4001`.

Events are addressed to a room, to users (all their connections) or to devices (only the connection of that
device). Room events that concern a channel (`message.*`, reactions and pins as `message.update`, `typing`,
`thread.*`, `voice.state`, `files.*`, `mls.*`, `history.pending`, `message.redact`, …: every event whose `data`
names a `conversation_id` or `channel_id` of the room, directly or in an embedded `thread` or `message`) reach only
**all room members who can view the channel** at delivery time: `view_channel` after roles and overrides
(`permissions.md`) and the age gate of §5e; a change of roles, overrides or membership applies to the next event.
`message.purge` (`conversation_ids`) reaches the members who can view at least one of its channels. The room's
metadata events (`room.*`, `channel.*`, `category.*`, `role.*`, `member.*`, `override.update`, `emoji.update`,
`soundboard.update`, `commands.update`, `user.*`) reach all room members. The same check gates web push (§6d)
and the `notify` hints to other nodes (`FEDERATION.md` §5.2). Event types besides the room/message events of
phase 1:

| Type | Audience | `data` |
|---|---|---|
| `mls.commit` | conversation audience¹ | `{ conversation_id, epoch }`: the group is now at `epoch` (0 after creation) |
| `mls.welcome` | the added devices | `{ conversation_id, epoch }`: fetch `GET /mls/welcomes` |
| `mls.remove_needed` | conversation audience¹ | `{ conversation_id, identities }`: leaves the node wants removed (`ENCRYPTION.md` §4.5) |
| `history.pending` | conversation audience¹ | `{ conversation_id, user, since, key_reset_at, min_epoch }`: `user` joined the group of an encrypted channel whose policy gives it history and waits for keys (`ENCRYPTION.md` §7b; `key_reset_at`/`min_epoch` non-null only after a key reset) |
| `history.keys_available` | the recipient (all of their connections on the hosting node) | `{ conversation_id }`: a history key share for the user waits at `GET …/history-keys` |
| `history.request` | the room's owner and the members whose roles hold `restore_history` or `administrator` | `{ room_id, request }`: a member asks to restore its history after a key reset (`ENCRYPTION.md` §7b, `HistoryRequest`) |
| `history.request_decided` | the requester and the recipients of `history.request` | `{ room_id, request }`: the request was approved or denied |
| `identity.changed` | the user, friends, DM contacts | `{ user, user_id, identity_reset_at, at }` |
| `identity.rotated` | the user, friends, DM contacts | `{ user, user_id, identity_public_key?, identity_generation?, at }`: the identity key was rotated with a continuity statement (`ENCRYPTION.md` §9a); the user's other devices pick up the new key, contacts re-check it (the key fields only on the home node) |
| `friend.request` | both parties | `{ request: { id, user, direction, created_at } }` (`user` = the other party) |
| `friend.accept` | both parties | `{ user, since }` |
| `friend.remove` | both parties | `{ request_id, user }` (`request_id` null when a friendship ended) |
| `conversation.create` | members (and a newly added member) | `{ conversation }` |
| `conversation.update` | members | `{ conversation }` (members or name changed) |
| `conversation.leave` | the removed user | `{ conversation_id }` |
| `typing` | room members who can view the channel (channels; a typing operation in a channel the sender cannot view is dropped) or the members of a DM/group DM | `{ room_id, channel_id, user_id }` or `{ conversation_id, user_id }` |
| `read.update` | the user (all of their connections) | `{ conversation_id, last_read_message_id }`: the read marker moved |
| `room.invite`, `conversation.invite` | the invited user (on the home node) | `{ invite }`: a new entry of the invite list (`FEDERATION.md` §4) |
| `notify` | the user (on the home node) | `{ node, conversation_id, room_id, mention, everyone }`: push hint for a conversation on another node, no content; `everyone` = the mention is only `@everyone`. The home node drops hints the user's notification settings do not want (§6c) |
| `notifications.update` | the user (all of their connections) | `{ settings }`: the notification settings changed (§6c) |
| `ban.notify` | the user (on the home node) | `{ room: { node, id, name }, scope }`: information that a room or node banned the user |
| `federation.undeliverable` | the sending user | `{ type, to }`: a friend request or invitation to another node could not be delivered |
| `voice.state` | room members who can view the channel | `{ room_id, channel_id, epoch, participants: [{ user, user_id, device_id, identity, muted, deafened, streaming, camera, server_muted, joined_at }] }`: the complete participant list of a voice channel after every change (`VOICE.md` §5) |
| `voice.move` | the moved user | `{ room_id, from_channel_id, channel_id, user_id }`: a moderator moved the user; the client joins `channel_id` (`VOICE.md` §7) |
| `soundboard.update` | room members | `{ room_id }`: the room's soundboard clips changed (`VOICE.md` §8) |
| `files.update` | room members who can view the channel | `{ room_id, channel_id, parent_id }`: the content of a folder of a files channel changed (`FILES.md` §3) |
| `files.backend` | room members who can view the channel | `{ room_id, channel_id, backend }`: the storage backend of a files channel changed (`FILES.md` §5) |
| `presence.update` | who may see the user (§6a); the user's own connections | `Presence` `{ user_id, user, status, custom_status, activity }`; at most one per user and second |
| `user.update` | the user's rooms, friends and DM contacts | `{ user }`: name or avatar changed (refresh lists and profile cards); for the pseudo user of a webhook (`kind = "webhook"`) the webhook's room |
| `application.subscription_disabled` | the owner of the application | `{ application_id, url, last_error }`: the event subscription was disabled after 3 days without a successful delivery (`APPLICATIONS.md` §6.2) |
| `conversation.request` | the recipient of a message request (§8a) | `{ request: ConversationRequest }` |
| `ephemeral` | conversation audience with read access², except the sending device | `{ conversation_id, type, from: { user, device_id }, content }`: an ephemeral event (below), never stored or replayed |
| `whiteboard.session` | conversation audience with read access² | `{ conversation_id, session }`: the whiteboard session changed (`session` null when it ended; `WHITEBOARD.md` §2.2) |
| `application.install` | the bot (on its home node) | `{ room_id, room_name, node, installed_by }`: the bot was installed in a room of `node` (`APPLICATIONS.md` §4.2) |
| `application.uninstall` | the bot (on its home node) | `{ room_id, node, reason }`: the bot left a room (`removed`, `kicked`, `banned`, `left`, `no_bots`, `owner_banned`, `blocked`, `deleted`; §4.3) |
| `application.token_expiring` | the application's owner and its bot | `{ application_id, token_id, expires_at, days }`: an app token expires in 7 or 1 days (§2.2) |
| `commands.update` | room members (and bots with the `commands` scope) | `{ room_id }`: the application commands of the room changed (definitions, approval, room settings, installations); clients refetch their palettes (`APPLICATIONS.md` §5.1, §5.3) |
| `command.invoke` | exactly one connection of the bot whose token has the `commands` scope (round robin over its devices) | the interaction data of `APPLICATIONS.md` §5.6 (`interaction_id`, `command`, `conversation_id`, `user`, `device_id`, `permissions`, `args` or `args_ciphertext` + `epoch`, `locale`, `expires_at`) |
| `interaction.reply` | the invoker: their other connections for the first response, all of them for follow-ups | `EphemeralReply` `{ interaction_id, conversation_id, application: { ref, name, bot }, device_id, content, epoch, created_at }`: an ephemeral reply, shown only to the invoker and never stored (`APPLICATIONS.md` §5.7) |
| `message.redact` | conversation audience¹ | `{ room_id, conversation_id, ids, author_id }`: the content of these messages was deleted with their author's account (§5d); the slots stay with the content `{"type":"system.deleted"}`. Clients replace cached content and drop the messages from local search indexes |
| `user.deleted` | the rooms the user was in, friends and DM contacts | `{ user_id, address, tombstone }`: an account was deleted (§5d); its messages now name the tombstone (`author_deleted: true`) |
| `thread.create`, `thread.update` | room members who can view the channel | `{ room_id, thread }`: a thread was started, or its title, tags, archive or lock state or its counters changed (§7e) |
| `thread.delete` | room members who can view the channel | `{ room_id, channel_id, id }`: a thread was deleted with its messages (§7e) |
| `thread.read` | the user (all of their connections) | `ThreadReadState`: the per-thread read marker or the follow state changed (§7e) |
| `legal.statement` | the uploader | `{ case_id, decision, counter_deadline? }`: a statement of reasons or a decision about the user's content (`LEGAL.md` §1.4); details at `GET /users/me/legal-notices` |
| `report.create` | the users who may see the report (room moderators, node admins), except the reporter | `{ report: { id, scope, source, kind, room_id, room_name, conversation_id, category, created_at } }`: a new report in the moderation inbox (`MODERATION.md` §1.5) |
| `report.update` | the same audience | `{ id, scope, room_id, status }`: a report changed, was acted on or deleted (`status: "deleted"`) |
| `moderation.alert` | the room's moderators (owner, `moderate_members`), for node rules the node admins | `{ room_id, channel_id, user, kind, at, … }`: auto-moderation acted; `kind` `spam` (flood: `deleted`, `timeout_until`) or `content` (`rule`, `scope`, `matched`, `action`), `MODERATION.md` §2 |

¹ Room channels: all room members who can view the channel (roles, overrides and the age gate of §5e); DMs and
group DMs: their members. `message.create`, `message.update` and
`message.delete` of DMs and group DMs go to the members' users as well (`room_id` is null).
² Room channels: only the members who may view the channel (roles, overrides and the age gate of §5e); DMs and group DMs: the members
who accepted them.

**Ephemeral events (design note 4.10, normative: `WHITEBOARD.md` §2).** `POST /conversations/{id}/ephemeral
{ type, content, session? }` sends a short-lived event to the conversation: `type` is `cursor` or
`whiteboard.<name>` (`[a-z_]{1,32}`), `content` is encrypted exactly like message content in encrypted
conversations (`ENCRYPTION.md` §5, checked like a message) and a JSON object otherwise, at most 64 KiB; 30 events
per second and sender. The node fans it out as `ephemeral` and forgets it. The only types it interprets are
`whiteboard.open`, `whiteboard.grant` and `whiteboard.close`, whose plaintext `session` field
(`{ open_for_all, grants }`) maintains the whiteboard session of the conversation (`GET
/conversations/{id}/whiteboard`, event `whiteboard.session`). Errors: `ephemeral.type_invalid`,
`ephemeral.encryption_mismatch`, `ephemeral.ciphertext_invalid`, `ephemeral.epoch_unknown`, `ephemeral.too_large`,
`whiteboard.open_forbidden`, `whiteboard.session_exists`, `whiteboard.not_owner`, `whiteboard.close_forbidden`,
`whiteboard.no_session`, `whiteboard.state_missing`, `whiteboard.grants_invalid`, plus the usual access codes and
`429`.

**Read markers and unread counts (lazy history, design note 4.4).** Clients never load whole histories: they page
messages newest first (`GET …/messages?limit=50`, at most 100; older pages with `before=<oldest id>`, newer ones
with `after`, which the node returns oldest first; cursors must be message ids, `400 validation.id` otherwise) and
take unread and mention counts from the lists instead. **`around=<message id>`** (jump to a search result or a
link) returns the page around one message, newest first: up to `limit / 2` newer messages, the message itself and
older ones up to `limit` in total. It cannot be combined with `before`, `after` or `epoch`
(`400 message.cursor_conflict`) and answers `404 message.not_found` when the message is not in this conversation
or not visible to the caller (the history cut of §7b of ENCRYPTION.md applies as for any page). A client that
opened the history this way is *detached* from the live end: it pages newer messages with `after` until a page is
not full and does not insert live `message.create` events before that.

- `PUT /conversations/{conversation_id}/read { last_read_message_id }` → `200 ReadState`: moves the user's read
  marker forward; an older id leaves it unchanged (markers never move backwards). Only members who may view the
  conversation (`403 room.not_member` / `channel.view_forbidden`, `404 conversation.not_found` for DMs of
  others); the message must belong to the conversation (`400 validation.id`, `404 message.not_found`);
  rate-limited per user (`429`). When the marker moved, the user's connections get `read.update`.
- `ReadState` = `{ conversation_id, last_message_id, last_read_message_id, unread_count, mention_count, muted }`.
  `unread_count` counts messages of others after the marker, `mention_count` those of them that mention the
  user (plaintext `mentions`), one of the user's roles in the room (`role:<id>`) or `@everyone`; both are capped
  at 999 (clients show "999+"). Without a marker, messages count from the user's join (room membership or DM
  membership). The user's notification settings apply (§6c): muted conversations report `0`/`0` and
  `muted: true`, mode `nothing` reports no mentions, `suppress_everyone` leaves `@everyone` out. The welcome
  channel (`kind = "system"`) never counts mentions and reports `unread_count` 1 when something changed since the
  marker (clients show a dot, no number).
- `GET /rooms/{room_id}` (`RoomDetail`) carries `read_states` for the channels the requester can view (empty
  for node admins who are not members). `GET /conversations` carries `last_read_message_id`, `unread_count`
  and `mention_count` per DM/group DM (these fields are absent in other conversation responses and events).
- Clients keep the counts current with `message.create` (counted unless the conversation is open and the tab
  focused) and `read.update`, and send the marker (debounced) when a conversation is opened or new messages
  arrive while it is visible.

**History for new members of encrypted channels (design note 4.13 item 11, normative: `ENCRYPTION.md` §7b).**
Channels carry `history_for_new_members`: `since_join` (default), `days:<n>` (1 ≤ n ≤ 3650) or `all`; changed with
`PATCH /rooms/{room_id}/channels/{channel_id}` (`manage_channels`, audit action `channel.history_policy`
with `{ from, to }`, `400 channel.history_policy_invalid`), announced with `channel.update`. In `GET …/messages`
the node cuts **encrypted** messages older than the requester's window: the room membership's `joined_at`
(`since_join`, or always without permission bit 34 `read_history`), `joined_at` minus `n` days (`days:<n>`),
nothing (`all`). Plaintext messages are never cut; owners and administrators follow the same rule; node admins who
are not members, and DMs, are not cut; group DM members start at their own join. A re-join starts a new window.
`GET …/messages?epoch=<n>` lists only encrypted messages of that epoch (within the window), for key checks. The
history key routes `POST|GET /conversations/{id}/history-keys`, `DELETE /conversations/{id}/history-keys/{share_id}`
and `GET /conversations/{id}/history-pending` are described in `ENCRYPTION.md` §7b. Files channels differ: their
policy is `all` (their default) or `since_join`, never `days:<n>`, and entry records take the place of messages
(`FILES.md` §8.7).

**History after a key reset (capability `history.restore`, normative: `ENCRYPTION.md` §7b "History after a key
reset").** An identity reset sets `key_reset_at` on the member's room memberships: the message cut and the automatic
key shares then start at the reset, and history from before it comes back only when a member with permission bit 37
`restore_history` approves the member's request (`POST|GET /rooms/{room_id}/history-requests`, `GET
…/history-requests/mine`, `DELETE …/history-requests/{id}`, `POST …/history-requests/{id}/approve|deny`). Rooms switch
requests off with the setting `history_restore: "off"` (default `"request"`, `PATCH /rooms/{room_id}`,
`manage_room`). Decisions go to the audit log (`history.restore_requested`, `history.restore_approved`,
`history.restore_denied`) and the welcome channel (`system.history_restored`, `system.history_restore_denied`).

**Channels with webhooks.** Channels carry `has_webhooks` (computed, announced with `channel.update` when a webhook
is created, moved or deleted). In encrypted channels with webhooks the device that commits an epoch publishes the
epoch's inbox key with `PUT /conversations/{id}/inbox-key` (`APPLICATIONS.md` §6.1a, `ENCRYPTION.md` §5b); channels
without webhooks never do.

`mls.remove_needed` is emitted when a user leaves, is kicked or banned from a room, leaves or is removed from
a group DM, deletes a device and after an identity reset. Losing read access through a role or override change
is not detected generically: clients additionally compare the MLS roster with the member list (`ENCRYPTION.md`
§4.6) and remove leaves of users who are no longer entitled.

## 6a. Presence (design note 4.9)

Presence is kept by **every node the user has a session on**, never forwarded between nodes: the client
pushes its state to its home node and, through its federated sessions, to every node hosting its rooms and
conversations. A node therefore never learns the presence of a user without a session there (decided
2026-10-05; FEDERATION.md §13.2).

- A user is online on a node while at least one WebSocket of theirs is open there. The **chosen status**
  (`online`, `dnd`, `invisible`) and the **custom status** `{ text ≤ 128, emoji?, expires_at? }` belong to the
  account; `idle` and the **activity** `{ type: playing|listening|watching|streaming|competing, name ≤ 128,
  details?, state?, started_at, ends_at?, application? }` belong to the device. `state` (≤ 128) is a second line,
  `ends_at` (RFC 3339, after `started_at`, at most 7 days ahead) a countdown, `application` `{ ref, name }` the
  application that reported it through the local activity bridge (`APPLICATIONS.md` §7.2–§7.3; clients show
  "via <name>"); the node checks the format only. Bots set their own presence and activity with the `presence`
  scope (`APPLICATIONS.md` §7.1). Effective status: `offline` without a connection, else `dnd` or
  `invisible` as chosen, else `idle` when every connected device is idle, else `online`. Clients report `idle`
  after 10 minutes without input (only while the chosen status is `online`) and `online` when input returns.
- Others see `invisible` as `offline` (without custom status and activity) and never see the activity of a
  user with `hide_activity`. Only friends, members of rooms in which the user does not hide their presence
  (`PUT /rooms/{id}/presence { hidden }`) and members of shared accepted DMs/group DMs see it; blocks hide it
  in both directions.
- `GET /users/me/presence` → `MyPresence { status, effective, idle, custom_status, activity, hide_activity }`;
  `PUT /users/me/presence { status?, custom_status? }` (`custom_status: null` clears it; `idle` affects this
  device only); `PUT /users/me/activity` / `DELETE /users/me/activity` (this device); `GET /presence` lists the
  presences the requester may see that are not offline. Errors: `400 presence.status_invalid`,
  `presence.invalid` (custom status: text or emoji required, expiry in the future and at most 30 days),
  `presence.activity_invalid`; `429` per device.
- `presence.update` is batched: at most one per user and second, carrying the state at the time of sending;
  unchanged states are not repeated.

## 6b. Profiles and the media pipeline (design note 4.9)

- `GET /users/{address}/profile` (public; `name` or `name@domain`; this node's mirror for users of other
  nodes it knows) → `Profile`: the user fields plus `profile_version`, `avatar` (path of the animated variant
  if there is one, else the still), `avatar_still`, `avatar_animated`, `header`, `header_still`,
  `header_animated`, the base64url SHA-256 of every image variant (`avatar_sha256`, `avatar_animated_sha256`,
  `header_sha256`, `header_animated_sha256`), `bio` (Markdown subset, ≤ 512 characters, rendered and sanitized
  by clients), `links` `[{ service, value, url }]` and the effective `dm_policy`. User objects everywhere carry
  `avatar` and `avatar_still`; room objects `icon`, `icon_still`, `icon_animated`. Image paths are relative to
  the node that served the object (`/api/v1/media/{id}`, `/api/v1/media/{id}/animated`); those routes are
  public, typed by the stored file, `nosniff`, sandboxed and cached for a year (the id changes with every upload).
- `PATCH /users/me { display_name?, bio?, links?, dm_policy?, hide_activity?, auto_preview?, locale? }` (`auto_preview`:
  §7a "Automatic previews"; private, never part of the public profile). `locale` is the language of the mails the
  node sends the user (email confirmation, password reset, account and legal notices, app token expiry): a language
  tag such as `de` or `pt-BR`, stored lowercase (`400 validation.locale` otherwise), `""` clears it; `GET`/`PATCH
  /users/me` return it as `locale` (null = English). A new account starts with the first tag of the registration's
  `Accept-Language`; clients send the language the user picked whenever it differs. The node uses its texts for the
  most specific language it has (`de-at` → `de`) and English otherwise. Links: at most 10
  (`profile.links_too_many`); `service` one of steam, battlenet, xbox, playstation, nintendo, twitch, youtube,
  x, mastodon, website (`profile.link_service`); the node validates the value per service and derives the URL
  itself from an allowlist of https hosts (a pasted profile URL of the service is accepted; `website` takes any
  https URL of a public host name without IP literals, credentials or ports); anything else is
  `profile.link_invalid`. Bio: `profile.bio_too_long`. Public changes increment `profile_version`.
- Uploads (raw body, the client's content type is ignored): `PUT /users/me/avatar` (256 × 256), `PUT
  /users/me/header` (1200 × 400), `PUT /users/me/background` (private, fit into 1280 px; read back with
  `GET /users/me/background[/still|/animated]`), `PUT /rooms/{id}/icon` (owner or `manage_room`, audited as
  `room.icon` / `room.icon_remove`, `room.update` event), each with `DELETE`. Input: PNG, JPEG, GIF, WebP, MP4,
  WebM by magic bytes (SVG and everything else `415 media.type_not_allowed`), at most 20 MB (`413
  media.too_large`, checked while reading), 4096 px per side (`400 media.dimensions`), 30 s (`400
  media.too_long`); unreadable files `400 media.invalid`. Output: WebP; animated input additionally an animated
  WebP (≤ 10 s loop) with its first frame as the still; at most 1 MB per variant (avatars, icons) or 2 MB
  (headers, backgrounds), otherwise `413 media.output_too_large`. ffmpeg runs without a shell, without network
  protocols (forced demuxer, `file`/`pipe` only), with an empty environment and a 30-second budget per job
  (`400 media.timeout`); `TAVRN_MEDIA_WORKERS` jobs at once, a few more wait, the rest get `503 media.busy`. With
  `TAVRN_MEDIA_FFMPEG=off` only PNG, JPEG and simple WebP stills are accepted (metadata removed by the node),
  animated input and video are `415 media.animation_unavailable`, other stills `415
  media.conversion_unavailable`. Metadata (EXIF, XMP, comments) never survives. Replaced images are deleted.

**Per-room profiles (design note 4.11).** A member can have a nickname, avatar and bio in one room ("server
profile"); they belong to the membership and are deleted (files included) when it ends (leave, kick, ban).

- `PUT /rooms/{id}/members/me/profile { nickname?, bio? }` (`change_nickname`; nickname 1–32 characters, `null`
  removes it; bio like the profile bio, empty removes it) and `DELETE …/members/me/profile` (resets all three).
- `PUT /rooms/{id}/members/me/avatar` (raw body, same pipeline and limits as the user avatar, `change_nickname`),
  `DELETE …/members/me/avatar`.
- `PATCH /rooms/{id}/members/{user_id}/profile { nickname?, bio?, reset_avatar? }` (`manage_nicknames`, only
  members below the own highest role, never the owner; the owner can change everybody's), audited as
  `member.profile`. `PATCH /rooms/{id}/members/{user_id} { nickname }` keeps working for the nickname alone.
- Member objects carry `nick` (also as the older `nickname`), `room_avatar` (animated variant if any),
  `room_avatar_still`, `room_avatar_animated`, `room_bio` (null without). Messages in room channels carry
  `author_room_profile { nick, avatar, avatar_still, avatar_animated }` (null without one). Clients prefer them
  over the user's display name and avatar everywhere in that room; changes arrive as `member.update`. Errors:
  `403 room.not_member`, `403 member.nickname_forbidden`, `400 validation.length`, `400 profile.bio_too_long`,
  the media errors above.

## 6c. Notification settings (design note 4.11)

`GET /users/me/notification-settings` → `NotificationSettings`, also returned as `notification_settings` by
`GET /users/me` (local users only). `PUT /users/me/notification-settings` replaces them (validated, at most 500
rooms, 2000 channels and 64 KiB, `400 notifications.invalid`, `413 notifications.too_large`); the user's
connections get `notifications.update`. Remote users with a federated session are refused
(`403 federation.local_only`): settings live on the home node.

```json
{ "global":   { "mode": "all", "sound": true, "browser": false, "push_text": false },
  "rooms":    { "<room id>": { "mode": "mentions", "muted_until": null, "suppress_everyone": true } },
  "channels": { "<conversation id>": { "mode": "nothing", "muted_until": "forever" } } }
```

- `mode`: `all` (every message notifies), `mentions` (mentions of the user, of one of their roles or `@everyone`),
  `nothing`. The channel's mode wins over the room's, which wins over `global`.
- `muted_until`: RFC 3339 time or `"forever"`; a muted room mutes all its channels. Clients offer 1 h, 8 h, 24 h
  and forever.
- `suppress_everyone` (rooms): `@everyone`/`@here` count as no mention there.
- The node applies them to the unread and mention counts of its lists (§6) and to received `notify` hints:
  a hint for a muted conversation, a non-mention under `mentions`, anything under `nothing` and a pure
  `@everyone` under `suppress_everyone` is neither stored nor forwarded. `sound` and `browser` are applied by
  clients (sound and Notification API when the tab is in the background); in-app toasts follow `mode`.
- `push_text` (optional, default `false`, left out while off): web pushes (§6d) of unencrypted conversations carry
  a preview of the message text. Never for encrypted conversations.
- `reports` (optional, default `true`, left out while on): web pushes (§6d) of new reports for the users who receive
  them (room moderators and node admins, `MODERATION.md` §1.5). Clients show the switch to moderators and node admins.

## 6d. Web push (`push.webpush`, design note 4.9)

A node with `push.webpush` sends web pushes (RFC 8030, payload encryption RFC 8291 `aes128gcm`, VAPID RFC 8292) to
the browsers and installed web apps of its **local** users while they have **no open WebSocket** on the node, for
whatever would notify them under their notification settings (§6c). Push is per node and home-node only: the home
node holds the settings and receives the `notify` hints of the other nodes (FEDERATION.md §5.2), so a client
registers its subscription with its home node only (`403 federation.local_only` for remote users, `403
app.bot_forbidden` for bots).

Routes:

- `GET /push/vapid` (public) → `{ enabled, public_key }`: whether the node sends pushes and the VAPID public key
  (base64url of the uncompressed P-256 point, the `applicationServerKey` of `PushManager.subscribe()`; `null` while
  off). The key is long-lived: when an operator replaces it, every subscription stops working and clients
  subscribe again (they compare the key they subscribed with).
- `PUT /users/me/push-subscriptions { endpoint, keys: { p256dh, auth }, device_id?, expiration_time? }` (the
  browser's `PushSubscription.toJSON()`; `expirationTime` is accepted too) registers the subscription for the
  requesting device → `201` (new) or `200` (an existing endpoint of the account, also from another of its devices,
  is updated). An endpoint of another account's live subscription (not expired, its device has a live session) is
  refused with `409 push.endpoint_taken`, so knowing an endpoint URL does not cut another account off its pushes;
  the client then unsubscribes the browser and subscribes again (a new endpoint). A stale one is taken over.
  `endpoint`: `https://` URL of a public host, at most 2048 characters (`400 push.endpoint_invalid`); `p256dh` a
  base64url uncompressed P-256 point, `auth` base64url of 16 bytes (`400 push.keys_invalid`); `device_id` must be
  the requesting device (`400 push.device_invalid`); `expiration_time` Unix milliseconds in the future or null (`400
  push.expiration_invalid`). At most 20 subscriptions per account (`409 push.too_many`), 30
  registrations per hour (`429`), `404 push.disabled` while off. Response `PushRegistration { id, device_id,
  push_service, current_device, created_at, last_used_at, expires_at, failures }` (keys and endpoint are never
  returned; `push_service` is the endpoint's origin).
- `GET /users/me/push-subscriptions` → the account's subscriptions; `DELETE /users/me/push-subscriptions/{id}` →
  `204` (`404 push.subscription_not_found`); `POST /users/me/push-subscriptions/test` → `202`, a push of type
  `test` to every subscription, also while connected (5 per 10 minutes, `429`).
- A subscription belongs to its device: it is deleted when the device is removed or its sessions are revoked
  (sign-out), when the push service answers `404`/`410`, and after 30 failed deliveries in a row. Clients delete
  their subscription before signing out and when the user turns push off.

When a push is sent:

- A new message in a channel, DM or group DM hosted by the node: for every member with a subscription who has no
  open WebSocket, may read the conversation (room member with `view_channel`, an accepted DM), has not blocked or
  been blocked by the author and is not the author, and whose settings let the message through: nothing while the
  channel or room is muted or under `nothing`; DMs and group DMs follow their own mode, else every message unless
  the global mode is `nothing`, and always count as mentions; channels follow their mode, `mentions` lets through
  mentions of the user or one of their roles and `@everyone` unless the room suppresses it. Welcome and system
  channels never push.
- A call ring in a DM or group DM hosted by the node, unless the conversation is muted or under `nothing`.
- A `notify` hint received from another node (FEDERATION.md §5.2) that passed the user's settings: DMs, group DMs and
  mentions of conversations on other nodes, and call rings. Messages of remote channels under mode `all` do not
  push (the hosting node sends hints only for DMs and mentions).
- At most one push per conversation and user every 30 seconds (call rings excepted) and `TAVRN_PUSH_MAX_PER_MINUTE`
  per user (default 10); with several instances both counters are shared. Delivery is best-effort in the
  background; `TTL` 6 hours (call rings 45 seconds), `Urgency: high` for DMs, mentions and calls, `Topic` per
  conversation (a newer push replaces one not yet delivered).

Payload (JSON, encrypted for the subscription; the service worker decides how to show it):

```json
{ "v": 1, "type": "message", "node": "example.org", "local": true,
  "conversation_id": "<id>", "room_id": "<id>", "conversation_kind": "channel",
  "room": "Tavern", "conversation": "general", "sender": "Alice", "text": "Hello", "encrypted": false }
```

- `type`: `message` (channel message), `mention`, `dm`, `call`, `test`, or `notice` (other features, with `title`
  and `body`). `node` hosts the conversation; `local` is `false` for pushes forwarded from a `notify` hint (then
  `conversation_kind` is `channel` or `direct`, `sender` is the caller's address of a ring, and there are no names).
  `conversation_kind`: `channel`, `dm`, `group` (or `direct`); `room` and `conversation` are the room and channel
  name or the group DM name (at most 100 characters); `sender` is the author's room nickname or display name.
- Encrypted conversations (`encrypted: true`) never carry ciphertext, plaintext or message ids. `text` (at most 120
  characters) appears only for unencrypted messages and only with `push_text` (§6c).
- Unknown fields and types are ignored; clients show a generic notification for unknown types.

**Reports.** A new report (`MODERATION.md` §1.5, user reports and automod entries alike) pushes to every local user
of its audience (the room's moderators and the node admins, never the reporter or the reported user) who has no open
WebSocket and has not turned `global.reports` (§6c) off: `{ "v": 1, "type": "report", "node", "local": true, "room_id",
"room", "report_kind", "encrypted": false }` with `report_kind` `message`, `user` or `room` and the room's id and name
for room reports (node reports have neither). Nothing else of the report travels: no reporter, target, category,
detail or evidence. At most one report push per room (node reports: per node) and user every 30 seconds, and the
per-user limit above; the client opens its moderation inbox.

**Rooms on other nodes (decision).** Push stays home-node only. A room hosted on another node sends `notify` hints to
the member's home node only for DMs, group DMs, mentions and call rings (FEDERATION.md §5.2), so in rooms on other
nodes a channel under notification mode `all` does **not** push for ordinary messages; mentions, DMs and calls do.
Clients say so next to the notification settings. Registering subscriptions with every node of the user was rejected:
it would need the notification settings replicated to those nodes and double pushes avoided across them.

## 7. Message envelope

Every message consists of an envelope (readable by the node) and content (opaque to the node when `encrypted = true`).

```json
{
  "id": "01J…",
  "conversation_id": "01J…",
  "author": "alice@node.example",
  "author_id": "01J…",
  "author_kind": "user",
  "device_id": "01J…",
  "created_at": "2026-10-04T12:00:00Z",
  "edited_at": null,
  "encrypted": true,
  "format": 1,
  "reply_to": null,
  "thread_id": null,
  "mentions": ["bob@other.example"],
  "mentions_everyone": false,
  "attachments": [{ "id": "01J…", "name": "image.png", "mime": "image/png", "size": 12345, "sha256": "…" }],
  "reactions": [{ "emoji": "👍", "count": 2, "me": true }],
  "pinned": false,
  "epoch": 42,
  "content": "<base64url: ciphertext>",
  "signature": null
}
```

- `encrypted = true`: `content` is AES-256-GCM ciphertext under the per-epoch content key of the MLS group
  (`epoch`), including the device signature; the exact format is `ENCRYPTION.md` §5. In encrypted
  messages the envelope's `attachments` entries carry only `id`, `size` and `sha256` of the encrypted blob;
  names, types and file keys are inside the encrypted content (`ENCRYPTION.md` §6).
- `encrypted = false`: `content` is the JSON content object in plaintext. Only allowed in channels whose
  `encrypted` flag is `false`. The node rejects plaintext in encrypted channels and ciphertext in unencrypted
  channels with `message.encryption_mismatch`.
- `thread_id` names the thread the message belongs to (§7e), null for messages of the channel itself. A message
  that started a thread carries the summary `thread` of that thread (absent otherwise).
- `author_kind` is the author's `kind` (`user`, `bot`, `webhook`, …) so every client can show the BOT or WEBHOOK
  badge (`APPLICATIONS.md` §1.5) without loading the author.
- `webhook` (messages of an incoming webhook only, set by the node, `APPLICATIONS.md` §6.1): `{ id, name }` with the
  webhook's id and the name shown for this message (the per-message `username` or the webhook's name at the time).
  Such messages have `author_kind = "webhook"` (the author is the webhook's pseudo user `wh.<id>@<node>`),
  `device_id` and `signature` are null. In unencrypted channels they are plaintext; in encrypted channels they are
  sealed (`encrypted = true`, `epoch` set, `content` = `{ "type": "webhook.sealed", "epoch", "sealed", "sealed_by" }`,
  `APPLICATIONS.md` §6.1a, `ENCRYPTION.md` §5b). Clients show `webhook.name` (or the `username` inside a sealed box)
  with the WEBHOOK badge and never the "unverified" marker (the node authenticated the webhook). The field is absent on
  every other message.
- `interaction` (set by the node on a message an application posted as the answer to a command, `APPLICATIONS.md`
  §5.7): `{ id, command, application, user }` with the interaction id, the command's name, the application reference
  and the invoker's address. Clients show "<user> used /<command>" above the message. The field is absent on every
  other message.
- `device_id` is the sending (or last editing) device, null for system and webhook messages; `epoch` is set for
  encrypted messages only. For
  encrypted content the node checks `ENCRYPTION.md` §5.3 (`message.ciphertext_invalid`,
  `message.epoch_mismatch`, `message.epoch_unknown`, `e2ee.device_not_attested`).
- `signature` (plaintext only, optional on create and edit): `base64url(nonce(16) || Ed25519 signature(64))`
  by the sending device over the envelope fields `conversation` (qualified), `author`, `device_id`,
  `reply_to_id`, `thread_id`, `mentions_everyone`, `mentions`, `attachments` (id, size, sha256) and the
  RFC 8785 (JCS) form of `content` (FEDERATION.md §10.3). The node does not verify it (it cannot know every
  device key cheaply); it accepts it only in unencrypted conversations, checks the format (exactly 80 bytes
  of base64url without padding, otherwise `400 message.signature_invalid`, also for a signature on an
  encrypted conversation), stores it unchanged and returns it; null for encrypted and unsigned messages.
  Because the signature covers `mentions` in envelope order, a signed request must send them normalized
  (lowercase, trimmed, no duplicates; otherwise `400 message.mention_invalid`); the node never rewrites
  signed fields. An edit carries the new signature of the editing device; an edit without one clears it.
  Attachments are listed in the envelope sorted by id, signers sign them in that order. Clients verify
  against the author's attested devices: valid → normal, missing or not checkable → small "unverified"
  marker, wrong or reused nonce → content hidden ("could not be verified").
- `mentions` deliberately stays in plaintext so the node can filter notifications for "mentions only".
  Clients must inform users about this (privacy notice). Entries are user addresses (lowercase) or roles of
  the room as `role:<role id>` (the id in canonical uppercase; only in room channels, `400 message.mention_invalid`
  otherwise or for unknown roles). Mentioning a role that is not `mentionable` needs `mention_everyone`
  (`403 message.mention_role_forbidden`). Role mentions count as mentions for every member holding the role.
- Attachment blobs are uploaded first (`POST …/uploads`) and bound to the message on send. In encrypted
  channels the client encrypts the file with a random key and carries key and hash inside the encrypted content.

Content object (after decryption or in plaintext):

```json
{ "type": "text", "body": "Hello **world** :pogchamp:", "gif": { "url": "https://media.giphy.com/…", "preview_url": "…", "width": 480, "height": 270 } }
```

`text` content may carry `embeds` (`APPLICATIONS.md` §6.4, any author, encrypted or not): at most 10 objects
`{ title?, description?, url?, color?, fields?, footer?, timestamp? }` with `title` ≤ 256, `description` ≤ 4096
(Markdown subset), `url` `https://` without credentials (≤ 2048), `color` 0–16777215, at most 25 `fields`
`{ name ≤ 256, value ≤ 1024, inline? }`, `footer` ≤ 2048, `timestamp` RFC 3339, at most 6000 characters over all
text fields, at least a title, description, field or footer per embed; `body` may then be empty. The node checks
plaintext content (`400 message.embeds_invalid`), clients check encrypted content before encrypting and drop invalid
embeds after decrypting. Embeds never contain images; clients render them through the message Markdown sanitizer
and show links with their full host. Unknown embed fields are ignored.

Reserved `type` values: `text`, `action`, `system.join`, `system.leave`, `system.key_changed`, `system.bot_added`, `system.bot_removed`, `system.pin`, `system.encryption_changed`, `system.history_restored`, `system.history_restore_denied`,
`command.args` (encrypted command arguments, `APPLICATIONS.md` §5.8: `{ type, command, nonce, issued_at, args }`,
only ever inside `args_ciphertext` of an invocation, never as a message), `poll` (later). Unknown types are shown by clients as "Your client cannot display this message". `action`
(`{ "type": "action", "body": "waves" }`, `/me`) follows the rules of `text` and is rendered in italics after the
author's name.

**System messages** are written by the node only (plaintext even in encrypted conversations, `device_id` null,
clients cannot send `system.*`, `400 message.type_reserved`):

| Type | Where | Content |
|---|---|---|
| `system.encryption_changed` | the channel | `{ encrypted, by }` |
| `system.join` | the room's welcome channel | `{ user, display_name, avatar, avatar_still }`: a member joined (`user` = address; name and avatar paths are a snapshot) |
| `system.leave` | the room's welcome channel | `{ user, display_name, avatar, avatar_still, reason_kind }`: `reason_kind` = `leave`, `kick` or `ban` (reasons and moderator names stay in the audit log) |
| `system.key_changed` | the room's welcome channel | `{ user, display_name, avatar, avatar_still, at, rotated }`: the member's identity key changed (`at`, RFC 3339). `rotated: true` for a rotation with a valid continuity statement (`ENCRYPTION.md` §9a), `false` for an identity reset (§9) or any other change |
| `system.bot_added` | the room's welcome channel | `{ bot, display_name, avatar, avatar_still, channel, channel_name, channel_system_name, by }`: a bot's first leaf joined the encryption group of the encrypted channel `channel` (`by` = the committer's address; `APPLICATIONS.md` §3.6) |
| `system.bot_removed` | the room's welcome channel | `{ bot, display_name, avatar, avatar_still, channel, channel_name, channel_system_name, reason }`: the bot's last leaf left that group (`reason`, `APPLICATIONS.md` §3.6) |
| `system.history_restored` | the room's welcome channel | `{ user, display_name, avatar, avatar_still, by }`: `by` (an address) approved the request of `user` to restore its encrypted history after a key reset (`ENCRYPTION.md` §7b) |
| `system.history_restore_denied` | the room's welcome channel | `{ user, display_name, avatar, avatar_still, by }`: `by` denied that request (the reason stays in the audit log) |

The message author of `system.join`/`system.leave`/`system.key_changed`/`system.history_restore*` is the member concerned (of `system.bot_*` the
bot). Clients render them
localized in the viewer's language with the avatar. `system.key_changed` is informational: the client decides with its
own pin of the user's key what it shows (`ENCRYPTION.md` §3.3): the same "security key changed" warning as elsewhere
while a change is unacknowledged, a soft "rotated" notice after a verified continuity statement, plain text once
acknowledged. The node writes the entry into the welcome channel of every room it hosts that the user is a member of:
the home node at an identity reset or rotation of a local user, a room node when it learns a changed key of a remote
member (`identity.changed`, or a refetch of the keys document after `devices.changed` or on use; `rotated` = the
document's continuity chain leads from the cached key to the new one).

**Welcome channel, the room's security log (design note 4.11, 4.13 item 12).** Every room has exactly one channel of
`kind = "system"` with `system_name = "welcome"`, created with the room (and for older rooms at node start):
never encrypted (the encryption switch is refused with `400 channel.system_protected`), outside every category,
`position` −1 (pinned first), read-only for everyone (`403 channel.read_only` for messages, reactions are allowed;
its entries cannot be deleted by anyone, `403 message.system_protected`, `MODERATION.md` §3), not renamable, movable or deletable (`400 channel.system_protected`; only `topic`
and overrides change), no whiteboard. It is always visible: `view_channel` and `read_history` are forced there
(`permissions.md` "System channels"), so every member, including new ones, reads its whole history; overrides
cannot hide it and the room cannot switch it off (the former setting `welcome_channel_enabled` is ignored and no
longer returned; rooms that had it off show it again after a startup fixup). Members can still mute its
notifications (§6c). Room purges leave it alone, even when it is named.

## 7a. Upload categories (design note 4.11)

Every attachment falls into one category. Plaintext uploads are classified by the node: content (magic bytes)
first, then the file name's last extension, then the declared `Content-Type`. Encrypted uploads are ciphertext:
the client classifies the file with the same table and declares it in `Tavrn-Upload-Category`
(`images` … `other`, or `executable`; missing = `other`, `400 upload.category_invalid` for anything else). The
node trusts the declaration, so this is cooperative enforcement in encrypted conversations (a modified client
can lie); it reveals only the coarse category.

| Category | Content | Extensions | Types |
|---|---|---|---|
| `images` | PNG, JPEG, GIF, WebP, BMP, AVIF/HEIC | png jpg jpeg jfif gif webp avif bmp ico tif tiff heic heif | `image/*` except `image/svg+xml` |
| `audio` | ID3/MP3, FLAC, WAV, Ogg (not Theora), M4A, MIDI | mp3 ogg oga opus wav flac m4a aac weba mid midi | `audio/*` |
| `video` | ISO media (`ftyp`), Matroska/WebM, AVI, Ogg Theora | mp4 m4v mov webm mkv avi ogv wmv flv 3gp | `video/*` |
| `documents` | PDF; SVG markup; ZIP containers with a document extension | pdf txt md markdown csv tsv json xml yaml yml toml ini cfg conf log rtf doc docx odt xls xlsx ods ppt pptx odp epub srt vtt svg svgz | `text/*`, PDF, JSON, XML, RTF, Office, OpenDocument, `image/svg+xml` |
| `archives` | ZIP, 7z, RAR, gzip, bzip2, xz, zstd, tar | zip 7z rar tar gz tgz bz2 tbz2 xz txz zst lz lzma | zip, 7z, rar, tar, gzip, bzip2, xz, zstd |
| `other` | everything else | | |

**Executables and dangerous types** count as `other` and are flagged: Windows/ELF/Mach-O/DEX executables, `#!`
scripts, Java classes, Windows shortcuts and ISO 9660/DMG images by content; the extensions exe msi msix msp appx
appxbundle bat cmd com pif scr cpl hta reg lnk url inf ps1 psm1 psd1 vbs vbe js jse mjs wsf wsh wsc sct jar class
apk aab xapk ipa dmg pkg mpkg app command sh bash zsh csh ksh fish run bin elf deb rpm snap flatpakref appimage iso
img vhd vhdx xll docm xlsm pptm dotm xltm potm ppam xlam gadget msc application scf dll sys drv ocx py pyw pl rb php
desktop workflow action website settingcontent-ms; and executable content types (`application/x-msdownload`,
`application/x-sh`, `application/java-archive`, `application/vnd.android.package-archive`, JavaScript, …).
Content or extension alone is enough (`setup.png` with an `MZ` header is an executable, so is `photo.exe`).
They are refused unless the node sets `TAVRN_UPLOAD_ALLOW_EXECUTABLES=true` **and** the member may upload `other`.

**SVG (design note 4.12)** can carry scripts, so it is a `documents` upload, never an image: by content (markup that
starts with `<` and contains `<svg` in the first KiB), by extension (`svg`, `svgz`) or by type. The node stores a
plaintext SVG as `image/svg+xml` whatever type was declared and serves it, like every blob, only with
`Content-Disposition: attachment`, `X-Content-Type-Options: nosniff` and `Content-Security-Policy: default-src
'none'; sandbox`. Clients must never render SVG attachments inline nor open them as a document (no viewer, no
"open original"); they offer the download only. This also holds for encrypted attachments whose content
declares `image/svg+xml` or an `.svg` name. Object URLs that clients create for attachments keep only the type
of raster images, audio and video; everything else gets `application/octet-stream`.

**Automatic previews (design note 4.12).** `PATCH /users/me { auto_preview }` (`always`, `friends_and_shared` (default)
or `never`; `400 validation.enum` otherwise) stores the user's setting on the home node; `GET`/`PATCH /users/me`
return it. `GET /node` (`preview_auto_max_bytes`) and `/.well-known/tavrn` (`policies.preview_auto_max_bytes`)
publish the node's cap (`TAVRN_PREVIEW_AUTO_MAX_BYTES`, default 5 MiB). Clients load an image preview without a
click only if the setting allows it for the author (own messages; in room channels every author is a member of
a shared room; in DMs and group DMs friends) and the image is at most the cap; otherwise they show a
placeholder with name, size and a load button and fetch nothing. Audio, video and other files load on demand
anyway.

**Who may upload what:** roles carry `allowed_upload_categories` (array of names; null = not set; `@everyone`
always has a value, default all six), channel and category overrides carry `upload_allow`/`upload_deny`
(`PUT /rooms/{id}/overrides`; absent = unchanged; allowing and denying the same category is
`400 override.conflict`). Evaluation: `permissions.md` "Upload categories". DMs and group DMs use the node's
`TAVRN_UPLOAD_DM_CATEGORIES` (default all). The node's `TAVRN_UPLOAD_ALLOWED_TYPES` (MIME allowlist for
plaintext uploads) still applies on top.

- `GET /conversations/{conversation_id}/upload-policy` → `{ allowed_categories, executables_allowed, max_bytes,
  can_attach }` for the requester (composer file pickers filter with it).
- Refusal: `403 upload.type_forbidden` with `meta { category, executable, allowed_categories }`.

`:name:` tokens in `body` refer to the room's custom emojis. `gif` is only accepted when the URL points to the
node's configured GIF provider. Custom emoji tokens by id, spoilers and attachment spoilers: §7b.

## 7b. Custom emojis, spoilers (design note 4.13)

**Emoji tokens.** `body` and reactions name custom emojis as `<:name:ID>` (an emoji of the node hosting the
conversation) or `<:name:ID@host>` (an emoji hosted on `host`): `name` = 2–32 of `a-z0-9_`, `ID` = the canonical
(uppercase) ULID, `host` = lowercase DNS labels with an optional `:port`, nothing else (no `/`, `?`, `@`,
brackets). Anything not matching exactly is plain text. Readers load the image from
`GET https://<host>/api/v1/emojis/{ID}/image` (`?still=1`: the first frame of an animated emoji). `:name:` keeps
meaning the current room's emoji. Reactions are a Unicode emoji (1–16 characters, no whitespace or `<>`),
`:name:` or a token (`400 reaction.invalid` otherwise).

**External use.** An emoji that is not one of the current room's (personal emojis, other rooms, other nodes) is
external: room channels need `use_external_emojis` (bit 31), DMs and group DMs always allow it. The node checks
reactions and plaintext bodies on create and edit (`403 emoji.external_forbidden`); encrypted bodies are checked
by clients, which also grey such emojis out in the picker. Clips: `POST /rooms/{id}/channels/{channel_id}/soundboard/play
{ sound_id, host? }` → `{ external, emoji }`, `use_soundboard` + `speak`, and `use_external_sounds` (bit 32) for
any clip that is not the room's (`403 soundboard.external_forbidden`). Clients call it before mixing a clip into
their microphone (cooperative: the SFU cannot stop a modified client).

**Personal emojis and clips** (home node, local users only, `federation.local_only` otherwise):
`GET/POST /users/me/emojis` (`Tavrn-Emoji-Name`, image body), `PATCH /users/me/emojis/{id} { name }`,
`DELETE …`; `GET/POST /users/me/sounds` (`Tavrn-Sound-Name`, `Tavrn-Sound-Duration-Ms`, optional
`Tavrn-Sound-Emoji`, percent-encoded), `PATCH /users/me/sounds/{id} { name?, emoji? }`, `DELETE …`. Limits per
user (`403 emoji.limit`, `403 soundboard.limit`); the lists carry `max_personal`. Room clips:
`PATCH /rooms/{id}/soundboard/{sound_id} { name?, emoji? }` (`manage_emojis`). The `emoji` of a clip is a Unicode
emoji or a token (`400 soundboard.emoji_invalid`).

**Conversion.** Every uploaded emoji (room and personal) is converted by the node: WebP, at most 128 px,
at most 256 KiB per variant, animations cut to 5 s and 60 frames, plus a still variant; `animated` in the JSON.
Animated input above 1024 px or with more than 1000 GIF frames, and videos, are refused before decoding.

**Public bytes.** `GET /emojis/{id}/image` and `GET /sounds/{id}/audio` serve every emoji and clip of the node
(room and personal) without authentication: `Cache-Control: public, max-age=31536000, immutable`,
`X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'; sandbox`,
`Cross-Origin-Resource-Policy: cross-origin`, an `ETag` (`If-None-Match` → `304`), and only image (WebP/PNG/GIF/JPEG)
or `audio/*` types. Ids are random; the responses reveal nothing about rooms or owners.

**Other nodes' emojis and clips.** Clients never load bytes from foreign nodes. A token `<:name:ID@host>` is loaded
from the node the client talks to for that conversation as `GET /emojis/{ID}/image?host=<host>` (clips:
`GET /sounds/{ID}/audio?host=<host>`; `host` = that node itself is the local route). The node fetches the bytes
from the origin once over the federation client (domain policy, public addresses only, redirects only to the same
origin, 5 s, at most 256 KiB for emojis and 1 MiB for clips, `image/*` checked by content, `audio/*` for clips),
keeps a copy (`remote_emoji_cache`) and serves it like its own (ETag `ID@host`). Errors: `400 media.host_invalid`,
`404 media.remote_not_found` (the origin has no such file and there is no copy), `502 media.remote_unavailable`.
Deletion at the origin does not reach copies, so messages stay readable; copies unused for
`TAVRN_MEDIA_CACHE_UNUSED_DAYS` (default 365, `0` = never; last use recorded at most once a day) are evicted, and
node admins purge one with `DELETE /admin/media-cache/{host}/{ID}` (audited as `media_cache.purge`). Clients show a
token whose image cannot be loaded as a muted `:name:` placeholder ("emoji no longer available") and a clip that
cannot be loaded as a short notice. A soundboard play of a clip of another node names it as `{ sound_id, host }`.

**Spoilers.** `||text||` in `body` hides the text until the reader reveals it (inline, also inside quotes and
lists). Attachments: plaintext messages send `spoilers: [attachment ids]` (a subset of `attachments`,
`400 message.spoiler_invalid` otherwise) and the envelope returns `spoiler: true` on those attachments;
encrypted messages carry `"spoiler": true` in the entry of `content.attachments` (ENCRYPTION.md §6). Clients
blur images and videos and hide other files (with their names) until clicked.

**Deleted accounts.** `author_deleted: true` marks a message whose author deleted the account (§5d): `author` names the
tombstone, `device_id` and `signature` are null. Content `{"type":"system.deleted"}` (with `encrypted: false`) means the
content was deleted with the account; the slot stays so replies and threads keep their place.

**Deleted originals.** `reply_to_id` stays when the original is deleted; the node then sets `reply_deleted: true`
and clients show "message deleted" (never a copy of the original).

## 7b. Link previews and embeds (design note 4.13 item 7)

Two independent mechanisms; neither makes readers or the hosting node fetch anything on their own.

**Sender-generated preview.** The content object of `text` (and `action`) may carry

```json
{ "type": "text", "body": "Read https://news.example/a",
  "preview": { "url": "https://news.example/a", "title": "…", "description": "…", "site": "News", "image": "data:image/webp;base64,…" } }
```

`url` must be one of the http(s) links in `body` as written (readers show the card only then, so a preview never
points somewhere the text does not show); `title` ≤ 300, `description` ≤ 500, `site` ≤ 200 characters; `image`
is optional and only a `data:image/webp|png|jpeg;base64,` URL (≤ 60 KiB as text). In encrypted conversations the
preview is part of the encrypted content; in plaintext conversations it is covered by the device signature like
every content field (FEDERATION.md §10.3) and the node checks the shape (`400 message.preview_invalid`). Clients
validate it again before rendering, open the link with `rel="noopener noreferrer"` and never load anything for it.
The whole content still has to fit `message.too_large` (64 KiB; clients drop the image first).

The sender's client builds the preview with its **home node**:

- `GET /api/v1/unfurl?url=<http(s) URL>` (session of a local user; federated sessions get
  `403 federation.local_only`, bots are refused by the route table) → `200 { url, title, description, site,
  image_data_url? }`. The node fetches the page itself: http/https only, no credentials in the URL, ports 80, 443,
  8080 and 8443, every address (IP literal or every DNS answer, on every redirect hop) must be public unicast
  (FEDERATION.md §1.3 rule 3; the connection uses the vetted addresses only), at most 3 redirects, 5 seconds in
  total, at most 1 MiB of `text/html` read, OpenGraph, Twitter card, `<title>` and `<meta name="description">`
  parsed. The `og:image` (same rules, ≤ 5 MiB, raster formats only) is converted by the media pipeline to a WebP of
  at most 400 px and 40 KiB. Answers are cached for an hour (failures five minutes), 30 requests per user and
  minute. Errors: `400 unfurl.url_invalid`, `400 unfurl.address_forbidden`, `415 unfurl.not_html`,
  `502 unfurl.fetch_failed`, `502 unfurl.timeout`, `404 unfurl.disabled` (`TAVRN_UNFURL=off`), `429`.

**Embeds.** Clients may recognise allow-listed provider URLs in `body` (YouTube incl. Shorts, Twitch channels,
videos and clips, Vimeo, Spotify tracks, albums, playlists and episodes) and offer a click-to-play player from
`https://www.youtube-nocookie.com`, `https://player.twitch.tv`, `https://clips.twitch.tv`, `https://player.vimeo.com`
or `https://open.spotify.com/embed`; the reference client's CSP `frame-src` lists exactly these (besides the
captcha). Nothing is part of the content; a provider thumbnail or player reveals the reader's IP address to the
provider, so clients load them only by the reader's setting and never before the card is visible.

## 7d. Message search (design note 4.4, `search.v1`)

Two paths, one search box (details, index format and privacy guarantees: `SEARCH.md`):

- **Unencrypted channels: the node.** `GET /rooms/{room_id}/search?q=&channel=&author=&before=&after=&has=file&sort=&cursor=&limit=`
  (bearer token; app tokens need the scope `messages:read`) searches the plaintext `text` and `action` messages of the
  room's unencrypted channels: body, embed titles, descriptions and fields, attachment file names. Encrypted channels
  are never indexed; switching a channel to encrypted drops its rows, switching it back indexes its plaintext again.
  Deletes, purges and channel deletions remove the rows with the messages.
  - `q`: at most 256 characters, split into words (letters and digits); every word is a required prefix, case- and
    (through folded variants) diacritic-insensitive. Nothing the user types is query syntax: quotes, parentheses,
    `*`, `OR`, `NEAR`, `:` are separators or plain words. At most 16 words are used. `q` may be empty when a filter is
    set (`400 search.query_empty` otherwise; `400 search.query_too_long`).
  - Filters: `channel` (a channel id of the room), `author` (`user@domain`; an unknown address matches nothing),
    `after`/`before` (RFC 3339 or `YYYY-MM-DD`, UTC; `after` inclusive, `before` exclusive), `has=file`. Order
    `sort=newest` (default, cursor = the last message id) or `sort=relevance` (cursor `o<offset>`, at most 500 deep).
    `limit` 1–50 (default 25). Errors: `400 search.date_invalid`, `search.has_invalid`, `search.sort_invalid`,
    `search.author_invalid`, `search.cursor_invalid`, `validation.id`.
  - Access: room members (and node admins) only (`403 room.not_member`); per channel `view_channel` (and the bot rules
    of "no bots"); without `read_history` only messages from the member's join on. Hidden channels are left out
    silently, also when asked for with `channel`.
  - Response `200 { results: [{ message, snippet, rank }], next_cursor, searched: { kind: "node", channels } }`:
    `message` is the envelope of §7, `snippet` plain text of about 130 characters around the first match with every
    match wrapped in U+0001 … U+0002 (never markup; clients render the markers and escape the rest), `searched.channels`
    the number of channels searched (clients show it).
  - Limits: `TAVRN_SEARCH_RATE_PER_MINUTE` requests per user and minute (default 30, `429`), `TAVRN_SEARCH_ENABLED=false`
    removes the route (`404 search.disabled`) and the capability. Search queries are never logged.
- **Encrypted channels and DMs: the client's local encrypted index.** DMs and group DMs are always encrypted, so there
  is no node search for them (no `/conversations/{id}/search`). Clients index what they decrypt (text and file names
  only) in a local index sealed under the local store key and search it on the device.

## 7e. Threads, forum and announcement channels (design notes 4.3, 4.4; `threads`, `forum`, `announcement`)

Nodes announce the capabilities `threads`, `forum` and `announcement` when they implement this section. A
**thread** is a sub-conversation inside a room channel: its messages are ordinary messages of the channel whose
envelope carries `thread_id`. They live in the same conversation, so an encrypted channel's threads use the
channel's MLS group and epochs (no new groups, no new keys); history sharing (`ENCRYPTION.md` §7b), the search
index (§7d), pins, reactions, bots and the channel's permission checks work for them unchanged. Threads exist in
channels of kind `text`, `announcement` and `forum` (`400 thread.unsupported_channel` elsewhere; DMs and group DMs
have none, a `thread_id` there is `404 thread.not_found`). Threads live on the node hosting the room; members of
other nodes use the same routes with their federated session. Nothing crosses node boundaries.

**The thread object.**

```json
{ "id": "01J…", "room_id": "01J…", "channel_id": "01J…",
  "root_message_id": "01J…", "root_deleted": false,
  "encrypted": true, "title": "<plaintext, or ciphertext in encrypted channels>", "title_epoch": 7,
  "title_author": "alice@node.example", "title_device_id": "01J…",
  "tags": ["01J…"], "created_by": "alice@node.example", "created_by_id": "01J…", "created_at": "…",
  "last_message_id": "01J…", "last_message_at": "…", "message_count": 12, "participant_ids": ["01J…"],
  "archived_at": null, "locked": false,
  "me": { "following": true, "last_read_message_id": "01J…", "unread_count": 0, "mention_count": 0 },
  "root_message": { "…": "message envelope (§7)" }, "first_message": null }
```

- `root_message_id`: the channel message a text-channel thread was started from (it stays in the channel, with
  `thread_id` null); null for standalone threads and forum posts. One thread per root message. When the root is
  deleted the thread stays, `root_deleted` becomes true and clients show "(original message deleted)".
- **Titles** are 1–100 characters. In encrypted channels the node never sees them: `title` is encrypted content
  format 1 (`ENCRYPTION.md` §5.2) of the JSON object `{ "type": "thread.title", "body": "<title>" }`, encrypted and
  signed by the device that set it (`title_author`, `title_device_id`) under `title_epoch`; the node applies the
  ciphertext checks of `ENCRYPTION.md` §5.3 (`400 thread.title_invalid` for a malformed one, at most 2048
  characters, plus `message.epoch_mismatch`, `message.epoch_unknown`, `e2ee.device_not_attested`) and clients
  decrypt and verify it like message content and drop anything whose `type` is not `thread.title` or whose body is
  longer than 100 characters. In unencrypted channels `title` is plaintext (trimmed, 1–100 characters,
  `400 thread.title_invalid`) and `title_epoch` is null. `encrypted` says which of the two the stored title is
  (a channel switched to or from encryption keeps its old titles until they are renamed).
- `tags`: forum posts only, ids out of the channel's tag list (below). `message_count` counts the thread's
  messages (the root not included); `participant_ids` names up to three users who wrote in the thread most
  recently (newest first), for avatars.
- `archived_at`: archived threads are hidden from the default list and reopen with the next message (unless
  locked). `locked`: only members with `manage_threads` can write in it.
- `me` (the requester's state, absent in events): `following`, the per-thread read marker and the unread and
  mention counts of followed threads (both 0 for threads the user does not follow; mentions and the notification
  settings of the channel apply as in §6).
- `root_message` (text threads) and `first_message` (forum posts: the oldest message of the thread, the "preview"
  of a post card) are the enriched envelopes the requester may see (the history cut of `ENCRYPTION.md` §7b applies;
  null otherwise). Messages carry a summary of the thread they started in `thread`
  (`{ id, message_count, last_message_id, last_message_at, participant_ids, archived_at, locked }`, absent on
  other messages), so clients can render "N replies · last reply 5 min ago" under the root.

**Routes** (all need room membership and `view_channel`, `403 room.not_member` / `channel.view_forbidden`):

- `POST /rooms/{room_id}/channels/{channel_id}/threads { id?, title, title_epoch?, root_message_id?, tags?, message? }`
  → `201 Thread`. `message` is a message create body (§7, `POST …/messages`) posted as the thread's first message.
  `id` is the thread id chosen by the client, so the device signature of a plaintext first message
  (`FEDERATION.md` §10.3) covers its `thread_id` like every other message of the thread: a ULID in its canonical
  form (26 characters, uppercase) whose time lies within 10 minutes of the node's clock (`400 thread.id_invalid`),
  not used by another thread (`409 thread.id_taken`; pick a new one). Without `id` the node picks it and the first
  message cannot be signed. Clients send `id` whenever they send `message` and the node announces
  `threads.client_ids` (§3).
  Text and announcement channels: `send_messages` and `create_threads` (`403 message.send_forbidden`,
  `403 thread.create_forbidden`); `root_message_id` must be a message of the channel outside any thread (`400 thread.root_invalid`), at most one thread per root
  (`409 thread.exists`, `meta.thread_id`); `tags` are refused (`400 thread.tags_invalid`). Forum channels (a post):
  `send_messages` (`403 message.send_forbidden`; `create_threads` is not needed there), `message` is required
  (`400 thread.message_required`), no root, at most 5 tags of the channel (`400 thread.tags_invalid`). The creator
  follows the thread. Rate limit: 10 threads per user and minute (`429`). Events: `thread.create`, then
  `message.create` for the first message.
- `GET /rooms/{room_id}/channels/{channel_id}/threads?archived=&tag=&sort=&before=&limit=` →
  `{ items: [Thread], next }`. `archived`: `false` (default: active threads), `true` (archived only) or `all`;
  `sort`: `activity` (default, newest `last_message_at` first) or `created` (newest first); `tag`: forum posts
  carrying this tag; `before`: the id of the last thread of the previous page; `limit` 1–50 (default 25). Errors:
  `400 thread.filter_invalid`, `400 validation.id`.
- `GET /threads/{thread_id}` → `Thread`; `404 thread.not_found` for unknown threads and threads of channels the
  requester cannot view.
- `PATCH /threads/{thread_id} { title?, title_epoch?, tags?, archived?, locked? }` → `Thread`: the thread's creator
  or `manage_threads` (`403 thread.manage_forbidden`); `tags` only in forum channels (others' posts with
  `manage_threads`). Changes by someone other than the creator are audit-logged (`thread.update`). Event
  `thread.update`.
- `DELETE /threads/{thread_id}` → `204`: deletes the thread with all its messages and their uploads permanently
  (the root message stays in the channel). Its creator may delete it while it contains only their own messages,
  otherwise `manage_threads` is needed (`403 thread.delete_forbidden`). Audit-logged (`thread.delete`, with the
  number of deleted messages); event `thread.delete`.
- `PUT /threads/{thread_id}/read { last_read_message_id }` → `ThreadReadState`
  (`{ thread_id, channel_id, room_id, following, last_read_message_id, unread_count, mention_count }`): moves the
  per-thread read marker forward (never backwards; the message must belong to the thread, `404 message.not_found`),
  rate-limited like `PUT …/read`. The user's connections get `thread.read` with the same object.
- `POST /threads/{thread_id}/follow` and `DELETE /threads/{thread_id}/follow` → `ThreadReadState`: follow or
  unfollow; `thread.read` to the user's connections. Creating a thread or writing in it follows it automatically.
- `GET /rooms/{room_id}/followed-threads` → `{ items: [ThreadReadState] }`: the requester's followed threads in
  channels they can view, most recent activity first, at most 200 (clients use it for badges and to decide which
  thread messages notify).
- **Messages.** `POST …/messages { …, thread_id }` writes into a thread: it needs what a channel message needs plus
  `create_threads` in text and announcement channels (`403 thread.reply_forbidden`; forum channels need only
  `send_messages`), a locked thread needs `manage_threads` (`403 thread.locked`), and an archived thread reopens
  (`thread.update`). `thread_id` cannot change on edit. `GET …/messages?thread=<thread_id>` pages one thread like a
  channel (`before`, `after`, `around`, the history cut); without `thread` the channel's list leaves thread
  messages out (`epoch=<n>` lists the epoch's messages of the whole channel, threads included, for the key checks of
  `ENCRYPTION.md` §7b; `threads=all` lists the channel with its threads, for clients that sync a local search index;
  `400 thread.filter_invalid` for other values or together with `thread`). Deleting a message of a thread updates its counters.
- **Read state.** Thread messages count towards the channel's `unread_count` and `mention_count` (§6) only for users
  who follow the thread (counted after the thread's read marker, or after following when there is none); the
  channel's `last_message_id` and its own marker ignore thread messages. `notify` hints (`FEDERATION.md` §5.2) for a
  thread message go to followers (and to users it mentions directly); `@everyone` inside a thread reaches followers
  only. Clients apply the same rule to their in-app notifications.

**Events** (room members who can view the channel unless noted): `thread.create { room_id, thread }`, `thread.update { room_id, thread }`
(rename, tags, archive, lock, new messages: counters and `last_message_*`), `thread.delete { room_id, channel_id,
id }`, `thread.read` (the user's own connections: a `ThreadReadState`). `message.*` events of thread messages carry
`thread_id` in the envelope. Bots receive `thread.*` with the scope `messages:read`.

**Auto-archive.** Channels carry `auto_archive_minutes` (60–43200, default 10080 = 7 days; `PATCH
/rooms/{room_id}/channels/{channel_id}` with `manage_channels`, `400 validation.range`). The node archives every
thread whose last activity is older than that (hourly housekeeping, `thread.update` per thread).

**Forum channels** (`kind = "forum"`): the channel itself has no messages outside threads
(`400 message.thread_required`); every post is a thread with a title, a first message and tags. Channels carry
`tags` `[{ id, name, emoji }]`: at most 20, names 1–32 characters, unique ignoring case, `emoji` null, a Unicode
emoji or a custom emoji token (§7b); replaced as a whole with `PATCH …/channels/{channel_id} { tags: [{ id?, name,
emoji? }] }` (`manage_channels`; entries without `id` get a new one; `400 channel.tags_invalid`), audit-logged as
`channel.tags`. A post's tags change with `PATCH /threads/{id} { tags }`. Tag ids of deleted tags are dropped from
the posts' `tags` when they are returned. Tag names are channel metadata and never encrypted; the titles and messages
of posts in encrypted forums are.

**Announcement channels** (`kind = "announcement"`): writing outside threads needs `manage_messages` in addition to
`send_messages` (`403 message.announcement_forbidden`); everybody else may react and reply in threads
(`create_threads`). Clients show a notice instead of the composer to members who cannot post. Cross-posting to
other rooms is not part of v1.

**Permissions** (`permissions.md`): `create_threads` (bit 6) starts threads and writes in them; `manage_threads`
(bit 36) renames, archives, locks and deletes other people's threads and edits the tags of any post;
`manage_messages` keeps deleting single messages.

**Privacy.** The node sees the thread structure (which message started a thread, which messages belong to which
thread, counters, tags, archive and lock state) like the reply references of §7, never the content or the titles of
threads in encrypted channels. A title ciphertext is bound to the conversation, epoch and setting device like
message content (`ENCRYPTION.md` §5.4) but not to one thread: a hostile node could show one of the author's titles
on another thread of the same channel; clients treat titles as display text only.

## 7f. Message retention

A node may delete old messages (`TAVRN_RETENTION_DAYS`, default `0` = keep forever, at most 36500): its hourly
housekeeping deletes messages of the channels, DMs and group DMs it hosts, encrypted or not, once they are older than
the retention of their conversation, together with their attachments, reactions, pins and search entries; threads
count their messages again (§7e).

- A room may set a **shorter** retention for its channels: `PATCH /rooms/{room_id} { message_retention_days }`
  (owner or `manage_room`, 1–36500, `0` = the node's value, `400 validation.range` otherwise; audited in `room.update`
  with `meta.message_retention_days`). Room objects carry `message_retention_days` (null = the node's value). The
  effective retention is the shorter non-zero of the room's and the node's value: a room can never extend the node's.
- Never deleted by retention: **pinned** messages (unpinning lets them expire) and the entries of the room's
  **welcome channel** (the room's security log, `MODERATION.md` §3).
- The node writes one node audit entry `retention.messages { deleted, node_days, rooms, incomplete }` per run that
  deleted something. Clients get no event: what they already loaded stays until they reload. Attachment retention
  (`ENTITLEMENTS.md` §6) is separate and may delete files earlier.
- `GET /node` names the node value as `message_retention_days` (clients show it next to the room setting); the
  account's data summary (`LEGAL.md` §3.1, `GET /users/me/data`) as `retention.message_retention_days`.

## 8. Encryption marker (mandatory for all clients)

If a channel has `encrypted = false`, every client **must** permanently and clearly show a notice above the
message area, along the lines of: *"This channel is not end-to-end encrypted. The operator of node.example can
read along."* Additionally the channel is marked with a crossed-out lock in lists. Direct messages, group DMs
and voice channels are always encrypted and have no such flag. Files channels follow their `encrypted` flag, which is
fixed at creation (`FILES.md` §1); for unencrypted ones clients show "Files in this channel are not end-to-end
encrypted" permanently above the file list.

## 8a. Direct messages, group DMs and friends

- **Conversations** are channels of rooms, direct messages (`dm`, exactly two users) and group DMs (`group`,
  2–50 users). Messages, reactions, pins, uploads and the MLS delivery service of every conversation live under
  `/api/v1/conversations/{conversation_id}/…`; room channels are additionally reachable under
  `/rooms/{room_id}/channels/{channel_id}/…`. DMs and group DMs are always encrypted; the node rejects plaintext.
- `POST /conversations { kind, members, name? }` creates a group DM or returns the existing DM of the two users
  (`200`). DMs and group DMs are visible to their members only (`404 conversation.not_found` otherwise). Any
  member may add members to a group DM and rename it (`PATCH /conversations/{id} { name }`, empty removes the
  name); members may leave; the creator may remove others. Typing notices, read markers and unread counts
  work as in channels (§6).
- **Who may start a DM** (design note 4.9): every user chooses `dm_policy` ("Who can message me": `friends`,
  `everyone_shared` = friends and people who share a room of the deciding node, `everyone`; default
  `everyone_shared`); the node's `dm_policy` (`GET /node`, default `everyone`, `open` = old name of
  `everyone`) is the upper bound. Friends and the owner of a bot always get a normal conversation. Bots live in
  1:1 DMs only: a group DM with a bot (creating one or adding a bot) is refused with `400 app.bot_forbidden`. Anybody else
  gets a **message request**: the conversation is created, the recipient's membership is `requested`
  (`Conversation.pending` lists such members). Refusals: `403 dm.not_friends` (the node allows only friends),
  `dm.friends_only` (the recipient allows only friends; clients offer a friend request instead),
  `dm.no_shared_room`, `dm.blocked`. Blocks (`POST /users/me/blocks`) always win: a blocked user cannot send
  friend requests, start DMs or write in an existing DM with the blocking user.
- **Message requests**: `GET /conversations/requests` → `[{ conversation, from, shared_rooms, first_message_id
  }]` (not in `GET /conversations`); the WS event `conversation.request` announces new ones. A requested member
  may read the conversation (the preview) but gets no `message.*` events, no unread counts and no push hints,
  and cannot write (`403 conversation.request_pending`). `POST /conversations/{id}/accept` makes it a normal
  conversation (idempotent; `conversation.update` to the members). `POST /conversations/{id}/decline { block?,
  reason? }` removes the member (the sender is not told; `409 conversation.not_requested` for accepted ones),
  optionally blocking the creator with a private note. A declined DM is not offered again: `POST
  /conversations` with the same person returns the existing DM (200) and adds the other side back only once
  the two are friends.
- **Friend request messages and block notes**: `POST /users/me/friends/requests { user, message? }` (≤ 256
  characters, shown in `FriendRequest.message`, also across nodes); `POST /users/me/blocks { user, reason? }`
  (≤ 256, private; blocking again updates it); `GET /users/me/blocks` → `[{ user, reason, created_at }]`.
- **Friends**: requests are accepted by the recipient; a request to someone who already asked accepts both.
  `GET /users/me/friends` lists friends, incoming and outgoing requests and blocked users.
- **Members of other nodes** (`FEDERATION.md` §6): friends, blocks, DMs and group DMs take addresses of any node
  (`bob@b.example`). A DM or group DM lives on the home node of its creator; remote members are members from the
  start, receive a `conversation.invite` in the invite list of their home node and use the conversation on the
  hosting node with a federated session (messages, MLS, Welcomes, adding members to group DMs). Friendships are
  stored on both home nodes, and both nodes apply their `dm_policy` and blocks: the hosting node when the DM is
  created or a member is added, the recipient's home node before it shows the invitation. Member lists show remote
  members with their full address; their user ids are local to the hosting node.

## 9. Federation

Normative: `FEDERATION.md` (capability `federation.v1`), which replaces the earlier route sketch of this
section. Invariants worth repeating:

- Only a user's home node issues federation tokens for that user (`POST /api/v1/federation/token`, full session);
  the target node verifies them against the home node's `.well-known` keys and issues its own session
  (`POST /api/v1/auth/federated`).
- Server-to-server notifications go to `POST /api/v1/federation/inbox`, signed with `s2s` tokens (§5), and are
  idempotent by message id.
- Nothing in the room and conversation API changes: users of other nodes use it with their session on the
  hosting node.
- Room and conversation ids are only unique per node. Clients qualify them with the hosting domain wherever
  they leave one node's context; the reference web client keeps the home node's routes (`/rooms/<id>/…`)
  and puts rooms of other nodes under `/n/<domain>/rooms/<id>/…` (`FEDERATION.md` §13.2).

## 10. Permissions

Bit mask (u64) as a decimal string. Bit positions, defaults, evaluation order and hierarchy rules are
normative in `permissions.md`; reference test vectors live in `testvectors/permissions.json` and must be passed
by server and client.

Overrides (`PUT /rooms/{room_id}/overrides`, `manage_roles`) are layered: the category's overrides apply to the
role base, the channel's own overrides on top, and a neutral bit inherits from the layer below (`permissions.md`
"Evaluation"). They carry only channel-scoped bits (`CHANNEL_SCOPED`, `400 permissions.not_channel_scoped`).
Channels no longer have `sync_with_category` (`PATCH` ignores the field for one release, `GET` does not return it).
Setting an override with `allow = deny = "0"` and empty `upload_allow`/`upload_deny` removes it; a client "resets a
channel to its category" by removing each of the channel's own overrides.
