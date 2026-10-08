# tavrn applications, bots, commands, webhooks and SSO (`apps.v1`, `commands.v1`, `webhooks.v1`, `sso.oidc`, draft v1)

License: CC-BY-4.0 (this text; schemas, test vectors and permission tables Apache-2.0, see `LICENSE.md`). This document is normative for nodes and clients that announce the capabilities `apps.v1`,
`commands.v1`, `webhooks.v1` or `sso.oidc` (§10). It refines the design notes 4.2 (single sign-on),
4.6 (moderation), 4.7 (API, bots, applications), 4.9 (activity), 4.11 (slash commands) and 9b–9d, and extends
`PROTOCOL.md` (§1 identity, §3 capabilities, §5/§5a tokens and authentication, §6 events, §7 envelope),
`ENCRYPTION.md` (§2–§4, §9) and `FEDERATION.md` (§2, §3, §5). Where this document adds fields, routes or
event types to those documents, §10.2 lists the additions; they are compatible extensions in the sense of
`PROTOCOL.md` §3.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in RFC 2119. Byte-string notation and
base64url (without padding) are the ones of `ENCRYPTION.md` §0. All routes are relative to `/api/v1`; errors are
Problem Details with stable `code`s (`PROTOCOL.md` §4).

## 0. Principles and terms

- **An application is a bot account with an owner.** A bot is a user row with `kind = "bot"` on its owner's home
  node, with its own address (`weatherbot@node.example`), profile, devices and MLS keys. There is no second kind of
  principal: everything a bot does goes through the normal client API and the normal permission evaluation
  (`permissions.md`), additionally capped by the **scopes** of its token (§2.4).
- **Owner**: the local user who created the application (or accepted its transfer). Owners are always local users of
  the bot's home node; remote users cannot create or own applications.
- **Bot home node (H)**: the node of the bot account. It issues app tokens, holds the application record, the
  command definitions, the interactions URL and the event subscription. **Room node (T)**: the node of a room the
  bot is installed in (H itself or another node, reached with a federated session exactly like a remote user,
  `FEDERATION.md` §2.5).
- **Application reference**: `<H domain>/<application ULID>` (e.g. `node.example/01J9…`). Application ids are
  node-local; wherever an id leaves its node it is qualified this way.
- **Installation**: the membership of a bot in a room, created only through the add flow (§4). Bots never join rooms
  by themselves.
- **Webhook**: a write-only URL that posts messages into one channel, sealed for the members in encrypted channels
  (§6.1, §6.1a). Webhooks are not bots and have no token, no device and no read access.
- **Trust**: a bot token is a single factor without a second factor. Everything in this document follows from
  that: tokens are capped by scopes, rooms can declare "no bots" zones (§3.5), a leaked token can never redirect
  event streams (§6.2) or take over the owner's account, and every bot action is attributable to its application
  in the audit log (§9.2).

## 1. Applications and bot accounts

### 1.1 Data model

```
applications(id, bot_user_id, owner_id, name, description, public, requested_permissions, scopes,
             interactions_url, rpc_origins, commands_version, disabled_at, disabled_reason, created_at)
application_tokens(id, application_id, device_id, name, scopes, jti, token_hash, prev_jti, prev_valid_until,
                   created_at, expires_at, last_used_at, revoked_at)
application_commands(id, application_id, name, definition (JSON), definition_hash, created_at, updated_at)
application_installations(id, room_id, application_ref, bot_user_id, role_id, permissions, installed_by,
                          installed_at)                                  -- on the room node
application_install_index(application_id, node, room_id, room_name, installed_at)  -- on H, for the bot
room_command_settings(room_id, command_ref, enabled, permissions, allowed_roles, disabled_channels)
command_approvals(application_ref, definition_hash, approved_by, approved_at)
application_subscriptions(application_id, url, events, state, last_success_at, last_error, created_at)
application_outbox(id, application_id, event_id, body, attempts, next_at, expires_at, last_error)
application_blocks(subject, reason, created_by, created_at)              -- subject = bot address
application_transfers(application_id, from_user_id, to_user_id, created_at, expires_at)
webhooks(id, room_id, channel_id, user_id, name, token_hash, allow_mentions_everyone, suspended,
         created_by, created_at, last_used_at)
external_identities(user_id, issuer, subject, linked_at, last_login_at)  -- SSO, §8
sso_grants(user_id, kind, room_id, role_id, grp, granted_at)             -- what an SSO sync granted, §8.5
```

`users.kind` takes `user`, `bot` or `webhook` (§6.1); `users.owner_id` references the owner for bots and the
creator for webhook users. The columns `kind` and `owner_id` exist since phase 1.

### 1.2 Who may create applications

| Variable | Default | Meaning |
|---|---|---|
| `TAVRN_APP_CREATION` | `all` | `all`: every local user; `invite`: users with an application grant (`PATCH /admin/users/{id} { app_creation_grant: n }`, consumed per creation, or granted by an SSO group, §8.5); `admins`: node admins only |
| `TAVRN_APPS_PER_USER` | `5` | applications per owner (0–100); node admins are not exempt |

Only local users with a full session (password and second factor, passkey, or SSO) create applications; remote users
get `403 federation.local_only`, bots `403 app.bot_forbidden`, and disabled users cannot sign in at all.

### 1.3 Creating an application

`POST /applications` (full session of a local user; local-only route, `FEDERATION.md` §2.8)

```json
{ "name": "WeatherBot", "username": "weatherbot", "description": "Forecasts on demand",
  "public": false, "requested_permissions": "3", "scopes": ["messages:read", "messages:write", "commands"] }
```

- `name`: 2–32 characters of free text (the bot's display name). `username`: optional; the bot's immutable
  username, grammar of `PROTOCOL.md` §1, unique in the node's user namespace (`409 app.username_taken`); when
  absent the node derives it from `name` (lowercase, invalid characters → `-`, suffix `-2`, `-3`, … on collision).
  `description`: at most 400 characters (Markdown subset like the profile bio).
- `public`: `true` lets every room manager with the add link install it; `false` restricts installation to the
  owner (§4.2).
- `requested_permissions`: decimal permission mask the add flow proposes (§4). It MUST NOT contain
  `administrator` (`400 app.permissions_invalid`): a one-click administrator grant to a single-factor token is the
  most common bot compromise; room admins can still grant it explicitly through roles.
- `scopes`: the **upper bound** for every token of the application (§2.4), shown on the consent screen. Default:
  all scopes of §2.4.

Response `201 Application`:

```json
{ "id": "01J…", "ref": "node.example/01J…", "name": "WeatherBot", "description": "…", "public": false,
  "bot": { …User, "kind": "bot", "owner": "alice@node.example", "application_id": "01J…" },
  "owner": "alice@node.example", "requested_permissions": "3", "scopes": ["…"],
  "interactions_url": null, "rpc_origins": [], "commands_version": 0, "tokens": 0,
  "disabled": false, "disabled_reason": null, "created_at": "2026-10-05T12:00:00Z",
  "add_link": "https://node.example/add/01J…" }
```

The node creates the bot user (`kind = bot`, `owner_id`, no password, no email, `dm_policy = everyone_shared`)
in the same transaction. Errors: `403 app.creation_forbidden` (`TAVRN_APP_CREATION`), `409 app.limit_reached`
(`meta.max`), `409 app.username_taken`, `400 app.permissions_invalid`, `400 app.scope_invalid`, `400
validation.*`, `429` (5 creations per day and user). Audited as `app.create` (node audit log, §9.2).

### 1.4 The bot account

- Address `<username>@<H domain>`, `kind = "bot"`; the public `User` object of a bot carries `owner` (address)
  and `application_id`, everywhere (members, authors, profiles, search results).
- **No interactive login.** A bot has no password, no email, no second factor and no secret storage. `POST
  /auth/login` with a bot's username fails like a wrong password (`401 auth.invalid_credentials`); password reset,
  WebAuthn and connect routes never match a bot. Bots are exempt from the mandatory second factor (design note 4.2a);
  their only credential is the app token.
- The bot's profile (display name, avatar, description) is managed by the owner through the application (§1.6);
  `PATCH /users/me` and the profile image routes are refused for app tokens.
- Bots are never node admins (`TAVRN_ADMIN_USERS` does not match bots), never room owners (ownership transfer to a
  bot: `400 app.bot_forbidden`), cannot create rooms, applications, account invites, friend requests or group DMs,
  and cannot join rooms by themselves (§2.5).
- **Usernames of bots are never reused.** A deleted application leaves a disabled bot row (tombstone) so its
  messages keep an author and nobody can later register the address to impersonate it.

### 1.5 BOT badge (normative for all clients)

`kind` is part of every user, member and author object, and the envelope carries `author_kind` (§10.2). Clients
MUST show a "BOT" badge next to every bot name: member lists, message headers, mentions, DMs and the DM list,
profile cards, voice tiles, the consent screen and search results. `kind = "webhook"` gets a "WEBHOOK" badge; a
client that does not know a `kind` value MUST render it like `bot`. A bot's profile card shows the owner's full
address. In conversations with an effective "no bots" flag a bot leaf is a ghost member (§3.5).

### 1.6 Managing an application (owner)

All routes in this table require the owner's full session and are local-only. `{id}` is the application ULID.

| Route | Body → response | Notes |
|---|---|---|
| `GET /applications` | → `[Application]` | the caller's applications |
| `GET /applications/{id}` | → `Application` | `404 app.not_found` for others (no oracle) |
| `PATCH /applications/{id}` | `{ name?, description?, public?, requested_permissions?, scopes?, interactions_url?, rpc_origins?, dm_policy? }` → `Application` | `name` also renames the bot's display name. Narrowing `scopes` narrows existing tokens at once (effective token scopes = token ∩ application). `interactions_url` is verified (§6.3, `400 app.url_verification_failed`); `null` removes it. `rpc_origins`: at most 10 `https://` origins (§7.3). `dm_policy`: the bot's "who can message me" (§2.5). Audited `app.update` with the changed fields |
| `PUT /applications/{id}/avatar`, `DELETE …` | raw body → `Application` | media pipeline of `PROTOCOL.md` §6b (256 × 256 avatar rules), sets the bot's avatar |
| `DELETE /applications/{id}` | `{ name }` (must equal the current name) → `204` | §1.7 deletion; `400 app.name_confirm` |
| `POST /applications/{id}/transfer` | `{ to: "<local username>" }` → `202` | pending transfer for 7 days, the target sees it in their application settings; one at a time (`409 app.transfer_pending`); target must be allowed to create applications and below their limit (`400 app.transfer_target_invalid`) |
| `DELETE /applications/{id}/transfer` | → `204` | owner cancels |
| `POST /applications/{id}/transfer/accept`, `…/decline` | → `Application` / `204` | target only (`404 app.transfer_not_found`) |
| `POST /applications/{id}/identity/reset` | → `204` | §3.4 |

**Transfer** revokes every token, deletes every device of the bot and resets its identity (§3.4) when accepted:
the previous owner may keep copies of tokens and of the bot key file, so the new owner starts with fresh
credentials. Memberships, roles, commands and settings stay. Audited `app.transfer` (both addresses).

### 1.7 Owner state, bans and deletion cascade

| Event | Effect on the owner's applications |
|---|---|
| Owner disabled (node admin) | every application disabled (`disabled_reason = owner_disabled`): tokens fail with `403 app.disabled`, WebSockets close with `4001`, `session.revoke { device: null }` to every domain in the bot's `federation_targets` (`FEDERATION.md` §2.9). Re-enabling the owner re-enables them |
| Owner deleted | every application deleted (below) |
| Owner banned from a room (address, or the owner's domain) | every bot of that owner is removed from the room like a banned member (`member.leave`, `mls.remove_needed`) and can neither be installed again (`403 app.owner_banned`) nor log in there; the ban list shows only the owner (design note 4.3) |
| Owner banned on a node (node ban) | as above for every room of that node, and federated logins of the bots are refused (`403 federation.user_banned`, existing) |
| Application blocked by a node (§4.4) | that node removes the bot everywhere and refuses it |

**Deleting an application** (owner, owner deletion, or node admin `DELETE /admin/applications/{id}`): tokens
revoked, devices deleted (`devices.changed`), local memberships removed (`member.leave`, `mls.remove_needed`), local
webhooks it created stay (they belong to rooms), commands and subscription deleted, `app.changed { deleted: true }`
to every node in `application_install_index` (§4.5), `session.revoke` to every federation target, bot row kept as a
disabled tombstone (§1.4). Audited `app.delete`.

### 1.8 Public application document

`GET /applications/{id}/public` (no authentication, CORS-open, cacheable 5 minutes) → the information every node
and client needs to show and install an application:

```json
{ "ref": "node.example/01J…", "id": "01J…", "node": "node.example", "name": "WeatherBot", "description": "…",
  "bot": "weatherbot@node.example", "owner": "alice@node.example", "public": false,
  "avatar": "/api/v1/media/01J…", "avatar_sha256": "<base64url>",
  "requested_permissions": "3", "scopes": ["messages:read", "messages:write", "commands"],
  "rpc_origins": [], "commands_version": 3, "commands": [ Command, … ], "created_at": "…" }
```

It is served for private applications too (installers need it; the owner check happens on the room node, §4.2).
Disabled, blocked-by-H and deleted applications answer `404 app.not_found`. Other nodes fetch it with the outbound
client of `FEDERATION.md` §1.3 (at most 128 KiB), require `bot` to be an address of the serving domain, mirror the
avatar like a profile image (`FEDERATION.md` §2.7 path and hash rules) and never trust any other field for
authorization except `public`, `owner`, `bot`, `requested_permissions` and `scopes`.

## 2. Tokens and scopes

### 2.1 App token (`typ = "app"`)

An EdDSA JWT under the node's signing key (header rules of `FEDERATION.md` §2.1), shown **once** and stored only as
`token_hash = SHA-256(token)`:

| Claim | Value |
|---|---|
| `iss`, `aud` | H's domain (both) |
| `sub` | the bot's user ULID (like a session token) |
| `typ` | `"app"` |
| `iat`, `exp` | `exp − iat ≤ TAVRN_APP_TOKEN_MAX_DAYS × 86400` (default 365 days) |
| `jti` | ULID of this secret; changes on reset and rotation |
| `dev` | the bot device bound to the token (§3.2) |
| `app` | the application ULID |
| `owner` | the owner's address |
| `scp` | the token's scopes (array of strings) |

`exp` is mandatory because design note 9b and the token verifier of the reference node require it for every token; "until revoked" in
`PROTOCOL.md` §5 becomes "until revoked or expired" (§10.2). Long-running bots rotate (§2.2).

### 2.2 Token routes

A token is a named **bot device** (§3.2): creating a token creates a device, resetting keeps it, revoking deletes it.

| Route | Auth | Body → response | Errors |
|---|---|---|---|
| `POST /applications/{id}/tokens` | owner | `{ name (1–64), scopes?, expires_in_days? }` → `201 { token: AppToken, secret: "<jwt>" }` | `409 app.token_limit` (5 per application), `400 app.scope_invalid` (not ⊆ application scopes), `400 validation.range` |
| `GET /applications/{id}/tokens` | owner | → `[AppToken]` | |
| `POST /applications/{id}/tokens/{token_id}/reset` | owner | `{ expires_in_days? }` → `{ token, secret }` (same device, new `jti`, old secret invalid at once) | `404 app.token_not_found` |
| `DELETE /applications/{id}/tokens/{token_id}` | owner | → `204`: revoked, device deleted (`devices.changed`, `mls.remove_needed` for its leaves, `session.revoke { device }` to federation targets) | |
| `POST /applications/me/tokens/rotate` | app token | → `{ secret, expires_at }`: same token row and device, new `jti`; the previous secret stays valid for 24 h (`prev_jti`) so a bot can restart with the new one | `429` (once per 24 h) |
| `GET /applications/me` | app token | → `Application` without `interactions_url` | |

`AppToken` = `{ id, name, device_id, scopes, created_at, expires_at, last_used_at, revoked_at }`. Rate limit for
create/reset: 10 per hour per application. Audited `app.token_create`, `app.token_reset`, `app.token_revoke`
(token id and name, never the secret). Seven days and one day before `expires_at` the owner and the bot get a WS
event `application.token_expiring { application_id, token_id, expires_at, days }` (once per threshold and secret; a
reset or rotation starts over), and the owner an email when the node has SMTP and the owner a verified address (once
per threshold and secret too, in the owner's language, naming the application and linking its settings).

### 2.3 Verification

The authentication extractor accepts `typ = "session"` and `typ = "app"` (and `preauth` only where §5a allows). For
an app token, in this order:

1. header, `kid`, strict Ed25519 signature, `typ`, `iss = aud = own domain`, `exp`
   (`401 auth.token_invalid` / `401 auth.token_expired`);
2. token row by `jti` (or `prev_jti` within `prev_valid_until`), not revoked, constant-time comparison of
   `SHA-256(token)` with `token_hash` (`401 auth.token_invalid`);
3. application, bot and owner not disabled and the bot not on the node's application blocklist
   (`403 app.disabled`, `meta.reason` = `disabled` | `owner_disabled` | `blocked`);
4. route allowed for app tokens and the token's effective scopes cover it (§2.5, `403 app.bot_forbidden` /
   `403 app.scope_missing` with `meta.scope`);
5. per-application rate limit (§2.7).

`last_used_at` is written at most once per minute. The resulting principal is an `AuthUser` with `device_id = dev`,
the bot user, and the effective scopes = `scp ∩ applications.scopes`.

### 2.4 Scopes

Scopes cap what a token may do **at all**; room permissions still decide what it may do **where**. Effective
permission of a bot in a channel:

```
eval      = permissions.md evaluation for the bot member (administrator / owner expand to all bits first)
perm(bot) = 0                                          if the channel's effective no_bots flag is set (§3.5)
          = eval ∩ (ALWAYS ∪ ⋃ bits(scope) for scope in effective scopes)   otherwise
ALWAYS    = view_channel | change_nickname
```

| Scope | Permission bits it unlocks | Routes and events it unlocks (beyond the always-allowed set) |
|---|---|---|
| `messages:read` | `read_history` | `GET …/messages`, pins, attachment downloads, search, received history keys (`GET`/`DELETE …/history-keys`, `GET …/history-pending`); events `message.*`, `typing`, `read.update`, `history.*` |
| `messages:write` | `send_messages`, `attach_files`, `add_reactions`, `mention_everyone`, `create_threads`, `pin_messages`, `use_external_emojis` | create/edit/delete own messages, reactions, uploads, pins, typing, read markers, `ephemeral` type `cursor` |
| `members:read` | – | `GET /rooms/{id}/members`, `GET /presence`; events `member.*`, `presence.update`, `user.update` |
| `moderation` | `manage_messages`, `kick_members`, `ban_members`, `moderate_members`, `purge`, `view_audit_log`, `manage_nicknames`, `mute_members`, `move_members`, `manage_threads` | kicks, bans, timeouts, purge (with preview), audit log, voice mute/move/disconnect |
| `rooms:manage` | `manage_room`, `manage_channels`, `manage_roles`, `create_invites`, `manage_emojis`, `manage_files`, `manage_applications` | room, category, channel, role, override, emoji, soundboard and invite management (installing applications and the room's command settings stay closed to app tokens, §4.2) |
| `voice` | `connect`, `speak`, `stream`, `use_camera`, `use_soundboard`, `use_external_sounds`, `priority_speaker` | `voice/join`, voice state, soundboard; event `voice.state`, `voice.move` |
| `whiteboard` | `use_whiteboard`, `manage_whiteboard` (bits added in phase 4E) | `ephemeral` types `whiteboard.*`; event `whiteboard.session` |
| `commands` | – | `PUT /applications/me/commands`, interaction callbacks and follow-ups; event `command.invoke` |
| `webhooks:manage` | `manage_webhooks` (new bit, §10.2) | webhook routes of §6.1 |
| `presence` | – | `PUT /users/me/presence`, `PUT/DELETE /users/me/activity` for the bot; the local activity bridge of §7.3 |
| `dms` | – | `POST /conversations { kind: "dm" }` (reading/writing DMs still needs `messages:*`) |

**Threads** (`PROTOCOL.md` §7e) need no scope of their own: listing and reading threads and
`GET /rooms/{id}/followed-threads` fall under `messages:read` (events `thread.*` too); starting threads, writing in
them, renaming, archiving, deleting, following and per-thread read markers under `messages:write`; other people's
threads additionally need `manage_threads`, which only `moderation` unlocks. Bots receive `thread_id` in every
message envelope and reply in a thread by sending it.

**Always allowed** for an app token (no scope): `GET /users/me`, `GET /users/{address}/profile`, `GET /rooms`,
`GET /rooms/{id}` and channel/category/role reads, `GET /node`, the WebSocket, `POST /rooms/{id}/leave`
(= uninstall, §4.3), every E2EE route of §3 (identity, device key, KeyPackages, claims, MLS delivery service,
Welcomes, backups), `POST /federation/token`, `GET /applications/me*`. Events `room.*`, `channel.*`, `category.*`,
`role.*`, `override.update`, `mls.*`, `identity.changed`, `devices.changed`, `application.*` are always delivered.
Unknown future scope strings MUST be rejected at token creation (`400 app.scope_invalid`).

### 2.5 Route table for app tokens (fail closed)

The node keeps one table `APP_ROUTES: (method, route template, scope | always)` next to `federation::guard::
LOCAL_ONLY`; the extractor checks it for every app token against the matched route template. **A template not in
the table is refused** with `403 app.bot_forbidden`, so a new route is unavailable to bots until it is classified.
Explicitly never in the table: password, second factor, WebAuthn, secret storage, `/users/me/identity/reset`,
`PATCH /users/me`, profile images, the whiteboard scene library, friends and blocks, the invite list, account
invites, `POST /rooms`, `POST /rooms/{id}/join`, `POST /invites/{code}/join`, `/auth/connect/*`, directory reports,
the owner routes of §1.6/§2.2, `/admin/*`, and `POST /conversations` with `kind = group`. Adding a bot to a group
DM is refused as well (`400 app.bot_forbidden`): bots live in rooms and 1:1 DMs only.

Bot DMs follow `PROTOCOL.md` §8a: the owner always gets a normal conversation, everyone else a message request
under their `dm_policy`; the bot's own `dm_policy` is set by the owner (`PATCH /applications/{id} { dm_policy }`,
default `everyone_shared`).

### 2.6 WebSocket

`{"op":"hello","token":"<app token>","capabilities":[…],"last_event_id":…}`; `ready` additionally carries
`"application_id"`. At most **2** concurrent connections per token, so a restarting process can connect before the
old one is gone; a third closes the oldest with the new close code `4004` ("replaced", do not reconnect).
Events are filtered by membership exactly as for users and then by the effective scopes (§2.4); an event a scope
does not cover is dropped, never truncated. A revoked, reset or expired token closes the connection with `4001`.

### 2.7 Rate limits

| Limit | Default | Key |
|---|---|---|
| All API requests (REST and WS operations) | `TAVRN_APP_RATE_REQUESTS` = 1200 per minute | application (all tokens; on T: the remote bot) |
| Message creation | 5 per 5 s | bot and conversation |
| New DMs | 10 per 10 minutes | bot |
| Command announcement (`PUT …/commands`) | 10 per hour | application |
| Token create/reset | 10 per hour | application |
| Interactions | 5 per 5 s | invoking user |
| Webhook execution | 5 per 2 s and 30 per minute | webhook |

Bot limits are separate from and stricter than user limits; exceeding one answers `429` with `Retry-After` and
`meta.limit`. Auto-moderation (design note 4.6) treats bots like users (burst limits, mention floods); its actions on
a bot are audited with the application id.

### 2.8 Bots on other nodes (federation)

- H issues federation tokens to bots (`POST /federation/token` with the app token) while `TAVRN_APPS_FEDERATE` is
  on (default `true`; `403 federation.bots_refused` otherwise). The token carries `kind = "bot"`, `owner` (existing)
  and the new claims **`app`** (application ULID on H) and **`scopes`** (the effective scopes), `FEDERATION.md`
  §2.2. A token without `scopes` (older H) counts as all scopes.
- T admits a remote bot (`POST /auth/federated`) only if `TAVRN_FEDERATION_REMOTE_BOTS` is on (`403
  federation.bots_refused`), the bot address is not on T's application blocklist (`403 app.blocked`), and neither
  the bot, nor its owner, nor their domains are node-banned (existing). T stores `app` and `scopes` with the
  federated session and applies §2.4–§2.7 unchanged; the route table of §2.5 applies on top of `LOCAL_ONLY`.
- A remote bot is in a room of T only through an installation on T (§4.2). Its federated session renews with fresh
  federation tokens as for users (7-day cap).
- **Split of the existing switch**: today `TAVRN_FEDERATION_REMOTE_BOTS=false` also stops H from issuing federation
  tokens to its *own* bots (`FEDERATION.md` §13.1). From phase 5 that is `TAVRN_APPS_FEDERATE`;
  `TAVRN_FEDERATION_REMOTE_BOTS` only decides whether bots of other nodes are accepted.

## 3. Bot devices and end-to-end encryption

A bot is an E2EE participant like any user: identity key, attested devices, KeyPackages, MLS leaves, content keys.
The node treats its keys exactly as `ENCRYPTION.md` §2–§4 describe; only the way the bot gets and keeps its master
secret differs.

### 3.1 Identity and the bot key file

- The **bot process** holds the bot's master secret (`ENCRYPTION.md` §2.1). The SDK reads it from
  `TAVRN_BOT_KEY` (the compact `key:` string of the key file, `ENCRYPTION.md` §2.2, version `0x01`) or from the file
  at `TAVRN_BOT_KEY_FILE` (default `./tavrn-key-<username>.txt`). These are variables of the bot process, not of the
  node.
- **First start**: when the bot has no identity key (`GET /users/me` → `has_identity_key: false`) and no key is
  configured, the SDK generates a master secret, writes the key file (mode `0600`, never overwriting an existing
  file) and calls `PUT /users/me/identity` with the app token. The node accepts it once, as for users (`409
  e2ee.identity_exists` afterwards). If the account has an identity key but the process has no key, the SDK stops
  with a clear error ("restore the key file or ask the owner to reset the bot identity").
- There is **no recovery key and no secret storage** for bots: the secret storage routes are not in the app route
  table. The key file is the backup; owners are told so when they create the first token.

### 3.2 Devices = tokens

Every app token is bound to one bot device (`dev`). The process attests that device with the bot's identity key
(`PUT /users/me/devices/{dev}/key`, `ENCRYPTION.md` §3.1, only for `dev`) and keeps KeyPackages uploaded
(`ENCRYPTION.md` §3.2, same limits). Several tokens give several devices (shards, staging), at most 5. Resetting
a token keeps the device, its key and its MLS leaves; revoking it deletes the device (`devices.changed`,
`mls.remove_needed`). History backups (`ENCRYPTION.md` §7) work with the app token so that a bot with a fresh
state directory can read history it was entitled to. The reference runtime keeps **no** history backup unless the bot
operator enables it (`historyBackup: true` in `createBot()`, design note 4.7): without it a bot with a fresh state
directory reads only what is sent after it joined again.

### 3.3 Groups, reading and writing

- A bot joins MLS groups like any device: external commit for channels it may view (`ENCRYPTION.md` §4.5 rule 2,
  with the bot entitlement of §3.5), Welcomes for private channels and DMs it was added to, the commit protocol of
  §4.3, weekly self updates. The SDK joins **eagerly** by default (every viewable encrypted channel after an
  installation, `application.install`) and offers **lazy** joining (on first need) for bots in large rooms, because
  every join creates an epoch.
- It decrypts and signs messages with its device key (`ENCRYPTION.md` §5) and is subject to every node check
  (`e2ee.device_not_attested` etc.). Its local MLS state is encrypted under `local_key` (`ENCRYPTION.md` §2.1) in
  `TAVRN_BOT_STATE_DIR` (default `./.tavrn-state`).
- The consent screen (§4.1) MUST tell installers that an installed bot can read every encrypted channel it can
  view, because it becomes a member of the encryption groups.

### 3.4 What a bot cannot do; identity reset by the owner

Bots have no recovery UI, no PRF passkeys, no "lock on close" and no identity reset of their own
(`/users/me/identity/reset` needs the password, which bots do not have). When the key file is lost or leaked, the
owner resets the identity:

`POST /applications/{id}/identity/reset` (owner, full session) → `204`. The node clears the bot's identity key, sets
`identity_reset_at = now`, deletes all device attestations, KeyPackages and backups of the bot, emits
`identity.changed` (locally and S2S, `FEDERATION.md` §5.2) and `mls.remove_needed` for the bot's leaves. Unlike the
user reset (`ENCRYPTION.md` §9), the new key is not part of the call: the bot process sets it with `PUT
/users/me/identity` on its next start (§3.1) and re-attests its existing device keys. Owners SHOULD reset the tokens
as well when the key file leaked. Audited `app.identity_reset`. Contacts see "security key changed".

### 3.5 "No bots" zones

Rooms, categories and channels get a boolean `no_bots` (design note 4.7 item 7), set by the room owner or holders of
`manage_room` (`PATCH /rooms/{id} { no_bots }`, `PATCH …/categories/{id} { no_bots }`, `PATCH …/channels/{id}
{ no_bots }`; for categories and channels additionally `manage_channels`). Audited `room.no_bots` /
`channel.no_bots` / `category.no_bots`; `room.update` / `channel.update` / `category.update` carry the flag, and
channel objects carry `no_bots_effective`.

- **Effective flag** of a channel = `room.no_bots ∨ category.no_bots ∨ channel.no_bots` (the category flag applies to
  every channel in it, synced or not). DMs never have the flag.
- **Room level**: the node refuses installations (`403 app.room_no_bots`) and, when the flag is set, removes every
  bot membership (uninstall, §4.3, reason `no_bots`). The settings UI confirms this with the number of bots removed.
- **Channel level**: permission evaluation returns 0 for every account with `kind = bot` (§2.4), regardless of roles,
  overrides, administrator or tokens; the channel is invisible to bots, MLS external joins and Adds of bot devices
  are refused (`403 mls.forbidden`), and setting the flag emits `mls.remove_needed` for bot leaves.
- **Node**: the conversation member list served for the MLS roster check omits bots in such channels.
- **Clients** (normative, `ENCRYPTION.md` §4.6): a leaf whose user is a bot in a conversation whose effective
  `no_bots` is set is a ghost member (warning, sending blocked until acknowledged), even if the node lists the bot as
  a member. Clients take `kind` from the user's home node (`GET /users/{username}/keys` carries `kind`, §10.2), so a
  lying room node cannot disguise a bot.
- Channels show the flag as an icon in the channel list and in the settings. Webhooks are not affected (§6.1): they
  cannot read.

**Bots in encrypted channels** (design note 4.7, decided 2026-10-06). A room setting `bots_in_encrypted_channels` =
`per_channel` | `allowed` and a channel setting `bots_allowed` (boolean, default `false`) extend the effective flag:

- **Effective flag** of a channel = `room.no_bots ∨ category.no_bots ∨ channel.no_bots ∨ (channel encrypted ∧
  ¬channel.bots_allowed ∧ room.bots_in_encrypted_channels ≠ "allowed")` (`permissions.md`, vectors
  `testvectors/no_bots.json`). The explicit flags always win; `bots_allowed` only matters for encrypted channels of a
  `per_channel` room. Unknown setting values count as `per_channel`.
- New rooms are created with `per_channel`: an installed bot reaches only plaintext channels and the encrypted channels
  that allow bots. Rooms that existed before the setting keep `allowed` (nothing changes for them).
- `PATCH /rooms/{id} { bots_in_encrypted_channels }` (owner or `manage_room`, `400 validation.bots_in_encrypted_channels`
  for other values) and `PATCH …/channels/{id} { bots_allowed }` (`manage_channels` and `manage_room`; refused for the
  welcome channel with `400 channel.system_protected`). Bots can never change these settings or the `no_bots` flags
  (`403 app.bot_forbidden`), whatever their roles and scopes. Audited `room.bots_in_encrypted_channels` (`from`, `to`,
  `channels_changed`) and `channel.bots_allowed` (`value`, `encrypted`). `Room` carries `bots_in_encrypted_channels`,
  `Channel` carries `bots_allowed`.
- A change that closes a channel emits `mls.remove_needed` for the bots' leaves (as setting `no_bots` does) and
  `channel.update` for every channel whose effective flag changed; a change that opens one emits `channel.update`, on
  which the bot runtime joins. Switching a channel to encrypted in a `per_channel` room closes it the same way.
- Clients compute the flag themselves from the room and channel settings and OR it with the node's
  `no_bots_effective` for the ghost rule (`ENCRYPTION.md` §4.6), so a node cannot present a closed channel as open.

### 3.6 Bots in the security log

Whenever an accepted commit (or the creation of a group) makes a bot's first leaf join, or its last leaf leave, an
encrypted channel's group, the room node writes an entry into the room's welcome channel (`PROTOCOL.md` §7), so every
member sees who can read along:

- `system.bot_added { bot, display_name, avatar, avatar_still, channel, channel_name, channel_system_name, by }`: `by` is the address of the
  committer (the bot itself for an external join, the member for an Add with Welcome);
- `system.bot_removed { bot, display_name, avatar, avatar_still, channel, channel_name, channel_system_name, reason }`: `reason` as the node
  sees it right after the commit: `left` (the bot removed its own leaf), the reason of its uninstall if it is no member
  any more (`uninstalled`, `kicked`, `banned`, `no_bots`, `owner_banned`, `blocked`, `deleted`), `no_bots` (an explicit
  flag), `bots_not_allowed` (an encrypted channel of a `per_channel` room without `bots_allowed`), `no_access` (no read
  access any more), else `device_removed`.

The author of the entry is the bot. Like the other security entries they are plaintext, readable by every member and
follow the normal moderation rules of the welcome channel.

## 4. Add link and installation

### 4.1 Add link and consent screen

Every application has the add link `https://<H>/add/<application id>`. Every web client also accepts
`/add/<domain>/<application id>` and add links pasted into "Add an application" in the room settings or the "+"
dialog, so users of other nodes can use their own client.

The client loads the public document (§1.8) from H (CORS-open). If the user is not signed in, it offers sign-in,
including "an account of another node" (`FEDERATION.md` §8). The **consent screen** MUST show:

- name, avatar, BOT badge, the bot's full address and the owner's full address (foreign domains prominent,
  design note 9d), description, public/private;
- a room picker listing rooms on every node the client has a session with where the user holds `manage_applications`
  (`permissions.md` bit 35); rooms with `no_bots` are listed disabled with the reason;
- the requested permissions by name (`permissions.md`), each as a checkbox the installer may clear; permissions
  the installer does not hold are shown disabled ("you do not have this permission"); without `manage_roles` the
  screen says that the bot joins with the `@everyone` permissions only;
- the application's scopes as an informational list ("the most this bot's tokens can do");
- the E2EE notice of §3.3 and, for remote bots, that the bot's home node is `<H>`.

### 4.2 Installing (room node)

`POST /rooms/{room_id}/applications` on the room's node:

```json
{ "application": "node.example/01J…", "permissions": "3", "create_role": true }
```

Checks, in this order:

1. the caller holds `manage_applications` in the room (`403 app.manage_forbidden`); bots cannot install bots
   (`403 app.bot_forbidden`, also with the `rooms:manage` scope that carries the bit);
2. the room is not `no_bots` (`403 app.room_no_bots`);
3. the application: local → database; remote → its public document from H (§1.8), subject to the domain policy
   (`FEDERATION.md` §1.5) and `TAVRN_FEDERATION_REMOTE_BOTS` (`403 federation.bots_refused`); `502
   federation.peer_unreachable` / `federation.peer_invalid` / `404 app.not_found`;
4. not on this node's application blocklist (`403 app.blocked`), not disabled (`403 app.disabled`);
5. a private application only by its owner: the caller's address equals `owner` (`403 app.private`);
6. bot, owner and their domains not banned in the room or on the node (`403 room.banned` / `403 app.owner_banned`);
7. not installed yet (`409 app.already_installed`); at most `TAVRN_APPS_PER_ROOM` applications (default 25,
   `409 app.room_limit`);
8. `permissions` ⊆ `requested_permissions` and without `administrator` (`400 app.permissions_invalid`); the
   **granted** set is `permissions ∩ the caller's room-level permissions` (owner and node admins: all);
9. a role is created only if `create_role`, the granted set is non-empty and the caller may manage roles
   (`manage_roles` or owner/admin; otherwise `403 role.manage_forbidden`). Requiring `manage_roles` in addition to
   `manage_applications` keeps the install flow from becoming a way around the role editor.

Effects in one transaction: for a remote bot a stub user (`FEDERATION.md` §2.6, `kind = bot`, owner stub from the
document); the membership (`member.join` with the bot's user object); the role named like the application (suffix
on collision), no color, not hoisted, not mentionable, positioned directly below the caller's highest role, marked
with `application_id` (shown as "managed by WeatherBot" in the role editor, editable and deletable like any role);
the installation row; audit `app.install` (`meta`: application ref, granted and dropped permissions, role id). Then
the bot is told: locally WS `application.install { room_id, room_name, node, installed_by }` to its connections,
remotely the S2S message `app.install` (§4.5).

Response `201 Installation`:

```json
{ "application": { "ref": "node.example/01J…", "name": "WeatherBot", "avatar": "…" },
  "bot": { …User }, "role_id": "01J…", "permissions": "3", "dropped_permissions": "0",
  "installed_by": "carol@community.example", "installed_at": "…" }
```

### 4.3 Per-room application list and removal

- `GET /rooms/{room_id}/applications` (`manage_applications` or `manage_room`) → `[Installation]` (with each
  application's enabled command count).
- `DELETE /rooms/{room_id}/applications/{application_ref}` (`manage_applications`, `403 app.manage_forbidden`) → `204`: membership removed
  (`member.leave`, `mls.remove_needed`), the managed role deleted (if it still exists), the room's command settings
  for the application deleted, installation row deleted. Audited `app.uninstall` (`meta.reason`: `removed`).
- Kicking the bot is an uninstall (`reason: kicked`); banning it is an uninstall plus a ban (reinstall refused);
  the bot leaving (`POST /rooms/{id}/leave` with its token) is an uninstall (`reason: left`, actor = the bot).
- After every uninstall the bot is told (`application.uninstall` locally, S2S `app.uninstall` remotely).

### 4.4 Node-level controls

| Route | Auth | Effect |
|---|---|---|
| `GET /admin/applications` | node admin | local applications with owner, tokens, installation count, disabled state |
| `PATCH /admin/applications/{id}` | node admin | `{ disabled: bool }` (`disabled_reason = admin`) |
| `DELETE /admin/applications/{id}` | node admin | deletion (§1.7) |
| `GET /admin/applications/blocks` | node admin | `[{ bot, reason, created_by, created_at }]` |
| `POST /admin/applications/blocks` | node admin | `{ bot: "<address>", reason? }`: uninstalls the bot from every room of this node (`reason: blocked`), refuses installs, tokens (local) and federated logins (remote) with `403 app.blocked` |
| `DELETE /admin/applications/blocks/{bot}` | node admin | lifts the block (no automatic reinstall) |

`TAVRN_FEDERATION_REMOTE_BOTS=false` blocks all foreign applications at once. Blocks and unblocks are audited
(`admin.app_block`, `admin.app_unblock`). Users report applications to their home node's admins with the
existing report route (`POST /directory/reports` with `subject: { kind: "application", ref }`, §10.2).

### 4.5 Server-to-server messages

New inbox types (`FEDERATION.md` §5.2 envelope, outbox and limits unchanged):

| Type | Sender (`iss`) | `from` → `to` | `payload` | Receiver behavior |
|---|---|---|---|---|
| `app.install` | the room node | room node domain → bot address | `{ room: { node, id, name }, installed_by }` | H checks that the bot exists and is not disabled (else `404 federation.recipient_unknown`), adds `application_install_index`, emits `application.install` to the bot's connections |
| `app.uninstall` | the room node | room node domain → bot address | `{ room: { node, id }, reason }` | H removes the index entry, emits `application.uninstall` |
| `app.changed` | H | bot address (domain = `iss`) → receiving domain | `{ application_id, commands_version, deleted }` | refetch the public document (commands, name, avatar); `deleted: true` → uninstall the bot from every local room and refuse it |

H sends `app.changed` to every node in the application's install index when the name, avatar, scopes, requested
permissions or commands change, and on deletion. `GET /applications/me/installations` (app token) → `[{ node,
room_id, room_name, installed_at }]` lets the SDK find every room node to open federated sessions with.

## 5. Commands

### 5.1 Command definitions and announcement

The registry shape of design note 4.11 (`{ name, description, args: [{ name, type, required }], permission?, source }`)
is extended for applications:

```json
{ "id": "01J…", "name": "weather", "description": "Forecast for a city",
  "args": [
    { "name": "city", "description": "City name", "type": "string", "required": true, "max_length": 100 },
    { "name": "units", "description": "Unit system", "type": "string", "required": false,
      "options": [ { "name": "Metric", "value": "metric" }, { "name": "Imperial", "value": "imperial" } ] }
  ],
  "default_permissions": null, "dm_allowed": true }
```

- `name` and arg names: `^[a-z0-9_-]{1,32}$`, unique per application (arg names per command). `description`: 1–100
  characters. At most 100 commands per application and 25 args per command; required args come first.
- `type`: `string`, `integer`, `number`, `boolean`, `user` (address), `channel` (channel id), `role` (role id).
  `options` (the enum choices, at most 25, `name` 1–100 characters, `value` of the arg's type) only for `string`,
  `integer` and `number`; `min`/`max` for numbers, `max_length` (≤ 1000) for strings. Unknown fields are refused.
- `default_permissions`: decimal mask the invoker must hold in the channel unless the room overrides it (§5.3);
  `null` = no extra permission. `dm_allowed`: usable in a DM with the bot.

`PUT /applications/{id}/commands` (owner) or `PUT /applications/me/commands` (app token, scope `commands`) with
`{ "commands": [ … without id … ] }` replaces the whole set → `200 { commands, commands_version }`. Ids stay stable
per name; a removed name loses its room settings. `definition_hash` = base64url SHA-256 of the JCS form
(RFC 8785) of the definition without `id`. Errors: `400 command.invalid` (`meta.path`), `400 command.limit`, `429`.
The node increments `commands_version`, sends `app.changed` (§4.5) and `commands.update { room_id }` to the members
of every local room where the application is installed. Audited `app.commands` (`meta`: names added, changed,
removed).

### 5.2 Node approval

With `TAVRN_APP_COMMANDS_REQUIRE_APPROVAL=true` (default `false`) a node offers an application command in its rooms
only after a node admin approved its `definition_hash`; this applies to local and remote applications alike, on the
node serving the room. Any change of a definition makes it pending again.

- `GET /admin/applications/commands?state=pending|approved` → `[{ application: ref, command, definition_hash,
  state }]`;
- `POST /admin/applications/commands/approve` / `…/reject` `{ application, hashes: [..] }` → `204`.

Pending commands are absent from palettes; invoking one answers `403 command.pending_approval`. Audited
`admin.app_commands_approve` / `admin.app_commands_reject`. `GET /admin/applications/commands/approval` → `{ required }`
tells the admin UI whether the switch is on.

### 5.3 Per-room settings

Room managers decide where and for whom commands work:

- `GET /rooms/{room_id}/commands` (`manage_applications` or `manage_room`, like the installation list) → per installed
  application its commands with the effective settings.
- `PUT /rooms/{room_id}/commands/{command_ref}` (`manage_applications`, `403 app.manage_forbidden`) `{ enabled, permissions, allowed_roles,
  disabled_channels }` → `200`: `permissions` replaces `default_permissions` (decimal mask, `null` = the default);
  `allowed_roles` (role ids; empty = no role restriction; owners and administrators always pass);
  `disabled_channels` (channel ids). `command_ref` = `<application ref>/<command id>`. `DELETE` resets to the
  defaults. Audited `command.settings`; members receive `commands.update { room_id }`.

### 5.4 The `/` palette

`GET /conversations/{conversation_id}/commands` → the application commands the caller can invoke right now, in the
registry shape:

```json
[ { "id": "01J…", "ref": "node.example/01J…/01J…", "name": "weather", "description": "…", "args": [ … ],
    "permission": "0", "source": "app",
    "application": { "ref": "node.example/01J…", "name": "WeatherBot", "bot": "weatherbot@node.example" },
    "dm_allowed": true } ]
```

`permission` is the effective required mask. The list contains exactly the commands that pass checks 1–6 of §5.5
for the caller. Clients (normative for `commands.v1`):

- merge it with their built-in commands (`source: "builtin"`, design note 4.11), built-ins first; built-ins stay
  filtered by the user's permissions as before;
- a name used by a built-in or by another application is shown with the application name as qualifier
  (`/weather · WeatherBot`); the selection is bound to the command **id**, never resolved by name;
- render `options` as a pick list, validate types and required args before sending, and show the BOT badge;
- cache per conversation and refetch on `commands.update` for its room, on own `member.update` and on
  `role.update`/`override.update`.

### 5.5 Invocation

`POST /conversations/{conversation_id}/interactions` (user session; bots cannot invoke commands,
`403 app.bot_forbidden`):

```json
{ "command": "node.example/01J…/01J…", "args": { "city": "Berlin" },
  "args_ciphertext": null, "epoch": null, "thread_id": null }
```

`thread_id` (optional) names the thread of the channel the command is invoked in (`PROTOCOL.md` §7e): a thread of
the conversation (`404 thread.not_found`) the caller may write in (`403 thread.reply_forbidden`, `403
thread.locked`); the answers go there.

The node checks, in this order: (1) the caller may view the conversation and holds `send_messages` there;
(2) the application is installed in the room (for DMs: the conversation is a DM with this bot and `dm_allowed`,
`403 command.dm_not_allowed`), and the bot can view the channel (effective permission ≠ 0); (3) the command exists
(`404 command.not_found`) and is approved (§5.2); (4) enabled in the room and not disabled in the channel
(`403 command.disabled`); (5) the caller holds the required mask and, if set, one of `allowed_roles` (`403
command.forbidden`); (6) rate limit (§2.7); (7) args: in unencrypted conversations `args` is validated against the
definition (`400 command.args_invalid` with `meta.arg`), `args_ciphertext` must be null; in encrypted
conversations `args` must be null and `args_ciphertext` is checked like message content (`ENCRYPTION.md` §5.3,
`400 interaction.ciphertext_invalid`, `400 interaction.epoch_unknown`) (`400 interaction.encryption_mismatch` for
the wrong form).

The node creates an interaction `{ id, command, conversation_id, thread_id, user_id, created_at, expires_at = +15
min }` (kept only until it expires; a node of several instances keeps it in its shared cache, sealed, so any
instance takes the responses), delivers it (§5.6) and waits **at most 3 seconds** for the first response (§5.7). The
caller's request then returns:

```json
{ "interaction_id": "01J…", "outcome": "reply" | "defer" | "error",
  "message": Message | null, "ephemeral": EphemeralReply | null, "error": "…" | null }
```

or `503 interaction.app_offline` (no connection and no URL), `504 interaction.no_ack` (no response in 3 s;
the interaction is dropped). The invocation itself is not a message and is not stored.

### 5.6 Delivery to the application

- **WebSocket**: WS event `command.invoke` to exactly **one** live connection of the bot on this node whose token
  has the `commands` scope (round robin over devices), so shards do not answer twice.
- **Interactions URL** (only on H, only for local rooms and DMs, when `interactions_url` is set; preferred over the
  WebSocket): a hook request (§6.3) with the body `{ "type": "command.invoke", "id": "<interaction id>", "at",
  "data": … }`; the HTTP response body is the callback of §5.7. Other nodes never call application URLs; there a
  remote bot receives invocations over the WebSocket of its federated session.

`data` (WS and URL):

```json
{ "interaction_id": "01J…", "application_id": "01J…", "command": { "id": "01J…", "name": "weather" },
  "conversation_id": "01J…", "room_id": "01J…", "channel_id": "01J…", "thread_id": null, "encrypted": true,
  "user": "alice@node.example", "user_id": "01J…", "device_id": "01J…", "permissions": "123",
  "args": null, "args_ciphertext": "<base64url>", "epoch": 42, "locale": "de", "expires_at": "…" }
```

`permissions` is the invoker's effective mask in the channel, `locale` the first language of the invoker's
`Accept-Language`, `thread_id` the thread the command was invoked in (null outside threads).

### 5.7 Responses, follow-ups and ephemeral replies

`POST /interactions/{interaction_id}/callback` (app token of the interaction's application, scope `commands`; or
the URL response body). Only the first response counts (`409 interaction.already_acked`); after 3 s it is
`410 interaction.expired`.

```json
{ "type": "reply", "content": { "type": "text", "body": "12 °C, cloudy" } | "<ciphertext>", "epoch": 43,
  "device_id": "01J…", "ephemeral": false, "mentions": [], "thread_id": null }
{ "type": "defer", "ephemeral": false }
{ "type": "error", "message": "City not found" }
```

- **reply, not ephemeral**: the node stores a normal message authored by the bot (`device_id` = the token's device;
  in URL responses the body names it and the node checks that it is an attested device of the bot) with the new
  envelope field `interaction: { id, command: "weather", application: ref, user: "alice@…" }`, and emits
  `message.create`. The bot needs `send_messages` in the channel (`403 message.send_forbidden`).
- **Threads**: replies and follow-ups go into the interaction's `thread_id`, or into the thread of the conversation
  the body names with `thread_id` (`404 thread.not_found`); the bot needs what writing in that thread needs
  (`PROTOCOL.md` §7e: `create_threads` in text and announcement channels, `manage_threads` in a locked thread).
  An archived thread reopens.
- **reply, ephemeral**: not stored; returned to the invoker in the invocation response and as WS
  `interaction.reply` to the invoker's other connections on this node: `EphemeralReply = { interaction_id,
  conversation_id, thread_id, application: { ref, name, bot }, device_id, content, epoch, created_at }`. Clients show it
  marked "only you can see this" and drop it on reload.
- **defer**: clients show "WeatherBot is thinking…" until a follow-up arrives or the interaction expires.
- **error**: a short plaintext notice (≤ 200 characters) shown to the invoker only; bots SHOULD keep it generic in
  encrypted conversations because the node sees it.
- **Follow-ups**: `POST /interactions/{interaction_id}/messages` (app token, until `expires_at`, at most 10)
  `{ content, epoch?, device_id?, ephemeral, mentions?, thread_id? }` with the same rules (`429` / `409
  interaction.followup_limit` beyond; a refused follow-up does not count). Later edits use the normal message
  routes.

`content` follows the conversation's mode exactly like a message: a JSON content object in unencrypted
conversations, the ciphertext of `ENCRYPTION.md` §5.2 (author = bot, device = the bot device, current epoch) in
encrypted ones (`400 interaction.encryption_mismatch` otherwise).

### 5.8 Commands in encrypted conversations

- The node sees only metadata: which command was invoked by whom, where and when.
- The invoker's client encrypts the arguments as a content object under the current epoch (`ENCRYPTION.md` §5.2):
  `{ "type": "command.args", "command": "<command ref>", "nonce": "<base64url 16 bytes>", "issued_at": "…",
  "args": { … } }` → `args_ciphertext`, `epoch`.
- The application must be an MLS member of the conversation at that epoch. It decrypts, verifies the content
  signature against the invoker's attested device (`device_id`), and MUST reject arguments whose `command` differs
  from the invoked one, whose `issued_at` is older than 5 minutes, or whose `nonce` it saw before (kept 15 minutes),
  so a node cannot replay or move arguments. A bot that is not yet a member answers with `error` and joins.
- Replies and follow-ups are ciphertext produced by the bot (§5.7). An ephemeral reply is delivered only to the
  invoker's devices; it is encrypted under the channel's epoch key, so "ephemeral" is a display and delivery
  property, not a cryptographic one (any member of the epoch could decrypt it if the node handed it over).
- Context (recent messages, attachments) is read by the bot itself as a member (`messages:read`); invocations never
  carry message content.

### 5.9 Error codes

`command.invalid` (400), `command.limit` (400), `command.not_found` (404), `command.pending_approval` (403),
`command.disabled` (403), `command.forbidden` (403), `command.dm_not_allowed` (403), `command.args_invalid` (400),
`interaction.app_offline` (503), `interaction.no_ack` (504), `interaction.not_found` (404),
`interaction.expired` (410), `interaction.already_acked` (409), `interaction.followup_limit` (409),
`interaction.encryption_mismatch` (400), `interaction.ciphertext_invalid` (400), `interaction.epoch_unknown` (400),
`interaction.not_owner` (403: another application's interaction), `interaction.owner_unavailable` (503, several
instances: the instance holding the interaction does not answer; see the scaling guide of `tavrn-node`).

## 6. Webhooks

### 6.1 Incoming webhooks

A webhook posts messages into **one text, announcement or forum channel**: plaintext in unencrypted channels, sealed
boxes that only the channel's members can open in encrypted ones (§6.1a). In a forum channel it posts into posts
only (`thread_id`, below). The node never becomes a member of an MLS group and never holds a key that opens what
is stored.

| Route | Permission | Body → response |
|---|---|---|
| `GET /rooms/{room_id}/channels/{channel_id}/webhooks` | `manage_webhooks` in the channel | → `[Webhook]` |
| `POST /rooms/{room_id}/channels/{channel_id}/webhooks` | `manage_webhooks` | `{ name (1–32), allow_mentions_everyone?, sealing? }` → `201 { webhook, url }` (the URL is shown once; `sealing` §6.1a) |
| `GET /rooms/{room_id}/webhooks` | `manage_webhooks` (room level) | → `[Webhook]` of all channels |
| `PATCH /rooms/{room_id}/webhooks/{webhook_id}` | `manage_webhooks` (in the old and new channel) | `{ name?, channel_id?, allow_mentions_everyone?, sealing? }` → `Webhook` |
| `PUT` / `DELETE /rooms/{room_id}/webhooks/{webhook_id}/avatar` | `manage_webhooks` | avatar via the media pipeline (`PROTOCOL.md` §6b) |
| `POST /rooms/{room_id}/webhooks/{webhook_id}/reset` | `manage_webhooks` | → `{ webhook, url }` (the old URL stops working) |
| `DELETE /rooms/{room_id}/webhooks/{webhook_id}` | `manage_webhooks` | → `204` |
| `POST /webhooks/{webhook_id}/{secret}` | the secret in the URL | payload below (or a sealed body, §6.1a) → `204`, or `200 Message` with `?wait=true` |
| `GET /webhooks/{webhook_id}/{secret}/inbox-key` | the secret in the URL | → `{ epoch, public_key, algorithm }` (§6.1a) |

`Webhook` = `{ id, room_id, channel_id, name, avatar, avatar_still, user, created_by, created_at, last_used_at,
suspended, allow_mentions_everyone, sealing, pending_key }` (`suspended` is always `false` since §6.1a and kept for
compatibility). `url` = `https://<domain>/api/v1/webhooks/<id>/<secret>`, `secret` = 32
random bytes base64url, stored as SHA-256 and compared in constant time. An unknown id and a wrong secret both
answer `404 webhook.not_found` (no oracle).

- **Author**: every webhook has a pseudo user `kind = "webhook"`, username `wh.<lowercase id>`, display name = the
  webhook name, `owner` = its creator. It has no password, token, device, keys or memberships and appears in no
  member list. Messages carry the new node-set envelope field `webhook: { id, name }` (name = the per-message
  `username` or the webhook name), `device_id: null`, `signature: null`. Clients show the WEBHOOK badge and MUST NOT
  show the "unverified" marker of `FEDERATION.md` §10.3 for webhook messages (they are authenticated by the node, as
  the badge says).
- **Payload** (`application/json`, at most 32 KiB, `413 webhook.too_large`):
  ```json
  { "content": { "type": "text", "body": "Deploy **v1.2** finished", "embeds": [ Embed ] },
    "username": "CI", "mentions": ["alice@node.example"], "mentions_everyone": false, "reply_to": null,
    "thread_id": null }
  ```
  `content` is validated like a plaintext message (`PROTOCOL.md` §7, `message.*` codes) with `embeds` (§6.4);
  `username` 1–32 characters, no `@`, `#` or `:`, not `everyone` or `here` (`400 webhook.username_invalid`);
  `mentions` that are not room members are dropped; `mentions_everyone` needs `allow_mentions_everyone`, which only
  a creator holding `mention_everyone` can set. `thread_id` posts into a thread of the webhook's channel
  (`PROTOCOL.md` §7e; `404 thread.not_found` for unknown ids and threads of other channels, `403 thread.locked` for
  a locked thread, an archived one reopens); webhooks need no `create_threads`, their creator decided where they
  post. Forum channels show posts only: there `thread_id` (a post of the forum) is required, a message without it is
  refused with `400 message.thread_required`. No attachments in v1. `400 webhook.payload_invalid` for anything
  else.
- **Encryption switch**: the webhooks stay (§6.1a). When the channel becomes encrypted they are sealed by the sender
  and `pending_key` until a member publishes the inbox key; when it becomes unencrypted they post plaintext again.
  Both are audited as `webhook.update` with `{ changed: ["sealing"], sealing }`. Deleting the channel deletes its
  webhooks.
- **"No bots"** zones do not block webhooks: they cannot read, so a leaked URL cannot spy (§3.5 rationale).
- **Moderation**: webhook messages are deleted, bulk-deleted and purged like any message (author = the pseudo user).
- **Limits**: `TAVRN_WEBHOOKS_PER_CHANNEL` (default 10), 50 per room, the rate limits of §2.7; `TAVRN_WEBHOOKS_ENABLED`
  (default `true`) — `false` refuses creation and execution with `403 webhook.disabled`.
- **Audit**: `webhook.create`, `webhook.update`, `webhook.reset`, `webhook.suspend`, `webhook.delete` (actor, channel,
  webhook id; never the secret). Request logs MUST redact the secret path segment (`/webhooks/<id>/***`).

### 6.1a Webhooks in encrypted channels (write-only, sealed)

In an encrypted channel a webhook can post without ever being able to read, and the node stores only what it cannot
open. The members derive an X25519 **inbox key pair** per epoch from the epoch's content key (`ENCRYPTION.md` §5b);
a member device publishes the public key; a post is a libsodium **sealed box** (`crypto_box_seal`: X25519 with an
ephemeral sender key, XSalsa20-Poly1305) to the newest published key.

**Sealing mode** (`Webhook.sealing`), chosen by the creator for encrypted channels (`sealing` on create, changeable
with `PATCH`), `null` in unencrypted channels (`400 webhook.sealing_invalid` when given there or unknown):

| `sealing` | The service | The node |
|---|---|---|
| `sender` (default) | fetches the key from `GET …/inbox-key`, seals `{ "content": {…}, "username"? }` itself and posts `{ "sealed": "<base64url>", "epoch": n, "thread_id"? }` (`thread_id` as in §6.1, outside the box) | accepts only that body (`400 webhook.sealed_required` for anything else, unknown fields included), never sees the text |
| `node` | posts the plaintext payload of §6.1 over HTTPS as before | checks it like a plaintext payload, seals `{ content, username? }` in memory to the newest key and stores only the box; it sees the text at that moment, so its operator could read it |

**Inbox key route for senders**: `GET /webhooks/{webhook_id}/{secret}/inbox-key` → `{ "epoch": n, "public_key":
"<base64url, 32 bytes>", "algorithm": "x25519-xsalsa20poly1305-sealedbox" }`, authenticated by the secret exactly like
the execution route (`404 webhook.not_found` for unknown ids and wrong secrets, the burst rate limit of §2.7);
`409 webhook.not_sealed` in unencrypted channels, `409 webhook.pending_key` before a key exists.

**Publishing** (members' devices): `PUT /conversations/{conversation_id}/inbox-key` `{ epoch, public_key, signature }`
→ `200 { epoch, public_key, algorithm }` with the newest key. `signature` is the Ed25519 signature of the session's
device over `"tavrn webhook inbox key v1" || 0x00 || str16(qualified conversation id) || u64(epoch) || public_key`
(`ENCRYPTION.md` §5b). The node checks, in this order: the caller is entitled to the channel (member with
`view_channel`), the channel is encrypted (`400 inbox_key.not_encrypted`; DMs too), it has webhooks
(`409 inbox_key.no_webhooks`), the group exists (`404 mls.no_group`), `0 ≤ epoch ≤` the group's epoch and a 32-byte
key (`400 inbox_key.invalid`), the device is attested (`403 e2ee.device_not_attested`), the signature verifies
(`400 inbox_key.bad_signature`). It keeps only the newest key per conversation: an older epoch, or another key for the
stored epoch, answers `409 inbox_key.stale` with `meta.epoch`; the same key again answers `200`. Bot tokens may
publish (`Always`, like the MLS routes). Clients publish after every commit of their own (adds, removes, external
joins, self updates, the group's creation) **only** for channels whose `has_webhooks` is set; when a channel gets
webhooks and on loading a room, a client that holds the group publishes the current epoch's key once (the same key
for every member, so concurrent publishers agree), and the creator of a webhook publishes right after creating it.
Without any member device online the webhook stays `pending_key` and executions answer `409 webhook.pending_key`.

**Stored message**: the normal envelope of a webhook message (`webhook: { id, name }` with the webhook's name,
`author_kind = "webhook"`, `device_id` and `signature` null) with `encrypted = true`, `epoch = n` and `content` =
`{ "type": "webhook.sealed", "epoch": n, "sealed": "<base64url>", "sealed_by": "sender" | "node" }`. The per-message
`username` travels inside the box. Sender-sealed posts carry no mentions, `@everyone` or reply target; node-sealed
posts keep `mentions`, `mentions_everyone` and `reply_to` as plaintext metadata, like every encrypted message
(`PROTOCOL.md` §7). Messages are moderated (deleted, bulk-deleted, purged) like any other.

**Epoch window**: the node seals with, and senders should use, the newest key it has. Right after a commit the node may
still hold the previous epoch's key until the committing device's `PUT` arrives (normally milliseconds, at most seconds
with a slow client): a post in that window is sealed for the previous epoch and says so in `epoch`. Members of both
epochs read it; a member added by that very commit cannot until it receives the key through the history keys
(`ENCRYPTION.md` §7b) — the same rule as for every message of an epoch before one's join. In sender mode the node
accepts any `0 ≤ epoch ≤` the newest published epoch (`400 webhook.epoch_invalid` otherwise).

**Reading** (clients): derive the inbox secret of the message's epoch from the content key (current state, history
backup or history share), open the box, and accept the inner JSON only as a webhook text payload: `content.type =
"text"`, `body` ≤ 4000 characters (empty only with embeds), valid embeds (§6.4; invalid ones dropped), nothing else
(attachments, GIFs, previews are dropped); a `username` that breaks the rules of §6.1 is ignored. Show the WEBHOOK badge
plus a lock; for `sealed_by = "node"` the lock's tooltip says "sealed by the node: the node saw the text when it was
posted". Messages whose epoch key is unknown render as "cannot be decrypted" like other undecryptable messages.

**Logs**: in both modes nothing readable reaches logs, traces, span fields, audit entries or error messages: a refused
node-sealed payload keeps its code and status but answers with a fixed `detail`
(`webhook_logs_flow.rs` captures every log line of a node-sealed post and of refused ones).

What this does **not** protect against (`ENCRYPTION.md` §5b): a malicious node can hand a sender its own public key
(the sender cannot tell; pinning the key is the sender's choice), and in `node` mode the node sees each text once.

### 6.2 Outgoing event subscriptions

An application can receive events of its **local** installations at an HTTPS URL instead of (or in addition to) a
WebSocket. Configuring where data goes is owner-only, so a leaked bot token cannot redirect the event stream.

- `PUT /applications/{id}/subscriptions` (owner) `{ url, events: ["message.create", …] }` → `200 Subscription`
  after the URL verification (§6.3); `GET` → `Subscription`; `DELETE` → `204`; `POST
  /applications/{id}/subscriptions/enable` re-enables a disabled subscription (verifies again). `Subscription` =
  `{ url, events, state: "active" | "failing" | "disabled", last_success_at, last_error, queued, dropped,
  created_at }`. Audited `app.subscription`.
- **Event types**: `application.install`, `application.uninstall`, `member.join`, `member.leave`, `member.update`,
  `message.create`, `message.update`, `message.delete`, `commands.update`. Unknown types: `400
  subscription.event_invalid`.
- **Eligibility**: only events of rooms on H where the application is installed (and its DMs on H), only those the
  bot would receive on its WebSocket with the application's scopes (§2.6), and **never** content of encrypted
  conversations: `message.*` events of encrypted conversations are not delivered at all, nor `mls.*`, `ephemeral`,
  `typing` or presence. Rooms on other nodes never feed subscriptions; there the bot uses the WebSocket.
- **Delivery**: `POST <url>` with `{ "id": "<event id>", "type", "at", "application_id", "room_id", "data" }`
  (`data` = the WS event data) and a hook token (§6.3). Writes go to `application_outbox` in the transaction of the
  change; retries follow `FEDERATION.md` §5.3 (1 min, 5 min, 30 min, 2 h, 12 h, then every 12 h, give up after 3
  days, `Retry-After` honored), at most 4 concurrent requests per application, at most 10 000 queued events per
  application (the oldest are dropped and counted in `dropped`). Success = `2xx` within 10 s. State `failing` after
  the first given-up event, `disabled` after 3 days without any success; the owner gets WS
  `application.subscription_disabled`. Receivers deduplicate by `id`; there is no ordering guarantee.

### 6.3 Hook requests (interactions URL and subscriptions)

Every request a node sends to an application URL carries `Tavrn-Signature: <JWT>`, signed with the node's key
(verifiable through `https://<node>/.well-known/tavrn`), instead of a shared HMAC secret: there is no secret to
store, leak or rotate, and the format is the node token of `FEDERATION.md` §2.3.

| Claim | Value |
|---|---|
| `iss`, `sub` | the node's domain |
| `aud` | `app:<application id>` |
| `typ` | `"hook"` |
| `iat`, `exp` | `exp − iat ≤ 300` |
| `jti` | ULID per attempt |
| `htu` | the exact target URL |
| `body_sha256` | base64url SHA-256 of the exact body |

Further headers: `Tavrn-Event-Type`, `Tavrn-Event-Id`, `User-Agent: tavrn-node/<version> (+https://<domain>)`.
Applications MUST verify (the SDK's `verifyHookRequest()` does): EdDSA signature with a key of the node's
`.well-known` (cached ≤ 1 h, one refetch on an unknown `kid`), `typ`, `aud`, `iat` within ±5 minutes, `exp`, `htu`
equals the configured URL, the body hash **before** parsing, `jti` unseen until `exp + 5 min`.

**URL rules** (`interactions_url`, subscription URLs): `https://` only, no credentials or fragment, at most 2048
characters; requests go through the outbound client of `FEDERATION.md` §1.3 (verified TLS, vetted and pinned
address, private and loopback ranges refused unless `TAVRN_APP_ALLOW_PRIVATE_URLS` or `--dev`), **no redirects**,
response at most 64 KiB; timeouts 3 s for invocations, 10 s for events. **Verification** when a URL is set or
re-enabled: `{ "type": "ping", "challenge": "<base64url 32 bytes>" }`; the URL must answer `200` with
`{ "challenge": "<same>" }` within 5 s (`400 app.url_verification_failed`), so a node cannot be pointed at a
third party's server.

### 6.4 Embeds

`text` content objects gain an optional `embeds` array (any author, encrypted or not; `PROTOCOL.md` §7): at most 10
embeds, at most 6000 characters over all text fields; `body` may be empty when `embeds` is present.

```json
{ "title": "Build #128", "description": "All **42** tests passed", "url": "https://ci.example/b/128",
  "color": 3066993, "fields": [ { "name": "Branch", "value": "main", "inline": true } ],
  "footer": "ci.example", "timestamp": "2026-10-05T12:00:00Z" }
```

`title` ≤ 256, `description` ≤ 4096 (Markdown subset), `url` `https://` only, `color` 0–16777215, `fields` ≤ 25 with
`name` ≤ 256 and `value` ≤ 1024, `footer` ≤ 2048. There are **no remote images** in embeds: clients never load
images from foreign hosts (design note 4.9). Invalid embeds: `400 message.embeds_invalid`. Clients render them through
the same sanitizer as message Markdown and show links with their full host.

## 7. Rich presence and the activity API

### 7.1 A bot's own presence

A bot is online while at least one of its WebSockets is open on a node (`PROTOCOL.md` §6a). With the `presence`
scope it sets its status and custom status (`PUT /users/me/presence`) and its activity (`PUT /users/me/activity`,
per device) like a user, e.g. `{ "type": "watching", "name": "3 servers" }`. Visibility rules are those of §6a.

### 7.2 Activity object

The activity of `PROTOCOL.md` §6a gains optional fields (compatible additions):

```json
{ "type": "playing", "name": "Space Miners", "details": "Ranked match", "state": "In a party (2 of 4)",
  "started_at": "…", "ends_at": null, "application": { "ref": "games.example/01J…", "name": "Space Miners" } }
```

`state` ≤ 128 characters, `ends_at` after `started_at`, `application` set only through the bridge below. The node
validates the format only (`400 presence.activity_invalid`); clients show "via <application name>" and, when they
already know the bot user of `application.ref`, its avatar. No other images, buttons or party joins in v1.

### 7.3 Local activity bridge (interface fixed now, implemented with the desktop apps in phase 6)

Applications never set a **user's** activity through the node: there is no route for it, and no token grants it.
Instead a local program (a game or its launcher) talks to the user's desktop client, which asks the user and then
sets the activity on the user's own sessions.

- **Transport**: the desktop client listens on `ws://127.0.0.1:<port>/tavrn-activity?v=1`, `<port>` the first free
  of 46480–46489 (programs try them in order). Loopback only.
- **Origin**: connections without an `Origin` header (native programs) are accepted; connections with one only when
  the origin is listed in the application's `rpc_origins` (§1.8). Everything else is closed with `4003`.
- **Handshake**: `{ "op": "hello", "v": 1, "application": "<application ref>" }`. The client fetches the public
  document (§1.8) from the application's node; unknown, disabled or blocked applications, and applications whose
  `scopes` do not include `presence`, are refused (`{ "op": "error", "code": "app.not_allowed" }`).
- **Consent**: the first time, the client asks "Allow <name> (<bot address>) to show what you are doing?" with
  allow once / always / never; the decision is stored per application ref on the device and revocable in the
  settings. Users with `hide_activity` are asked nothing and nothing is shown.
- **Operations**: `{ "op": "set_activity", "activity": { type, name, details?, state?, started_at, ends_at? } }`
  and `{ "op": "clear_activity" }`, answered `{ "op": "ok" }` or `{ "op": "error", "code" }`; at most one update per
  5 s (excess coalesced). The client adds `application`, publishes through `PUT /users/me/activity` to every node it
  has a session with (`PROTOCOL.md` §6a), and clears the activity when the program disconnects.
- The bridge never reveals the user's identity, tokens, rooms or contacts to the local program in v1.

## 8. Single sign-on via OpenID Connect

### 8.1 Configuration

SSO is optional per node (design note 4.2, decision 10) and enabled when `TAVRN_OIDC_ISSUER` is set.

| Variable | Default | Meaning |
|---|---|---|
| `TAVRN_OIDC_ISSUER` | empty | issuer URL; discovery at `<issuer>/.well-known/openid-configuration`; `https://` only (`http://` with `--dev`) |
| `TAVRN_OIDC_CLIENT_ID` | – | required with an issuer |
| `TAVRN_OIDC_CLIENT_SECRET` / `TAVRN_OIDC_CLIENT_SECRET_FILE` | – | confidential client; the file variant keeps the secret out of the environment |
| `TAVRN_OIDC_SCOPES` | `openid profile email groups` | must contain `openid` |
| `TAVRN_OIDC_USERNAME_CLAIM` | `preferred_username` | source of the username at provisioning |
| `TAVRN_OIDC_DISPLAY_NAME_CLAIM` | `name` | updated on every login |
| `TAVRN_OIDC_GROUPS_CLAIM` | `groups` | array of strings, from the ID token or UserInfo |
| `TAVRN_OIDC_BUTTON_LABEL` | `Sign in with SSO` | login button text |
| `TAVRN_OIDC_ONLY` | `false` | disable password and passkey-only login (break-glass below) |
| `TAVRN_OIDC_AUTO_PROVISION` | `true` | create accounts on first login |
| `TAVRN_OIDC_GROUP_MAP` | empty | JSON mapping, §8.5; also editable in the admin UI (`GET/PUT /admin/sso/group-map`) unless set here |
| `TAVRN_OIDC_GROUP_SYNC` | `add` | `add`: grant only; `sync`: also revoke what an earlier sync granted |
| `TAVRN_OIDC_SESSION_DAYS` | `7` | hard end of an SSO session (1–30); the user signs in at the provider again (often silently) |

Startup validation (design note 8) checks the combination; discovery and JWKS are fetched lazily and cached (1 h, one
refetch on an unknown `kid`), so an unreachable provider does not stop the node: SSO logins answer `502
sso.idp_unreachable`, everything else works. The redirect URI to register at the provider is
`https://<domain>/api/v1/auth/oidc/callback` (fixed; never taken from a request).

The node announces `sso.oidc` (§10) and `GET /node` carries `sso: { label, only } | null`, which the login page uses.

### 8.2 Login flow

```
client                               node                                         IdP
  │ POST /auth/oidc/start ─────────────▶ store state, nonce, PKCE verifier,
  │   { code_challenge, client_state,     client challenge (10 min, single use)
  │     device_name, purpose }
  │ ◀── { authorization_url } ─────────
  │ ─ navigate ─────────────────────────────────────────────────────────────────▶ /authorize (code, S256, state, nonce)
  │                                      ◀── GET /auth/oidc/callback?code&state ── redirect
  │                                      token request (code, verifier, secret), ID token checks (§8.7),
  │                                      link / provision (§8.3), group sync (§8.5), one-time code (60 s)
  │ ◀── 303 <web>/sso/callback?code=…&state=<client_state>
  │ POST /auth/oidc/token { code, code_verifier } ──▶ session response (PROTOCOL.md §5a.1)
```

- `POST /auth/oidc/start` `{ purpose: "login" | "link" | "reauth", code_challenge (S256), client_state, device_name? }`
  → `{ authorization_url, expires_in: 600 }`. `link` and `reauth` require a full session (§8.3, §8.4); for them the
  provider must return an identity not linked elsewhere (`link`) or the one linked to that account (`reauth`).
  The node generates
  `state`, `nonce` and its own PKCE pair for the provider; the client's `code_challenge` binds the final exchange
  to the browser that started the flow (the same pattern as the connect flow, `FEDERATION.md` §8).
- `GET /auth/oidc/callback` handles the provider's redirect and always answers with a `303` to the node's own web
  origin (`<web>/sso/callback`, `PROTOCOL.md` §2), never to a URL from the request; errors arrive there as
  `?error=<code>&state=…`. **Tokens never appear in URLs** (design note 4.2).
- `POST /auth/oidc/token` `{ code, code_verifier }` → the session response (`status: "ok"`) for `login`,
  `{ "linked": true }` for `link`, `{ "reauth_token", "expires_in": 300 }` for `reauth`. Codes are single use,
  60 s, bound to the challenge (`400 sso.code_invalid`).
- Signing in on another node's web client uses the connect flow (`FEDERATION.md` §8.3) on the home node; mobile and
  desktop apps (phase 6) use the system browser with the same routes.

### 8.3 Provisioning and account linking

- An external identity is `(issuer, sub)`; it is linked to at most one account and an account to at most one
  identity of the configured issuer.
- **Known identity** → that account (disabled accounts: `401 auth.account_disabled`).
- **Unknown identity, `AUTO_PROVISION` on** → a new local account: username from the username claim, sanitized to
  the grammar of `PROTOCOL.md` §1 and suffixed on collision (`-2`, `-3`, …; never taking over an existing name);
  display name from the display name claim; email from `email` and verified only when `email_verified` is true.
  With `TAVRN_EMAIL=required` an unverified email is refused (`403 sso.email_unverified`). `TAVRN_REGISTRATION` does
  not apply: the provider is the gate. Audited `sso.provision`.
- **Unknown identity, `AUTO_PROVISION` off** → `403 sso.not_provisioned`.
- **Linking** is only possible from a signed-in account (password **and** second factor): settings → "Link SSO
  account" (`purpose: "link"`). The node never links by matching email or username, because whoever controls a
  provider account with a matching claim would otherwise take over a local account. An identity already linked to
  another account: `409 sso.identity_linked`. Audited `sso.link`.
- `GET /auth/oidc/identity` (session) → `{ issuer, linked_at, last_login_at } | null`; `DELETE /auth/oidc/identity`
  unlinks, only if the account also has a password and a second factor (`409 sso.last_login_method`). Audited
  `sso.unlink`.
- **SSO-only accounts** (provisioned, no password) cannot set a password in v1 (`409 sso.password_unavailable`).
  With `TAVRN_OIDC_ONLY` the node refuses `POST /auth/register`, `POST /auth/login` and passkey-only logins
  (`403 auth.password_login_disabled`), **except** for the accounts in `TAVRN_ADMIN_USERS` (break-glass, password and
  second factor as usual), so a provider outage cannot lock the operators out.

### 8.4 Second factor and E2EE

- An SSO login yields a **full session**: the provider is responsible for the authentication strength, so SSO
  logins are exempt from the tavrn second factor (design note 4.2a), also for linked accounts that have one (the password
  path still requires it).
- SSO accounts may register passkeys (for PRF unlocking of the secret storage, `ENCRYPTION.md` §2.4) and TOTP; with
  `TAVRN_OIDC_ONLY` those factors only unlock and never log in.
- E2EE is unchanged: on the first login the client creates the master secret, the recovery key (shown once,
  confirmation required) and the device attestation; new devices unlock from the secret storage with the recovery key
  or a PRF passkey; losing all of them leads to the identity reset, which for SSO-only accounts is confirmed by a
  fresh SSO login instead of the password: `purpose: "reauth"` (§8.2) yields a `reauth_token` (5 minutes, single
  use) passed as `{ identity_public_key, reauth_token }` to `POST /users/me/identity/reset`.

### 8.5 Groups → rights

`TAVRN_OIDC_GROUP_MAP` (or the admin UI) maps provider groups to node rights:

```json
{ "it-admins": { "node_admin": true },
  "staff":     { "room_creation": 5, "app_creation": 3 },
  "devs":      { "rooms": [ { "room": "01J…", "roles": ["01J…", "01J…"] } ] } }
```

- `node_admin`: node admin flag; `room_creation` / `app_creation`: grants for the `invite` modes; `rooms`: membership
  in local rooms with the listed roles (`@everyone` implied).
- **Sync on every login**: the groups claim is read from the verified ID token or from UserInfo (fetched with the
  access token of the same login), never from anything the client sends. Every right a sync grants is recorded in
  `sso_grants`. With `TAVRN_OIDC_GROUP_SYNC=sync`, rights in `sso_grants` whose group is gone are revoked (leaving a
  room, removing a role, clearing the admin flag); rights granted by hand are never touched, and
  `TAVRN_ADMIN_USERS` always wins.
- Room and node bans win over the map: a banned user is not added again. Rooms joined through the map skip the
  join mode and the rules gate, and clients show the rules on first open. Mapped role assignments ignore the role
  hierarchy (the operator configured them) but are audited as `member.roles` with `meta.source = "sso"` and actor
  null; joins as `member.join` events with the same meta.
- Group changes take effect at the next login, at the latest after `TAVRN_OIDC_SESSION_DAYS`.

### 8.6 Sessions and logout

- SSO sessions are normal sessions (1 h access token, rotating refresh token) with a hard end after
  `TAVRN_OIDC_SESSION_DAYS` (the `max_expires_at` mechanism of federated sessions). Federation tokens are issued for
  them as for any full session.
- `POST /auth/logout` revokes the tavrn session as today; for SSO sessions the response additionally carries
  `end_session_url` (the provider's `end_session_endpoint` with `client_id` and `post_logout_redirect_uri =
  <web>/login`) when the provider has one; clients offer "also sign out at <label>".
- Disabling an account at the provider takes effect at the next SSO login or session end; operators who need it
  faster disable the account in tavrn as well. (OIDC back-channel logout MAY be added later as
  `POST /auth/oidc/backchannel-logout`.)

### 8.7 Security checks

- Authorization code flow with PKCE (S256) through the `openidconnect` crate; `state` (single use, 10 min, bound to
  the start request) and `nonce` checked; implicit and hybrid flows are not supported.
- **Issuer pinning**: the discovery document's `issuer` MUST equal `TAVRN_OIDC_ISSUER` exactly, and the ID token's
  `iss` MUST equal it. `aud` MUST contain the client id, `azp` (if present or if several audiences) MUST equal it;
  `exp`, `iat` (±5 minutes), `nonce`; signature against the provider's JWKS with the algorithms the provider
  announces except `none` and HMAC (`RS256`, `PS256`, `ES256`, `EdDSA`). The EdDSA-only rule of design note 9b applies to
  tokens tavrn issues, not to the provider's.
- Provider requests (discovery, JWKS, token, UserInfo) require `https://` and verified TLS; private addresses are
  allowed because the operator configured the provider (company IdPs often live in the LAN), but no redirects are
  followed, responses are capped (256 KiB) and time-limited (10 s).
- Rate limits: `start` 20 per minute per IP, `token` 10 per minute per IP. The client secret, authorization codes,
  ID tokens and access tokens are never logged or stored beyond the login (the ID token is not kept).

### 8.8 Error codes

`sso.disabled` (404: no provider configured), `sso.state_invalid` (400), `sso.code_invalid` (400), `sso.idp_error`
(502: the provider answered with an error, `meta.error`), `sso.idp_unreachable` (502), `sso.token_invalid` (502:
the ID token failed a check), `sso.not_provisioned` (403), `sso.email_unverified` (403), `sso.identity_linked`
(409), `sso.already_linked` (409), `sso.last_login_method` (409), `sso.password_unavailable` (409),
`auth.password_login_disabled` (403).

## 9. Security, limits and operations

### 9.1 Summary

| Topic | Rule |
|---|---|
| Authentication | every application route needs the owner's full session or an app token (§2.3); app tokens are EdDSA JWTs checked against the stored hash on every use; hook requests carry node-signed hook tokens (§6.3); webhooks authenticate by a URL secret stored as a hash |
| Authorization | effective permission = room evaluation ∩ scope mask, 0 in "no bots" zones (§2.4, §3.5); route table fails closed (§2.5); configuration of outgoing URLs is owner-only |
| Least privilege | no `administrator` in add links; granted ≤ the installer's permissions; role creation needs `manage_roles`; private applications only by the owner |
| Cascades | owner disabled → bots disabled; owner banned → bots banned; application blocked → removed from the node; transfer → fresh tokens and identity |
| Outbound | application URLs and the OIDC provider through vetted clients without redirects; SSRF rules of `FEDERATION.md` §1.3 for application URLs |
| Lifetimes | app token ≤ 365 days (rotation with 24 h overlap), interaction 15 min, hook token 5 min, SSO state 10 min, SSO one-time code 60 s, SSO session ≤ `TAVRN_OIDC_SESSION_DAYS` |
| Sizes | public document 128 KiB, command set 64 KiB, webhook payload 32 KiB, callback/URL response 64 KiB, embeds 6000 characters |
| Rate limits | §2.7, §8.7 |

### 9.2 Audit log

Every action of a bot is audited like a user action with the bot as actor and `meta.application` = the application
reference (and `meta.owner`), so moderators can tell bots from people in every entry. New actions:

| Action | Log | `meta` |
|---|---|---|
| `app.create`, `app.update`, `app.delete`, `app.transfer`, `app.identity_reset`, `app.commands`, `app.subscription` | node | application ref, changed fields |
| `app.token_create`, `app.token_reset`, `app.token_revoke` | node | token id, name, device id |
| `app.install`, `app.uninstall` | room | application ref, granted/dropped permissions, role id, reason |
| `command.settings` | room | command ref, settings |
| `room.no_bots`, `category.no_bots`, `channel.no_bots` | room | value, bots removed |
| `webhook.create`, `webhook.update`, `webhook.reset`, `webhook.suspend`, `webhook.delete` | room | webhook id, channel id |
| `admin.app_block`, `admin.app_unblock`, `admin.app_disable`, `admin.app_commands_approve`, `admin.app_commands_reject` | node | bot address / application ref, hashes |
| `sso.provision`, `sso.link`, `sso.unlink`, `admin.sso_group_map` | node | issuer (never the subject's tokens) |
| `member.roles`, `member.join` with `meta.source = "sso"` | room | group |

### 9.3 Abuse controls

Owner bans and disables cascade (§1.7); node admins disable, delete and block applications (§4.4);
`TAVRN_FEDERATION_REMOTE_BOTS=false` refuses all foreign bots; users report applications (§4.4); room managers
uninstall and set "no bots" zones; command approval is available for curated nodes (§5.2); auto-moderation applies to
bots; bot DMs are message requests for non-owners and rate-limited (§2.7).

### 9.4 Logging

Logged (structured, with `request_id`): token use (application, token id, route, status; sampled for successful
reads), token management, installations, interactions (application, command, conversation, outcome, latency; never
arguments or replies), hook deliveries (application, event type, id, status, attempt, latency), webhook executions
(webhook id, status), SSO logins (issuer, account, result, error code). Never logged: app tokens, webhook secrets
(path redacted), hook tokens, command arguments, reply content, OIDC client secret, codes, ID or access tokens.

### 9.5 Error codes (applications)

`app.not_found` (404), `app.creation_forbidden` (403), `app.limit_reached` (409), `app.username_taken` (409),
`app.permissions_invalid` (400), `app.scope_invalid` (400), `app.scope_missing` (403), `app.bot_forbidden` (403/400),
`app.disabled` (403), `app.blocked` (403), `app.private` (403), `app.owner_banned` (403), `app.room_no_bots` (403),
`app.already_installed` (409), `app.room_limit` (409), `app.not_installed` (404), `app.token_limit` (409),
`app.token_not_found` (404), `app.name_confirm` (400), `app.transfer_pending` (409), `app.transfer_not_found` (404),
`app.transfer_target_invalid` (400), `app.url_invalid` (400), `app.url_verification_failed` (400),
`app.manage_forbidden` (403, `manage_applications` missing), `validation.bots_in_encrypted_channels` (400),
`webhook.not_found` (404), `webhook.limit` (409), `webhook.disabled` (403),
`webhook.username_invalid` (400), `webhook.payload_invalid` (400), `webhook.too_large` (413),
`webhook.sealing_invalid` (400), `webhook.sealed_required` (400), `webhook.epoch_invalid` (400),
`webhook.pending_key` (409), `webhook.not_sealed` (409), `inbox_key.invalid` (400), `inbox_key.bad_signature` (400),
`inbox_key.not_encrypted` (400), `inbox_key.no_webhooks` (409), `inbox_key.stale` (409),
`subscription.event_invalid` (400), `subscription.not_found` (404), `webhook.manage_forbidden` (403),
`message.embeds_invalid` (400); commands §5.9, SSO §8.8.

### 9.6 Operator switches

| Variable | Default | Meaning |
|---|---|---|
| `TAVRN_APP_CREATION` | `all` | `all`, `invite`, `admins` (§1.2) |
| `TAVRN_APPS_PER_USER` | `5` | applications per owner |
| `TAVRN_APPS_PER_ROOM` | `25` | installed applications per room |
| `TAVRN_APP_TOKEN_MAX_DAYS` | `365` | maximum app token lifetime (1–3650) |
| `TAVRN_APP_RATE_REQUESTS` | `1200` | API requests per application and minute |
| `TAVRN_APP_COMMANDS_REQUIRE_APPROVAL` | `false` | node admins approve every command definition (§5.2) |
| `TAVRN_APP_ALLOW_PRIVATE_URLS` | `false` | allow application URLs on private/loopback addresses (intranets, tests) |
| `TAVRN_APPS_FEDERATE` | `true` | this node's bots may obtain federation tokens (split from `TAVRN_FEDERATION_REMOTE_BOTS`, §2.8) |
| `TAVRN_FEDERATION_REMOTE_BOTS` | `true` | accept bots of other nodes (existing; meaning narrowed) |
| `TAVRN_WEBHOOKS_ENABLED` | `true` | incoming webhooks |
| `TAVRN_WEBHOOKS_PER_CHANNEL` | `10` | webhooks per channel (room cap 50) |
| `TAVRN_OIDC_*` | – | §8.1 |

Variables of the **bot process** (SDK, not the node): `TAVRN_BOT_NODE` (node URL), `TAVRN_BOT_TOKEN`,
`TAVRN_BOT_KEY` / `TAVRN_BOT_KEY_FILE` (§3.1), `TAVRN_BOT_STATE_DIR` (§3.3).

## 10. Capabilities, versioning and changes to other documents

### 10.1 Capabilities

| Capability | Announced by | Meaning |
|---|---|---|
| `apps.v1` | nodes | §1–§4, §7.1–§7.2: applications, app tokens, scopes, bot devices, "no bots", installation, `app.*` inbox types |
| `commands.v1` | nodes and clients | §5: command definitions, palette route, interactions; clients merge the palette and encrypt arguments |
| `webhooks.v1` | nodes (while `TAVRN_WEBHOOKS_ENABLED`) | §6: incoming webhooks, subscriptions, hook tokens, embeds |
| `sso.oidc` | nodes (with a configured issuer) | §8 |

Incompatible changes (token claims, hook token format, the bot key file, the interaction protocol) get `.v2`
capabilities and run in parallel for at least 12 months (`PROTOCOL.md` §3). New scopes, event types, command arg
types and embed fields are compatible additions; receivers ignore unknown ones, except scopes, which nodes refuse at
token creation (§2.4). A client without `commands.v1` shows built-in commands only; a client without `apps.v1`
still shows bots with the badge rule of §1.5, which depends only on `kind`.

### 10.2 Additions to other documents (to be folded in during phase 5)

- **PROTOCOL.md**: §1 `kind` takes `webhook`; `User` objects of bots carry `owner` and `application_id`; §3 the
  four capabilities; §5 token table: `app` lifetime "≤ `TAVRN_APP_TOKEN_MAX_DAYS`, revocable", new `hook` typ; §5a
  SSO routes and `auth.password_login_disabled`; §6 events `application.install`, `application.uninstall`,
  `application.token_expiring`, `application.subscription_disabled`, `commands.update`, `command.invoke`,
  `interaction.reply`; WebSocket close code `4004` (§2.6); §6a activity fields `state`, `ends_at`, `application`;
  §7 envelope fields `author_kind`, `interaction`, `webhook`, `device_id` nullable for webhook messages, `embeds` in
  `text` content, reserved content type `command.args`; §8a bots in DMs only.
- **permissions.md**: new bit `manage_webhooks` (management class, never on `@everyone`, design note 4.11) at the next
  free position after the phase 4E bits; the evaluation gains the bot inputs (`kind`, effective `no_bots`, scope
  mask) with test vectors in `testvectors/permissions.json`.
- **ENCRYPTION.md**: §2.3 the keys document carries `kind`; §3/§8 bot devices (token-bound, no secret storage);
  §4.5 rule 2/3 bots are not entitled in "no bots" channels; §4.6 the bot ghost rule of §3.5; §9 the owner-driven
  bot reset of §3.4 and the SSO confirmation of §8.4.
- **FEDERATION.md**: §2.2 claims `app` and `scopes` for bots; §2.4 `TAVRN_APPS_FEDERATE`; §2.5 application blocklist
  check; §2.8 the new local-only routes (`/applications*` owner routes, `/auth/oidc/*`, `/admin/applications*`);
  §5.2 inbox types `app.install`, `app.uninstall`, `app.changed`; §9.2 report subject `application`; §11.4
  `TAVRN_FEDERATION_REMOTE_BOTS` narrowed.
- **Node configuration** (design note 8): the switches of §9.6 and §8.1.

## 11. Phase 5 implementation order

Every step is test-first (design note 9a); every route gets a permission test with a caller lacking the permission, a
bot token lacking the scope and a remote user, and every limit an exceeding test. Rust integration tests use the
in-process `TestNode` (two nodes for federation cases); SDK tests run Vitest against an in-process node started by
the test harness; Playwright runs the web client against real nodes (phone, tablet and desktop projects).

- [x] **1. Applications, tokens, scopes, "no bots" (node)**: migrations (§1.1), `POST/GET/PATCH/DELETE
  /applications`, avatar, transfer, tokens (create, reset, revoke, rotate), `typ = app` in the extractor, the
  fail-closed `APP_ROUTES` table with scopes, WS hello with app tokens and scope filtering, per-application rate
  limits, owner cascades (disable, ban, delete), `no_bots` flags and the bot branch of permission evaluation (Rust and
  `permissions.ts`, shared vectors), MLS rules for bots, `kind`/`owner`/`author_kind` on objects, bot E2EE
  routes with app tokens, owner identity reset, `TAVRN_APPS_FEDERATE` split, federation token claims `app`/`scopes`
  and their enforcement on T. Tests: token tampering (wrong `alg`, `typ = session` claims in an app token, expired,
  revoked, reset old secret, rotated secret after 24 h), hash mismatch, every scope boundary, administrator bit
  masked by scopes, bot refused on each never-allowed route, "no bots" at all three levels incl. external join and
  Add refused and `mls.remove_needed`, owner disabled → bot `403` and WS `4001`, remote bot with narrowed scopes on
  T, `federation.bots_refused` both directions.
- [x] **2. Add link and per-room applications**: public document, `POST/GET/DELETE /rooms/{id}/applications`, role
  creation rules, local and remote installs with the public document fetch, `app.install`/`app.uninstall`/
  `app.changed` inbox types, install index, node blocklist and admin routes, reports. Tests: granted ⊆ installer ∩
  requested, `administrator` refused, private app by non-owner, `manage_roles` missing → no role, banned owner,
  room limit, blocked bot uninstalled everywhere, cross-node install with two `TestNode`s; Playwright: consent screen
  (permission checkboxes, disabled permissions, room picker with a "no bots" room disabled, remote bot domain
  shown), uninstall from the room settings, BOT badge in member list, header, mention and DM.
- [x] **3. Commands**: definitions and `PUT …/commands`, approval, per-room settings, palette route, interactions
  (WS and URL delivery, 3 s ack, callbacks, follow-ups, ephemeral replies), `commands.update`, encrypted arguments.
  Tests: every check of §5.5 in order, ack timeout with an injected clock, duplicate callback, follow-up limit,
  encryption mismatch both ways, round robin over two devices, approval invalidated by a definition change; Vitest:
  palette merge (built-in collisions, two apps with one name, permission filter), argument encryption and the bot's
  replay/command checks; Playwright: type `/`, pick an app command, fill a pick-list arg, see the reply, an ephemeral
  reply and "thinking…" for a deferred one, in an unencrypted and an encrypted channel.
- [x] **4. Webhooks in and out**: `manage_webhooks` bit, webhook routes and execution, pseudo users, envelope
  `webhook`, embeds, suspension on the encryption switch, subscriptions with the outbox, hook tokens, URL
  verification. Tests: secret and id oracle (both `404`), encrypted channel refused and suspended, payload limits and
  username rules, `@everyone` gating, log redaction, SSRF targets (`127.0.0.1`, `169.254.169.254`, redirect to a
  private address), retry schedule and disable after 3 days, no encrypted content ever enqueued; Playwright: create a
  webhook, copy the URL once, post with `curl`-like fetch, see the WEBHOOK badge and embed rendering.
- [x] **5. SDK bot runtime**: move the MLS session manager and content codec of the web client's `crypto` module into a shared module
  usable by `@tavrn/sdk` (the web client keeps using it), add `createBot({ node, token, keyFile | key, stateDir })`
  with key file bootstrap (§3.1), attestation and KeyPackage top-up, federated sessions for remote installations,
  eager/lazy group joins, `bot.command(name, handler)` with `reply`/`defer`/`followUp`/`ephemeral`, encrypted argument
  handling, `verifyHookRequest()`, token rotation, and an example bot in the `@tavrn/bot` examples (echo + `/weather`-style
  command, encrypted channel). Tests: Vitest against an in-process node: first start creates the key file and
  identity, restart reuses state, missing key with existing identity fails clearly, the bot reads and answers in an
  encrypted channel, a remote installation on a second node works, hook verification rejects tampered bodies,
  replayed `jti` and wrong `htu`. Done in two parts: 5a (shared module `@tavrn/e2ee`) and 5b (the runtime
  `@tavrn/bot`, notes in §12 "Step 5b").
- [ ] **6. SSO via OpenID Connect**: config and validation, discovery/JWKS cache, start/callback/token routes, linking
  and unlinking, provisioning, `TAVRN_OIDC_ONLY` with break-glass, group map with `sso_grants` and sync modes,
  session cap, logout URL, identity reset confirmation by SSO. Tests: a fake provider in the Rust test harness
  (`--dev`, `http://` issuer) covering wrong `iss`, wrong `aud`/`azp`, expired, bad `nonce`, reused `state`, `alg =
  none`/HS256, unknown `kid` refresh, `email_verified` false with `TAVRN_EMAIL=required`, username collisions,
  no auto-link by email, `sync` revoking only SSO grants, bans winning over the map; Playwright: SSO button, login
  through the fake provider, first-login recovery key setup, linking from the settings.
- [x] **7. Rich presence**: activity fields, bot presence with the `presence` scope, the bridge interface as a typed
  module and a mock bridge for tests (implementation in the phase 6 desktop app). Tests: activity validation, scope
  refusal, consent decision storage in the mock bridge.

Each step ends with the full check suite green, the OpenAPI regenerated, `PROTOCOL.md`/`FEDERATION.md`/`ENCRYPTION.md`/
`permissions.md` updated per §10.2, and implementation notes appended here as §12.

## 12. Implementation notes

These notes record how the reference implementations realize this document. File names refer to them: Rust
files and migrations to the node (repository `tavrn-node`), `sealed.rs` to `tavrn-crypto`, TypeScript files to
`@tavrn/sdk`, `@tavrn/e2ee` and `@tavrn/bot` (repository `tavrn-js`) or the web client (`tavrn-web`), and
`*.spec.ts` to the end-to-end suite of `tavrn-web`.

### Step 5a: shared encryption module (2026-10-05)

- The client side of the encryption moved out of the web client's `crypto` module into the package `@tavrn/e2ee`
  (repository `tavrn-js`, MPL-2.0, TypeScript source like `@tavrn/sdk`): the MLS session manager (`MlsManager`, unchanged
  behaviour), the content and attachment codecs, the plaintext signature helpers, the account flows (device
  attestation, KeyPackage top-up, recovery key and passkey PRF unlock, identity reset) and `ensureCrypto()`, which
  loads `@tavrn/crypto` with `init()` in browsers and `initSync` from the package file in Node.js.
- Local state goes through the `KeyStore` interface (master secret, device id, named secrets, encrypted under
  `local_key`, `ENCRYPTION.md` §2.1). Implementations: the web client's IndexedDB store (`crypto/store.ts`,
  with "lock on close"), `MemoryKeyStore`, and `FileKeyStore` (`@tavrn/e2ee/node`) for `TAVRN_BOT_STATE_DIR`
  (§3.3): one `state.json` (mode 0600, directory 0700) with a plaintext header (`v`, `account`, `device_id`, `iv`)
  and AES-256-GCM over all secrets with additional data bound to the account; atomic serialized writes; no key on
  disk, so the bot unlocks it with the master secret from its key file on every start; one account and one
  process per directory.
- `openMlsManager(store, …)` builds the session manager from a `KeyStore` (client state `mls-client`, `pins`,
  `mls-meta`, `verified-contacts`); the web client and the bot runtime (step 5b) share it.
- WebAuthn, the UI stores and React hooks stay in the web client (`tavrn-web`). The Playwright helpers load the WebAssembly through
  `ensureCrypto()` but keep driving raw MLS clients (the specs need devices that misbehave).
- Open for step 5b: `@tavrn/e2ee` depends on `@tavrn/sdk` (types, base64url, JCS, `TavrnApiError`). A `createBot()`
  inside `@tavrn/sdk` would make the two packages depend on each other; decide in step 5b between a package that
  depends on both (e.g. `@tavrn/bot`, re-exported by the SDK docs) and accepting the workspace cycle.

### 12.6 Step 6: SSO via OpenID Connect (2026-10-05)

- **No `openidconnect` crate** (deviation from §8.7): the node implements the small code flow itself on reqwest
  (`oidc/`) and verifies ID tokens with jsonwebtoken 10 (`rust_crypto`, JWK parsing plus the RustCrypto
  RSA/PSS/ECDSA/Ed25519 verifiers, called explicitly because livekit-token installs an HMAC-only process-global
  provider). Reasons: one provider and one flow, exact control over the outbound requests (no redirects,
  256 KiB / 10 s caps, issuer pinning), no second HTTP stack, a fraction of the dependency tree.
- **Accepted algorithms**: RS256, PS256, ES256 (P-256), EdDSA (Ed25519), intersected with the provider's
  `id_token_signing_alg_values_supported` (missing = RS256). `none`, every HMAC algorithm, keys marked `use: enc`,
  keys whose own `alg` differs and RSA keys below 2048 bits are refused. An unknown `kid` refetches the JWKS once
  (at most every 10 s). `iat` must lie within ±5 minutes, `exp`/`nbf` have 60 s leeway, `azp` is required with
  several audiences. The discovery document must announce PKCE S256 if it lists methods at all.
- **Effects at the exchange, not in the callback** (deviation from the §8.2 diagram): the callback only verifies
  the provider's answer and stores the verified identity under the one-time code; provisioning, linking, the
  group sync and the session happen at `POST /auth/oidc/token`, in the browser that holds the PKCE verifier (and,
  for `link`/`reauth`, the session that started the flow, `403 sso.session_mismatch`). A callback URL replayed in
  another browser (login or linking CSRF) therefore changes nothing; the error codes of §8.3 are answers of that
  route.
- **State in memory** like the connect codes (FEDERATION.md §8): provider state with nonce and the node's PKCE
  verifier (10 min), one-time codes (60 s), reauth tokens (5 min), at most 10 000 each (`503 sso.busy`). A restart
  only invalidates logins in progress.
- **Reauth** (§8.4) adds `prompt=login&max_age=0` and requires `auth_time` not older than the start of the flow;
  the provider must confirm the linked subject (`403 sso.identity_mismatch`). `POST /users/me/identity/reset` takes
  `password` or `reauth_token`.
- **Additional codes**: `sso.not_linked` (409: reauth or unlink without a linked identity), `sso.session_mismatch`
  (403), `sso.identity_mismatch` (403), `sso.busy` (503), `sso.group_map_fixed` (409), `sso.group_map_invalid` (400);
  the callback adds `idp_error=<sanitized OAuth error>` to `error=sso.idp_error`.
- **Provisioning**: usernames are the sanitized claim (local part of an email-like value, invalid characters → `-`,
  fallback `user`), suffixed `-2`, `-3`, …; the names of `TAVRN_ADMIN_USERS` and the conformance probe are never
  given to SSO accounts (break-glass names stay with the operators). Only the very first account of a fresh node
  becomes admin automatically. Display names follow the claim on every login.
- **Group map**: `sso_grants(user_id, kind, room_id, role_id, grp, granted_at)` with kinds `node_admin`,
  `room_creation`, `room`, `role`. A right that existed before (manual admin flag, manual membership or role, a
  room creation grant by an admin) is not recorded and therefore never revoked by `sync`. Room creation grants are
  created once (they are consumed per room), not refilled at every login. Map joins skip join mode and rules
  (rules not accepted, clients show them), are audited as `member.join`/`member.roles` with actor null and
  `meta.source = "sso"`, and `sync` revocations leave as `member.leave` (the room owner is never removed). Room and
  node bans win. `app_creation` is validated and stored but applied once applications (step 1) are merged.
- **Sessions**: `sessions.sso = 1`, `max_expires_at = now + TAVRN_OIDC_SESSION_DAYS`; refreshes never extend it.
- **`check-config`** fetches discovery and JWKS when an issuer is set and prints the redirect URI to register;
  the client secret is never serialized.
- **Tests**: `sso_flow.rs` (14 tests) against a fake provider on `127.0.0.1` (`tests/common/oidc.rs`,
  `--dev` allows `http://`) covering every negative case of §11; unit tests for the token checks, the map, the
  username rules and the configuration; Vitest for the flow helpers and the callback page; Playwright
  `sso.spec.ts` with `fake-oidc.mjs` (button, first login with the recovery key and no second
  factor, provider logout, denied login, linking from the settings and signing in afterwards, group → role in the
  member list, an SSO-only node with break-glass sign-in).
- **Open**: OIDC back-channel logout (§8.6 MAY), `app_creation` grants (after step 1). The admin UI for the group
  map came with step 2 (admin page, tab "SSO", shown while the node announces `sso.oidc`).
### Step 1: applications, tokens, scopes, "no bots" (2026-10-05)

Implemented: `applications.rs` (token claims and verification, `APP_ROUTES`, event filter, WebSocket
registry, cascades), `store/applications.rs`, `routes/applications.rs`, migration
`0070_applications.sql`, the bot branch of `permissions.rs` / `permissions.ts` with shared vectors, the
"no bots" flags, the federation claims, the SDK methods `api.applications.*` and the web client's "Applications"
settings tab and "no bots" toggles. Where the reference node deviates from or refines §1–§3:

- **Joining rooms before installations exist.** Installation (§4) is step 2. Until then a bot joins a room only
  through a **direct invite bound to its address** (`POST /rooms/{id}/invites/direct`) that a member holding
  `manage_room` created, and only outside "no bots" rooms: `POST /invites/{code}/join` is classified `always`
  in `APP_ROUTES`, and the handler refuses every other invite with `403 app.bot_forbidden` (no-bots room:
  `403 app.room_no_bots`). Public joins (`POST /rooms/{id}/join`) stay refused. Step 2 replaces this path with
  the add flow and removes the interim rule.
- **Tables.** The migration creates the tables step 1 uses (`applications`, `application_tokens`,
  `application_transfers`, `application_blocks`) plus `sessions.application_ref` / `sessions.scopes` for remote
  bots and `users.app_creation_grant`; the other tables of §1.1 come with their steps. `application_tokens`
  additionally keeps `prev_token_hash` (the previous secret is checked against its hash during the 24-hour
  rotation overlap) and `rotated_at`.
- **Bot user objects.** `owner` and `application_id` are stored on the bot's user row (`users.owner_address`,
  `users.application_id`) so every `User` can be built without a join; remote bots get them from the federation
  token (`application_id = <H>/<app>`). A deleted application leaves the bot row disabled with `owner_id` cleared
  (so removing an owner can never cascade to it) and `owner_address` kept for attribution.
- **Revoked tokens are deleted** together with their device; `AppToken.revoked_at` is therefore always null in
  listings (the audit log keeps `app.token_revoke`).
- **Owner disabled** is evaluated on every request (`403 app.disabled`, `meta.reason = owner_disabled`); nothing
  is stored on the application, so re-enabling the owner re-enables the bots at once. Disabling the owner (admin
  `PATCH /admin/users/{id}` or a node ban of the address) closes the bots' WebSockets (`4001`) and sends
  `session.revoke` to their federation targets. The node has no account deletion route yet, so "owner deleted"
  has no trigger in this step.
- **Owner bans.** A room ban of an address or domain removes every member bot whose owner it names (audited as
  `app.uninstall`, `meta.reason = owner_banned`); direct invites and joins of such bots are refused with
  `403 room.banned`. Node bans remove them from every room of the node.
- **Identity reset of a bot** (§3.4): the reset clears the key, so the S2S notification at reset time is
  `devices.changed` (`identity.changed` needs a key, `FEDERATION.md` §5.2); when the bot sets its new key with
  `PUT /users/me/identity` the node sends `identity.changed` locally and to the federation targets.
- **Owner routes.** `GET /applications/transfers` (not in §1.6) lists transfers offered to the caller; the
  `Application` object additionally carries `transfer` (the pending outgoing transfer) and `dm_policy`.
  `interactions_url` cannot be set yet (it needs the URL verification of §6.3, steps 3/4); `rpc_origins` is
  validated (at most 10 `https://host[:port]` origins, `400 app.url_invalid`). `GET /applications/me` and the
  rotation answer `404 app.not_found` to callers without an app token of this node. Rotation keeps the token's
  lifetime (capped by `TAVRN_APP_TOKEN_MAX_DAYS`); verification also refuses tokens whose `exp − iat` exceeds it.
- **Route table classifications** beyond the lists of §2.4: conversation listings, message requests and room
  emojis under `messages:read`; read markers, upload policy and `POST …/ephemeral` under `messages:write` (the
  handler additionally requires `whiteboard` for `whiteboard.*` types); `PATCH /rooms/{id}/members/{user}`
  under `moderation` or `rooms:manage`; room icon, soundboard management and direct invites under
  `rooms:manage`; DM calls and soundboard playback under `voice`; message-request accept/decline under `dms`.
  `DELETE /rooms/{id}`, `GET /users/me/devices`, the conversation index and the notification settings stay
  closed. The WebSocket operations `typing` and `ack` need `messages:write`.
- **Event filter** (§2.6): `room.*` (except `room.invite`), `channel.*`, `category.*`, `role.*`, `mls.*`,
  `application.*`, `override.update`, `identity.changed`, `devices.changed` always; `message.*`, `reaction.*`,
  `pin.*`, `emoji.*`, `conversation.*` (except `conversation.invite`), `typing`, `read.update` and `ephemeral`
  type `cursor` with `messages:read`; `member.*`, `presence.*`, `user.update` with `members:read`; `voice.*`,
  `call.*`, `soundboard.*` with `voice`; `whiteboard.*` and `ephemeral` type `whiteboard.*` with `whiteboard`;
  `command.*` with `commands`; everything else (friends, notifications, invites) is dropped.
- **Rate limits** of §2.7 apply in development mode as well (they are part of the protocol); the five creations
  per day are counted in memory per process. Remote bots share one budget per bot (`app:<local user id>`).
- **"No bots".** Setting the room flag removes every bot member (`app.uninstall`, `meta.reason = no_bots`;
  `room.no_bots` records `bots_removed`) and emits `channel.update` for every channel (their effective flag
  changed). Category and channel flags need `manage_room` and `manage_channels`. `GET /rooms/{id}` omits the
  channels a bot cannot view, so a "no bots" channel is invisible to it; `channel.*` events still name it (they
  are always delivered). The room member list is per room and is not filtered per channel: the client-side ghost
  rule of §3.5 (ENCRYPTION.md §4.6) is the safeguard; it is not in the clients yet and follows in `@tavrn/e2ee`
  (step 5a moved the session manager there in parallel with this step).
- **Not yet in this step:** `application.token_expiring` (event and email), the capability `apps.v1` (announced
  once installations exist, step 2), the admin routes and blocklist management of §4.4 (the blocklist is
  already checked for app tokens and federated logins), `kind = "webhook"` users (step 4).

### Step 2: add link and per-room applications (2026-10-06)

Implemented: `installations.rs` (public document, the add flow, uninstalls, the install index, `app.*`
inbox handlers, blocks), `store/installations.rs`, `routes/installations.rs`, migration
`0180_app_installs.sql`, the web client's add link and consent screen (`/add/<id>`, `/add/<domain>/<id>`,
`pages/AddApplicationPage.tsx`), "Add an application" in the room settings (new "Applications" tab) and the
"+" dialog, the admin page's "Applications" tab and the SSO group map tab. Where the reference node deviates from or
refines §1.8 and §4:

- **The interim join path of step 1 is gone.** Bots enter rooms only through an installation: `POST
  /invites/{code}/join` and `POST /rooms/{id}/join` answer `403 app.bot_forbidden` for every bot (the invite join is
  no longer in `APP_ROUTES`); direct invites of bot addresses can still be created but never used.
- **Transaction boundary.** Membership, managed role, member role and installation row are written in one
  transaction; the stub user of a remote bot (and its owner stub, profile mirror, owner address and application
  reference) is created just before it, outside the transaction, like every other stub (FEDERATION.md §2.6). A
  failed installation can therefore leave a stub, which the remote user cleanup removes like any unused stub.
- **Role position.** "Directly below the caller's highest role": the managed role takes the position of the
  caller's highest role and every non-`@everyone` role at or above it moves up by one (`role.update` for each);
  for owners and node admins it goes above every role. Names collide case-insensitively (`Name (2)`, `Name (3)`, …).
  The role carries `application_id` = the application reference; the web client shows "Managed by <name>" in the
  role list and editor. `create_role` defaults to `true`; with `create_role: false` (the consent screen sends it when
  the installer lacks `manage_roles`) the bot joins with `@everyone` only and `permissions` is recorded as granted.
- **Installation object.** `dropped_permissions` is part of the `201` answer only; listings carry
  `enabled_commands` (always 0 until step 3). The application's name and avatar are the bot user's (the owner's
  rename also renames the bot, §1.6).
- **Uninstall reasons.** `removed` (room managers), `kicked`, `banned` (address or domain ban, also node bans of
  remote bots), `left` (the bot itself), `no_bots`, `owner_banned`, `blocked`, `deleted`. Every bot that leaves a
  room by any path loses its managed role and installation row, is audited as `app.uninstall` and is told
  (`application.uninstall` locally; `app.uninstall` to its home node, except for `deleted`). `DELETE
  /rooms/{room_id}/applications/{application_ref}` takes the reference with the slash percent-encoded and answers
  `404 app.not_installed` for anything not installed.
- **Install index.** H indexes local installations directly and remote ones on `app.install` (with the room name of
  the message), so `GET /applications/me/installations` lists both; `app.changed` goes to every *other* node of the
  index. `app.changed` is sent on name, avatar (set or removed), scopes and requested permission changes and on
  deletion (before the application row and its index go). The receiver acts only for a bot it knows as exactly that
  application (`<iss>/<application_id>`); otherwise it answers `202` with no effect. Deletion disables the stub, so
  federated logins fail with `401 auth.account_disabled` and installations with `404 app.not_found` (H no longer
  serves the document).
- **Inbox checks.** `app.install` / `app.uninstall` must come from the room's node (`from` = `iss`, `403
  federation.type_forbidden` otherwise, counted as a conformance violation) with `room.node` = `iss` (`400
  federation.envelope_invalid`); recipients that are no bot of this node, or a bot whose application is disabled,
  get `404 federation.recipient_unknown`. Unknown uninstall reasons are stored as `removed`. An application's index holds
  at most 10 000 entries; further `app.install` messages are accepted and ignored.
- **Admin routes and codes beyond §4.4.** `PATCH /admin/applications/{id}` answers `204` and is audited as
  `admin.app_disable` `{ application, disabled }`; disabling closes the bot's WebSockets and ends its federated
  sessions. `POST /admin/applications/blocks` answers `201 ApplicationBlock`, refuses malformed addresses (`400
  validation.address`), user addresses (`400 app.not_a_bot`) and duplicates (`409 app.already_blocked`); `DELETE`
  of an unknown block is `404 app.block_not_found`. Blocking a local bot also closes its WebSockets and revokes its
  federated sessions; blocking a remote bot revokes its sessions here. `admin.app_block` records `bots_removed`.
  Admin API tokens cannot use these routes (they are not in the admin token scope table).
- **Reports.** `POST /directory/reports` takes `{ subject: { kind: "application", ref }, check, detail }` instead of
  `domain` (`400 validation.subject` for other kinds or malformed references); unlike node reports, an application
  of the reporter's own node may be reported. Stored in `directory_reports.application_ref`, listed with
  `application` in the reports of that domain (admin Federation tab).
- **Public document.** `Cache-Control: public, max-age=300`; `avatar` is the still image of the bot's avatar on H and
  `avatar_sha256` its hash; `commands` is empty until step 3. Receivers ignore unknown scopes in it and refuse
  documents whose `ref`, `id`, `node`, `bot` or `owner` do not belong to the serving domain, whose
  `requested_permissions` contain `administrator`, or whose name is empty (`502 federation.peer_invalid`).
- **Client.** The room picker lists rooms of the home node and of every node with a federated session (room details
  are loaded per room to read `my_permissions`); add links of another node's web client are recognized by the web
  origins of known sessions, other links only with `https` and a real domain. Mentions of bots in messages carry a
  BOT badge (the `mentions` list of the message decides). `application.token_expiring` shows a toast.
- **`TAVRN_APPS_PER_ROOM`** (default 25, 0–1000) limits installations per room (`409 app.room_limit`, `meta.max`).
- **Token expiry notices** (§2.2, leftover of step 1): the hourly housekeeping sends `application.token_expiring`
  seven days and one day before a secret expires, to the owner and the bot, once per threshold and secret
  (`application_tokens.expiry_notified_days`); the e-mail of §2.2 followed later (localized like the other mails of the
  node). The draft named 14 and 3 days;
  the phase 5 task set 7 and 1, and §2.2 now says so.
- **Tests.** `app_install_flow.rs` (12 tests: granted ⊆ installer ∩ requested with the role position,
  administrator and non-subset refused, private application, `manage_roles` missing, name collisions, owner and bot
  bans, node ban, disabled and blocked applications, room limit, "no bots", uninstall/kick/ban with WS events and
  the index, the public document, admin routes and blocklist, application reports, cross-node install with
  `app.install`/`app.uninstall`/`app.changed` and deletion, remote bots refused, blocked on T and private, inbox
  tampering, token expiry notices, bot presence); `applications_flow.rs` moved to installations; unit
  tests for the document rules, references, role names and inbox payloads; Vitest for add links and mention badges;
  Playwright `app-install.spec.ts` (consent screen with checkboxes, disabled permissions and a disabled
  "no bots" room, install, managed role marker, BOT badge on message, mention, member list and DM, uninstall from the
  room settings, pasted links in the "+" dialog and the room settings, a bot of a.test installed on b.test with its
  home node shown) and `admin-apps.spec.ts` (disable, block, unblock, delete; SSO group map).
- **Open:** command counts and `commands` in the document (step 3); the token expiry e-mail; a room picker in the SSO
  group map tab (rooms and roles are entered as ids).
- **Update (2026-10-06, bots and E2EE wave):** installing, uninstalling and the room picker of the consent screen now
  use `manage_applications` (bit 35) instead of `manage_room` (`403 app.manage_forbidden`); the installation list is
  readable with either. The "Applications" tab of the room settings needs the new bit. Installations into rooms created
  from now on reach encrypted channels only where the channel allows bots ("Bots in encrypted channels" below).

### Step 7: rich presence (2026-10-06)

- **Node.** `Activity` gains `state` (≤ 128 characters, no control characters), `ends_at` (after `started_at`, at
  most 7 days ahead) and `application` `{ ref, name }` (`<domain>/<ULID>`, name 1–128 characters; the domain is
  lower-cased, the id kept). Everything else of a bad activity is `400 presence.activity_invalid` as before; a body
  that is not an activity at all (e.g. `application` without `ref`) is `400 request.invalid_json`. Bots use
  `PUT /users/me/presence` and `PUT`/`DELETE /users/me/activity` with the `presence` scope (`403 app.scope_missing`
  without it, already classified in step 1); their activity, like a user's, belongs to an open WebSocket, so a bot
  shows activity only while connected.
- **Bridge (§7.3).** `activity/bridge.ts` fixes the interface for the phase 6 desktop app: protocol constants
  (path, version, ports 46480–46489, close code 4003, one update per 5 s with coalescing), typed messages and a
  parser that never throws, the origin rule (an unlisted origin is closed with 4003 without any answer, so a web page
  cannot probe for applications), the handshake (public document of the application's node, `ref` and bot domain
  checked, `presence` scope required, else `app.not_allowed`), consent per application reference in `localStorage`
  (`tavrn.activity.consent`; "always" and "never" are stored, "once" and a dismissed prompt are not), the
  `hide_activity` rule (nothing asked, nothing published, the program still gets `ok`), `application` taken from
  the document rather than from the program, clearing on disconnect, and a `MockTransport`. There is no listener in
  the browser; the consent dialog itself comes with the desktop app.
- **Client.** The member list's activity line and the profile card show `details`, `state`, "until <time>" and
  "via <application name>" with the bot's avatar when the bot of `application.ref` is a known room member. The
  privacy settings list the stored bridge decisions ("Game activity: allowed applications") with revoke.
- **Tests.** Unit tests of the validation (`presence.rs`), the presence part of `app_install_flow.rs` (scope
  refusal on all three routes, the bot's status and activity reaching a room member, rich fields accepted and
  refused through the route), Vitest `activity/bridge.test.ts` and `display.test.ts` (consent decisions,
  storage and revocation, `hide_activity`, message parsing, origin rule, handshake refusals, rate limit, clearing),
  Playwright `activity.spec.ts` ("via" in the member list and profile card, revoking a stored decision).

### Step 4: webhooks in and out (2026-10-06)

Implemented: `webhooks.rs` (secrets, execution, pseudo users, suspension, log redaction),
`embeds.rs` (the node's half of the embed codec), `hooks.rs` (URL rules, the vetted outbound
client, hook tokens, URL verification), `subscriptions.rs` (recording, outbox delivery, states), the
stores `store/webhooks.rs` and `store/subscriptions.rs`, the routes `routes/webhooks.rs` and
`routes/subscriptions.rs`, migration `0190_webhooks.sql`, `embeds.ts`, `verifyHookRequest()` /
`HookVerifier` in `hooks.ts`, the room settings tab "Webhooks" and the "Event subscriptions" section of the
application editor. Where the reference node deviates from or refines §6:

- **Pseudo users** (`kind = "webhook"`, username `wh.<lowercase id>`, display name = the webhook's name) name their
  creator only by address (`users.owner_address`, shown as `owner`); `owner_id` stays null, so nothing cascades from
  the creator's account and the owner/bot DM shortcut never applies. They have DMs set to `friends`, and
  `resolve_or_stub` never returns them, so friend requests, blocks, DMs and direct invites answer
  `404 user.not_found`. Usernames starting with `wh.` are reserved for registration, applications and SSO
  provisioning. A deleted webhook leaves its pseudo user as a disabled tombstone (its messages keep an author and
  their `webhook` envelope field); a deleted channel or room deletes its webhooks with it. The admin user list and
  the node statistics skip pseudo users; member lists, rosters and presence never contain them (no memberships).
- **Execution**: the order of checks is `TAVRN_WEBHOOKS_ENABLED` (`403 webhook.disabled`), size (`413
  webhook.too_large`, declared or read), id + secret (`404 webhook.not_found`; an unknown id hashes and compares
  against a placeholder, so both paths do the same work), the rate limits of §2.7 (after the secret check, so a
  stranger who knows only the id cannot use up the webhook's budget), then the payload (in encrypted channels the
  sealing rules of §6.1a; the former `409 webhook.channel_encrypted` is gone). Payloads are `deny_unknown_fields` (`attachments` and other
  fields: `400 webhook.payload_invalid`) and `content.type` must be `text`. `mentions` keep only addresses of room
  members (role mentions are dropped); `mentions_everyone` without `allow_mentions_everyone` answers
  `403 message.mention_everyone_forbidden`, the code also used when a creator without `mention_everyone` sets the
  flag (on create, on update and when moving a webhook that has it). `reply_to` must name a message of the channel
  (`400 message.reply_target_missing`). Webhook messages skip slowmode and auto-moderation (they have their own
  limits), cannot be edited, and are deleted, bulk-deleted and purged like any message.
- **Additional codes**: `webhook.manage_forbidden` (403, management without `manage_webhooks` in the channel or, for
  the room list, at room level), `channel.no_text` (400, webhooks post into `text`, `announcement` and `forum`
  channels only), `subscription.not_found` (404, `GET`/`DELETE` without a subscription).
- **Transfer**: accepting a transfer deletes the event subscription and its queue (like the tokens, the URL was
  the previous owner's choice); the new owner configures it anew.
- **Moving** a webhook (`PATCH … { channel_id }`) needs `manage_webhooks` in both channels, a text, announcement or forum channel and room
  for it under the limits (since §6.1a also an encrypted one, which seals it). Renames and avatar changes emit
  `user.update` for the pseudo user to the room, so author caches refresh.
- **Request logs**: the HTTP trace span logs the method, the path with `/webhooks/<id>/***` (wherever the segment
  appears outside `/rooms/…`) and the version, never the query string (which also keeps query tokens of other
  routes out of the logs). `webhook_logs_flow.rs` captures every log line of real executions.
- **Embeds**: the node and `@tavrn/e2ee` apply the same rules (also: every embed needs a title, description,
  field or footer; field names and values must not be empty; unknown embed fields are accepted as compatible
  additions and never rendered). Senders refuse invalid embeds before encrypting (`EmbedsInvalidError`, code
  `message.embeds_invalid`), receivers drop invalid embeds after decrypting. The web client renders title (link),
  the link's full host, the description through the message Markdown sanitizer (images are forbidden there), a
  colour bar, fields (inline ones in three columns from tablet width on), footer and timestamp. The composer never
  creates embeds.
- **Subscriptions are recorded in the request of the change**, right after the change was written and before the
  response, at every place that emits the eligible events (`subscriptions::room_event` for `member.*`,
  `Conv::publish_recorded` for `message.*`, the webhook execution). The stores do not share one database
  transaction, so a crash between the change and the queueing can lose the events of that one request; nothing is
  ever queued for a change that did not happen. `application.install`/`uninstall` and `commands.update` are
  accepted in the event list and delivered once steps 2 and 3 emit them.
- **Eligibility** until installations exist (step 2): the bot is a member of the room (the interim direct-invite
  path of step 1). On top of the WebSocket filter of §2.6, `message.*` events need `view_channel` and
  `read_history` of the bot in the channel (so "no bots" channels and channels hidden by overrides never feed
  subscriptions); the event body's `data` is the WebSocket event data. Disabled applications (or owners) get
  nothing queued. Reactions and pins (`message.update` of reaction counts) are not queued.
- **Delivery**: up to 512 due entries per round, 16 applications and 4 requests per application at a time, the
  worker runs every 5 seconds and right after an enqueue. A success turns a `failing` subscription `active` again.
  `disabled` = `failing` and no success (or (re-)enabling) for 3 days; the queue is then cleared. Verification
  (PUT and `enable`) is limited to 10 per hour per application (`429`), because it sends requests to a URL of the
  owner's choice.
- **URLs**: `http://` is accepted only on development nodes, and `TAVRN_APP_ALLOW_PRIVATE_URLS` defaults to `true`
  there (`false` otherwise), so local test receivers work with `--dev`. Every request checks IP literals and every
  DNS answer (all addresses must be public), connects only to vetted addresses, follows no redirect (a `3xx` fails),
  reads at most 64 KiB and uses the federation `User-Agent`.
- **Hook tokens** carry `sub` = the node's domain like `iss`; `verifyHookRequest()` takes the node's domain or (for
  development) its origin, checks `iss`/`sub` against the `domain` of the node's `.well-known`, refetches the keys
  at most once per 10 seconds for unknown `kid`s and keeps spent `jti`s until `exp` + 5 minutes.
- **Not yet**: setting `interactions_url` (step 3 uses `hooks::verify_url`/`hooks::send` as they are),
  `application.install`/`uninstall`/`commands.update` events (steps 2 and 3), webhook attachments (not in v1).
- **Tests**: `webhooks_flow.rs` (16 tests: envelope, id/secret oracle incl. timing class, encryption
  switch, payload limits and usernames, `@everyone` gating, rate limits, pseudo user absence, moderation,
  permissions for users, bots and remote users, limits, the node switch, "no bots", embeds, avatars),
  `subscriptions_flow.rs` (8 tests: signed delivery, never encrypted content, scope and visibility
  filters, retry schedule with an injected clock and disabling after 3 days, final errors and `Retry-After`,
  concurrency and the queue cap, SSRF targets incl. `127.0.0.1`, `169.254.169.254`, `[::1]`, mapped IPv6 and a
  hostname resolving to a private address, redirects and wrong challenges), `webhook_logs_flow.rs`,
  unit tests of the new modules, Vitest for `HookVerifier` (tampered body, replayed `jti`, wrong `htu` and `aud`,
  expired, unknown `kid` refetch), the embed codec and the MLS round trip, the web embed card and badge, and
  Playwright `webhooks.spec.ts` and `subscriptions.spec.ts` (phone and desktop).

### Step 3: commands (2026-10-06)

Implemented: `commands.rs` (definitions, validation, JCS hashes, remote sets, approval, room settings, the
palette and checks 1–5 and 7 of §5.5), `interactions.rs` (invocation, delivery, the injectable `Clock`,
callbacks, follow-ups, ephemeral replies), `store/commands.rs`, `routes/commands.rs`, migration
`0200_commands.sql`, `commands.ts` (`command.args`, `encryptCommandArgs`, `CommandArgsVerifier`), the SDK
namespace `api.commands`, the web client's palette merge (`commands/merge.ts`), interaction notices and the
"Commands" panel of the room's Applications tab. Where the reference node deviates from or refines §5:

- **Storage.** Definitions live per application reference in `application_commands`, each in its JCS form without
  `id`; `definition_hash` is the hash of exactly that text. A room node copies the set of a remote application from
  its public document at installation and on `app.changed` (only while the application is installed there) and
  forgets it when the last installation goes. Definitions of another node that this node cannot parse (e.g. newer
  argument types, missing or duplicate ids) are ignored, the rest of the set is kept.
- **Definitions.** `dm_allowed` and an argument's `required` default to `false`; an `id` in a `PUT` body is ignored;
  `options` must be non-empty with unique values; `min`/`max` only for numbers (integral for `integer`, `min` ≤
  `max`); `max_length` 1–1000 only for strings; descriptions and option names must not contain control characters.
  `commands_version` grows only when the set changes (order included): an identical `PUT` changes nothing and sends
  no events. Invalid sets do not count against the 10 announcements per hour. Removing a name deletes its room
  settings on this node; adding it again gives it a new id.
- **Approval.** Decisions are stored per `(application, definition_hash)` whether or not the switch is on; while
  `TAVRN_APP_COMMANDS_REQUIRE_APPROVAL` is on, pending *and rejected* definitions are absent from palettes and
  answer `403 command.pending_approval`. The listing also takes `state=rejected`; approving and rejecting take 1–100
  hashes of current definitions (`404 command.not_found` otherwise) and emit `commands.update` to the rooms of the
  application. There is no admin UI yet (API only).
- **Room settings.** `PUT` is a full replacement (absent fields = defaults); `allowed_roles` and `disabled_channels`
  must be roles and channels of the room (at most 100 each, `400 validation.invalid` with `meta.field`); the answer
  is `RoomCommand { ref, command, settings, effective_permissions, approved }`. `enabled_commands` counts the commands
  that are enabled in the room and approved.
- **Checks of §5.5, codes.** (1) bots `403 app.bot_forbidden`, non-members `403 room.not_member`, an unaccepted
  message request `403 conversation.request_pending`, otherwise `403 message.send_forbidden`; (2) an application that
  is not installed in the room (or not the bot of a 1:1 DM, or disabled or blocked) `404 app.not_installed`, a bot
  that cannot view the channel `403 command.disabled` with `meta.reason = bot_cannot_view`, `dm_allowed` false in a
  DM `403 command.dm_not_allowed`; malformed command references are `404 command.not_found`; (4) `command.disabled`
  carries `meta.reason` `room` or `channel`; (7) arguments: unknown names, wrong types, choices outside `options`,
  out-of-range numbers and too long strings (1000 without `max_length`) are `400 command.args_invalid` with
  `meta.arg`; `user` must be an address (stored lowercase), `channel` and `role` ULIDs; plaintext `args` at most
  8 KiB. In encrypted conversations `args_ciphertext` (at most 16 KiB) is required: a malformed payload or an
  `epoch` that differs from its header is `400 interaction.ciphertext_invalid`, an epoch newer than the group
  `400 interaction.epoch_unknown`, and the invoking device must be attested as for messages.
- **Palette.** It applies checks 1–5, not the rate limit (check 6 is transient); bots get `403
  app.bot_forbidden`, a caller failing check 1 an empty list. DMs list the `dm_allowed` commands of the bot's
  application when this node knows its definitions (local applications, or remote ones installed in a room here).
- **Delivery.** Interactions live in memory (at most 100 000, `503 interaction.busy` beyond; a restart loses the
  pending ones, whose invokers get `504 interaction.no_ack`). Round robin goes over the bot's devices in the order
  they connected, to the newest connection of the chosen device; only connections whose effective scopes contain
  `commands` receive invocations (local tokens and federated sessions of remote bots alike). `commands.update` and
  `command.*` reach bots with the `commands` scope. `data.application_id` is the application's ULID (the ULID part of
  the reference for remote applications).
- **Interactions URL.** Set with `PATCH /applications/{id} { interactions_url }` (owner only, verified with the ping of
  §6.3, 10 verifications per hour, `null` removes it). For a local application it is preferred over the WebSocket. Its
  answer is the callback; a failed request, an answer that is not a valid callback, or a `device_id` that is not a
  device of the bot leaves the interaction unanswered (`504 interaction.no_ack`, logged without content).
- **Responses.** A callback is answered with the same `InvokeResponse` the invoker gets. Only the first *valid*
  response counts: an invalid one is refused and the interaction keeps waiting until its deadline; while another
  response is being processed a second one gets `409 interaction.already_acked`. Further codes:
  `400 interaction.device_invalid` (a `device_id` that is not the token's device, or encrypted content without a
  device in a URL answer), `400 validation.type`, `400 validation.message` (`error` text 1–200 characters without
  control characters). Follow-ups answer `201 { message | ephemeral }`; invalid ones do not count against the ten.
  The ephemeral first response goes to the invoker's other connections, ephemeral follow-ups to all of them.
  Non-ephemeral replies and follow-ups are bot messages and count against the bot message limit of §2.7.
- **Envelope.** `interaction` is stored as JSON with the message (`messages.interaction`); clients show
  "<user> used /<command>" above the answer.
- **Client.** The palette is fetched per conversation when the node announces `commands.v1` and refetched on
  `commands.update`, `role.*`, `override.update` and `member.update`. Typed names resolve to the picked command, else
  the built-in, else the only application command of the name; two applications with one name and no pick are an
  error that asks to pick from the list. `options` and booleans are offered as a pick list; `user` arguments are sent
  as addresses, `channel` and `role` arguments as ids. Ephemeral replies and error notices are memory only (dropped on
  reload), "… is thinking" ends with the first answer or after 15 minutes.
- **Tests.** `commands_flow.rs` (11 tests: definitions with owner, bot, scope, rate limit and validation
  paths, the palette with room settings and allowed roles, every check of §5.5 in order, replies, duplicate
  callbacks, `not_owner`, ephemeral replies, defer and the follow-up limit, the ack timeout with a `ManualClock`, round
  robin over two tokens on real WebSockets, the verified and signed interactions URL, encrypted conversations both
  ways with real MLS clients, approval invalidated by a definition change, DMs, a remote application on a second node
  with `app.changed` and its federated WebSocket, remote users refused on the owner routes); unit tests of the
  validation, hashing, arguments, references, the registry and the clock; Vitest for the palette merge (built-in
  collisions, two applications with one name, permission and DM filters, id binding), pick lists, argument
  resolution, the notices store, the composer and `@tavrn/e2ee` (`command.args`, the verifier's replay, command and
  age checks, an MLS round trip); Playwright `app-commands.spec.ts` (palette, pick list, reply, ephemeral
  reply and "thinking…" in an unencrypted and an encrypted channel with an in-test bot, the room's command settings).
- **Open.** DM commands of remote bots that are not installed in a room of the DM's node.
- **Update (2026-10-06, bots and E2EE wave):** the room's command settings (`PUT`/`DELETE`) need `manage_applications`,
  reading them `manage_applications` or `manage_room`; the admin UI for the approval exists ("Command approval" in the
  admin page's Applications tab, with `GET /admin/applications/commands/approval`); `createBot()` command handlers came
  with step 5b; invocations reach a bot connected to another instance of the node (scaling guide of `tavrn-node`).

### Step 5b: SDK bot runtime (2026-10-06)

Implemented: the package `@tavrn/bot` (repository `tavrn-js`, Apache-2.0, TypeScript source like `@tavrn/sdk`, Node.js 20+,
no browser build) with `createBot({ node, token, key | keyFile, stateDir, logger?, joinPolicy? })`, the example bot
`examples/echo-weather` (variables `TAVRN_BOT_NODE`, `TAVRN_BOT_TOKEN`, `TAVRN_BOT_KEY_FILE`,
`TAVRN_BOT_KEY`, `TAVRN_BOT_STATE_DIR`), developer documentation in the package README, and the client-side bot ghost
rule of §3.5 in `@tavrn/e2ee`. Where the implementation decides what §3 and §5 leave open:

- **Placement.** A separate package, as 5a proposed: `@tavrn/bot` depends on `@tavrn/sdk`, `@tavrn/e2ee` and
  `@tavrn/crypto`; the SDK stays free of the encryption code. It re-exports `verifyHookRequest()` / `HookVerifier`.
  The example runs with `vite-node` (TypeScript source, no build step).
- **Start.** The app token's claims are read without verification (`dev`, `app`, `iss`, `exp`; `typ` must be `app`,
  `token_invalid` otherwise, `token_expired` before any request). `node` is a URL (used as given for API and
  WebSocket, also an internal address; its discovery document must name the token's issuer) or the issuer's domain
  (resolved like any node). `GET /users/me` must be a bot.
- **Key file (§3.1).** No identity and no key: a new master secret is written to the key file (`open(…, "wx", 0600)`,
  an existing file is never replaced) before `PUT /users/me/identity`; a `409 e2ee.identity_exists` race is accepted
  when the published key equals ours. An identity without a configured key stops with `key_missing` and the message
  of §3.1; a key whose derived identity key differs from the published one stops with `key_mismatch`. A key file
  readable by other users is accepted with a warning. Malformed keys and recovery keys are `key_invalid`.
- **State (§3.3).** `FileKeyStore` in `stateDir`, unlocked with the master secret on every start. State of another
  device of the same bot (a new token) or of an earlier identity (owner reset) is discarded with a warning; state of
  another account is `state_dir_in_use`. A fresh directory restores the history backups once (§3.2), and `stop()`
  flushes pending backups before it locks the store.
- **Device (§3.2).** `ensureDevice` attests the token's device and tops up KeyPackages at start, after every Welcome
  and every 10 minutes; the same timer renews federated sessions near their 7-day cap and retries backups.
- **Groups.** `eager` (default) joins every viewable encrypted `text`/`announcement`/`forum` channel of a room after
  `application.install`, on `channel.create`/`channel.update` and, for channels without a group yet, on their first
  `mls.commit`; the bot never creates a channel's group when joining eagerly (`no_group` waits for the first member),
  only `send()` may. `lazy` joins on a message, an invocation or `send()`. Channels whose effective `no_bots` is set
  are never joined. A message of an epoch before the join is reported as `undecryptable`.
- **WebSocket.** Capabilities `content.v1`, `reactions`, `e2ee.mls1`. Every `ready` after the first and every
  `resync` re-reads Welcomes, rooms and channels and catches up the groups (no events are replayed). The SDK's
  `TavrnSocket` gained `onClose` and stops on `4004` (replaced, §2.6); the runtime reports `replaced` and
  `token_refused` (a `4001` that a reconnect with the current secret does not fix) as `error` events and stops when
  the home node's connection ends this way.
- **Remote installations (§2.8, §4.5).** At start `GET /applications/me/installations` lists the room nodes; each gets
  a federated session (federation token of the home node, `POST /auth/federated` with device name `tavrn bot`) and a
  WebSocket. Access tokens refresh with the session's refresh token (`createRefresher` without locks); a refused
  refresh signs in again with a fresh federation token. `application.install` for an unknown node connects it; the
  last `application.uninstall` of a node closes its session. Other nodes are found through their discovery document
  or the home node's resolution (`GET /federation/resolve/{domain}`, development peers, SRV).
- **Messages.** Own messages (any device of the bot) and system messages are skipped. Plaintext messages carry the
  author device's signature status; `send()` signs plaintext with the bot device (FEDERATION.md §10.3) and encrypts
  in encrypted conversations (known channels, else `GET /conversations/{id}`). Attachments are not supported yet.
- **Commands (§5.6–§5.8).** `bot.command(name, handler)` and `bot.setCommands(definitions)` (`PUT
  /applications/me/commands`). The handler's `Interaction` answers with `reply`, `ephemeral`, `defer`, `followUp`
  and `error` in call order; `reply` after `defer` is a follow-up, a second first answer is `interaction_answered`.
  A handler still running after `autoDeferMs` (2 s) is deferred automatically; a failing or silent handler gets a
  generic error notice (never the exception text, the node sees it). Encrypted arguments are decrypted as a message
  of the invoker's device and checked with `CommandArgsVerifier` of `@tavrn/e2ee` against
  `<home domain>/<application id>/<command id>`; a bot without the group answers "joining" and joins (§5.8).
  Encrypted answers name the token's device.
- **Tokens (§2.2).** `application.token_expiring` becomes `tokenExpiring`; `rotateToken()` switches to the new secret
  at once (REST and the next WebSocket hello) and emits `tokenRotated`.
- **"No bots" ghost rule (§3.5, ENCRYPTION.md §4.6, leftover of step 1).** `MlsManager.ghostCheck(q, members,
  { noBots })` reports leaves of users whose `kind` (from their home node's keys document; kinds other than `user`
  count, older nodes without `kind` count as users) is not `user` with the new reason `bot`; `LeafCleaner` removes
  them like departed members when the user may manage the conversation (rule 3 of §4.7, the node allows it because
  the bot is not entitled). The web client passes the channel's `no_bots_effective` (text, voice) and the ghost
  warning explains the case.
- **Development node hook.** `POST /api/v1/dev/notify-expiring-tokens { now? }` (only with `--dev`, not in the API
  description) runs the token expiry housekeeping at once for tests.
- **Tests.** Vitest in the `@tavrn/bot` tests against in-process nodes (the harness starts a `tavrn-node --dev` binary
  on free ports): key file and identity on the first start, restart with the same state,
  `key_missing` without and `key_mismatch` with another key, the key as text, non-app tokens and a foreign node;
  install, eager join, an encrypted message answered and decrypted by the user, plaintext signed, `stop()` uploading
  the backups; `tokenExpiring` and `rotateToken()`; a remote installation on a second node (session on
  `application.install`, encrypted answer there, reconnection after a restart); `/weather` against the node with
  reply, ephemeral reply and defer + follow-up in an unencrypted and an encrypted channel; unit tests of the command
  module with recorded `command.invoke` frames through `TavrnSocket` (replies, defer, follow-ups, double answers,
  auto-defer, failures, encrypted arguments of another command, stale, replayed or badly signed), the key file and the
  token claims; `@tavrn/e2ee` and web tests of the ghost rule; Playwright `bot-runtime.spec.ts` starts the
  example bot against the e2e node, installs it through the consent screen, sees the encrypted echo with the BOT
  badge and a `/weather` reply picked from the palette (phone and desktop).
- **Open.** Attachments in `send()`; DMs started by the bot (`dms` scope) have no helper yet; the interactions URL is
  not served by the runtime (bots use the WebSocket; `verifyHookRequest()` is available for own HTTP servers).

### Sealed webhooks in encrypted channels (2026-10-06)

Implemented §6.1a and `ENCRYPTION.md` §5b: `sealed.rs` (inbox key derivation, the signing input, sealed
boxes through the `crypto_box` crate with its `seal` feature: three small RustCrypto crates, `crypto_box`,
`crypto_secretbox`, `salsa20`, the rest was already in the tree), `Client::inbox_key` / `Client::open_sealed` and the
WASM bindings `Client.inboxKey`, `Client.openSealed`, `inboxPublicKey`, `sealToInbox`, the vectors `webhook_inbox` in
`testvectors/encryption.json` (checked against libsodium-wrappers 0.8 both ways), the node in
`webhooks.rs` (sealing modes, inbox keys, the redaction of refused node-sealed payloads) with the routes in
`routes/webhooks.rs`, migration `0250_sealed_webhooks.sql` (`webhooks.sealing`, table `inbox_keys` with the newest key
per conversation, suspended webhooks resume as sender-sealed), `has_webhooks` on channels, `sealed.ts`
and `MlsManager.setInboxWanted` / `publishInboxKey` / sealed messages in `decrypt`, the web client's mode choice,
mode and `pending_key` in the webhook list, the key URL in the URL dialog, the lock with its tooltip next to the
WEBHOOK badge, and the webhook guide of `tavrn-node` with sealing snippets for Node.js, Python and Go.

- **Derivation from the content key, not a second exporter label.** `inbox_secret = HKDF-Expand(content_key(epoch),
  "tavrn webhook inbox v1", 32)`: the content key is itself the MLS exporter output of the epoch, so the pair is
  still "one HKDF per epoch from the exporter", but everything that already carries content keys (the history backup,
  history shares for new members) carries the inbox keys too, without a new backup or share format, and no extra
  exporter call happens on the MLS path. Readers of a sealed post are exactly the readers of the epoch's messages.
- **libsodium's sealed box instead of AES-256-GCM.** `crypto_box_seal` is available in every language through
  libsodium bindings (Node.js `libsodium-wrappers`, Python `pynacl`, Go `x/crypto/nacl/box.SealAnonymous`), so a
  service needs no custom construction; the crate cost is the three small crates above.
- **No change to MLS**: no extra commits, no group changes; the derivation and one signature happen only after an own
  commit in channels with webhooks, and the `PUT` is sent outside the commit path (fire and forget).
- **Not yet**: attachments in sealed posts; a key that a new member received through a history share is only checked
  against an ordinary message of its epoch (`ENCRYPTION.md` §7b), so an epoch with nothing but webhook posts stays
  unreadable for members who join later.
- **Tests**: `sealed_webhooks_flow.rs` (publishing: signatures, foreign devices, non-members, members
  without `view_channel` or an attested device, remote users, future and stale epochs, plaintext channels; sender
  mode refuses plaintext, unknown fields, future epochs and broken boxes; node mode stores nothing readable, keeps the
  username in the box, answers refused payloads without quoting them, the epoch window; the encryption switch both
  ways; moderation), `webhooks_flow.rs` (modes across the switch and moves), `webhook_logs_flow.rs` (every log line of
  a node-sealed post and of refused ones), the crypto unit and integration tests and vectors, Vitest
  (`sealed.test.ts`: vectors through WASM, payload checks; `mls.test.ts`: publishing only where wanted and
  after own commits, decrypting, later members, history backup; the web message row), Playwright
  `sealed-webhooks.spec.ts` (sender mode sealed with libsodium-wrappers, node mode, a later member reads
  both, a post after his join's commit; phone and desktop) and the updated `webhooks.spec.ts`.

- **Update (2026-10-06, bots and E2EE wave):** history backups are opt-in (`historyBackup: true`; by default the runtime
  neither uploads nor restores backups, so a fresh state directory reads only new messages, see the `@tavrn/bot` README). The join
  decision follows the node's `no_bots_effective`, which now includes the room setting `bots_in_encrypted_channels`;
  the runtime joins on the `channel.update` that opens a channel.

### Bots, permissions and E2EE (2026-10-06, design note 4.7 "Decided 2026-10-06")

Implemented: the permission bit `manage_applications` (35) in `permissions.rs`, `permissions.ts`,
the shared vectors and `permissions.md`; `bot_channels.rs` (the room and channel settings, applying changed
flags, the security log entries); migration `0240_bots_permissions.sql`; two startup fixups; the cross-instance delivery
of invocations (`interactions.rs`, `cache::Message::Invoke`, `cache::relay`); the bot runtime option `historyBackup`;
the web client's settings, markers, security log entries and the admin "Command approval" section. Where the reference
node decides what §3.5, §3.6, §4 and §5 leave open:

- **`manage_applications`.** Management class (never on `@everyone`, `EVERYONE_RESTRICTED` = `4611686062204976004`),
  covered by `rooms:manage`. Install, uninstall and `PUT`/`DELETE` of command settings need it (`403
  app.manage_forbidden`); the installation list and `GET /rooms/{id}/commands` accept it or `manage_room`. The managed
  role still needs `manage_roles`; the installer's permissions still cap the bot. The startup fixup
  `fixup.manage_applications` adds the bit once to every role holding `manage_room` (`FixupReport.manage_applications_roles`);
  roles created later are not touched.
- **Settings.** `rooms.bots_in_encrypted_channels` (TEXT, column default `allowed` for existing rooms; the node creates
  rooms with `per_channel`) and `channels.bots_allowed` (BIGINT). The fixup `fixup.bots_in_encrypted_channels` records
  `room.bots_in_encrypted_channels { value: allowed, reason: existing_room }` once in every room that existed then
  (`FixupReport.bots_encrypted_rooms`). The node computes the effective flag in one place (`ChannelRow::no_bots` →
  `permissions::no_bots_effective`), so permission evaluation, the channel list served to bots, MLS entitlement
  (external joins and Adds, `403 mls.forbidden`) and the roster member list follow without further changes. Bots may
  not change `no_bots` (room, category, channel), `bots_in_encrypted_channels` or `bots_allowed` (`403 app.bot_forbidden`):
  a bot holding `manage_room` through `rooms:manage` could otherwise open channels to itself.
- **Security log.** Written by the commit route after an accepted commit (and by the group creation), from the roster
  before and after: one entry per bot whose presence in the roster changed (several devices of one bot count as one).
  Users are never logged here. The reason of a removal is derived from the node's state right after the commit (§3.6);
  the uninstall reason comes from the latest `app.uninstall` audit entry of the bot in the room (`removed` is reported
  as `uninstalled`).
- **Web client.** Room settings → Overview: "Bots in encrypted channels" (checked = `per_channel`, with the current
  meaning); channel settings: "Bots allowed" for encrypted channels of `per_channel` rooms (hidden otherwise, with a note
  when a "no bots" flag wins). Channel lists show the "no bots" icon only for explicit flags (an encrypted channel of a
  `per_channel` room is closed by default and needs no icon) and a bot icon on encrypted channels that allow bots. The
  ghost rule input is the node's flag OR the client's own computation (`lib/botAccess.ts`). The role editor shows
  "Manage applications" with a hint; the consent screen's room picker and the "Applications" tab need the bit.
- **Command approval UI.** Admin page → Applications → "Command approval": the definitions per state (pending, approved,
  rejected), grouped by application, approve / reject per definition and "approve all" per application, and whether
  `TAVRN_APP_COMMANDS_REQUIRE_APPROVAL` is on (`GET /admin/applications/commands/approval` → `{ required }`, node admins
  only, `403 federation.local_only` for remote users).
- **Several instances** (scaling guide of `tavrn-node`): receivers are registered in the cache (`cmdrecv:<bot user id>`); the
  instance that takes the invocation owns the pending interaction, publishes `Invoke` on the bus for one live instance
  holding a receiver when it has none itself, and records `interaction:<id>` → its instance id (TTL 16 minutes);
  callbacks and follow-ups that arrive elsewhere are relayed to it over HTTP (`503 interaction.owner_unavailable` when it
  does not answer). Without `TAVRN_CACHE_URL` nothing changes.
- **Tests.** `bots_encrypted_flow.rs` (the bit on every affected route with users, bot tokens with and
  without `rooms:manage` and `@everyone`; both fixups and their idempotence; a new room's encrypted channels closed to an
  installed bot for external joins and Adds, opened per channel, closed again with `mls.remove_needed`, the explicit flag
  winning, the room setting both ways, the encryption switch, the security log entries with `by` and the reasons
  `bots_not_allowed`, `no_bots`, `uninstalled`; attacker paths: invalid values, the welcome channel, a bot with management
  bits; the approval state route for admins, members and remote admins), `cluster_flow.rs`
  (`interactions_reach_a_bot_connected_to_another_instance`, in-process cache and Valkey), unit tests and the shared
  vectors `testvectors/no_bots.json` (Rust and SDK), Vitest for the markers, the ghost input and the security log
  entries, the `@tavrn/bot` tests (no backups by default and a fresh state directory reading only new messages; joining once the
  channel allows bots), Playwright `bots-encrypted.spec.ts` and `admin-apps.spec.ts` ("Command approval").
