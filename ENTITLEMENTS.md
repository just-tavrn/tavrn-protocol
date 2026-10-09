# Entitlements, admin API tokens and attachment retention

Status: implemented 2026-10-06 (design note 4.13 items 1 and 2). Node-local: nothing in this document crosses
node boundaries, and no other node has to understand it. Clients only read the effective values.

Entitlements are a small, generic layer on top of a node's fixed limits. They let an operator run plans or
subscriptions ("Plus: 500 MB uploads, 1080p streams") without forking the node: the node defaults come from
`TAVRN_*` variables, everything above them is data that node admins (or the operator's billing system, with an
admin API token) write through the admin API.

## 1. Keys

Every key is an integer. `0` means **unlimited** unless the rule says otherwise.

| Key | Rule | Scope | Node default | Enforced at |
|---|---|---|---|---|
| `rooms.max_owned` | max | user | `TAVRN_MAX_ROOMS_PER_USER` (5) | `POST /rooms` → `403 room.limit_reached` |
| `upload.max_bytes` | max | user | `TAVRN_UPLOAD_MAX_BYTES` (25 MiB) | uploads → `413 upload.too_large`; capped by `TAVRN_UPLOAD_MAX_BYTES_CEILING` |
| `storage.max_bytes_per_room` | max | room | `TAVRN_STORAGE_QUOTA_PER_ROOM_BYTES` (10 GiB) | uploads → `413 upload.quota_exceeded` (DMs: per conversation, the uploader's grants) |
| `voice.max_participants` | max | room | `TAVRN_VOICE_CHANNEL_MAX_PARTICIPANTS` (0) | voice token → `409 voice.participant_limit`; never above `TAVRN_VOICE_MAX_PARTICIPANTS` |
| `stream.max_height` | max | user | `TAVRN_STREAM_MAX_HEIGHT` (0) | sent with the voice token, client-enforced (§4) |
| `stream.max_fps` | max | user | `TAVRN_STREAM_MAX_FPS` (0) | sent with the voice token, client-enforced |
| `camera.max_height` | max | user | `TAVRN_CAMERA_MAX_HEIGHT` (0) | sent with the voice token, client-enforced |
| `emoji.max_per_room` | max | room | `TAVRN_EMOJI_MAX_PER_ROOM` (100) | `POST /rooms/{id}/emojis` → `403 emoji.limit` |
| `emoji.max_personal` | max | user | `TAVRN_EMOJI_MAX_PERSONAL` (20) | personal emojis (design note 4.13 item 4) |
| `sounds.max_per_room` | max | room | `TAVRN_SOUNDS_MAX_PER_ROOM` (50) | `POST /rooms/{id}/soundboard` → `403 soundboard.limit` |
| `sounds.max_personal` | max | user | `TAVRN_SOUNDS_MAX_PERSONAL` (10) | personal sounds (design note 4.13 item 4) |
| `attachments.retention_days` | shortest non-zero | room | `TAVRN_ATTACHMENT_RETENTION_DAYS` (0 = keep) | housekeeping (§6) |
| `files_channels.enabled` | flag (0/1) | room | `TAVRN_FILES_CHANNELS` (`on` = 1) | files channels (design note 4.13 item 9) |
| `files_channels.max_bytes` | max | room | `TAVRN_FILES_CHANNELS_MAX_BYTES` (0) | files channels |

`GET /api/v1/admin/entitlements/keys` lists the keys with rule, scope, largest allowed value and node default.
Plans and grants may only contain these keys; values are integers from `0` to the key's maximum (e.g.
`upload.max_bytes` ≤ 1 TiB, `stream.max_height` ≤ 4320, `files_channels.enabled` ≤ 1). Anything else is
refused with `400 entitlements.invalid_limits`.

## 2. Plans and grants

- A **plan** is a named bundle of limits (`{"name": "Plus", "limits": {"upload.max_bytes": 524288000}}`). Names
  are unique. Changing a plan changes every grant that uses it. A plan that grants still use cannot be deleted
  (`409 entitlements.plan_in_use`).
- A **grant** gives one subject an optional plan and optional per-key `overrides` (on top of the plan), an
  optional `expires_at` and a `note` (e.g. the customer or invoice number). It needs a plan or at least one
  override. Subjects:
  - `user:<id>` or `user:<name>` / `user:<name>@<this domain>`: a **local** user. Users of other nodes cannot
    receive grants (`400 entitlements.subject_not_local`): a grant never extends what a foreign account may do.
  - `room:<id>`: a room hosted on this node.
- **Expiry** is compared at evaluation time (no timers). An expired grant counts for nothing; it is still listed
  with `include_expired=true` (`expired: true`) and deleted by housekeeping a week after `expires_at`. Grants of
  deleted users or rooms are deleted by housekeeping as well. An expiry must lie in the future when it is set.
- Limits per node: 500 plans, 50 active grants per subject.

## 3. Evaluation

`effective(key, user, room)` combines the node default with the **active** grants:

- **max** (most keys): the highest value among the node default, the evaluated user's grants and the room's
  grants. `0` (unlimited) beats every number. A grant only ever extends: a grant with a lower value than the node
  default changes nothing.
- **flag** (`files_channels.enabled`): `0`/`1`, the highest wins (here `0` means *off*, not unlimited).
- **shortest non-zero** (`attachments.retention_days`, the one exception): the smallest non-zero value among
  the node default, the room's grants and the room's own setting (`attachment_retention_days`, §6). A room can
  only **shorten** the node's retention, never extend it; user grants play no part. `0` everywhere = keep.

Which user's grants count depends on the key's **scope**:

- *user* keys are evaluated for the **acting user** (the uploader, the joiner, the creator) plus the grants of
  the room the action happens in (a room grant raises the upload size of everybody in that room).
- *room* keys are evaluated for the room's **owner** plus the room's grants: an owner's plan covers the rooms
  they own (e.g. `emoji.max_per_room` from the owner's "Plus" plan).

**Node admins** are unlimited for user keys (what they do themselves: rooms, uploads, personal emojis). Rooms
they own follow the room rules like every other room; an admin can grant their rooms anything explicitly.

Hard caps that no grant can lift: `TAVRN_UPLOAD_MAX_BYTES_CEILING` (an unlimited or larger upload grant becomes
the ceiling; default `0` = `TAVRN_UPLOAD_MAX_BYTES`, so grants cannot raise uploads until the operator sets it),
`TAVRN_VOICE_MAX_PARTICIPANTS` (LiveKit's room limit), the screenshare/camera policies
(`TAVRN_SCREENSHARE_MAX_RESOLUTION`, `…_MAX_FPS`, `TAVRN_CAMERA_MAX_RESOLUTION`).

Results are computed per request (one indexed query for the grants of the acting user, the room owner and the
room); there is no cache to invalidate, so changes apply to the next request.

## 4. What clients see

- `GET /api/v1/users/me/entitlements[?room=<id>]` (any signed-in user; with a room: members only):
  `{"values": {key: value, …}, "upload_max_bytes": <effective upload size>, "retention_bound_days": <room bound or null>}`.
  `retention_bound_days` is the room's retention without its own setting (node value and room grants), the
  upper bound the room settings show.
- `GET /api/v1/conversations/{id}/upload-policy` returns the effective `max_bytes` for the requester in that
  conversation; clients show this number in the composer.
- The voice join answer (`POST …/voice/join`, `…/call/join`) carries `limits.stream_max_height`,
  `limits.stream_max_fps` and `limits.camera_max_height` (0 = no cap beyond `limits.screenshare` /
  `limits.camera`). **Clients enforce them** by lowering their publish resolution and frame rate (the web client
  folds them into `screenshare.max_resolution`, `screenshare.max_fps` and `camera.max_resolution` at join; caps
  below the smallest preset keep that preset). The SFU cannot cap what a modified client sends: this is a soft
  limit, suitable for plans, not for security.
- Messages list their attachments with `expired: true` once retention deleted the file (§6).

## 5. Admin API

All routes need a node admin session or an admin API token with the `entitlements` scope. Every change writes
an audit log entry (`entitlements.plan_create|plan_update|plan_delete|grant_create|grant_update|grant_delete`).

| Route | Purpose |
|---|---|
| `GET /api/v1/admin/entitlements/keys` | keys, rules, maxima, node defaults |
| `GET /api/v1/admin/entitlements/plans` · `POST` | list (by name) · create `{name, limits}` |
| `PATCH /api/v1/admin/entitlements/plans/{id}` · `DELETE` | rename and/or replace `limits` · delete if unused |
| `GET /api/v1/admin/entitlements/grants?subject=&include_expired=&limit=&after=` | list, paged by id (`limit` ≤ 500) |
| `POST /api/v1/admin/entitlements/grants` | create `{subject, plan_id?, overrides?, expires_at?, note?}` |
| `PATCH /api/v1/admin/entitlements/grants/{id}` · `DELETE` | change `plan_id` (null removes), `overrides` (replaces), `expires_at` (null removes), `note` · delete |
| `GET /api/v1/admin/entitlements/effective?user=&room=` | effective values, node defaults, retention bound |

A grant in responses: `{id, subject: "user:<id>", subject_kind, subject_id, subject_label, plan_id, plan_name,
overrides, values (plan + overrides), expires_at, expired, note, created_by, created_at, updated_at}`.

### 5.1 Admin API tokens

Node admins create named bearer tokens for scripts and billing systems:

- `POST /api/v1/admin/tokens` `{name, scopes, expires_at?}` → `201` with the token and `secret` **once**. Only a
  session can create tokens (a token can never mint tokens). `GET /api/v1/admin/tokens` lists them (name,
  scopes, creator, `expires_at`, `last_used_at`, `expired`; never the secret or its hash).
  `DELETE /api/v1/admin/tokens/{id}` revokes (deletes) one. At most 100 tokens per node.
- Format: `tavrn_adm_<ULID>.<32 random bytes, base64url>`. The node stores only the SHA-256 of the whole token
  and compares it in constant time.
- A token is accepted **only** on `/api/v1/admin/*` routes whose scope it carries; everywhere else, including the
  WebSocket and every non-admin route, it fails with `401 auth.admin_token_not_allowed` (fail closed). An admin
  route not listed below answers `403 admin_token.route_forbidden`; a missing scope `403 admin_token.scope_missing`
  (`meta.scope`). An expired token answers `401 auth.token_expired`, a revoked or wrong one `401 auth.token_invalid`.
- The token acts with the rights of its **creator**, who must still be an enabled node admin of this node
  (otherwise `403 auth.node_admin_required`). Bots never reach `/admin/*`.
- Every call writes an audit entry `admin.token_call` (reason = token name, meta: token id, method, route).
  Tokens share the rate limit class of admin sessions (600 requests per minute per token or admin).

| Scope | Routes |
|---|---|
| `entitlements` | `/api/v1/admin/entitlements/*` |
| `users:read` | `GET /api/v1/admin/users` |
| `users:write` | `PATCH /api/v1/admin/users/{user_id}` (disable, admin right, creation grants) |
| `invites` | `GET`/`POST /api/v1/admin/invites`, `DELETE /api/v1/admin/invites/{code}` |

Deliberately closed to tokens: token management, user purges, second-factor resets, bans, federation and
directory administration, SSO group maps, the overview and the audit log.

## 6. Attachment retention

- The effective `attachments.retention_days` of a conversation: rooms by §3 (node value, room grants, the room
  setting `attachment_retention_days` via `PATCH /rooms/{id}` with `manage_room`, `0` = node value, 1–36500);
  DMs and group DMs use the node value.
- Housekeeping (hourly) deletes the files of attachments uploaded longer ago than that, in batches of 500 within
  a time budget (the rest follows an hour later): file and wrapped file key go, the `blobs` row stays with
  `expired_at`. Messages keep listing the attachment with `expired: true`; `GET /api/v1/blobs/{id}` answers
  `410 attachment.expired`. Clients show "file expired" without preview, player or download.
- Exempt: attachments of **pinned** messages, uploads not yet bound to a message (the orphan sweep handles them),
  profile media, custom emojis and sounds (not attachments), and files-channel entries.
- Expired files no longer count against the room's storage.
- Message retention (`TAVRN_RETENTION_DAYS`, `PROTOCOL.md` §7f) is separate: it deletes whole messages with their
  attachments.

## 7. Example: a subscription system

An operator sells "Plus" (bigger uploads, more rooms, 1080p streams) and boosts for rooms:

```sh
# Once, in .env: let grants raise uploads up to 500 MiB; keep streams at 720p unless a plan says otherwise.
TAVRN_UPLOAD_MAX_BYTES_CEILING=524288000
TAVRN_STREAM_MAX_HEIGHT=720

# Once, as a node admin: create a token for the billing system (admin page → API tokens, or):
curl -sX POST https://chat.example/api/v1/admin/tokens -H "Authorization: Bearer $SESSION" \
  -H 'Content-Type: application/json' -d '{"name":"billing","scopes":["entitlements"]}'
# → {"id":"01J…","secret":"tavrn_adm_01J….…", …}   store the secret in the billing system

# Once: the plans.
curl -sX POST https://chat.example/api/v1/admin/entitlements/plans -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Plus","limits":{"upload.max_bytes":524288000,"rooms.max_owned":20,"stream.max_height":1080,"stream.max_fps":60,"emoji.max_personal":100}}'
curl -sX POST https://chat.example/api/v1/admin/entitlements/plans -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Room boost","limits":{"emoji.max_per_room":500,"storage.max_bytes_per_room":107374182400,"voice.max_participants":0}}'

# On payment: a grant until the end of the paid period (the note links it to the invoice).
curl -sX POST https://chat.example/api/v1/admin/entitlements/grants -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"subject":"user:alice","plan_id":"<Plus id>","expires_at":"2026-11-06T00:00:00Z","note":"invoice 4711"}'

# On renewal: move the expiry. On cancellation: do nothing, the grant simply expires.
curl -sX PATCH https://chat.example/api/v1/admin/entitlements/grants/<grant id> -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"expires_at":"2026-12-06T00:00:00Z"}'

# Support: what does alice get in her room?
curl -s "https://chat.example/api/v1/admin/entitlements/effective?user=alice&room=<room id>" -H "Authorization: Bearer $TOKEN"
```

Find a customer's grants with `GET …/grants?subject=user:alice` (add `include_expired=true` for the last week's
expired ones). Keep the billing system the source of truth: re-sending a grant for the same period is harmless
apart from a duplicate row, so prefer `PATCH` with the stored grant id.
