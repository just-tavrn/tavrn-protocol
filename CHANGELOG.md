# Changelog

Changes of the protocol that implementations must follow, newest first. Versions are the tags of this repository
(`README.md` "Versioning and capabilities").

## Unreleased

### Changed

- **The node quota of files channels covers the node's own storage only** (`FILES.md` §4, §5, `ENTITLEMENTS.md`).
  `files_channels.max_bytes` no longer limits channels on external WebDAV/S3 stores. Such a channel has its own
  optional limit, `max_bytes` in `PUT …/files/backend` (returned by `GET backend`, `0`/absent = unlimited), set by the
  members who configure the store, enforced with `413 files.quota_exceeded` and named as `limit_bytes` in `GET usage`.

### Added

- **Files channels on external stores only** (`FILES.md` §5, `PROTOCOL.md` §2). A node policy
  (`TAVRN_FILES_INTERNAL=off`) under which files channels keep no files on the node: `files_internal` in `GET /node`
  and `policies.files_internal` in the discovery document; a new files channel has no store (`backend`/`kind`
  `none` in `GET usage` and `GET backend`, which also carries `internal_allowed`) and answers uploads, new folders
  and `PUT …/files/backend { kind: "internal" }` with `403 files.internal_disabled` until an external store is set.

- **Passkeys in the apps** (`PROTOCOL.md` §5a.4, §2). A node may accept the WebAuthn origins of its own apps
  (Android: `android:apk-key-hash:<base64url SHA-256 of the signing certificate>`, the certificate also listed in the
  relying party's `assetlinks.json`) and publishes the accepted origins as `webauthn.origins` (web origin first) in
  `GET /node` and the discovery document; clients offer in-app passkeys only while their origin is listed. Desktop
  apps run the ceremony natively with the node's web origin.
- **`profile.changed`** (`FEDERATION.md` §2.7 (d), §5.2, §5.4). After a change of a user's public profile (display
  name, images, bio, links, DM setting) the home node sends `profile.changed { profile_version }` to the domains of
  `identity.changed`, coalesced to one queued message per user and target. The receiver refreshes the mirror of a
  user it knows when the version is newer (rate-limited per sender and user, `429` beyond it), so a changed avatar
  or name shows on other nodes at once instead of with the next federated login. Additive: nodes that do not know
  the type ignore it.

- **Confirmation mail again** (`PROTOCOL.md` §5a.3). `POST /auth/verify-email/resend { account }` sends a new
  confirmation link to an unconfirmed address (always `204`, three mails per account and hour); `POST /auth/verify-email`
  is listed in the route table.

### Security

- **Fresh proof for new sessions and login methods** (`PROTOCOL.md` §5c, `FEDERATION.md` §8, `APPLICATIONS.md`
  §8.3). `POST /auth/connect/code` (origin, or a `login` app session) and linking or unlinking a single sign-on
  identity need a reauth token (`403 auth.reauth_required`). The session of a connect code exchange carries no
  reauth token. §5c lists what counts as a fresh proof.
- **Revocations take effect at once** (`PROTOCOL.md` §5b, §6). Logout, password change or reset, device deletion,
  disabling, second-factor reset, node ban and account deletion end the access tokens of the affected devices
  (`401 auth.session_revoked`), close their WebSockets (`4001`) and remove them from voice and calls. Deleting a
  device id of another account changes nothing (`404 device.not_found`).
- **WebSocket limits** (`PROTOCOL.md` §6). Client frames at most 64 KiB; connecting counts against the general
  request limit; a per-user connection cap (close `4002`, reason `too_many_connections`); `ack` shares the limit of
  `PUT …/read`.
- **Password reset limits** (`PROTOCOL.md` §5a). `POST /auth/forgot-password`: three mails per account and hour, a
  pending link stays valid, `503 mail.unavailable` on nodes without e-mail. Failed logins count per account, and the
  right password with a valid device proof passes an account over its limit.
- SRV delegation no longer makes DNS the trust anchor: the target must present a certificate valid for the identity
  domain, and a document from another source with none of the known keys is a key conflict (`FEDERATION.md` §1.3, §1.4).
- Requests to a slow peer cannot hold node-wide connection slots; failed discovery is remembered for 60 seconds and
  peers known only from unverified requests are capped (`FEDERATION.md` §1.3, §1.4).
- More IPv6 transition ranges and 192.88.99.0/24 are non-public addresses (`FEDERATION.md` §1.3 rule 3).
- Domain bans and blocklist entries cover subdomains (`FEDERATION.md` §1.5, §3.3).
- A remote account's kind and owner come from the verified token; a bot is never turned into a user
  (`federation.kind_mismatch`, `FEDERATION.md` §2.6).
- Inviters and callers of third nodes are unverified: never a friend, always a request, shown with `via`
  (`FEDERATION.md` §5.2; new optional `via` of invite list entries).
- `ban.notify` only from nodes the user signed in on; forwarded legal notices need federation history, are limited
  and send no confirmation mail (`FEDERATION.md` §5.2, `LEGAL.md` §1.5).
- `message.purge` is sent per channel (`PROTOCOL.md` §6).
- New reference values `testvectors/federation_node.json` (discovery documents, node and listing tokens).
- **A leaf never changes its identity** (`ENCRYPTION.md` §4.3, §4.4). The delivery service and clients refuse a
  member commit whose update-path leaf carries another identity than the committer's, and the delivery service
  refuses a commit after which two leaves share a signature key.
- **External joins replace every old leaf of the device** (`ENCRYPTION.md` §4.5 rule 2): the commit must remove
  every leaf with the joiner's key; a leaf with its identity but another key is a ghost any member may remove. Rule 4 lets any member remove a leaf whose key is not the attested
  key of the device it names.
- **Claim budget per source and target** (`ENCRYPTION.md` §3.2): home nodes limit KeyPackage claims of requesters
  who share no room, DM or friendship with the target per source (the node itself or one requesting node).
- **Clarifications** (`ENCRYPTION.md` §7b, §9; `PROTOCOL.md` §7): the 64 KiB share limit is measured on the
  base64url string; the identity reset accepts any reauth token of the session and records `key_reset_at` with the
  key change; the envelope example names the field `reply_to_id`.
- **Unknown devices block every encrypted write** (`ENCRYPTION.md` §4.6). Clients encrypt no content (messages, edits,
  thread titles, forum posts, file records, scenes) while the roster holds a ghost leaf the user has not explicitly
  acknowledged; a leaf naming an attested device with another key is unattested.
- **Claimed KeyPackages are checked** (`ENCRYPTION.md` §4.2): the leaf must carry the claimed device's identity and
  attested key.
- **Retired re-attestation only for own recorded devices** (`ENCRYPTION.md` §4.7); removals name the leaf by identity
  and signature key.
- **Plaintext in encrypted conversations** (`ENCRYPTION.md` §5.4) is never shown as the author's content; link
  previews are listed with the metadata the node sees.
- **Trust record** (`ENCRYPTION.md` §7): pins, verified contacts and own devices as an encrypted backup, restored
  before first-use pinning; a conflicting pin is a changed key unless a continuity chain links the keys.
- **Unattended clients and ghosts** (`ENCRYPTION.md` §4.6): acknowledgements cover one leaf (identity and key); bots
  decide by an operator setting (default: only retired devices are accepted).
- **History shares: format 1 removed** (`ENCRYPTION.md` §7b). Clients send only format 2 and bound the window of an
  automatic share by their own knowledge of the member.
- **Native apps: SRV targets must hold a certificate for the identity domain** (`FEDERATION.md` §1.4). At the SRV
  step a native app connects to the target but makes the request for the identity domain (SNI and `Host`), and the
  target's certificate must be valid for that domain; a certificate only for the target counts as a failure of that
  record. A forged DNS answer can no longer bind the app to another node.

### Fixed

- `FEDERATION.md` §7.1/§7.2 match the implementation notes (6-hour announces to reference nodes, 48-hour expiry);
  §10.3 says how signed mentions are handled by a node that normalises mentions; §1.2 recommends `kid`s that a
  restored node cannot repeat.

- **CORS mirrors the requested headers** (`FEDERATION.md` §8 "CORS and CSP"). Nodes allow at least the listed
  request headers and the `Tavrn-*` headers of the upload routes; the reference node mirrors whatever headers a
  preflight names, allows every method and exposes `Content-Range` and `Content-Disposition` besides `ETag`,
  `Retry-After` and `Location`. Before, a fixed header list broke every new upload header for clients of other
  origins, the desktop app included.
- **Unsigned messages of bots and webhooks** (`FEDERATION.md` §10.3). Clients show no "unverified" marker on
  unsigned messages of bots and webhooks: the node authenticated the application's token and the bot badge takes the
  marker's place. A bot signature that cannot be checked is still marked.
- **Voice presence of all rooms at once** (`VOICE.md` §5, §9). New route `GET /api/v1/users/me/voice` →
  `{ rooms: [ { room_id, channels: [VoiceChannelState] } ] }`: the initial voice state of every room of the node the
  requester is a member of, limited to channels with participants the requester can view (like
  `GET /rooms/{id}/voice`); app tokens need the scope `voice`. Clients call it after `ready` and after a resync.
- **Moving members into channels they may not view or connect to** (`VOICE.md` §7 "Moved participations",
  `permissions.md`, `PROTOCOL.md` §6, `ENCRYPTION.md` §4.5). `…/voice/members/{address}/move` and
  `/voice/move-all` need only the mover's permissions; `voice.target_forbidden` now means "below the target's age
  gate" (before: no `connect` in the target). Each move leaves a single-use grant (60 seconds) that entitles the
  member's next join of the target without `connect` and beyond its `user_limit`; the participation that follows is
  marked `moved: true` in `VoiceParticipant` (new field) and lasts until the member leaves or is removed (a rejoin
  within the reconnect grace period keeps it). Meanwhile the member views the channel (`channel.create` before
  `voice.move`, its events, `GET /rooms/{id}`, its MLS group, reading its messages) and the access watcher and the
  `/rtc` proxy accept them without `view_channel` or `connect`; when it ends they get `channel.delete
  { hidden: true }` and their leaves are announced with `mls.remove_needed`. No self-rejoin without `connect`.
- **History since the join under `since_join`** (`ENCRYPTION.md` §7b, `PROTOCOL.md` §6, `FILES.md` §8.7). The history
  window belongs to the room membership: messages (and entry records of files channels) posted after a member's room
  join but before its device first entered the channel's MLS group are part of the member's history under every
  policy. Nodes therefore mark such members `history_pending` also under `since_join` (encrypted content in the window
  from before the device's first leaf; `view_channel` and `read_history` as before), list them in `…/history-pending`
  and accept `POST …/history-keys` under `since_join` (no more `403 history.forbidden` for the policy; the recipient's
  window still bounds what its node serves and its client accepts). Sharing clients send the epochs of the encrypted
  messages since the recipient's join; every window lookup of a sharing client includes thread messages (`GET
  …/messages?…&threads=all`), so forum posts count. Clients join the groups of a room's encrypted channels the user
  may view when the room is loaded, one after the other, so the gap stays small.
- **History shares v2 and signed titles and answers** (`ENCRYPTION.md`, capability `history.shares2`). Every device
  has an X25519 share key, signed by its device key, published with the device key (`PUT
  /users/me/devices/{id}/key` gets `share_public_key` and `share_key_signature`) or once with the new `PUT
  /users/me/devices/{id}/share-key` (`409 e2ee.share_key_exists`, `400 e2ee.share_key_invalid`), and served in the
  keys document next to the attestation (§3.1). History shares of format 2 encrypt the payload (`"v": 2`) under a
  fresh key and seal it to every roster device of the recipient: `POST …/history-keys` takes `v` and `boxes` (1–20,
  each at most 128 bytes, devices attested with a share key, `400 history.invalid`), `GET` returns `v` and the
  requesting device's own `box` and omits format 2 shares without one (§7b). Clients send format 2 when the node
  announces the capability and every roster device of the recipient has a verified share key, format 1 otherwise;
  format 1 is to be removed. Encrypted thread titles carry `ctx { thread_id }`, bot answers to interactions
  `ctx { thread_id, reply_to, interaction }`; a mismatch is `envelope_mismatch` (§5.2, `PROTOCOL.md` §7e,
  `APPLICATIONS.md` §5.7). New reference values in `testvectors/encryption.json`: `device_share_key`,
  `history_share_v2`.
- **Encryption review** (`ENCRYPTION.md`). Messages carry a signed context `ctx { thread_id, reply_to }` inside the
  encrypted JSON; receivers compare it with the envelope and show a mismatch as `envelope_mismatch` (content without
  `ctx` stays valid, §5.2). Devices under a changed, unacknowledged identity key are not added to DMs and are ghosts
  with the reason `key_changed` until the user acknowledges (§3.3, §4.6). Senders do not send after a failed
  catch-up; nodes accept new content only under the current epoch or the previous one within 60 seconds of its
  commit, otherwise `409 mls.epoch_stale` with `meta.epoch` (§5.3). The sample message of a history key check must
  carry a valid content signature; a message whose author device cannot be verified at all (the recipient's own
  device from before an identity reset) is passed over for the next one (§7b step 4). Notes: old secret-storage
  entries stay valid until an identity reset (§2.4), history shares are readable by every current member (§7b),
  forced rejoin (§11). New reference values in `testvectors/encryption.json`: `content_context`, `history_share`,
  `local_storage_key`, `whiteboard_scene`, `device_login`, `sealed_unlock`.
- **Authorization audit, round 2.** Metadata audiences (`PROTOCOL.md` §6 "Audiences of the room's metadata"):
  `channel.*` and a channel's `override.update` reach only the members to whom the channel is listed, `category.*`
  and a category's `override.update` those to whom the category is listed; members who gain a channel get
  `channel.create` (and `category.create`), members who lose one `channel.delete` / `category.delete` with the new
  field `hidden: true`. `GET /rooms/{id}` lists only the overrides of listed channels and categories. Moving
  channels (`permissions.md` "Moving channels"): deleting a category or moving a channel out of it copies the
  category's overrides into the channel (audit `channel.overrides_copied`); moving into a category that grants more
  needs `manage_roles`. Timeouts: typing needs `send_messages`, ephemeral events answer `403 member.timed_out`
  (`WHITEBOARD.md` §2.1). Voice participants who lose `view_channel` or `connect` are disconnected, members leaving
  a group DM leave its call (`VOICE.md` §5, §11). Federation (`FEDERATION.md` §1.5, §3.5, §5.2): per-domain limits
  only after the signature check, per address before it; the receiver's own users named as inviter, caller or claim
  requester must have signed in on the sending node; `notify` hints only for recipients who did.
- **Permissions: layered overrides** (`permissions.md` "Evaluation", "Channel-scoped bits", "Changes"). The
  evaluation applies the role base, then the category's overrides, then the channel's own overrides; a neutral bit
  inherits from the layer below. The channel field `sync_with_category` is removed (`GET` no longer returns it,
  `PATCH` ignores it for one release). Overrides carry only the bits of `CHANNEL_SCOPED` (value `103049789951`);
  others are refused with `400 permissions.not_channel_scoped`, and nodes strip them from existing overrides at start
  (audit action `role.override_restricted`). New and changed cases in `testvectors/permissions.json` ("Layered: …");
  the vectors no longer carry `sync_with_category`. Bit 37 `restore_history` is room-level, not channel-scoped.
- **History restore after a key reset** (`ENCRYPTION.md` §7b "History after a key reset", capability
  `history.restore`, `permissions.md`, `MODERATION.md` §3). An identity reset keeps the memberships, so the history
  window let other members' clients share the old epoch keys automatically with whoever took over the account. Now
  the reset sets `key_reset_at` on the user's memberships, the node records the group epoch at the reset per
  encrypted channel, the member's window and the automatic shares start after it, and history from before the reset
  comes back only through a request (`POST /rooms/{room_id}/history-requests`, `GET …/history-requests`, `…/mine`,
  `…/{request_id}`) that a member with the new permission bit 37 `restore_history` approves or denies (`…/approve`,
  `…/deny`), audited and written into the welcome channel. Room setting `history_restore` (`request` by default, or
  `off`). Files channels are included (their entry records follow the same range). New cases in
  `testvectors/permissions.json`: owner and administrator include bit 37.
- **End-to-end encrypted files channels** (`FILES.md` §8, §9, capability `files.e2ee`, `ENCRYPTION.md` §5c,
  `SEARCH.md` §3.6). New files channels are encrypted with the channel's MLS group by default, fixed at creation
  (`400 channel.encryption_fixed`): chunked AES-256-GCM per file with per-part keys and counter nonces (streaming and
  ranges keep working), encrypted entry records in content format 1 that carry the file key, name and type, the few
  plaintext fields the node keeps, `GET …/files/mine` for deleting without keys, `GET …/files/records` for history key
  checks and the clients' search sync, client-made encrypted thumbnails, and the history window for records. Files
  channels take `history_for_new_members` `all` (their default) or `since_join`, never `days:<n>`. §9 describes the
  deletion of files channels and rooms (internal files at once, external objects through a retried queue,
  `keep_external` for unencrypted external channels). New reference values in `testvectors/encryption.json`:
  `file_chunks`, `file_record`.
- **Date of birth, age status and age gates** (`PROTOCOL.md` §5e, capability `age.v1`, `FEDERATION.md` §2.2,
  `MODERATION.md` §4a). `POST /auth/register` requires `date_of_birth` and refuses users below the node's minimum age
  (`TAVRN_MINIMUM_AGE`, default 16; `403 age.below_minimum`); accounts without one complete it with `PUT
  /users/me/date-of-birth` and get `403 age.status_required` until then; node admins correct it with `PUT
  /admin/users/{user_id}/date-of-birth`. The age status (`adult`, `minor`, `unknown`) is private to the user. Rooms
  and channels carry `age_gate` (`none` or `adults_only`); the hosting node keeps users below a gate out of discover
  lists, joins and gated channels (`403 age.restricted`), for users of other nodes by the signed `age_over_18` claim
  of their federation token, the only age information that leaves the home node.
- **Client-chosen thread ids** (`PROTOCOL.md` §7e, capability `threads.client_ids`, `FEDERATION.md` §10.3). `POST
  …/threads` takes `id`, a canonical ULID of about now (`400 thread.id_invalid`, `409 thread.id_taken`), so clients
  sign the first message of a forum post with its thread id. First messages of threads created without it stay
  unsigned and are shown unverified, not invalid.
- **Channel events reach only the members who can view the channel** (`PROTOCOL.md` §6). The events of a room
  channel (messages, reactions, pins, typing, threads, voice, files, MLS) reach only the room members who can view
  the channel at delivery time (`view_channel` after roles and overrides, and the age gate); the room's metadata
  events still reach every member. The same check gates web push (§6d) and the `notify` hints to other nodes
  (`FEDERATION.md` §5.2).
- **Threads in interactions and webhooks** (`APPLICATIONS.md` §5.5–§5.7, §6.1, §6.1a). The invocation request and the
  interaction payload carry `thread_id`; replies and follow-ups go into that thread unless they name another thread
  of the conversation, and ephemeral replies name it. Refused follow-ups do not count towards the ten. Webhook
  payloads (plain and sealed) name a thread of the channel with `thread_id`; forum channels require it (`400
  message.thread_required`).
- **Message retention, mail language and report pushes** (`PROTOCOL.md` §7f, §6, §6c, §6d, `MODERATION.md` §1.5,
  §2.3, `LEGAL.md` §1.2, `APPLICATIONS.md` §2.2). Nodes may delete messages older than `TAVRN_RETENTION_DAYS`; rooms
  may set a shorter `message_retention_days`; pinned messages and the welcome channel are exempt; `GET /node` names
  the node's value. `PATCH /users/me { locale }` sets the language of the node's mails (the token expiry e-mail is
  sent now). Web push of type `report` (kind and room only, coalesced per room) with the notification setting
  `reports`. Push stays home-node only, so remote rooms in mode "all" do not push for ordinary messages. The node's
  auto-moderation lists are read again hourly and on `SIGHUP`; an invalid file keeps the old lists.
- **Push endpoints and the WebAuthn relying party** (`PROTOCOL.md` §6d, §5a.4). Another account's live push endpoint
  is refused with `409 push.endpoint_taken` (the same account still moves an endpoint between its devices, a stale
  subscription is taken over). Nodes publish their relying party id as `webauthn.rp_id` in `GET /api/v1/node` and
  `/.well-known/tavrn`, and clients that build a WebAuthn assertion themselves pass it.
- **Sealed unlock material for native apps** (`FEDERATION.md` §8 step 3 "Sealed unlock material", `ENCRYPTION.md`
  §2.4). An app session may carry an ephemeral X25519 public key in the URL fragment (`#k=`); after a passkey sign-in
  the connect page seals the PRF output and the credential id to it (the sealed box of the webhook inbox) and sends
  the box with the confirmation (`sealed_unlock`); the node keeps it opaque and hands it out once with the code. The
  session `purpose` `unlock` covers an app that is signed in but locked, and `method=passkey|sso|register` starts one
  sign-in method at once. The confirmation page says when a passkey also unlocks the encrypted messages. New
  reference values in `testvectors/encryption.json`: `sealed_unlock`.
- **Voice quality presets and music mode** (`VOICE.md` §2, §3, §4a, §11). Clients offer quality presets for the
  channel bitrate (from 8 kbps "Saver" to 192 kbps "Music"); music mode (192 kbps and above) captures without echo
  cancellation, noise suppression and auto gain and publishes stereo only for a real two-channel capture. The join
  limits announce `audio_fec`, `TAVRN_VOICE_MAX_BITRATE_KBPS` defaults to 192, calls in DMs stay at speech bitrate,
  and the cap applies only to a bitrate that is being set.
- **App sessions of the connect flow** (`FEDERATION.md` §8 step 3, capability `connect.app`). A native app has no
  `https://` origin to return to: it creates an app session (`POST /api/v1/auth/connect/session`), opens the home
  node's `/connect` page with the session id, polls `GET /api/v1/auth/connect/session/{session_id}` for the one-time
  code and exchanges it with its PKCE verifier (`POST /api/v1/auth/connect/token`), so passkeys, the login captcha and
  single sign-on work for native apps too.

## 0.2.1

- `openapi.json` is valid JSON again: the 0.2.0 tag carries an `info.version` line with a stray trailing comma. The
  0.2.0 tag stays; 0.2.1 replaces it as the version implementations pin.

## 0.2.0

- **Threads, forum and announcement channels** (`PROTOCOL.md` §7e, capabilities `threads`, `forum`, `announcement`).
- **Reports with evidence and auto-moderation** (`MODERATION.md`, capabilities `reports.v1`, `automod.v1`).
- **Web push** (`PROTOCOL.md` §6d, capability `push.webpush`).
- `openapi.json` carries the protocol version in `info.version`.

## 0.1.1

- The descriptions in `openapi.json` are in English.

## 0.1.0

- The first tagged version of the specification, the OpenAPI description, the permission table and the test vectors.
