# Changelog

Changes of the protocol that implementations must follow, newest first. Versions are the tags of this repository
(`README.md` "Versioning and capabilities").

## Unreleased

- **Whisper to selected participants** (`VOICE.md` §4c, §9.0): a second encrypted microphone track named
  `whisper`, selective SFU subscription permissions, targeted reliable `tavrn.whisper` start/end signals,
  mandatory receiver filtering, size/rate limits and failure recovery that restores ordinary microphone state.
  `canPublishData` now also permits `speak` while not server-muted; existing soundboard grants remain valid.
  Groups are per room, reply-to-last clears on leave, no ducking or outsider whisper markers. The shared
  epoch-key privacy boundary is explicit in `ENCRYPTION.md` §5a; native engines may offer a browser fallback.

- Private single-choice modal inputs (`components.modal_select.v1`, `APPLICATIONS.md` §5.10.3): a select style
  with 1–25 validated options, invoker-only presentation and unchanged text-map submits, including encryption.
  Applications can follow a public class choice with a private spec form without changing shared controls.


### Security

- **The welcome channel names no private channel** (`APPLICATIONS.md` §3.6, `PROTOCOL.md` §7): `system.bot_added` and
  `system.bot_removed` go into the welcome channel only when `@everyone` can view the channel; otherwise the node
  writes them into the channel itself as a security notice (plaintext, delivered to the channel's viewers only). Security
  notices never count towards unread or mention counts, cannot be deleted (`403 message.system_protected`) and are
  skipped by purges and retention. Clients name the channel of an older welcome channel entry only when the viewer can
  see that channel ("a private channel" otherwise). No schema change.

- **Outbound requests honour the domain policy** (`FEDERATION.md` §1.5): outbox entries, profile and image mirroring
  and application documents no longer reach a banned or blocked domain; queued entries are dropped as undeliverable.
- **The KeyPackage claim budget of a requesting node** (`ENCRYPTION.md` §3.2) exempts only related requesters that
  node can speak for; users of third nodes count against its budget.
- **Inbound friend requests are limited** per sending node and recipient, and their stubs leave a reserve of the
  remote-user quota for federated logins (`FEDERATION.md` §2.6, §6.2).
- **Forwarded reports** (`MODERATION.md` §1.6): evidence authors other than the reported user get pseudonyms of the
  report only, never the reporter's, and lose their message ids.
- **Files channels** (`FILES.md` §4): a rename is classified like an upload; uploads in progress count towards the
  channel total.
- **More dangerous extensions** (`PROTOCOL.md` §7a): compiled help, click-once and web-query files, search and
  library connectors, diagnostic packages and further Windows script and installer types are flagged as executables
  (new test vector `help.chm`; clients extend their lists).

### Changed

- **Rules on every join route** (`PROTOCOL.md` §6b "Room rules"): spelled out that personal invitations and federated
  joins need `accept_rules: true` like the other routes, and that clients show the rules on every path that leads
  to a join. The node already behaved this way.
- **Room rules are Markdown** (`PROTOCOL.md` §6b "Room rules"): a room's `rules` are a Markdown subset like `bio`,
  rendered and sanitized by clients without images or embeds; clients without a renderer show the text as is. The
  join routes' `accept_rules` requirement is spelled out. Prose only, no schema change.
- **Remote users and logins get a share of their domain's budget** (`FEDERATION.md` §3.2, §11.1): a remote user's
  requests and a federated login count against a per-user (and per-address) share first, and attempts the share
  refuses do not count for the domain, so one account cannot lock the other users of its domain out. A rate-limited
  WebSocket hello closes with `4002 rate_limited`, never `4001`.
- **Auto-moderation follows the hierarchy** (`MODERATION.md` §2.2): `delete` and `timeout` rules act only on members
  ranked below the member who last saved the rules; interaction replies and follow-ups are checked like other
  messages; auto-moderation timeouts are announced with `member.update`; a message needing more matching work than
  the node allows is refused with `403 automod.blocked`.
- **Moderation bots never see reports about their owner** or the owner's other bots (`MODERATION.md` §1.4a).
- **One node holds at most 500 entries of a bot's install index** (`APPLICATIONS.md` §4.5).
- **A keys document stays within the clients' limits** (`ENCRYPTION.md` §3): at most 100 devices per account (`403
  auth.device_limit` at a login beyond it), 1000 retired entries and 100 continuity statements (`409 e2ee.rotation_limit`).
- **The DM list and the message requests can be paged** (`PROTOCOL.md` §8a). `GET /conversations` and `GET
  /conversations/requests` accept `limit` (1–200) and `before` (the sort key of the last item: `last_message_id`, else
  the id, for the DM list; the conversation id for the requests). Without `limit` both return the whole list as
  before; the responses stay plain arrays. The requests are ordered newest first by conversation id.
- **Anonymous `GET /rooms/discover` may be rate-limited** per client address (`FEDERATION.md` §7, `429`; the
  reference node allows 120 per minute, as for the directory reads).
- **Clarified: the history window covers pins and reactions** (`ENCRYPTION.md` §7b). Reaction, reactor, pin and unpin
  routes answer `404 message.not_found` for an encrypted message outside the requester's window, and `GET …/pins`
  lists only pinned messages inside it, as a page of messages does.
- **WebSocket close code `1013`** (`PROTOCOL.md` §6): a temporary problem of the node (e.g. `db.unavailable` as the
  reason) closes with `1013` "try again later"; clients reconnect with backoff and keep the session. Before, nodes could
  close such cases with `4001`, which clients answer with a refresh and then the end of the session.
- **Clarified: malformed input and `request_id`** (`PROTOCOL.md` §4): `400 request.invalid_json`,
  `413 request.too_large` and `400 request.invalid_query` on every route; `request_id` equals `X-Request-Id`.

- **Leaf cleanup election** (`ENCRYPTION.md` §4.7): devices that may not commit a removal or are known to be offline do not count for the election, and a voice join never waits for it (the elected device removes at once, others join on the current epoch and clean up in the background).
- **A secret storage entry marks its passkey as PRF-capable** (`ENCRYPTION.md` §2.4, `PROTOCOL.md` §3.3).
  `PUT /users/me/secret-storage/passkey/{credential_id}` accepts the entry for any credential of the user and sets
  `prf_supported`; the `409 secret_storage.prf_unsupported` refusal is gone. Authenticators that announce the PRF only
  at assertion time (or gain it with a system update) can unlock messages without re-registration.
- **The node quota of files channels covers the node's own storage only** (`FILES.md` §4, §5, `ENTITLEMENTS.md`).
  `files_channels.max_bytes` no longer limits channels on external WebDAV/S3 stores. Such a channel has its own
  optional limit, `max_bytes` in `PUT …/files/backend` (returned by `GET backend`, `0`/absent = unlimited), set by the
  members who configure the store, enforced with `413 files.quota_exceeded` and named as `limit_bytes` in `GET usage`.

### Added

- **Room privacy notice and legal notice** (`PROTOCOL.md` §6b "Room privacy notice and legal notice"): optional
  Markdown documents of a room (`privacy_notice` up to 20,000 and `legal_notice` up to 5,000 characters, `manage_room`
  via `PATCH /rooms/{room_id}`), audited as `room.legal`, announced with `room.update`. Room objects carry
  `privacy_notice_updated_at` and `legal_notice_updated_at` (null while off); the texts come with the previews.
  Information only: joining never needs an acknowledgement of them.
- **Room preview** `GET /rooms/{room_id}/preview` (`PROTOCOL.md` §6b "Room preview"): room, rules and legal documents
  before joining; public rooms for everyone (rate-limited anonymously, age gates as on Discover), other rooms for
  their members and node admins only. The invite preview `GET /invites/{code}` carries the same fields
  (`InvitePreview` is now `RoomPreview` plus `code`).
- **Links** (`PROTOCOL.md` §7h): the canonical https form of links to rooms, channels, messages (`?message=`), files of
  files channels (`…/files/<entry>`), invites and profiles, on the web origin of the hosting node; clients recognise
  them only for nodes they already talk to (no request to unknown hosts), resolve names with the viewer's session and
  show neutral chips without access. `@name@domain` is a mention, never an e-mail link; clients may mark members a
  bot's card names without a `mentions` list, without notification. Prose only, no schema change.
- **Test vectors for upload categories** (`PROTOCOL.md` §7a, `testvectors/upload_categories.json`): the category and
  the executable flag of a file from its name, its declared type and its first bytes, with the order of the magic-byte
  checks spelled out. Clients that declare the category of encrypted uploads run them; the node classifies plaintext
  uploads by the same cases.
- **Files channels for bots** (`FILES.md` §3, `APPLICATIONS.md` §2.4, §2.5, §2.7, fixes #44). The files routes are
  in the app route table: listings, entries, downloads, thumbnails, `GET records`, `GET mine` and `GET usage` under
  `messages:read`; folders, uploads, rename/move/delete and `PUT …/thumbnail` under `messages:write` (the channel's
  `attach_files`, upload categories and the executable rule apply as for users); others' entries need `manage_files`
  (`rooms:manage`). The storage backend routes (`GET`/`PUT …/files/backend`, `POST …/files/backend/test`) stay
  closed (`403 app.bot_forbidden`), and `GET usage` answers bots with `can_configure: false` and no backend host or
  prefix. Events `files.update` and `files.backend` reach bots with `messages:read`. "No bots" zones and
  `bots_allowed` apply unchanged; in encrypted channels the bot encrypts records and chunks itself (§8). Compatible:
  a bot without the scopes sees no change.
- **Moderation bots read the room's report inbox, metadata only** (`MODERATION.md` §1.4a, §1.5, `APPLICATIONS.md`
  §2.4–§2.6, fixes #45). App tokens with the existing scope `moderation` that hold `moderate_members` in a room may
  call `GET /rooms/{room_id}/reports` → `AppReportList` and `GET /reports/{report_id}` → `AppReport` for the room's
  reports (`scope: room`; never about the bot itself or the room's owner) and receive `report.create` and
  `report.update` of that room. `AppReport` carries kind, category, target, status, counts, timestamps and the
  reported message's id, never `detail`, `snapshot`, `evidence`, `note`, `assignee` or the actions; `reporter` is a
  pseudonym in the format of the forwarded reports (§1.6), stable per reporter, bot and room, never the address.
  Creating, triage, action shortcuts, forwarding and deleting stay closed to bots. No new scope, no new consent line.

- **Reaction events name the change and the reactor; reactors route** (`PROTOCOL.md` §6, §7 "Reactions",
  `APPLICATIONS.md` §2.6, fixes #43). A `message.update` caused by a reaction change carries `reaction: { emoji, user,
  user_id, added }` and is sent only when the reactions changed; its audience is unchanged (the conversation audience,
  bots with `messages:read`), and clients may show who reacted. `GET /conversations/{id}/messages/{message_id}/reactions/{emoji}?after=&limit=`
  → `{ items: [{ user, user_id, created_at }], next }` lists the reactors (oldest first, at most 100 per page, the
  message's read rules, `400 reaction.cursor_invalid`). Message events carry no per-viewer state: `reactions[].me` is
  `false` in `message.create` and `message.update`; HTTP responses keep the caller's flags.
- **Entitlement `files_channels.internal`** (`ENTITLEMENTS.md` §1, §3, `FILES.md` §5, tavrn-node#64). A room key
  with the new rule *setting* (`0`/`1`; a value set by the room owner's or the room's grants wins over the node
  default `TAVRN_FILES_INTERNAL`, in both directions): a plan or override can allow the node's own storage for the
  files channels of some owners' rooms on a node with external stores only, or take it away on a node that keeps
  files. `GET …/files/usage` gains `internal_allowed` (the room's effective value), `GET …/files/backend` reports the
  same value in `internal_allowed`, and `backend: "none"`, `403 files.internal_disabled` follow it; `files_internal`
  in `GET /node` and the discovery document stays the node default.
- **Message components** (`APPLICATIONS.md` §5.10, capability `components.v1`, fixes #27). `text` content carries
  optional `components`: at most 5 rows of 1–5 buttons (`primary`, `secondary`, `success`, `danger`, `link`) or one
  select menu (1–25 options, `min`/`max`), 8 KiB, unknown keys refused (`400 message.components_invalid` with
  `meta.path`); only bots' messages carry them (the node refuses them in plaintext from users and webhooks, clients
  render them only on bot messages). Clicking or selecting:
  `POST /conversations/{id}/messages/{message_id}/interactions { custom_id, values | values_ciphertext + epoch }`
  (permission `use_components`; `403 component.forbidden`, `404 component.not_found` when the author is not the bot of
  an installed application, `410 component.expired` after `TAVRN_COMPONENT_MAX_AGE_DAYS`, `400
  component.values_invalid`) creates an interaction of `kind` `component`, delivered as `component.invoke`. New
  responses for every interaction: `update` (edits the message carrying the component; `400
  interaction.update_unsupported`, `403 interaction.update_forbidden`) and `modal` (a form shown on the invoking
  device; `400 interaction.modal_invalid`, `400 interaction.modal_nested`), with `outcome` `update`/`modal` and the
  new field `modal` in the invocation response. Modal submits: `POST /interactions/{id}/submit` (`403
  interaction.not_invoker`, `409 interaction.already_submitted`, `400 interaction.values_invalid`) create an
  interaction of `kind` `modal`, delivered as `modal.submit`. Encrypted conversations carry the values as the content
  objects `component.values` and `modal.values` (signed by the invoking device, checked by the bot like
  `command.args`). `EphemeralReply` and `interaction.reply` gain `message_id`; the envelope field `interaction` gains
  `kind` and `message_id` (`command` is null for components). New test vectors `testvectors/components.json`.
- **Permission `use_components`** (`permissions.md` bit 40): channel-scoped, default of `@everyone`, independent of
  `send_messages`, covered by no app-token scope, granted once to every role holding `send_messages` (marker
  `fixup.use_components`). `CHANNEL_SCOPED` is now `2027195138559`.
- **Polls and date polls** (`PROTOCOL.md` §7g, `ENCRYPTION.md` §5.2, capability `polls.v1`, fixes #35). The
  content type `poll` (`kind` `choice` with 2–20 options and `max_choices`, or `date` with 1–60 time slots answered
  `yes`/`maybe`/`no`; `results_visible`, `votes_visible`, both cooperative) is encrypted like any content; the node
  checks plaintext polls (`400 message.poll_invalid`) and refuses editing them (`400 message.poll_immutable`).
  Messages carry the plaintext close time `poll_closes_at` (set on create, 1 minute to 1 year ahead; through `PATCH
  …/messages/{id} { poll_closes_at }` the author or `manage_messages` closes a poll now, also one without a close
  time, or moves its close time earlier, never later). Votes are vote
  records, one per user and poll on the hosting node: `PUT`/`DELETE /conversations/{id}/messages/{message_id}/poll/vote`
  and `GET …/poll/votes`, content `poll.vote` encrypted and device-signed under the current epoch (plaintext
  conversations: checked against the poll, optional plaintext signature), bound to the poll by `ctx.poll` and
  `ctx.poll_hash` (SHA-256 of the poll's JCS form without `ctx`); `409 poll.closed`, `413 poll.vote_too_large`
  (4 KiB), 10 changes per minute. Events `poll.vote` and `poll.vote.delete`; votes never count as unread or notify
  and go with their message. New test vectors `testvectors/polls.json` (`poll_vote`).
- **Permission `create_polls`** (`permissions.md` bit 39): channel-scoped, default of `@everyone`, covered by
  `messages:write`, granted once to every role and override that allowed `send_messages` (marker
  `fixup.create_polls`), denied in the welcome channel. The node needs it for plaintext polls and every message with
  `poll_closes_at`; clients enforce it for encrypted polls. `CHANNEL_SCOPED` is now `927683510783`.
- **Voice session start** (`VOICE.md` §5, fixes #31): `VoiceChannelState` carries `session_started_at` (RFC 3339 or
  `null`): when the channel's current session began, set with the first connected participant, kept while anybody
  is connected or reconnecting, cleared with the last one. Every voice state (`GET …/voice`, `GET /users/me/voice`,
  the join answer, `voice.state`) carries it; clients show a session timer that is right for late joiners.
- **Voice channel status** (`VOICE.md` §2a, `permissions.md` bit 38, fixes #32): voice channels carry `status`
  (plain text, at most 128 characters, `""` = none) next to the text channels' `topic`. Members with the new
  channel-scoped permission `voice_status` change it at any time with `PATCH …/channels/{id}` `{ status }` without
  `manage_channels` (`403 channel.status_forbidden` without the bit, `400 channel.status_not_voice` on other
  kinds); audit `channel.voice_status`, event `channel.update`. The bit is granted once to every role with
  `manage_channels`; `CHANNEL_SCOPED` is now `377927696895` and the shared vectors cover the bit.
- **Reports v2: forwarding reports to the reported user's home node** (`MODERATION.md` §1.6, `FEDERATION.md` §5.2,
  capability `reports.v2`, fixes #2). Node admins forward a report about a user of another node with
  `POST /reports/{report_id}/forward` (idempotent; `400 report.forward_invalid`, `409 report.target_local`,
  `409 report.forward_unsupported` when the home node does not announce `reports.v2`). The inbox type
  `report.forward` carries kind, category, detail, the snapshot or the released evidence and a **pseudonym** of the
  reporter (never the address; other authors in the evidence are pseudonymized too). The home node stores it in its
  admins' inbox as `source: forward` with `origin { node, report_id, reporter, reported_at }`, deduplicated per
  origin report and limited per sending domain (`TAVRN_REPORTS_INBOUND_PER_HOUR`); `ModerationReport` gains
  `forwarded` and `origin`.
  The reporter is told nothing. Additive: nodes without `reports.v2` ignore the type, `reports.v1` is unchanged.

- **Screen publishers** (`VOICE.md` §4b, §3, §5, §11.1, `ENCRYPTION.md` §5a). A device may add one second LiveKit
  participant to its voice channel or call that only publishes its screen share, for apps whose WebRTC cannot take
  the system's screen capture (the Android app): `voice/join` and `call/join` take an optional body
  `{ "role": "screen" }` and return a token for `<user>/<device>#screen` that publishes `screen_share` and
  `screen_share_audio` only and never subscribes (`409 voice.not_connected` without the device's own participation,
  `403 voice.stream_forbidden`, `409 voice.screen_active` for a second one); it counts as its owner (no seat, no
  limit), is listed right after the owner with `screen_of` = the owner's identity, ends with the owner's
  participation, and `voice/leave` / `call/leave` with `{ "role": "screen" }` end it alone. It encrypts with the
  owner's frame key, which the owner's client hands to it over the app's local bridge. Additive: devices are
  unchanged, `screen_of` is absent for them.
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

- **The `rooms:manage` scope lists `voice_status`** (`APPLICATIONS.md` §2.4, fixes #47). The scope table names bit 38
  and the status of voice channels (`VOICE.md` §2a) in the routes column, as `permissions.md` and the reference node
  already did.

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
